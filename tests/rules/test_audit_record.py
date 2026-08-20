"""审计落盘字段：默认元数据、正文 opt-in、双决策与 adapter。"""
from __future__ import annotations

import json
import os
import stat
from datetime import date
from dataclasses import replace
from pathlib import Path

import pytest

from safety_guard import audit, runner
from safety_guard.adapters.codex_approval import ApprovalOutcome
from safety_guard.adapters.registry import get
from safety_guard.config import load as load_config


@pytest.fixture
def audit_cfg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv(audit.AUDIT_DISABLE_ENV, raising=False)
    cfg = replace(load_config(), fail_open=False, dry_run=False, audit_dir=tmp_path / "audit")
    return cfg


@pytest.fixture
def audit_body_cfg(audit_cfg):
    return replace(audit_cfg, audit_include_body=True)


def _read_all(audit_dir: Path) -> list[dict]:
    files = sorted(audit_dir.glob("audit-*.jsonl"))
    out: list[dict] = []
    for f in files:
        for line in f.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
    return out


def test_grok_medium_records_engine_ask_rendered_allow(audit_cfg, tmp_path: Path):
    cwd = tmp_path / "proj"
    cwd.mkdir()
    out = runner.run(
        {
            "hook_event_name": "pre_tool_use",
            "tool_name": "run_terminal_command",
            "tool_input": {"command": "rm -rf ./tmp-dir"},
            "cwd": str(cwd),
        },
        adapter=get("grok"),
        config=audit_cfg,
    )
    assert out == {}
    rows = _read_all(audit_cfg.audit_dir)
    assert len(rows) == 1
    rec = rows[0]
    assert rec["adapter"] == "grok"
    assert rec["engine_decision"] == "ask"
    assert rec["rendered_decision"] == "allow"
    assert rec["decision"] == "ask"  # 兼容字段 = 引擎结论
    assert rec["hook_event"] == "PreToolUse"
    assert rec["cmd_body_stored"] is False
    assert rec["match_details_stored"] is False
    assert "cmd_body" not in rec
    assert "cmd_preview" not in rec
    assert rec["matches"] == [{"id": "bash-rm-targeted", "severity": "medium"}]
    assert "harness" not in rec


def test_claude_allow_empty_render_is_abstain(audit_cfg, tmp_path: Path):
    cwd = tmp_path / "proj"
    cwd.mkdir()
    out = runner.run(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "git status"},
            "cwd": str(cwd),
        },
        adapter=get("claude"),
        config=audit_cfg,
    )
    assert out == {}
    rec = _read_all(audit_cfg.audit_dir)[0]
    assert rec["adapter"] == "claude"
    assert rec["engine_decision"] == "allow"
    assert rec["rendered_decision"] == "abstain"
    assert rec["decision"] == "allow"


def test_codex_permission_dry_run_records_native_abstain(audit_cfg, tmp_path: Path):
    cfg = replace(audit_cfg, dry_run=True)
    cwd = tmp_path / "proj"
    cwd.mkdir()
    output = runner.run(
        {
            "hook_event_name": "PermissionRequest",
            "tool_name": "Bash",
            "tool_input": {"command": "git status"},
            "cwd": str(cwd),
        },
        adapter=get("codex-permission"),
        config=cfg,
    )

    assert output == {}
    record = _read_all(cfg.audit_dir)[0]
    assert record["decision"] == "dry-run-allow"
    assert record["rendered_decision"] == "abstain"


@pytest.mark.parametrize(
    ("status", "rendered_decision"),
    [("approved", "abstain"), ("denied", "deny")],
)
def test_codex_interactive_approval_is_audited(
    audit_cfg,
    tmp_path: Path,
    status: str,
    rendered_decision: str,
):
    class Resolver:
        def resolve(self, request, result, *, timeout_seconds):
            return ApprovalOutcome(status, provider="synthetic-dialog")

    cwd = tmp_path / "proj"
    cwd.mkdir()
    runner.run(
        {
            "hook_event_name": "PreToolUse",
            "permission_mode": "bypassPermissions",
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf ./synthetic-dir"},
            "cwd": str(cwd),
        },
        adapter=get("codex-pretool"),
        config=replace(audit_cfg, codex_approval_mode="native-gap"),
        approval_resolver=Resolver(),
    )

    record = _read_all(audit_cfg.audit_dir)[0]
    assert record["engine_decision"] == "ask"
    assert record["rendered_decision"] == rendered_decision
    assert record["decision_source"] == "interactive"
    assert record["approval"] == {
        "provider": "synthetic-dialog",
        "status": status,
        "mode": "native-gap",
        "permission_mode": "bypassPermissions",
        "origin": "policy",
    }


def test_full_body_preserves_newlines(audit_body_cfg, tmp_path: Path):
    cwd = tmp_path / "proj"
    cwd.mkdir()
    cmd = "echo one\necho two\ngit status"
    runner.run(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": cmd},
            "cwd": str(cwd),
        },
        adapter=get("claude"),
        config=audit_body_cfg,
    )
    rec = _read_all(audit_body_cfg.audit_dir)[0]
    assert rec["cmd_body"] == cmd
    assert "\n" in rec["cmd_body"]
    assert rec["cmd_lines"] == 3


def test_long_command_truncated_without_body(audit_body_cfg, tmp_path: Path, monkeypatch):
    cwd = tmp_path / "proj"
    cwd.mkdir()
    # 压低阈值，避免写超大字符串
    monkeypatch.setattr(audit, "FULL_BODY_CHARS", 50)
    monkeypatch.setattr(audit, "PREVIEW_CHARS", 40)
    cmd = "echo " + ("x" * 200)
    runner.run(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": cmd},
            "cwd": str(cwd),
        },
        adapter=get("claude"),
        config=audit_body_cfg,
    )
    rec = _read_all(audit_body_cfg.audit_dir)[0]
    assert rec["cmd_truncated"] is True
    assert "cmd_body" not in rec
    assert rec["cmd_preview"].endswith(audit.TRUNCATION_SUFFIX)
    assert rec["cmd_chars"] == len(cmd)


def test_match_extra_redacts_home(audit_body_cfg, tmp_path: Path):
    cwd = tmp_path / "proj"
    cwd.mkdir()
    home = str(Path.home())
    target = f"{home}/nonexistent-probe-extra.txt"
    runner.run(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_input": {"file_path": target, "old_string": "a", "new_string": "b"},
            "cwd": str(cwd),
        },
        adapter=get("claude"),
        config=audit_body_cfg,
    )
    rec = _read_all(audit_body_cfg.audit_dir)[0]
    blob = json.dumps(rec.get("matches") or [], ensure_ascii=False)
    assert home not in blob
    assert "$HOME" in blob


def test_home_path_redacted_in_body(audit_body_cfg, tmp_path: Path):
    cwd = tmp_path / "proj"
    cwd.mkdir()
    home = str(Path.home())
    cmd = f"ls {home}/nonexistent-probe-audit-only"
    runner.run(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": cmd},
            "cwd": str(cwd),
        },
        adapter=get("claude"),
        config=audit_body_cfg,
    )
    rec = _read_all(audit_body_cfg.audit_dir)[0]
    body = rec.get("cmd_body") or ""
    assert home not in body
    assert "$HOME" in body


@pytest.mark.parametrize(
    ("command", "secret"),
    [
        ("API_KEY=synthetic-api-value run-tool", "synthetic-api-value"),
        ("OPENAI_API_KEY=synthetic-vendor-api-value run-tool", "synthetic-vendor-api-value"),
        ("run-tool --access-token synthetic-token-value", "synthetic-token-value"),
        ("curl -H 'Authorization: Bearer synthetic-bearer-value' https://example.invalid", "synthetic-bearer-value"),
        ("run-tool --password='synthetic-password-value'", "synthetic-password-value"),
        ("PASSWORD='synthetic password with spaces' run-tool", "synthetic password with spaces"),
        ("run-tool --password 'synthetic option password with spaces'", "synthetic option password with spaces"),
        ("printf '%s' '{\"api_key\":\"synthetic-json-api-value\"}'", "synthetic-json-api-value"),
        ("printf '%s' '{\"Authorization\":\"Bearer synthetic-json-bearer\"}'", "synthetic-json-bearer"),
    ],
)
def test_credentials_are_redacted_from_audit_body(
    audit_body_cfg,
    tmp_path: Path,
    command: str,
    secret: str,
):
    cwd = tmp_path / "proj"
    cwd.mkdir()
    runner.run(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "cwd": str(cwd),
        },
        adapter=get("claude"),
        config=audit_body_cfg,
    )
    blob = json.dumps(_read_all(audit_body_cfg.audit_dir)[0], ensure_ascii=False)
    assert secret not in blob
    assert audit.REDACTED_SECRET in blob


def test_new_audit_permissions_are_private(audit_cfg, tmp_path: Path):
    cwd = tmp_path / "proj"
    cwd.mkdir()
    runner.run(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "git status"},
            "cwd": str(cwd),
        },
        adapter=get("claude"),
        config=audit_cfg,
    )
    log = next(audit_cfg.audit_dir.glob("audit-*.jsonl"))
    assert stat.S_IMODE(audit_cfg.audit_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(log.stat().st_mode) == 0o600


def test_existing_non_private_audit_directory_is_not_chmodded(audit_cfg, tmp_path: Path):
    cwd = tmp_path / "proj"
    cwd.mkdir()
    audit_cfg.audit_dir.mkdir(mode=0o755)
    audit_cfg.audit_dir.chmod(0o755)

    runner.run(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "git status"},
            "cwd": str(cwd),
        },
        adapter=get("claude"),
        config=audit_cfg,
    )

    assert stat.S_IMODE(audit_cfg.audit_dir.stat().st_mode) == 0o755
    assert list(audit_cfg.audit_dir.iterdir()) == []


def test_prune_ignores_unmanaged_audit_like_files(audit_cfg, tmp_path: Path):
    audit_cfg.audit_dir.mkdir(mode=0o700)
    audit_cfg.audit_dir.chmod(0o700)
    unrelated = audit_cfg.audit_dir / "audit-user-data.jsonl"
    unrelated.write_text("sentinel", encoding="utf-8")
    unrelated.chmod(0o600)
    os.utime(unrelated, (0, 0))

    audit._maybe_prune(audit_cfg.audit_dir, replace(audit_cfg, audit_retention_days=0))

    assert unrelated.read_text(encoding="utf-8") == "sentinel"


def test_unmarked_date_log_is_neither_appended_nor_pruned(audit_cfg, tmp_path: Path):
    cwd = tmp_path / "proj"
    cwd.mkdir()
    audit_cfg.audit_dir.mkdir(mode=0o700)
    audit_cfg.audit_dir.chmod(0o700)
    existing = audit_cfg.audit_dir / f"audit-{date.today().isoformat()}.jsonl"
    existing.write_text("sentinel\n", encoding="utf-8")
    existing.chmod(0o600)
    os.utime(existing, (0, 0))

    runner.run(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "git status"},
            "cwd": str(cwd),
        },
        adapter=get("claude"),
        config=replace(audit_cfg, audit_retention_days=0),
    )

    assert existing.read_text(encoding="utf-8") == "sentinel\n"
    managed = audit_cfg.audit_dir / f"audit-{date.today().isoformat()}-01.jsonl"
    record = json.loads(managed.read_text(encoding="utf-8").splitlines()[0])
    assert record["safety_guard_schema"] == audit._AUDIT_SCHEMA


def test_three_digit_rolled_log_is_managed(audit_cfg):
    audit_cfg.audit_dir.mkdir(mode=0o700)
    rolled = audit_cfg.audit_dir / f"audit-{date.today().isoformat()}-100.jsonl"
    rolled.write_text(
        json.dumps({"safety_guard_schema": audit._AUDIT_SCHEMA}) + "\n",
        encoding="utf-8",
    )
    rolled.chmod(0o600)

    assert audit._is_managed_audit_file(rolled)


@pytest.mark.parametrize("link_kind", ["symlink", "hardlink"])
def test_audit_refuses_linked_log_target_without_touching_target(
    audit_cfg,
    tmp_path: Path,
    link_kind: str,
):
    """审计文件不能借链接跟随写入仓库外的合成目标。"""
    target = tmp_path / "synthetic-target.txt"
    target.write_text("sentinel", encoding="utf-8")
    audit_cfg.audit_dir.mkdir()
    log = audit_cfg.audit_dir / f"audit-{date.today().isoformat()}.jsonl"
    if link_kind == "symlink":
        log.symlink_to(target)
    else:
        os.link(target, log)

    runner.run(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "git status"},
            "cwd": str(tmp_path / "proj"),
        },
        adapter=get("claude"),
        config=audit_cfg,
    )

    assert target.read_text(encoding="utf-8") == "sentinel"
    assert log.is_symlink() or log.stat().st_nlink == 2


def test_audit_refuses_symlinked_directory_without_creating_files(audit_cfg, tmp_path: Path):
    target_dir = tmp_path / "synthetic-audit-target"
    target_dir.mkdir()
    audit_cfg.audit_dir.symlink_to(target_dir, target_is_directory=True)

    runner.run(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "git status"},
            "cwd": str(tmp_path / "proj"),
        },
        adapter=get("claude"),
        config=audit_cfg,
    )

    assert list(target_dir.iterdir()) == []


def test_audit_records_config_load_error(audit_cfg, tmp_path: Path):
    cwd = tmp_path / "proj"
    cwd.mkdir()
    cfg = replace(
        audit_cfg,
        load_error="config_parse_error",
    )
    runner.run(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "git status"},
            "cwd": str(cwd),
        },
        adapter=get("claude"),
        config=cfg,
    )
    record = _read_all(cfg.audit_dir)[0]
    assert record["config_load_error"] == "config_parse_error"


def test_parse_failure_audit_hashes_untrusted_labels(audit_cfg, tmp_path: Path):
    class RejectingAdapter:
        name = "synthetic-rejecting"

        @staticmethod
        def parse(stdin_json):
            raise ValueError("synthetic parse failure")

        @staticmethod
        def render(result):
            return {"decision": "deny"}

    tool_secret = "FutureTool\nsynthetic-tool-label-secret"
    event_secret = "PreToolUse\nsynthetic-event-label-secret"
    runner.run(
        {
            "hook_event_name": event_secret,
            "tool_name": tool_secret,
            "tool_input": {},
            "cwd": str(tmp_path),
        },
        adapter=RejectingAdapter(),
        config=audit_cfg,
    )

    record = _read_all(audit_cfg.audit_dir)[0]
    blob = json.dumps(record, ensure_ascii=False)
    assert record["tool"].startswith("unknown:")
    assert record["hook_event"].startswith("unknown:")
    assert "synthetic-tool-label-secret" not in blob
    assert "synthetic-event-label-secret" not in blob


def test_no_audit_env_skips_write(audit_cfg, tmp_path: Path, monkeypatch):
    monkeypatch.setenv(audit.AUDIT_DISABLE_ENV, "1")
    cwd = tmp_path / "proj"
    cwd.mkdir()
    runner.run(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "git status"},
            "cwd": str(cwd),
        },
        adapter=get("claude"),
        config=audit_cfg,
    )
    assert _read_all(audit_cfg.audit_dir) == []


def test_infer_rendered_helpers():
    assert audit.infer_rendered_decision({}, engine_decision="allow") == "allow"
    assert (
        audit.infer_rendered_decision({}, engine_decision="allow", adapter="claude")
        == "abstain"
    )
    assert (
        audit.infer_rendered_decision(
            {},
            engine_decision="allow",
            adapter="codex-permission",
            hook_event="PermissionRequest",
        )
        == "abstain"
    )
    assert audit.infer_rendered_decision({"decision": "deny"}, engine_decision="ask") == "deny"
    assert (
        audit.infer_rendered_decision({"unexpected": True}, engine_decision="abstain")
        == "abstain"
    )
    assert (
        audit.infer_rendered_decision(
            {"hookSpecificOutput": {"permissionDecision": "deny"}},
            engine_decision="ask",
        )
        == "deny"
    )
