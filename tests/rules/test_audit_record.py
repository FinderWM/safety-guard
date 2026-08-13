"""审计落盘字段：完整正文、双决策、adapter 必填。"""
from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

from safety_guard import audit, runner
from safety_guard.adapters.registry import get
from safety_guard.config import load as load_config


@pytest.fixture
def audit_cfg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv(audit.AUDIT_DISABLE_ENV, raising=False)
    cfg = replace(load_config(), fail_open=False, dry_run=False, audit_dir=tmp_path / "audit")
    return cfg


def _read_all(audit_dir: Path) -> list[dict]:
    files = sorted(audit_dir.glob("audit-*.jsonl"))
    out: list[dict] = []
    for f in files:
        for line in f.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
    return out


def test_grok_medium_records_engine_ask_rendered_deny(audit_cfg, tmp_path: Path):
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
    assert out["decision"] == "deny"
    rows = _read_all(audit_cfg.audit_dir)
    assert len(rows) == 1
    rec = rows[0]
    assert rec["adapter"] == "grok"
    assert rec["engine_decision"] == "ask"
    assert rec["rendered_decision"] == "deny"
    assert rec["decision"] == "ask"  # 兼容字段 = 引擎结论
    assert rec["hook_event"] == "PreToolUse"
    assert rec.get("cmd_truncated") is False
    assert "rm -rf ./tmp-dir" in (rec.get("cmd_body") or "")
    assert rec["cmd_body"] == rec["cmd_preview"]
    assert "harness" not in rec


def test_claude_allow_empty_render_is_allow(audit_cfg, tmp_path: Path):
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
    assert rec["rendered_decision"] == "allow"
    assert rec["decision"] == "allow"


def test_full_body_preserves_newlines(audit_cfg, tmp_path: Path):
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
        config=audit_cfg,
    )
    rec = _read_all(audit_cfg.audit_dir)[0]
    assert rec["cmd_body"] == cmd
    assert "\n" in rec["cmd_body"]
    assert rec["cmd_lines"] == 3


def test_long_command_truncated_without_body(audit_cfg, tmp_path: Path, monkeypatch):
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
        config=audit_cfg,
    )
    rec = _read_all(audit_cfg.audit_dir)[0]
    assert rec["cmd_truncated"] is True
    assert "cmd_body" not in rec
    assert rec["cmd_preview"].endswith(audit.TRUNCATION_SUFFIX)
    assert rec["cmd_chars"] == len(cmd)


def test_match_extra_redacts_home(audit_cfg, tmp_path: Path):
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
        config=audit_cfg,
    )
    rec = _read_all(audit_cfg.audit_dir)[0]
    blob = json.dumps(rec.get("matches") or [], ensure_ascii=False)
    assert home not in blob
    assert "$HOME" in blob


def test_home_path_redacted_in_body(audit_cfg, tmp_path: Path):
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
        config=audit_cfg,
    )
    rec = _read_all(audit_cfg.audit_dir)[0]
    body = rec.get("cmd_body") or ""
    assert home not in body
    assert "$HOME" in body


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
    assert audit.infer_rendered_decision({"decision": "deny"}, engine_decision="ask") == "deny"
    assert (
        audit.infer_rendered_decision(
            {"hookSpecificOutput": {"permissionDecision": "deny"}},
            engine_decision="ask",
        )
        == "deny"
    )
