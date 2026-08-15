"""Codex Hook 集成测试。"""
from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

import pytest


HOOKS_DIR = Path(__file__).resolve().parents[2]
if str(HOOKS_DIR) not in sys.path:
    sys.path.insert(0, str(HOOKS_DIR))

from safety_guard import config as config_module  # noqa: E402
from safety_guard import runner  # noqa: E402
from safety_guard.adapters.registry import get  # noqa: E402
from safety_guard.config import Config  # noqa: E402


@pytest.fixture
def cwd(tmp_path: Path) -> Path:
    return tmp_path


def _run(data: dict, adapter_name: str, config: Config | None = None) -> dict:
    effective_config = config or replace(config_module.load(), fail_open=False)
    return runner.run(data, adapter=get(adapter_name), config=effective_config)


def _pretool(command: str, cwd: Path, tool_name: str = "Bash") -> dict:
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": {"command": command},
        "cwd": str(cwd),
    }


def _permission(command: str, cwd: Path, tool_name: str = "Bash") -> dict:
    return {
        "hook_event_name": "PermissionRequest",
        "tool_name": tool_name,
        "tool_input": {"command": command},
        "cwd": str(cwd),
    }


def test_pretool_high_risk_denies(cwd: Path):
    out = _run(_pretool("git push --force origin main", cwd), "codex-pretool")
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert out["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert "bash-git-push-force-protected" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_pretool_medium_risk_warns_without_authorizing(cwd: Path):
    out = _run(_pretool("rm -rf /tmp/foo", cwd), "codex-pretool")
    assert "systemMessage" in out
    assert out["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert "additionalContext" in out["hookSpecificOutput"]
    assert "permissionDecision" not in out["hookSpecificOutput"]


def test_permission_high_risk_denies(cwd: Path):
    out = _run(_permission("rm ~/.codex/config.toml", cwd), "codex-permission")
    decision = out["hookSpecificOutput"]["decision"]
    assert out["hookSpecificOutput"]["hookEventName"] == "PermissionRequest"
    assert decision["behavior"] == "deny"
    assert "bash-disable-safety-hook" in decision["message"]


def test_permission_medium_risk_preserves_native_approval(cwd: Path):
    out = _run(_permission("rm -rf /tmp/foo", cwd), "codex-permission")
    assert out == {}


def test_pretool_apply_patch_critical_target_warns(cwd: Path):
    patch = """*** Begin Patch
*** Update File: ~/.codex/config.toml
@@
-old
+new
*** End Patch
"""
    out = _run(_pretool(patch, cwd, tool_name="apply_patch"), "codex-pretool")
    hs = out["hookSpecificOutput"]
    assert hs["hookEventName"] == "PreToolUse"
    assert "file-critical-path-write" in hs["additionalContext"]
    assert "permissionDecision" not in hs


def test_permission_apply_patch_critical_target_preserves_native_approval(cwd: Path):
    patch = """*** Begin Patch
*** Update File: ~/.codex/config.toml
@@
-old
+new
*** End Patch
"""
    out = _run(_permission(patch, cwd, tool_name="apply_patch"), "codex-permission")
    assert out == {}


def test_permission_apply_patch_critical_operation_preserves_native_approval(cwd: Path):
    safe = cwd / "safe.txt"
    safe.write_text("old")
    patch = f"""*** Begin Patch
*** Update File: {safe}
@@
-old
+new
*** Update File: ~/.codex/config.toml
@@
-old
+new
*** End Patch
"""
    out = _run(_permission(patch, cwd, tool_name="apply_patch"), "codex-permission")
    assert out == {}


def test_permission_apply_patch_delete_preserves_native_approval(cwd: Path):
    target = cwd / "legacy.txt"
    target.write_text("legacy")
    patch = f"""*** Begin Patch
*** Delete File: {target}
*** End Patch
"""
    out = _run(_permission(patch, cwd, tool_name="apply_patch"), "codex-permission")
    assert out == {}


def test_pretool_bash_parse_error_is_audited(cwd: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    # 这条正是在测审计写入本身，得关掉 conftest 给全局设的 SAFETY_GUARD_NO_AUDIT
    monkeypatch.delenv("SAFETY_GUARD_NO_AUDIT", raising=False)
    cfg = replace(config_module.load(), fail_open=False, audit_dir=tmp_path / "audit")
    out = _run(_pretool("apply_patch <<'\n", cwd), "codex-pretool", config=cfg)

    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    logs = list((tmp_path / "audit").glob("audit-*.jsonl"))
    assert len(logs) == 1
    record = logs[0].read_text(encoding="utf-8")
    assert '"decision": "deny"' in record
    assert '"error_type": "bash_parse_error"' in record
    assert '"cmd_chars":' in record
    assert '"error_detail":' not in record


@pytest.mark.parametrize("command", [
    "apply_patch <<'PATCH'\n*** Begin Patch\n*** End Patch\nPATCH",
    'apply_patch <<"PATCH"\n*** Begin Patch\n*** End Patch\nPATCH',
    "apply_patch <<'\\PATCH'\n*** Begin Patch\n*** End Patch\nPATCH",
])
def test_pretool_apply_patch_heredoc_delimiters_are_allowed(cwd: Path, command: str):
    assert _run(_pretool(command, cwd), "codex-pretool") == {}
