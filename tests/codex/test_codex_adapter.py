"""Codex Adapter 行为测试。"""
from __future__ import annotations

from pathlib import Path


def _patch(body: str) -> str:
    return f"*** Begin Patch\n{body}\n*** End Patch\n"


def test_pretool_high_is_denied(pretool, cwd: Path):
    out = pretool("Bash", {"command": "git push --force origin main"}, cwd)
    assert out["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "bash-git-push-force-protected" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_pretool_medium_is_denied(pretool, cwd: Path):
    out = pretool("Bash", {"command": "rm -rf ./tmp-dir"}, cwd)
    hs = out["hookSpecificOutput"]
    assert hs["hookEventName"] == "PreToolUse"
    assert hs["permissionDecision"] == "deny"
    assert "bash-rm-targeted" in hs["permissionDecisionReason"]


def test_permission_medium_is_denied(permission, cwd: Path):
    out = permission("Bash", {"command": "rm -rf ./tmp-dir"}, cwd)
    hs = out["hookSpecificOutput"]
    assert hs["hookEventName"] == "PermissionRequest"
    assert hs["decision"]["behavior"] == "deny"
    assert "bash-rm-targeted" in hs["decision"]["message"]


def test_permission_high_is_denied(permission, cwd: Path):
    out = permission("Bash", {"command": "rm -rf /"}, cwd)
    hs = out["hookSpecificOutput"]
    assert hs["hookEventName"] == "PermissionRequest"
    assert hs["decision"]["behavior"] == "deny"
    assert "bash-rm-root-or-home" in hs["decision"]["message"]


def test_apply_patch_critical_path_denied(permission, cwd: Path):
    cmd = _patch(
        """*** Update File: ~/.codex/config.toml
@@
-old
+new"""
    )
    out = permission("apply_patch", {"command": cmd}, cwd)
    hs = out["hookSpecificOutput"]
    assert hs["hookEventName"] == "PermissionRequest"
    assert hs["decision"]["behavior"] == "deny"
    assert "file-critical-path-write" in hs["decision"]["message"]


def test_apply_patch_delete_is_denied(permission, cwd: Path):
    victim = cwd / "old.txt"
    victim.write_text("x")
    cmd = _patch("*** Delete File: old.txt")
    out = permission("apply_patch", {"command": cmd}, cwd)
    hs = out["hookSpecificOutput"]
    assert hs["decision"]["behavior"] == "deny"
    assert "file-patch-delete" in hs["decision"]["message"]


def test_apply_patch_any_high_wins(permission, cwd: Path):
    safe = cwd / "safe.txt"
    safe.write_text("ok")
    cmd = _patch(
        """*** Update File: safe.txt
@@
-ok
+ok2
*** Update File: ~/.codex/config.toml
@@
-x
+y"""
    )
    out = permission("apply_patch", {"command": cmd}, cwd)
    hs = out["hookSpecificOutput"]
    assert hs["decision"]["behavior"] == "deny"
    assert "file-critical-path-write" in hs["decision"]["message"]


def test_apply_patch_parse_error_fails_closed(pretool, cwd: Path):
    out = pretool("apply_patch", {"command": "*** Update File: x.txt\n*** End Patch"}, cwd)
    hs = out["hookSpecificOutput"]
    assert hs["permissionDecision"] == "deny"
    assert "hook 输入解析失败" in hs["permissionDecisionReason"]
