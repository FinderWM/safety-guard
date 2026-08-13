"""真实 hook 接入缺口回归。合成路径 / 临时目录，不碰本机真实数据。"""
from __future__ import annotations

from pathlib import Path

import pytest

from safety_guard import runner
from safety_guard.adapters.registry import get
from safety_guard.config import load as load_config
from dataclasses import replace


PROBE = "/nonexistent-probe/secret"


def test_path_extension_allows(bash, cwd: Path):
    for cmd in (
        'PATH="$PATH" git status',
        'PATH="./node_modules/.bin:$PATH" true',
        'export PATH="/usr/local/bin:$PATH"',
        'env PATH="/opt/bin:$PATH" ls',
    ):
        decision, reason = bash(cmd, cwd)
        assert decision == "allow", f"{cmd!r} -> {decision} ({reason})"


def test_path_replace_still_denies(bash, cwd: Path):
    decision, reason = bash("PATH=/tmp/evil cat ./file", cwd)
    assert decision == "deny"
    assert "bash-env-subversion" in (reason or "")


def test_virtual_device_read_allows(bash, cwd: Path):
    for cmd in ("cat /dev/null", "dd if=/dev/zero of=./out.dat count=1"):
        decision, reason = bash(cmd, cwd)
        assert "bash-outside-cwd-read" not in (reason or ""), f"{cmd!r} 误报读：{reason}"


def test_dd_overwrite_existing_asks(bash, cwd: Path):
    target = cwd / "existing.txt"
    target.write_text("old")
    decision, reason = bash("dd if=/dev/zero of=existing.txt count=1", cwd)
    assert decision == "ask"
    assert "bash-util-overwrite-existing" in (reason or "")


def test_truncate_overwrite_asks(bash, cwd: Path):
    target = cwd / "existing.txt"
    target.write_text("old")
    decision, reason = bash("truncate -s 0 existing.txt", cwd)
    assert decision == "ask"
    assert "bash-util-overwrite-existing" in (reason or "")


def test_file_uri_read_asks(bash, cwd: Path):
    decision, reason = bash(f"curl {PROBE.replace('/nonexistent-probe', 'file:///nonexistent-probe')}", cwd)
    assert decision == "ask"
    assert "bash-outside-cwd-read" in (reason or "")


@pytest.mark.parametrize(
    "command,rule_id",
    [
        ("unlink ./victim.txt", "bash-rm-targeted"),
        ("shred -u ./victim.txt", "bash-rm-targeted"),
        ("trash ./victim.txt", "bash-rm-targeted"),
        ("find . -delete", "bash-find-exec-rm"),
        ("git restore .", "bash-git-destructive"),
        ("git checkout -- existing.txt", "bash-git-destructive"),
    ],
)
def test_delete_and_discard_ask(bash, cwd: Path, command: str, rule_id: str):
    decision, reason = bash(command, cwd)
    assert decision == "ask", f"{command!r} -> {decision} ({reason})"
    assert rule_id in (reason or "")


def test_git_restore_staged_allows(bash, cwd: Path):
    decision, reason = bash("git restore --staged .", cwd)
    assert "bash-git-destructive" not in (reason or "")


def test_git_push_delete_protected_denies(bash, cwd: Path):
    for cmd in (
        "git push origin :main",
        "git push --delete origin main",
        "git push origin --delete master",
    ):
        decision, reason = bash(cmd, cwd)
        assert decision == "deny", f"{cmd!r} -> {decision} ({reason})"
        assert "bash-git-push-force-protected" in (reason or "")


def test_interpreter_write_critical_denies(bash, cwd: Path):
    decision, reason = bash(
        "python3 -c 'open(\"~/.grok/config.toml\",\"w\").write(\"x\")'",
        cwd,
    )
    assert decision == "deny"
    assert "bash-interpreter-write" in (reason or "")


def test_interpreter_overwrite_in_cwd_asks(bash, cwd: Path):
    (cwd / "existing.txt").write_text("old")
    decision, reason = bash(
        "python3 -c 'open(\"existing.txt\",\"w\").write(\"x\")'",
        cwd,
    )
    assert decision == "ask"
    assert "bash-interpreter-write" in (reason or "")


def test_interpreter_read_literal_not_write(bash, cwd: Path):
    decision, reason = bash(
        "python3 -c 'print(open(\"existing.txt\").read())'",
        cwd,
    )
    assert "bash-interpreter-write" not in (reason or "")


def test_grok_read_file_outside_denied(cwd: Path):
    out = runner.run(
        {
            "hookEventName": "pre_tool_use",
            "toolName": "read_file",
            "toolInput": {"target_file": PROBE},
            "cwd": str(cwd),
        },
        adapter=get("grok"),
        config=replace(load_config(), fail_open=False),
    )
    assert out["decision"] == "deny"
    assert "file-outside-cwd" in (out.get("reason") or "")


def test_grok_list_dir_and_grep_inside_allow(cwd: Path):
    cfg = replace(load_config(), fail_open=False)
    adapter = get("grok")
    inside = cwd / "a.txt"
    inside.write_text("hi")
    for tool, payload in (
        ("list_dir", {"target_directory": str(cwd)}),
        ("grep", {"pattern": "hi", "path": str(cwd)}),
        ("read_file", {"target_file": str(inside)}),
    ):
        out = runner.run(
            {
                "hookEventName": "pre_tool_use",
                "toolName": tool,
                "toolInput": payload,
                "cwd": str(cwd),
            },
            adapter=adapter,
            config=cfg,
        )
        assert out == {"decision": "allow"}, f"{tool} -> {out}"


def test_grok_arguments_alias_catches_rm_root(cwd: Path):
    out = runner.run(
        {
            "hookEventName": "pre_tool_use",
            "toolName": "run_terminal_command",
            "arguments": {"command": "rm -rf /"},
            "cwd": str(cwd),
        },
        adapter=get("grok"),
        config=replace(load_config(), fail_open=False),
    )
    assert out["decision"] == "deny"
    assert "bash-rm-root-or-home" in (out.get("reason") or "")


def test_claude_read_outside_asks(cwd: Path):
    out = runner.run(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": PROBE},
            "cwd": str(cwd),
        },
        adapter=get("claude"),
        config=replace(load_config(), fail_open=False),
    )
    decision = out["hookSpecificOutput"]["permissionDecision"]
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert decision == "ask"
    assert "file-outside-cwd" in reason


def test_claude_grep_default_path_allows(cwd: Path):
    out = runner.run(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Grep",
            "tool_input": {"pattern": "foo"},
            "cwd": str(cwd),
        },
        adapter=get("claude"),
        config=replace(load_config(), fail_open=False),
    )
    assert out == {}
