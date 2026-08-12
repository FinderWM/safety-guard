"""Grok Adapter 行为测试。"""
from __future__ import annotations

from pathlib import Path


def test_native_run_terminal_command_high_denied(grok, cwd: Path):
    out = grok("run_terminal_command", {"command": "rm -rf /"}, cwd)
    assert out == {
        "decision": "deny",
        "reason": out["reason"],
    }
    assert "bash-rm-root-or-home" in out["reason"]


def test_native_event_snake_case_and_bash_alias(grok, cwd: Path):
    out = grok(
        "Bash",
        {"command": "git push --force origin main"},
        cwd,
        event="pre_tool_use",
        camel=True,
    )
    assert out["decision"] == "deny"
    assert "bash-git-push-force-protected" in out["reason"]


def test_pascal_event_still_works(grok, cwd: Path):
    out = grok(
        "run_terminal_command",
        {"command": "rm -rf /"},
        cwd,
        event="PreToolUse",
        camel=False,
    )
    assert out["decision"] == "deny"
    assert "bash-rm-root-or-home" in out["reason"]


def test_medium_ask_promoted_to_deny(grok, cwd: Path):
    out = grok("run_terminal_command", {"command": "rm -rf ./tmp-dir"}, cwd)
    assert out["decision"] == "deny"
    assert "bash-rm-targeted" in out["reason"]


def test_allow_benign_command(grok, cwd: Path):
    out = grok("run_terminal_command", {"command": "git status"}, cwd)
    assert out == {"decision": "allow"}


def test_search_replace_create_maps_to_write_allow(grok, cwd: Path):
    target = cwd / "new.txt"
    out = grok(
        "search_replace",
        {"file_path": str(target), "old_string": "", "new_string": "hi"},
        cwd,
    )
    assert out == {"decision": "allow"}


def test_search_replace_overwrite_existing_denied(grok, cwd: Path):
    target = cwd / "existing.txt"
    target.write_text("old")
    out = grok(
        "search_replace",
        {"file_path": str(target), "old_string": "", "new_string": "new"},
        cwd,
    )
    assert out["decision"] == "deny"
    assert "file-overwrite-existing" in out["reason"]


def test_search_replace_edit_outside_cwd_denied(grok, cwd: Path):
    out = grok(
        "search_replace",
        {
            "file_path": "/etc/hosts",
            "old_string": "127.0.0.1",
            "new_string": "x",
        },
        cwd,
    )
    assert out["decision"] == "deny"
    assert "file-outside-cwd" in out["reason"]


def test_search_replace_edit_inside_cwd_allow(grok, cwd: Path):
    target = cwd / "x.txt"
    target.write_text("hi")
    out = grok(
        "search_replace",
        {"file_path": str(target), "old_string": "hi", "new_string": "yo"},
        cwd,
    )
    assert out == {"decision": "allow"}


def test_target_file_alias_accepted(grok, cwd: Path):
    target = cwd / "y.txt"
    out = grok(
        "search_replace",
        {"target_file": str(target), "old_string": "", "new_string": "z"},
        cwd,
    )
    assert out == {"decision": "allow"}


def test_unrelated_event_ignored(grok, cwd: Path):
    out = grok(
        "run_terminal_command",
        {"command": "rm -rf /"},
        cwd,
        event="post_tool_use",
    )
    assert out == {}


def test_unsupported_tool_fails_closed(grok, cwd: Path):
    out = grok("read_file", {"target_file": str(cwd / "a.txt")}, cwd)
    assert out["decision"] == "deny"
    assert "unsupported Grok tool" in out["reason"]


def test_malformed_tool_input_fails_closed(cwd: Path):
    from dataclasses import replace

    from safety_guard import runner
    from safety_guard.adapters.registry import get
    from safety_guard.config import load as load_config

    out = runner.run(
        {
            "hookEventName": "pre_tool_use",
            "toolName": "run_terminal_command",
            "toolInput": "not-an-object",
            "cwd": str(cwd),
        },
        adapter=get("grok"),
        config=replace(load_config(), fail_open=False),
    )
    assert out["decision"] == "deny"
    assert "tool_input must be an object" in out["reason"]

def test_native_write_lowercase_create_allow(grok, cwd: Path):
    target = cwd / "from-write.txt"
    out = grok("write", {"file_path": str(target), "content": "hi"}, cwd)
    assert out == {"decision": "allow"}


def test_native_write_lowercase_overwrite_denied(grok, cwd: Path):
    target = cwd / "exists.txt"
    target.write_text("old")
    out = grok("write", {"file_path": str(target), "content": "new"}, cwd)
    assert out["decision"] == "deny"
    assert "file-overwrite-existing" in out["reason"]


def test_edit_dot_grok_config_denied(grok, cwd: Path):
    from pathlib import Path as P
    out = grok(
        "search_replace",
        {
            "file_path": str(P.home() / ".grok" / "config.toml"),
            "old_string": "a",
            "new_string": "b",
        },
        cwd,
    )
    assert out["decision"] == "deny"
    assert "file-critical-path-write" in out["reason"] or "file-outside-cwd" in out["reason"]


def test_read_dot_grok_zone_allowed(grok, cwd: Path):
    out = grok("run_terminal_command", {"command": "ls ~/.grok"}, cwd)
    assert out == {"decision": "allow"}

