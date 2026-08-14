"""Codex matcher、读取工具与 PermissionRequest 授权边界。"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from safety_guard.adapters.codex import CODEX_HOOK_MATCHER, CodexAdapter
from safety_guard.contracts import DecisionResult, Operation


@pytest.mark.parametrize("tool", ["Read", "view_image"])
def test_read_tools_map_to_read_operation(tool: str, cwd: Path):
    adapter = CodexAdapter(name="codex-pretool", event="PreToolUse")
    request = adapter.parse(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": {"path": "synthetic.png"},
            "cwd": str(cwd),
        }
    )

    assert request is not None
    assert request.operations == (Operation("Read", {"file_path": "synthetic.png"}),)


@pytest.mark.parametrize(
    "tool",
    [
        "Bash",
        "apply_patch",
        "Edit",
        "Write",
        "Read",
        "view_image",
        "mcp__future_server__future_tool",
    ],
)
def test_matcher_covers_modeled_and_unknown_review_tools(tool: str):
    assert re.fullmatch(CODEX_HOOK_MATCHER, tool)


def test_matcher_captures_unknown_local_tool_for_reviewer():
    assert re.fullmatch(CODEX_HOOK_MATCHER, "FutureLocalTool") is not None


def test_permission_allow_does_not_bypass_native_approval():
    adapter = CodexAdapter(name="codex-permission", event="PermissionRequest")
    assert adapter.render(DecisionResult("allow")) == {}


def test_permission_high_deny_is_explicit():
    adapter = CodexAdapter(name="codex-permission", event="PermissionRequest")
    output = adapter.render(DecisionResult("deny", "synthetic policy reason"))
    decision = output["hookSpecificOutput"]["decision"]
    assert decision == {"behavior": "deny", "message": "synthetic policy reason"}
