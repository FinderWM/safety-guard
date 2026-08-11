"""Claude Code Hook 适配器。"""
from __future__ import annotations

import json
import os
from typing import Any

from ..contracts import DecisionResult, NormalizedRequest, Operation


_EVENT = "PreToolUse"
_SUPPORTED_TOOLS = frozenset({"Bash", "Write", "Edit", "NotebookEdit"})


def _audit_input(tool: str, raw_input: dict[str, Any]) -> str:
    if tool == "Bash":
        command = raw_input.get("command", "")
        return command if isinstance(command, str) else json.dumps(raw_input, ensure_ascii=False)
    path = raw_input.get("file_path") or raw_input.get("notebook_path")
    return path if isinstance(path, str) else json.dumps(raw_input, ensure_ascii=False)


class ClaudeAdapter:
    name = "claude"

    def parse(self, stdin_json: dict[str, Any]) -> NormalizedRequest | None:
        event = stdin_json.get("hook_event_name") or stdin_json.get("hookEventName")
        if event != _EVENT:
            return None

        tool = stdin_json.get("tool_name") or stdin_json.get("toolName")
        if tool not in _SUPPORTED_TOOLS:
            raise ValueError(f"unsupported Claude tool: {tool!r}")

        raw_input = stdin_json.get("tool_input") or stdin_json.get("toolInput") or {}
        if not isinstance(raw_input, dict):
            raise ValueError("tool_input must be an object")

        cwd = stdin_json.get("cwd") or os.getcwd()
        if not isinstance(cwd, str):
            raise ValueError("cwd must be a string")

        return NormalizedRequest(
            adapter=self.name,
            event=_EVENT,
            tool=tool,
            operations=(Operation(tool=tool, tool_input=raw_input),),
            cwd=cwd,
            audit_input=_audit_input(tool, raw_input),
        )

    def render(self, result: DecisionResult) -> dict[str, Any]:
        if result.decision == "allow":
            return {}
        output: dict[str, Any] = {
            "hookSpecificOutput": {
                "hookEventName": _EVENT,
                "permissionDecision": result.decision,
            }
        }
        if result.reason:
            output["hookSpecificOutput"]["permissionDecisionReason"] = result.reason
        return output
