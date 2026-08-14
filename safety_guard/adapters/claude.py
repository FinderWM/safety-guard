"""Claude Code Hook 适配器。"""
from __future__ import annotations

import json
from typing import Any

from ..contracts import DecisionResult, NormalizedRequest, Operation
from .base import AdapterCapabilities, project_decision, unknown_request
from . import fields


_EVENT = "PreToolUse"
_READ_TOOLS = frozenset({"Read", "Grep", "Glob"})
_SUPPORTED_TOOLS = frozenset({"Bash", "Write", "Edit", "NotebookEdit"}) | _READ_TOOLS


def _read_path(tool: str, raw_input: dict[str, Any]) -> str:
    if tool in {"Grep", "Glob"}:
        path = raw_input.get("path") or raw_input.get("file_path") or "."
    else:
        path = raw_input.get("file_path") or raw_input.get("target_file") or raw_input.get("path") or ""
    if not isinstance(path, str) or not path.strip():
        raise ValueError("file tool requires a non-empty file_path")
    return path


def _audit_input(tool: str, raw_input: dict[str, Any]) -> str:
    if tool == "Bash":
        command = raw_input.get("command", "")
        return command if isinstance(command, str) else json.dumps(raw_input, ensure_ascii=False)
    path = raw_input.get("file_path") or raw_input.get("notebook_path") or raw_input.get("path")
    return path if isinstance(path, str) else json.dumps(raw_input, ensure_ascii=False)


class ClaudeAdapter:
    name = "claude"
    capabilities = AdapterCapabilities(supports_ask=True)

    def parse(self, stdin_json: dict[str, Any]) -> NormalizedRequest | None:
        event = fields.event_name(stdin_json)
        if event != _EVENT:
            return None

        tool = fields.tool_name(stdin_json)
        if tool is None:
            raise ValueError("missing tool_name")
        if tool not in _SUPPORTED_TOOLS:
            raw_input = fields.safe_tool_input(stdin_json)
            return unknown_request(
                adapter=self.name,
                event=_EVENT,
                tool=tool,
                cwd=fields.cwd(stdin_json),
                raw_input=raw_input,
            )

        raw_input = fields.tool_input(stdin_json)
        cwd = fields.cwd(stdin_json)

        if tool in _READ_TOOLS:
            path = _read_path(tool, raw_input)
            operation = Operation("Read", {"file_path": path})
            internal = "Read"
            audit = path
        else:
            operation = Operation(tool=tool, tool_input=raw_input)
            internal = tool
            audit = _audit_input(tool, raw_input)

        return NormalizedRequest(
            adapter=self.name,
            event=_EVENT,
            tool=internal,
            operations=(operation,),
            cwd=cwd,
            audit_input=audit,
            provenance=("adapter:claude",),
        )

    def render(self, result: DecisionResult) -> dict[str, Any]:
        decision = project_decision(result, self.capabilities)
        if decision in ("allow", "abstain"):
            return {}
        output: dict[str, Any] = {
            "hookSpecificOutput": {
                "hookEventName": _EVENT,
                "permissionDecision": decision,
            }
        }
        if result.reason:
            output["hookSpecificOutput"]["permissionDecisionReason"] = result.reason
        return output
