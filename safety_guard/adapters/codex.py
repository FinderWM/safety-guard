"""Codex PreToolUse 与 PermissionRequest 适配器。"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, Literal

from ..contracts import DecisionResult, NormalizedRequest, Operation


_PRETOOL_EVENT = "PreToolUse"
_PERMISSION_EVENT = "PermissionRequest"
_TOOL_MAP = {
    "Bash": "Bash",
    "bash": "Bash",
    "shell": "Bash",
    "apply_patch": "ApplyPatch",
}
_PATCH_BEGIN = "*** Begin Patch"
_PATCH_END = "*** End Patch"
_PATCH_OP_RE = re.compile(r"^\*\*\* (Add|Delete|Update) File: (.+)$")
_PATCH_MOVE_RE = re.compile(r"^\*\*\* Move to: (.+)$")


def _clean_path(raw: str) -> str:
    path = raw.strip()
    if len(path) >= 2 and ((path[0] == path[-1] == '"') or (path[0] == path[-1] == "'")):
        path = path[1:-1].strip()
    if not path:
        raise ValueError("empty patch file path")
    return path


def parse_apply_patch(patch_text: str) -> list[dict[str, str]]:
    """解析 apply_patch 文本，返回规范化文件操作。"""
    if not isinstance(patch_text, str):
        raise ValueError("patch must be a string")
    if not patch_text.strip():
        return []

    lines = patch_text.splitlines()
    index = 0
    while index < len(lines) and not lines[index].strip():
        index += 1
    if index >= len(lines) or lines[index].strip() != _PATCH_BEGIN:
        raise ValueError("missing *** Begin Patch")
    index += 1

    targets: list[dict[str, str]] = []
    seen_end = False
    while index < len(lines):
        line = lines[index].strip()
        if line == _PATCH_END:
            seen_end = True
            index += 1
            break

        operation = _PATCH_OP_RE.match(line)
        if operation:
            action = operation.group(1).lower()
            path = _clean_path(operation.group(2))
            index += 1
            if action == "update" and index < len(lines):
                move = _PATCH_MOVE_RE.match(lines[index].strip())
                if move:
                    targets.append({"file_path": path, "action": "delete"})
                    targets.append({"file_path": _clean_path(move.group(1)), "action": "add"})
                    index += 1
                    continue
            targets.append({"file_path": path, "action": action})
            continue

        if _PATCH_MOVE_RE.match(line):
            raise ValueError("Move to must follow Update File")
        index += 1

    if not seen_end:
        raise ValueError("missing *** End Patch")
    while index < len(lines):
        if lines[index].strip():
            raise ValueError("unexpected content after *** End Patch")
        index += 1
    return targets


def _patch_operations(targets: list[dict[str, str]]) -> tuple[Operation, ...]:
    operations: list[Operation] = []
    for target in targets:
        action = target["action"]
        path = target["file_path"]
        if action == "add":
            operations.append(Operation("Write", {"file_path": path, "patch_action": "add"}))
        elif action == "update":
            operations.append(Operation("Edit", {"file_path": path, "patch_action": "update"}))
        elif action == "delete":
            operations.append(Operation("Edit", {"file_path": path, "patch_action": "delete"}))
        else:
            raise ValueError(f"unknown patch action: {action}")
    return tuple(operations)


@dataclass(frozen=True)
class CodexAdapter:
    name: str
    event: Literal["PreToolUse", "PermissionRequest"]

    def parse(self, stdin_json: dict[str, Any]) -> NormalizedRequest | None:
        event = stdin_json.get("hook_event_name") or stdin_json.get("hookEventName")
        if event != self.event:
            return None

        raw_tool = stdin_json.get("tool_name") or stdin_json.get("toolName")
        tool = _TOOL_MAP.get(raw_tool)
        if tool is None:
            raise ValueError(f"unsupported Codex tool: {raw_tool!r}")

        raw_input = stdin_json.get("tool_input") or stdin_json.get("toolInput") or {}
        if not isinstance(raw_input, dict):
            raise ValueError("tool_input must be an object")
        cwd = stdin_json.get("cwd") or os.getcwd()
        if not isinstance(cwd, str):
            raise ValueError("cwd must be a string")

        if tool == "Bash":
            command = raw_input.get("command") or raw_input.get("cmd") or ""
            if isinstance(command, list):
                command = " ".join(str(item) for item in command)
            if not isinstance(command, str):
                raise ValueError("Bash command must be a string")
            operations = (Operation("Bash", {"command": command}),)
            audit_input = command
        else:
            patch_text = raw_input.get("command") or raw_input.get("patch") or ""
            if not isinstance(patch_text, str):
                raise ValueError("patch must be a string")
            operations = _patch_operations(parse_apply_patch(patch_text))
            audit_input = patch_text

        return NormalizedRequest(
            adapter=self.name,
            event=self.event,
            tool=tool,
            operations=operations,
            cwd=cwd,
            audit_input=audit_input,
        )

    def render(self, result: DecisionResult) -> dict[str, Any]:
        if result.decision == "allow":
            return {}
        if result.decision == "ask":
            return {"systemMessage": result.reason} if result.reason else {}
        if self.event == _PRETOOL_EVENT:
            output: dict[str, Any] = {
                "hookSpecificOutput": {
                    "hookEventName": _PRETOOL_EVENT,
                    "permissionDecision": "deny",
                }
            }
            if result.reason:
                output["hookSpecificOutput"]["permissionDecisionReason"] = result.reason
            return output

        output = {
            "hookSpecificOutput": {
                "hookEventName": _PERMISSION_EVENT,
                "decision": {"behavior": "deny"},
            }
        }
        if result.reason:
            output["hookSpecificOutput"]["decision"]["message"] = result.reason
        return output
