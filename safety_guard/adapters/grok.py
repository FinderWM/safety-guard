"""Grok Code PreToolUse 适配器。"""
from __future__ import annotations

import json
import os
from typing import Any

from ..contracts import DecisionResult, NormalizedRequest, Operation

# Grok stdin 使用 snake_case 事件名；PascalCase 与 matcher 别名一并接受。
_EVENTS = frozenset({"pre_tool_use", "PreToolUse"})
_CANONICAL_EVENT = "PreToolUse"

# matcher 别名（Bash/Write/Edit）与 Grok 真名都映射到内部 Operation.tool。
# 含小写 write：Grok TUI 原生工具名是 write，不是 Write。
_BASH_TOOLS = frozenset({
    "run_terminal_command", "Bash", "bash", "shell", "Shell",
})
_FILE_TOOLS = frozenset({
    "search_replace", "Write", "write", "Edit", "edit", "MultiEdit",
})
_SUPPORTED_TOOLS = _BASH_TOOLS | _FILE_TOOLS


def _event_name(stdin_json: dict[str, Any]) -> str | None:
    event = stdin_json.get("hook_event_name") or stdin_json.get("hookEventName")
    return event if isinstance(event, str) else None


def _tool_name(stdin_json: dict[str, Any]) -> str | None:
    tool = stdin_json.get("tool_name") or stdin_json.get("toolName")
    return tool if isinstance(tool, str) else None


def _tool_input(stdin_json: dict[str, Any]) -> dict[str, Any]:
    raw = stdin_json.get("tool_input") or stdin_json.get("toolInput") or {}
    if not isinstance(raw, dict):
        raise ValueError("tool_input must be an object")
    return raw


def _cwd(stdin_json: dict[str, Any]) -> str:
    cwd = stdin_json.get("cwd") or os.getcwd()
    if not isinstance(cwd, str):
        raise ValueError("cwd must be a string")
    return cwd


def _file_path(raw_input: dict[str, Any]) -> str:
    path = (
        raw_input.get("file_path")
        or raw_input.get("target_file")
        or raw_input.get("path")
    )
    if not isinstance(path, str) or not path.strip():
        raise ValueError("file tool requires a non-empty file_path")
    return path


def _bash_operation(raw_input: dict[str, Any]) -> tuple[Operation, str]:
    command = raw_input.get("command") or raw_input.get("cmd") or ""
    if isinstance(command, list):
        command = " ".join(str(item) for item in command)
    if not isinstance(command, str):
        raise ValueError("Bash command must be a string")
    return Operation("Bash", {"command": command}), command


def _file_operation(raw_tool: str, raw_input: dict[str, Any]) -> tuple[Operation, str]:
    path = _file_path(raw_input)
    # write / 空 old_string 的 search_replace → 整文件 Write；其余定点 Edit。
    if raw_tool in {"write", "Write"}:
        internal = "Write"
    elif raw_tool in {"search_replace", "MultiEdit"}:
        old = raw_input.get("old_string", "")
        if old is None:
            old = ""
        if not isinstance(old, str):
            raise ValueError("old_string must be a string")
        internal = "Write" if old == "" else "Edit"
    elif raw_tool == "Edit" or raw_tool == "edit":
        internal = "Edit"
    else:
        internal = "Edit"
    return Operation(internal, {"file_path": path}), path


def _audit_input(tool: str, raw_input: dict[str, Any], fallback: str) -> str:
    if tool == "Bash":
        return fallback
    return fallback if fallback else json.dumps(raw_input, ensure_ascii=False)


class GrokAdapter:
    name = "grok"

    def parse(self, stdin_json: dict[str, Any]) -> NormalizedRequest | None:
        event = _event_name(stdin_json)
        if event not in _EVENTS:
            return None

        raw_tool = _tool_name(stdin_json)
        if raw_tool is None:
            raise ValueError("missing tool_name")
        if raw_tool not in _SUPPORTED_TOOLS:
            raise ValueError(f"unsupported Grok tool: {raw_tool!r}")

        raw_input = _tool_input(stdin_json)
        cwd = _cwd(stdin_json)

        if raw_tool in _BASH_TOOLS:
            operation, audit = _bash_operation(raw_input)
            internal_tool = "Bash"
        else:
            operation, audit = _file_operation(raw_tool, raw_input)
            internal_tool = operation.tool

        return NormalizedRequest(
            adapter=self.name,
            event=_CANONICAL_EVENT,
            tool=internal_tool,
            operations=(operation,),
            cwd=cwd,
            audit_input=_audit_input(internal_tool, raw_input, audit),
        )

    def render(self, result: DecisionResult) -> dict[str, Any]:
        # Grok PreToolUse 只认顶层 decision allow/deny；无 Claude 式 ask UI。
        # medium(ask) 升为 deny，避免 fail-open 式“提示但不拦”。
        if result.decision == "allow":
            return {"decision": "allow"}
        output: dict[str, Any] = {"decision": "deny"}
        if result.reason:
            output["reason"] = result.reason
        return output
