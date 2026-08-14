"""Codex PreToolUse 与 PermissionRequest 适配器。"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

from ..contracts import DecisionResult, NormalizedRequest, Operation
from . import fields


_PRETOOL_EVENT = "PreToolUse"
_PERMISSION_EVENT = "PermissionRequest"
_TOOL_MAP = {
    "Bash": "Bash",
    "bash": "Bash",
    "shell": "Bash",
    "apply_patch": "ApplyPatch",
    # Codex 的 apply_patch 在 Hook stdin 中仍使用 canonical tool_name；保留
    # 这些别名兼容旧载荷和手工回放。
    "Edit": "Edit",
    "Write": "Write",
}
_FILE_TOOLS = frozenset({"Edit", "Write"})
_PATCH_BEGIN = "*** Begin Patch"
_PATCH_END = "*** End Patch"
_PATCH_OP_RE = re.compile(r"^\*\*\* (Add|Delete|Update) File: (.+)$")
_PATCH_MOVE_RE = re.compile(r"^\*\*\* Move to: (.+)$")


@dataclass(frozen=True)
class _McpPathField:
    """一个已核实的 MCP 本机路径字段及其内部安全语义。"""

    key: str
    operation_tool: Literal["Read", "Write", "Edit"]
    required: bool = False
    multiple: bool = False
    external_upload: bool = False
    path_kind: Literal["file", "directory"] = "file"


@dataclass(frozen=True)
class _McpPathTool:
    fields: tuple[_McpPathField, ...]
    require_any: bool = False
    mutually_exclusive: bool = False


# 不匹配泛化的 mcp__.*：不同 MCP 服务的名称和参数并不共享安全语义。
# 这些工具和字段来自当前 Codex 实际暴露的 Chrome DevTools MCP 输入 schema。
_MCP_PATH_TOOLS = {
    "mcp__chrome_devtools__evaluate_script": _McpPathTool(
        (_McpPathField("filePath", "Write"),),
    ),
    "mcp__chrome_devtools__get_network_request": _McpPathTool(
        (
            _McpPathField("requestFilePath", "Write"),
            _McpPathField("responseFilePath", "Write"),
        ),
    ),
    # Lighthouse 会在目录中写 report.html/report.json；用 Edit 保留写入边界检查，
    # 同时避免把正常复用的报告目录误判成「整文件覆盖」。
    "mcp__chrome_devtools__lighthouse_audit": _McpPathTool(
        (_McpPathField("outputDirPath", "Edit", path_kind="directory"),),
    ),
    "mcp__chrome_devtools__performance_start_trace": _McpPathTool(
        (_McpPathField("filePath", "Write"),),
    ),
    "mcp__chrome_devtools__performance_stop_trace": _McpPathTool(
        (_McpPathField("filePath", "Write"),),
    ),
    "mcp__chrome_devtools__take_heapsnapshot": _McpPathTool(
        (_McpPathField("filePath", "Write", required=True),),
    ),
    "mcp__chrome_devtools__take_screenshot": _McpPathTool(
        (_McpPathField("filePath", "Write"),),
    ),
    "mcp__chrome_devtools__take_snapshot": _McpPathTool(
        (_McpPathField("filePath", "Write"),),
    ),
    # 当前 Codex schema 是 filePath；上游新版 schema 是 filePaths。两者都识别，
    # 但同一次调用只能出现一种，防止其中一组路径绕过检查。
    "mcp__chrome_devtools__upload_file": _McpPathTool(
        (
            _McpPathField("filePath", "Read", external_upload=True),
            _McpPathField("filePaths", "Read", multiple=True, external_upload=True),
        ),
        require_any=True,
        mutually_exclusive=True,
    ),
}

# 当前 Chrome DevTools MCP 中不读写本机路径的工具。显式识别它们是为了在
# Adapter 被直接调用时保留正常使用；用户 matcher 无需把这些工具送入文件检测。
_MCP_NO_PATH_TOOLS = frozenset({
    "mcp__chrome_devtools__click",
    "mcp__chrome_devtools__close_page",
    "mcp__chrome_devtools__drag",
    "mcp__chrome_devtools__emulate",
    "mcp__chrome_devtools__fill",
    "mcp__chrome_devtools__fill_form",
    "mcp__chrome_devtools__get_console_message",
    "mcp__chrome_devtools__handle_dialog",
    "mcp__chrome_devtools__hover",
    "mcp__chrome_devtools__list_console_messages",
    "mcp__chrome_devtools__list_network_requests",
    "mcp__chrome_devtools__list_pages",
    "mcp__chrome_devtools__navigate_page",
    "mcp__chrome_devtools__new_page",
    "mcp__chrome_devtools__performance_analyze_insight",
    "mcp__chrome_devtools__press_key",
    "mcp__chrome_devtools__resize_page",
    "mcp__chrome_devtools__select_page",
    "mcp__chrome_devtools__type_text",
    "mcp__chrome_devtools__wait_for",
})


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
        raw_line = lines[index]
        directive = raw_line.rstrip() if raw_line.startswith("*** ") else None
        if directive == _PATCH_END:
            seen_end = True
            index += 1
            break

        operation = _PATCH_OP_RE.match(directive) if directive is not None else None
        if operation:
            action = operation.group(1).lower()
            path = _clean_path(operation.group(2))
            index += 1
            if action == "update" and index < len(lines):
                next_line = lines[index]
                move = (
                    _PATCH_MOVE_RE.match(next_line.rstrip())
                    if next_line.startswith("*** ")
                    else None
                )
                if move:
                    targets.append({"file_path": path, "action": "delete"})
                    targets.append({"file_path": _clean_path(move.group(1)), "action": "add"})
                    index += 1
                    continue
            targets.append({"file_path": path, "action": action})
            continue

        if directive is None:
            index += 1
            continue
        if _PATCH_MOVE_RE.match(directive):
            raise ValueError("Move to must follow Update File")
        raise ValueError(f"unsupported patch directive: {raw_line}")

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


def _file_operation(tool: str, raw_input: dict[str, Any]) -> tuple[Operation, str]:
    path = raw_input.get("file_path") or raw_input.get("target_file") or raw_input.get("path")
    if not isinstance(path, str) or not path.strip():
        raise ValueError("file tool requires a non-empty file_path")
    return Operation(tool, {"file_path": path}), path


def _mcp_path_operation(
    raw_tool: str,
    raw_input: dict[str, Any],
) -> tuple[tuple[Operation, ...], str]:
    spec = _MCP_PATH_TOOLS[raw_tool]
    operations: list[Operation] = []
    audit_paths: list[str] = []
    populated_fields = 0

    for field in spec.fields:
        value = raw_input.get(field.key)
        if value is None:
            if field.required:
                raise ValueError(f"{raw_tool} requires a non-empty {field.key}")
            continue

        populated_fields += 1
        if field.multiple:
            if not isinstance(value, list) or not value:
                raise ValueError(f"{raw_tool} {field.key} must be a non-empty array of strings")
            paths = value
        else:
            paths = [value]

        for path in paths:
            if not isinstance(path, str) or not path.strip():
                raise ValueError(f"{raw_tool} {field.key} must contain non-empty strings")
            operation_input: dict[str, Any] = {"file_path": path}
            if field.path_kind != "file":
                operation_input["path_kind"] = field.path_kind
            if field.external_upload:
                operation_input["external_upload"] = True
                operation_input["source_tool"] = raw_tool
            operations.append(Operation(field.operation_tool, operation_input))
            audit_paths.append(path)

    if spec.mutually_exclusive and populated_fields > 1:
        keys = ", ".join(field.key for field in spec.fields)
        raise ValueError(f"{raw_tool} accepts only one of: {keys}")
    if spec.require_any and not operations:
        keys = ", ".join(field.key for field in spec.fields)
        raise ValueError(f"{raw_tool} requires one of: {keys}")

    # 可选路径缺省时，MCP 会内联返回结果或使用自身临时目录。
    return tuple(operations), " | ".join(audit_paths) if audit_paths else raw_tool


def _unknown_request(
    *,
    adapter: str,
    event: str,
    raw_tool: str | None,
    cwd: str,
) -> NormalizedRequest:
    """保留未知工具检测入口；当前策略只审计归一化结果，不拦截。"""
    tool = raw_tool if isinstance(raw_tool, str) and raw_tool else "unknown"
    return NormalizedRequest(
        adapter=adapter,
        event=event,
        tool=tool,
        operations=(),
        cwd=cwd,
        audit_input=tool,
    )


@dataclass(frozen=True)
class CodexAdapter:
    name: str
    event: Literal["PreToolUse", "PermissionRequest"]

    def parse(self, stdin_json: dict[str, Any]) -> NormalizedRequest | None:
        event = fields.event_name(stdin_json)
        if event != self.event:
            return None

        raw_tool = fields.tool_name(stdin_json)
        cwd = fields.cwd(stdin_json)

        if raw_tool not in _MCP_PATH_TOOLS and raw_tool not in _MCP_NO_PATH_TOOLS and raw_tool not in _TOOL_MAP:
            return _unknown_request(
                adapter=self.name,
                event=self.event,
                raw_tool=raw_tool,
                cwd=cwd,
            )

        raw_input = fields.tool_input(stdin_json)

        if raw_tool in _MCP_PATH_TOOLS:
            operations, audit_input = _mcp_path_operation(raw_tool, raw_input)
            tool = raw_tool
        elif raw_tool in _MCP_NO_PATH_TOOLS:
            operations = ()
            audit_input = raw_tool
            tool = raw_tool
        else:
            tool = _TOOL_MAP.get(raw_tool)
            assert tool is not None

        if tool == "Bash":
            command = raw_input.get("command") or raw_input.get("cmd") or ""
            if isinstance(command, list):
                command = " ".join(str(item) for item in command)
            if not isinstance(command, str):
                raise ValueError("Bash command must be a string")
            operations = (Operation("Bash", {"command": command}),)
            audit_input = command
        elif tool in _FILE_TOOLS:
            operation, audit_input = _file_operation(tool, raw_input)
            operations = (operation,)
        elif tool == "ApplyPatch":
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
        # Codex PreToolUse/PermissionRequest 均无可靠的「ask 再确认」闸门可依赖：
        # medium 若只回 systemMessage 会被静默放行。与 Grok 对齐：ask 升 deny。
        if result.decision == "allow":
            return {}
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
