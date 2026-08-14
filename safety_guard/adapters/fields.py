"""Hook JSON 字段别名——各平台对 tool_input / cwd 命名不一致。"""
from __future__ import annotations

import os
from typing import Any


_INPUT_KEYS = ("tool_input", "toolInput", "arguments", "input")
_CWD_KEYS = ("cwd", "workspace_path", "working_directory", "workspaceDir", "workspace_dir")
_EVENT_KEYS = ("hook_event_name", "hookEventName")
_TOOL_KEYS = ("tool_name", "toolName")


def event_name(stdin_json: dict[str, Any]) -> str | None:
    for key in _EVENT_KEYS:
        value = stdin_json.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def tool_name(stdin_json: dict[str, Any]) -> str | None:
    for key in _TOOL_KEYS:
        value = stdin_json.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def tool_input(stdin_json: dict[str, Any]) -> dict[str, Any]:
    for key in _INPUT_KEYS:
        raw = stdin_json.get(key)
        if raw is None:
            continue
        if not isinstance(raw, dict):
            raise ValueError("tool_input must be an object")
        return raw
    return {}


def safe_tool_input(stdin_json: dict[str, Any]) -> dict[str, Any]:
    """未知工具也保留一个内存副本；畸形未知参数不应触发检测拦截。"""
    try:
        return tool_input(stdin_json)
    except ValueError:
        return {}


def cwd(stdin_json: dict[str, Any]) -> str:
    for key in _CWD_KEYS:
        value = stdin_json.get(key)
        if isinstance(value, str) and value.strip():
            return value
    fallback = os.getcwd()
    if not isinstance(fallback, str):
        raise ValueError("cwd must be a string")
    return fallback
