"""内置适配器注册与入口选择。"""
from __future__ import annotations

import os

from .base import Adapter
from .claude import ClaudeAdapter
from .codex import CodexAdapter


_DEFAULT = "claude"
_ADAPTER_ENV = "SAFETY_GUARD_ADAPTER"
_REGISTRY: dict[str, Adapter] = {}


def register(adapter: Adapter) -> None:
    if not adapter.name:
        raise ValueError("adapter name must not be empty")
    if adapter.name in _REGISTRY:
        raise ValueError(f"duplicate adapter: {adapter.name}")
    _REGISTRY[adapter.name] = adapter


def available() -> list[str]:
    return sorted(_REGISTRY)


def get(name: str) -> Adapter:
    adapter = _REGISTRY.get(name)
    if adapter is None:
        raise ValueError(f"unknown adapter: {name!r}, available: {available()}")
    return adapter


def select(name: str | None = None) -> Adapter:
    return get(name or os.environ.get(_ADAPTER_ENV) or _DEFAULT)


register(ClaudeAdapter())
register(CodexAdapter(name="codex-pretool", event="PreToolUse"))
register(CodexAdapter(name="codex-permission", event="PermissionRequest"))
