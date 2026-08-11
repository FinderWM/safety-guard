"""外部 Hook 协议适配器。"""
from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from ..contracts import DecisionResult, NormalizedRequest


@runtime_checkable
class Adapter(Protocol):
    name: str

    def parse(self, stdin_json: dict[str, Any]) -> NormalizedRequest | None:
        """解析目标事件；非本适配器事件返回 None，非法输入必须抛异常。"""
        ...

    def render(self, result: DecisionResult) -> dict[str, Any]:
        """把统一决策编码成平台原生 stdout JSON。"""
        ...
