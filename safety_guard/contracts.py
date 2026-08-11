"""Safety Guard 内部统一协议。"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal


Decision = Literal["allow", "deny", "ask"]


@dataclass(frozen=True)
class Operation:
    """一项可独立执行安全规则检查的规范化操作。"""

    tool: str
    tool_input: dict[str, Any]


@dataclass(frozen=True)
class NormalizedRequest:
    """适配器输出给规则引擎的统一请求。"""

    adapter: str
    event: str
    tool: str
    operations: tuple[Operation, ...]
    cwd: str
    audit_input: str


@dataclass(frozen=True)
class DecisionResult:
    """规则引擎输出给适配器的统一决策。"""

    decision: Decision
    reason: str | None = None
