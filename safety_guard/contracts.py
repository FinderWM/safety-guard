"""Safety Guard 内部统一协议。"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


Decision = Literal["allow", "deny", "ask", "abstain"]
RequestClassification = Literal["modeled", "known-noop", "unknown"]
DecisionSource = Literal["policy", "reviewer", "internal"]


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
    classification: RequestClassification = "modeled"
    # 未知载荷只在当前进程内保留，默认不会进入审计或 reviewer 的原始请求。
    raw_input: dict[str, Any] | None = None
    input_keys: tuple[str, ...] = field(default_factory=tuple)
    provenance: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class DecisionResult:
    """规则引擎输出给适配器的统一决策。

    decision：交给 adapter.render 的结论（策略 dry_run 时通常为 allow；未知 reviewer 仍可 abstain）。
    engine_decision：规则真实结论（审计用）；默认与 decision 相同。
    audit_matches：供审计落盘的规则命中（adapter 不读）。
    """

    decision: Decision
    reason: str | None = None
    engine_decision: Decision | None = None
    audit_matches: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    error_type: str | None = None
    error_detail: str | None = None
    review: dict[str, Any] = field(default_factory=dict)
    decision_source: DecisionSource = "policy"

    def resolved_engine_decision(self) -> Decision:
        return self.engine_decision or self.decision
