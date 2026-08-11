"""安全规则协议。"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar, Literal

from ..context import ToolContext


Severity = Literal["high", "medium"]


@dataclass
class RuleMatch:
    rule_id: str
    severity: Severity
    reason: str
    extra: dict = field(default_factory=dict)


class Rule:
    id: ClassVar[str] = ""
    severity: ClassVar[Severity] = "medium"
    applies_to: ClassVar[tuple[str, ...]] = ()
    description: ClassVar[str] = ""

    def match(self, ctx: ToolContext) -> RuleMatch | None:
        raise NotImplementedError
