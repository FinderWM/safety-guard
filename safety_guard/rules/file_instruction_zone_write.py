"""file-instruction-zone-write：Write/Edit/NotebookEdit 目标在 ~/.claude 或 ~/.agents 等指令区。

CLAUDE.md 第 1 条：这些路径只豁免读，写入仍需确认（防止注入内容偷改全局规则）。
"""
from __future__ import annotations

from ..context import FileToolContext
from .base import Rule, RuleMatch
from .registry import register


@register
class FileInstructionZoneWrite(Rule):
    id = "file-instruction-zone-write"
    severity = "medium"
    applies_to = ("Write", "Edit", "NotebookEdit")
    description = "写入 ~/.claude 或 ~/.agents 等指令区，需用户确认"

    def match(self, ctx: FileToolContext) -> RuleMatch | None:
        if ctx.classification != "instruction-zone":
            return None
        return RuleMatch(
            rule_id=self.id,
            severity=self.severity,
            reason=f"{ctx.tool} 写入指令区路径 {ctx.target_path}（可能偷改全局规则）",
            extra={"target": str(ctx.target_path)},
        )
