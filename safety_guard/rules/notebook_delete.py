"""notebook-delete：NotebookEdit 在 edit_mode=delete 时整 cell 删除。

CLAUDE.md 第 2 条点名要求确认。
"""
from __future__ import annotations

from ..context import FileToolContext
from .base import Rule, RuleMatch
from .registry import register


@register
class NotebookDelete(Rule):
    id = "notebook-delete"
    severity = "medium"
    applies_to = ("NotebookEdit",)
    description = "NotebookEdit edit_mode=delete 会丢弃单元格内容"

    def match(self, ctx: FileToolContext) -> RuleMatch | None:
        if ctx.edit_mode != "delete":
            return None
        return RuleMatch(
            rule_id=self.id,
            severity=self.severity,
            reason=f"NotebookEdit 将删除 {ctx.target_path} 中的某个单元格（数据将丢失）",
            extra={"target": str(ctx.target_path)},
        )
