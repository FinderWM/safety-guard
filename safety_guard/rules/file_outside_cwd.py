"""file-outside-cwd：Write/Edit/NotebookEdit 目标在 CWD 之外。"""
from __future__ import annotations

from ..context import FileToolContext
from .base import Rule, RuleMatch
from .registry import register


@register
class FileOutsideCwd(Rule):
    id = "file-outside-cwd"
    severity = "medium"
    applies_to = ("Write", "Edit", "NotebookEdit", "Read")
    description = "Write/Edit/NotebookEdit/Read 目标路径在 CWD 之外，需用户确认"

    def match(self, ctx: FileToolContext) -> RuleMatch | None:
        if ctx.classification != "outside":
            return None
        return RuleMatch(
            rule_id=self.id,
            severity=self.severity,
            reason=f"{ctx.tool} 目标 {ctx.target_path} 在 CWD ({ctx.cwd}) 之外",
            extra={"target": str(ctx.target_path)},
        )
