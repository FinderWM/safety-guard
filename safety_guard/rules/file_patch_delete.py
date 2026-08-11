"""file-patch-delete：apply_patch 删除文件需用户确认。"""
from __future__ import annotations

from ..context import FileToolContext
from .base import Rule, RuleMatch
from .registry import register


@register
class FilePatchDelete(Rule):
    id = "file-patch-delete"
    severity = "medium"
    applies_to = ("Edit",)
    description = "apply_patch 删除文件属于数据丢弃，需用户确认"

    def match(self, ctx: FileToolContext) -> RuleMatch | None:
        if ctx.patch_action != "delete":
            return None
        return RuleMatch(
            rule_id=self.id,
            severity=self.severity,
            reason=f"apply_patch 将删除文件 {ctx.target_path}",
            extra={"target": str(ctx.target_path)},
        )
