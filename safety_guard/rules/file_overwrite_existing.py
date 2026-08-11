"""file-overwrite-existing：Write 工具覆盖已存在文件。

Edit 不触发（Edit 是定点 old_string→new_string 替换，符合 CLAUDE.md 允许列表）。
NotebookEdit replace/insert 不触发（单 cell 操作，delete 由 notebook_delete 规则负责）。
"""
from __future__ import annotations

from ..context import FileToolContext
from .base import Rule, RuleMatch
from .registry import register


@register
class FileOverwriteExisting(Rule):
    id = "file-overwrite-existing"
    severity = "medium"
    applies_to = ("Write",)
    description = "Write 工具将覆盖已存在文件（whole-file overwrite）"

    def match(self, ctx: FileToolContext) -> RuleMatch | None:
        if ctx.tool != "Write":
            return None
        if not ctx.file_exists:
            return None
        if ctx.classification == "outside":
            # 由 file_outside_cwd 负责，避免重复列项
            return None
        return RuleMatch(
            rule_id=self.id,
            severity=self.severity,
            reason=f"Write 将整体覆盖已存在文件 {ctx.target_path}",
            extra={"target": str(ctx.target_path)},
        )
