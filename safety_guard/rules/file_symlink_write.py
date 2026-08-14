"""file-symlink-write：写入现有 symlink 可能越过词法 CWD 边界。"""
from __future__ import annotations

from ..context import FileToolContext
from .base import Rule, RuleMatch
from .registry import register


@register
class FileSymlinkWrite(Rule):
    id = "file-symlink-write"
    severity = "medium"
    applies_to = ("Write", "Edit", "NotebookEdit")
    description = "写入现有符号链接需用户确认"

    def match(self, ctx: FileToolContext) -> RuleMatch | None:
        link = ctx.disk.first_symlink(ctx.target_path, root=ctx.cwd)
        if link is None:
            return None
        try:
            target = ctx.target_path.resolve(strict=False)
        except (OSError, RuntimeError):
            target = ctx.target_path
        return RuleMatch(
            rule_id=self.id,
            severity=self.severity,
            reason=f"{ctx.tool} 目标 {ctx.target_path} 经过符号链接 {link}（实际目标 {target}），需确认写入。",
            extra={"target": str(ctx.target_path), "symlink": str(link), "resolved_target": str(target)},
        )
