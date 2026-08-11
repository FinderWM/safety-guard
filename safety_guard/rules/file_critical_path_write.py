"""file-critical-path-write：file 工具命中 critical_paths 时直接拒绝。"""
from __future__ import annotations

from ..context import FileToolContext
from ..paths import is_critical
from .base import Rule, RuleMatch
from .registry import register


@register
class FileCriticalPathWrite(Rule):
    id = "file-critical-path-write"
    severity = "high"
    applies_to = ("Write", "Edit", "NotebookEdit")
    description = "写入 critical_paths（如 ~/.codex/config.toml）直接拒绝"

    def match(self, ctx: FileToolContext) -> RuleMatch | None:
        if not is_critical(ctx.target_path, ctx.config.critical_paths):
            return None
        return RuleMatch(
            rule_id=self.id,
            severity=self.severity,
            reason=f"{ctx.tool} 目标 {ctx.target_path} 位于 critical_paths，已拒绝",
            extra={"target": str(ctx.target_path)},
        )
