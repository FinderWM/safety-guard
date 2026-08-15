"""file-critical-path-write：file 工具命中 critical_paths 时要求确认。"""
from __future__ import annotations

from ..context import FileToolContext
from ..paths import is_critical
from .base import Rule, RuleMatch
from .registry import register


@register
class FileCriticalPathWrite(Rule):
    id = "file-critical-path-write"
    severity = "medium"
    applies_to = ("Write", "Edit", "NotebookEdit")
    description = "写入 critical_paths（如 ~/.codex/hooks.json）需要用户确认"

    def match(self, ctx: FileToolContext) -> RuleMatch | None:
        candidates = [ctx.target_path]
        if ctx.disk.first_symlink(ctx.target_path, root=ctx.cwd) is not None:
            try:
                candidates.append(ctx.target_path.resolve(strict=False))
            except (OSError, RuntimeError):
                pass
        critical_target = next(
            (candidate for candidate in candidates if is_critical(candidate, ctx.config.critical_paths)),
            None,
        )
        if critical_target is None:
            return None
        return RuleMatch(
            rule_id=self.id,
            severity=self.severity,
            reason=f"{ctx.tool} 目标 {ctx.target_path} 指向 critical path {critical_target}，需要用户确认",
            extra={"target": str(ctx.target_path), "critical_target": str(critical_target)},
        )
