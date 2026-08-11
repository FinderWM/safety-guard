"""bash-cp-mv-overwrite-existing：cp/mv 目标文件已存在。

只在最后一个非选项参数为已存在文件时触发（最后一个 arg 是 destination）。
"""
from __future__ import annotations

from ..context import BashContext
from ..paths import resolve
from .base import Rule, RuleMatch
from .registry import register


@register
class BashCpMvOverwriteExisting(Rule):
    id = "bash-cp-mv-overwrite-existing"
    severity = "medium"
    applies_to = ("Bash",)
    description = "cp/mv 的目标文件已存在，将被覆盖"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        if ctx.ast is None:
            return None
        for cmd in ctx.ast.commands:
            if cmd.name not in ("cp", "mv"):
                continue
            non_opts = [w.raw for w in cmd.args if not w.raw.startswith("-")]
            if len(non_opts) < 2:
                continue
            dest = non_opts[-1]
            try:
                p = resolve(dest, ctx.policy)
            except Exception:
                continue
            if ctx.disk.is_dir(p):
                continue  # 移入目录里不是覆盖语义
            if ctx.disk.exists(p):
                return RuleMatch(
                    rule_id=self.id,
                    severity=self.severity,
                    reason=f"{cmd.name} 目标 {p} 已存在，将被覆盖",
                    extra={"target": str(p), "cmd": cmd.name},
                )
        return None
