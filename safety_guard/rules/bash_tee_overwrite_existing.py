"""bash-tee-overwrite-existing：tee 无 -a/--append 写入已存在文件。"""
from __future__ import annotations

from ..context import BashContext
from ..paths import resolve
from .base import Rule, RuleMatch
from .registry import register


@register
class BashTeeOverwriteExisting(Rule):
    id = "bash-tee-overwrite-existing"
    severity = "medium"
    applies_to = ("Bash",)
    description = "tee 无 -a 时将覆盖已存在文件"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        if ctx.ast is None:
            return None
        for cmd in ctx.ast.commands:
            if cmd.name != "tee":
                continue
            args = [w.raw for w in cmd.args]
            append = any(a in ("-a", "--append") for a in args)
            if append:
                continue
            targets = [a for a in args if not a.startswith("-")]
            for t in targets:
                try:
                    p = resolve(t, ctx.policy)
                except Exception:
                    continue
                if ctx.disk.exists(p) and not ctx.disk.is_dir(p):
                    return RuleMatch(
                        rule_id=self.id,
                        severity=self.severity,
                        reason=f"`tee {t}` 将覆盖已存在文件 {p}（如需追加请加 -a）",
                        extra={"target": str(p)},
                    )
        return None
