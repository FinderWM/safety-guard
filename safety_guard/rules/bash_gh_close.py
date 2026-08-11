"""bash-gh-close：gh pr close / gh issue close / gh release delete 等关闭/删除远端资源。"""
from __future__ import annotations

from ..context import BashContext
from .base import Rule, RuleMatch
from .registry import register

CLOSE_DELETE_SUBS = frozenset({"close", "delete"})


@register
class BashGhClose(Rule):
    id = "bash-gh-close"
    severity = "medium"
    applies_to = ("Bash",)
    description = "gh pr/issue/release close|delete 操作远端资源需用户确认"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        if ctx.ast is None:
            return None
        for cmd in ctx.ast.commands:
            if cmd.name != "gh":
                continue
            args = [w.raw for w in cmd.args]
            if len(args) >= 2 and args[1] in CLOSE_DELETE_SUBS:
                resource = args[0]
                action = args[1]
                return RuleMatch(
                    rule_id=self.id,
                    severity="medium",
                    reason=f"`{ctx.raw_command}` 将 {action} 远端 {resource}（不可静默撤销）",
                    extra={"resource": resource, "action": action},
                )
        return None
