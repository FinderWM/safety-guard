"""bash-git-push：普通 git push 也会改变远端状态，交给用户确认。"""
from __future__ import annotations

from ..context import BashContext
from ..helpers import git_push_is_non_mutating, git_subcommand_args, normalize_cmd_name
from .base import Rule, RuleMatch
from .registry import register


@register
class BashGitPush(Rule):
    id = "bash-git-push"
    severity = "medium"
    applies_to = ("Bash",)
    description = "git push 修改远端仓库状态，需用户确认"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        if ctx.ast is None:
            return None
        for cmd in ctx.ast.commands:
            if normalize_cmd_name(cmd.name or "") != "git":
                continue
            args = [getattr(w, "raw", str(w)) for w in cmd.args]
            subcommand, push_args = git_subcommand_args(args)
            if subcommand != "push":
                continue
            if git_push_is_non_mutating(push_args):
                continue
            return RuleMatch(
                rule_id=self.id,
                severity=self.severity,
                reason=f"`{ctx.raw_command}` 将推送到远端仓库，可能改变共享分支，请确认。",
            )
        return None
