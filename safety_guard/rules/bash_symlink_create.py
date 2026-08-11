"""bash-symlink-create：ln -s / ln / cp -s / Python os.symlink 等创建链接的命令。

CLAUDE.md 第 1 条明确：创建 symlink/hardlink 始终需要确认。
"""
from __future__ import annotations

from ..context import BashContext
from .base import Rule, RuleMatch
from .registry import register


@register
class BashSymlinkCreate(Rule):
    id = "bash-symlink-create"
    severity = "medium"
    applies_to = ("Bash",)
    description = "创建符号链接或硬链接（ln / ln -s / cp -s）需用户确认"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        if ctx.ast is None:
            return None
        for cmd in ctx.ast.commands:
            if cmd.name == "ln":
                return RuleMatch(
                    rule_id=self.id,
                    severity=self.severity,
                    reason=f"`{ctx.raw_command}` 创建链接（ln），可能绕过 CWD 边界",
                )
            if cmd.name == "cp" and any(w.raw in ("-s", "--symbolic-link", "-l", "--link") for w in cmd.args):
                return RuleMatch(
                    rule_id=self.id,
                    severity=self.severity,
                    reason=f"`{ctx.raw_command}` 通过 cp -s/-l 创建链接，可能绕过 CWD 边界",
                )
        return None
