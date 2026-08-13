"""bash-rm-targeted：rm 删除任意路径（非根/家时触发，需用户确认）。

根/家由 bash-rm-root-or-home 兜底 deny，此规则只对其余删除场景 ask。
"""
from __future__ import annotations

from ..context import BashContext
from ..helpers import is_root_like_path
from .base import Rule, RuleMatch
from .registry import register


_DELETE_COMMANDS = frozenset({
    "rm", "unlink", "shred", "trash", "trash-put",
})


@register
class BashRmTargeted(Rule):
    id = "bash-rm-targeted"
    severity = "medium"
    applies_to = ("Bash",)
    description = "rm/unlink/shred/trash 删除文件/目录（非根/家）需用户确认"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        if ctx.ast is None:
            return None
        for cmd in ctx.ast.commands:
            if cmd.name not in _DELETE_COMMANDS:
                continue
            targets = [w.raw for w in cmd.args if not w.raw.startswith("-")]
            non_root = [t for t in targets if not is_root_like_path(t)]
            if non_root:
                return RuleMatch(
                    rule_id=self.id,
                    severity=self.severity,
                    reason=f"`{ctx.raw_command}` 将删除：{', '.join(non_root)}",
                    extra={"targets": non_root},
                )
            # 无显式路径：常见于 `ls | xargs rm -rf`，目标由管道注入
            if not targets:
                return RuleMatch(
                    rule_id=self.id,
                    severity=self.severity,
                    reason=(
                        f"`{ctx.raw_command}` 中 rm 未给出显式路径，"
                        "删除目标可能来自管道/xargs，需确认。"
                    ),
                    extra={"targets": []},
                )
        return None
