"""bash-pipe-to-shell：curl|sh / wget|bash / base64 -d|sh 这类管道到 shell 的任意代码执行。"""
from __future__ import annotations

from ..context import BashContext
from ..helpers import NET_FETCHERS, SHELLS
from .base import Rule, RuleMatch
from .registry import register


@register
class BashPipeToShell(Rule):
    id = "bash-pipe-to-shell"
    severity = "high"
    applies_to = ("Bash",)
    description = "拦截 curl|sh / wget|bash / base64 -d|sh 这类管道执行远端任意代码"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        if ctx.ast is None:
            return None
        for pl in ctx.ast.pipelines:
            stages = pl.stages
            if len(stages) < 2:
                continue
            names = [s.name for s in stages]
            last = names[-1]
            if last not in SHELLS:
                continue
            # 模式 1：网络抓取在管道头
            if names[0] in NET_FETCHERS:
                return RuleMatch(
                    rule_id=self.id,
                    severity=self.severity,
                    reason=(
                        f"拒绝执行：`{ctx.raw_command}` 是 `{names[0]} … | {last}` 模式，"
                        f"等同于直接执行远端任意代码。先下载到本地审查后再运行。"
                    ),
                    extra={"first": names[0], "last": last},
                )
            # 模式 2：管道里出现 base64 解码再喂 shell
            if "base64" in names[:-1]:
                return RuleMatch(
                    rule_id=self.id,
                    severity=self.severity,
                    reason=(
                        f"拒绝执行：`{ctx.raw_command}` 中 base64 解码后直接喂给 {last}，"
                        f"是典型的混淆代码注入模式。"
                    ),
                    extra={"last": last},
                )
        return None
