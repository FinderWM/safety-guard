"""bash-eval-from-network：eval / sh -c 的参数来源含网络命令。

例：eval "$(curl …)"、sh -c "$(wget -O- …)"。
"""
from __future__ import annotations

from ..context import BashContext
from ..helpers import NET_FETCHERS, SHELLS
from .base import Rule, RuleMatch
from .registry import register


def _arg_contains_substitution(w) -> bool:
    """word 是否含 $(...) / `...` 命令替换。"""
    return w.has_expansion


@register
class BashEvalFromNetwork(Rule):
    id = "bash-eval-from-network"
    severity = "high"
    applies_to = ("Bash",)
    description = "拦截 eval / sh -c 包裹的网络抓取命令替换"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        if ctx.ast is None:
            return None
        # 遍历所有命令；对 eval 与 sh -c 的 argv 做命令替换检测
        for cmd in ctx.ast.commands:
            name = cmd.name
            if name == "eval" and any(_arg_contains_substitution(w) for w in cmd.args):
                # 进一步看 raw 中是否含 NET_FETCHERS 字面（保守：只要含 curl/wget 就拦）
                if any(fetcher in cmd.raw for fetcher in NET_FETCHERS):
                    return RuleMatch(
                        rule_id=self.id,
                        severity=self.severity,
                        reason=(
                            f"拒绝执行：`{ctx.raw_command}` 中 eval 包裹了网络抓取，"
                            f"等同于盲跑远端代码。"
                        ),
                    )
            if name in SHELLS:
                # 找 -c 后的参数
                args = list(cmd.args)
                for i, w in enumerate(args):
                    if w.raw == "-c" and i + 1 < len(args):
                        target = args[i + 1]
                        if target.has_expansion and any(f in target.raw for f in NET_FETCHERS):
                            return RuleMatch(
                                rule_id=self.id,
                                severity=self.severity,
                                reason=(
                                    f"拒绝执行：`{ctx.raw_command}` 中 {name} -c 的参数"
                                    f"包含网络抓取的命令替换，将执行远端任意代码。"
                                ),
                            )
        return None
