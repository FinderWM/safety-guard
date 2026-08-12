"""bash-eval-from-network：eval / sh -c 的参数来源含网络命令。

例：eval "$(curl …)"、sh -c "$(wget -O- …)"、/bin/bash -xc "$(curl …)"。
"""
from __future__ import annotations

from ..bash_ast import word_is_inline_command_flag
from ..context import BashContext
from ..helpers import NET_FETCHERS, is_shell_name, normalize_cmd_name
from .base import Rule, RuleMatch
from .registry import register


def _arg_contains_substitution(w) -> bool:
    """word 是否含 $(...) / `...` 命令替换。"""
    return w.has_expansion


def _raw_has_fetcher(text: str) -> bool:
    return any(fetcher in text for fetcher in NET_FETCHERS)


@register
class BashEvalFromNetwork(Rule):
    id = "bash-eval-from-network"
    severity = "high"
    applies_to = ("Bash",)
    description = "拦截 eval / sh -c 包裹的网络抓取命令替换"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        if ctx.ast is None:
            return None
        for cmd in ctx.ast.commands:
            name = normalize_cmd_name(cmd.name)
            if name == "eval" and any(_arg_contains_substitution(w) for w in cmd.args):
                if _raw_has_fetcher(cmd.raw):
                    return RuleMatch(
                        rule_id=self.id,
                        severity=self.severity,
                        reason=(
                            f"拒绝执行：`{ctx.raw_command}` 中 eval 包裹了网络抓取，"
                            f"等同于盲跑远端代码。"
                        ),
                    )
            if is_shell_name(cmd.name):
                args = list(cmd.args)
                for i, w in enumerate(args):
                    # 与 bash_ast 一致：-cx/-xc 等捆绑短选项也吃载荷
                    if word_is_inline_command_flag(w) and i + 1 < len(args):
                        target = args[i + 1]
                        if target.has_expansion and _raw_has_fetcher(target.raw):
                            return RuleMatch(
                                rule_id=self.id,
                                severity=self.severity,
                                reason=(
                                    f"拒绝执行：`{ctx.raw_command}` 中 {name} -c 的参数"
                                    f"包含网络抓取的命令替换，将执行远端任意代码。"
                                ),
                            )
        return None
