"""bash-rm-root-or-home：rm 目标是 /、~、$HOME 这类整盘/整家路径。

匹配变体：rm -rf /、rm -fr /*、rm --recursive --force "$HOME"、rm -rf ~、rm -rf ~/。
"""
from __future__ import annotations

from ..context import BashContext
from ..helpers import is_root_like_path
from .base import Rule, RuleMatch
from .registry import register


def _is_rm_recursive(words) -> bool:
    """命令是否携带 -r / -R / --recursive 标志（含组合如 -rf）。"""
    for w in words[1:]:
        s = w.raw
        if s.startswith("--"):
            if s in ("--recursive",):
                return True
            continue
        if s.startswith("-") and not s.startswith("--"):
            # 组合短选项，如 -rf / -fr / -fRr
            if any(c in s for c in ("r", "R")):
                return True
    return False


@register
class BashRmRootOrHome(Rule):
    id = "bash-rm-root-or-home"
    severity = "high"
    applies_to = ("Bash",)
    description = "拒绝 rm 目标为 / 或 $HOME 这类整盘/整家路径"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        if ctx.ast is None:
            return None
        for cmd in ctx.ast.commands:
            if cmd.name != "rm":
                continue
            if not _is_rm_recursive(cmd.words):
                continue
            for arg in cmd.args:
                if is_root_like_path(arg.raw):
                    return RuleMatch(
                        rule_id=self.id,
                        severity=self.severity,
                        reason=(
                            f"拒绝执行：`{ctx.raw_command}` 中 rm -rf 的目标 `{arg.raw}` "
                            f"指向根目录或用户主目录，将清空整盘/整家。"
                        ),
                        extra={"target": arg.raw},
                    )
        return None
