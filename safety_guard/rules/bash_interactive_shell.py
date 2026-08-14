"""bash-interactive-shell：交互式 shell 会把后续 stdin 变成未审查命令。"""
from __future__ import annotations

from ..bash_ast import word_is_inline_command_flag
from ..context import BashContext
from ..helpers import SHELLS, normalize_cmd_name
from .base import Rule, RuleMatch
from .registry import register


_SAFE_INFO_FLAGS = frozenset({"--help", "-h", "--version", "-version"})
_INTERACTIVE_FLAGS = frozenset({"-i", "-s", "--interactive"})
_VALUE_OPTIONS = frozenset({"-O", "-o", "--rcfile", "--init-file"})


def _has_script_operand(args: list[str]) -> bool:
    index = 0
    while index < len(args):
        raw = args[index]
        if raw == "--":
            return index + 1 < len(args)
        if raw in _VALUE_OPTIONS:
            index += 2
            continue
        if any(raw.startswith(option + "=") for option in _VALUE_OPTIONS if option.startswith("--")):
            index += 1
            continue
        if raw.startswith("-"):
            index += 1
            continue
        return True
    return False


@register
class BashInteractiveShell(Rule):
    id = "bash-interactive-shell"
    severity = "medium"
    applies_to = ("Bash",)
    description = "启动交互式 shell 后续输入不一定再次经过当前 PreToolUse"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        if ctx.ast is None:
            return None
        for cmd in ctx.ast.commands:
            if normalize_cmd_name(cmd.name or "") not in SHELLS:
                continue
            args = [getattr(w, "raw", str(w)) for w in cmd.args]
            if any(arg in _SAFE_INFO_FLAGS for arg in args):
                continue
            if any(word_is_inline_command_flag(word) for word in cmd.args):
                continue
            if any(
                arg in _INTERACTIVE_FLAGS
                or (arg.startswith("-") and not arg.startswith("--") and "i" in arg[1:])
                or (arg.startswith("-") and not arg.startswith("--") and "s" in arg[1:])
                for arg in args
            ):
                return RuleMatch(
                    rule_id=self.id,
                    severity=self.severity,
                    reason=(
                        f"`{ctx.raw_command}` 启动交互式 shell；后续交互命令"
                        "不一定再次经过当前 PreToolUse 检查，请确认后再启动。"
                    ),
                )
            # 第一个非选项参数是脚本路径；没有脚本时 stdin 会成为命令入口。
            if _has_script_operand(args):
                continue
            return RuleMatch(
                rule_id=self.id,
                severity=self.severity,
                reason=(
                    f"`{ctx.raw_command}` 启动交互式 shell；后续交互命令"
                    "不一定再次经过当前 PreToolUse 检查，请确认后再启动。"
                ),
            )
        return None
