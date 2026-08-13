"""bash-disable-safety-hook：拒绝任何写/删 critical_paths 的命令。

critical_paths 默认含 settings.json、safety-guard.py、safety_guard/ 整个包。
"""
from __future__ import annotations

from pathlib import Path

from ..context import BashContext
from ..helpers import command_uses_in_place_edit, iter_path_args
from ..paths import is_critical, resolve
from .base import Rule, RuleMatch
from .registry import register

# 命令名→可能写/删该命令第几个参数（粗略：所有非选项参数都看）
WRITE_LIKE_COMMANDS = frozenset({
    "rm", "mv", "cp", "tee", "ln", "touch", "truncate", "shred", "unlink",
    "install", "trash", "trash-put",
})


@register
class BashDisableSafetyHook(Rule):
    id = "bash-disable-safety-hook"
    severity = "high"
    applies_to = ("Bash",)
    description = "拒绝任何 bash 命令写入或删除受保护的 safety-guard 配置/脚本"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        if ctx.ast is None:
            return None
        critical = ctx.config.critical_paths

        # 1) 命令 argv 中含 critical path
        for cmd in ctx.ast.commands:
            if cmd.name in WRITE_LIKE_COMMANDS or command_uses_in_place_edit(cmd.name, cmd.args):
                args = iter_path_args(cmd.name, cmd.args) if cmd.name in ("sed", "awk") else cmd.args
                for arg in args:
                    if arg.raw.startswith("-"):                        continue
                    try:
                        p = resolve(arg.path_text, ctx.policy)
                    except Exception:
                        continue
                    if is_critical(p, critical):
                        return RuleMatch(
                            rule_id=self.id,
                            severity=self.severity,
                            reason=(
                                f"拒绝执行：`{ctx.raw_command}` 中 {cmd.name} 试图修改受保护路径 {p}，"
                                f"等同于禁用 safety-guard 防线。"
                            ),
                            extra={"target": str(p), "cmd": cmd.name},
                        )

        # 2) 重定向目标是 critical path（如 echo {} > settings.json）
        for r in ctx.ast.redirects:
            if r.target is None:
                continue
            if r.op not in (">", ">>", ">|", "&>", "&>>"):
                continue
            try:
                p = resolve(r.target.path_text, ctx.policy)
            except Exception:
                continue
            if is_critical(p, critical):
                return RuleMatch(
                    rule_id=self.id,
                    severity=self.severity,
                    reason=(
                        f"拒绝执行：`{ctx.raw_command}` 中重定向 `{r.op}` 目标为受保护路径 {p}，"
                        f"等同于禁用 safety-guard 防线。"
                    ),
                    extra={"target": str(p)},
                )
        return None
