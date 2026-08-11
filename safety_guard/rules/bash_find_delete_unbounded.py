"""bash-find-delete-unbounded：find 从根/家开始且带 -delete 或 -exec rm。"""
from __future__ import annotations

from ..context import BashContext
from ..helpers import is_root_like_path
from .base import Rule, RuleMatch
from .registry import register


@register
class BashFindDeleteUnbounded(Rule):
    id = "bash-find-delete-unbounded"
    severity = "high"
    applies_to = ("Bash",)
    description = "拒绝 find / 或 find ~ 配合 -delete / -exec rm 这类无界删除"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        if ctx.ast is None:
            return None
        for cmd in ctx.ast.commands:
            if cmd.name != "find":
                continue
            # 找第一个非选项的 path arg
            paths: list[str] = []
            args_iter = iter(cmd.args)
            for w in args_iter:
                s = w.raw
                if s.startswith("-"):
                    break
                paths.append(s)
            has_delete = any(w.raw == "-delete" for w in cmd.args)
            has_exec_rm = False
            args_list = list(cmd.args)
            for i, w in enumerate(args_list):
                if w.raw in ("-exec", "-execdir") and i + 1 < len(args_list):
                    if args_list[i + 1].raw in ("rm", "/bin/rm", "/usr/bin/rm", "unlink"):
                        has_exec_rm = True
                        break
            if not (has_delete or has_exec_rm):
                continue
            for p in paths:
                if is_root_like_path(p):
                    return RuleMatch(
                        rule_id=self.id,
                        severity=self.severity,
                        reason=(
                            f"拒绝执行：`{ctx.raw_command}` 从根/家目录开始的 find 带删除操作，"
                            f"目标 `{p}`，影响面无界。"
                        ),
                        extra={"target": p},
                    )
        return None
