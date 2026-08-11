"""bash-redirect-overwrite-existing：> 重定向到磁盘上已存在的文件。

>> 追加不触发；>| 强制覆盖也触发。
"""
from __future__ import annotations

from ..context import BashContext
from ..helpers import is_null_device_path
from ..paths import resolve
from .base import Rule, RuleMatch
from .registry import register


@register
class BashRedirectOverwriteExisting(Rule):
    id = "bash-redirect-overwrite-existing"
    severity = "medium"
    applies_to = ("Bash",)
    description = "shell 重定向 > 将覆盖已存在文件"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        if ctx.ast is None:
            return None
        for r in ctx.ast.redirects:
            if r.target is None or not r.target.raw:
                continue
            if r.op not in (">", ">|", "&>"):
                continue
            try:
                p = resolve(r.target.raw, ctx.policy)
            except Exception:
                continue
            if is_null_device_path(p):
                continue
            if ctx.disk.exists(p) and not ctx.disk.is_dir(p):
                return RuleMatch(
                    rule_id=self.id,
                    severity=self.severity,
                    reason=f"重定向 `{r.op} {r.target.raw}` 将覆盖已存在文件 {p}",
                    extra={"target": str(p), "op": r.op},
                )
        return None
