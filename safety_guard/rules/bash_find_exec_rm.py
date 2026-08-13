"""bash-find-exec-rm：任意起点 find -exec/-execdir + rm 家族 → medium ask。

与 bash-find-delete-unbounded（high，仅根/家）分离：
  - `find / -exec rm …`  → high deny（既有规则）
  - `find . -exec rm …`  → medium ask（本规则）
  - `find . -delete`     → medium ask（本规则）
  - `find . -exec grep…` → allow
"""
from __future__ import annotations

from ..context import BashContext
from ..helpers import is_root_like_path
from .base import Rule, RuleMatch
from .registry import register

_RM_FAMILY = frozenset({
    "rm", "/bin/rm", "/usr/bin/rm",
    "unlink", "/bin/unlink", "/usr/bin/unlink",
})


@register
class BashFindExecRm(Rule):
    id = "bash-find-exec-rm"
    severity = "medium"
    applies_to = ("Bash",)
    description = "任意起点 find -delete 或 -exec rm/unlink 需用户确认"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        if ctx.ast is None:
            return None
        for cmd in ctx.ast.commands:
            if cmd.name != "find":
                continue
            paths: list[str] = []
            for w in cmd.args:
                if w.raw.startswith("-"):
                    break
                paths.append(w.raw)
            # 纯根/家起点交给 high 规则，避免与 deny 叠成 medium 文案
            if paths and all(is_root_like_path(p) for p in paths):
                continue
            args_list = list(cmd.args)
            if any(w.raw == "-delete" for w in args_list):
                shown_paths = paths or ["."]
                return RuleMatch(
                    rule_id=self.id,
                    severity=self.severity,
                    reason=(
                        f"`{ctx.raw_command}` 使用 find -delete，"
                        f"起点 {', '.join(shown_paths)}；匹配到的文件都会被删除，需确认。"
                    ),
                    extra={"exec": "-delete", "paths": shown_paths, "flag": "-delete"},
                )
            for i, w in enumerate(args_list):
                if w.raw not in ("-exec", "-execdir"):
                    continue
                if i + 1 >= len(args_list):
                    continue
                exe = args_list[i + 1].raw
                if exe not in _RM_FAMILY:
                    continue
                shown_paths = paths or ["."]
                return RuleMatch(
                    rule_id=self.id,
                    severity=self.severity,
                    reason=(
                        f"`{ctx.raw_command}` 使用 find {w.raw} 调用 `{exe}`，"
                        f"起点 {', '.join(shown_paths)}；匹配到的文件都会被删除，需确认。"
                    ),
                    extra={"exec": exe, "paths": shown_paths, "flag": w.raw},
                )
        return None
