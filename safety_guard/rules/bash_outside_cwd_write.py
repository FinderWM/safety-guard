"""bash-outside-cwd-write：非只读命令访问 CWD 外路径（写、移动、删除等）。

排除：
  - 只读命令（由 bash-outside-cwd-read 兜底）
  - root-like 路径（由 bash-rm-root-or-home 高危拦截）
"""
from __future__ import annotations

from ..context import BashContext
from ..helpers import (
    READ_REDIRECT_OPS,
    is_null_device_path,
    is_root_like_path,
    iter_write_targets,
    looks_like_potentially_outside_path,
    strip_path_prefix,
    word_display,
)
from ..paths import resolve
from .base import Rule, RuleMatch
from .registry import register


@register
class BashOutsideCwdWrite(Rule):
    id = "bash-outside-cwd-write"
    severity = "medium"
    applies_to = ("Bash",)
    description = "非只读命令访问 CWD 外路径（写/移动/删除等）需用户确认"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        if ctx.ast is None:
            return None
        read_only = ctx.config.read_only_commands
        hits: list[tuple[str, str]] = []  # (cmd_name, raw_path)
        for cmd in ctx.ast.commands:
            for w in iter_write_targets(cmd.name, cmd.args, read_only):
                # `dd of=<路径>` 的路径嵌在 token 中段，不剥前缀的话 `of=..` 会被
                # 当成一个普通路径段吃掉一层 ..，归一化后反而落回 CWD 内判成安全。
                # 读侧一直有这一步，写侧此前漏了。
                target = strip_path_prefix(w.path_text)
                if not looks_like_potentially_outside_path(target):
                    continue
                if is_root_like_path(target):
                    # 由高危规则负责
                    continue
                cls = ctx.classify(target)
                if cls == "outside":
                    hits.append((cmd.name, word_display(w)))
        # 重定向目标也算——但只取输出方向。`cmd < file` 是读，归
        # bash-outside-cwd-read；不排除会把读报成写。
        for r in ctx.ast.redirects:
            if r.target is None:
                continue
            if r.op in READ_REDIRECT_OPS:
                continue
            t = r.target.path_text
            if not looks_like_potentially_outside_path(t):
                continue
            try:
                p = resolve(t, ctx.policy)
            except Exception:
                continue
            if is_null_device_path(p) or is_root_like_path(t):
                continue
            if ctx.classify(t) == "outside":
                hits.append((f"redirect {r.op}", word_display(r.target)))
        if hits:
            pretty = "; ".join(f"{n} → {p}" for n, p in hits)
            return RuleMatch(
                rule_id=self.id,
                severity=self.severity,
                reason=f"`{ctx.raw_command}` 写/操作 CWD 之外的路径：{pretty}",
                extra={"hits": [{"cmd": n, "path": p} for n, p in hits]},
            )
        return None
