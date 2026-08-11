"""bash-instruction-zone-write：bash 命令对 ~/.claude / ~/.agents 等指令区做写/删/移。

CLAUDE.md 第 1 条：指令区只读豁免，任何写入都需确认。
"""
from __future__ import annotations

from ..context import BashContext
from ..helpers import (
    READ_REDIRECT_OPS,
    iter_write_targets,
    looks_like_potentially_outside_path,
    strip_path_prefix,
    word_display,
)
from .base import Rule, RuleMatch
from .registry import register


@register
class BashInstructionZoneWrite(Rule):
    id = "bash-instruction-zone-write"
    severity = "medium"
    applies_to = ("Bash",)
    description = "bash 命令对指令区（~/.claude / ~/.agents）做写/删/移需用户确认"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        if ctx.ast is None:
            return None
        read_only = ctx.config.read_only_commands
        hits: list[tuple[str, str]] = []
        for cmd in ctx.ast.commands:
            for w in iter_write_targets(cmd.name, cmd.args, read_only):
                # 与 outside-cwd-write 同理：`dd of=<指令区路径>` 的路径嵌在中段
                target = strip_path_prefix(w.path_text)
                if not looks_like_potentially_outside_path(target):
                    continue
                if ctx.classify(target) == "instruction-zone":
                    hits.append((cmd.name, word_display(w)))
        for r in ctx.ast.redirects:
            if r.target is None:
                continue
            if r.op in READ_REDIRECT_OPS:
                continue  # `cmd < file` 是读，归 bash-outside-cwd-read
            t = r.target.path_text
            if not looks_like_potentially_outside_path(t):
                continue
            if ctx.classify(t) == "instruction-zone":
                hits.append((f"redirect {r.op}", word_display(r.target)))
        if hits:
            pretty = "; ".join(f"{n} → {p}" for n, p in hits)
            return RuleMatch(
                rule_id=self.id,
                severity=self.severity,
                reason=f"`{ctx.raw_command}` 修改指令区路径：{pretty}",
                extra={"hits": [{"cmd": n, "path": p} for n, p in hits]},
            )
        return None
