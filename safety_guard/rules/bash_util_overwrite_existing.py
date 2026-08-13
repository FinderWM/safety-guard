"""bash-util-overwrite-existing：truncate / dd of= 覆盖已存在文件。"""
from __future__ import annotations

from ..context import BashContext
from ..helpers import normalize_cmd_name, strip_path_prefix
from ..paths import resolve
from .base import Rule, RuleMatch
from .registry import register


def _truncate_targets(args: list) -> list[str]:
    out: list[str] = []
    i = 0
    while i < len(args):
        raw = getattr(args[i], "raw", str(args[i]))
        if raw in ("-s", "--size", "-o", "--io-blocks", "-r", "--reference"):
            i += 2
            continue
        if raw.startswith("-") and raw != "-":
            i += 1
            continue
        out.append(raw)
        i += 1
    return out


def _dd_of_targets(args: list) -> list[str]:
    out: list[str] = []
    for a in args:
        raw = getattr(a, "raw", str(a))
        if raw.startswith("of="):
            out.append(raw.split("=", 1)[1])
    return out


@register
class BashUtilOverwriteExisting(Rule):
    id = "bash-util-overwrite-existing"
    severity = "medium"
    applies_to = ("Bash",)
    description = "truncate / dd of= 覆盖已存在文件需用户确认"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        if ctx.ast is None:
            return None
        hits: list[str] = []
        for cmd in ctx.ast.commands:
            name = normalize_cmd_name(cmd.name or "")
            if name == "truncate":
                targets = _truncate_targets(cmd.args)
            elif name == "dd":
                targets = _dd_of_targets(cmd.args)
            else:
                continue
            for raw in targets:
                text = strip_path_prefix(raw)
                try:
                    path = resolve(text, ctx.policy)
                except Exception:
                    continue
                if ctx.disk.exists(path) and not ctx.disk.is_dir(path):
                    hits.append(text)
        if not hits:
            return None
        return RuleMatch(
            rule_id=self.id,
            severity=self.severity,
            reason=f"`{ctx.raw_command}` 将覆盖已存在文件：{', '.join(hits)}",
            extra={"targets": hits},
        )
