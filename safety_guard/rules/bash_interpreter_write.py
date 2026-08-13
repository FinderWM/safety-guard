"""bash-interpreter-write：解释器内联载荷写/删文件。

python/node/ruby 等 `-c/-e` 字面量里的 open(...,'w') / writeFileSync
不会出现在 shell argv，既有路径规则看不见。

分级：
  - 目标落在 critical_paths → high（自保，等同 disable-safety-hook）
  - 指令区写入 / CWD 外写入 / 覆盖已有文件 / 删除 → medium
"""
from __future__ import annotations

from ..context import BashContext
from ..helpers import looks_like_potentially_outside_path, normalize_cmd_name, redact_user_paths
from ..interp import FLAG_INTERPRETERS, flag_payloads, payload_is_delete, payload_is_write, quoted_strings
from ..paths import is_critical
from .base import Rule, RuleMatch
from .registry import register


def _quoted_paths(payload: str) -> list[str]:
    out: list[str] = []
    for body in quoted_strings(payload):
        if body.startswith(("http://", "https://", "ftp://", "data:", "javascript:", "mailto:")):
            continue
        if looks_like_potentially_outside_path(body) or "/" in body or body.startswith("."):
            out.append(body)
        elif body and not body.startswith("-") and "." in body:
            # 相对文件名 existing.txt
            out.append(body)
    return out


@register
class BashInterpreterWrite(Rule):
    id = "bash-interpreter-write"
    severity = "medium"
    applies_to = ("Bash",)
    description = "解释器 -c/-e 字面载荷写/删文件（critical 升 high）"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        if ctx.ast is None:
            return None
        high: list[str] = []
        medium: list[str] = []
        for cmd in ctx.ast.commands:
            name = normalize_cmd_name(cmd.name or "")
            if name not in FLAG_INTERPRETERS:
                continue
            for payload in flag_payloads(cmd):
                mutating = payload_is_write(payload) or payload_is_delete(payload)
                if not mutating:
                    continue
                for raw_path in _quoted_paths(payload):
                    shown = redact_user_paths(raw_path)
                    try:
                        resolved = ctx.resolve(raw_path)
                    except Exception:
                        continue
                    if is_critical(resolved, ctx.config.critical_paths):
                        high.append(shown)
                        continue
                    cls = ctx.classify(raw_path)
                    if cls in ("instruction-zone", "outside"):
                        medium.append(shown)
                        continue
                    if payload_is_delete(payload) or ctx.disk.exists(resolved):
                        medium.append(shown)
        if high:
            return RuleMatch(
                rule_id=self.id,
                severity="high",
                reason=(
                    f"解释器内联载荷写入/删除受保护路径：{', '.join(high)}。"
                    "等同于拆掉 safety-guard 或 CLI 配置。"
                ),
                extra={"targets": high, "severity": "high"},
            )
        if medium:
            return RuleMatch(
                rule_id=self.id,
                severity="medium",
                reason=(
                    f"解释器内联载荷写/删文件：{', '.join(medium)}。"
                    "路径藏在 -c/-e 字符串里，shell 路径规则看不见。"
                ),
                extra={"targets": medium},
            )
        return None
