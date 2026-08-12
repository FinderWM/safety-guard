"""bash-opaque-inline-script：内层命令静态不可见的执行形态。

覆盖：
  - inline-script：`bash -c "$(gen)"` / `eval "$(…)"` / `python3 -c "$(gen)"`
  - placeholder：`xargs -I{} sh -c '{}'`——字面 `{}` 运行时才填，禁止再 parse
  - process-subst：`bash <(curl …)` / `bash < <(…)` / `source <(…)`
  - stdin-script：`bash -s < …` / `source /dev/stdin <<< "$(…)"`

find-exec 由收集器标记，但 ask 交给 bash-find-exec-rm（仅 rm 家族），
避免 `find -exec grep` 被本规则误伤。

定级 medium：合法脚本里也有动态生成命令的用法，让用户看一眼即可。
"""
from __future__ import annotations

from ..context import BashContext
from .base import Rule, RuleMatch
from .registry import register

# find-exec 只作结构标记，不在此规则触发 ask
_ACTIVE_KINDS = frozenset({"inline-script", "placeholder", "process-subst", "stdin-script"})


def _format_payload(p) -> str:
    kind = getattr(p, "kind", "inline-script") or "inline-script"
    if kind == "placeholder":
        return f"{p.shell} -c {p.raw}（占位符，运行时填充）"
    if kind == "process-subst":
        return f"{p.shell} 以进程替换为脚本源：{p.raw}"
    if kind == "stdin-script":
        return f"{p.shell} 从 stdin/here-string 读脚本：{p.raw}"
    if p.shell == "eval":
        return f"eval {p.raw}"
    return f"{p.shell} -c {p.raw}"


@register
class BashOpaqueInlineScript(Rule):
    id = "bash-opaque-inline-script"
    severity = "medium"
    applies_to = ("Bash",)
    description = "内联/占位/进程替换脚本在运行时才成形，内层命令静态不可见"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        payloads = getattr(ctx, "opaque_payloads", None) or []
        active = [p for p in payloads if getattr(p, "kind", "inline-script") in _ACTIVE_KINDS]
        if not active:
            return None
        shown = [_format_payload(p) for p in active]
        kinds = sorted({getattr(p, "kind", "inline-script") for p in active})
        return RuleMatch(
            rule_id=self.id,
            severity=self.severity,
            reason=(
                f"执行载荷在运行时才成形（{'/'.join(kinds)}），"
                f"静态无法看见实际命令：{'; '.join(shown)}。"
                f"这类构造会让所有按命令名匹配的规则失效。"
            ),
            extra={"payloads": shown, "kinds": kinds},
        )
