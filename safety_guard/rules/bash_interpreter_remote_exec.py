"""bash-interpreter-remote-exec：解释器载荷里「网络取指 + 立即执行」。

与 bash-interpreter-shell-escape 互补：后者看 os.system/subprocess 把控制权交给 shell；
本规则看 urllib/requests/fetch + exec/eval 这类「下载并在解释器内执行」——
不一定出现 shell 逃逸 API，但语义同样是盲跑远端代码。

定级 medium：合法调试里偶发 urlopen+print；双信号（取指∧执行）才触发。
heredoc 正文 bashlex 不可见，故同时扫 raw_command（仅当命令行含解释器名时）。
"""
from __future__ import annotations

import re

from ..context import BashContext
from ..helpers import normalize_cmd_name
from .base import Rule, RuleMatch
from .registry import register

_FLAG_INTERPRETERS: dict[str, tuple[str, ...]] = {
    "python": ("-c",),
    "python2": ("-c",),
    "python3": ("-c",),
    "node": ("-e", "--eval", "-p", "--print"),
    "deno": ("-e", "--eval"),
    "bun": ("-e", "--eval"),
    "perl": ("-e", "-E"),
    "ruby": ("-e",),
    "php": ("-r",),
}

_INTERPRETERS = frozenset(_FLAG_INTERPRETERS)

_NET = re.compile(
    r"urllib\.request|urlopen\s*\(|requests\.(?:get|post|put|request)\s*\("
    r"|http\.client|httpx\.(?:get|post)|fetch\s*\("
    r"|https?\.(?:get|request)\s*\(|require\s*\(\s*['\"]https?['\"]",
    re.IGNORECASE,
)
_EXEC = re.compile(
    r"(?<![.\w])exec\s*\(|(?<![.\w])eval\s*\(|\bFunction\s*\("
    r"|\.then\s*\(\s*eval\s*\)"  # fetch(...).then(eval)
    r"|(?<![.\w])eval\b(?!\s*[=\w])"  # 回调/赋值右侧的裸 eval
    r"|compile\s*\([^)]*['\"]exec['\"]"
    r"|__import__\s*\(\s*['\"]builtins['\"]",
    re.IGNORECASE,
)


def _flag_payloads(cmd, flags: tuple[str, ...]) -> list[str]:
    out: list[str] = []
    words = cmd.words
    for i, w in enumerate(words[1:], start=1):
        if w.raw in flags and i + 1 < len(words):
            lit = getattr(words[i + 1], "literal", None)
            if lit:
                out.append(lit)
    return out


def _dual_signal(text: str) -> bool:
    return bool(_NET.search(text) and _EXEC.search(text))


@register
class BashInterpreterRemoteExec(Rule):
    id = "bash-interpreter-remote-exec"
    severity = "medium"
    applies_to = ("Bash",)
    description = "解释器载荷同时出现网络取指与 exec/eval，可能盲跑远端代码"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        texts: list[tuple[str, str]] = []
        if ctx.ast is not None:
            for cmd in ctx.ast.commands:
                name = normalize_cmd_name(cmd.name or "")
                if name not in _INTERPRETERS:
                    continue
                flags = _FLAG_INTERPRETERS.get(name)
                if flags:
                    for p in _flag_payloads(cmd, flags):
                        texts.append((f"{name} -c/-e", p))
                texts.append((name, cmd.raw))
        raw = ctx.raw_command or ""
        if raw and any(n in raw for n in _INTERPRETERS):
            texts.append(("raw", raw))

        hits: list[str] = []
        seen: set[str] = set()
        for where, text in texts:
            if not text or not _dual_signal(text):
                continue
            if where not in seen:
                seen.add(where)
                hits.append(where)
        if not hits:
            return None
        return RuleMatch(
            rule_id=self.id,
            severity=self.severity,
            reason=(
                f"解释器上下文同时出现网络取指与 exec/eval（{', '.join(hits)}），"
                "可能下载并执行远端代码。请改为先下载到本地审查后再运行。"
            ),
            extra={"where": hits},
        )
