"""bash-interpreter-outside-path：解释器内联载荷里的字面量越界路径。

bash-outside-cwd-read 只看 shell 路径参数；`python3 -c "open('/etc/hosts')"`、
`node -e "fs.readFileSync('/etc/passwd')"` 的路径藏在字符串里，整条 ALLOW。

不解析各语言 AST：从 `-c/-e/-r` 字面载荷里抽出引号字符串，用与 bash 相同的
looks_like + classify 判定。只对「像路径」的字面量报警，避免把普通字符串误伤。
"""
from __future__ import annotations

import re

from ..context import BashContext
from ..helpers import looks_like_potentially_outside_path, normalize_cmd_name, redact_user_paths
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
    "lua": ("-e",),
}

# 引号内片段；限制长度防止超大 -c 拖垮扫描
_QUOTED = re.compile(r"""(?P<q>['"])(?P<body>(?:\\.|(?!(?P=q)).){1,512})(?P=q)""")

# 明显不是路径的协议/模式
_SKIP_PREFIX = (
    "http://", "https://", "ftp://", "git@", "git://",
    "data:", "javascript:", "mailto:",
)


def _flag_payloads(cmd, flags: tuple[str, ...]) -> list[str]:
    out: list[str] = []
    words = cmd.words
    for i, w in enumerate(words[1:], start=1):
        if getattr(w, "raw", "") not in flags or i + 1 >= len(words):
            continue
        lit = getattr(words[i + 1], "literal", None)
        if lit:
            out.append(lit)
    return out


def _candidate_paths(payload: str) -> list[str]:
    hits: list[str] = []
    seen: set[str] = set()
    for m in _QUOTED.finditer(payload):
        body = m.group("body")
        # 还原最常见的转义，便于 classify
        body = body.replace("\\\\", "\\").replace("\\'", "'").replace('\\"', '"')
        if not body or body.startswith(_SKIP_PREFIX):
            continue
        if not looks_like_potentially_outside_path(body):
            continue
        if body not in seen:
            seen.add(body)
            hits.append(body)
    return hits


@register
class BashInterpreterOutsidePath(Rule):
    id = "bash-interpreter-outside-path"
    severity = "medium"
    applies_to = ("Bash",)
    description = "解释器 -c/-e 字面载荷中出现 CWD 外路径字面量需确认"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        if ctx.ast is None:
            return None
        hits: list[str] = []
        seen: set[str] = set()
        for cmd in ctx.ast.commands:
            name = normalize_cmd_name(cmd.name or "")
            flags = _FLAG_INTERPRETERS.get(name)
            if not flags:
                continue
            for payload in _flag_payloads(cmd, flags):
                for raw_path in _candidate_paths(payload):
                    if ctx.classify(raw_path) != "outside":
                        continue
                    shown = redact_user_paths(raw_path)
                    if shown not in seen:
                        seen.add(shown)
                        hits.append(shown)
        if not hits:
            return None
        return RuleMatch(
            rule_id=self.id,
            severity=self.severity,
            reason=(
                f"解释器内联载荷读取/引用 CWD 外路径字面量：{', '.join(hits)}。"
                "路径藏在 -c/-e 字符串里，bash 路径规则看不见；请确认是否必要。"
            ),
            extra={"paths": hits},
        )
