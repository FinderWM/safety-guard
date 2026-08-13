"""解释器内联载荷：抽字面量、路径与写/删形态。

供 bash-interpreter-write 等规则复用，不解析各语言 AST。
"""
from __future__ import annotations

import re

from .helpers import normalize_cmd_name


FLAG_INTERPRETERS: dict[str, tuple[str, ...]] = {
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

_QUOTED = re.compile(r"""(?P<q>['"])(?P<body>(?:\\.|(?!(?P=q)).){1,512})(?P=q)""")

_WRITE_CALL = re.compile(
    r"""(?ix)
    writeFileSync | writeFile\s*\(
    | write_text\s*\( | write_bytes\s*\(
    | file_put_contents\s*\(
    | File\.write\s*\(
    | \.write_text\s*\( | \.write_bytes\s*\(
    """,
)

_OPEN_WRITE = re.compile(
    r"""(?ix)
    open\s*\(
      [^)]*
      (?:
        ['\"][wax+]['\"]
        | mode\s*=\s*['\"][wax+]
      )
    """,
)

_DELETE_CALL = re.compile(
    r"""(?ix)
    os\s*\.\s*(?:remove|unlink)\s*\(
    | pathlib[\w.]*\s*\.\s*unlink\s*\(
    | \.unlink\s*\(
    | fs\s*\.\s*(?:unlinkSync|rmSync|rmdirSync)\s*\(
    | unlinkSync\s*\(
    | shutil\s*\.\s*rmtree\s*\(
    | File\.delete\s*\(
    | File\.unlink\s*\(
    """,
)


def flag_payloads(cmd, flags: tuple[str, ...] | None = None) -> list[str]:
    """取 `-c` / `-e` 后的字面载荷；动态载荷（literal is None）不收。"""
    name = normalize_cmd_name(getattr(cmd, "name", "") or "")
    use_flags = flags if flags is not None else FLAG_INTERPRETERS.get(name)
    if not use_flags:
        return []
    out: list[str] = []
    words = getattr(cmd, "words", []) or []
    for i, w in enumerate(words[1:], start=1):
        if getattr(w, "raw", "") not in use_flags or i + 1 >= len(words):
            continue
        lit = getattr(words[i + 1], "literal", None)
        if lit:
            out.append(lit)
    return out


def quoted_strings(payload: str) -> list[str]:
    hits: list[str] = []
    seen: set[str] = set()
    for m in _QUOTED.finditer(payload or ""):
        body = m.group("body")
        body = body.replace("\\\\", "\\").replace("\\'", "'").replace('\\"', '"')
        if body and body not in seen:
            seen.add(body)
            hits.append(body)
    return hits


def payload_is_write(payload: str) -> bool:
    if not payload:
        return False
    return bool(_WRITE_CALL.search(payload) or _OPEN_WRITE.search(payload))


def payload_is_delete(payload: str) -> bool:
    return bool(payload and _DELETE_CALL.search(payload))
