"""确定性 shell 展开：把 bashlex 未处理的展开阶段补齐，让路径判定看到真实目标。

bashlex 的 word 节点只做了引号移除，bash 求值链里这几个阶段没做：

    brace expansion    ~/.ss{,}h      → ~/.ssh
    ANSI-C quoting     ~/.ss$'\\x68'   → ~/.ssh
    backslash removal  ~/.\\ss\\h       → ~/.ssh

它们都是纯字符串变换，不需要运行时信息，所以可以静态求值。不补齐的后果不是
「判定不精确」，而是敏感路径规则被绕过——`.ss{,}h` 里根本没有连续的 `.ssh`
子串，任何字面量扫描都抓不到。

为什么要返回候选集合而不是单个字符串：brace expansion 一个 token 展开成多个
路径，`{a,b}/x` 同时指向 `a/x` 和 `b/x`，安全判定必须对每个候选都成立，所以
调用方按「任一候选命中即命中」处理。

真实语料（6.5k 条）实测：路径槽位里 brace 15 次、ANSI-C 1 次。其中 6 次 brace
是合法的多目录 rg（`java/cn/lyy/{controller,service}`），展开后仍在 CWD 内，
所以「展开 + 复用现有 classify」不会产生误报——这是本模块存在的前提。
"""
from __future__ import annotations

import re

# brace 组合会指数爆炸（{a,b}{c,d}{e,f} → 8），超限时放弃展开并让调用方
# 按不可解析处理，而不是静默返回原文——后者会退化成当前的绕过。
_MAX_CANDIDATES = 32
_MAX_DEPTH = 8

_ANSI_C = re.compile(r"\$'((?:[^'\\]|\\.)*)'")

_ESCAPES = {
    'n': '\n', 't': '\t', 'r': '\r', 'a': '\a', 'b': '\b',
    'f': '\f', 'v': '\v', '\\': '\\', "'": "'", '"': '"', 'e': '\x1b',
}


def _decode_ansi_c_body(body: str) -> str:
    out: list[str] = []
    i = 0
    n = len(body)
    while i < n:
        ch = body[i]
        if ch != '\\':
            out.append(ch)
            i += 1
            continue
        i += 1
        if i >= n:
            out.append('\\')
            break
        e = body[i]
        if e == 'x':
            hexs = ''
            j = i + 1
            while j < n and len(hexs) < 2 and body[j] in '0123456789abcdefABCDEF':
                hexs += body[j]
                j += 1
            if hexs:
                out.append(chr(int(hexs, 16)))
                i = j
                continue
            out.append('x')
            i += 1
            continue
        if e in '01234567':
            octs = ''
            j = i
            while j < n and len(octs) < 3 and body[j] in '01234567':
                octs += body[j]
                j += 1
            out.append(chr(int(octs, 8) & 0xFF))
            i = j
            continue
        if e == 'u' or e == 'U':
            width = 4 if e == 'u' else 8
            hexs = ''
            j = i + 1
            while j < n and len(hexs) < width and body[j] in '0123456789abcdefABCDEF':
                hexs += body[j]
                j += 1
            if hexs:
                try:
                    out.append(chr(int(hexs, 16)))
                except ValueError:
                    pass
                i = j
                continue
            out.append(e)
            i += 1
            continue
        out.append(_ESCAPES.get(e, e))
        i += 1
    return ''.join(out)


def expand_ansi_c(text: str) -> str:
    """把 $'...' 段解码成字面字符。段外内容原样保留。"""
    return _ANSI_C.sub(lambda m: _decode_ansi_c_body(m.group(1)), text)


def _split_top_level(body: str) -> list[str] | None:
    """按顶层逗号切分 brace 内容；无顶层逗号返回 None。"""
    parts: list[str] = []
    depth = 0
    cur: list[str] = []
    for ch in body:
        if ch == '{':
            depth += 1
            cur.append(ch)
        elif ch == '}':
            depth -= 1
            cur.append(ch)
        elif ch == ',' and depth == 0:
            parts.append(''.join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append(''.join(cur))
    return parts if len(parts) > 1 else None


_RANGE = re.compile(r'^(-?\d+)\.\.(-?\d+)$|^([a-zA-Z])\.\.([a-zA-Z])$')


def _range_items(body: str) -> list[str] | None:
    m = _RANGE.match(body)
    if not m:
        return None
    if m.group(1) is not None:
        lo, hi = int(m.group(1)), int(m.group(2))
        if abs(hi - lo) + 1 > _MAX_CANDIDATES:
            return None
        step = 1 if hi >= lo else -1
        return [str(v) for v in range(lo, hi + step, step)]
    lo, hi = ord(m.group(3)), ord(m.group(4))
    if abs(hi - lo) + 1 > _MAX_CANDIDATES:
        return None
    step = 1 if hi >= lo else -1
    return [chr(v) for v in range(lo, hi + step, step)]


def _find_brace(text: str) -> tuple[int, int] | None:
    """找最左的、配对的、内容非空的 brace。返回 (开, 闭) 下标。"""
    for i, ch in enumerate(text):
        if ch != '{':
            continue
        depth = 0
        for j in range(i, len(text)):
            if text[j] == '{':
                depth += 1
            elif text[j] == '}':
                depth -= 1
                if depth == 0:
                    if j > i + 1:      # 排除 `{}`（find -exec 占位符）
                        return i, j
                    break
    return None


def expand_braces(text: str, _depth: int = 0) -> list[str]:
    """brace expansion。无 brace 时返回 [text]；超限时返回 [] 表示放弃。"""
    if _depth > _MAX_DEPTH:
        return []
    span = _find_brace(text)
    if span is None:
        return [text]
    i, j = span
    pre, body, post = text[:i], text[i + 1:j], text[j + 1:]
    items = _split_top_level(body)
    if items is None:
        items = _range_items(body)
    if items is None:
        # 不是展开用途（如 `${x}` 已被折叠层处理，或 `.{141}` 正则量词）——
        # 把这段当普通字面量，继续找后面的 brace
        tail = expand_braces(post, _depth + 1)
        if not tail:
            return []
        return [f'{pre}{{{body}}}{t}' for t in tail]
    out: list[str] = []
    for it in items:
        for sub in expand_braces(f'{pre}{it}{post}', _depth + 1):
            out.append(sub)
            if len(out) > _MAX_CANDIDATES:
                return []
    return out


_ESC_CHAR = re.compile(r'\\(.)')


def remove_backslashes(text: str) -> str:
    """移除转义反斜杠，保留被转义的字符本身——bash 的 backslash removal 阶段。

    `~/.\\ss\\h/config` → `~/.ssh/config`。注意这必须在 brace/ANSI-C 之后做，
    否则会把 `\\{` 这类保护性转义提前吃掉。
    """
    return _ESC_CHAR.sub(r'\1', text)


def candidates(raw: str, *, drop_backslashes: bool = True) -> list[str]:
    """把一个 word 原文展开成所有确定性候选路径。

    返回空列表表示展开超限/放弃，调用方应按「不可解析」处理而非放行。
    """
    if not raw:
        return [raw]
    step1 = expand_ansi_c(raw)
    out: list[str] = []
    for c in expand_braces(step1):
        out.append(remove_backslashes(c) if drop_backslashes else c)
    # 去重但保序
    seen: set[str] = set()
    uniq: list[str] = []
    for c in out:
        if c not in seen:
            seen.add(c)
            uniq.append(c)
    return uniq
