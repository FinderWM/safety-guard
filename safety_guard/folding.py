"""常量折叠——把变量拼接的路径还原成确定字面量。

红队实测里「变量拼接」整组 0/5 全漏，就是因为缺这一层：

    A=$HOME/.s; B=sh; cat $A$B/config     # 分析器只看到 `$A$B/config`
    A=$HOME/.ssh; cat $A/config           # 同上，路径判定完全无从下手

折叠按 shell 的求值顺序单向扫描命令序列：遇到赋值就记进 env，遇到参数就用
env 回填。只有当每一个展开成分都能确定时才产出 folded；任何一处不确定
（命令替换、未知变量、间接展开）整个 word 判为不可折叠，由调用方按「不透明」
处理，而不是退回原文假装看懂了。

两条必须守住的边界：

1. **偏移坐标系**。bashlex 的 `node.word` 已去引号，而 `parts[].pos` 是相对
   整条命令的原文偏移。混用会错位——原型阶段 `cat "$HOME"/x` 折出过
   `$/Users/xxx`（多一个 `$`、少一个字符）。所以替换严格在原文切片上做。

2. **不做运行时推断**。`$(...)`、`${A#x}`、`$1` 一律不猜。宁可标记不可折叠，
   也不能给出一个"看起来对"的路径——错误的确定值比诚实的不确定更危险。
"""
from __future__ import annotations

import os

# 只信任值固定且与机密无关的环境变量。HOME 是路径判定的基准，必须支持；
# PATH/LD_PRELOAD 这类由 bash-env-subversion 单独负责，不在这里展开。
_TRUSTED_ENV = ("HOME",)

_OPAQUE_KINDS = frozenset({"commandsubstitution", "processsubstitution"})


def _seed_env(home: str) -> dict[str, str]:
    return {"HOME": home}


def _fold_parts(source: str, base: int, parts: tuple, env: dict[str, str], home: str) -> str | None:
    """在原文切片上做替换。任一成分不确定则返回 None。

    parts 是 ((kind, abs_start, abs_end, value), …)，偏移相对整条命令，
    减去 base 才是切片内坐标。
    """
    if source is None:
        return None
    if not parts:
        return _strip_quotes(source)

    ordered = sorted(parts, key=lambda p: p[1])
    out: list[str] = []
    cursor = 0
    for kind, start, end, value in ordered:
        s, e = start - base, end - base
        if s < cursor or e > len(source) or s < 0:
            return None          # 偏移越界 = 坐标系不对，宁可判不可折叠
        out.append(source[cursor:s])
        if kind == "tilde":
            out.append(home)
        elif kind == "parameter":
            if value in env:
                out.append(env[value])
            elif value in _TRUSTED_ENV:
                out.append(os.environ.get(value, home if value == "HOME" else ""))
            else:
                return None      # 未知变量：不猜
        elif kind in _OPAQUE_KINDS:
            return None          # 运行时才成形
        else:
            return None
        cursor = e
    out.append(source[cursor:])
    return _strip_quotes("".join(out))


def _strip_quotes(text: str) -> str:
    """移除折叠后残留的引号字符。

    bashlex 的 pos 指向含引号的原文，替换完成后引号仍在切片里；路径判定要的是
    引号移除后的结果（`cat ~/".ssh"/config` 与 `cat ~/.ssh/config` 同义）。
    """
    return text.replace('"', "").replace("'", "")


def fold_command(cmd, env: dict[str, str], home: str) -> None:
    """就地折叠一条命令的 words 与 assignments，并把赋值结果并入 env。

    顺序即 shell 的求值顺序：先按当前 env 折叠参数，再把本命令的赋值写进 env
    供后续命令使用。注意前缀赋值对本命令自身的参数展开无效
    （`A=/x echo $A` 输出的是旧值），所以参数折叠必须先于赋值写入。
    """
    for w in getattr(cmd, "words", []) or []:
        if w.has_expansion:
            w.folded = _fold_parts(w.source, w.base, w.parts, env, home)
        else:
            w.folded = _strip_quotes(w.raw)

    # bashlex 将重定向目标挂在 command.redirects，不在 words 中；若不折叠，
    # `F=existing; echo x > "$F"` 会退回字面 `$F` 并漏掉覆盖检查。
    for redirect in getattr(cmd, "redirects", []) or []:
        target = getattr(redirect, "target", None)
        if target is None:
            continue
        if target.has_expansion:
            target.folded = _fold_parts(target.source, target.base, target.parts, env, home)
        else:
            target.folded = _strip_quotes(target.raw)

    for a in getattr(cmd, "assignments", []) or []:
        if a.has_expansion:
            a.folded_value = _fold_parts(a.source, a.base, a.parts, env, home)
        else:
            a.folded_value = _strip_quotes(a.value_raw)
        if a.folded_value is not None:
            env[a.name] = a.folded_value
        else:
            env.pop(a.name, None)   # 变得不可知，撤销旧绑定


def fold_ast(ast, home: str | None = None) -> None:
    """按命令顺序折叠整棵 AST。就地修改 WordSpec.folded / AssignSpec.folded_value。"""
    resolved_home = home or os.path.expanduser("~")
    env = _seed_env(resolved_home)
    for cmd in getattr(ast, "commands", []) or []:
        fold_command(cmd, env, resolved_home)
