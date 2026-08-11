"""bashlex 封装——AST 解析 + 扁平化遍历。

规则消费 BashContext 里的 commands / redirects / pipelines 即可，不必直接面对 bashlex 节点。
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from typing import Iterable

import bashlex


class BashParseError(Exception):
    """bashlex 解析失败的封装异常。"""


@dataclass
class WordSpec:
    """命令的一个 word（argv 元素），含原文与字面值。"""
    raw: str                 # 原始文本，如 "$HOME"
    literal: str | None      # 不含参数展开的纯字面部分；含 $VAR 时为 None
    has_expansion: bool      # 是否含 $VAR / $(...) / 反引号 / process substitution
    folded: str | None = None   # 常量折叠后的确定字面量；无法确定时为 None
    # 折叠所需的原始素材：node.word 已去引号，而 parts[].pos 是原文偏移，
    # 两者混用会错位（`cat "$HOME"/x` 会折出 `$/Users/meyer.ssh/...`）。
    # 保留原文切片与段基址，让替换严格在同一坐标系里做。
    source: str | None = field(default=None, repr=False)   # 原文切片
    base: int = field(default=0, repr=False)               # 切片起始偏移
    parts: tuple = field(default=(), repr=False)           # ((kind, start, end, value), …)

    @property
    def path_text(self) -> str:
        """路径判定应该看的文本：优先折叠结果，退回原文。"""
        return self.folded if self.folded is not None else self.raw


@dataclass
class AssignSpec:
    """变量绑定：`A=1 cmd` 前缀赋值、`A=1` 独立赋值、`env A=1 cmd` 包装赋值。

    环境变量决定「动词字面量 → 实际执行的程序」这层映射（PATH / LD_PRELOAD /
    BASH_ENV），所以必须对规则可见——否则任何基于 argv[0] 的分析都能被一条前缀
    赋值推翻：`PATH=<dir> cat f` 的 argv[0] 字面量是 cat，实际跑的是 <dir>/cat。
    """
    name: str                # 变量名
    value_raw: str           # 右侧原文（可能含 $VAR / $(...)）
    raw: str                 # 完整 `NAME=VALUE` 原文
    has_expansion: bool      # 右侧是否含参数/命令展开
    origin: str = "prefix"   # prefix | standalone | wrapper | builtin
    folded_value: str | None = None   # 右侧折叠后的确定字面量
    source: str | None = field(default=None, repr=False)
    base: int = field(default=0, repr=False)
    parts: tuple = field(default=(), repr=False)


@dataclass
class CommandSpec:
    """一条命令的语义视图。"""
    name: str                # argv[0] 字面（含展开则取 raw）
    words: list[WordSpec]    # 含 name 在内的全部 words
    raw: str                 # 命令的原始片段
    redirects: list["RedirectSpec"] = field(default_factory=list)
    wrappers: tuple[str, ...] = ()  # 被剥掉的包装前缀，如 ("rtk",) / ("sudo", "env")
    assignments: list[AssignSpec] = field(default_factory=list)

    @property
    def args(self) -> list[WordSpec]:
        return self.words[1:]


@dataclass
class RedirectSpec:
    """重定向节点。"""
    op: str                  # >, >>, <, <<, &>, 2> 等
    target: WordSpec | None  # 目标 word，如 > file 的 file
    raw: str


@dataclass
class PipelineSpec:
    """管道：a | b | c。"""
    stages: list[CommandSpec]
    raw: str


@dataclass
class OpaquePayload:
    """运行时才成形、静态无法看见内层命令的载荷。

    与 words 里普通的 has_expansion 不同：那只是某个参数不确定，动词仍然可见；
    这里是整条内层命令都不可见，任何基于 argv[0] 的规则都无从下手。

    kind:
      inline-script  — sh -c / eval / python -c 的动态载荷
      process-subst  — bash <(curl …) / source <(…) 把进程替换当脚本源
      find-exec      — find -exec/-execdir 运行时拼出的子命令
      placeholder    — xargs sh -c '{}' 这类占位符，静态层看不见真实内层
    """
    shell: str        # 承载载荷的 shell/解释器名（sh / bash / find / xargs ...）
    raw: str          # 载荷原文
    command_raw: str  # 所属命令的完整原文
    kind: str = "inline-script"  # inline-script | process-subst | find-exec | placeholder


@dataclass
class BashAst:
    raw: str
    commands: list[CommandSpec]
    pipelines: list[PipelineSpec]
    redirects: list[RedirectSpec]
    opaque_payloads: list[OpaquePayload] = field(default_factory=list)


def parse(command: str) -> BashAst:
    normalized = _normalize_heredoc_delimiters(command)
    try:
        trees = bashlex.parse(normalized)
    except (bashlex.errors.ParsingError, NotImplementedError, Exception) as e:
        # bashlex 对复杂 rg/grep 正则里的反引号、括号和引号较脆弱；退回到轻量 token 视图。
        try:
            return _parse_with_shlex(command)
        except BashParseError:
            raise BashParseError(str(e)) from e

    commands: list[CommandSpec] = []
    pipelines: list[PipelineSpec] = []
    redirects: list[RedirectSpec] = []
    for tree in trees:
        _walk(tree, command, commands, pipelines, redirects)
    return BashAst(raw=command, commands=commands, pipelines=pipelines, redirects=redirects)


# ---------------------------------------------------------------------------
# 包装命令展开
#
# `rtk` / `sudo` / `env A=1` 这类前缀把真正的命令挡在 argv[1] 之后。所有按
# cmd.name 分发的规则（rm / git / psql / gh …）会整体失效，而只看路径的泛化规则
# 反过来把 `rtk cat FILE` 这种纯读误判成写——噪音留下、防护摘掉。
# 展开一层前缀后两边同时修好。
# ---------------------------------------------------------------------------

DEFAULT_WRAPPERS: tuple[str, ...] = (
    "rtk", "sudo", "doas", "env", "nohup", "command", "builtin", "exec",
    "nice", "ionice", "stdbuf", "time", "timeout", "xargs", "setsid",
    "proxychains", "proxychains4",
)

# 包装命令自身「带值」的选项：命中后跳过选项 + 它的值
_WRAPPER_VALUE_OPTS: dict[str, frozenset[str]] = {
    "sudo": frozenset({"-u", "--user", "-g", "--group", "-p", "--prompt", "-C", "--close-from", "-h", "--host"}),
    "doas": frozenset({"-u", "-C"}),
    "env": frozenset({"-u", "--unset", "-C", "--chdir", "-S", "--split-string"}),
    "nice": frozenset({"-n", "--adjustment"}),
    "ionice": frozenset({"-c", "-n", "-p"}),
    "stdbuf": frozenset({"-i", "-o", "-e", "--input", "--output", "--error"}),
    "timeout": frozenset({"-s", "--signal", "-k", "--kill-after"}),
    "xargs": frozenset({"-I", "-i", "-n", "-P", "-d", "-E", "-s", "-L", "-a",
                        "--replace", "--max-args", "--max-procs", "--delimiter",
                        "--max-lines", "--arg-file", "--eof"}),
}

# 包装命令在选项之后还要吃掉的位置参数个数（timeout 的 DURATION）
_WRAPPER_SKIP_POSITIONAL: dict[str, int] = {"timeout": 1}

# 包装命令自己的子命令，跳过后才是真命令（rtk proxy <cmd>）
_WRAPPER_SKIP_SUBCOMMAND: dict[str, frozenset[str]] = {
    "rtk": frozenset({"proxy", "exec", "run"}),
}

_MAX_UNWRAP_DEPTH = 4


def _unwrap_once(cmd: CommandSpec, wrappers: frozenset[str]) -> CommandSpec | None:
    """剥掉一层包装前缀；不是包装命令或剥完没内容则返回 None。"""
    name = cmd.name
    if name not in wrappers or len(cmd.words) < 2:
        return None

    value_opts = _WRAPPER_VALUE_OPTS.get(name, frozenset())
    skip_positional = _WRAPPER_SKIP_POSITIONAL.get(name, 0)
    subcommands = _WRAPPER_SKIP_SUBCOMMAND.get(name, frozenset())

    carried: list[AssignSpec] = []
    i = 1
    while i < len(cmd.words):
        raw = cmd.words[i].raw
        if raw in value_opts:
            i += 2
            continue
        if raw.startswith("-") and raw != "-":
            # 长/短选项、bundled 短选项（-n1、-I{}）都按无值处理
            i += 1
            continue
        # 任何 wrapper 在选项之后、真命令之前都可能夹着 NAME=VALUE。
        # 只认 env/sudo/doas 会漏掉：`rtk PATH=<dir> cat f`、`timeout 5 PATH=<dir>
        # cat f`、`nice -n 10 LD_PRELOAD=x.so ls`——赋值被当成 argv[0]，内层命令
        # 整段隐身，bash-env-subversion 与一切按名分发的规则同时失效。
        # shell 语义上 timeout/nice/nohup 本身不消费前缀赋值，但用户写成
        # `timeout 5 A=1 cmd` 时 A=1 仍是「下一个要执行的简单命令」的前缀，
        # 必须随命令带走，否则剥出来的 name 变成字面 `A=1`。
        if "=" in raw and not raw.startswith("/") and not raw.startswith("-"):
            spec = _assign_from_token(raw, "wrapper")
            if spec is not None:
                carried.append(spec)
                i += 1
                continue
            # 含 = 但不是合法赋值名（如 `--foo=bar` 已在上面处理，或 `=x`）
            # 落到下面按普通 token 处理
        if skip_positional > 0:
            skip_positional -= 1
            i += 1
            continue
        if raw in subcommands:
            i += 1
            continue
        break

    if i >= len(cmd.words):
        return None  # `env` / `sudo -v` 这类没有内层命令，保持原样

    inner = cmd.words[i:]
    return CommandSpec(
        name=inner[0].literal or inner[0].raw,
        words=inner,
        raw=cmd.raw,
        redirects=cmd.redirects,
        wrappers=cmd.wrappers + (name,),
        assignments=cmd.assignments + carried,
    )


def unwrap_command(cmd: CommandSpec, wrappers: frozenset[str]) -> CommandSpec:
    """反复剥掉包装前缀，直到 argv[0] 是真命令（如 `sudo env A=1 rtk rm`）。"""
    current = cmd
    for _ in range(_MAX_UNWRAP_DEPTH):
        nxt = _unwrap_once(current, wrappers)
        if nxt is None:
            return current
        current = nxt
    return current


# `bash -c '<inner>'` 的载荷需要再解析一层，否则内层危险命令完全不可见
_INLINE_SCRIPT_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh"})

# 解释器的内联代码选项。载荷不是 shell 语法，无法再解析成 CommandSpec，但
# 「运行时才成形」这一威胁与 sh -c 完全同构：`python3 -c "$(gen)"` 同样让
# 静态分析看不到任何实际操作，而解释器的文件读写能力并不比 shell 弱。
_INLINE_CODE_INTERPRETERS: dict[str, frozenset[str]] = {
    "python": frozenset({"-c"}),
    "python2": frozenset({"-c"}),
    "python3": frozenset({"-c"}),
    "node": frozenset({"-e", "--eval", "-p", "--print"}),
    "deno": frozenset({"eval"}),
    "bun": frozenset({"-e", "--eval"}),
    "perl": frozenset({"-e", "-E"}),
    "ruby": frozenset({"-e"}),
    "php": frozenset({"-r"}),
}


# eval 与 `sh -c` 语义同构：参数拼接成字符串后交给**当前** shell 执行。
# 不建模的话 `eval "rm -rf X"` 一条规则都不触发——载荷只是 eval 的普通字符串参数，
# 没有任何 -c 形态可供识别，而危害与 `bash -c 'rm -rf X'` 完全一致。
_EVAL_BUILTINS = frozenset({"eval"})


def _is_inline_command_flag(raw: str) -> bool:
    """判断一个 word 是不是「下一个参数是脚本载荷」的 -c 形态。

    bash 的单字母选项可任意捆绑与排序：`-cx` / `-xc` / `-cv` / `-ce` 都是合法的
    `-c`，实测全部会执行载荷。只认 `-c`/`-lc`/`-ic` 三个字面量的话，改一个字母
    就能让整条内层命令重新隐身——和只认 `-f` 却漏掉 `-rf` 是同一类错误。

    排除 `--` 开头的长选项：`--norc` 含 c 但不吃载荷。
    """
    if not raw.startswith("-") or raw.startswith("--") or raw == "-":
        return False
    flags = raw[1:]
    # 带值的单字母选项（-O shopt / -o option）后面跟的是选项值，不是载荷；
    # 若它们出现在捆绑串里，`c` 之后的字母会被当成那个值，此处保守只看是否含 c。
    return "c" in flags


def _is_placeholder_literal(text: str) -> bool:
    """xargs/parallel 占位符：`sh -c '{}'` 的字面载荷不能再 parse，否则会发明命令名 `{}`。"""
    return text.strip() == "{}"


def _inline_script_payloads(cmd: CommandSpec) -> tuple[list[str], list["OpaquePayload"]]:
    """拆出 inline 形态（sh -c / python3 -c / node -e …）的载荷，分成「可再解析的字面量」与「不透明的」两类。

    不透明载荷必须显式回传，不能像早期实现那样静默丢弃：
    `bash -c "$(printf '\\x63\\x61\\x74 ...')"` 的载荷在运行时才成形，
    literal 为 None，丢掉就等于内层命令完全不可见 —— 整条命令直接 ALLOW。

    字面量 `{}` 同样不透明：xargs -I{} 运行时才填，再 parse 只会发明假命令名。
    """
    words = cmd.words
    if cmd.name in _EVAL_BUILTINS:
        # eval 没有选项，全部参数都是载荷（shell 先拼接再执行）。
        # 字面量交给下游再 parse 一层，不透明的标记出来。
        ev_literals: list[str] = []
        ev_opaque: list[OpaquePayload] = []
        for w in cmd.args:
            if w.literal is not None and not _is_placeholder_literal(w.literal):
                ev_literals.append(w.literal)
            elif w.literal is not None and _is_placeholder_literal(w.literal):
                ev_opaque.append(
                    OpaquePayload(
                        shell="eval", raw=w.raw, command_raw=cmd.raw, kind="placeholder",
                    )
                )
            else:
                ev_opaque.append(
                    OpaquePayload(shell="eval", raw=w.raw, command_raw=cmd.raw)
                )
        return ev_literals, ev_opaque
    if cmd.name in _INLINE_CODE_INTERPRETERS:
        # 解释器载荷不是 shell 语法，不能再 parse；只在不透明时报告
        flags = _INLINE_CODE_INTERPRETERS[cmd.name]
        opaque: list[OpaquePayload] = []
        for i, w in enumerate(words[1:], start=1):
            if w.raw in flags and i + 1 < len(words):
                payload = words[i + 1]
                if payload.literal is None:
                    opaque.append(
                        OpaquePayload(shell=cmd.name, raw=payload.raw, command_raw=cmd.raw)
                    )
                elif _is_placeholder_literal(payload.literal):
                    opaque.append(
                        OpaquePayload(
                            shell=cmd.name,
                            raw=payload.raw,
                            command_raw=cmd.raw,
                            kind="placeholder",
                        )
                    )
        return [], opaque
    if cmd.name not in _INLINE_SCRIPT_SHELLS:
        return [], []
    literals: list[str] = []
    opaque: list[OpaquePayload] = []
    for i, w in enumerate(words[1:], start=1):
        if _is_inline_command_flag(w.raw) and i + 1 < len(words):
            payload = words[i + 1]
            if payload.literal is not None and not _is_placeholder_literal(payload.literal):
                literals.append(payload.literal)
            elif payload.literal is not None and _is_placeholder_literal(payload.literal):
                opaque.append(
                    OpaquePayload(
                        shell=cmd.name,
                        raw=payload.raw,
                        command_raw=cmd.raw,
                        kind="placeholder",
                    )
                )
            else:
                opaque.append(
                    OpaquePayload(shell=cmd.name, raw=payload.raw, command_raw=cmd.raw)
                )
    return literals, opaque


# 把 process substitution 当「脚本源」的宿主：shell / source / 解释器。
# cat <(…) 只是读 fd，不在此列——否则日常 process-subst 读会全被误伤。
_PROCESS_SUBST_SCRIPT_HOSTS = frozenset(
    set(_INLINE_SCRIPT_SHELLS)
    | set(_INLINE_CODE_INTERPRETERS)
    | {"source", "."}
)


def _is_process_subst_script_word(w: WordSpec) -> bool:
    """word 是否为 `<(…)` 进程替换（脚本源形态；`>(…)` 是写出，不在此列）。"""
    raw = w.raw.lstrip()
    if not raw.startswith("<("):
        return False
    if any(kind == "processsubstitution" for kind, *_ in (w.parts or ())):
        return True
    # shlex 回退路径没有 parts，靠字面前缀判定
    return True


def _collect_structural_opaque(cmd: CommandSpec) -> list[OpaquePayload]:
    """收集非 inline-script 的不透明执行形态：process-subst / find-exec。

    placeholder 在 _inline_script_payloads 里处理（与 -c 载荷同路径）。
    """
    found: list[OpaquePayload] = []
    if cmd.name in _PROCESS_SUBST_SCRIPT_HOSTS:
        for w in cmd.words[1:]:
            raw = w.raw
            # 跳过选项；下一位置参数才可能是脚本源
            if raw.startswith("-") and raw not in ("-", "--"):
                continue
            if raw == "--":
                continue
            if _is_process_subst_script_word(w):
                found.append(
                    OpaquePayload(
                        shell=cmd.name,
                        raw=w.raw,
                        command_raw=cmd.raw,
                        kind="process-subst",
                    )
                )
                break
            # 第一个位置参数已见且非 process-subst → 普通脚本路径，结束
            break
    if cmd.name == "find":
        args = list(cmd.args)
        for i, w in enumerate(args):
            if w.raw not in ("-exec", "-execdir"):
                continue
            tail: list[str] = [w.raw]
            for u in args[i + 1:]:
                tail.append(u.raw)
                if u.raw in (";", "+"):
                    break
            found.append(
                OpaquePayload(
                    shell="find",
                    raw=" ".join(tail),
                    command_raw=cmd.raw,
                    kind="find-exec",
                )
            )
    return found


def expand(ast: BashAst, wrappers: frozenset[str]) -> BashAst:
    """展开包装前缀 + 内联 shell 脚本，返回规则可直接消费的 AST。

    原地重建 commands / pipelines.stages，使两者指向同一批 CommandSpec。
    """
    unwrapped: dict[int, CommandSpec] = {}

    def _u(c: CommandSpec) -> CommandSpec:
        key = id(c)
        if key not in unwrapped:
            unwrapped[key] = unwrap_command(c, wrappers)
        return unwrapped[key]

    commands = [_u(c) for c in ast.commands]
    pipelines = [PipelineSpec(stages=[_u(s) for s in p.stages], raw=p.raw) for p in ast.pipelines]

    # bash -c '<inner>' 递归展开一层（再深就不追了，避免 quoting 噩梦）
    extra: list[CommandSpec] = []
    extra_redirects: list[RedirectSpec] = []
    # 内层的 pipeline 结构必须一起并进来。只并 commands 会让按 pipeline 判定的规则
    # 集体失效：`curl … | sh` 是 deny，套一层 `bash -c '…'` 后 stages 丢失，
    # bash-pipe-to-shell 看不到管道，整条 allow——一个包装前缀就摘掉一条 HIGH。
    extra_pipelines: list[PipelineSpec] = []
    opaque: list[OpaquePayload] = list(ast.opaque_payloads)
    for c in commands:
        literals, unresolvable = _inline_script_payloads(c)
        opaque.extend(unresolvable)
        opaque.extend(_collect_structural_opaque(c))
        for payload in literals:
            try:
                sub = expand(parse(payload), wrappers)
            except (BashParseError, RecursionError):
                continue
            extra.extend(sub.commands)
            extra_redirects.extend(sub.redirects)
            extra_pipelines.extend(sub.pipelines)
            opaque.extend(sub.opaque_payloads)

    from .folding import fold_ast

    result = BashAst(
        raw=ast.raw,
        commands=commands + extra,
        pipelines=pipelines + extra_pipelines,
        redirects=ast.redirects + extra_redirects,
        opaque_payloads=opaque,
    )
    fold_ast(result)
    return result



def _normalize_heredoc_delimiters(command: str) -> str:
    """Mask heredoc delimiter quoting that bashlex does not quote-remove.

    Bash quote-removes the delimiter token in `<<'EOF'`, `<<"EOF"`, and
    `<<\\EOF`; bashlex compares the literal token instead, so it expects the
    terminating line to include quotes/backslashes. Replacing only those quote
    bytes with spaces keeps node positions stable while giving bashlex the
    delimiter Bash actually uses.
    """
    chars = list(command)
    i = 0
    n = len(chars)
    while i < n - 1:
        if chars[i] != "<" or chars[i + 1] != "<":
            i += 1
            continue

        i += 2
        if i < n and chars[i] == "-":
            i += 1
        while i < n and chars[i] in " \t":
            i += 1
        while i < n and chars[i] not in " \t\r\n;|&()":
            if chars[i] in "'\"\\":
                chars[i] = " "
            i += 1
    return "".join(chars)


def _slice(raw: str, node) -> str:
    try:
        a, b = node.pos
        return raw[a:b]
    except (AttributeError, TypeError, ValueError):
        return ""


def _word_spec(raw: str, node) -> WordSpec:
    pos = getattr(node, "pos", None)
    start = pos[0] if pos is not None else 0
    end = pos[1] if pos is not None else len(raw)
    text = getattr(node, "word", None) or raw[start:end]
    parts = getattr(node, "parts", []) or []
    has_exp = any(p.kind in ("parameter", "tilde", "commandsubstitution", "processsubstitution") for p in parts)
    literal = None if has_exp else text
    return WordSpec(
        raw=text,
        literal=literal,
        has_expansion=has_exp,
        source=raw[start:end],
        base=start,
        parts=tuple((p.kind, p.pos[0], p.pos[1], getattr(p, "value", None)) for p in parts),
    )


_REDIRECT_RE = re.compile(r"^(?:\d+)?(&>>|&>|>\||>>?|<<?)(.+)$")
_ASSIGN_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_REDIRECT_OPS = frozenset({">", ">>", ">|", "<", "<<", "&>", "&>>"})
_COMMAND_SEPARATORS = frozenset({"&&", "||", ";", "&"})
# 行尾出现这些说明命令跨行继续，不能在行边界收尾（`curl … |` 换行 `sh`）
_LINE_CONTINUATIONS = frozenset({"|", "&&", "||"})


def _token_word(token: str) -> WordSpec:
    has_exp = "$" in token or "`" in token or "$(" in token or "<(" in token or ">(" in token
    return WordSpec(raw=token, literal=None if has_exp else token, has_expansion=has_exp)


def _parse_redirect_token(token: str, next_token: str | None) -> tuple[RedirectSpec | None, bool]:
    if token in _REDIRECT_OPS:
        if next_token is None:
            return None, False
        return RedirectSpec(op=token, target=_token_word(next_token), raw=f"{token} {next_token}"), True
    m = _REDIRECT_RE.match(token)
    if m:
        op = m.group(1)
        target = m.group(2)
        if target:
            return RedirectSpec(op=op, target=_token_word(target), raw=token), False
    return None, False


def _command_from_tokens(tokens: list[str]) -> CommandSpec | None:
    if not tokens:
        return None
    words: list[WordSpec] = []
    redirects: list[RedirectSpec] = []
    assigns: list[AssignSpec] = []
    i = 0
    while i < len(tokens):
        next_token = tokens[i + 1] if i + 1 < len(tokens) else None
        redirect, consumed_next = _parse_redirect_token(tokens[i], next_token)
        if redirect is not None:
            redirects.append(redirect)
            i += 2 if consumed_next else 1
            continue
        if not words:
            # 只有 argv[0] 之前的 NAME=VALUE 才是赋值；之后的是普通参数
            spec = _assign_from_token(tokens[i], "prefix")
            if spec is not None:
                assigns.append(spec)
                i += 1
                continue
        words.append(_token_word(tokens[i]))
        i += 1
    if not words:
        for a in assigns:
            a.origin = "standalone"
        return CommandSpec(name="", words=[], raw=" ".join(tokens), redirects=redirects, assignments=assigns)
    return CommandSpec(
        name=words[0].literal or words[0].raw,
        words=words,
        raw=" ".join(tokens),
        redirects=redirects,
        assignments=assigns,
    )


_HEREDOC_START_RE = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")


def _strip_heredoc_bodies(command: str) -> str:
    """去掉 heredoc 正文再交给 shlex。

    shlex 不认 heredoc，会把 `python3 <<'PY' … open('/tmp/x.js') … PY` 的正文
    整段切成 token，于是 python 字符串里的路径被当成命令的路径参数。正文本身不是
    argv，丢掉即可——真正要判定的是宿主命令。
    """
    lines = command.splitlines()
    if len(lines) < 2:
        return command
    out: list[str] = []
    pending: list[str] = []
    terminator: str | None = None
    for line in lines:
        if terminator is not None:
            if line.strip() == terminator:
                terminator = pending.pop(0) if pending else None
            continue
        out.append(line)
        delims = [m.group(2) for m in _HEREDOC_START_RE.finditer(line)]
        if delims:
            terminator = delims[0]
            pending = delims[1:]
    return "\n".join(out)


def _shlex_line_tokens(command: str) -> list[list[str]]:
    """逐行 tokenize，把「引号跨行」的片段合并回去。

    shlex 把换行当普通空白，整串喂进去会让多行命令塌成一条：第二行起的 argv[0]
    沦为第一行命令的参数，rm / git / psql / curl|sh 这些按命令名分发的规则集体
    失效。实测 `echo \\`date +%s` 换行 `rm -rf /` 曾整条放行（单独跑是 deny）——
    bashlex 被反引号噎住退到这里，命令边界随即丢失。
    comments=True 同理：`#` 之后原本会吞掉后续所有行，现在只影响当前行。
    """
    out: list[list[str]] = []
    pending = ""
    for line in command.splitlines():
        chunk = f"{pending}\n{line}" if pending else line
        try:
            tokens = shlex.split(chunk, posix=True, comments=True)
        except ValueError:
            pending = chunk  # 引号未闭合，跟下一行合并后重试
            continue
        pending = ""
        out.append(tokens)
    if pending:
        # 到结尾仍未闭合——按解析失败上报，沿用 shlex 的原始错误信息
        try:
            out.append(shlex.split(pending, posix=True, comments=True))
        except ValueError as e:
            raise BashParseError(str(e)) from e
    return out


def _parse_with_shlex(command: str) -> BashAst:
    commands: list[CommandSpec] = []
    pipelines: list[PipelineSpec] = []
    redirects: list[RedirectSpec] = []
    current: list[str] = []
    pipe_stages: list[CommandSpec] = []

    def flush_command() -> None:
        nonlocal current
        spec = _command_from_tokens(current)
        current = []
        if spec is None:
            return
        commands.append(spec)
        redirects.extend(spec.redirects)
        pipe_stages.append(spec)

    def flush_pipeline() -> None:
        nonlocal pipe_stages
        if len(pipe_stages) > 1:
            pipelines.append(PipelineSpec(stages=pipe_stages, raw=" | ".join(s.raw for s in pipe_stages)))
        pipe_stages = []

    for tokens in _shlex_line_tokens(_strip_heredoc_bodies(command)):
        for token in tokens:
            if token == "|":
                flush_command()
                continue
            if token in _COMMAND_SEPARATORS:
                flush_command()
                flush_pipeline()
                continue
            current.append(token)
        if tokens and tokens[-1] in _LINE_CONTINUATIONS:
            continue  # 管道/逻辑操作符跨行，命令尚未结束
        flush_command()
        flush_pipeline()

    flush_command()
    flush_pipeline()
    return BashAst(raw=command, commands=commands, pipelines=pipelines, redirects=redirects)



def _redirect_spec(raw: str, node) -> RedirectSpec:
    op = getattr(node, "type", "") or ""
    output_node = getattr(node, "output", None)
    target = _word_spec(raw, output_node) if output_node is not None else None
    return RedirectSpec(op=op, target=target, raw=_slice(raw, node))


def _assign_spec(raw: str, node, origin: str = "prefix") -> AssignSpec | None:
    """把 bashlex 的 assignment 节点转成 AssignSpec；不含 `=` 则返回 None。"""
    text = getattr(node, "word", None) or _slice(raw, node)
    if "=" not in text:
        return None
    name, value = text.split("=", 1)
    parts = getattr(node, "parts", []) or []
    has_exp = any(
        getattr(p, "kind", "") in ("parameter", "tilde", "commandsubstitution", "processsubstitution")
        for p in parts
    )
    pos = getattr(node, "pos", None)
    start = pos[0] if pos is not None else 0
    end = pos[1] if pos is not None else len(text)
    src = raw[start:end] if pos is not None else text
    # 去掉 name= 前缀，让 source 对应 value 原文
    eq = src.find("=")
    value_src = src[eq + 1:] if eq >= 0 else src
    return AssignSpec(
        name=name,
        value_raw=value,
        raw=text,
        has_expansion=has_exp,
        origin=origin,
        source=value_src,
        base=start + (eq + 1 if eq >= 0 else 0),
        parts=tuple((p.kind, p.pos[0], p.pos[1], getattr(p, "value", None)) for p in parts),
    )


def _assign_from_token(token: str, origin: str) -> AssignSpec | None:
    """shlex 回退路径：从 `NAME=VALUE` token 构造 AssignSpec。"""
    if "=" not in token or token.startswith("="):
        return None
    name, value = token.split("=", 1)
    if not name or not _ASSIGN_NAME_RE.match(name):
        return None
    return AssignSpec(
        name=name,
        value_raw=value,
        raw=token,
        has_expansion=("$" in value or "`" in value),
        origin=origin,
    )


def _command_spec(raw: str, node) -> CommandSpec:
    words: list[WordSpec] = []
    rds: list[RedirectSpec] = []
    assigns: list[AssignSpec] = []
    for p in getattr(node, "parts", []):
        kind = getattr(p, "kind", "")
        if kind == "word":
            words.append(_word_spec(raw, p))
        elif kind == "redirect":
            rds.append(_redirect_spec(raw, p))
        elif kind == "assignment":
            spec = _assign_spec(raw, p)
            if spec is not None:
                assigns.append(spec)
    if not words:
        # assignment-only commands（`A=1`）、或空命令
        for a in assigns:
            a.origin = "standalone"
        return CommandSpec(name="", words=[], raw=_slice(raw, node), redirects=rds, assignments=assigns)
    return CommandSpec(
        name=words[0].literal or words[0].raw,
        words=words,
        raw=_slice(raw, node),
        redirects=rds,
        assignments=assigns,
    )


def _walk(
    node,
    raw: str,
    commands: list[CommandSpec],
    pipelines: list[PipelineSpec],
    redirects: list[RedirectSpec],
) -> None:
    kind = getattr(node, "kind", "")
    if kind == "command":
        spec = _command_spec(raw, node)
        commands.append(spec)
        redirects.extend(spec.redirects)
        # 递归 parts，处理 word 内嵌的 commandsubstitution / processsubstitution
        for p in getattr(node, "parts", []):
            for sub in getattr(p, "parts", []):
                _walk(sub, raw, commands, pipelines, redirects)
        return
    if kind == "pipeline":
        stage_specs: list[CommandSpec] = []
        for p in getattr(node, "parts", []):
            if getattr(p, "kind", "") == "command":
                spec = _command_spec(raw, p)
                stage_specs.append(spec)
                commands.append(spec)
                redirects.extend(spec.redirects)
            else:
                _walk(p, raw, commands, pipelines, redirects)
        if stage_specs:
            pipelines.append(PipelineSpec(stages=stage_specs, raw=_slice(raw, node)))
        return
    if kind == "list":
        for p in getattr(node, "parts", []):
            _walk(p, raw, commands, pipelines, redirects)
        return
    if kind == "compound":
        for p in getattr(node, "list", []) or []:
            _walk(p, raw, commands, pipelines, redirects)
        # 复合节点的 redirects 也算
        for p in getattr(node, "redirects", []) or []:
            redirects.append(_redirect_spec(raw, p))
        return
    if kind == "function":
        # 函数体：不递归的话 `f(){ rm -rf /; }; f` 整段不可见——定义处藏危险命令、
        # 调用处只剩一个无害的标识符，是最省事的一种规则绕过。
        for p in getattr(node, "parts", []) or []:
            _walk(p, raw, commands, pipelines, redirects)
        body = getattr(node, "body", None)
        if body is not None:
            _walk(body, raw, commands, pipelines, redirects)
        return
    if kind in ("commandsubstitution", "processsubstitution"):
        # $(...) / <(...) 内部递归
        cmd = getattr(node, "command", None)
        if cmd is not None:
            _walk(cmd, raw, commands, pipelines, redirects)
        return
    # 其它节点（word/parameter/reservedword/operator/...）忽略
