"""共用辅助——保护分支、命令类别、glob 匹配等。"""
from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Iterable


SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish", "ash"})
NET_FETCHERS = frozenset({
    "curl", "wget", "fetch", "aria2c", "nc", "ncat",
    "http", "https", "httpie", "axel", "lwp-request",
})
# 管道终点：把远端字节流当程序跑的解释器（与 shell 同级拦截）
EXEC_INTERPRETERS = frozenset({
    "python", "python2", "python3",
    "node", "deno", "bun",
    "perl", "ruby", "php", "lua",
    "osascript", "pwsh", "powershell", "powershell.exe",
    "Rscript", "julia",
})
# busybox/toybox 多调用：`busybox sh` 的 argv[0] 是 busybox，真正 shell 在 argv[1]
_MULTICALL_BUSYBOX = frozenset({"busybox", "toybox"})
DESTRUCTIVE_GIT_SUBCOMMANDS = frozenset({"clean", "reset", "branch", "stash", "worktree", "rebase"})

# 可直接执行脚本文件的解释器/壳（路径操作数 outside → outside-script-exec）
SCRIPT_RUNNERS = frozenset(
    set(SHELLS)
    | {
        "python", "python2", "python3", "node", "deno", "bun",
        "perl", "ruby", "php", "lua", "osascript", "pwsh", "powershell",
        "Rscript", "julia", "make",
    }
)


def normalize_cmd_name(name: str) -> str:
    """去掉 argv[0] 的目录前缀，供按命令名匹配的规则使用。

    `/bin/bash`、`/usr/bin/curl` 与裸名同义；不剥的话 SHELLS/NET_FETCHERS/
    read_only_commands 的精确集合全被绕过。只取最后一段，不解析 PATH、不 follow link。
    """
    if not name:
        return name
    # 防御 `bash\n` 之类异常 token
    base = name.rstrip("/").rsplit("/", 1)[-1]
    return base if base else name


def redact_user_paths(text: str, home: str | None = None) -> str:
    """对外展示/审计前去掉真实家目录，避免 reason/audit 泄漏用户名路径。"""
    if not text:
        return text
    h = home or str(Path.home())
    if h and h in text:
        text = text.replace(h, "$HOME")
    # 常见绝对家目录形态（其它用户机器上的审计回放）
    if text.startswith("/Users/") or "/Users/" in text:
        import re
        text = re.sub(r"/Users/[^/\s\"']+", "$HOME", text)
    if text.startswith("/home/") or "/home/" in text:
        import re
        text = re.sub(r"/home/[^/\s\"']+", "$HOME", text)
    return text


def is_shell_name(name: str) -> bool:
    return normalize_cmd_name(name) in SHELLS


def is_net_fetcher_name(name: str) -> bool:
    return normalize_cmd_name(name) in NET_FETCHERS


def is_exec_interpreter_name(name: str) -> bool:
    return normalize_cmd_name(name) in EXEC_INTERPRETERS


def is_pipeline_exec_sink(cmd) -> bool:
    """管道终点是否会执行上游字节流（shell / busybox sh / 解释器）。"""
    raw_name = getattr(cmd, "name", "") or ""
    name = normalize_cmd_name(raw_name)
    if name in SHELLS or name in EXEC_INTERPRETERS:
        return True
    if name in _MULTICALL_BUSYBOX:
        args = getattr(cmd, "args", None) or getattr(cmd, "words", [])[1:]
        if not args:
            return False
        first = getattr(args[0], "literal", None) or getattr(args[0], "raw", "") or ""
        # busybox sh / busybox ash —— ash 也当 shell sink
        return normalize_cmd_name(first) in SHELLS or normalize_cmd_name(first) == "ash"
    return False


def pipeline_sink_label(cmd) -> str:
    """理由串里展示的终点名（保留 busybox sh 形态）。"""
    raw_name = getattr(cmd, "name", "") or ""
    name = normalize_cmd_name(raw_name)
    if name in _MULTICALL_BUSYBOX:
        args = getattr(cmd, "args", None) or []
        if args:
            sub = getattr(args[0], "literal", None) or getattr(args[0], "raw", "") or ""
            return f"{name} {normalize_cmd_name(sub)}"
    return name or raw_name

# 「选项 + 独立取值」形式的参数：跳过选项和它的值，避免把值当成路径操作数。
# 漏登记的后果是正则被当路径：`rg -C 8 '/api/foo' src` 里 `8` 被当成 pattern，
# 于是 `/api/foo` 变成「读 CWD 外路径」——Java 仓里正则带 / 极常见，是最高频误报。
# 只登记确实吃一个独立值的选项；错登记会把 pattern 或真实路径吞掉造成漏防，
# 所以 rg/grep 同名不同义的（rg -r=--replace 取值，grep -r=--recursive 不取值；
# rg -E=--encoding 取值，grep -E=--extended-regexp 不取值）必须分开维护。
_OPTION_TAKES_VALUE = {
    "rg": frozenset({
        "-e", "--regexp", "-f", "--file",
        "-g", "--glob", "--iglob", "-t", "--type", "-T", "--type-not", "--type-add",
        "-A", "--after-context", "-B", "--before-context", "-C", "--context",
        "-m", "--max-count", "--max-depth", "--max-filesize", "-M", "--max-columns",
        "-r", "--replace", "-j", "--threads", "-E", "--encoding",
        "--sort", "--sortr", "--color", "--colors", "--engine",
        "--ignore-file", "--pre", "--path-separator", "--context-separator",
        "--field-context-separator", "--field-match-separator",
        "--dfa-size-limit", "--regex-size-limit",
    }),
    "grep": frozenset({
        "-e", "--regexp", "-f", "--file",
        "-A", "--after-context", "-B", "--before-context", "-C", "--context",
        "-m", "--max-count", "-d", "--directories", "-D", "--devices",
        "--include", "--exclude", "--exclude-from", "--exclude-dir",
        "--binary-files", "--label", "--color", "--colour", "--group-separator",
    }),
    "sed": frozenset({"-e", "--expression", "-f", "--file"}),
    "awk": frozenset({"-f", "--file", "-v", "-F"}),
}

# pattern 由选项显式给出时，后续位置参数一律是路径（否则第一个路径会被当成 pattern
# 吞掉：`rg -e foo /etc/passwd` 曾整条放行）
_PATTERN_FROM_OPTION = {
    "rg": frozenset({"-e", "--regexp", "-f", "--file"}),
    "grep": frozenset({"-e", "--regexp", "-f", "--file"}),
}



def matches_any_glob(name: str, patterns: tuple[str, ...]) -> bool:
    """fnmatch 通配匹配，如 'release/*' 匹配 'release/1.0'。"""
    return any(fnmatch.fnmatchcase(name, p) for p in patterns)


def is_protected_branch(branch: str, protected: tuple[str, ...]) -> bool:
    return matches_any_glob(branch, protected)


def is_root_like_path(path: str) -> bool:
    """判断字符串是不是 /、/*、~、~/、$HOME、$HOME/* 这类整盘/整家路径。"""
    s = path.strip()
    if s in ("/", "/*", "~", "~/", "~/*"):
        return True
    if s in ("$HOME", "${HOME}", "$HOME/", "${HOME}/", "$HOME/*", "${HOME}/*"):
        return True
    return False


def word_display(w) -> str:
    """理由串里展示 word：折叠改变了含义时同时给出原文与折叠结果。

    `$A/config` 单独看不出指向哪，`$A/config → $HOME/…` 才让用户有判断依据。
    折叠后的绝对家目录会脱敏，避免确认框/审计泄漏真实用户名路径。
    """
    raw = getattr(w, "raw", str(w))
    folded = getattr(w, "folded", None)
    if folded and folded != raw:
        return f"{raw} → {redact_user_paths(folded)}"
    return redact_user_paths(raw)


def has_traversal(token: str) -> bool:
    """token 里是否含 `..` 路径段。

    `cat ../../x` 不是混淆，是最朴素的越界读法，却因为不以 / ~ $HOME 开头被
    looks_like_potentially_outside_path 整类跳过——折叠层、展开层、路径分类全都
    没机会介入。classify() 用 normpath 本来就能正确解析 ..，缺的只是让它被调用。

    带空白的 token 直接排除：`git commit -m "fix ../ bug"` 这类文案里也有 ..，
    而真实路径操作数极少带空格——这一条挡掉绝大部分误报。
    """
    if ".." not in token or any(ch.isspace() for ch in token):
        return False
    return any(seg == ".." for seg in token.split("/"))


def looks_like_potentially_outside_path(token: str) -> bool:
    """token 是否可能解析到 CWD 之外。

    两类入口：以 / ~ $HOME 开头的绝对/家目录路径，以及含 `..` 段的相对穿越。
    其余相对路径默认假定在 CWD 内（避免把 commit message 等当路径误判）。

    含 brace/ANSI-C/转义时按展开后的候选判断：`~/.ss{,}h` 的原文以 `~` 开头没问题，
    但 `.ss{,}h` 这类变体不展开就看不出指向哪，任一候选像外部路径即返回 True。
    """
    if not token:
        return False
    token = strip_file_uri(token)
    if token.startswith("-"):
        return False
    if _starts_outside(token) or has_traversal(token):
        return True
    from . import expand as _expand_mod
    try:
        cands = _expand_mod.candidates(token)
    except Exception:
        return False
    return any(_starts_outside(c) or has_traversal(c) for c in cands if c != token)


def strip_path_prefix(token: str) -> str:
    """剥掉 `key=`、`key=@`、`@` 这类前缀，露出其中的路径。

    `dd if=/etc/shadow`、`curl -F key=@/etc/shadow` 的路径嵌在 token 中段，
    直接按「以 / 开头」判断会整条漏掉——这两个形态正是红队里 curl/dd 逃逸的原因。
    """
    if not token:
        return token
    body = token
    if "=" in body:
        head, tail = body.split("=", 1)
        # 只在左侧像选项名（无路径分隔符）时才认为是 key=value
        if "/" not in head and "~" not in head:
            body = tail
    return body[1:] if body.startswith("@") else body


def _starts_outside(token: str) -> bool:
    return (
        token.startswith("/")
        or token.startswith("~")
        or token.startswith("$HOME")
        or token.startswith("${HOME}")
    )


def command_uses_in_place_edit(name: str, args: Iterable) -> bool:
    """Return whether sed/awk style command mutates input files in place."""
    raw_args = [getattr(a, "raw", str(a)) for a in args]
    if name == "sed":
        return any(
            a == "-i"
            or a.startswith("-i")
            or a == "--in-place"
            or a.startswith("--in-place=")
            for a in raw_args
        )
    if name == "awk":
        for i, a in enumerate(raw_args):
            if a in ("--in-place", "-iinplace"):
                return True
            if a == "-i" and i + 1 < len(raw_args) and raw_args[i + 1] == "inplace":
                return True
        return False
    return False


def command_is_read_only(name: str, args: Iterable, read_only_commands: frozenset[str]) -> bool:
    """Return whether a command should be treated as path-read-only."""
    name = normalize_cmd_name(name)
    if name not in read_only_commands:
        return False
    if name in ("sed", "awk"):
        return not command_uses_in_place_edit(name, args)
    return True


def iter_path_args(name: str, args: list) -> list:
    """Extract likely file path operands for common read/search tools.

    Regex/program operands for rg/grep/sed/awk are intentionally skipped so a
    pattern like `/api/foo|/api/bar` is not mistaken for an absolute path.
    """
    name = normalize_cmd_name(name)
    if name in ("rg", "grep"):
        return _path_args_after_pattern(name, args)
    if name in ("sed", "awk"):
        return _path_args_after_script(name, args)
    return [a for a in args if not getattr(a, "raw", str(a)).startswith("-")]


_VIRTUAL_DEVICES = frozenset({
    "/dev/null", "/dev/zero", "/dev/full",
    "/dev/random", "/dev/urandom",
    "/dev/stdin", "/dev/stdout", "/dev/stderr",
    "/dev/tty", "/dev/console",
})


def is_virtual_device_path(path: Path | str) -> bool:
    """/dev/null、/dev/zero 等不是跨 CWD 的真实文件。"""
    text = str(path)
    if text in _VIRTUAL_DEVICES:
        return True
    return text.startswith("/dev/fd/") or text.startswith("/dev/pts/")


def is_null_device_path(path: Path) -> bool:
    return is_virtual_device_path(path)


def strip_file_uri(token: str) -> str:
    """`file:///etc/passwd` → `/etc/passwd`；非 file: 原文返回。"""
    if not token:
        return token
    lower = token.lower()
    if lower.startswith("file://"):
        rest = token[7:]
        if rest.lower().startswith("localhost"):
            rest = rest[9:]
        if rest.startswith("/"):
            return rest
        return "/" + rest if rest else token
    if lower.startswith("file:"):
        rest = token[5:]
        return rest if rest.startswith("/") else token
    return token


# ---------------------------------------------------------------------------
# 写入目标提取
#
# bash-instruction-zone-write / bash-outside-cwd-write 原先各自「非只读命令的全部
# argv 都算写目标」，把大量纯读误判成写：`curl -o /dev/null`、`mvn --settings X`、
# `bash <脚本>`、`cp <源> <目的>` 的源、`cd <目录>`。两条规则只有 classify() 结果
# 不同，提取逻辑抽这里统一。
# ---------------------------------------------------------------------------

# 只切换目录，不写任何东西
NAVIGATION_COMMANDS = frozenset({"cd", "pushd", "popd", "dirs"})

# 解释器：路径操作数是「被执行的脚本」，读不是写
INTERPRETERS = frozenset({
    "bash", "sh", "zsh", "dash", "ksh", "fish", "ash",
    "python", "python3", "python2",
    "node", "deno", "bun", "ruby", "perl", "php", "lua",
    "osascript", "Rscript", "pwsh", "powershell",
    "java", "go", "uv", "uvx", "npx", "pnpx", "julia",
})

# 参数是纯数据、从不打开文件的命令。它们的输出去向由重定向分支单独判定，
# 所以把 argv 排除掉不会漏防：`echo x > <外部路径>` 仍由 redirect 命中。
# 不排除的话「未知命令 → 全部 argv 算写目标」的兜底会把数据当路径：
# `echo '../../x' >> ./.gitignore` 里的 `../../x` 只是要写进文件的一行文本。
DATA_ONLY_COMMANDS = frozenset({
    "echo", "printf", "seq", "sleep", "expr", "true", "false", ":",
    # 赋值内建：`export PATH=/usr/local/bin:$PATH` 的值不是写目标
    "export", "declare", "typeset", "readonly", "unset", "local",
})

# 任何命令下都按「只读配置」处理的选项，其值不算写目标
_READ_ONLY_VALUE_OPTS_ANY = frozenset({
    "--config", "--configfile", "--config-file", "--settings", "--rcfile",
    "--conf", "--global-settings", "--from-file",
})

# 特定命令的只读选项（值是被读取的配置/输入，不是写目标）
_READ_ONLY_VALUE_OPTS = {
    "mvn": frozenset({"-s", "--settings", "-gs", "--global-settings", "-f", "--file", "-o"}),
    "mvnw": frozenset({"-s", "--settings", "-gs", "--global-settings", "-f", "--file"}),
    "gradle": frozenset({"-b", "--build-file", "-c", "--settings-file", "-I", "--init-script"}),
    "eslint": frozenset({"-c", "--config", "--resolve-plugins-relative-to"}),
    "prettier": frozenset({"--config", "--ignore-path"}),
    "markdownlint-cli2": frozenset({"--config"}),
    "pytest": frozenset({"-c", "--rootdir"}),
    "docker": frozenset({"--config"}),
    "ssh": frozenset({"-F", "-i"}),
    "scp": frozenset({"-F", "-i"}),
    "git": frozenset({"-C", "--git-dir", "--work-tree", "--exec-path"}),
}

# 只有这些选项的值才是写目标，其余 argv（URL 等）一概不算
_WRITE_ONLY_VALUE_OPTS = {
    "curl": frozenset({"-o", "--output", "--dump-header", "-D", "--trace", "--trace-ascii", "--cookie-jar", "-c"}),
    "wget": frozenset({"-O", "--output-document", "-o", "--output-file", "-a", "--append-output"}),
    "tar": frozenset({"-f", "--file"}),
}

# 源是读、只有目的地是写
_DEST_ONLY_COMMANDS = frozenset({"cp", "install", "rsync", "scp"})
_DEST_DIR_OPTS = frozenset({"-t", "--target-directory"})


# ---------------------------------------------------------------------------
# 读取来源提取
#
# 写侧建模完整，读侧却只覆盖 read_only_commands 白名单（cat/rg/grep…），于是
# 红队里「非 cat 的读法」整组漏光：cp/dd/tar/curl -F @/scp/rsync 的**源文件**、
# `source f`、`cmd < f` 全部放行。这些命令读文件的能力和 cat 完全一样。
#
# 与 iter_write_targets 对称：同一批 argv，按命令的参数语义分成「读的那些」和
# 「写的那些」。cp 的源在这里、目的地在那里，两边互补而非重叠。
# ---------------------------------------------------------------------------

# 位置参数里「最后一个是目的地、其余都是源」的命令
_SRC_THEN_DEST_COMMANDS = frozenset({"cp", "mv", "install", "rsync", "scp"})

# 「选项 + 值」形式指定输入文件
_READ_VALUE_OPTS = {
    "dd": frozenset({"if"}),                      # dd if=FILE（key=value 形态，单独处理）
    "tar": frozenset({"-f", "--file"}),
    "openssl": frozenset({"-in", "-inkey", "-CAfile", "-cert", "-key"}),
    "ssh": frozenset({"-i"}),
    "sftp": frozenset({"-i"}),
    "gpg": frozenset({"--decrypt", "-d"}),
    "sqlite3": frozenset({"-init"}),
}

# 内建：把文件内容当脚本执行——读取能力等同 cat，且立即执行
_SOURCE_BUILTINS = frozenset({"source", "."})

# 这些命令的路径操作数只被读取，不写：归 iter_read_sources，不进 iter_write_targets。
# dd 刻意不在此列——它同时读写，if= 归读、of= 归写，整个当只读等于把 `dd of=<路径>`
# 这条最经典的覆写原语彻底摘掉。
READ_ONLY_SOURCE_COMMANDS = frozenset({"source", ".", "openssl", "ssh", "sftp", "gpg"})

# 纯读方向的重定向：目标是被读的文件，不是写目标。
# 刻意不含 `<>`（读写打开，按写处理更保守）与 `<&`（复制 fd，目标是数字不是路径）。
# 此前这里有两处同名定义，窄的那条覆盖了宽的那条——留一处，避免看着像支持其实没有。
READ_REDIRECT_OPS = frozenset({"<", "<<<"})

# tar 传统无横杠写法的合法模式字母，用于区分 `czf` 与真实路径操作数
_TAR_MODE_LETTERS = frozenset("cxtrufzjJvpahmkPWO")


def _kv_option_values(args: list, keys: frozenset[str]) -> list:
    """提取 `key=value` 形态选项的值 word（dd if=FILE）。

    返回的是原 word 对象——值和键在同一个 token 里，规则侧用 path_text 取
    折叠结果时需要整体判断，所以这里保留 word 而非切出字符串。
    """
    out: list = []
    for a in args:
        raw = getattr(a, "raw", str(a))
        if "=" in raw and raw.split("=", 1)[0] in keys:
            out.append(a)
    return out


def iter_read_sources(name: str, args: list, read_only_commands: frozenset[str]) -> list:
    """返回命令中会被**读取**的路径 words。

    与 iter_write_targets 互补：白名单只读命令的路径参数由 iter_path_args 负责，
    这里补的是「不在白名单、但确实读文件」的那批命令。
    """
    if not name:
        return []
    name = normalize_cmd_name(name)
    # 白名单只读命令走既有通道，避免重复上报
    if command_is_read_only(name, args, read_only_commands):
        return []

    if name in _SOURCE_BUILTINS:
        return _positional_args(args)

    if name == "dd":
        return _kv_option_values(args, frozenset({"if"}))

    if name == "tar":
        return _tar_read_sources(args)

    if name in _READ_VALUE_OPTS:
        return _option_values(args, _READ_VALUE_OPTS[name])

    if name in NET_FETCHERS:
        # curl -F key=@FILE / -T FILE / --data-binary @FILE：把本地文件上传出去，
        # 是「读 + 外传」，比单纯读更值得确认
        out: list = []
        for a in args:
            raw = getattr(a, "raw", str(a))
            if "@" in raw and not raw.startswith("-"):
                out.append(a)
            if raw.lower().startswith("file:"):
                out.append(a)
        out.extend(_option_values(args, frozenset({"-T", "--upload-file"})))
        return out

    if name == "xargs":
        # xargs -a FILE / --arg-file=FILE：从文件读参数列表，等同读源
        return _option_values(args, frozenset({"-a", "--arg-file"}))

    if name in _SRC_THEN_DEST_COMMANDS:
        positional = _positional_args(_skip_read_only_options(name, args))
        return positional[:-1] if len(positional) >= 2 else []

    return []


def iter_read_redirect_targets(redirects: list) -> list:
    """输入重定向的来源 word：`cat < /etc/shadow` 里的 /etc/shadow。"""
    out: list = []
    for r in redirects:
        if getattr(r, "op", "") in READ_REDIRECT_OPS and getattr(r, "target", None) is not None:
            out.append(r.target)
    return out


def _positional_args(args: list) -> list:
    """去掉选项与它们的值之外的裸操作数（保守：只按前缀判断选项）。"""
    return [a for a in args if not getattr(a, "raw", str(a)).startswith("-")]


def _skip_read_only_options(name: str, args: list) -> list:
    """丢掉只读选项及其值，返回剩下的 words。"""
    ro = _READ_ONLY_VALUE_OPTS.get(name, frozenset()) | _READ_ONLY_VALUE_OPTS_ANY
    out: list = []
    i = 0
    while i < len(args):
        raw = getattr(args[i], "raw", str(args[i]))
        if raw in ro:
            i += 2
            continue
        if raw.startswith("--") and "=" in raw and raw.split("=", 1)[0] in ro:
            i += 1
            continue
        out.append(args[i])
        i += 1
    return out


def _option_values(args: list, opts: frozenset[str]) -> list:
    """收集指定选项的值（支持 `--opt=value` 与 `--opt value` 两种写法）。"""
    out: list = []
    i = 0
    while i < len(args):
        raw = getattr(args[i], "raw", str(args[i]))
        if raw in opts and i + 1 < len(args):
            out.append(args[i + 1])
            i += 2
            continue
        if "=" in raw and raw.split("=", 1)[0] in opts:
            # `--opt=value`：值就嵌在同一个 word 里。此前这里只 i += 1 跳过，
            # 等于把命中的路径丢掉——`tar --file=<secret> -x` 因此整条漏检。
            out.append(args[i])
            i += 1
            continue
        i += 1
    return out


def _tar_letters(args: list) -> str:
    """收集 tar 的模式字母，兼容 `-czf`、`--create`、无横杠的 `czf` 三种风格。"""
    letters = ""
    for i, a in enumerate(args):
        t = getattr(a, "raw", str(a))
        if t.startswith("--"):
            letters += t[2:].split("=", 1)[0]
        elif t.startswith("-"):
            letters += t[1:]
        elif i == 0 and _is_tar_mode_token(t):
            # BSD/GNU 传统写法：首个操作数无横杠，如 `tar czf out.tgz src`
            letters += t
    return letters


def _tar_archive_word(args: list, letters: str):
    """定位 tar 的档案参数（-f 的值），支持捆绑写法。

    `-cf X` / `czf X` 里 -f 混在字母串中，`_option_values` 只认独立的 `-f`，
    所以必须单独处理：档案是「含 f 的那个选项 token」之后的第一个位置参数。
    """
    explicit = _option_values(args, frozenset({"-f", "--file"}))
    if explicit:
        return explicit[0]
    if "f" not in letters:
        return None
    seen_flag = False
    for a in args:
        raw = getattr(a, "raw", str(a))
        if not seen_flag:
            if (raw.startswith("-") and "f" in raw.lstrip("-")) or _is_tar_mode_token(raw):
                seen_flag = True
            continue
        if not raw.startswith("-"):
            return a
    return None


def _tar_read_sources(args: list) -> list:
    """tar 的读源随模式翻转，且短选项可捆绑——与 `bash -cx` 同一类绕过。

    -c 建档：档案 -f 是写目标，位置参数是被读的源
    -x/-t     ：档案 -f 才是被读的对象

    -c 判别必须同时接受 `-czf` 与无前导横杠的 `czf`（GNU/BSD 双风格），
    -f 的取值支持 `-f X`、`--file=X`、捆绑 `xzf X` 三种写法。
    """
    letters = _tar_letters(args)
    if "c" in letters:
        # -c 建档：档案（-f 的值）是写目标，剩余位置参数才是被读的源。
        # 捆绑写法 `-cf X` 里 -f 不是独立 token，必须走 _tar_archive_word 定位，
        # 否则 X 留在位置参数里，会把写目标当成读源误报。
        archive = _tar_archive_word(args, letters)
        skip = {id(archive)} if archive is not None else set()
        return [
            a for a in _positional_args(_skip_read_only_options("tar", args))
            if id(a) not in skip and not _is_tar_mode_token(getattr(a, "raw", str(a)))
        ]
    # -x/-t：档案本身被读。捆绑写法 `xzf X` 里 -f 不是独立 token，统一走
    # _tar_archive_word 定位，避免取到模式串 "xzf" 而非档案路径。
    archive = _tar_archive_word(args, letters)
    return [archive] if archive is not None else []


def _is_tar_mode_token(text: str) -> bool:
    """`czf` / `xzf` 这类无横杠模式串——不是路径。"""
    return bool(text) and "/" not in text and all(ch in _TAR_MODE_LETTERS for ch in text)


def iter_write_targets(name: str, args: list, read_only_commands: frozenset[str]) -> list:
    """返回命令中真正会被写/删/移的路径 words。纯读命令返回空。"""
    if not name:
        return []
    name = normalize_cmd_name(name)
    if command_is_read_only(name, args, read_only_commands):
        return []
    if name in NAVIGATION_COMMANDS or name in INTERPRETERS:
        return []
    if name in DATA_ONLY_COMMANDS:
        return []
    # 纯读命令：路径参数是输入而非输出。不排除的话会同时报 read + write，
    # 决策虽仍是 ask，但理由写成「写」——将来给这些命令加白名单时，
    # 拦截会静默消失而没人发现。
    if name in READ_ONLY_SOURCE_COMMANDS:
        return []

    if name == "dd":
        # dd 同时读写：if= 是读源（归 iter_read_sources），of= 才是写目标。
        # 整命令当只读会漏掉 `dd of=<文件>`——它能直接覆写任意路径。
        return _kv_option_values(args, frozenset({"of"}))

    if name == "tar":
        # -f 语义随模式翻转：-c 建档时档案是写目标；-x/-t 时档案是被读的源。
        # 捆绑写法 `-cf X` 里 -f 不是独立 token，_option_values 只认独立 -f 会漏，
        # 统一走 _tar_archive_word 定位。
        flags_letters = _tar_letters(args)
        archive = _tar_archive_word(args, flags_letters)
        if "c" in flags_letters:
            return [archive] if archive is not None else []
        return []

    if name in _WRITE_ONLY_VALUE_OPTS:
        candidates = _option_values(args, _WRITE_ONLY_VALUE_OPTS[name])
    elif name in _DEST_ONLY_COMMANDS:
        # cp/rsync/scp：源只是读；-t DIR 指定目的地时所有位置参数都是源
        dest_dirs = _option_values(args, _DEST_DIR_OPTS)
        if dest_dirs:
            candidates = dest_dirs
        else:
            positional = _positional_args(_skip_read_only_options(name, args))
            candidates = positional[-1:] if len(positional) >= 2 else positional
    elif name in ("sed", "awk"):
        candidates = iter_path_args(name, args)
    else:
        candidates = _skip_read_only_options(name, args)

    return [w for w in candidates if getattr(w, "raw", str(w)) != "/dev/null"]



def _path_args_after_pattern(name: str, args: list) -> list:
    paths: list = []
    pattern_seen = False
    files_only = False
    takes_value = _OPTION_TAKES_VALUE.get(name, frozenset())
    from_option = _PATTERN_FROM_OPTION.get(name, frozenset())
    i = 0
    while i < len(args):
        raw = getattr(args[i], "raw", str(args[i]))
        if raw in ("--files", "--files-with-matches", "--files-without-match"):
            files_only = True
            i += 1
            continue
        if raw in from_option:
            # pattern 由 -e/-f 提供，后面的位置参数全都是路径而非 pattern
            pattern_seen = True
            i += 2
            continue
        if raw in takes_value:
            i += 2
            continue
        if raw.startswith("--") and "=" in raw:
            if raw.split("=", 1)[0] in from_option:
                pattern_seen = True
            i += 1
            continue
        if raw.startswith("-") and raw != "-":
            i += 1
            continue
        if files_only:
            paths.append(args[i])
        elif not pattern_seen:
            pattern_seen = True
        else:
            paths.append(args[i])
        i += 1
    return paths


def _path_args_after_script(name: str, args: list) -> list:
    paths: list = []
    script_seen = False
    script_from_option = False
    i = 0
    while i < len(args):
        raw = getattr(args[i], "raw", str(args[i]))
        if raw in _OPTION_TAKES_VALUE.get(name, frozenset()):
            script_from_option = True
            i += 2
            continue
        if name == "sed" and raw == "-i" and i + 1 < len(args):
            next_raw = getattr(args[i + 1], "raw", str(args[i + 1]))
            if next_raw in ("", "''", '""'):
                i += 2
                continue
        if name == "awk" and raw == "-i" and i + 1 < len(args):
            i += 2
            continue
        if raw in ("--in-place",):
            i += 1
            continue
        if raw.startswith("--") and "=" in raw:
            i += 1
            continue
        if raw.startswith("-") and raw not in ("-",):
            i += 1
            continue
        if script_from_option or script_seen:
            paths.append(args[i])
        else:
            script_seen = True
        i += 1
    return paths

