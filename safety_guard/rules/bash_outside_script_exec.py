"""bash-outside-script-exec：用解释器/shell 直接执行 CWD 外的脚本文件。

`source /out/x.sh` 已由 outside-cwd-read 覆盖；但 `bash /out/x.sh`、
`python3 /out/x.py` 的路径参数被当成「要执行的脚本」而非普通读源——
INTERPRETERS 在 iter_write_targets 里整类排除，读源提取也不收，结果 ALLOW。

定级 medium：合法场景会跑系统工具脚本；与「读外传」同级确认即可。
"""
from __future__ import annotations

from ..context import BashContext
from ..helpers import (
    SCRIPT_RUNNERS,
    deno_bun_run_program_index,
    looks_like_potentially_outside_path,
    normalize_cmd_name,
    word_display,
)
from .base import Rule, RuleMatch
from .registry import register

_VALUE_OPTS = frozenset({
    "-c", "-e", "-r", "-E", "-Command", "-command",
    "--eval", "-p", "--print",
    "-C", "-f", "--file", "-S", "--split-string",
})


def _script_path_args(cmd) -> list:
    """跳过选项后的位置参数（脚本路径通常是第一个）。"""
    name = normalize_cmd_name(cmd.name or "")
    args = list(cmd.args)
    if name in ("deno", "bun"):
        raw_args = [getattr(arg, "raw", str(arg)) for arg in args]
        program_index = deno_bun_run_program_index(name, raw_args)
        return [args[program_index]] if program_index is not None else []
    i = 0
    while i < len(args):
        raw = args[i].raw
        if raw == "--":
            i += 1
            continue
        if raw.startswith("-") and raw != "-":
            if raw.startswith("--split-string="):
                i += 1
                continue
            if raw in _VALUE_OPTS:
                i += 2
                continue
            if (
                not raw.startswith("--")
                and "c" in raw[1:]
                and name in SCRIPT_RUNNERS
            ):
                i += 2
                continue
            i += 1
            continue
        return [args[i]]
    return []


@register
class BashOutsideScriptExec(Rule):
    id = "bash-outside-script-exec"
    severity = "medium"
    applies_to = ("Bash",)
    description = "用 shell/解释器执行 CWD 外脚本文件需用户确认"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        if ctx.ast is None:
            return None
        hits: list[str] = []
        for cmd in ctx.ast.commands:
            name = normalize_cmd_name(cmd.name or "")
            if name not in SCRIPT_RUNNERS:
                continue
            for w in _script_path_args(cmd):
                text = w.path_text
                if not looks_like_potentially_outside_path(text):
                    continue
                if ctx.classify(text) != "outside":
                    continue
                hits.append(f"{name} {word_display(w)}")
        if not hits:
            return None
        return RuleMatch(
            rule_id=self.id,
            severity=self.severity,
            reason=(
                f"`{ctx.raw_command}` 将执行 CWD 外的脚本：{', '.join(hits)}。"
                "脚本内容不经本闸门审查，等价于运行未知代码。"
            ),
            extra={"scripts": hits},
        )
