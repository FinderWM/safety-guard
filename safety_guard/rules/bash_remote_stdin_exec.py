"""bash-remote-stdin-exec：shell/source 从 stdin/进程替换执行且脚本来自网络抓取。

与 bash-pipe-to-shell / eval-from-network 同级（high）。

覆盖：
  bash -s < <(curl …)
  bash < <(wget …)
  zsh <(curl …)          # 位置参数形态的 process-subst
  source /dev/stdin <<< "$(curl …)"
"""
from __future__ import annotations

from ..bash_ast import is_process_subst_script_word, word_is_inline_command_flag
from ..context import BashContext
from ..helpers import NET_FETCHERS, is_shell_name, normalize_cmd_name
from .base import Rule, RuleMatch
from .registry import register

_STDIN_TARGETS = frozenset({"/dev/stdin", "-", "/dev/fd/0"})
_SOURCE = frozenset({"source", "."})


def _has_fetcher(text: str) -> bool:
    return any(f in text for f in NET_FETCHERS)


def _shell_or_source(cmd) -> bool:
    name = normalize_cmd_name(cmd.name)
    return is_shell_name(name) or name in _SOURCE


@register
class BashRemoteStdinExec(Rule):
    id = "bash-remote-stdin-exec"
    severity = "high"
    applies_to = ("Bash",)
    description = "拦截 shell/source 从 stdin/进程替换执行网络抓取得到的脚本"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        if ctx.ast is None:
            return None
        for cmd in ctx.ast.commands:
            if not _shell_or_source(cmd):
                continue
            name = normalize_cmd_name(cmd.name)
            # -c 载荷由 eval-from-network / 递归解析负责
            if is_shell_name(name) and any(word_is_inline_command_flag(w) for w in cmd.words[1:]):
                continue

            # 1) 位置参数 process-subst：bash <(curl …) / zsh <(curl …)
            for w in cmd.words[1:]:
                if w.raw.startswith("-") and w.raw not in ("-", "--"):
                    continue
                if w.raw == "--":
                    continue
                if is_process_subst_script_word(w) and _has_fetcher(w.raw):
                    return RuleMatch(
                        rule_id=self.id,
                        severity=self.severity,
                        reason=(
                            f"拒绝执行：`{ctx.raw_command}` 让 {name} 以进程替换为脚本源，"
                            f"且来源含网络抓取，等同于盲跑远端代码。"
                        ),
                        extra={"shell": name, "source": w.raw},
                    )
                break

            # 2) source /dev/stdin
            if name in _SOURCE:
                pos = [w.raw for w in cmd.args if not w.raw.startswith("-")]
                if not any(p in _STDIN_TARGETS for p in pos):
                    # 非 stdin 的 source 不走本规则
                    if not any(is_process_subst_script_word(w) for w in cmd.args):
                        continue

            # 3) 重定向 stdin / here-string
            for r in cmd.redirects:
                if r.op not in ("<", "<<<") or r.target is None:
                    continue
                t = r.target
                if not (t.has_expansion or is_process_subst_script_word(t)):
                    continue
                if not _has_fetcher(t.raw) and not _has_fetcher(cmd.raw):
                    continue
                return RuleMatch(
                    rule_id=self.id,
                    severity=self.severity,
                    reason=(
                        f"拒绝执行：`{ctx.raw_command}` 让 {name} 从 stdin/进程替换执行脚本，"
                        f"且脚本来源含网络抓取，等同于盲跑远端代码。"
                    ),
                    extra={"shell": name, "redirect": f"{r.op} {t.raw}"},
                )
        return None
