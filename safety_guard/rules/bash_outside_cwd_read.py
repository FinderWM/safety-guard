"""bash-outside-cwd-read：读取 CWD 外路径需用户确认。

覆盖两类读取通道：
  1. 白名单只读命令（cat/rg/grep/find/ls…）的路径参数
  2. 非白名单命令的读源——cp/scp/rsync 的源、dd if=、tar -f、curl -F @、
     openssl -in、ssh -i、source f，以及 `cmd < file` 输入重定向

第 2 类是补的洞：这些命令读文件的能力和 cat 完全一样，此前整组放行。

注意：- 指令区 (~/.claude / ~/.agents) 的读取按 CLAUDE.md 是豁免的，不触发
       - 路径必须显式以 / ~ $HOME 开头才检测（相对路径默认按 in-cwd）
"""
from __future__ import annotations

from ..context import BashContext
from ..helpers import (
    command_is_read_only,
    is_virtual_device_path,
    iter_path_args,
    iter_read_redirect_targets,
    iter_read_sources,
    looks_like_potentially_outside_path,
    strip_file_uri,
    strip_path_prefix,
    word_display,
)
from .base import Rule, RuleMatch
from .registry import register


@register
class BashOutsideCwdRead(Rule):
    id = "bash-outside-cwd-read"
    severity = "medium"
    applies_to = ("Bash",)
    description = "读取 CWD 外路径需用户确认（含 cp/dd/tar/curl 等读源，指令区豁免）"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        if ctx.ast is None:
            return None
        read_only = ctx.config.read_only_commands
        hits: list[str] = []
        seen: set[str] = set()

        def consider(w) -> None:
            text = strip_file_uri(strip_path_prefix(w.path_text))
            if not looks_like_potentially_outside_path(text):
                return
            try:
                if is_virtual_device_path(ctx.resolve(text)):
                    return
            except Exception:
                pass
            if ctx.classify(text) != "outside":
                return
            shown = word_display(w)
            if shown not in seen:
                seen.add(shown)
                hits.append(shown)

        for cmd in ctx.ast.commands:
            if command_is_read_only(cmd.name, cmd.args, read_only):
                for w in iter_path_args(cmd.name, cmd.args):
                    consider(w)
            else:
                for w in iter_read_sources(cmd.name, cmd.args, read_only):
                    consider(w)
            # wrapper 继承读源（xargs -a FILE 剥层后挂在 extra_reads）
            for w in getattr(cmd, "extra_reads", None) or []:
                consider(w)

        for w in iter_read_redirect_targets(ctx.ast.redirects):
            consider(w)

        if hits:
            return RuleMatch(
                rule_id=self.id,
                severity=self.severity,
                reason=f"`{ctx.raw_command}` 读取 CWD 之外的路径：{', '.join(hits)}",
                extra={"paths": hits},
            )
        return None
