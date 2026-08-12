"""bash-pipe-to-shell：curl|sh / wget|bash / base64 -d|sh 这类管道到执行端的任意代码执行。

终点不仅是裸名 shell：`/bin/bash`、`busybox sh`、以及把 stdin 当程序跑的
python/node 等解释器与 shell 同级拦截。起点抓取器经 basename 规范化，并含 nc。
"""
from __future__ import annotations

from ..context import BashContext
from ..helpers import (
    SHELLS,
    is_net_fetcher_name,
    is_pipeline_exec_sink,
    normalize_cmd_name,
    pipeline_sink_label,
)
from .base import Rule, RuleMatch
from .registry import register


@register
class BashPipeToShell(Rule):
    id = "bash-pipe-to-shell"
    severity = "high"
    applies_to = ("Bash",)
    description = "拦截 curl|sh / base64|bash（high）及本地构造管道进 shell/解释器（medium）"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        if ctx.ast is None:
            return None
        soft: RuleMatch | None = None
        for pl in ctx.ast.pipelines:
            stages = pl.stages
            if len(stages) < 2:
                continue
            sink = stages[-1]
            if not is_pipeline_exec_sink(sink):
                continue
            last_label = pipeline_sink_label(sink)
            first = stages[0]
            first_name = normalize_cmd_name(first.name)
            # 模式 1：网络抓取在管道头（中间可夹 tee/sed）
            if is_net_fetcher_name(first.name):
                return RuleMatch(
                    rule_id=self.id,
                    severity=self.severity,
                    reason=(
                        f"拒绝执行：`{ctx.raw_command}` 是 `{first_name} … | {last_label}` 模式，"
                        f"等同于直接执行远端任意代码。先下载到本地审查后再运行。"
                    ),
                    extra={"first": first_name, "last": last_label},
                )
            # 模式 2：管道里出现 base64 解码再喂执行端
            mid = [normalize_cmd_name(s.name) for s in stages[:-1]]
            if "base64" in mid:
                return RuleMatch(
                    rule_id=self.id,
                    severity=self.severity,
                    reason=(
                        f"拒绝执行：`{ctx.raw_command}` 中 base64 解码后直接喂给 {last_label}，"
                        f"是典型的混淆代码注入模式。"
                    ),
                    extra={"last": last_label},
                )
            # 模式 3：本地构造再喂 shell（printf|bash、echo|sh…）。
            # 解释器终点仍靠 high 的 curl|python 与 interpreter-* 规则，避免
            # `cat x | python3 -m json.tool` 之类日常管道被 medium 误伤。
            sink_name = normalize_cmd_name(getattr(sink, "name", "") or "")
            if soft is None and sink_name in SHELLS:
                soft = RuleMatch(
                    rule_id=self.id,
                    severity="medium",
                    reason=(
                        f"`{ctx.raw_command}` 将数据管道进 `{last_label}`，"
                        "等同于执行管道上游生成的代码。请确认上游输出可信，"
                        "或改为写入文件审查后再运行。"
                    ),
                    extra={"first": first_name, "last": last_label, "mode": "local-pipe"},
                )
        return soft
