"""bash-terraform-destroy：Terraform destroy 会删除当前 state 管理的资源。"""
from __future__ import annotations

from ..context import BashContext
from ..helpers import normalize_cmd_name
from .base import Rule, RuleMatch
from .registry import register


_SAFE_INFO_FLAGS = frozenset({"--help", "-help", "-h"})
_VALUE_OPTIONS = frozenset({"-chdir"})


def _terraform_subcommand(args: list[str]) -> tuple[str | None, list[str]]:
    index = 0
    while index < len(args):
        raw = args[index]
        if raw in _VALUE_OPTIONS:
            index += 2
            continue
        if raw.startswith("--") and "=" in raw:
            index += 1
            continue
        if raw.startswith("-"):
            index += 1
            continue
        return raw, args[index + 1 :]
    return None, []


@register
class BashTerraformDestroy(Rule):
    id = "bash-terraform-destroy"
    severity = "medium"
    applies_to = ("Bash",)
    description = "terraform destroy 删除基础设施资源，需用户确认"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        if ctx.ast is None:
            return None
        for cmd in ctx.ast.commands:
            if normalize_cmd_name(cmd.name or "") != "terraform":
                continue
            args = [getattr(w, "raw", str(w)) for w in cmd.args]
            subcommand, sub_args = _terraform_subcommand(args)
            if subcommand != "destroy":
                continue
            if any(arg in _SAFE_INFO_FLAGS for arg in sub_args):
                continue
            return RuleMatch(
                rule_id=self.id,
                severity=self.severity,
                reason=f"`{ctx.raw_command}` 将执行 terraform destroy，可能删除托管资源，请确认。",
            )
        return None
