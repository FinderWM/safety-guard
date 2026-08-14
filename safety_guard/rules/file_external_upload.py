"""file-external-upload：本机文件即将通过外部工具上传。"""
from __future__ import annotations

from ..context import FileToolContext
from .base import Rule, RuleMatch
from .registry import register


@register
class FileExternalUpload(Rule):
    id = "file-external-upload"
    severity = "high"
    applies_to = ("Read",)
    description = "本机文件将被上传到外部页面，无法在本地规则中验证接收方"

    def match(self, ctx: FileToolContext) -> RuleMatch | None:
        if ctx.raw_input.get("external_upload") is not True:
            return None
        source = ctx.raw_input.get("source_tool")
        source_name = source if isinstance(source, str) and source else "external tool"
        return RuleMatch(
            rule_id=self.id,
            severity=self.severity,
            reason=f"{source_name} 将上传本机文件 {ctx.target_path}，无法验证外部接收方，已拒绝",
            extra={"target": str(ctx.target_path), "source_tool": source_name},
        )
