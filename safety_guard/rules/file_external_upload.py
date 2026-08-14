"""file-external-upload：本机文件即将通过外部工具上传。"""
from __future__ import annotations

from ..context import FileToolContext
from .base import Rule, RuleMatch
from .registry import register


@register
class FileExternalUpload(Rule):
    id = "file-external-upload"
    severity = "medium"
    applies_to = ("Read",)
    description = "本机文件将被上传到外部页面，无法在本地规则中验证接收方"

    def match(self, ctx: FileToolContext) -> RuleMatch | None:
        if ctx.raw_input.get("external_upload") is not True:
            return None
        source = ctx.raw_input.get("source_tool")
        source_name = source if isinstance(source, str) and source else "external tool"
        sensitive_path = ctx.target_path
        resolved_target = ctx.target_path
        resolution_failed = False
        if ctx.disk.first_symlink(ctx.target_path, root=ctx.cwd) is not None:
            try:
                resolved_target = ctx.target_path.resolve(strict=False)
                sensitive_path = resolved_target
            except (OSError, RuntimeError):
                resolution_failed = True
        actual_outside = resolved_target != ctx.cwd and ctx.cwd not in resolved_target.parents
        sensitive = _is_sensitive_path(sensitive_path)
        severity = (
            "medium"
            if (
                ctx.classification == "in-cwd"
                and not actual_outside
                and not sensitive
                and not resolution_failed
            )
            else "high"
        )
        suffix = "请确认接收方与文件内容" if severity == "medium" else "已拒绝"
        return RuleMatch(
            rule_id=self.id,
            severity=severity,
            reason=f"{source_name} 将上传本机文件 {ctx.target_path}，无法验证外部接收方，{suffix}",
            extra={
                "target": str(ctx.target_path),
                "resolved_target": str(resolved_target),
                "source_tool": source_name,
                "sensitive": sensitive,
                "actual_outside": actual_outside,
                "resolution_failed": resolution_failed,
            },
        )


def _is_sensitive_path(path) -> bool:
    parts = {part.lower() for part in path.parts}
    name = path.name.lower()
    sensitive_dirs = {
        ".ssh", ".aws", ".gnupg", ".kube", ".docker", ".azure", ".terraform.d", ".git",
    }
    public_key = name.startswith("id_") and name.endswith(".pub")
    if sensitive_dirs & parts and not (".ssh" in parts and public_key):
        return True
    if ".config" in parts and {"gcloud", "gh", "glab-cli", "op"} & parts:
        return True
    if name == ".env" or (
        name.startswith(".env.")
        and not name.endswith((".example", ".sample", ".template"))
    ):
        return True
    if name in {
        ".git-credentials",
        ".netrc",
        ".npmrc",
        ".pypirc",
        ".vault-token",
        "application_default_credentials.json",
        "credentials.json",
        "credentials.tfrc.json",
        "service-account.json",
    }:
        return True
    return (name.startswith("id_") and not public_key) or name.endswith((".pem", ".key", ".p12", ".pfx", ".jks"))
