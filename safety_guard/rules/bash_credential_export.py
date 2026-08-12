"""bash-credential-export：明确的凭据导出/读取命令（无路径槽也能命中）。"""
from __future__ import annotations

from ..context import BashContext
from ..helpers import normalize_cmd_name
from .base import Rule, RuleMatch
from .registry import register

# 环境变量名里的高敏片段（printenv/echo $VAR/export 读取）
_SECRET_ENV_MARKERS = (
    "SECRET", "TOKEN", "PASSWORD", "PASSWD", "API_KEY", "ACCESS_KEY",
    "PRIVATE_KEY", "CREDENTIAL", "AUTH_TOKEN",
)


@register
class BashCredentialExport(Rule):
    id = "bash-credential-export"
    severity = "medium"
    applies_to = ("Bash",)
    description = "gpg/security/kubectl/云 CLI 等凭据导出或密钥读取命令需用户确认"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        if ctx.ast is None:
            return None
        hits: list[str] = []
        for cmd in ctx.ast.commands:
            name = normalize_cmd_name(cmd.name or "")
            args = [getattr(w, "raw", str(w)) for w in cmd.words]
            low = [a.lower() for a in args]
            joined = " ".join(low)
            if name == "gpg" and any(a.startswith("--export-secret") for a in args):
                hits.append("gpg 导出私钥")
            elif name == "security" and any(
                a in ("find-generic-password", "find-internet-password", "dump-keychain")
                for a in args
            ):
                hits.append("security 读取钥匙串")
            elif name == "kubectl" and "secret" in args and any(
                a in ("get", "describe") for a in args
            ):
                hits.append("kubectl 读取 Secret")
            elif name == "op" and any(a in ("read", "get", "inject") for a in args):
                hits.append("op 读取秘密")
            elif name == "vault" and any(a in ("read", "kv") for a in args):
                hits.append("vault 读取秘密")
            elif name == "aws" and any(
                x in joined for x in ("secretsmanager", "get-secret-value", "ssm get-parameter")
            ):
                hits.append("aws 读取秘密")
            elif name in ("gcloud", "gcloud.cmd") and "secrets" in args and any(
                a in ("access", "versions", "describe") for a in args
            ):
                hits.append("gcloud 读取 Secret")
            elif name == "doppler" and any(a in ("secrets", "get", "run") for a in args):
                hits.append("doppler 读取秘密")
            elif name in ("printenv", "env") and any(
                any(m in a.upper() for m in _SECRET_ENV_MARKERS) for a in args[1:]
            ):
                hits.append(f"{name} 读取敏感环境变量")
            elif name == "export" and any(
                any(m in a.upper().split("=", 1)[0] for m in _SECRET_ENV_MARKERS) for a in args
            ):
                hits.append("export 敏感环境变量")
        if not hits:
            return None
        uniq = list(dict.fromkeys(hits))
        return RuleMatch(
            rule_id=self.id,
            severity=self.severity,
            reason=(
                f"`{ctx.raw_command}` 触发凭据导出/读取：{', '.join(uniq)}。"
                "输出可能含私钥或令牌，请确认是否必要。"
            ),
            extra={"hits": uniq},
        )
