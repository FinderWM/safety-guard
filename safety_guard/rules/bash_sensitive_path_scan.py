"""bash-sensitive-path-scan：敏感路径/密钥字面量的全文兜底扫描。

为什么需要：AST 之外的文本里藏着敏感路径，字面量扫描是唯一能抓到的通道。
  - heredoc 正文：`python3 - <<'PY' … open('/x/.ssh/key') … PY`，bashlex 把正文
    当分隔符吞掉，命令列表里只剩一个无害的 `python3`。
  - 解释器内联载荷的字面量：`python3 -c "open('~/.ssh/config')"`、`node -e
    "require('fs').readFileSync('...')"`。载荷是字面量，bash-opaque-inline-script
    只拦运行时才成形的 `$(…)`，这种整条 ALLOW。

扫描的是 ctx.raw_command（原始命令全文），不依赖 AST——parse 失败时同样生效。
范围刻意只覆盖「出现在文件系统里的真实密钥位置」，排除纯讨论/文档上下文
（`cat ~/.ssh/` 会被 bash-outside-cwd-read 兜住，这里补的是分析器看不见的那层）。

定级 medium：命中不代表一定在窃取（可能只是提到路径），让用户看一眼即可。
"""
from __future__ import annotations

import re

from ..context import BashContext
from .base import Rule, RuleMatch
from .registry import register

# 每个模式只匹配「真实文件系统位置」形态，避免把文档里的 `~/.ssh/` 讨论误伤
_PATTERNS = {
    # 目录形态：前面是引号/空白/赋值/路径分隔，后面紧跟斜杠
    "ssh-dir":      re.compile(r"(?:^|[/\s'\"=:])\.ssh/"),
    "ssh-key":      re.compile(r"\bid_(?:rsa|dsa|ecdsa|ed25519)\b"),
    "aws-cred":     re.compile(r"\.aws/(?:credentials|config)\b"),
    "gnupg":        re.compile(r"(?:^|[/\s'\"=:])\.gnupg\b"),
    "netrc":        re.compile(r"(?:^|[/\s'\"=:])\.netrc\b"),
    "kube-config":  re.compile(r"\.kube/config\b"),
    "docker-config":re.compile(r"\.docker/config\.json\b"),
    "gcloud":       re.compile(r"\.config/gcloud\b"),
    "npmrc":        re.compile(r"(?:^|[/\s'\"=:])\.npmrc\b"),
    "pem-key":      re.compile(r"\.(?:pem|p12|pfx|jks|keystore)\b"),
    "privkey-body": re.compile(
        r"BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+|PGP\s+)?PRIVATE\s+KEY",
        re.IGNORECASE,
    ),
}

# 刻意不收 `.env`：它是项目本地文件而非家目录凭据，`ls -la .env`、
# `cat ./.env.example` 这类日常操作会被整片误伤，信噪比不合格。
# 项目内的 .env 由 in-cwd 判定放行，跨 CWD 访问自有路径规则兜底。


def _scan_text(text: str) -> list[str]:
    return [name for name, rx in _PATTERNS.items() if rx.search(text)]


def _expanded_texts(ctx: BashContext) -> list[str]:
    """raw + 路径槽 expand/fold 候选。brace/ANSI-C 拆开后才能命中凭据模式。"""
    texts = [ctx.raw_command or ""]
    ast = ctx.ast
    if ast is None:
        return texts
    from .. import expand as expand_mod

    for cmd in ast.commands:
        for w in cmd.words:
            pt = getattr(w, "path_text", None) or getattr(w, "raw", "") or ""
            if not pt:
                continue
            texts.append(pt)
            try:
                texts.extend(expand_mod.candidates(pt) or [])
            except Exception:
                pass
        for r in cmd.redirects:
            t = getattr(r, "target", None)
            if t is None:
                continue
            pt = getattr(t, "path_text", None) or getattr(t, "raw", "") or ""
            if pt:
                texts.append(pt)
                try:
                    texts.extend(expand_mod.candidates(pt) or [])
                except Exception:
                    pass
    return texts


@register
class BashSensitivePathScan(Rule):
    id = "bash-sensitive-path-scan"
    severity = "medium"
    applies_to = ("Bash",)
    description = "命令全文出现敏感密钥路径/密钥体字面量需用户确认"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        hit_set: list[str] = []
        seen: set[str] = set()
        for text in _expanded_texts(ctx):
            if not text:
                continue
            for name in _scan_text(text):
                if name not in seen:
                    seen.add(name)
                    hit_set.append(name)
        if not hit_set:
            return None
        return RuleMatch(
            rule_id=self.id,
            severity=self.severity,
            reason=(
                f"命令全文出现敏感密钥路径/密钥体字面量：{', '.join(hit_set)}。"
                "可能读取、复制或外传 ~/.ssh、云凭证等机密文件。"
            ),
            extra={"patterns": hit_set},
        )
