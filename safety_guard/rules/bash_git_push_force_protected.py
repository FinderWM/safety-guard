"""bash-git-push-force-protected：git push --force 到 main/master/release/*。"""
from __future__ import annotations

from ..context import BashContext
from ..helpers import is_protected_branch
from .base import Rule, RuleMatch
from .registry import register


def _is_force(words) -> bool:
    for w in words[1:]:
        s = w.raw
        if s == "--force" or s == "--force-with-lease" or s == "-f":
            return True
        if s.startswith("-") and not s.startswith("--") and "f" in s and "r" not in s:
            # 组合短选项 -fu 等。-r 不是 push 的选项，这里粗略
            return True
        # refspec 强制：+main、+refs/heads/main:refs/heads/main
        if s.startswith("+") and len(s) > 1:
            return True
        if ":" in s and s.split(":", 1)[0].startswith("+"):
            return True
    return False


def _normalize_branch(token: str) -> str:
    """去掉 + / : 前缀和 refs/heads/，得到分支名。"""
    t = token[1:] if token.startswith("+") else token
    if t.startswith(":"):
        t = t[1:]
    elif ":" in t:
        t = t.split(":", 1)[-1]
    for prefix in ("refs/heads/", "refs/remotes/origin/"):
        if t.startswith(prefix):
            t = t[len(prefix):]
    return t


def _branch_from_refspec(token: str) -> str:
    """去掉强制前缀 +，再取 refspec 右侧（远端分支）。"""
    return _normalize_branch(token)


def _is_delete_push(args: list[str]) -> bool:
    if "--delete" in args or "-d" in args:
        return True
    return any(a.startswith(":") and len(a) > 1 and not a.startswith("--") for a in args)


@register
class BashGitPushForceProtected(Rule):
    id = "bash-git-push-force-protected"
    severity = "high"
    applies_to = ("Bash",)
    description = "拒绝 git push --force 推到 main/master/release/* 等保护分支"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        if ctx.ast is None:
            return None
        for cmd in ctx.ast.commands:
            if cmd.name != "git":
                continue
            args = [w.raw for w in cmd.args]
            if "push" not in args:
                continue
            push_idx = args.index("push")
            tail = [a for a in args[push_idx + 1 :] if not a.startswith("-")]
            deleting = _is_delete_push(args[push_idx + 1 :])
            forcing = _is_force(cmd.words)
            if not deleting and not forcing:
                continue
            if len(tail) < 1:
                if forcing:
                    return RuleMatch(
                        rule_id=self.id,
                        severity=self.severity,
                        reason=(
                            f"拒绝执行：`{ctx.raw_command}` force-push 未指定分支，"
                            f"可能将本地强推到默认上游（往往是 main/master）。请显式指定非保护分支后重试。"
                        ),
                    )
                continue
            target = tail[-1]
            branch = _branch_from_refspec(target)
            if not is_protected_branch(branch, ctx.config.protected_branches):
                continue
            if deleting:
                return RuleMatch(
                    rule_id=self.id,
                    severity=self.severity,
                    reason=(
                        f"拒绝执行：`{ctx.raw_command}` 将删除远端受保护分支 `{branch}`。"
                    ),
                    extra={"branch": branch, "mode": "delete"},
                )
            return RuleMatch(
                rule_id=self.id,
                severity=self.severity,
                reason=(
                    f"拒绝执行：`{ctx.raw_command}` 将 force-push 到受保护分支 `{branch}`。"
                    f"如需强推非保护分支，请显式指定分支名。"
                ),
                extra={"branch": branch},
            )
        return None
