"""bash-git-push-force-protected：git push --force 到 main/master/release/*。"""
from __future__ import annotations

from ..context import BashContext
from ..helpers import (
    GIT_PUSH_VALUE_OPTIONS,
    git_push_is_non_mutating,
    git_subcommand_args,
    is_protected_branch,
)
from .base import Rule, RuleMatch
from .registry import register


def _is_force(args: list[str]) -> bool:
    """识别 force 开关/refspec，同时跳过 push 取值选项。"""
    for raw in _push_control_tokens(args):
        if (
            raw in {"--force", "--force-with-lease"}
            or raw.startswith("--force-with-lease=")
        ):
            return True
        if raw.startswith("-") and not raw.startswith("--") and "f" in raw[1:]:
            return True
    return any(raw.startswith("+") and len(raw) > 1 for raw in _push_refspecs(args))


def _push_control_tokens(args: list[str]) -> list[str]:
    """返回未被 push 取值选项消费的 token，避免把其值当控制开关。"""
    tokens: list[str] = []
    index = 0
    while index < len(args):
        raw = args[index]
        if raw == "--":
            break
        if raw in GIT_PUSH_VALUE_OPTIONS:
            index += 2
            continue
        if any(raw.startswith(option + "=") for option in GIT_PUSH_VALUE_OPTIONS if option.startswith("--")):
            index += 1
            continue
        if raw.startswith("-o") and raw != "-o" and not raw.startswith("--"):
            index += 1
            continue
        tokens.append(raw)
        index += 1
    return tokens


def _push_refspecs(args: list[str]) -> list[str]:
    """返回真实 refspec，跳过 push 自身选项及其值。"""
    positionals: list[str] = []
    repository_from_option = False
    after_options = False
    index = 0
    while index < len(args):
        raw = args[index]
        if after_options:
            positionals.append(raw)
            index += 1
            continue
        if raw == "--":
            after_options = True
            index += 1
            continue
        if raw in GIT_PUSH_VALUE_OPTIONS:
            if raw == "--repo":
                repository_from_option = True
            index += 2
            continue
        if raw.startswith("--repo="):
            repository_from_option = True
            index += 1
            continue
        if raw.startswith("--") or (raw.startswith("-") and raw != "-"):
            index += 1
            continue
        positionals.append(raw)
        index += 1
    return positionals if repository_from_option else positionals[1:]


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
    control_tokens = _push_control_tokens(args)
    if "--delete" in control_tokens or "-d" in control_tokens:
        return True
    return any(a.startswith(":") and len(a) > 1 and not a.startswith("--") for a in _push_refspecs(args))


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
            subcommand, push_args = git_subcommand_args(args)
            if subcommand != "push":
                continue
            if git_push_is_non_mutating(push_args):
                continue
            refspecs = _push_refspecs(push_args)
            deleting = _is_delete_push(push_args)
            forcing = _is_force(push_args) or "--mirror" in _push_control_tokens(push_args)
            if not deleting and not forcing:
                continue
            if not refspecs:
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
            protected = [
                _branch_from_refspec(target)
                for target in refspecs
                if is_protected_branch(
                    _branch_from_refspec(target),
                    ctx.config.protected_branches,
                )
                or _branch_from_refspec(target) == "*"
            ]
            if not protected:
                continue
            branch = protected[0]
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
