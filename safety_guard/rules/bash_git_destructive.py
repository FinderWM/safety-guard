"""bash-git-destructive：reset --hard / clean -fd / branch -D / stash drop / worktree remove / rebase 等。

git 的全局选项可以出现在子命令之前：

    git -C <dir> clean -fd
    git --git-dir=<path> reset --hard
    git -c key=val branch -D topic

如果直接拿 args[0] 当子命令，`-C` / `--git-dir` 会被误认为 sub，整条破坏性操作
静默放行——连 `git -C . clean -fd`（目录就在 CWD）都漏。定位子命令必须先跳过
git 自己的全局选项。
"""
from __future__ import annotations

from ..context import BashContext
from ..helpers import git_subcommand_args
from .base import Rule, RuleMatch
from .registry import register


# 吃一个独立值的全局选项（`git -C <dir>` / `git -c key=val`）
def _subcommand_args(args: list[str]) -> list[str]:
    """跳过 git 全局选项，返回「子命令 + 其子参数」切片。

    支持：
      -C DIR / -c key=val          分离写法
      --git-dir=PATH               等号写法
      --git-dir PATH               长选项分离写法
    """
    subcommand, sub_args = git_subcommand_args(args)
    return [subcommand, *sub_args] if subcommand is not None else []


def _detect(args: list[str]) -> str | None:
    """返回检测到的 destructive 操作描述，没有则 None。"""
    sub_args = _subcommand_args(args)
    if not sub_args:
        return None
    sub = sub_args[0]
    rest = sub_args[1:]
    if sub == "reset" and ("--hard" in rest or "-H" in rest):
        return "reset --hard 将丢弃工作区和暂存区改动"
    if sub == "clean":
        for option in rest:
            if option == "--":
                break
            if option == "--dry-run" or (
                option.startswith("-")
                and not option.startswith("--")
                and "n" in option[1:]
            ):
                return None
        for a in rest:
            if a.startswith("-") and "f" in a:
                return "clean 将删除未跟踪文件（含 .gitignore 内文件，若带 -x）"
    if sub == "branch":
        if "-D" in rest or "--delete=force" in rest or (
            "--delete" in rest and ("--force" in rest or "-f" in rest)
        ):
            return "branch -D 将强制删除分支（含未合并提交）"
    if sub == "stash" and "drop" in rest:
        return "stash drop 将丢弃 stash 条目"
    if sub == "worktree" and "remove" in rest:
        return "worktree remove 将删除 worktree 目录与对应分支元数据"
    if sub == "rebase":
        return "rebase 操作可能丢弃或重写提交历史"
    if sub == "restore":
        # --staged 只取消暂存，工作区还在；带 --worktree 或默认工作区则丢改动
        if "--staged" in rest and "--worktree" not in rest:
            return None
        return "restore 将丢弃工作区改动"
    if sub == "checkout" and "--" in rest:
        return "checkout -- 将丢弃指定路径的工作区改动"
    return None


@register
class BashGitDestructive(Rule):
    id = "bash-git-destructive"
    severity = "medium"
    applies_to = ("Bash",)
    description = (
        "git 的破坏性子命令（reset --hard / clean -f / branch -D / stash drop / "
        "worktree remove / rebase / restore / checkout --）"
    )

    def match(self, ctx: BashContext) -> RuleMatch | None:
        if ctx.ast is None:
            return None
        for cmd in ctx.ast.commands:
            if cmd.name != "git":
                continue
            args = [w.raw for w in cmd.args]
            desc = _detect(args)
            if desc:
                sub_args = _subcommand_args(args)
                return RuleMatch(
                    rule_id=self.id,
                    severity=self.severity,
                    reason=f"`{ctx.raw_command}` — {desc}",
                    extra={"subcommand": sub_args[0] if sub_args else ""},
                )
        return None
