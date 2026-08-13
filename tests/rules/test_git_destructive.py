"""bash-git-destructive：子命令定位必须跳过全局选项。

    git clean -fd                         → ask
    git -C . clean -fd                    → 也曾必须 ask（修前 allow）
    git -C ../../sibling clean -fd        → ask
    git --git-dir=<path> reset --hard     → ask

安全：只调分析器；-C / --git-dir 目标一律用不存在的合成路径。
"""
from __future__ import annotations

from pathlib import Path

import pytest

RULE = "bash-git-destructive"
OUT = "../../sibling"
ABS = "/nonexistent-probe/other"


DESTRUCTIVE = [
    "git clean -fd",
    "git -C . clean -fd",
    f"git -C {OUT} clean -fd",
    f"git -C {ABS} clean -fd",
    f"git --git-dir={ABS}/.git clean -fd",
    f"git --work-tree={ABS} clean -fdx",
    f"git --git-dir={ABS}/.git --work-tree={ABS} reset --hard",
    f"git -C {OUT} reset --hard",
    f"git -C {OUT} branch -D topic",
    "git -c foo.bar=1 clean -fd",
    "git -C . stash drop",
    "git -C . worktree remove ../wt",
    "git -C . rebase origin/main",
    "git restore .",
    "git checkout -- existing.txt",
    f"rtk git -C {OUT} clean -fd",
    f"bash -c 'git -C {OUT} clean -fd'",
]


@pytest.mark.parametrize("cmd", DESTRUCTIVE)
def test_git_destructive_asks(bash, cwd: Path, cmd: str):
    decision, reason = bash(cmd, cwd)
    assert decision in ("ask", "deny"), f"{cmd!r} 应拦下，实际 {decision} ({reason})"
    assert RULE in (reason or ""), f"{cmd!r} 未命中 destructive：{reason}"


SAFE = [
    "git status",
    "git -C . status",
    f"git -C {OUT} log --oneline",
    f"git -C {ABS} log",
    f"git --git-dir={ABS}/.git log",
    "git -C . branch -a",
    "git -C . diff",
    "git -C . stash list",
    "git clean -n",          # dry-run，无 -f
    "git branch -d topic",   # 非强制删除
    "git restore --staged .",
    "git checkout main",
]


@pytest.mark.parametrize("cmd", SAFE)
def test_git_safe_not_destructive(bash, cwd: Path, cmd: str):
    decision, reason = bash(cmd, cwd)
    assert RULE not in (reason or ""), f"{cmd!r} 误报 destructive：{reason}"
