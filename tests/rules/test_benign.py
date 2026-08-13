"""良性命令样本：必须 allow。"""
from __future__ import annotations

from pathlib import Path

import pytest


BENIGN = [
    "git status",
    "ls",
    "ls -la",
    "rg foo .",
    "grep foo ./file.txt",
    "cat ./foo.txt",
    "echo hi > new.txt",
    "echo hi >> ./append.txt",
    "npm install",
    "pnpm i",
    "git commit -m 'wip'",
    "git diff",
    "git push origin feature/x",
    "git push -f origin feature/x",  # 非保护分支强推允许
    "mkdir -p ./build",
    "curl https://example.com > out.html",
    "find . -name '*.py'",
    "sed -n '1,90p' ~/.codex/config.toml",
    "awk 'NR>=1 {print}' ~/.codex/config.toml",
    "rg -n '/resource-library|Count from|Business routes' .",
    'rg -n "className=\\"[^\"]*(bg-white|bg-slate-50)[^\"]*\\"" web/src | rg -v "dark:"',
    "ls -la .env 2>/dev/null || true",
    "cat /dev/null",
    'PATH="$PATH" git status',
    "ps aux | grep python",
    "docker ps",
    "apply_patch <<'PATCH'\n*** Begin Patch\n*** End Patch\nPATCH",
    'apply_patch <<"PATCH"\n*** Begin Patch\n*** End Patch\nPATCH',
    "printf '%s\\n' '*** Begin Patch' | apply_patch",
    "echo 'DROP DATABASE' > sql.txt",  # 不是 SQL 客户端执行
    "git stash",                       # stash 不是 stash drop
    "git rebase --continue",           # 仍然命中 bash-git-destructive(rebase)? 实际上会命中
    # rg/grep 的「选项 + 独立取值」：值不能被当成 pattern，否则真正的 pattern
    # （Java 仓里常带 /api/xxx）会被顺位当成路径而误报 outside-cwd-read
    "rg -C 8 '/integral-user/search|/search/v2' merchant",
    "rg -A 2 '/api/foo' src",
    "rg -B 2 '/api/foo' src",
    "rg -m 5 '/api/foo' src",
    "rg --max-count 5 '/api/foo' src",
    "rg -M 200 '/api/foo' src",
    "rg --max-depth 3 '/api/foo' src",
    "rg -j 4 '/api/foo' src",
    "rg -r '/x' '/api/foo' src",
    "rg -E utf-8 '/api/foo' src",
    "grep -C 3 '/api/foo' src",
    "grep -A 3 '/api/foo' src",
    "grep -m 5 '/api/foo' src",
    "grep -d skip -rn '/api/foo' src",
    "grep --include '*.yml' -rn '/api/foo' src",
    "grep --exclude-dir target -rn '/api/foo' src",
    # -r/-E 在 grep 下不取值，不能被误当取值选项吞掉后面的 pattern
    "grep -r '/api/foo' src",
    "grep -E '/api/foo' src",
]


# pattern 由 -e/-f 显式给出时，后面的位置参数是真路径，必须仍然可见
PATTERN_FROM_OPTION_ASK = [
    "rg -e foo /etc/passwd",
    "grep -e foo /etc/passwd",
    "rg --regexp=foo /etc/passwd",
    "rg -f pat.txt /etc/passwd",
    "grep -f pat.txt /etc/hosts",
    "rg -e foo -C 3 /etc",
]


@pytest.mark.parametrize("command", PATTERN_FROM_OPTION_ASK)
def test_explicit_pattern_option_keeps_paths_visible(bash, cwd: Path, command: str):
    decision, reason = bash(command, cwd)
    assert decision == "ask", f"{command!r} 的外部路径被当成 pattern 吞掉了：{decision} {reason}"



@pytest.mark.parametrize("command", [
    c for c in BENIGN if c != "git rebase --continue"
])
def test_benign_allow(bash, cwd: Path, command: str):
    decision, reason = bash(command, cwd)
    assert decision == "allow", f"{command!r} unexpectedly {decision}: {reason}"


def test_git_rebase_is_destructive(bash, cwd: Path):
    """git rebase 任意子命令保守 ask（含 --continue）。"""
    decision, _ = bash("git rebase --continue", cwd)
    assert decision == "ask"
