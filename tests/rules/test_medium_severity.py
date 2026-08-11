"""MEDIUM 规则：必须 ask。"""
from __future__ import annotations

from pathlib import Path

import pytest


@pytest.mark.parametrize("command,rule_id", [
    ("rm -rf /tmp/some-not-existing-dir",  "bash-rm-targeted"),
    ("rm ./foo",                            "bash-rm-targeted"),
    ("rm -rf ./build",                      "bash-rm-targeted"),
    ("git reset --hard",                    "bash-git-destructive"),
    ("git clean -fd",                       "bash-git-destructive"),
    ("git branch -D feature/x",             "bash-git-destructive"),
    ("git stash drop",                      "bash-git-destructive"),
    ("git worktree remove ./wt",            "bash-git-destructive"),
    ("ln -s /etc/hosts ./h",                "bash-symlink-create"),
    ("ln /etc/passwd ./p",                  "bash-symlink-create"),
    ("cp -s /etc/hosts ./h",                "bash-symlink-create"),
    ("cat /etc/hosts",                      "bash-outside-cwd-read"),
    ("grep foo /var/log/system.log",        "bash-outside-cwd-read"),
    ("sed -n '1p' /etc/hosts",           "bash-outside-cwd-read"),
    ("awk '{print}' /etc/hosts",         "bash-outside-cwd-read"),
    ("mv /etc/foo ./bar",                   "bash-outside-cwd-write"),
    ("gh pr close 123",                     "bash-gh-close"),
    ("gh issue close 99",                   "bash-gh-close"),
    ("psql -c \"DELETE FROM users\"",       "bash-sql-delete-truncate"),
    ("psql -c \"TRUNCATE TABLE log\"",      "bash-sql-delete-truncate"),
])
def test_medium_severity_asks(bash, cwd: Path, command: str, rule_id: str):
    decision, reason = bash(command, cwd)
    assert decision == "ask", f"{command!r} should ASK but got {decision} ({reason})"
    assert rule_id in (reason or ""), f"{command!r} expected {rule_id} in reason, got: {reason}"


def test_redirect_overwrite_existing(bash, cwd: Path):
    """文件存在 → ask；不存在 → allow；追加 → allow。"""
    existing = cwd / "a.txt"
    existing.write_text("hi")
    new = cwd / "new.txt"

    d, reason = bash(f"echo x > {existing}", cwd)
    assert d == "ask" and "bash-redirect-overwrite-existing" in (reason or "")

    d, _ = bash(f"echo x > {new}", cwd)
    assert d == "allow"

    d, _ = bash(f"echo x >> {existing}", cwd)
    assert d == "allow"

    d, _ = bash("ls missing 2>/dev/null || true", cwd)
    assert d == "allow"


def test_tee_overwrite_existing(bash, cwd: Path):
    existing = cwd / "a.txt"
    existing.write_text("hi")
    d, reason = bash(f"echo x | tee {existing}", cwd)
    assert d == "ask" and "bash-tee-overwrite-existing" in (reason or "")

    d, _ = bash(f"echo x | tee -a {existing}", cwd)
    assert d == "allow"


def test_cp_mv_overwrite_existing(bash, cwd: Path):
    src = cwd / "src.txt"
    src.write_text("s")
    dst = cwd / "dst.txt"
    dst.write_text("d")
    d, reason = bash(f"cp {src} {dst}", cwd)
    assert d == "ask" and "bash-cp-mv-overwrite-existing" in (reason or "")

    dst2 = cwd / "new.txt"
    d, _ = bash(f"cp {src} {dst2}", cwd)
    assert d == "allow"
