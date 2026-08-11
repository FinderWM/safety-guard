"""路径分类核心语义。"""
from __future__ import annotations

import os
from pathlib import Path

from safety_guard.paths import PathPolicy, classify


def policy_for(cwd: Path) -> PathPolicy:
    return PathPolicy(
        cwd=Path(os.path.abspath(cwd)),
        home=Path.home(),
        zones=(Path.home() / ".claude", Path.home() / ".agents"),
    )


def test_in_cwd_absolute(cwd: Path):
    p = policy_for(cwd)
    assert classify(str(cwd / "foo"), p) == "in-cwd"


def test_in_cwd_relative(cwd: Path):
    p = policy_for(cwd)
    assert classify("./foo", p) == "in-cwd"
    assert classify("foo/bar", p) == "in-cwd"


def test_outside_absolute(cwd: Path):
    p = policy_for(cwd)
    assert classify("/etc/hosts", p) == "outside"


def test_instruction_zone(cwd: Path):
    p = policy_for(cwd)
    assert classify("~/.claude/CLAUDE.md", p) == "instruction-zone"
    assert classify("~/.agents/foo", p) == "instruction-zone"


def test_dotdot_escape(cwd: Path):
    """../../../etc/passwd 应被识别为 outside。"""
    p = policy_for(cwd)
    assert classify("../../../etc/passwd", p) == "outside"


def test_symlink_inside_cwd_keeps_in_cwd(cwd: Path, tmp_path_factory):
    """CWD 内的 symlink 即使指向外部，按路径位置仍是 in-cwd（CLAUDE.md 语义）。"""
    outside = tmp_path_factory.mktemp("outside") / "real.txt"
    outside.write_text("x")
    link = cwd / "link.txt"
    link.symlink_to(outside)
    p = policy_for(cwd)
    assert classify(str(link), p) == "in-cwd"
