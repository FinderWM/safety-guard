"""file 工具规则。"""
from __future__ import annotations

from pathlib import Path


def test_write_inside_cwd_new_file_allow(file_tool, cwd: Path):
    target = cwd / "new.txt"
    d, _ = file_tool("Write", str(target), cwd)
    assert d == "allow"


def test_write_inside_cwd_existing_file_ask(file_tool, cwd: Path):
    target = cwd / "existing.txt"
    target.write_text("hi")
    d, reason = file_tool("Write", str(target), cwd)
    assert d == "ask" and "file-overwrite-existing" in (reason or "")


def test_write_outside_cwd_ask(file_tool, cwd: Path, tmp_path_factory):
    other = tmp_path_factory.mktemp("other")
    target = other / "x.txt"
    d, reason = file_tool("Write", str(target), cwd)
    assert d == "ask" and "file-outside-cwd" in (reason or "")


def test_write_instruction_zone_ask(file_tool, cwd: Path):
    # 用户主目录下 ~/.claude 是 instruction-zone
    d, reason = file_tool("Write", "~/.claude/some-file", cwd)
    assert d == "ask" and "file-instruction-zone-write" in (reason or "")


def test_edit_inside_cwd_existing_allow(file_tool, cwd: Path):
    target = cwd / "x.txt"
    target.write_text("hi")
    d, _ = file_tool("Edit", str(target), cwd)
    assert d == "allow"


def test_edit_outside_cwd_ask(file_tool, cwd: Path):
    d, reason = file_tool("Edit", "/etc/something", cwd)
    assert d == "ask" and "file-outside-cwd" in (reason or "")


def test_read_outside_cwd_ask(file_tool, cwd: Path):
    d, reason = file_tool("Read", "/nonexistent-probe/hosts", cwd)
    assert d == "ask" and "file-outside-cwd" in (reason or "")


def test_read_inside_cwd_allow(file_tool, cwd: Path):
    target = cwd / "x.txt"
    target.write_text("hi")
    d, _ = file_tool("Read", str(target), cwd)
    assert d == "allow"


def test_notebook_delete_ask(file_tool, cwd: Path):
    target = cwd / "x.ipynb"
    target.write_text("{}")
    d, reason = file_tool("NotebookEdit", str(target), cwd, edit_mode="delete")
    assert d == "ask" and "notebook-delete" in (reason or "")


def test_notebook_replace_allow(file_tool, cwd: Path):
    target = cwd / "x.ipynb"
    target.write_text("{}")
    d, _ = file_tool("NotebookEdit", str(target), cwd, edit_mode="replace")
    assert d == "allow"
