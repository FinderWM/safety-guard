"""Deterministic secondary command slots must re-enter Bash analysis.

The fixtures are parsed only. They use synthetic hosts and paths and never execute
the embedded commands.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from safety_guard import bash_ast


@pytest.mark.parametrize(
    "command",
    [
        "find . -exec sh -c 'git push --force origin main' {} +",
        "git -c alias.deploy='!git push --force origin main' deploy",
        "git -c alias.deploy='push --force origin main' deploy",
        "ssh -o 'ProxyCommand=git push --force origin main' example.invalid",
        (
            "tar --checkpoint=1 "
            "--checkpoint-action='exec=git push --force origin main' "
            "-cf ./synthetic-archive.tar ."
        ),
        "sed -e 'e git push --force origin main' ./synthetic-input.txt",
    ],
)
def test_deterministic_command_slots_reuse_high_rules(bash, cwd: Path, command: str):
    decision, reason = bash(command, cwd)

    assert decision == "deny", f"{command!r} -> {decision} ({reason})"
    assert "bash-git-push-force-protected" in (reason or "")


@pytest.mark.parametrize(
    "command",
    [
        "git -c alias.summary='status --short' summary",
        "ssh -o ProxyCommand=none example.invalid",
        "tar --checkpoint-action=echo=checkpoint -cf ./synthetic-archive.tar .",
        "sed -e 's/foo/bar/' ./synthetic-input.txt",
    ],
)
def test_benign_command_slot_forms_remain_allowed(bash, cwd: Path, command: str):
    decision, reason = bash(command, cwd)

    assert decision == "allow", f"{command!r} -> {decision} ({reason})"


@pytest.mark.parametrize(
    "command",
    [
        "ssh -o 'ProxyCommand=$SYNTHETIC_PROXY' example.invalid",
        "sed -e 's/foo/bar/e' ./synthetic-input.txt",
    ],
)
def test_dynamic_command_slots_request_review(bash, cwd: Path, command: str):
    decision, reason = bash(command, cwd)

    assert decision == "ask", f"{command!r} -> {decision} ({reason})"
    assert "bash-opaque-inline-script" in (reason or "")


def test_deep_inline_expansion_is_bounded_and_becomes_opaque():
    # Constructing twelve shell-quoted layers grows exponentially and makes
    # bashlex spend its time on quoting noise instead of exercising the guard.
    # Start at the expansion boundary with a small, valid AST instead.
    ast = bash_ast.parse("bash -c 'printf synthetic'")
    expanded = bash_ast.expand(
        ast,
        frozenset(bash_ast.DEFAULT_WRAPPERS),
        _depth=bash_ast._MAX_EXPANSION_DEPTH,
    )

    assert expanded.commands == ast.commands
    assert [payload.kind for payload in expanded.opaque_payloads] == ["inline-script"]
    assert expanded.opaque_payloads[0].shell == "bash"
    assert expanded.opaque_payloads[0].raw == "printf synthetic"


def test_unparseable_inline_payload_becomes_opaque(monkeypatch):
    ast = bash_ast.parse("bash -c 'printf synthetic'")
    real_parse = bash_ast.parse

    def reject_inner(command: str):
        if command == "printf synthetic":
            raise bash_ast.BashParseError("synthetic inner parse failure")
        return real_parse(command)

    monkeypatch.setattr(bash_ast, "parse", reject_inner)
    expanded = bash_ast.expand(ast, frozenset(bash_ast.DEFAULT_WRAPPERS))

    assert [payload.kind for payload in expanded.opaque_payloads] == ["inline-script"]
    assert expanded.opaque_payloads[0].raw == "printf synthetic"
