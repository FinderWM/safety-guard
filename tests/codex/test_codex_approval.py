"""Codex PreToolUse 同步审批桥的隔离边界。"""
from __future__ import annotations

import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from safety_guard import runner
from safety_guard.adapters.codex_approval import (
    ApprovalStatus,
    ApprovalOutcome,
    MacOSDialogApprovalResolver,
    _prompt_text,
)
from safety_guard.adapters.registry import get
from safety_guard.config import load as load_config
from safety_guard.contracts import DecisionResult, NormalizedRequest


class StubApprovalResolver:
    def __init__(self, status: ApprovalStatus = "approved"):
        self.status = status
        self.calls: list[tuple[NormalizedRequest, DecisionResult, int]] = []

    def resolve(self, request, result, *, timeout_seconds):
        self.calls.append((request, result, timeout_seconds))
        return ApprovalOutcome(self.status, provider="synthetic-dialog")


class RaisingApprovalResolver:
    def resolve(self, request, result, *, timeout_seconds):
        raise RuntimeError("synthetic resolver failure")


def _config(mode: str):
    return replace(
        load_config(),
        fail_open=False,
        dry_run=False,
        codex_approval_mode=mode,
        codex_approval_timeout_seconds=7,
    )


def _input(cwd: Path, *, event: str = "PreToolUse", permission_mode: str | None = None) -> dict:
    payload = {
        "hook_event_name": event,
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf ./synthetic-dir"},
        "cwd": str(cwd),
    }
    if permission_mode is not None:
        payload["permission_mode"] = permission_mode
    return payload


@pytest.mark.parametrize("permission_mode", ["dontAsk", "bypassPermissions"])
def test_native_gap_approved_allows_codex_pretool(cwd: Path, permission_mode: str):
    resolver = StubApprovalResolver("approved")
    output = runner.run(
        _input(cwd, permission_mode=permission_mode),
        adapter=get("codex-pretool"),
        config=_config("native-gap"),
        approval_resolver=resolver,
    )

    assert output == {}
    assert len(resolver.calls) == 1
    assert resolver.calls[0][2] == 7


def test_approval_timeout_is_bounded_for_hook_budget(cwd: Path):
    resolver = StubApprovalResolver()
    output = runner.run(
        _input(cwd, permission_mode="bypassPermissions"),
        adapter=get("codex-pretool"),
        config=replace(_config("native-gap"), codex_approval_timeout_seconds=99),
        approval_resolver=resolver,
    )

    assert output == {}
    assert resolver.calls[0][2] == 25


@pytest.mark.parametrize("status", ["denied", "cancelled", "timed_out", "unavailable", "error"])
def test_non_approval_fails_closed(cwd: Path, status: str):
    output = runner.run(
        _input(cwd, permission_mode="bypassPermissions"),
        adapter=get("codex-pretool"),
        config=_config("native-gap"),
        approval_resolver=StubApprovalResolver(status),
    )

    hook_output = output["hookSpecificOutput"]
    assert hook_output["permissionDecision"] == "deny"
    assert "人工审批未通过" in hook_output["permissionDecisionReason"]


def test_resolver_exception_fails_closed(cwd: Path):
    output = runner.run(
        _input(cwd, permission_mode="bypassPermissions"),
        adapter=get("codex-pretool"),
        config=_config("native-gap"),
        approval_resolver=RaisingApprovalResolver(),
    )

    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize("permission_mode", [None, "default", "acceptEdits", "plan"])
def test_native_gap_preserves_original_warning_when_native_approval_is_available(
    cwd: Path,
    permission_mode: str | None,
):
    resolver = StubApprovalResolver()
    output = runner.run(
        _input(cwd, permission_mode=permission_mode),
        adapter=get("codex-pretool"),
        config=_config("native-gap"),
        approval_resolver=resolver,
    )

    assert "systemMessage" in output
    assert "permissionDecision" not in output["hookSpecificOutput"]
    assert resolver.calls == []


def test_always_mode_resolves_without_permission_mode(cwd: Path):
    resolver = StubApprovalResolver()
    output = runner.run(
        _input(cwd),
        adapter=get("codex-pretool"),
        config=_config("always"),
        approval_resolver=resolver,
    )

    assert output == {}
    assert len(resolver.calls) == 1


def test_off_mode_never_resolves(cwd: Path):
    resolver = StubApprovalResolver()
    output = runner.run(
        _input(cwd, permission_mode="bypassPermissions"),
        adapter=get("codex-pretool"),
        config=_config("off"),
        approval_resolver=resolver,
    )

    assert "systemMessage" in output
    assert resolver.calls == []


def test_codex_permission_keeps_native_approval(cwd: Path):
    resolver = StubApprovalResolver()
    output = runner.run(
        _input(cwd, event="PermissionRequest", permission_mode="bypassPermissions"),
        adapter=get("codex-permission"),
        config=_config("always"),
        approval_resolver=resolver,
    )

    assert output == {}
    assert resolver.calls == []


@pytest.mark.parametrize("adapter_name", ["claude", "grok"])
def test_other_cli_adapters_never_resolve(cwd: Path, adapter_name: str):
    resolver = StubApprovalResolver()
    payload = _input(cwd, permission_mode="bypassPermissions")
    if adapter_name == "grok":
        payload["tool_name"] = "run_terminal_command"
    output = runner.run(
        payload,
        adapter=get(adapter_name),
        config=_config("always"),
        approval_resolver=resolver,
    )

    assert output is not None
    assert resolver.calls == []


def test_high_and_allow_results_never_resolve(cwd: Path):
    resolver = StubApprovalResolver()
    high = _input(cwd, permission_mode="bypassPermissions")
    high["tool_input"] = {"command": "rm -rf /"}
    allowed = _input(cwd, permission_mode="bypassPermissions")
    allowed["tool_input"] = {"command": "git status"}

    denied_output = runner.run(
        high,
        adapter=get("codex-pretool"),
        config=_config("always"),
        approval_resolver=resolver,
    )
    allowed_output = runner.run(
        allowed,
        adapter=get("codex-pretool"),
        config=_config("always"),
        approval_resolver=resolver,
    )

    assert denied_output["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert allowed_output == {}
    assert resolver.calls == []


def test_dry_run_never_resolves(cwd: Path):
    resolver = StubApprovalResolver()
    output = runner.run(
        _input(cwd, permission_mode="bypassPermissions"),
        adapter=get("codex-pretool"),
        config=replace(_config("always"), dry_run=True),
        approval_resolver=resolver,
    )

    assert output == {}
    assert resolver.calls == []


def test_macos_dialog_maps_timeout_and_unexpected_output(
    monkeypatch: pytest.MonkeyPatch,
    cwd: Path,
):
    request = NormalizedRequest(
        adapter="codex-pretool",
        event="PreToolUse",
        tool="Bash",
        operations=(),
        cwd=str(cwd),
        audit_input="rm synthetic",
    )
    result = DecisionResult("ask", "synthetic reason")
    resolver = MacOSDialogApprovalResolver()
    monkeypatch.setattr("safety_guard.adapters.codex_approval.sys.platform", "darwin")

    def time_out(*args, **kwargs):
        raise subprocess.TimeoutExpired("osascript", 1)

    monkeypatch.setattr("safety_guard.adapters.codex_approval.subprocess.run", time_out)
    assert resolver.resolve(request, result, timeout_seconds=1).status == "timed_out"

    monkeypatch.setattr(
        "safety_guard.adapters.codex_approval.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, "unexpected\n", ""),
    )
    assert resolver.resolve(request, result, timeout_seconds=1).status == "error"


def test_prompt_is_bounded_and_redacts_home(cwd: Path):
    request = NormalizedRequest(
        adapter="codex-pretool",
        event="PreToolUse",
        tool="Bash",
        operations=(),
        cwd=str(Path.home() / "synthetic-project"),
        audit_input="x" * 3000,
    )

    prompt = _prompt_text(request, DecisionResult("ask", "synthetic reason"))

    assert str(Path.home()) not in prompt
    assert "$HOME/synthetic-project" in prompt
    assert "x" * 1600 + "…" in prompt
    assert "x" * 1601 not in prompt
