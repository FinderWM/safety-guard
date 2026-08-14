"""未知工具 reviewer 的隔离、脱敏与失效回退。"""
from __future__ import annotations

import json
import threading
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from safety_guard import engine, runner
from safety_guard import reviewer as reviewer_module
from safety_guard.adapters.registry import get
from safety_guard.config import load as load_config
from safety_guard.contracts import NormalizedRequest
from safety_guard.reviewer import ReviewRequest, ReviewResult, review_unknown


def _input(cwd: Path, tool_input: Any | None = None) -> dict[str, Any]:
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": "FutureTool",
        "tool_input": {} if tool_input is None else tool_input,
        "cwd": str(cwd),
    }


def _request(cwd: Path, tool_input: dict[str, Any] | None = None) -> NormalizedRequest:
    request = get("claude").parse(_input(cwd, tool_input))
    assert request is not None
    return request


class StaticReviewer:
    name = "static-reviewer"

    def __init__(self, result: object):
        self.result = result
        self.calls = 0
        self.request: ReviewRequest | None = None

    def review(self, request: ReviewRequest):
        self.calls += 1
        self.request = request
        return self.result


def test_noop_reviewer_abstains_and_platform_allows(cwd: Path):
    cfg = replace(load_config(), fail_open=False)
    request = _request(cwd)

    result = engine.evaluate(request, cfg)

    assert result.decision == "abstain"
    assert result.review == {"reviewer": "noop", "status": "abstain"}
    assert runner.run(_input(cwd), adapter=get("claude"), config=cfg) == {}


def test_reviewer_can_deny_with_redacted_reason(cwd: Path):
    cfg = replace(load_config(), fail_open=False)
    reviewer = StaticReviewer(
        ReviewResult(
            decision="deny",
            reason=(
                "token=synthetic-review-secret "
                "https://example.invalid/check?trace=synthetic-query-value"
            ),
        )
    )

    output = runner.run(
        _input(cwd),
        adapter=get("claude"),
        config=cfg,
        reviewer=reviewer,
    )

    blob = json.dumps(output, ensure_ascii=False)
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "synthetic-review-secret" not in blob
    assert "synthetic-query-value" not in blob
    assert "<redacted>" in blob


def test_reviewer_timeout_abstains(cwd: Path):
    cfg = replace(load_config(), fail_open=False, reviewer_timeout_ms=1)

    class SlowReviewer:
        name = "slow"

        def review(self, request: ReviewRequest):
            threading.Event().wait(0.05)
            return "deny"

    result = engine.evaluate(_request(cwd), cfg, reviewer=SlowReviewer())

    assert result.decision == "abstain"
    assert result.review["error_type"] == "timeout"


def test_reviewer_timeout_releases_original_capacity(
    cwd: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    slots = threading.BoundedSemaphore(value=1)
    replacement = threading.BoundedSemaphore(value=0)
    started = threading.Event()
    finished = threading.Event()

    class SlowReviewer:
        name = "slow-capacity"

        def review(self, request: ReviewRequest):
            started.set()
            finished.wait(1)
            return "abstain"

    monkeypatch.setattr(reviewer_module, "_REVIEW_SLOTS", slots)
    result = engine.evaluate(
        _request(cwd),
        replace(load_config(), fail_open=False, reviewer_timeout_ms=1),
        reviewer=SlowReviewer(),
    )

    assert result.review["error_type"] == "timeout"
    assert started.wait(1)
    monkeypatch.setattr(reviewer_module, "_REVIEW_SLOTS", replacement)
    finished.set()
    assert slots.acquire(timeout=1)
    assert not replacement.acquire(blocking=False)


def test_reviewer_capacity_abstains(cwd: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(reviewer_module, "_REVIEW_SLOTS", threading.BoundedSemaphore(value=0))

    result = engine.evaluate(
        _request(cwd),
        replace(load_config(), fail_open=False),
        reviewer=StaticReviewer("deny"),
    )

    assert result.decision == "abstain"
    assert result.review["error_type"] == "capacity"


def test_reviewer_exception_abstains_without_error_detail(cwd: Path):
    cfg = replace(load_config(), fail_open=False)

    class BrokenReviewer:
        name = "broken"

        def review(self, request: ReviewRequest):
            raise RuntimeError("synthetic-exception-secret")

    result = engine.evaluate(_request(cwd), cfg, reviewer=BrokenReviewer())

    assert result.decision == "abstain"
    assert result.review == {
        "reviewer": "broken",
        "status": "abstain",
        "error_type": "error",
    }
    assert "synthetic-exception-secret" not in json.dumps(result.review)


def test_invalid_reviewer_result_abstains(cwd: Path):
    cfg = replace(load_config(), fail_open=False)
    reviewer = StaticReviewer(object())

    result = engine.evaluate(_request(cwd), cfg, reviewer=reviewer)

    assert result.decision == "abstain"
    assert result.review["error_type"] == "invalid_result"


def test_unavailable_configured_reviewer_abstains_with_visible_error(cwd: Path):
    cfg = replace(load_config(), fail_open=False, unknown_reviewer="synthetic-missing-reviewer")

    result = engine.evaluate(_request(cwd), cfg)

    assert result.decision == "abstain"
    assert result.review == {
        "reviewer": "synthetic-missing-reviewer",
        "status": "abstain",
        "error_type": "unavailable_reviewer",
    }


def test_reviewer_recursion_is_stopped(cwd: Path):
    cfg = replace(load_config(), fail_open=False)
    request = _request(cwd)

    class RecursiveReviewer:
        name = "recursive"

        def review(self, review_request: ReviewRequest):
            return review_unknown(request, cfg, self)

    result = engine.evaluate(request, cfg, reviewer=RecursiveReviewer())

    assert result.decision == "abstain"
    assert result.review["error_type"] == "recursion"


def test_reviewer_payload_never_contains_content_or_credentials(cwd: Path):
    cfg = replace(load_config(), fail_open=False)
    reviewer = StaticReviewer("abstain")
    secrets = {
        "command": "synthetic-command-secret",
        "patch": "synthetic-patch-secret",
        "api_key": "synthetic-api-secret",
        "url": "https://example.invalid/path?token=synthetic-url-secret",
        "synthetic-key-secret": "synthetic-value-secret",
        "opaque_numeric_value": 987654321012345678,
        "nested": {"body": "synthetic-body-secret"},
    }

    engine.evaluate(_request(cwd, secrets), cfg, reviewer=reviewer)

    assert reviewer.request is not None
    blob = json.dumps(reviewer.request, default=lambda value: value.__dict__, ensure_ascii=False)
    for secret in (
        "synthetic-command-secret",
        "synthetic-patch-secret",
        "synthetic-api-secret",
        "synthetic-url-secret",
        "synthetic-key-secret",
        "synthetic-value-secret",
        "synthetic-body-secret",
    ):
        assert secret not in blob
    assert "987654321012345678" not in blob
    assert any(
        isinstance(value, dict) and value.get("type") == "number"
        for value in reviewer.request.payload["input"].values()
    )


def test_reviewer_preserves_safe_underscore_tool_name(cwd: Path):
    tool_name = "mcp__future_server__future_tool"
    payload = _input(cwd)
    payload["tool_name"] = tool_name
    request = get("claude").parse(payload)
    reviewer = StaticReviewer("abstain")

    assert request is not None
    engine.evaluate(
        request,
        replace(load_config(), fail_open=False),
        reviewer=reviewer,
    )

    assert reviewer.request is not None
    assert reviewer.request.tool == tool_name
    assert reviewer.request.payload["tool"] == tool_name


def test_reviewer_payload_keeps_safe_behavior_metadata_without_values(cwd: Path):
    reviewer = StaticReviewer("abstain")
    engine.evaluate(
        _request(
            cwd,
            {
                "action": "delete",
                "mode": "recursive",
                "type": "file",
                "name": "synthetic-private-name",
                "id": "synthetic-private-id",
                "url": "https://example.invalid/check?token=synthetic-token",
            },
        ),
        replace(load_config(), fail_open=False),
        reviewer=reviewer,
    )

    assert reviewer.request is not None
    payload = reviewer.request.payload
    assert payload["input"]["action"]["value"] == "delete"
    assert payload["input"]["mode"]["value"] == "recursive"
    assert payload["input"]["type"]["value"] == "file"
    assert payload["input"]["url"]["host_scope"] == "domain-name"
    blob = json.dumps(payload, ensure_ascii=False)
    assert "example.invalid" not in blob
    assert "synthetic-token" not in blob
    assert "synthetic-private-name" not in blob
    assert "synthetic-private-id" not in blob


def test_reviewer_path_and_cwd_values_are_replaced_by_structure(cwd: Path):
    reviewer = StaticReviewer("abstain")
    secret_segment = "synthetic-private-project-name"
    path = f"{cwd}/{secret_segment}/../output.txt"

    engine.evaluate(
        _request(cwd, {"file_path": path, "target_directory": f"../{secret_segment}"}),
        replace(load_config(), fail_open=False),
        reviewer=reviewer,
    )

    assert reviewer.request is not None
    assert reviewer.request.cwd["type"] == "path-string"
    assert reviewer.request.payload["input"]["path-field"]["scope"] == "cwd"
    assert reviewer.request.payload["input"]["path-field"]["traversal"] is True
    blob = json.dumps(reviewer.request, default=lambda value: value.__dict__, ensure_ascii=False)
    assert str(cwd) not in blob
    assert secret_segment not in blob


def test_codex_permission_reviewer_allow_is_explicit():
    adapter = get("codex-permission")
    payload = _input(Path("/synthetic-review-cwd"), {"action": "safe"})
    payload["hook_event_name"] = "PermissionRequest"
    output = runner.run(
        payload,
        adapter=adapter,
        config=replace(load_config(), fail_open=False),
        reviewer=StaticReviewer("allow"),
    )
    assert output["hookSpecificOutput"]["decision"] == {"behavior": "allow"}


@pytest.mark.parametrize("review_decision", ["allow", "deny", "ask", "abstain"])
def test_codex_permission_dry_run_never_grants_unknown_tool(review_decision: str):
    adapter = get("codex-permission")
    payload = _input(Path("/synthetic-review-cwd"), {"action": "safe"})
    payload["hook_event_name"] = "PermissionRequest"

    output = runner.run(
        payload,
        adapter=adapter,
        config=replace(load_config(), fail_open=False, dry_run=True),
        reviewer=StaticReviewer(review_decision),
    )

    assert output == {}


def test_deterministic_high_rule_never_calls_reviewer(cwd: Path):
    cfg = replace(load_config(), fail_open=False)
    reviewer = StaticReviewer("allow")
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /"},
        "cwd": str(cwd),
    }

    output = runner.run(payload, adapter=get("claude"), config=cfg, reviewer=reviewer)

    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert reviewer.calls == 0


def test_known_noop_never_calls_reviewer(cwd: Path):
    cfg = replace(load_config(), fail_open=False)
    reviewer = StaticReviewer("deny")
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "mcp__chrome_devtools__list_pages",
        "tool_input": {},
        "cwd": str(cwd),
    }

    output = runner.run(payload, adapter=get("codex-pretool"), config=cfg, reviewer=reviewer)

    assert output == {}
    assert reviewer.calls == 0
