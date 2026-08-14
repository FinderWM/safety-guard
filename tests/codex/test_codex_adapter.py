"""Codex Adapter 行为测试。"""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from safety_guard import runner
from safety_guard.adapters.codex import CodexAdapter, parse_apply_patch
from safety_guard.adapters.registry import get
from safety_guard.config import load as load_config
from safety_guard.contracts import Operation


def _patch(body: str) -> str:
    return f"*** Begin Patch\n{body}\n*** End Patch\n"


def _mcp_input(tool_name: str, tool_input: dict, cwd: Path) -> dict:
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input,
        "cwd": str(cwd),
    }


_NO_PATH_MCP_CASES: tuple[tuple[str, dict[str, Any]], ...] = (
    ("click", {"uid": "node-1"}),
    ("close_page", {"pageId": 1}),
    ("drag", {"from_uid": "node-1", "to_uid": "node-2"}),
    ("emulate", {"colorScheme": "dark"}),
    ("fill", {"uid": "node-1", "value": "synthetic"}),
    ("fill_form", {"elements": [{"uid": "node-1", "value": "synthetic"}]}),
    ("get_console_message", {"msgid": 1}),
    ("handle_dialog", {"action": "dismiss"}),
    ("hover", {"uid": "node-1"}),
    ("list_console_messages", {}),
    ("list_network_requests", {}),
    ("list_pages", {}),
    ("navigate_page", {"type": "reload"}),
    ("new_page", {"url": "https://example.invalid"}),
    ("performance_analyze_insight", {"insightName": "LCPBreakdown", "insightSetId": "synthetic"}),
    ("press_key", {"key": "Escape"}),
    ("resize_page", {"height": 600, "width": 800}),
    ("select_page", {"pageId": 1}),
    ("type_text", {"text": "synthetic"}),
    ("wait_for", {"text": ["synthetic"]}),
)


def test_pretool_high_is_denied(pretool, cwd: Path):
    out = pretool("Bash", {"command": "git push --force origin main"}, cwd)
    assert out["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "bash-git-push-force-protected" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_pretool_medium_is_denied(pretool, cwd: Path):
    out = pretool("Bash", {"command": "rm -rf ./tmp-dir"}, cwd)
    hs = out["hookSpecificOutput"]
    assert hs["hookEventName"] == "PreToolUse"
    assert hs["permissionDecision"] == "deny"
    assert "bash-rm-targeted" in hs["permissionDecisionReason"]


def test_permission_medium_is_denied(permission, cwd: Path):
    out = permission("Bash", {"command": "rm -rf ./tmp-dir"}, cwd)
    hs = out["hookSpecificOutput"]
    assert hs["hookEventName"] == "PermissionRequest"
    assert hs["decision"]["behavior"] == "deny"
    assert "bash-rm-targeted" in hs["decision"]["message"]


def test_permission_high_is_denied(permission, cwd: Path):
    out = permission("Bash", {"command": "rm -rf /"}, cwd)
    hs = out["hookSpecificOutput"]
    assert hs["hookEventName"] == "PermissionRequest"
    assert hs["decision"]["behavior"] == "deny"
    assert "bash-rm-root-or-home" in hs["decision"]["message"]


def test_permission_edit_inside_cwd_is_allowed(permission, cwd: Path):
    target = cwd / "existing.txt"
    target.write_text("old", encoding="utf-8")

    out = permission(
        "Edit",
        {"file_path": str(target), "old_string": "old", "new_string": "new"},
        cwd,
    )

    assert out == {}


def test_pretool_write_existing_file_is_denied(pretool, cwd: Path):
    target = cwd / "existing.txt"
    target.write_text("old", encoding="utf-8")

    out = pretool("Write", {"file_path": str(target), "content": "new"}, cwd)

    hs = out["hookSpecificOutput"]
    assert hs["hookEventName"] == "PreToolUse"
    assert hs["permissionDecision"] == "deny"
    assert "file-overwrite-existing" in hs["permissionDecisionReason"]


def test_apply_patch_critical_path_denied(permission, cwd: Path):
    cmd = _patch(
        """*** Update File: ~/.codex/config.toml
@@
-old
+new"""
    )
    out = permission("apply_patch", {"command": cmd}, cwd)
    hs = out["hookSpecificOutput"]
    assert hs["hookEventName"] == "PermissionRequest"
    assert hs["decision"]["behavior"] == "deny"
    assert "file-critical-path-write" in hs["decision"]["message"]


def test_apply_patch_delete_is_denied(permission, cwd: Path):
    victim = cwd / "old.txt"
    victim.write_text("x")
    cmd = _patch("*** Delete File: old.txt")
    out = permission("apply_patch", {"command": cmd}, cwd)
    hs = out["hookSpecificOutput"]
    assert hs["decision"]["behavior"] == "deny"
    assert "file-patch-delete" in hs["decision"]["message"]


def test_apply_patch_any_high_wins(permission, cwd: Path):
    safe = cwd / "safe.txt"
    safe.write_text("ok")
    cmd = _patch(
        """*** Update File: safe.txt
@@
-ok
+ok2
*** Update File: ~/.codex/config.toml
@@
-x
+y"""
    )
    out = permission("apply_patch", {"command": cmd}, cwd)
    hs = out["hookSpecificOutput"]
    assert hs["decision"]["behavior"] == "deny"
    assert "file-critical-path-write" in hs["decision"]["message"]


def test_apply_patch_parse_error_fails_closed(pretool, cwd: Path):
    out = pretool("apply_patch", {"command": "*** Update File: x.txt\n*** End Patch"}, cwd)
    hs = out["hookSpecificOutput"]
    assert hs["permissionDecision"] == "deny"
    assert "hook 输入解析失败" in hs["permissionDecisionReason"]


@pytest.mark.parametrize(
    ("tool_name", "tool_input", "operation"),
    [
        (
            "mcp__chrome_devtools__evaluate_script",
            {"function": "() => 1", "filePath": "output.json"},
            Operation("Write", {"file_path": "output.json"}),
        ),
        (
            "mcp__chrome_devtools__lighthouse_audit",
            {"outputDirPath": "report"},
            Operation("Edit", {"file_path": "report", "path_kind": "directory"}),
        ),
        (
            "mcp__chrome_devtools__performance_start_trace",
            {"filePath": "start-trace.json"},
            Operation("Write", {"file_path": "start-trace.json"}),
        ),
        (
            "mcp__chrome_devtools__performance_stop_trace",
            {"filePath": "stop-trace.json"},
            Operation("Write", {"file_path": "stop-trace.json"}),
        ),
        (
            "mcp__chrome_devtools__take_heapsnapshot",
            {"filePath": "heap.heapsnapshot"},
            Operation("Write", {"file_path": "heap.heapsnapshot"}),
        ),
        (
            "mcp__chrome_devtools__take_screenshot",
            {"filePath": "image.png"},
            Operation("Write", {"file_path": "image.png"}),
        ),
        (
            "mcp__chrome_devtools__take_snapshot",
            {"filePath": "snapshot.txt"},
            Operation("Write", {"file_path": "snapshot.txt"}),
        ),
    ],
)
def test_chrome_mcp_local_paths_are_normalized(
    cwd: Path,
    tool_name: str,
    tool_input: dict,
    operation: Operation,
):
    request = CodexAdapter(name="codex-pretool", event="PreToolUse").parse(
        _mcp_input(tool_name, tool_input, cwd)
    )

    assert request is not None
    assert request.tool == tool_name
    assert request.operations == (operation,)
    assert request.audit_input == operation.tool_input["file_path"]


@pytest.mark.parametrize(("short_name", "tool_input"), _NO_PATH_MCP_CASES)
def test_chrome_mcp_no_path_tools_are_supported(short_name: str, tool_input: dict, cwd: Path):
    tool_name = f"mcp__chrome_devtools__{short_name}"
    request = CodexAdapter(name="codex-pretool", event="PreToolUse").parse(
        _mcp_input(tool_name, tool_input, cwd)
    )

    assert request is not None
    assert request.tool == tool_name
    assert request.operations == ()
    assert request.audit_input == tool_name


@pytest.mark.parametrize(
    ("tool_input", "expected"),
    [
        (
            {"requestFilePath": "request.network-request"},
            (Operation("Write", {"file_path": "request.network-request"}),),
        ),
        (
            {"responseFilePath": "response.network-response"},
            (Operation("Write", {"file_path": "response.network-response"}),),
        ),
        (
            {
                "requestFilePath": "request.network-request",
                "responseFilePath": "response.network-response",
            },
            (
                Operation("Write", {"file_path": "request.network-request"}),
                Operation("Write", {"file_path": "response.network-response"}),
            ),
        ),
    ],
)
def test_get_network_request_normalizes_each_output_path(
    tool_input: dict,
    expected: tuple[Operation, ...],
    cwd: Path,
):
    tool_name = "mcp__chrome_devtools__get_network_request"
    request = CodexAdapter(name="codex-pretool", event="PreToolUse").parse(
        _mcp_input(tool_name, tool_input, cwd)
    )

    assert request is not None
    assert request.operations == expected


@pytest.mark.parametrize(
    ("tool_name", "tool_input"),
    [
        ("mcp__chrome_devtools__evaluate_script", {"function": "() => 1"}),
        ("mcp__chrome_devtools__get_network_request", {}),
        ("mcp__chrome_devtools__lighthouse_audit", {"mode": "snapshot"}),
        ("mcp__chrome_devtools__performance_start_trace", {"autoStop": True}),
        ("mcp__chrome_devtools__performance_stop_trace", {}),
        ("mcp__chrome_devtools__take_screenshot", {}),
        ("mcp__chrome_devtools__take_snapshot", {}),
    ],
)
def test_chrome_mcp_optional_output_path_does_not_block(
    tool_name: str,
    tool_input: dict,
    pretool,
    cwd: Path,
):
    assert pretool(tool_name, tool_input, cwd) == {}


@pytest.mark.parametrize(
    ("tool_name", "tool_input"),
    [
        ("mcp__chrome_devtools__take_heapsnapshot", {}),
        ("mcp__chrome_devtools__upload_file", {}),
        ("mcp__chrome_devtools__upload_file", {"filePaths": []}),
    ],
)
def test_chrome_mcp_required_path_fails_closed(
    tool_name: str,
    tool_input: dict,
    pretool,
    cwd: Path,
):
    out = pretool(tool_name, tool_input, cwd)
    hs = out["hookSpecificOutput"]
    assert hs["permissionDecision"] == "deny"
    assert "hook 输入解析失败" in hs["permissionDecisionReason"]


def test_chrome_mcp_output_overwrite_is_denied(pretool, cwd: Path):
    target = cwd / "image.png"
    target.write_text("synthetic", encoding="utf-8")

    out = pretool("mcp__chrome_devtools__take_screenshot", {"filePath": str(target)}, cwd)

    hs = out["hookSpecificOutput"]
    assert hs["permissionDecision"] == "deny"
    assert "file-overwrite-existing" in hs["permissionDecisionReason"]


def test_lighthouse_existing_output_directory_is_allowed(pretool, cwd: Path):
    target = cwd / "reports"
    target.mkdir()

    assert pretool(
        "mcp__chrome_devtools__lighthouse_audit",
        {"outputDirPath": str(target)},
        cwd,
    ) == {}


def test_lighthouse_output_directory_outside_cwd_is_denied(pretool, cwd: Path):
    out = pretool(
        "mcp__chrome_devtools__lighthouse_audit",
        {"outputDirPath": "/nonexistent-probe/reports"},
        cwd,
    )

    hs = out["hookSpecificOutput"]
    assert hs["permissionDecision"] == "deny"
    assert "file-outside-cwd" in hs["permissionDecisionReason"]


@pytest.mark.parametrize(
    ("tool_input", "expected_paths"),
    [
        ({"filePath": "one.txt"}, ("one.txt",)),
        ({"filePaths": ["one.txt", "two.txt"]}, ("one.txt", "two.txt")),
    ],
)
def test_chrome_mcp_upload_paths_have_external_upload_marker(
    tool_input: dict,
    expected_paths: tuple[str, ...],
    cwd: Path,
):
    tool_name = "mcp__chrome_devtools__upload_file"
    request = CodexAdapter(name="codex-pretool", event="PreToolUse").parse(
        _mcp_input(tool_name, tool_input, cwd)
    )

    assert request is not None
    assert request.operations == tuple(
        Operation(
            "Read",
            {
                "file_path": path,
                "external_upload": True,
                "source_tool": tool_name,
            },
        )
        for path in expected_paths
    )


@pytest.mark.parametrize(
    "tool_input",
    [
        {"filePath": "one.txt"},
        {"filePaths": ["one.txt", "two.txt"]},
    ],
)
def test_chrome_mcp_upload_inside_cwd_is_denied(tool_input: dict, pretool, cwd: Path):
    out = pretool("mcp__chrome_devtools__upload_file", tool_input, cwd)

    hs = out["hookSpecificOutput"]
    assert hs["permissionDecision"] == "deny"
    assert "file-external-upload" in hs["permissionDecisionReason"]


def test_chrome_mcp_upload_aliases_cannot_be_combined(pretool, cwd: Path):
    out = pretool(
        "mcp__chrome_devtools__upload_file",
        {"filePath": "one.txt", "filePaths": ["two.txt"]},
        cwd,
    )

    hs = out["hookSpecificOutput"]
    assert hs["permissionDecision"] == "deny"
    assert "accepts only one of" in hs["permissionDecisionReason"]


@pytest.mark.parametrize(
    "tool_name",
    [
        "mcp__chrome_devtools__future_tool",
        "mcp__unknown_server__write_file",
    ],
)
def test_codex_unknown_mcp_tool_uses_noop_detection_entry(tool_name: str, pretool, cwd: Path):
    out = pretool(tool_name, {}, cwd)
    request = CodexAdapter(name="codex-pretool", event="PreToolUse").parse(
        _mcp_input(tool_name, {}, cwd)
    )

    assert out == {}
    assert request is not None
    assert request.tool == tool_name
    assert request.operations == ()


def test_codex_unknown_tool_does_not_parse_unimplemented_input(cwd: Path):
    out = runner.run(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "mcp__future__tool",
            "tool_input": "schema-not-implemented",
            "cwd": str(cwd),
        },
        adapter=get("codex-pretool"),
        config=replace(load_config(), fail_open=False),
    )

    assert out == {}


def test_codex_malformed_tool_input_fails_closed(cwd: Path):
    out = runner.run(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "mcp__chrome_devtools__list_pages",
            "tool_input": "not-an-object",
            "cwd": str(cwd),
        },
        adapter=get("codex-pretool"),
        config=replace(load_config(), fail_open=False),
    )

    hs = out["hookSpecificOutput"]
    assert hs["permissionDecision"] == "deny"
    assert "tool_input must be an object" in hs["permissionDecisionReason"]


def test_apply_patch_unknown_directive_fails_closed(pretool, cwd: Path):
    out = pretool("apply_patch", {"command": _patch("*** Rename File: x.txt")}, cwd)

    hs = out["hookSpecificOutput"]
    assert hs["permissionDecision"] == "deny"
    assert "unsupported patch directive" in hs["permissionDecisionReason"]


def test_apply_patch_body_marker_is_not_treated_as_directive():
    patch = _patch(
        """*** Update File: x.txt
@@
-old
+*** Rename File: this-is-file-content"""
    )

    assert parse_apply_patch(patch) == [{"file_path": "x.txt", "action": "update"}]


def test_apply_patch_context_lines_are_not_treated_as_directives():
    patch = _patch(
        """*** Update File: x.txt
@@
 *** Delete File: this-is-file-content
 *** Move to: this-is-file-content
 *** End Patch"""
    )

    assert parse_apply_patch(patch) == [{"file_path": "x.txt", "action": "update"}]


def test_external_upload_rule_does_not_change_other_adapters(cwd: Path):
    cfg = replace(load_config(), fail_open=False)
    target = cwd / "synthetic.txt"
    claude_out = runner.run(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": str(target)},
            "cwd": str(cwd),
        },
        adapter=get("claude"),
        config=cfg,
    )
    grok_out = runner.run(
        {
            "hookEventName": "pre_tool_use",
            "toolName": "read_file",
            "toolInput": {"target_file": str(target)},
            "cwd": str(cwd),
        },
        adapter=get("grok"),
        config=cfg,
    )

    assert claude_out == {}
    assert grok_out == {"decision": "allow"}
