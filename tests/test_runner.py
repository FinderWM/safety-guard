"""统一 Adapter/Runner 入口测试。"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from safety_guard import runner
from safety_guard import config as config_module
from safety_guard.adapters.registry import available, get, select
from safety_guard.config import Config, load as load_config


def _fail_closed_config() -> Config:
    return replace(load_config(), fail_open=False)


def _claude_input(tool: str, tool_input: Any, cwd: Path) -> dict[str, Any]:
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": tool_input,
        "cwd": str(cwd),
    }


def test_registry_contains_builtin_adapters():
    assert available() == ["claude", "codex-permission", "codex-pretool", "grok"]


def test_registry_selects_canonical_environment(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SAFETY_GUARD_ADAPTER", "codex-pretool")
    assert select().name == "codex-pretool"


def test_canonical_runtime_environment_overrides_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    config_path = tmp_path / "safety_guard.toml"
    config_path.write_text("fail_open = false\ndry_run = false\n", encoding="utf-8")
    monkeypatch.setenv("SAFETY_GUARD_FAIL_OPEN", "1")
    monkeypatch.setenv("SAFETY_GUARD_DRY_RUN", "1")

    cfg = config_module.load(config_path)

    assert cfg.fail_open is True
    assert cfg.dry_run is True


def test_example_config_is_valid_and_keeps_all_rules_enabled():
    example = Path(__file__).resolve().parent.parent / "safety_guard.toml.example"

    cfg = config_module.load(example)

    assert cfg.load_error is None
    assert cfg.disabled_rules == ()
    assert cfg.fail_open is False


@pytest.mark.parametrize(
    "body",
    [
        'fail_open = "false"\n',
        'protected_branches = "main"\n',
        '[severity_overrides]\nbash-rm-targeted = "low"\n',
    ],
)
def test_invalid_safety_types_fall_back_to_fail_closed(
    tmp_path: Path,
    body: str,
):
    config_path = tmp_path / "invalid-safety-guard.toml"
    config_path.write_text(body, encoding="utf-8")

    cfg = config_module.load(config_path)

    assert cfg.load_error == "config_invalid"
    assert cfg.fail_open is False
    assert cfg.protected_branches == ("main", "master", "release/*")


def test_unknown_adapter_is_rejected():
    with pytest.raises(ValueError, match="unknown adapter"):
        get("missing")


def test_unknown_tool_uses_default_allow(tmp_path: Path):
    output = runner.run(
        _claude_input("UnknownTool", {}, tmp_path),
        adapter=get("claude"),
        config=_fail_closed_config(),
    )
    assert output == {}


@pytest.mark.parametrize(
    ("adapter_name", "event"),
    [
        ("claude", "PreToolUse"),
        ("codex-pretool", "PreToolUse"),
        ("codex-permission", "PermissionRequest"),
        ("grok", "PreToolUse"),
    ],
)
def test_missing_tool_name_fails_closed(adapter_name: str, event: str, tmp_path: Path):
    output = runner.run(
        {"hook_event_name": event, "tool_input": {}, "cwd": str(tmp_path)},
        adapter=get(adapter_name),
        config=_fail_closed_config(),
    )

    if adapter_name == "grok":
        assert output["decision"] == "deny"
    elif adapter_name == "codex-permission":
        assert output["hookSpecificOutput"]["decision"]["behavior"] == "deny"
    else:
        assert output["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_dry_run_bash_parse_error_does_not_block(tmp_path: Path):
    output = runner.run(
        _claude_input("Bash", {"command": "apply_patch <<'"}, tmp_path),
        adapter=get("claude"),
        config=replace(_fail_closed_config(), dry_run=True),
    )

    assert output == {}


def test_invalid_tool_input_fails_closed(tmp_path: Path):
    output = runner.run(
        _claude_input("Bash", "not-an-object", tmp_path),
        adapter=get("claude"),
        config=_fail_closed_config(),
    )
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "tool_input must be an object" in output["hookSpecificOutput"]["permissionDecisionReason"]


def test_unrelated_event_is_ignored(tmp_path: Path):
    output = runner.run(
        {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"},
            "cwd": str(tmp_path),
        },
        adapter=get("claude"),
        config=_fail_closed_config(),
    )
    assert output == {}


def test_real_entry_reads_stdin_with_explicit_adapter(tmp_path: Path):
    entry = Path(__file__).resolve().parents[1] / "safety-guard.py"
    payload = _claude_input("Bash", {"command": "git push --force origin main"}, tmp_path)
    env = {
        **os.environ,
        "SAFETY_GUARD_NO_AUDIT": "1",
        "SAFETY_GUARD_IGNORE_DISABLED_RULES": "1",
    }

    completed = subprocess.run(
        [sys.executable, str(entry), "--adapter", "codex-pretool"],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    output = json.loads(completed.stdout)
    assert output["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"

def test_wrong_adapter_on_pretool_fails_closed(tmp_path: Path):
    output = runner.run(
        {
            "hook_event_name": "pre_tool_use",
            "tool_name": "run_terminal_command",
            "tool_input": {"command": "rm -rf /"},
            "cwd": str(tmp_path),
        },
        adapter=get("claude"),
        config=_fail_closed_config(),
    )
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "未识别此 PreToolUse" in output["hookSpecificOutput"]["permissionDecisionReason"]


def test_post_tool_use_still_ignored(tmp_path: Path):
    output = runner.run(
        {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"},
            "cwd": str(tmp_path),
        },
        adapter=get("claude"),
        config=_fail_closed_config(),
    )
    assert output == {}
