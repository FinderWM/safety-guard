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
    assert available() == ["claude", "codex-permission", "codex-pretool"]


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


def test_unknown_adapter_is_rejected():
    with pytest.raises(ValueError, match="unknown adapter"):
        get("missing")


def test_unknown_tool_fails_closed(tmp_path: Path):
    output = runner.run(
        _claude_input("UnknownTool", {}, tmp_path),
        adapter=get("claude"),
        config=_fail_closed_config(),
    )
    reason = output["hookSpecificOutput"]["permissionDecisionReason"]
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "unsupported Claude tool" in reason


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
