"""Codex Adapter 测试 fixtures。"""
from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

import pytest

# add hooks root for `import safety_guard`
HOOKS_DIR = Path(__file__).resolve().parent.parent.parent
if str(HOOKS_DIR) not in sys.path:
    sys.path.insert(0, str(HOOKS_DIR))

from safety_guard import runner
from safety_guard.adapters.registry import get
from safety_guard.config import load as load_config


@pytest.fixture
def cwd(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture
def pretool():
    adapter = get("codex-pretool")

    def _run(tool_name: str, tool_input: dict, cwd: Path):
        return runner.run(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": tool_name,
                "tool_input": tool_input,
                "cwd": str(cwd),
            },
            adapter=adapter,
            config=replace(load_config(), fail_open=False),
        )

    return _run


@pytest.fixture
def permission():
    adapter = get("codex-permission")

    def _run(tool_name: str, tool_input: dict, cwd: Path):
        return runner.run(
            {
                "hook_event_name": "PermissionRequest",
                "tool_name": tool_name,
                "tool_input": tool_input,
                "cwd": str(cwd),
            },
            adapter=adapter,
            config=replace(load_config(), fail_open=False),
        )

    return _run
