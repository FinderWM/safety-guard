"""Grok Adapter 测试 fixtures。"""
from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

import pytest

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
def grok():
    adapter = get("grok")

    def _run(
        tool_name: str,
        tool_input: dict,
        cwd: Path,
        *,
        event: str = "pre_tool_use",
        camel: bool = True,
    ):
        if camel:
            payload = {
                "hookEventName": event,
                "toolName": tool_name,
                "toolInput": tool_input,
                "cwd": str(cwd),
            }
        else:
            payload = {
                "hook_event_name": event,
                "tool_name": tool_name,
                "tool_input": tool_input,
                "cwd": str(cwd),
            }
        return runner.run(
            payload,
            adapter=adapter,
            config=replace(load_config(), fail_open=False),
        )

    return _run
