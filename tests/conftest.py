"""公共 fixtures：构造 ToolContext、模拟 stdin JSON。"""
from __future__ import annotations

import os
import sys
from dataclasses import replace
from pathlib import Path

# 测试与生产环境的两处隔离，必须在 import safety_guard 之前设好，子进程测试也靠继承生效：
#   1. 不写生产审计——runner.run() 会调 audit.write()，跑一轮 pytest/--regression
#      就往 audit/ 灌几百条 `rm -rf /` 之类的 fixture 记录，统计失真且挤占 retention。
#   2. 忽略 toml 里的 disabled_rules——改 hook 自身时要临时把自保护规则关掉，
#      那个窗口会让十来条自保护测试假性 FAIL。
os.environ.setdefault("SAFETY_GUARD_NO_AUDIT", "1")
os.environ.setdefault("SAFETY_GUARD_IGNORE_DISABLED_RULES", "1")

# 把 hooks 目录加入 sys.path
HOOKS_DIR = Path(__file__).resolve().parent.parent
if str(HOOKS_DIR) not in sys.path:
    sys.path.insert(0, str(HOOKS_DIR))

import pytest
from safety_guard import runner
from safety_guard.adapters.registry import get
from safety_guard.config import Config, load as _load_config


CLAUDE_ADAPTER = get("claude")


@pytest.fixture
def cfg() -> Config:
    return replace(_load_config(), fail_open=False)


@pytest.fixture
def cwd(tmp_path: Path) -> Path:
    """每个测试一个隔离的临时 cwd。"""
    return tmp_path


def make_bash_input(command: str, cwd: Path) -> dict:
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "cwd": str(cwd),
    }


def make_file_input(tool: str, file_path: str, cwd: Path, edit_mode: str | None = None) -> dict:
    inp: dict = {
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "cwd": str(cwd),
    }
    if tool == "NotebookEdit":
        inp["tool_input"] = {"notebook_path": file_path}
        if edit_mode is not None:
            inp["tool_input"]["edit_mode"] = edit_mode
    else:
        inp["tool_input"] = {"file_path": file_path}
    return inp


def decide(stdin_json: dict) -> tuple[str, str | None]:
    """跑统一入口，返回 (decision, reason)。decision ∈ {allow, ask, deny}。"""
    out = runner.run(
        stdin_json,
        adapter=CLAUDE_ADAPTER,
        config=replace(_load_config(), fail_open=False),
    )
    if not out:
        return "allow", None
    h = out["hookSpecificOutput"]
    return h["permissionDecision"], h.get("permissionDecisionReason")


@pytest.fixture
def bash():
    """快捷：决策一条 bash 命令。"""
    def _go(command: str, cwd: Path):
        return decide(make_bash_input(command, cwd))
    return _go


@pytest.fixture
def file_tool():
    """快捷：决策一次 file 工具调用。"""
    def _go(tool: str, file_path: str, cwd: Path, edit_mode: str | None = None):
        return decide(make_file_input(tool, file_path, cwd, edit_mode))
    return _go
