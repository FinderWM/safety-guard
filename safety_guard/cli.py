"""CLI 工具——调试 / 干跑 / 自检入口。

子命令：
  --list-rules                                    列出所有已注册规则
  --explain --tool TOOL --command CMD [--cwd P]   模拟匹配，控制台打印决策（不输出 hook JSON）
  --explain --tool TOOL --path P [--cwd P]         同上，用于 Write/Edit/NotebookEdit
  --selftest                                      调用 pytest 跑 tests/
  --regression                                    跑 tests/fixtures/regression_commands.txt
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from . import audit, engine, runner
from .adapters.registry import get
from .config import load as load_config
from .rules.registry import all_rules


def _cmd_list_rules() -> int:
    rules = sorted(all_rules(), key=lambda r: r.id)
    for r in rules:
        applies = ",".join(r.applies_to)
        print(f"  [{r.severity.upper():6}] {r.id:42}  ({applies})")
        print(f"           {r.description}")
    print(f"\n共 {len(rules)} 条规则")
    return 0


def _build_stdin(tool: str, *, command: str | None, path: str | None, cwd: str | None, edit_mode: str | None) -> dict:
    tool_input: dict = {}
    if tool == "Bash":
        tool_input["command"] = command or ""
    elif tool in ("Write", "Edit"):
        tool_input["file_path"] = path or ""
    elif tool == "NotebookEdit":
        tool_input["notebook_path"] = path or ""
        if edit_mode:
            tool_input["edit_mode"] = edit_mode
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": tool_input,
        "cwd": cwd or os.getcwd(),
    }


def _cmd_explain(args) -> int:
    if args.tool == "Bash" and not args.command:
        print("ERROR: --tool Bash 需配合 --command", file=sys.stderr)
        return 2
    if args.tool != "Bash" and not args.path:
        print(f"ERROR: --tool {args.tool} 需配合 --path", file=sys.stderr)
        return 2

    stdin_json = _build_stdin(
        args.tool, command=args.command, path=args.path,
        cwd=args.cwd, edit_mode=args.edit_mode,
    )
    cfg = load_config()
    print(f"Input:    {args.command or args.path}")
    print(f"Tool:     {args.tool}")
    print(f"CWD:      {stdin_json['cwd']}")
    print()

    adapter = get("claude")
    try:
        request = adapter.parse(stdin_json)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    if request is None:
        print("Request: <ignored event>")
        return 0

    result = engine.evaluate(request, cfg)
    if result.reason:
        print(f"Reason:   {result.reason}")
    print(f"Final decision: {result.decision.upper()}")
    return 0


def _cmd_selftest() -> int:
    pkg_root = Path(__file__).resolve().parent.parent
    tests_dir = pkg_root / "tests"
    if not tests_dir.exists():
        print(f"ERROR: tests dir not found: {tests_dir}", file=sys.stderr)
        return 2
    env = {**os.environ, audit.AUDIT_DISABLE_ENV: "1"}
    return subprocess.call([sys.executable, "-m", "pytest", str(tests_dir), "-v"], env=env)


def _cmd_regression() -> int:
    pkg_root = Path(__file__).resolve().parent.parent
    fx = pkg_root / "tests" / "fixtures" / "regression_commands.txt"
    if not fx.exists():
        print(f"ERROR: regression file not found: {fx}", file=sys.stderr)
        return 2
    # 回归样本全是合成的危险命令，绝不能进生产审计
    os.environ[audit.AUDIT_DISABLE_ENV] = "1"
    cfg = load_config()
    adapter = get("claude")
    fail = 0
    for line in fx.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # 格式：EXPECTED|CMD（EXPECTED ∈ allow/ask/deny）
        if "|" not in line:
            continue
        expected, cmd = line.split("|", 1)
        expected = expected.strip().lower()
        cmd = cmd.strip()
        stdin_json = _build_stdin("Bash", command=cmd, path=None, cwd=str(Path.cwd()), edit_mode=None)
        out = runner.run(stdin_json, adapter=adapter, config=cfg)
        if not out:
            actual = "allow"
        else:
            actual = out["hookSpecificOutput"]["permissionDecision"]
        ok = "OK" if actual == expected else "FAIL"
        if actual != expected:
            fail += 1
        print(f"  {ok:4} expected={expected:5} actual={actual:5}  {cmd}")
    print()
    print(f"Total fails: {fail}")
    return 0 if fail == 0 else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="safety-guard")
    sub = parser.add_mutually_exclusive_group(required=True)
    sub.add_argument("--list-rules", action="store_true", help="列出所有已注册规则")
    sub.add_argument("--explain", action="store_true", help="模拟一次匹配并打印决策（不输出 hook JSON）")
    sub.add_argument("--selftest", action="store_true", help="跑 tests/ 下全部测试")
    sub.add_argument("--regression", action="store_true", help="跑 regression 命令样本")

    parser.add_argument("--tool", choices=("Bash", "Write", "Edit", "NotebookEdit"), help="工具名")
    parser.add_argument("--command", help="Bash 命令字符串")
    parser.add_argument("--path", help="Write/Edit/NotebookEdit 的 file_path")
    parser.add_argument("--cwd", help="模拟 CWD（默认 os.getcwd()）")
    parser.add_argument("--edit-mode", help="NotebookEdit 的 edit_mode（replace/insert/delete）")

    args = parser.parse_args(argv)

    if args.list_rules:
        return _cmd_list_rules()
    if args.explain:
        if not args.tool:
            parser.error("--explain 需要 --tool")
        return _cmd_explain(args)
    if args.selftest:
        return _cmd_selftest()
    if args.regression:
        return _cmd_regression()
    return 2
