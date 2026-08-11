"""Hook 运行入口——连接 Adapter、Engine 与标准输入输出。"""
from __future__ import annotations

import json
import sys
from typing import Any

from . import engine
from .adapters.base import Adapter
from .adapters.registry import select
from .config import Config, load as load_config
from .contracts import DecisionResult


def _internal_result(reason: str, cfg: Config) -> DecisionResult:
    if cfg.fail_open:
        return DecisionResult("allow")
    return DecisionResult("deny", f"[INTERNAL:safety-guard] {reason}")


def run(
    stdin_json: dict[str, Any],
    *,
    adapter: Adapter | None = None,
    config: Config | None = None,
) -> dict[str, Any]:
    """执行一次 Hook 请求并返回目标平台的原生输出。"""
    selected = adapter or select()
    cfg = config or load_config()
    try:
        request = selected.parse(stdin_json)
    except Exception as e:
        return selected.render(_internal_result(f"hook 输入解析失败：{e}", cfg))
    if request is None:
        return {}
    return selected.render(engine.evaluate(request, cfg))


def main_stdin(adapter_name: str | None = None) -> int:
    """从 stdin 读取一次 Hook 请求，并将平台原生 JSON 写到 stdout。"""
    try:
        selected = select(adapter_name)
    except ValueError as e:
        print(f"[INTERNAL:safety-guard] {e}", file=sys.stderr)
        return 2

    try:
        raw = sys.stdin.read()
    except OSError:
        return 0
    if not raw.strip():
        return 0

    cfg = load_config()
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("hook 输入必须是 JSON object")
    except (json.JSONDecodeError, ValueError) as e:
        output = selected.render(_internal_result(f"hook 输入 JSON 无法解析：{e}", cfg))
    else:
        output = run(data, adapter=selected, config=cfg)

    if output:
        print(json.dumps(output, ensure_ascii=False))
    return 0
