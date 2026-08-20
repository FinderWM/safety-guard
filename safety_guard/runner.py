"""Hook 运行入口——连接 Adapter、Engine 与标准输入输出。"""
from __future__ import annotations

import json
import sys
from typing import Any

from . import audit, engine
from .adapters.base import Adapter, safe_tool_label
from .adapters import fields
from .adapters.codex_approval import ApprovalResolver, resolve_codex_ask
from .adapters.registry import select
from .config import Config, load as load_config
from .contracts import DecisionResult, NormalizedRequest
from .reviewer import Reviewer

# 各平台 PreToolUse 族事件：adapter 未认领时不应静默放行（否则错 adapter 会放行 rm -rf /）。
_PRETOOL_EVENTS = frozenset({
    "PreToolUse",
    "pre_tool_use",
    "PermissionRequest",
    "permission_request",
})


def _looks_like_pretool(stdin_json: dict[str, Any]) -> bool:
    event = fields.event_name(stdin_json)
    if not isinstance(event, str) or event not in _PRETOOL_EVENTS:
        return False
    tool = fields.tool_name(stdin_json)
    return isinstance(tool, str) and bool(tool.strip())


def _internal_result(reason: str, cfg: Config) -> DecisionResult:
    if cfg.dry_run:
        return DecisionResult(
            "allow",
            reason,
            engine_decision="deny",
            error_type="internal",
            error_detail=reason,
            decision_source="internal",
        )
    if cfg.fail_open:
        return DecisionResult("allow", engine_decision="allow", decision_source="internal")
    return DecisionResult(
        "deny",
        f"[INTERNAL:safety-guard] {reason}",
        engine_decision="deny",
        error_type="internal",
        error_detail=reason,
        decision_source="internal",
    )


def _tool_name(stdin_json: dict[str, Any]) -> str:
    raw = fields.tool_name(stdin_json)
    return safe_tool_label(raw) if raw is not None else "unknown"


def _cwd(stdin_json: dict[str, Any]) -> str:
    try:
        return fields.cwd(stdin_json)
    except ValueError:
        return ""


def _audit_raw(stdin_json: dict[str, Any]) -> str:
    """无 NormalizedRequest 时尽量留下可回放线索。"""
    try:
        ti = fields.tool_input(stdin_json)
    except ValueError:
        ti = {}
    if isinstance(ti, dict):
        cmd = ti.get("command") or ti.get("cmd")
        if isinstance(cmd, str):
            return cmd
        path = ti.get("file_path") or ti.get("target_file") or ti.get("path")
        if isinstance(path, str):
            return path
    try:
        return json.dumps(stdin_json, ensure_ascii=False)[: audit.FULL_BODY_CHARS]
    except (TypeError, ValueError):
        return ""


def _emit_audit(
    *,
    cfg: Config,
    adapter_name: str,
    result: DecisionResult,
    output: dict[str, Any],
    tool: str,
    cwd: str,
    raw_input: str,
    hook_event: str | None = None,
    classification: str | None = None,
    review: dict[str, Any] | None = None,
) -> None:
    try:
        audit.record_evaluation(
            adapter=adapter_name,
            tool=tool or "unknown",
            cwd=cwd or "",
            raw_input=raw_input or "",
            matches=list(result.audit_matches),
            engine_decision=result.resolved_engine_decision(),
            rendered_output=output,
            config=cfg,
            hook_event=hook_event,
            error_type=result.error_type,
            error_detail=result.error_detail,
            classification=classification,
            review=review,
            approval=result.approval,
            decision_source=result.decision_source,
        )
    except Exception:
        pass


def run(
    stdin_json: dict[str, Any],
    *,
    adapter: Adapter | None = None,
    config: Config | None = None,
    reviewer: Reviewer | None = None,
    approval_resolver: ApprovalResolver | None = None,
) -> dict[str, Any]:
    """执行一次 Hook 请求并返回目标平台的原生输出。"""
    selected = adapter or select()
    cfg = config or load_config()
    try:
        request = selected.parse(stdin_json)
    except Exception as e:
        result = _internal_result(f"hook 输入解析失败：{e}", cfg)
        output = selected.render(result)
        _emit_audit(
            cfg=cfg,
            adapter_name=selected.name,
            result=result,
            output=output,
            tool=_tool_name(stdin_json),
            cwd=_cwd(stdin_json),
            raw_input=_audit_raw(stdin_json),
            hook_event=fields.event_name(stdin_json),
            classification="unknown",
        )
        return output
    if request is None:
        if _looks_like_pretool(stdin_json):
            result = _internal_result(
                f"adapter={selected.name!r} 未识别此 PreToolUse 载荷"
                f"（事件/工具与适配器不匹配）。请检查 --adapter / "
                f"SAFETY_GUARD_ADAPTER 是否与当前 CLI 一致。",
                cfg,
            )
            output = selected.render(result)
            _emit_audit(
                cfg=cfg,
                adapter_name=selected.name,
                result=result,
                output=output,
                tool=_tool_name(stdin_json),
                cwd=_cwd(stdin_json),
                raw_input=_audit_raw(stdin_json),
                hook_event=fields.event_name(stdin_json),
            )
            return output
        return {}

    result = engine.evaluate(request, cfg, reviewer=reviewer)
    result = resolve_codex_ask(
        stdin_json=stdin_json,
        adapter_name=selected.name,
        request=request,
        result=result,
        config=cfg,
        resolver=approval_resolver,
    )
    output = selected.render(result)
    _emit_audit(
        cfg=cfg,
        adapter_name=request.adapter,
        result=result,
        output=output,
        tool=request.tool,
        cwd=request.cwd,
        raw_input=request.audit_input,
        hook_event=request.event,
        classification=request.classification,
        review=result.review,
    )
    return output


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
        result = _internal_result(f"hook 输入 JSON 无法解析：{e}", cfg)
        output = selected.render(result)
        _emit_audit(
            cfg=cfg,
            adapter_name=selected.name,
            result=result,
            output=output,
            tool="unknown",
            cwd="",
            raw_input=raw[: audit.FULL_BODY_CHARS],
        )
    else:
        output = run(data, adapter=selected, config=cfg)

    if output:
        print(json.dumps(output, ensure_ascii=False))
    return 0
