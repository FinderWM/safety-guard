"""Codex PreToolUse 的本机同步审批桥。"""
from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from ..audit import redact_text
from ..config import Config
from ..contracts import DecisionResult, NormalizedRequest
from ..helpers import safe_identifier


ApprovalStatus = Literal[
    "approved",
    "denied",
    "cancelled",
    "timed_out",
    "unavailable",
    "error",
]

_CODEX_PRETOOL_ADAPTER = "codex-pretool"
_PRETOOL_EVENT = "PreToolUse"
_NATIVE_APPROVAL_GAP_MODES = frozenset({"dontAsk", "bypassPermissions"})
_PROMPT_PREVIEW_CHARS = 1600
_MAX_APPROVAL_TIMEOUT_SECONDS = 25
_OSASCRIPT = "/usr/bin/osascript"
_DIALOG_SCRIPT = (
    'ObjC.import("Foundation");\n'
    'function run(argv) {\n'
    '  const app = Application.currentApplication();\n'
    '  app.includeStandardAdditions = true;\n'
    '  const data = $.NSFileHandle.fileHandleWithStandardInput.readDataToEndOfFile;\n'
    '  const prompt = ObjC.unwrap($.NSString.alloc.initWithDataEncoding(data, $.NSUTF8StringEncoding));\n'
    '  const timeoutSeconds = Number(argv[0]);\n'
    '  try {\n'
    '    const answer = app.displayDialog(prompt, {\n'
    '      withTitle: "Safety Guard",\n'
    '      buttons: ["拒绝", "允许"],\n'
    '      defaultButton: "拒绝",\n'
    '      cancelButton: "拒绝",\n'
    '      withIcon: "caution",\n'
    '      givingUpAfter: timeoutSeconds\n'
    '    });\n'
    '    if (answer.gaveUp) return "timed_out";\n'
    '    return answer.buttonReturned === "允许" ? "approved" : "denied";\n'
    '  } catch (error) {\n'
    '    if (error.number === -128) return "cancelled";\n'
    '    return "error";\n'
    '  }\n'
    '}'
)


@dataclass(frozen=True)
class ApprovalOutcome:
    status: ApprovalStatus
    provider: str = "macos-dialog"


class ApprovalResolver(Protocol):
    def resolve(
        self,
        request: NormalizedRequest,
        result: DecisionResult,
        *,
        timeout_seconds: int,
    ) -> ApprovalOutcome:
        """同步等待一次本机人工审批。"""
        ...


class MacOSDialogApprovalResolver:
    """通过系统自带 osascript 显示阻塞式确认框，不需要常驻服务。"""

    def resolve(
        self,
        request: NormalizedRequest,
        result: DecisionResult,
        *,
        timeout_seconds: int,
    ) -> ApprovalOutcome:
        if sys.platform != "darwin":
            return ApprovalOutcome("unavailable")
        try:
            completed = subprocess.run(
                [
                    _OSASCRIPT,
                    "-l",
                    "JavaScript",
                    "-e",
                    _DIALOG_SCRIPT,
                    "--",
                    str(timeout_seconds),
                ],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                input=_prompt_text(request, result),
                timeout=min(timeout_seconds, _MAX_APPROVAL_TIMEOUT_SECONDS) + 2,
            )
        except subprocess.TimeoutExpired:
            return ApprovalOutcome("timed_out")
        except OSError:
            return ApprovalOutcome("unavailable")

        if completed.returncode != 0:
            return ApprovalOutcome("error")
        response = completed.stdout.strip()
        if response in {"approved", "denied", "cancelled", "timed_out"}:
            return ApprovalOutcome(response)
        return ApprovalOutcome("error")


def approval_result(
    result: DecisionResult,
    outcome: ApprovalOutcome,
    config: Config,
    permission_mode: str | None,
) -> DecisionResult:
    """把人工结果映射回统一决策，同时保留引擎原始结论。"""
    engine_decision = result.resolved_engine_decision()
    approval = {
        "provider": safe_identifier(outcome.provider),
        "status": outcome.status,
        "mode": config.codex_approval_mode,
        "permission_mode": safe_identifier(permission_mode),
        "origin": result.decision_source,
    }
    if outcome.status == "approved":
        return DecisionResult(
            decision="allow",
            reason=result.reason,
            engine_decision=engine_decision,
            audit_matches=result.audit_matches,
            error_type=result.error_type,
            error_detail=result.error_detail,
            review=result.review,
            approval=approval,
            decision_source="interactive",
        )

    labels = {
        "denied": "用户拒绝",
        "cancelled": "用户取消",
        "timed_out": "等待确认超时",
        "unavailable": "当前环境无法显示确认框",
        "error": "确认框执行失败",
    }
    prefix = labels.get(outcome.status, "审批未通过")
    reason = f"Safety Guard 人工审批未通过（{prefix}）"
    if result.reason:
        reason += f"：{redact_text(result.reason)}"
    return DecisionResult(
        decision="deny",
        reason=reason,
        engine_decision=engine_decision,
        audit_matches=result.audit_matches,
        error_type=result.error_type,
        error_detail=result.error_detail,
        review=result.review,
        approval=approval,
        decision_source="interactive",
    )


def resolve_codex_ask(
    *,
    stdin_json: dict[str, Any],
    adapter_name: str,
    request: NormalizedRequest,
    result: DecisionResult,
    config: Config,
    resolver: ApprovalResolver | None = None,
) -> DecisionResult:
    """只在配置命中的 Codex PreToolUse ask 上执行同步审批。"""
    permission_mode = _permission_mode(stdin_json)
    if not _should_resolve(
        adapter_name=adapter_name,
        request=request,
        result=result,
        config=config,
        permission_mode=permission_mode,
    ):
        return result

    active_resolver = resolver or MacOSDialogApprovalResolver()
    try:
        outcome = active_resolver.resolve(
            request,
            result,
            timeout_seconds=min(config.codex_approval_timeout_seconds, _MAX_APPROVAL_TIMEOUT_SECONDS),
        )
    except Exception:
        outcome = ApprovalOutcome("error")
    return approval_result(result, outcome, config, permission_mode)


def _permission_mode(stdin_json: dict[str, Any]) -> str | None:
    for key in ("permission_mode", "permissionMode"):
        value = stdin_json.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _should_resolve(
    *,
    adapter_name: str,
    request: NormalizedRequest,
    result: DecisionResult,
    config: Config,
    permission_mode: str | None,
) -> bool:
    if (
        adapter_name != _CODEX_PRETOOL_ADAPTER
        or request.adapter != _CODEX_PRETOOL_ADAPTER
        or request.event != _PRETOOL_EVENT
        or result.decision != "ask"
    ):
        return False
    if config.codex_approval_mode == "always":
        return True
    return (
        config.codex_approval_mode == "native-gap"
        and permission_mode in _NATIVE_APPROVAL_GAP_MODES
    )


def _prompt_text(request: NormalizedRequest, result: DecisionResult) -> str:
    body = redact_text(request.audit_input.strip() or "（无可显示内容）")
    if len(body) > _PROMPT_PREVIEW_CHARS:
        body = body[:_PROMPT_PREVIEW_CHARS] + "…"
    reason = redact_text(result.reason or "Safety Guard 检测到需要确认的操作。")
    cwd = redact_text(request.cwd)
    return (
        "Codex 请求执行一个需要确认的操作。\n\n"
        f"工具：{safe_identifier(request.tool)}\n"
        f"工作目录：{cwd}\n"
        f"风险：{reason}\n\n"
        f"待执行内容：\n{body}\n\n"
        "是否仅允许本次操作？"
    )
