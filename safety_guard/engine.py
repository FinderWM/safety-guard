"""规则引擎——只处理规范化请求，不感知外部 Hook 协议。"""
from __future__ import annotations

import traceback
from typing import Any

from . import audit, context
from .config import Config
from .contracts import Decision, DecisionResult, NormalizedRequest
from .rules.base import RuleMatch
from .rules.registry import iter_rules_for_tool


def _apply_severity_overrides(matches: list[RuleMatch], cfg: Config) -> list[RuleMatch]:
    if not cfg.severity_overrides:
        return matches
    adjusted: list[RuleMatch] = []
    for m in matches:
        sev = cfg.severity_overrides.get(m.rule_id, m.severity)
        if sev != m.severity:
            adjusted.append(RuleMatch(rule_id=m.rule_id, severity=sev, reason=m.reason, extra=m.extra))
        else:
            adjusted.append(m)
    return adjusted


def _match_to_audit(m: RuleMatch) -> dict[str, Any]:
    out: dict[str, Any] = {"id": m.rule_id, "severity": m.severity, "reason": m.reason}
    if m.extra:
        out["extra"] = m.extra
    return out


def _bash_parse_reason(parse_error: str) -> str:
    return (
        f"Bash 命令解析失败，无法判定安全性：{parse_error}。"
        "如果这是只读搜索，请检查 shell 引号；正则中的反引号、内层双引号建议改用单引号包裹或转义。"
    )


def _decide(matches: list[RuleMatch]) -> tuple[Decision, str | None]:
    """聚合决策：有 high → deny；只有 medium → ask；空 → allow。"""
    if not matches:
        return "allow", None
    severities = {m.severity for m in matches}
    if "high" in severities:
        ordered = sorted(matches, key=lambda m: 0 if m.severity == "high" else 1)
        reason = " | ".join(f"[{m.severity.upper()}:{m.rule_id}] {m.reason}" for m in ordered)
        return "deny", reason
    reason = " | ".join(f"[{m.severity.upper()}:{m.rule_id}] {m.reason}" for m in matches)
    return "ask", reason


def _internal_result(reason: str, cfg: Config) -> DecisionResult:
    if cfg.fail_open:
        return DecisionResult("allow")
    return DecisionResult("deny", f"[INTERNAL:safety-guard] {reason}")


def _write_internal_audit(
    *,
    cfg: Config,
    adapter: str,
    tool: str,
    cwd: str,
    raw_input: str,
    reason: str,
    error_type: str,
) -> None:
    try:
        audit.write(
            tool=tool,
            cwd=cwd,
            raw_input=raw_input,
            matches=[],
            decision="dry-run-deny" if cfg.dry_run else "deny",
            adapter=adapter,
            error_type=error_type,
            error_detail=reason,
            config=cfg,
        )
    except Exception:
        pass


def _collect_matches(tool: str, ctx, cfg: Config) -> list[RuleMatch]:
    matches: list[RuleMatch] = []
    for rule in iter_rules_for_tool(tool, disabled=cfg.disabled_rules):
        try:
            m = rule.match(ctx)
        except Exception as e:
            tb = traceback.format_exc(limit=2)
            matches.append(RuleMatch(
                rule_id=rule.id,
                severity="high",  # 规则崩溃→fail-closed 当 high 处理
                reason=f"规则 {rule.id} 执行异常：{e}",
                extra={"traceback": tb},
            ))
            continue
        if m is not None:
            matches.append(m)
    return matches


def evaluate(request: NormalizedRequest, cfg: Config) -> DecisionResult:
    """检查请求中的全部操作，并聚合为一个统一决策。"""
    matches: list[RuleMatch] = []
    for operation in request.operations:
        try:
            ctx = context.build(operation, request.cwd, cfg)
        except Exception as e:
            return _internal_result(f"上下文构造失败：{e}", cfg)

        if operation.tool == "Bash" and getattr(ctx, "parse_error", None):
            if cfg.fail_open:
                continue
            reason = _bash_parse_reason(ctx.parse_error)
            _write_internal_audit(
                cfg=cfg,
                adapter=request.adapter,
                tool=operation.tool,
                cwd=str(ctx.cwd),
                raw_input=ctx.raw_command,
                reason=reason,
                error_type="bash_parse_error",
            )
            return _internal_result(reason, cfg)

        matches.extend(_collect_matches(operation.tool, ctx, cfg))

    matches = _apply_severity_overrides(matches, cfg)
    decision, reason = _decide(matches)

    try:
        audit.write(
            tool=request.tool,
            cwd=request.cwd,
            raw_input=request.audit_input,
            matches=[_match_to_audit(match) for match in matches],
            decision="dry-run-" + decision if cfg.dry_run else decision,
            adapter=request.adapter,
            config=cfg,
        )
    except Exception:
        pass

    if cfg.dry_run:
        return DecisionResult("allow")
    return DecisionResult(decision, reason)
