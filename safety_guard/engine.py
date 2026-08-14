"""规则引擎——只处理规范化请求，不感知外部 Hook 协议。"""
from __future__ import annotations

import traceback
from typing import Any

from .config import Config
from .contracts import Decision, DecisionResult, NormalizedRequest
from . import context
from .reviewer import Reviewer, review_unknown
from .rules.base import RuleMatch
from .rules.registry import iter_rules_for_tool


def _apply_severity_overrides(matches: list[RuleMatch], cfg: Config) -> list[RuleMatch]:
    if not cfg.severity_overrides:
        return matches
    adjusted: list[RuleMatch] = []
    for m in matches:
        if m.extra and m.extra.get("internal_error") is True:
            adjusted.append(m)
            continue
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
    from .helpers import redact_user_paths

    if not matches:
        return "allow", None
    severities = {m.severity for m in matches}
    if "high" in severities:
        ordered = sorted(matches, key=lambda m: 0 if m.severity == "high" else 1)
        reason = " | ".join(f"[{m.severity.upper()}:{m.rule_id}] {m.reason}" for m in ordered)
        return "deny", redact_user_paths(reason)
    reason = " | ".join(f"[{m.severity.upper()}:{m.rule_id}] {m.reason}" for m in matches)
    return "ask", redact_user_paths(reason)


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


def _collect_matches(tool: str, ctx, cfg: Config) -> list[RuleMatch]:
    matches: list[RuleMatch] = []
    for rule in iter_rules_for_tool(tool, disabled=cfg.disabled_rules):
        try:
            m = rule.match(ctx)
        except Exception as e:
            if cfg.fail_open:
                continue
            tb = traceback.format_exc(limit=2)
            matches.append(RuleMatch(
                rule_id=rule.id,
                severity="high",
                reason=f"规则 {rule.id} 执行异常：{e}",
                extra={"traceback": tb, "internal_error": True},
            ))
            continue
        if m is not None:
            matches.append(m)
    return matches


def _review_decision(request: NormalizedRequest, cfg: Config, reviewer: Reviewer | None) -> DecisionResult:
    reviewed = review_unknown(request, cfg, reviewer)
    metadata = {
        "reviewer": reviewed.reviewer,
        "status": reviewed.status,
    }
    if reviewed.error_type:
        metadata["error_type"] = reviewed.error_type
    decision = reviewed.decision
    reason = reviewed.reason or "未知工具保持默认放行策略"
    if cfg.dry_run:
        return DecisionResult(
            "abstain",
            reason,
            engine_decision=decision,
            review=metadata,
            decision_source="reviewer",
        )
    return DecisionResult(
        decision,
        reason,
        engine_decision=decision,
        review=metadata,
        decision_source="reviewer",
    )


def evaluate(
    request: NormalizedRequest,
    cfg: Config,
    reviewer: Reviewer | None = None,
) -> DecisionResult:
    """检查请求中的全部操作，并聚合为一个统一决策。

    不写审计：由 runner 在 render 之后统一落盘（才能记 rendered_decision）。
    """
    if request.classification == "unknown":
        return _review_decision(request, cfg, reviewer)
    if request.classification == "known-noop" and not request.operations:
        return DecisionResult("allow", engine_decision="allow")

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
            detail = f"[INTERNAL:safety-guard] {reason}"
            if cfg.dry_run:
                return DecisionResult(
                    "allow",
                    detail,
                    engine_decision="deny",
                    error_type="bash_parse_error",
                    error_detail=reason,
                    decision_source="internal",
                )
            return DecisionResult(
                "deny",
                detail,
                engine_decision="deny",
                error_type="bash_parse_error",
                error_detail=reason,
            )

        matches.extend(_collect_matches(operation.tool, ctx, cfg))

    matches = _apply_severity_overrides(matches, cfg)
    decision, reason = _decide(matches)
    audit_matches = tuple(_match_to_audit(m) for m in matches)

    if cfg.dry_run:
        # 平台侧放行，审计仍记录真实引擎结论
        return DecisionResult(
            "allow",
            reason,
            engine_decision=decision,
            audit_matches=audit_matches,
        )
    return DecisionResult(
        decision,
        reason,
        engine_decision=decision,
        audit_matches=audit_matches,
    )
