"""外部 Hook 协议适配器。"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Protocol, runtime_checkable

from ..contracts import DecisionResult, NormalizedRequest
from ..helpers import safe_identifier


@dataclass(frozen=True)
class AdapterCapabilities:
    """声明平台原生决策能力，避免把一个平台的语义套到其它平台。"""

    supports_ask: bool
    ask_fallback: Literal["abstain", "allow"] = "abstain"
    abstain_fallback: Literal["abstain", "allow"] = "abstain"


def project_decision(result: DecisionResult, capabilities: AdapterCapabilities) -> str:
    """把统一决策投影为平台真实支持的动作。"""
    if result.decision == "ask" and not capabilities.supports_ask:
        return capabilities.ask_fallback
    if result.decision == "abstain":
        return capabilities.abstain_fallback
    return result.decision


def safe_tool_label(tool: str | None) -> str:
    """Return a bounded tool label suitable for audit and error paths."""
    return safe_identifier(tool)


def unknown_request(
    *,
    adapter: str,
    event: str,
    tool: str | None,
    cwd: str,
    raw_input: dict[str, Any] | None = None,
) -> NormalizedRequest:
    """统一构造未知工具请求，保证所有平台走同一个 reviewer 入口。"""
    safe_tool = safe_tool_label(tool)
    payload = dict(raw_input or {})
    return NormalizedRequest(
        adapter=adapter,
        event=event,
        tool=safe_tool,
        operations=(),
        cwd=cwd,
        audit_input=safe_tool,
        classification="unknown",
        raw_input=payload,
        input_keys=tuple(payload),
        provenance=(f"adapter:{adapter}",),
    )


@runtime_checkable
class Adapter(Protocol):
    name: str
    capabilities: AdapterCapabilities

    def parse(self, stdin_json: dict[str, Any]) -> NormalizedRequest | None:
        """解析目标事件；非本适配器事件返回 None，非法输入必须抛异常。"""
        ...

    def render(self, result: DecisionResult) -> dict[str, Any]:
        """把统一决策编码成平台原生 stdout JSON。"""
        ...
