"""未知工具的可插拔审查入口。

默认 reviewer 只返回 abstain。真正的外部/LLM reviewer 必须显式注册，且收到的
请求默认是结构化、脱敏、截断后的摘要；原始未知载荷不会自动离开当前进程。
"""
from __future__ import annotations

import contextvars
import hashlib
import ipaddress
import posixpath
import re
import threading
from dataclasses import dataclass, field
from itertools import islice
from typing import Any, Protocol
from urllib.parse import urlsplit

from .contracts import Decision, NormalizedRequest, RequestClassification
from .helpers import redact_user_paths, safe_identifier


@dataclass(frozen=True)
class ReviewRequest:
    adapter: str
    event: str
    tool: str
    cwd: dict[str, Any]
    classification: RequestClassification
    payload: dict[str, Any]
    provenance: tuple[str, ...] = ()


@dataclass(frozen=True)
class ReviewResult:
    decision: Decision = "abstain"
    reason: str | None = None
    reviewer: str = "noop"
    status: str = "abstain"
    error_type: str | None = None


class Reviewer(Protocol):
    name: str

    def review(self, request: ReviewRequest) -> ReviewResult:
        ...


class AbstainReviewer:
    name = "noop"

    def review(self, request: ReviewRequest) -> ReviewResult:
        return ReviewResult(
            decision="abstain",
            reviewer=self.name,
            status="abstain",
            reason="未知工具暂未接入审查器，按默认放行策略继续",
        )


_REVIEWERS: dict[str, Reviewer] = {"noop": AbstainReviewer()}
_REVIEWERS_LOCK = threading.RLock()
_REVIEW_SLOTS = threading.BoundedSemaphore(value=4)
_DEPTH: contextvars.ContextVar[int] = contextvars.ContextVar("safety_guard_review_depth", default=0)
_SENSITIVE_KEY = re.compile(
    r"(?:pass(word|wd)?|secret|token|api[_-]?key|access[_-]?(?:key|token)|authorization|credential|private[_-]?key|bearer)",
    re.IGNORECASE,
)
_CONTENT_KEY = re.compile(
    r"(?:command|cmd|patch|content|old[_-]?string|new[_-]?string|script|code|prompt|text|body)",
    re.IGNORECASE,
)
_PATH_KEY = re.compile(
    r"(?:^|[_-])(path|file|directory|dir|cwd|workspace)(?:$|[_-])|filePath|target_file|target_directory",
    re.IGNORECASE,
)
_INLINE_SECRET = re.compile(
    r"(?i)(?P<prefix>(?:api[_-]?key|access[_-]?(?:key|token)|auth(?:orization)?|"
    r"bearer|client[_-]?secret|password|passwd|pwd|private[_-]?key|secret|token)"
    r"\s*(?:=|:)\s*)(?P<value>[^\s&;,]+)"
)
_URL_SECRET = re.compile(
    r"(?i)(?P<prefix>[?&](?:api[_-]?key|access[_-]?token|auth|password|secret|token)=)"
    r"(?P<value>[^&#\s]+)"
)
_URL_QUERY_VALUE = re.compile(r"(?P<prefix>[?&][^=&#\s]+)=([^&#\s]*)")
_SAFE_METADATA_FIELDS = frozenset({
    "action",
    "args",
    "arguments",
    "description",
    "id",
    "ids",
    "input",
    "inputs",
    "limit",
    "mode",
    "name",
    "offset",
    "options",
    "output",
    "outputs",
    "query",
    "recursive",
    "timeout",
    "type",
    "uri",
    "url",
})
_SAFE_ENUM_FIELDS = frozenset({"action", "mode", "type"})
_SAFE_NUMERIC_FIELDS = frozenset({"count", "limit", "offset", "page", "size", "timeout"})
_SAFE_ENUM_VALUES = frozenset({
    "add",
    "allow",
    "append",
    "copy",
    "create",
    "delete",
    "deny",
    "directory",
    "download",
    "edit",
    "execute",
    "file",
    "list",
    "move",
    "read",
    "recursive",
    "remove",
    "rename",
    "replace",
    "run",
    "update",
    "upload",
    "write",
})
_URL_FIELDS = frozenset({"url", "uri"})
_MAX_DEPTH = 4
_MAX_ITEMS = 24


def register(reviewer: Reviewer, *, replace: bool = False) -> None:
    name = getattr(reviewer, "name", "")
    if not isinstance(name, str) or not name.strip():
        raise ValueError("reviewer name must not be empty")
    with _REVIEWERS_LOCK:
        if name in _REVIEWERS and not replace:
            raise ValueError(f"duplicate reviewer: {name}")
        _REVIEWERS[name] = reviewer


def available() -> list[str]:
    with _REVIEWERS_LOCK:
        return sorted(_REVIEWERS)


def get(name: str | None) -> Reviewer:
    selected = name or "noop"
    with _REVIEWERS_LOCK:
        return _REVIEWERS.get(selected, _REVIEWERS["noop"])


def _resolve(name: str | None) -> tuple[Reviewer, bool]:
    selected = name or "noop"
    with _REVIEWERS_LOCK:
        reviewer = _REVIEWERS.get(selected)
        return (reviewer or _REVIEWERS["noop"], reviewer is not None)


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]


def _string_summary(value: str, *, kind: str) -> dict[str, Any]:
    return {"type": kind, "chars": len(value)}


def _redact_inline(text: str) -> str:
    redacted = redact_user_paths(text)
    redacted = _INLINE_SECRET.sub(lambda match: f"{match.group('prefix')}<redacted>", redacted)
    redacted = _URL_SECRET.sub(lambda match: f"{match.group('prefix')}<redacted>", redacted)
    return _URL_QUERY_VALUE.sub(lambda match: f"{match.group('prefix')}=<redacted>", redacted)


def _safe_identifier(value: str) -> str:
    return safe_identifier(value)


def _safe_field_name(value: Any) -> str:
    text = str(value)
    if _SENSITIVE_KEY.search(text):
        return "sensitive-field"
    if _CONTENT_KEY.search(text):
        return "content-field"
    if _PATH_KEY.search(text):
        return "path-field"
    if text in _SAFE_METADATA_FIELDS:
        return text
    return f"field:{_digest(text)}"


def _enum_summary(value: str) -> dict[str, Any]:
    shown = value.strip()
    if shown.lower() in _SAFE_ENUM_VALUES:
        shown = shown.lower()
    else:
        shown = f"unknown:{_digest(shown)}"
    return {"type": "enum", "value": shown, "chars": len(value)}


def _url_summary(value: str) -> dict[str, Any]:
    """只保留 URL 结构，不把主机、路径、查询值交给外部 reviewer。"""
    try:
        parsed = urlsplit(value)
        host = parsed.hostname or ""
        if not parsed.scheme or not host:
            raise ValueError
        try:
            address = ipaddress.ip_address(host)
            if address.is_loopback:
                host_scope = "loopback"
            elif address.is_private or address.is_link_local:
                host_scope = "private-address"
            else:
                host_scope = "public-address"
        except ValueError:
            lowered = host.lower().rstrip(".")
            if lowered == "localhost" or lowered.endswith(".localhost"):
                host_scope = "loopback-name"
            elif "." not in lowered:
                host_scope = "single-label-name"
            else:
                host_scope = "domain-name"
        return {
            "type": "url",
            "scheme": parsed.scheme.lower(),
            "host_scope": host_scope,
            "host_chars": len(host),
            "host_labels": len([part for part in host.split(".") if part]),
            "port": parsed.port,
            "path_chars": len(parsed.path),
            "has_query": bool(parsed.query),
        }
    except (TypeError, ValueError):
        return {"type": "url-string", "chars": len(value)}


def _path_summary(value: str, *, cwd: str | None = None) -> dict[str, Any]:
    text = value.strip()
    normalized = posixpath.normpath(text) if text else "."
    absolute = posixpath.isabs(text)
    parts = [part for part in normalized.split("/") if part not in {"", "."}]
    traversal = any(part == ".." for part in text.split("/"))
    if text.startswith("~"):
        scope = "home-relative"
    elif not absolute:
        scope = "relative-traversal" if traversal else "relative"
    elif cwd and posixpath.isabs(cwd):
        normalized_cwd = posixpath.normpath(cwd)
        try:
            inside = posixpath.commonpath([normalized, normalized_cwd]) == normalized_cwd
        except ValueError:
            inside = False
        scope = "cwd" if inside else "outside-cwd"
    else:
        scope = "absolute"
    return {
        "type": "path-string",
        "scope": scope,
        "absolute": absolute,
        "chars": len(value),
        "segments": len(parts),
        "traversal": traversal,
        "has_glob": any(char in text for char in "*?["),
    }


def _sanitize(value: Any, key: str = "", depth: int = 0, *, cwd: str | None = None) -> Any:
    """保留字段形状与长度，不保留命令、补丁、凭据正文。"""
    if depth > _MAX_DEPTH:
        return {"type": type(value).__name__, "truncated": True}
    if isinstance(value, str):
        if _SENSITIVE_KEY.search(key):
            return _string_summary(value, kind="redacted-string")
        if _CONTENT_KEY.search(key):
            return _string_summary(value, kind="content-string")
        if key.lower() in _SAFE_ENUM_FIELDS:
            return _enum_summary(value)
        if key.lower() in _URL_FIELDS:
            return _url_summary(value)
        if _PATH_KEY.search(key):
            return _path_summary(value, cwd=cwd)
        return _string_summary(value, kind="string")
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for raw_key, item in islice(value.items(), _MAX_ITEMS):
            key_name = _safe_field_name(raw_key)
            if key_name in out:
                suffix = 2
                while f"{key_name}#{suffix}" in out:
                    suffix += 1
                key_name = f"{key_name}#{suffix}"
            out[key_name] = _sanitize(item, str(raw_key), depth + 1, cwd=cwd)
        if len(value) > _MAX_ITEMS:
            out["__truncated_keys__"] = len(value) - _MAX_ITEMS
        return out
    if isinstance(value, (list, tuple)):
        out = [_sanitize(v, key, depth + 1, cwd=cwd) for v in islice(value, _MAX_ITEMS)]
        if len(value) > _MAX_ITEMS:
            out.append({"__truncated_items__": len(value) - _MAX_ITEMS})
        return out
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        if key.lower() in _SAFE_NUMERIC_FIELDS:
            return value
        shown = str(value)
        return {
            "type": "number",
            "chars": len(shown),
            "negative": shown.startswith("-"),
        }
    return {"type": type(value).__name__}


def build_request(request: NormalizedRequest) -> ReviewRequest:
    raw = request.raw_input if isinstance(request.raw_input, dict) else {}
    payload = {
        "tool": _safe_identifier(request.tool),
        "input_keys": [_safe_field_name(key) for key in (request.input_keys or raw.keys())],
        "input": _sanitize(raw, cwd=request.cwd),
    }
    return ReviewRequest(
        adapter=request.adapter,
        event=request.event,
        tool=_safe_identifier(request.tool),
        cwd=_path_summary(request.cwd),
        classification=request.classification,
        payload=payload,
        provenance=tuple(request.provenance) + ("safety-guard", "unknown-review"),
    )


def _coerce(raw: Any, reviewer_name: str) -> ReviewResult:
    if isinstance(raw, ReviewResult):
        if raw.decision not in {"allow", "deny", "ask", "abstain"}:
            return ReviewResult(reviewer=reviewer_name, status="abstain", error_type="invalid_decision")
        return ReviewResult(
            decision=raw.decision,
            reason=raw.reason,
            reviewer=reviewer_name,
            status=raw.decision,
            error_type=_safe_identifier(raw.error_type) if isinstance(raw.error_type, str) else None,
        )
    if isinstance(raw, str) and raw in {"allow", "deny", "ask", "abstain"}:
        return ReviewResult(decision=raw, reviewer=reviewer_name, status=raw)
    return ReviewResult(reviewer=reviewer_name, status="abstain", error_type="invalid_result")


def review_unknown(
    request: NormalizedRequest,
    cfg,
    reviewer: Reviewer | None = None,
) -> ReviewResult:
    """在受限线程与超时内执行 reviewer，任何异常都保持 abstain。"""
    if _DEPTH.get() > 0 or "unknown-review" in request.provenance:
        return ReviewResult(
            reviewer="recursion-guard",
            status="abstain",
            error_type="recursion",
            reason="检测到审查递归，未知工具保持默认放行",
        )

    configured_name = getattr(cfg, "unknown_reviewer", None)
    if reviewer is None:
        selected, configured = _resolve(configured_name)
        if not configured:
            return ReviewResult(
                reviewer=_safe_identifier(str(configured_name or "noop")),
                status="abstain",
                error_type="unavailable_reviewer",
                reason="配置的未知工具审查器不可用，按默认放行策略继续",
            )
    else:
        selected = reviewer
    name = _safe_identifier(str(getattr(selected, "name", "custom")))
    review_request = build_request(request)
    result_box: list[ReviewResult] = []
    error_box: list[BaseException] = []
    parent_depth = _DEPTH.get()

    # Capture the semaphore for this invocation.  A test or embedding process may
    # replace the module-level limit while a timed-out reviewer is still running;
    # release must go back to the slot that was actually acquired.
    slots = _REVIEW_SLOTS
    if not slots.acquire(blocking=False):
        return ReviewResult(
            reviewer=name,
            status="abstain",
            error_type="capacity",
            reason="未知工具审查并发已达上限，按默认放行策略继续",
        )

    def invoke() -> None:
        token = _DEPTH.set(parent_depth + 1)
        try:
            result_box.append(_coerce(selected.review(review_request), name))
        except BaseException as exc:  # reviewer is an extension boundary
            error_box.append(exc)
        finally:
            _DEPTH.reset(token)
            slots.release()

    thread = threading.Thread(target=invoke, name="safety-guard-review", daemon=True)
    try:
        thread.start()
    except BaseException:
        slots.release()
        return ReviewResult(
            reviewer=name,
            status="abstain",
            error_type="start_error",
            reason="未知工具审查无法启动，按默认放行策略继续",
        )
    timeout_ms = getattr(cfg, "reviewer_timeout_ms", 250)
    try:
        timeout_s = max(0.001, min(float(timeout_ms) / 1000.0, 10.0))
    except (TypeError, ValueError):
        timeout_s = 0.25
    thread.join(timeout_s)
    if thread.is_alive():
        return ReviewResult(
            reviewer=name,
            status="abstain",
            error_type="timeout",
            reason="未知工具审查超时，按默认放行策略继续",
        )
    if error_box or not result_box:
        return ReviewResult(
            reviewer=name,
            status="abstain",
            error_type="error",
            reason="未知工具审查失败，按默认放行策略继续",
        )
    result = result_box[0]
    reason = result.reason
    if isinstance(reason, str):
        reason = _redact_inline(reason)[:512]
    return ReviewResult(
        decision=result.decision,
        reason=reason,
        reviewer=result.reviewer or name,
        status=result.status or result.decision,
        error_type=result.error_type,
    )
