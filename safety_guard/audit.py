"""审计日志——按天分文件 + 自动轮转清理。

文件：<install_root>/audit/audit-YYYY-MM-DD.jsonl（默认随安装目录走，可通过 toml 覆盖）
轮转策略：
  - retention_days：超期文件按 mtime 删
  - max_file_mb：当日单文件超阈值切到 -NN.jsonl
  - max_total_mb：所有文件总和超阈值按 mtime 删老的
去抖：stamp 文件 .last-pruned 记录上次清理时间，距今 < 1h 跳过。

字段（优化拦截用）：
  - adapter：平台适配器名（唯一平台标识；历史日志可能只有 harness）
  - engine_decision：规则引擎/reviewer 结论 allow|ask|deny|abstain
  - rendered_decision：写入平台后的对外结论
  - decision：兼容旧字段；等于 engine_decision，dry_run 时加 dry-run- 前缀
  - cmd_digest/cmd_chars/cmd_lines：默认保留的元数据
  - cmd_body/cmd_preview：仅 audit_include_body=true 时写入
  - hook_event：规范化事件名（若有）
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import re
import stat
import time
from pathlib import Path
from typing import Any

from . import config as _cfg
from .helpers import safe_identifier

_STAMP = ".last-pruned"
_PRUNE_INTERVAL_S = 3600
# 合成流量（pytest / --regression / 手工回放）置 1，避免污染生产审计。
AUDIT_DISABLE_ENV = "SAFETY_GUARD_NO_AUDIT"

# 完整正文上限：超过则只留 preview，避免单条 jsonl 膨胀与密钥大段落盘。
FULL_BODY_CHARS = 8192
# 截断预览长度（保留换行，不再压成单行）
PREVIEW_CHARS = 4096
TRUNCATION_SUFFIX = "…"
REDACTED_SECRET = "<redacted>"
_AUDIT_DIR_MODE = 0o700
_AUDIT_FILE_MODE = 0o600

_SENSITIVE_NAME = (
    r"(?:(?:[A-Za-z][A-Za-z0-9]*[_-])*(?:api[_-]?key|access[_-]?(?:token|key)|"
    r"auth[_-]?token|bearer[_-]?token|client[_-]?secret|password|passwd|pwd|"
    r"private[_-]?key|secret|token|authorization|credential))"
)
_ASSIGNMENT_SECRET_RE = re.compile(
    rf"(?i)(?P<prefix>\b{_SENSITIVE_NAME}\b\s*=\s*)"
    r"(?P<quote>['\"]?)(?P<value>[^\s'\";|&]+)(?P=quote)"
)
_OPTION_SECRET_RE = re.compile(
    rf"(?i)(?P<prefix>--{_SENSITIVE_NAME}(?:=|\s+))"
    r"(?P<quote>['\"]?)(?P<value>[^\s'\";|&]+)(?P=quote)"
)
_QUOTED_ASSIGNMENT_SECRET_RE = re.compile(
    rf"(?i)(?P<prefix>\b{_SENSITIVE_NAME}\b\s*=\s*)"
    r"(?P<quote>['\"])(?P<value>(?:\\.|[^'\"\\])*)(?P=quote)"
)
_QUOTED_OPTION_SECRET_RE = re.compile(
    rf"(?i)(?P<prefix>--{_SENSITIVE_NAME}(?:=|\s+))"
    r"(?P<quote>['\"])(?P<value>(?:\\.|[^'\"\\])*)(?P=quote)"
)
_AUTH_HEADER_RE = re.compile(
    r"(?i)(?P<prefix>\b(?:authorization|proxy-authorization)\s*:\s*)"
    r"(?P<scheme>bearer|basic)\s+(?P<value>[^\s'\"]+)"
)
_JSON_DOUBLE_QUOTED_SECRET_RE = re.compile(
    rf'(?i)(?P<prefix>"{_SENSITIVE_NAME}"\s*:\s*")'
    r'(?P<value>(?:\\.|[^"\\])*)(?P<suffix>")'
)
_JSON_SINGLE_QUOTED_SECRET_RE = re.compile(
    rf"(?i)(?P<prefix>'{_SENSITIVE_NAME}'\s*:\s*')"
    r"(?P<value>(?:\\.|[^'\\])*)(?P<suffix>')"
)


def disabled() -> bool:
    return os.environ.get(AUDIT_DISABLE_ENV) == "1"


def _today_path(audit_dir: Path, cfg: _cfg.Config) -> Path:
    today = _dt.date.today().isoformat()
    candidate = audit_dir / f"audit-{today}.jsonl"
    if not candidate.exists():
        return candidate
    return _rolled_path_if_needed(candidate, audit_dir, today, cfg)


def _rolled_path_if_needed(base: Path, audit_dir: Path, today: str, cfg: _cfg.Config) -> Path:
    cap = cfg.audit_max_file_mb * 1024 * 1024
    try:
        if base.stat().st_size < cap:
            return base
    except OSError:
        return base
    n = 1
    while True:
        rolled = audit_dir / f"audit-{today}-{n:02d}.jsonl"
        try:
            if not rolled.exists() or rolled.stat().st_size < cap:
                return rolled
        except OSError:
            return rolled
        n += 1
        if n > 999:
            return rolled


def _maybe_prune(audit_dir: Path, cfg: _cfg.Config) -> None:
    stamp = audit_dir / _STAMP
    now = time.time()
    try:
        stamp_stat = stamp.lstat()
        if (
            stat.S_ISREG(stamp_stat.st_mode)
            and stamp_stat.st_nlink == 1
            and (now - stamp_stat.st_mtime) < _PRUNE_INTERVAL_S
        ):
            return
    except OSError:
        pass

    cutoff = now - cfg.audit_retention_days * 86400
    files: list[Path] = sorted(audit_dir.glob("audit-*.jsonl"))
    for f in list(files):
        try:
            if f.stat().st_mtime < cutoff:
                f.unlink(missing_ok=True)
                files.remove(f)
        except OSError:
            continue

    total_cap = cfg.audit_max_total_mb * 1024 * 1024
    files.sort(key=lambda p: p.stat().st_mtime if p.exists() else 0)
    while files:
        total = sum(f.stat().st_size for f in files if f.exists())
        if total <= total_cap:
            break
        oldest = files.pop(0)
        try:
            oldest.unlink(missing_ok=True)
        except OSError:
            pass

    _touch_private_stamp(stamp)


def _digest(cmd: str) -> str:
    return "sha256:" + hashlib.sha256(cmd.encode("utf-8", errors="replace")).hexdigest()[:16]


def _redact_secrets(text: str) -> str:
    def replace_assignment(match: re.Match[str]) -> str:
        quote = match.group("quote") or ""
        return f"{match.group('prefix')}{quote}{REDACTED_SECRET}{quote}"

    def replace_quoted_secret(match: re.Match[str]) -> str:
        return f"{match.group('prefix')}{REDACTED_SECRET}{match.group('suffix')}"

    redacted = _JSON_DOUBLE_QUOTED_SECRET_RE.sub(replace_quoted_secret, text)
    redacted = _JSON_SINGLE_QUOTED_SECRET_RE.sub(replace_quoted_secret, redacted)
    redacted = _QUOTED_ASSIGNMENT_SECRET_RE.sub(replace_assignment, redacted)
    redacted = _QUOTED_OPTION_SECRET_RE.sub(replace_assignment, redacted)
    redacted = _ASSIGNMENT_SECRET_RE.sub(replace_assignment, redacted)
    redacted = _OPTION_SECRET_RE.sub(replace_assignment, redacted)
    return _AUTH_HEADER_RE.sub(
        lambda match: f"{match.group('prefix')}{match.group('scheme')} {REDACTED_SECRET}",
        redacted,
    )


def _redact(text: str) -> str:
    from .helpers import redact_user_paths
    return _redact_secrets(redact_user_paths(text or ""))


def _ensure_private_dir(path: Path) -> bool:
    try:
        path.mkdir(mode=_AUDIT_DIR_MODE, parents=True, exist_ok=True)
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
    except OSError:
        return False
    try:
        current = os.fstat(fd)
        if not stat.S_ISDIR(current.st_mode):
            return False
        os.fchmod(fd, _AUDIT_DIR_MODE)
        return True
    except OSError:
        return False
    finally:
        os.close(fd)


def _touch_private_stamp(path: Path) -> None:
    flags = os.O_WRONLY | os.O_CREAT
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, _AUDIT_FILE_MODE)
    except OSError:
        return
    try:
        current = os.fstat(fd)
        if not stat.S_ISREG(current.st_mode) or current.st_nlink != 1:
            return
        os.fchmod(fd, _AUDIT_FILE_MODE)
        os.utime(fd, None)
    except (OSError, TypeError, ValueError):
        return
    finally:
        os.close(fd)


def _append_private(path: Path, line: str) -> None:
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, _AUDIT_FILE_MODE)
    try:
        current = os.fstat(fd)
        if not stat.S_ISREG(current.st_mode) or current.st_nlink != 1:
            raise OSError("audit target must be a single-link regular file")
        os.fchmod(fd, _AUDIT_FILE_MODE)
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            fd = -1
            handle.write(line)
    finally:
        if fd >= 0:
            os.close(fd)


def _cmd_fields(raw_input: str, *, include_body: bool = False) -> dict[str, Any]:
    """构造命令元数据；正文必须显式 opt-in。"""
    raw = raw_input if isinstance(raw_input, str) else ""
    redacted = _redact(raw)
    # digest 对脱敏后正文：回放与去重都基于落盘可见内容，避免同一命令因用户名分叉
    fields: dict[str, Any] = {
        "cmd_digest": _digest(redacted),
        "cmd_chars": len(raw),
        "cmd_lines": raw.count("\n") + 1 if raw else 0,
    }
    if not include_body:
        fields["cmd_body_stored"] = False
        return fields
    fields["cmd_body_stored"] = True
    if len(redacted) <= FULL_BODY_CHARS:
        fields["cmd_body"] = redacted
        fields["cmd_truncated"] = False
        # preview 与 body 一致（短），便于旧工具只读 preview
        fields["cmd_preview"] = redacted
    else:
        fields["cmd_truncated"] = True
        preview = redacted if len(redacted) <= PREVIEW_CHARS else redacted[:PREVIEW_CHARS] + TRUNCATION_SUFFIX
        fields["cmd_preview"] = preview
        # 不写 cmd_body，避免超大行
    return fields


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return _redact(value)
    if isinstance(value, list):
        return [_redact_value(v) for v in value]
    if isinstance(value, dict):
        return {k: _redact_value(v) for k, v in value.items()}
    return value


def _redact_matches(matches: list[dict], *, include_details: bool) -> list[dict]:
    out: list[dict] = []
    for m in matches:
        mm = {key: m[key] for key in ("id", "severity") if key in m}
        if not include_details:
            out.append(mm)
            continue
        mm = dict(m)
        if isinstance(mm.get("reason"), str):
            mm["reason"] = _redact(mm["reason"])
        if isinstance(mm.get("extra"), dict):
            mm["extra"] = _redact_value(mm["extra"])
        out.append(mm)
    return out


def infer_rendered_decision(
    output: dict[str, Any] | None,
    *,
    engine_decision: str,
    adapter: str | None = None,
    hook_event: str | None = None,
) -> str:
    """从 adapter.render 输出推断平台侧最终决策。"""
    if not output:
        # Grok 官方协议将退出 0 + 无输出定义为 allow。Claude/Codex
        # 则只表示 Hook 不作决定，不应在审计中伪造显式授权。
        if adapter == "grok":
            return "allow"
        if adapter in {"claude", "codex-pretool", "codex-permission"} or hook_event == "PermissionRequest":
            return "abstain"
        # 保留未标注 adapter 的旧调用语义。
        return "allow"
    top = output.get("decision")
    if top in ("allow", "deny", "ask"):
        return str(top)
    hso = output.get("hookSpecificOutput")
    if isinstance(hso, dict):
        perm = hso.get("permissionDecision")
        if perm in ("allow", "deny", "ask"):
            return str(perm)
        dec = hso.get("decision")
        if isinstance(dec, dict):
            behavior = dec.get("behavior")
            if behavior in ("allow", "deny", "ask"):
                return str(behavior)
    # 旧 Codex soft-ask
    if output.get("systemMessage") and engine_decision == "ask":
        return "ask"
    # 有输出但认不出时，保守跟引擎
    if engine_decision in ("allow", "ask", "deny", "abstain"):
        return engine_decision
    return "allow"


def write(
    *,
    tool: str,
    cwd: str,
    raw_input: str,
    matches: list[dict],
    decision: str,
    adapter: str = "claude",
    config: _cfg.Config | None = None,
    error_type: str | None = None,
    error_detail: str | None = None,
    engine_decision: str | None = None,
    rendered_decision: str | None = None,
    hook_event: str | None = None,
    dry_run: bool | None = None,
    classification: str | None = None,
    review: dict[str, Any] | None = None,
) -> None:
    """写入一条审计。decision 保持旧语义；engine/rendered 为优化用显式字段。"""
    if disabled():
        return
    cfg = config or _cfg.load()
    audit_dir = cfg.audit_dir
    if not _ensure_private_dir(audit_dir):
        return

    _maybe_prune(audit_dir, cfg)

    eng = engine_decision or decision.removeprefix("dry-run-")
    if eng not in ("allow", "ask", "deny", "abstain"):
        eng = decision.removeprefix("dry-run-") if decision else "allow"
    rendered = rendered_decision if rendered_decision is not None else eng
    is_dry = bool(cfg.dry_run if dry_run is None else dry_run)
    # 兼容字段：dry_run 时加前缀，便于旧统计脚本
    compat = f"dry-run-{eng}" if is_dry and not str(decision).startswith("dry-run-") else decision
    if is_dry and engine_decision and not str(decision).startswith("dry-run-"):
        compat = f"dry-run-{eng}"

    record: dict[str, Any] = {
        "ts": _dt.datetime.now(_dt.timezone.utc).astimezone().isoformat(timespec="seconds"),
        "adapter": adapter or "unknown",
        "tool": safe_identifier(tool),
        "cwd": _redact(cwd),
        **_cmd_fields(raw_input, include_body=cfg.audit_include_body),
        "matches": _redact_matches(matches, include_details=cfg.audit_include_body),
        "match_details_stored": cfg.audit_include_body,
        "decision": compat,
        "engine_decision": eng,
        "rendered_decision": rendered,
    }
    if cfg.load_error:
        record["config_load_error"] = cfg.load_error
    if hook_event:
        record["hook_event"] = safe_identifier(hook_event)
    if classification:
        record["classification"] = classification
    if review:
        record["review"] = _redact_value(review)
    if is_dry:
        record["dry_run"] = True
    if error_type:
        record["error_type"] = error_type
    if error_detail and cfg.audit_include_body:
        record["error_detail"] = _redact(error_detail)

    line = json.dumps(record, ensure_ascii=False) + "\n"
    target = _today_path(audit_dir, cfg)
    try:
        _append_private(target, line)
    except OSError:
        return


def record_evaluation(
    *,
    adapter: str,
    tool: str,
    cwd: str,
    raw_input: str,
    matches: list[dict],
    engine_decision: str,
    rendered_output: dict[str, Any] | None,
    config: _cfg.Config,
    hook_event: str | None = None,
    error_type: str | None = None,
    error_detail: str | None = None,
    classification: str | None = None,
    review: dict[str, Any] | None = None,
) -> None:
    """evaluate + render 之后的统一落盘入口。"""
    eng = engine_decision
    if config.dry_run:
        # dry_run：引擎结论保留，平台侧不拦截；PermissionRequest 的空输出仍是
        # abstain（保留 Codex 原生审批），而非伪造显式 allow。
        rendered = infer_rendered_decision(
            rendered_output,
            engine_decision="allow",
            adapter=adapter,
            hook_event=hook_event,
        )
        compat = f"dry-run-{eng}"
    else:
        rendered = infer_rendered_decision(
            rendered_output,
            engine_decision=eng,
            adapter=adapter,
            hook_event=hook_event,
        )
        compat = eng
    write(
        tool=tool,
        cwd=cwd,
        raw_input=raw_input,
        matches=matches,
        decision=compat,
        adapter=adapter,
        config=config,
        engine_decision=eng,
        rendered_decision=rendered,
        hook_event=hook_event,
        dry_run=config.dry_run,
        error_type=error_type,
        error_detail=error_detail,
        classification=classification,
        review=review,
    )
