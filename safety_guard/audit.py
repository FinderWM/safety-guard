"""审计日志——按天分文件 + 自动轮转清理。

文件：<install_root>/audit/audit-YYYY-MM-DD.jsonl（默认随安装目录走，可通过 toml 覆盖）
轮转策略：
  - retention_days：超期文件按 mtime 删
  - max_file_mb：当日单文件超阈值切到 -NN.jsonl
  - max_total_mb：所有文件总和超阈值按 mtime 删老的
去抖：stamp 文件 .last-pruned 记录上次清理时间，距今 < 1h 跳过。

字段（优化拦截用）：
  - adapter：平台适配器名（唯一平台标识；历史日志可能只有 harness）
  - engine_decision：规则引擎结论 allow|ask|deny（dry_run 时仍是真实结论）
  - rendered_decision：写入平台后的对外结论（Grok 会把 ask 升 deny）
  - decision：兼容旧字段；等于 engine_decision，dry_run 时加 dry-run- 前缀
  - cmd_body：脱敏后的完整输入（不超过 FULL_BODY_CHARS 时写入，供精确回放）
  - cmd_truncated：超长时 true，仅有 cmd_preview
  - cmd_preview：短预览（保留换行；超长截断），便于人读与 grep
  - hook_event：规范化事件名（若有）
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

from . import config as _cfg

_STAMP = ".last-pruned"
_PRUNE_INTERVAL_S = 3600
# 合成流量（pytest / --regression / 手工回放）置 1，避免污染生产审计。
AUDIT_DISABLE_ENV = "SAFETY_GUARD_NO_AUDIT"

# 完整正文上限：超过则只留 preview，避免单条 jsonl 膨胀与密钥大段落盘。
FULL_BODY_CHARS = 8192
# 截断预览长度（保留换行，不再压成单行）
PREVIEW_CHARS = 4096
TRUNCATION_SUFFIX = "…"


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
        if stamp.exists() and (now - stamp.stat().st_mtime) < _PRUNE_INTERVAL_S:
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

    try:
        stamp.touch()
    except OSError:
        pass


def _digest(cmd: str) -> str:
    return "sha256:" + hashlib.sha256(cmd.encode("utf-8", errors="replace")).hexdigest()[:16]


def _redact(text: str) -> str:
    from .helpers import redact_user_paths
    return redact_user_paths(text or "")


def _cmd_fields(raw_input: str) -> dict[str, Any]:
    """构造命令正文相关字段：短命令存全文，长命令可截断回放。"""
    raw = raw_input if isinstance(raw_input, str) else ""
    redacted = _redact(raw)
    # digest 对脱敏后正文：回放与去重都基于落盘可见内容，避免同一命令因用户名分叉
    fields: dict[str, Any] = {
        "cmd_digest": _digest(redacted),
        "cmd_chars": len(raw),
        "cmd_lines": raw.count("\n") + 1 if raw else 0,
    }
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


def _redact_matches(matches: list[dict]) -> list[dict]:
    out: list[dict] = []
    for m in matches:
        mm = dict(m)
        if isinstance(mm.get("reason"), str):
            mm["reason"] = _redact(mm["reason"])
        out.append(mm)
    return out


def infer_rendered_decision(output: dict[str, Any] | None, *, engine_decision: str) -> str:
    """从 adapter.render 输出推断平台侧最终决策。"""
    if not output:
        # Claude/Codex allow → {} ；也兼容「无输出即放行」
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
    if engine_decision in ("allow", "ask", "deny"):
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
) -> None:
    """写入一条审计。decision 保持旧语义；engine/rendered 为优化用显式字段。"""
    if disabled():
        return
    cfg = config or _cfg.load()
    audit_dir = cfg.audit_dir
    try:
        audit_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return

    _maybe_prune(audit_dir, cfg)

    eng = engine_decision or decision.removeprefix("dry-run-")
    if eng not in ("allow", "ask", "deny"):
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
        "tool": tool,
        "cwd": _redact(cwd),
        **_cmd_fields(raw_input),
        "matches": _redact_matches(matches),
        "decision": compat,
        "engine_decision": eng,
        "rendered_decision": rendered,
    }
    if hook_event:
        record["hook_event"] = hook_event
    if is_dry:
        record["dry_run"] = True
    if error_type:
        record["error_type"] = error_type
    if error_detail:
        record["error_detail"] = _redact(error_detail)

    line = json.dumps(record, ensure_ascii=False) + "\n"
    target = _today_path(audit_dir, cfg)
    try:
        with target.open("a", encoding="utf-8") as f:
            f.write(line)
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
) -> None:
    """evaluate + render 之后的统一落盘入口。"""
    eng = engine_decision
    if config.dry_run:
        # dry_run：引擎结论保留，平台侧视为 allow
        rendered = "allow"
        compat = f"dry-run-{eng}"
    else:
        rendered = infer_rendered_decision(rendered_output, engine_decision=eng)
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
    )
