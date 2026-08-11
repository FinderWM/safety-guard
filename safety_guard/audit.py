"""审计日志——按天分文件 + 自动轮转清理。

文件：<install_root>/audit/audit-YYYY-MM-DD.jsonl（默认随安装目录走，可通过 toml 覆盖）
轮转策略：
  - retention_days：超期文件按 mtime 删
  - max_file_mb：当日单文件超阈值切到 -NN.jsonl
  - max_total_mb：所有文件总和超阈值按 mtime 删老的
去抖：stamp 文件 .last-pruned 记录上次清理时间，距今 < 1h 跳过。
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import time
from pathlib import Path

from . import config as _cfg

_STAMP = ".last-pruned"
_PRUNE_INTERVAL_S = 3600
# 合成流量（pytest / --regression / 手工回放）置 1，避免污染生产审计。
# 不加这道闸的后果实测过：一周 12508 条审计里 76% 是 fixture 命令（`rm -rf /`、
# `git push --force origin main` …），统计彻底失真，还会顺着 retention 把真实
# 历史挤出保留窗口。
AUDIT_DISABLE_ENV = "SAFETY_GUARD_NO_AUDIT"


def disabled() -> bool:
    return os.environ.get(AUDIT_DISABLE_ENV) == "1"


def _today_path(audit_dir: Path, cfg: _cfg.Config) -> Path:
    today = _dt.date.today().isoformat()
    candidate = audit_dir / f"audit-{today}.jsonl"
    if not candidate.exists():
        return candidate
    # 单文件超阈值时切到 -NN
    return _rolled_path_if_needed(candidate, audit_dir, today, cfg)


def _rolled_path_if_needed(base: Path, audit_dir: Path, today: str, cfg: _cfg.Config) -> Path:
    cap = cfg.audit_max_file_mb * 1024 * 1024
    try:
        if base.stat().st_size < cap:
            return base
    except OSError:
        return base
    # 找到当日最大编号
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
            return rolled  # 兜底，几乎不可能到这


def _maybe_prune(audit_dir: Path, cfg: _cfg.Config) -> None:
    stamp = audit_dir / _STAMP
    now = time.time()
    try:
        if stamp.exists() and (now - stamp.stat().st_mtime) < _PRUNE_INTERVAL_S:
            return
    except OSError:
        pass

    # 按 retention 删超期
    cutoff = now - cfg.audit_retention_days * 86400
    files: list[Path] = sorted(audit_dir.glob("audit-*.jsonl"))
    for f in list(files):
        try:
            if f.stat().st_mtime < cutoff:
                f.unlink(missing_ok=True)
                files.remove(f)
        except OSError:
            continue

    # 按总量删（老到新）
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


def _preview(cmd: str, n: int = 500) -> str:
    s = cmd.replace("\n", " ").strip()
    return s if len(s) <= n else s[:n] + "…"


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
) -> None:
    if disabled():
        return
    cfg = config or _cfg.load()
    audit_dir = cfg.audit_dir
    try:
        audit_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return  # 写不进去就放弃，不要让审计失败拖垮主流程

    _maybe_prune(audit_dir, cfg)

    record = {
        "ts": _dt.datetime.now(_dt.timezone.utc).astimezone().isoformat(timespec="seconds"),
        "adapter": adapter,
        "tool": tool,
        "cwd": cwd,
        "cmd_digest": _digest(raw_input),
        "cmd_chars": len(raw_input),
        "cmd_lines": raw_input.count("\n") + 1 if raw_input else 0,
        "cmd_preview": _preview(raw_input),
        "matches": matches,
        "decision": decision,
    }
    if error_type:
        record["error_type"] = error_type
    if error_detail:
        record["error_detail"] = error_detail
    line = json.dumps(record, ensure_ascii=False) + "\n"

    target = _today_path(audit_dir, cfg)
    try:
        with target.open("a", encoding="utf-8") as f:
            f.write(line)
    except OSError:
        return
