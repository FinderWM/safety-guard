"""审计日志回放——用真实历史命令建立决策基线并做前后对比。

现有 `--regression` 只有 76 条合成用例，无法回答「改一条规则会让多少真实命令
从 allow 变 ask」。本工具直接消费 audit/*.jsonl，把每条记录连同它自己的 cwd
重放进 engine，得到可对比的决策快照。

用法：
    # 建立基线（改动前）
    python3 tools/replay.py --save /tmp/before.json

    # 改动后对比
    python3 tools/replay.py --compare /tmp/before.json

    # 只看某条规则的影响
    python3 tools/replay.py --compare /tmp/before.json --rule bash-env-subversion

保真度限制（会在报告里显式说明，不静默丢弃）：
  - 优先 cmd_body（完整脱敏正文）；旧日志或超长命令只有 cmd_preview
  - cmd_truncated=true / preview 以 `…` 结尾的样本无法逐字复现，默认跳过
  - 存在性依赖规则（*-overwrite-existing）依赖当时的磁盘状态，现已漂移
  - 对比时优先 engine_decision（兼容旧 decision / dry-run-* 前缀）
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

# 必须在导入 safety_guard 之前设置：回放 16k 条会把审计日志翻倍
os.environ["SAFETY_GUARD_NO_AUDIT"] = "1"
os.environ.setdefault("SAFETY_GUARD_IGNORE_DISABLED_RULES", "1")

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from safety_guard import engine  # noqa: E402
from safety_guard.adapters.registry import get  # noqa: E402
from safety_guard.config import load as load_config  # noqa: E402

from safety_guard.audit import TRUNCATION_SUFFIX  # noqa: E402

# 决策依赖当时磁盘状态，回放必然分歧——默认排除，--include-existence 可保留
EXISTENCE_DEPENDENT = frozenset({
    "bash-redirect-overwrite-existing",
    "bash-tee-overwrite-existing",
    "bash-cp-mv-overwrite-existing",
    "file-overwrite-existing",
})


def _fixture_commands() -> set[str]:
    """regression fixture 里的命令：自测污染，不算真实历史。"""
    path = _ROOT / "tests" / "fixtures" / "regression_commands.txt"
    out: set[str] = set()
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "|" not in line:
            continue
        out.add(line.split("|", 1)[1].strip())
    return out



def _command_text(rec: dict) -> str:
    """回放用命令：优先完整 cmd_body，回退 cmd_preview。"""
    body = rec.get("cmd_body")
    if isinstance(body, str) and body:
        return body
    prev = rec.get("cmd_preview") or ""
    return prev if isinstance(prev, str) else ""


def _recorded_decision(rec: dict) -> str:
    """对比基线用的引擎决策（去掉 dry-run- 前缀）。"""
    eng = rec.get("engine_decision")
    if eng in ("allow", "ask", "deny"):
        return eng
    d = str(rec.get("decision") or "?")
    return d.removeprefix("dry-run-")


def load_records(audit_dir: Path, *, include_fixture: bool = False) -> tuple[list[dict], Counter]:
    """读取审计记录，返回 (可回放记录, 跳过原因统计)。"""
    fixture = set() if include_fixture else _fixture_commands()
    skipped: Counter = Counter()
    records: list[dict] = []

    for path in sorted(audit_dir.glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                skipped["json-decode-error"] += 1
                continue
            if rec.get("tool") != "Bash":
                skipped[f"non-bash-tool:{rec.get('tool')}"] += 1
                continue
            cmd = _command_text(rec)
            if not cmd:
                skipped["empty-preview"] += 1
                continue
            if rec.get("cmd_truncated") or cmd.endswith(TRUNCATION_SUFFIX):
                skipped["truncated-preview"] += 1
                continue
            if cmd in fixture:
                skipped["fixture-contamination"] += 1
                continue
            if not rec.get("cwd"):
                skipped["missing-cwd"] += 1
                continue
            # 规范化供回放使用的命令字段
            rec = {**rec, "_replay_cmd": cmd}
            records.append(rec)
    return records, skipped


def _stdin_for(rec: dict) -> dict:
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": rec.get("_replay_cmd") or _command_text(rec)},
        "cwd": rec["cwd"],
    }


def evaluate_all(records: list[dict]) -> list[dict]:
    """重放每条记录，返回 {cmd, cwd, recorded, replayed, rules}。"""
    cfg = load_config()
    adapter = get("claude")
    out: list[dict] = []
    for rec in records:
        try:
            request = adapter.parse(_stdin_for(rec))
            result = engine.evaluate(request, cfg)
            decision = result.decision
            reason = result.reason or ""
        except Exception as e:  # 回放本身不该炸，但炸了要看得见
            decision = f"ERROR:{type(e).__name__}"
            reason = str(e)
        out.append({
            "cmd": rec.get("_replay_cmd") or _command_text(rec),
            "cwd": rec["cwd"],
            "recorded": _recorded_decision(rec),
            "recorded_rendered": rec.get("rendered_decision"),
            "replayed": decision,
            "adapter": rec.get("adapter") or rec.get("harness"),
            "rules": sorted({m.get("id", "") for m in (rec.get("matches") or [])}),
            "reason": reason[:400],
        })
    return out
# --- 报告与对比 -------------------------------------------------------------

_RANK = {"allow": 0, "ask": 1, "deny": 2}


def _severity_delta(before: str, after: str) -> str:
    """变严 / 变松 / 横向变化。未知决策（ERROR:*）一律当异常。"""
    b, a = _RANK.get(before), _RANK.get(after)
    if b is None or a is None:
        return "error"
    if a > b:
        return "tightened"
    if a < b:
        return "loosened"
    return "same"


def summarize(rows: list[dict], skipped: Counter, *, label: str) -> None:
    print(f"\n=== {label} ===")
    print(f"可回放记录: {len(rows)}")
    dist = Counter(r["replayed"] for r in rows)
    for k, v in dist.most_common():
        pct = 100 * v / max(len(rows), 1)
        print(f"  {k:24s} {v:6d}  {pct:5.2f}%")

    drift = [r for r in rows if r["recorded"] != r["replayed"]]
    existence = [r for r in drift if set(r["rules"]) & EXISTENCE_DEPENDENT]
    real = [r for r in drift if r not in existence]
    print(f"\n与历史记录不一致: {len(drift)}"
          f"（其中存在性依赖 {len(existence)}，其余 {len(real)}）")

    if skipped:
        print("\n跳过的记录:")
        for k, v in skipped.most_common():
            print(f"  {k:28s} {v:6d}")


def compare(baseline_path: Path, rows: list[dict], *, rule_filter: str | None) -> int:
    """与基线对比。返回进程退出码：有变严即非 0，便于 CI 卡关。"""
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    prev = {(r["cmd"], r["cwd"]): r for r in baseline["rows"]}

    changes: list[tuple[str, dict, dict]] = []
    for row in rows:
        key = (row["cmd"], row["cwd"])
        old = prev.get(key)
        if old is None:
            continue
        if old["replayed"] == row["replayed"]:
            continue
        changes.append((_severity_delta(old["replayed"], row["replayed"]), old, row))

    if rule_filter:
        changes = [c for c in changes if rule_filter in c[2]["reason"]]

    buckets = Counter(kind for kind, _, _ in changes)
    total = len(rows)
    print(f"\n=== 与基线对比 ({baseline_path.name}) ===")
    print(f"基线 {len(prev)} 条 / 当前 {total} 条")
    for kind in ("tightened", "loosened", "same", "error"):
        n = buckets.get(kind, 0)
        if n:
            print(f"  {kind:12s} {n:5d}  {100*n/max(total,1):5.2f}%")
    if not changes:
        print("  无变化")
        return 0

    for kind in ("tightened", "loosened", "error"):
        sel = [(o, n) for k, o, n in changes if k == kind]
        if not sel:
            continue
        print(f"\n--- {kind} ({len(sel)}) ---")
        for old, new in sel[:25]:
            print(f"  {old['replayed']:5s} -> {new['replayed']:5s}  {new['cmd'][:88]}")
            if new["reason"]:
                print(f"        {new['reason'][:96]}")
        if len(sel) > 25:
            print(f"  … 另有 {len(sel)-25} 条")

    return 1 if buckets.get("tightened") or buckets.get("error") else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="回放审计日志建立决策基线")
    ap.add_argument("--audit-dir", type=Path, default=_ROOT / "audit")
    ap.add_argument("--save", type=Path, help="把本次回放结果写成基线 JSON")
    ap.add_argument("--compare", type=Path, help="与指定基线对比")
    ap.add_argument("--rule", help="只看 reason 含该字符串的变化")
    ap.add_argument("--include-fixture", action="store_true",
                    help="不过滤 regression fixture 命令")
    ap.add_argument("--dedupe", action="store_true",
                    help="相同 (cmd, cwd) 只回放一次")
    args = ap.parse_args()

    if not args.audit_dir.is_dir():
        print(f"审计目录不存在: {args.audit_dir}", file=sys.stderr)
        return 2

    records, skipped = load_records(args.audit_dir, include_fixture=args.include_fixture)
    if args.dedupe:
        seen: set[tuple[str, str]] = set()
        deduped = []
        for r in records:
            key = (r["cmd_preview"], r["cwd"])
            if key in seen:
                skipped["duplicate"] += 1
                continue
            seen.add(key)
            deduped.append(r)
        records = deduped

    rows = evaluate_all(records)
    summarize(rows, skipped, label="回放结果")

    if args.save:
        args.save.write_text(
            json.dumps({"rows": rows}, ensure_ascii=False, indent=1),
            encoding="utf-8",
        )
        print(f"\n基线已写入 {args.save}")

    if args.compare:
        return compare(args.compare, rows, rule_filter=args.rule)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

