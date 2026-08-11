"""路径分类——对齐 CLAUDE.md "Cross-CWD file access" 语义。

- in-cwd：路径位于 CWD 子树内（含 CWD 内的 symlink，无论 target 在哪）
- instruction-zone：路径位于 ~/.claude 或 ~/.agents 等指令区（只读豁免，写仍需 ask）
- outside：其它任何位置

关键语义：用 lstat 判断、不 follow link，链接位置决定归属。
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path, PurePath
from typing import Literal

from . import expand as _expand_mod


def _expand_candidates(raw: str) -> list[str]:
    """展开确定性构造；放弃展开时退回原文（判定仍按原文进行）。"""
    try:
        cands = _expand_mod.candidates(raw)
    except Exception:
        return [raw]
    return cands or [raw]


Classification = Literal["in-cwd", "instruction-zone", "outside"]


@dataclass(frozen=True)
class PathPolicy:
    cwd: Path
    home: Path
    zones: tuple[Path, ...]


def _expand(raw: str, home: Path, cwd: Path) -> Path:
    """把 ~/$HOME/相对路径 normalize 到绝对路径，不 follow symlink。"""
    s = os.path.expandvars(raw)
    if s.startswith("~"):
        s = s.replace("~", str(home), 1)
    p = Path(s)
    if not p.is_absolute():
        p = cwd / p
    # os.path.normpath 处理 .. 和 . 但不 follow link
    return Path(os.path.normpath(str(p)))


def _is_descendant(path: Path, root: Path) -> bool:
    """path 是否在 root 子树内（含相等）。基于词法比较，不 follow link。"""
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def classify(raw_path: str, policy: PathPolicy) -> Classification:
    """分类单个路径。含 brace/ANSI-C/转义时按最危险的候选定级。

    `~/.ss{,}h/x` 展开后是 `~/.ssh/x`——不展开的话字面量里没有连续的 `.ssh`，
    敏感路径判定会被整条绕过。多候选取最危险的一个（outside > instruction-zone
    > in-cwd），因为命令会对每个候选都实际执行一次。
    """
    cands = _expand_candidates(raw_path)
    if len(cands) == 1:
        return _classify_one(cands[0], policy)
    ranked = [_classify_one(c, policy) for c in cands]
    for level in ("outside", "instruction-zone", "in-cwd"):
        if level in ranked:
            return level  # type: ignore[return-value]
    return "in-cwd"


def _classify_one(raw_path: str, policy: PathPolicy) -> Classification:
    abs_path = _expand(raw_path, policy.home, policy.cwd)
    if _is_descendant(abs_path, policy.cwd):
        return "in-cwd"
    for zone in policy.zones:
        if _is_descendant(abs_path, zone):
            return "instruction-zone"
    return "outside"


def resolve(raw_path: str, policy: PathPolicy) -> Path:
    """返回 raw_path 解析后的绝对路径（不 follow link）。"""
    return _expand(raw_path, policy.home, policy.cwd)


def is_critical(path: Path, critical_paths: tuple[Path, ...]) -> bool:
    """路径是否落在受保护的 critical_paths 内（用于 disable-safety-hook 类规则）。"""
    for cp in critical_paths:
        if path == cp or _is_descendant(path, cp):
            return True
    return False
