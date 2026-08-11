"""ToolContext 构造——把 PreToolUse JSON 预处理成规则方便消费的形态。

规则只读 context，不重复 parse / lstat / classify。
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from . import bash_ast as _bash_ast
from . import paths as _paths
from .config import Config
from .contracts import Operation
from .paths import Classification, PathPolicy


@dataclass
class DiskStat:
    """lstat 缓存——同一命令多次查同一路径走缓存。"""
    _cache: dict[Path, os.stat_result | None] = field(default_factory=dict)

    def _stat(self, p: Path) -> os.stat_result | None:
        if p in self._cache:
            return self._cache[p]
        try:
            st = os.lstat(p)
        except OSError:
            st = None
        self._cache[p] = st
        return st

    def exists(self, p: Path) -> bool:
        return self._stat(p) is not None

    def is_symlink(self, p: Path) -> bool:
        import stat as _s
        st = self._stat(p)
        return st is not None and _s.S_ISLNK(st.st_mode)

    def is_dir(self, p: Path) -> bool:
        import stat as _s
        st = self._stat(p)
        return st is not None and _s.S_ISDIR(st.st_mode)


@dataclass
class BashContext:
    tool: Literal["Bash"]
    raw_input: dict
    raw_command: str
    cwd: Path
    home: Path
    config: Config
    policy: PathPolicy
    disk: DiskStat
    ast: _bash_ast.BashAst | None
    parse_error: str | None  # 解析失败时的错误信息，None 表示成功
    opaque_payloads: list[_bash_ast.OpaquePayload] = field(default_factory=list)

    def classify(self, raw_path: str) -> Classification:
        return _paths.classify(raw_path, self.policy)

    def resolve(self, raw_path: str) -> Path:
        return _paths.resolve(raw_path, self.policy)


@dataclass
class FileToolContext:
    tool: Literal["Write", "Edit", "NotebookEdit"]
    raw_input: dict
    target_path: Path
    classification: Classification
    file_exists: bool
    edit_mode: str | None
    patch_action: str | None
    cwd: Path
    home: Path
    config: Config
    policy: PathPolicy
    disk: DiskStat


ToolContext = BashContext | FileToolContext


def build(operation: Operation, cwd_raw: str, config: Config) -> ToolContext:
    """把规范化操作构造成规则可消费的上下文；非法操作直接抛错。"""
    tool = operation.tool
    raw_input = operation.tool_input
    if not isinstance(cwd_raw, str):
        raise ValueError("cwd must be a string")

    cwd = Path(os.path.abspath(cwd_raw))
    home = Path.home()
    policy = PathPolicy(cwd=cwd, home=home, zones=config.read_only_zones)
    disk = DiskStat()

    if tool == "Bash":
        cmd = raw_input.get("command", "")
        if not isinstance(cmd, str):
            raise ValueError("Bash command must be a string")
        try:
            if cmd.strip():
                ast = _bash_ast.expand(_bash_ast.parse(cmd), config.wrapper_commands)
            else:
                ast = _bash_ast.BashAst(raw=cmd, commands=[], pipelines=[], redirects=[])
            parse_error = None
        except _bash_ast.BashParseError as e:
            ast = None
            parse_error = str(e)
        return BashContext(
            tool="Bash",
            raw_input=raw_input,
            raw_command=cmd,
            cwd=cwd,
            home=home,
            config=config,
            policy=policy,
            disk=disk,
            ast=ast,
            parse_error=parse_error,
            opaque_payloads=list(ast.opaque_payloads) if ast is not None else [],
        )

    if tool in ("Write", "Edit", "NotebookEdit"):
        target_raw = raw_input.get("file_path") or raw_input.get("notebook_path") or ""
        if not isinstance(target_raw, str) or not target_raw:
            raise ValueError(f"{tool} target path must be a non-empty string")
        target_path = _paths.resolve(target_raw, policy)
        return FileToolContext(
            tool=tool,
            raw_input=raw_input,
            target_path=target_path,
            classification=_paths.classify(target_raw, policy),
            file_exists=disk.exists(target_path),
            edit_mode=raw_input.get("edit_mode"),
            patch_action=raw_input.get("patch_action"),
            cwd=cwd,
            home=home,
            config=config,
            policy=policy,
            disk=disk,
        )

    raise ValueError(f"unsupported operation tool: {tool!r}")
