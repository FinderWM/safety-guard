"""读取 safety_guard.toml 配置——路径自感知，可放在任意位置。

配置文件查找顺序：
  1. 环境变量 SAFETY_GUARD_CONFIG 指向的文件
  2. 安装根目录下的 safety_guard.toml（推荐）

环境变量优先级高于 TOML：
  SAFETY_GUARD_FAIL_OPEN=1  → fail_open=true
  SAFETY_GUARD_DRY_RUN=1    → dry_run=true
"""
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

from . import bash_ast as _bash_ast


_FAIL_OPEN_ENV = "SAFETY_GUARD_FAIL_OPEN"
_DRY_RUN_ENV = "SAFETY_GUARD_DRY_RUN"


def _install_root() -> Path:
    """safety_guard 包所在目录的父目录——入口脚本和 toml 都在这里。"""
    return Path(__file__).resolve().parent.parent


def _package_dir() -> Path:
    """safety_guard 包目录本身。"""
    return Path(__file__).resolve().parent


def _entry_script() -> Path:
    """入口脚本路径（命名固定为 safety-guard.py）。"""
    return _install_root() / "safety-guard.py"


def _find_config_path() -> Path | None:
    env = os.environ.get("SAFETY_GUARD_CONFIG")
    if env:
        p = Path(env).expanduser()
        if p.exists():
            return p
    primary = _install_root() / "safety_guard.toml"
    if primary.exists():
        return primary
    return None


def _defaults() -> dict:
    return {
        "disabled_rules": [],
        "severity_overrides": {},
        "protected_branches": ["main", "master", "release/*"],
        "read_only_zones": ["~/.claude", "~/.agents", "~/.codex", "~/.grok"],
        "read_only_commands": [
            "cat", "rg", "grep", "find", "ls", "head", "tail", "wc", "stat", "file",
            "sed", "awk",
            # 纯读/纯查询，加进来是为了让泛化路径规则别把它们当写入
            "nl", "tree", "diff", "jq", "yq", "du", "df", "realpath", "readlink",
            "basename", "dirname", "which", "type", "column", "sort", "uniq", "cut",
            "less", "more", "od", "xxd", "hexdump", "strings",
            "base64", "base32", "certutil",
            "md5", "md5sum", "shasum", "sha1sum", "sha256sum", "cksum",
            "bat", "batcat",
        ],
        # 前缀包装命令：剥掉后按内层真命令分发规则。
        # 不剥的话 `rtk rm -rf /` / `sudo rm -rf /` 会绕过全部按命令名匹配的规则。
        "wrapper_commands": list(_bash_ast.DEFAULT_WRAPPERS),
        # 默认只自保护——把 hook 自身和入口脚本列入。CLI 特定的路径（如 ~/.claude/settings.json）
        # 由各 CLI 的 safety_guard.toml 自行追加。
        "critical_paths": [
            str(_entry_script()),
            str(_package_dir()),
            # Grok CLI 配置与 hook 定义：被改掉等于卸防护
            str(Path.home() / ".grok" / "config.toml"),
            str(Path.home() / ".grok" / "hooks"),
        ],
        "fail_open": False,
        "dry_run": False,
        # audit 目录默认在安装根目录下，跟随 hook 一起迁移
        "audit_dir": str(_install_root() / "audit"),
        "audit_retention_days": 7,
        "audit_max_file_mb": 5,
        "audit_max_total_mb": 50,
    }


@dataclass(frozen=True)
class Config:
    disabled_rules: tuple[str, ...]
    severity_overrides: dict[str, str]
    protected_branches: tuple[str, ...]
    read_only_zones: tuple[Path, ...]
    read_only_commands: frozenset[str]
    critical_paths: tuple[Path, ...]
    fail_open: bool
    dry_run: bool
    audit_dir: Path
    audit_retention_days: int
    audit_max_file_mb: int
    audit_max_total_mb: int
    # 带默认值，保证 load() 未显式传入时也能构造（避免改配置时把 hook 锁死）
    wrapper_commands: frozenset[str] = frozenset(_bash_ast.DEFAULT_WRAPPERS)


def _expand_path(p: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(p)))


def _minimal_config() -> Config:
    """不依赖任何模块级辅助函数的兜底配置。

    存在的理由：`critical_paths` 默认保护 safety_guard/ 整个包，一旦包内代码写坏
    （import 错、NameError），`load()` 抛异常 → engine fail-closed → 连修包的那次
    编辑本身都被 deny，形成不可自愈的死锁。这里保证 load() 永不抛，规则层照常工作。
    """
    root = Path(__file__).resolve().parent.parent
    return Config(
        disabled_rules=(),
        severity_overrides={},
        protected_branches=("main", "master", "release/*"),
        read_only_zones=(Path.home() / ".claude", Path.home() / ".agents", Path.home() / ".codex", Path.home() / ".grok"),
        read_only_commands=frozenset({"cat", "rg", "grep", "find", "ls", "head", "tail", "wc", "stat", "file", "sed", "awk"}),
        critical_paths=(root / "safety-guard.py", root / "safety_guard"),
        fail_open=False,
        dry_run=False,
        audit_dir=root / "audit",
        audit_retention_days=7,
        audit_max_file_mb=5,
        audit_max_total_mb=50,
    )


def load(path: Path | None = None) -> Config:
    try:
        return _load(path)
    except Exception:
        # 兜底而不是抛——见 _minimal_config 的说明
        return _minimal_config()


def _load(path: Path | None = None) -> Config:
    raw: dict = _defaults()
    cfg_path = path if path is not None else _find_config_path()
    if cfg_path is not None and cfg_path.exists():
        try:
            with cfg_path.open("rb") as f:
                user = tomllib.load(f)
            # critical_paths 与默认合并（不让用户配置丢失 self-protection）
            if "critical_paths" in user:
                merged = list(dict.fromkeys(list(raw["critical_paths"]) + list(user["critical_paths"])))
                user["critical_paths"] = merged
            raw.update(user)
        except (OSError, tomllib.TOMLDecodeError):
            # 解析失败用默认值；engine 层有 fail-closed 兜底
            pass

    if os.environ.get(_FAIL_OPEN_ENV) == "1":
        raw["fail_open"] = True
    if os.environ.get(_DRY_RUN_ENV) == "1":
        raw["dry_run"] = True
    if os.environ.get("SAFETY_GUARD_IGNORE_DISABLED_RULES") == "1":
        # 只会让规则更全，不会放松防线。测试用：改 hook 自身时要在 toml 里临时把
        # 自保护规则塞进 disabled_rules，那个窗口会让十来条自保护测试假性 FAIL。
        raw["disabled_rules"] = []

    return Config(
        disabled_rules=tuple(raw["disabled_rules"]),
        severity_overrides=dict(raw["severity_overrides"]),
        protected_branches=tuple(raw["protected_branches"]),
        read_only_zones=tuple(_expand_path(z) for z in raw["read_only_zones"]),
        read_only_commands=frozenset(raw["read_only_commands"]),
        critical_paths=tuple(_expand_path(p) for p in raw["critical_paths"]),
        fail_open=bool(raw["fail_open"]),
        dry_run=bool(raw["dry_run"]),
        audit_dir=_expand_path(raw["audit_dir"]),
        audit_retention_days=int(raw["audit_retention_days"]),
        audit_max_file_mb=int(raw["audit_max_file_mb"]),
        audit_max_total_mb=int(raw["audit_max_total_mb"]),
        wrapper_commands=frozenset(raw.get("wrapper_commands") or _bash_ast.DEFAULT_WRAPPERS),
    )
