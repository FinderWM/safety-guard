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
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Literal

from . import bash_ast as _bash_ast
from .bash_ast import WrapperSpec


_FAIL_OPEN_ENV = "SAFETY_GUARD_FAIL_OPEN"
_DRY_RUN_ENV = "SAFETY_GUARD_DRY_RUN"
_AUDIT_INCLUDE_BODY_ENV = "SAFETY_GUARD_AUDIT_INCLUDE_BODY"
ConfigLoadError = Literal["config_read_error", "config_parse_error", "config_invalid"]
_ALLOWED_SEVERITIES = frozenset({"medium", "high"})


def _install_root() -> Path:
    """safety_guard 包所在目录的父目录——入口脚本和 toml 都在这里。"""
    return Path(__file__).resolve().parent.parent


def _package_dir() -> Path:
    """safety_guard 包目录本身。"""
    return Path(__file__).resolve().parent


def _entry_script() -> Path:
    """入口脚本路径（命名固定为 safety-guard.py）。"""
    return _install_root() / "safety-guard.py"


def _platform_critical_paths() -> list[str]:
    home = Path.home()
    return [
        str(home / ".claude" / "settings.json"),
        str(home / ".codex" / "config.toml"),
        str(home / ".codex" / "hooks.json"),
        str(home / ".grok" / "config.toml"),
        str(home / ".grok" / "hooks"),
    ]


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
        "wrapper_specs": {},
        "critical_paths": [
            str(_entry_script()),
            str(_package_dir()),
            *_platform_critical_paths(),
        ],
        "fail_open": False,
        "dry_run": False,
        "audit_include_body": False,
        "unknown_reviewer": "noop",
        "reviewer_timeout_ms": 250,
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
    audit_include_body: bool
    unknown_reviewer: str
    reviewer_timeout_ms: int
    audit_dir: Path
    audit_retention_days: int
    audit_max_file_mb: int
    audit_max_total_mb: int
    load_error: ConfigLoadError | None = None
    # 带默认值，保证 load() 未显式传入时也能构造（避免改配置时把 hook 锁死）
    wrapper_commands: frozenset[str] = frozenset(_bash_ast.DEFAULT_WRAPPERS)
    wrapper_specs: dict[str, WrapperSpec] = field(default_factory=lambda: dict(_bash_ast.DEFAULT_WRAPPER_SPECS))


def _expand_path(p: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(p)))


def _string_list(raw: dict, key: str) -> list[str]:
    value = raw.get(key)
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{key} must be an array of strings")
    return value


def _bool_value(raw: dict, key: str) -> bool:
    value = raw.get(key)
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be a boolean")
    return value


def _int_value(raw: dict, key: str, *, minimum: int) -> int:
    value = raw.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{key} must be an integer >= {minimum}")
    return value


def _severity_overrides(raw: dict) -> dict[str, str]:
    value = raw.get("severity_overrides")
    if not isinstance(value, dict):
        raise ValueError("severity_overrides must be a table")
    if any(
        not isinstance(rule_id, str)
        or not isinstance(severity, str)
        or severity not in _ALLOWED_SEVERITIES
        for rule_id, severity in value.items()
    ):
        raise ValueError("severity_overrides values must be medium or high")
    return dict(value)


def _validate_wrapper_specs(raw: dict) -> None:
    specs = raw.get("wrapper_specs")
    if not isinstance(specs, dict):
        raise ValueError("wrapper_specs must be a table")
    for name, spec in specs.items():
        if not isinstance(name, str) or not name or not isinstance(spec, dict):
            raise ValueError("wrapper_specs entries must be named tables")
        for key in ("value_opts", "subcommands"):
            value = spec.get(key)
            if value is not None and (
                not isinstance(value, list)
                or any(not isinstance(item, str) for item in value)
            ):
                raise ValueError(f"wrapper_specs.{name}.{key} must be an array of strings")
        skip = spec.get("skip_positional")
        if skip is not None and (
            isinstance(skip, bool)
            or not isinstance(skip, int)
            or skip < 0
        ):
            raise ValueError(f"wrapper_specs.{name}.skip_positional must be an integer >= 0")


def _validate_raw(raw: dict) -> None:
    for key in (
        "disabled_rules",
        "protected_branches",
        "read_only_zones",
        "read_only_commands",
        "critical_paths",
        "wrapper_commands",
    ):
        _string_list(raw, key)
    _severity_overrides(raw)
    _validate_wrapper_specs(raw)
    for key in ("fail_open", "dry_run", "audit_include_body"):
        _bool_value(raw, key)
    reviewer = raw.get("unknown_reviewer")
    if not isinstance(reviewer, str) or not reviewer.strip():
        raise ValueError("unknown_reviewer must be a non-empty string")
    audit_dir = raw.get("audit_dir")
    if not isinstance(audit_dir, str) or not audit_dir.strip():
        raise ValueError("audit_dir must be a non-empty string")
    _int_value(raw, "reviewer_timeout_ms", minimum=1)
    _int_value(raw, "audit_retention_days", minimum=0)
    _int_value(raw, "audit_max_file_mb", minimum=1)
    _int_value(raw, "audit_max_total_mb", minimum=1)


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
        critical_paths=tuple(
            [root / "safety-guard.py", root / "safety_guard"]
            + [Path(path) for path in _platform_critical_paths()]
        ),
        fail_open=False,
        dry_run=False,
        audit_include_body=False,
        unknown_reviewer="noop",
        reviewer_timeout_ms=250,
        audit_dir=root / "audit",
        audit_retention_days=7,
        audit_max_file_mb=5,
        audit_max_total_mb=50,
        wrapper_commands=frozenset(_bash_ast.DEFAULT_WRAPPERS),
        wrapper_specs=dict(_bash_ast.DEFAULT_WRAPPER_SPECS),
    )


def load(path: Path | None = None) -> Config:
    try:
        return _load(path)
    except Exception:
        # 兜底而不是抛——见 _minimal_config 的说明
        return replace(
            _minimal_config(),
            load_error="config_invalid",
        )


def _load(path: Path | None = None) -> Config:
    raw: dict = _defaults()
    load_error: ConfigLoadError | None = None
    cfg_path = path if path is not None else _find_config_path()
    if cfg_path is not None and cfg_path.exists():
        try:
            with cfg_path.open("rb") as f:
                user = tomllib.load(f)
            # critical_paths 与默认合并（不让用户配置丢失 self-protection）
            if "critical_paths" in user:
                if not isinstance(user["critical_paths"], list) or any(
                    not isinstance(path, str) for path in user["critical_paths"]
                ):
                    raise ValueError("critical_paths must be an array of strings")
                merged = list(dict.fromkeys(list(raw["critical_paths"]) + list(user["critical_paths"])))
                user["critical_paths"] = merged
            user_wrapper_specs = user.get("wrapper_specs")
            raw.update(user)
            if isinstance(user_wrapper_specs, dict):
                raw["wrapper_specs"] = user_wrapper_specs
        except OSError:
            load_error = "config_read_error"
        except tomllib.TOMLDecodeError:
            load_error = "config_parse_error"

    if os.environ.get(_FAIL_OPEN_ENV) == "1":
        raw["fail_open"] = True
    if os.environ.get(_DRY_RUN_ENV) == "1":
        raw["dry_run"] = True
    if os.environ.get(_AUDIT_INCLUDE_BODY_ENV) == "1":
        raw["audit_include_body"] = True
    if os.environ.get("SAFETY_GUARD_IGNORE_DISABLED_RULES") == "1":
        # 只会让规则更全，不会放松防线。测试用：改 hook 自身时要在 toml 里临时把
        # 自保护规则塞进 disabled_rules，那个窗口会让十来条自保护测试假性 FAIL。
        raw["disabled_rules"] = []

    _validate_raw(raw)

    return Config(
        disabled_rules=tuple(_string_list(raw, "disabled_rules")),
        severity_overrides=_severity_overrides(raw),
        protected_branches=tuple(_string_list(raw, "protected_branches")),
        read_only_zones=tuple(_expand_path(z) for z in _string_list(raw, "read_only_zones")),
        read_only_commands=frozenset(_string_list(raw, "read_only_commands")),
        critical_paths=tuple(_expand_path(p) for p in _string_list(raw, "critical_paths")),
        fail_open=_bool_value(raw, "fail_open"),
        dry_run=_bool_value(raw, "dry_run"),
        audit_include_body=_bool_value(raw, "audit_include_body"),
        unknown_reviewer=str(raw.get("unknown_reviewer") or "noop"),
        reviewer_timeout_ms=_int_value(raw, "reviewer_timeout_ms", minimum=1),
        audit_dir=_expand_path(raw["audit_dir"]),
        audit_retention_days=_int_value(raw, "audit_retention_days", minimum=0),
        audit_max_file_mb=_int_value(raw, "audit_max_file_mb", minimum=1),
        audit_max_total_mb=_int_value(raw, "audit_max_total_mb", minimum=1),
        load_error=load_error,
        wrapper_commands=_wrapper_command_names(raw),
        wrapper_specs=_bash_ast.merge_wrapper_specs(raw.get("wrapper_specs")),
    )


def _wrapper_command_names(raw: dict) -> frozenset[str]:
    names = set(raw.get("wrapper_commands") or _bash_ast.DEFAULT_WRAPPERS)
    specs = raw.get("wrapper_specs")
    if isinstance(specs, dict):
        names.update(k for k in specs if isinstance(k, str) and k)
    return frozenset(names)
