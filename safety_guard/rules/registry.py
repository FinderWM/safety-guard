"""规则注册、校验与显式加载。"""
from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Iterable
from pathlib import Path

from .base import Rule


_REGISTRY: list[Rule] = []
_LOADED = False


def register(rule_class: type[Rule]) -> type[Rule]:
    if not rule_class.id:
        raise ValueError(f"Rule class {rule_class.__name__} missing id")
    if not rule_class.applies_to:
        raise ValueError(f"Rule {rule_class.id} missing applies_to")
    if any(rule.id == rule_class.id for rule in _REGISTRY):
        raise ValueError(f"duplicate rule id: {rule_class.id}")
    _REGISTRY.append(rule_class())
    return rule_class


def load_rules() -> None:
    global _LOADED
    if _LOADED:
        return
    package_dir = Path(__file__).parent
    module_names = sorted(
        module.name
        for module in pkgutil.iter_modules([str(package_dir)])
        if not module.name.startswith("_") and module.name not in {"base", "registry"}
    )
    for module_name in module_names:
        importlib.import_module(f"{__package__}.{module_name}")
    _LOADED = True


def all_rules() -> list[Rule]:
    load_rules()
    return list(_REGISTRY)


def iter_rules_for_tool(tool: str, disabled: Iterable[str] = ()) -> Iterable[Rule]:
    load_rules()
    disabled_set = frozenset(disabled)
    return tuple(rule for rule in _REGISTRY if rule.id not in disabled_set and tool in rule.applies_to)
