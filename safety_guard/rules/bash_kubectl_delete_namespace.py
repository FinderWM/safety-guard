"""bash-kubectl-delete-namespace：删除 Kubernetes namespace 会级联删除资源。"""
from __future__ import annotations

from ..context import BashContext
from ..helpers import normalize_cmd_name
from .base import Rule, RuleMatch
from .registry import register


_VALUE_OPTIONS = frozenset({
    "--cluster",
    "--context",
    "--dry-run",
    "--field-selector",
    "--filename",
    "--grace-period",
    "--kubeconfig",
    "--kustomize",
    "--namespace",
    "--output",
    "--request-timeout",
    "--selector",
    "--server",
    "--timeout",
    "--user",
    "-l",
    "-n",
    "-o",
    "-f",
    "-k",
})
_NAMESPACE_RESOURCES = frozenset({"namespace", "namespaces", "ns"})
_NON_MUTATING_DRY_RUN_MODES = frozenset({"client", "server"})
_GLOBAL_VALUE_OPTIONS = frozenset({
    "--as", "--as-group", "--as-uid", "--cache-dir", "--certificate-authority",
    "--client-certificate", "--client-key", "--cluster", "--context", "--kubeconfig",
    "--namespace", "--request-timeout", "--server", "--tls-server-name", "--user",
})


def _kubectl_subcommand(args: list[str]) -> tuple[str | None, list[str]]:
    index = 0
    while index < len(args):
        raw = args[index]
        if raw in _GLOBAL_VALUE_OPTIONS:
            index += 2
            continue
        if raw.startswith("--") and "=" in raw:
            index += 1
            continue
        if raw.startswith("-"):
            index += 1
            continue
        return raw, args[index + 1 :]
    return None, []


def _deleted_resource(args: list[str]) -> str | None:
    index = 0
    while index < len(args):
        raw = args[index]
        if raw == "--":
            return args[index + 1] if index + 1 < len(args) else None
        if raw in _VALUE_OPTIONS:
            index += 2
            continue
        if raw.startswith("-"):
            index += 1
            continue
        return raw
    return None


def _is_namespace_resource(resource: str | None) -> bool:
    if not resource:
        return False
    resource_type = resource.split("/", 1)[0].split(".", 1)[0].lower()
    return resource_type in _NAMESPACE_RESOURCES


def _dry_run_mode(args: list[str]) -> str | None:
    """只把 kubectl 明确声明的 client/server dry-run 视为不落盘。"""
    index = 0
    while index < len(args):
        raw = args[index]
        if raw == "--":
            return None
        if raw == "--dry-run":
            if index + 1 < len(args):
                return args[index + 1].strip().lower()
            return None
        if raw.startswith("--dry-run="):
            return raw.split("=", 1)[1].strip().lower()
        if raw in _VALUE_OPTIONS:
            index += 2
            continue
        index += 1
    return None


@register
class BashKubectlDeleteNamespace(Rule):
    id = "bash-kubectl-delete-namespace"
    severity = "medium"
    applies_to = ("Bash",)
    description = "kubectl delete namespace 会级联删除资源，需用户确认"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        if ctx.ast is None:
            return None
        for cmd in ctx.ast.commands:
            if normalize_cmd_name(cmd.name or "") != "kubectl":
                continue
            args = [getattr(w, "raw", str(w)) for w in cmd.args]
            subcommand, tail = _kubectl_subcommand(args)
            if subcommand != "delete":
                continue
            if "--help" in tail or "-h" in tail:
                continue
            if _dry_run_mode(tail) in _NON_MUTATING_DRY_RUN_MODES:
                continue
            if _is_namespace_resource(_deleted_resource(tail)):
                return RuleMatch(
                    rule_id=self.id,
                    severity=self.severity,
                    reason=f"`{ctx.raw_command}` 将删除 Kubernetes namespace 并级联资源，请确认。",
                )
        return None
