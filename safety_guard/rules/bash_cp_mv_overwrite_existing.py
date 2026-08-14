"""bash-cp-mv-overwrite-existing：cp/mv 的实际目标文件已存在。"""
from __future__ import annotations

from ..context import BashContext
from ..helpers import normalize_cmd_name, split_cp_mv_operands
from ..paths import resolve
from .base import Rule, RuleMatch
from .registry import register


def _path_text(value: object) -> str:
    return str(getattr(value, "path_text", getattr(value, "raw", value)))


def _has_no_clobber(args: list) -> bool:
    """识别 `-n`/`--no-clobber`，且不把 `-t`/`-S` 的附着值当选项。"""
    index = 0
    while index < len(args):
        raw = str(getattr(args[index], "raw", args[index]))
        if raw == "--":
            return False
        if raw == "--no-clobber":
            return True
        if raw in {"-t", "--target-directory", "-S", "--suffix"}:
            index += 2
            continue
        if raw.startswith(("--target-directory=", "--suffix=")):
            index += 1
            continue
        if raw.startswith("-") and not raw.startswith("--") and raw != "-":
            short = raw[1:]
            value_positions = [pos for pos in (short.find("t"), short.find("S")) if pos >= 0]
            option_letters = short[:min(value_positions)] if value_positions else short
            if "n" in option_letters:
                return True
        index += 1
    return False


@register
class BashCpMvOverwriteExisting(Rule):
    id = "bash-cp-mv-overwrite-existing"
    severity = "medium"
    applies_to = ("Bash",)
    description = "cp/mv 的目标文件已存在，将被覆盖"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        if ctx.ast is None:
            return None
        for cmd in ctx.ast.commands:
            name = normalize_cmd_name(cmd.name or "")
            if name not in ("cp", "mv"):
                continue
            args = list(cmd.args)
            if _has_no_clobber(args):
                continue
            sources, destination, target_directory_mode = split_cp_mv_operands(args)
            if destination is None:
                continue
            try:
                target = resolve(_path_text(destination), ctx.policy)
            except Exception:
                continue
            if target_directory_mode and not ctx.disk.is_dir(target):
                continue
            if target_directory_mode or ctx.disk.is_dir(target):
                for source in sources:
                    try:
                        source_path = resolve(_path_text(source), ctx.policy)
                    except Exception:
                        continue
                    basename = source_path.name
                    if not basename or basename in (".", "..", "*"):
                        continue
                    nested = target / basename
                    if ctx.disk.exists(nested) and not ctx.disk.is_dir(nested):
                        return RuleMatch(
                            rule_id=self.id,
                            severity=self.severity,
                            reason=f"{name} 目标目录 {target} 中的 {nested} 已存在，将被覆盖",
                            extra={
                                "target": str(nested),
                                "cmd": name,
                                "destination_directory": str(target),
                            },
                        )
                continue
            if ctx.disk.exists(target):
                return RuleMatch(
                    rule_id=self.id,
                    severity=self.severity,
                    reason=f"{name} 目标 {target} 已存在，将被覆盖",
                    extra={"target": str(target), "cmd": name},
                )
        return None
