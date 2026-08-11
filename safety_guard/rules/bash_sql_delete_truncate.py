"""bash-sql-delete-truncate：SQL 客户端执行 DELETE FROM / TRUNCATE。"""
from __future__ import annotations

import re

from ..context import BashContext
from .base import Rule, RuleMatch
from .registry import register

SQL_CLIENTS = frozenset({"psql", "mysql", "mysqlsh", "sqlite3", "mongo", "mongosh"})
DELETE_PATTERN = re.compile(r"\b(delete\s+from|truncate(\s+table)?)\b", re.IGNORECASE)


@register
class BashSqlDeleteTruncate(Rule):
    id = "bash-sql-delete-truncate"
    severity = "medium"
    applies_to = ("Bash",)
    description = "SQL 客户端执行 DELETE FROM / TRUNCATE 需用户确认"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        if ctx.ast is None:
            return None
        for cmd in ctx.ast.commands:
            if cmd.name not in SQL_CLIENTS:
                continue
            if DELETE_PATTERN.search(cmd.raw):
                return RuleMatch(
                    rule_id=self.id,
                    severity=self.severity,
                    reason=f"`{ctx.raw_command}` 通过 {cmd.name} 执行 DELETE/TRUNCATE，可能丢数据",
                    extra={"client": cmd.name},
                )
        return None
