"""bash-sql-drop-database：psql / mysql / sqlite3 命令 argv 中含 DROP DATABASE / DROP SCHEMA。"""
from __future__ import annotations

import re

from ..context import BashContext
from .base import Rule, RuleMatch
from .registry import register

SQL_CLIENTS = frozenset({"psql", "mysql", "mysqlsh", "sqlite3", "mongo", "mongosh"})
DROP_PATTERN = re.compile(r"\bdrop\s+(database|schema)\b", re.IGNORECASE)


@register
class BashSqlDropDatabase(Rule):
    id = "bash-sql-drop-database"
    severity = "high"
    applies_to = ("Bash",)
    description = "拒绝 SQL 客户端执行 DROP DATABASE / DROP SCHEMA"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        if ctx.ast is None:
            return None
        for cmd in ctx.ast.commands:
            if cmd.name not in SQL_CLIENTS:
                continue
            # 所有参数和原文 raw 都扫一次
            text = cmd.raw
            if DROP_PATTERN.search(text):
                return RuleMatch(
                    rule_id=self.id,
                    severity=self.severity,
                    reason=(
                        f"拒绝执行：`{ctx.raw_command}` 通过 {cmd.name} 执行 DROP DATABASE/SCHEMA，"
                        f"将销毁整个库。"
                    ),
                    extra={"client": cmd.name},
                )
        return None
