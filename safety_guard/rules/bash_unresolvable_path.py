"""bash-unresolvable-path：路径槽位出现静态无法确定的表达式。

折叠层已经做对了一半：算不出来的 word 老实标 `folded=None`，绝不猜。但没有任何
规则消费这个信号——`path_text` 退回原文后，`$A/config` 既不以 / 也不以 ~ 开头，
`looks_like_potentially_outside_path` 判 False，整条命令放行。于是：

    「我看不懂这条路径」  和  「我看懂了且它安全」  得到同一个结论。

这正是原始安全报告 P1「未解析表达式默认放行」的残留。攻击面很直接：

    A=$(printf /outside); cat $A/key      # 折叠失败 → 无人过问
    cat $(gen_path)/key                   # 同上

判定标准不是「像不像危险」，而是**能不能解释**：正常命令的路径要么写死，要么能
由上文赋值推出（折叠层会算出来，folded 非空，本规则不触发）。算不出来本身就是
异常信号——这是「要求可解释性」而非「枚举危险」的直接落地。

两处刻意收窄，都是拿真实语料量过的（5670 条）：

1. **要求 word 里含 `/`**。不收窄命中 88 条（1.55%），其中 82 处是 `while read`
   / `for` 的循环变量——裸 `$f` 是「遍历本地文件」的常规写法，静态无从区分。
   收窄后 24 条（0.42%），全是 `$VAR/子路径` 这类**用分隔符拼装**的形态，
   也正是隐藏真实目标时必然留下的结构。

2. **排除 URL**。`https://host/$p.md` 含 `/` 且不可折叠，但它是网络地址不是文件
   路径，越界与否无从谈起——网络取指有 bash-pipe-to-shell / eval-from-network 管。

定级 medium：不可解析不等于恶意，让用户看一眼路径实际指向哪即可。
"""
from __future__ import annotations

from ..context import BashContext
from ..helpers import (
    command_is_read_only,
    iter_path_args,
    iter_read_redirect_targets,
    iter_read_sources,
    iter_write_targets,
)
from .base import Rule, RuleMatch
from .registry import register

_OPAQUE_PARTS = frozenset({"commandsubstitution", "processsubstitution"})

# 协议前缀：这些不是文件路径，越界判定无从谈起
_URL_SCHEMES = ("http://", "https://", "ftp://", "ssh://", "git@", "git://")


def _is_url(raw: str) -> bool:
    return raw.startswith(_URL_SCHEMES)


def _unresolvable_kind(w) -> str | None:
    """返回不可解析的类型；可解析或不构成路径表达式时返回 None。"""
    if not getattr(w, "has_expansion", False):
        return None
    if getattr(w, "folded", None) is not None:
        return None                      # 折叠成功 = 可解释，交给路径规则判定
    raw = getattr(w, "raw", "")
    if "/" not in raw or _is_url(raw):
        return None                      # 见模块 docstring 的两处收窄
    kinds = {p[0] for p in getattr(w, "parts", ())}
    return "命令替换" if kinds & _OPAQUE_PARTS else "变量拼接"


@register
class BashUnresolvablePath(Rule):
    id = "bash-unresolvable-path"
    severity = "medium"
    applies_to = ("Bash",)
    description = "路径参数含静态无法确定的表达式，无法证明其目标在 CWD 内"

    def match(self, ctx: BashContext) -> RuleMatch | None:
        if ctx.ast is None:
            return None
        read_only = ctx.config.read_only_commands
        hits: list[str] = []
        seen: set[str] = set()

        def consider(w) -> None:
            kind = _unresolvable_kind(w)
            if kind is None:
                return
            shown = f"{w.raw}（{kind}）"
            if shown not in seen:
                seen.add(shown)
                hits.append(shown)

        for cmd in ctx.ast.commands:
            if command_is_read_only(cmd.name, cmd.args, read_only):
                for w in iter_path_args(cmd.name, cmd.args):
                    consider(w)
            else:
                for w in iter_read_sources(cmd.name, cmd.args, read_only):
                    consider(w)
                for w in iter_write_targets(cmd.name, cmd.args, read_only):
                    consider(w)
            for w in getattr(cmd, "extra_reads", None) or []:
                consider(w)

        for w in iter_read_redirect_targets(ctx.ast.redirects):
            consider(w)
        for r in ctx.ast.redirects:
            if r.target is not None:
                consider(r.target)

        if not hits:
            return None
        return RuleMatch(
            rule_id=self.id,
            severity=self.severity,
            reason=(
                f"路径参数无法静态确定，不能证明目标在当前目录内：{', '.join(hits)}。"
                "请确认这些表达式实际会指向哪里。"
            ),
            extra={"paths": hits},
        )
