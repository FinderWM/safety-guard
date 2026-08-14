"""bash-env-subversion：拦截改变「动词字面量 → 实际程序」映射的环境变量注入。

为什么单独成一条规则、且是 high：

所有按 `cmd.name` 分发的规则（rm / git / psql / curl…）都隐含一个前提——argv[0]
的字面量就是实际执行的程序。这个前提可以被一条前缀赋值推翻：

    PATH=<dir> cat ./f      # AST 里 argv[0] 老实是 cat，实际跑的是 <dir>/cat
    LD_PRELOAD=<x.so> ls    # ls 还是 ls，但 x.so 的构造函数先于 main 执行
    BASH_ENV=<f> sh -c ls   # 子 shell 启动时先 source <f>

即攻击者不需要模糊动词本身，只需要模糊动词的解析。这类注入让整套按名分发的
规则集体失效，所以它是其它所有规则的地基，必须在它们之前判定。

分级依据（不是经验，是 shell 求值顺序的直接推论）：

    A=/PRESET; A=/INJECTED echo $A   →   输出 /PRESET

前缀赋值对同一条命令自身的参数展开无效——展开发生在赋值生效之前。所以「数据型」
变量在构造上就没法往同一条命令里偷渡路径，交给常量折叠处理即可。而 A/B 级变量
由 execve 和动态链接器消费，不走 shell 展开阶段，对同一条命令立即生效。

真实语料（16k 条）里 A 级 0 命中、B 级非空值 0 命中，拦截成本为零。
"""
from __future__ import annotations

import posixpath

from ..context import BashContext
from .base import Rule, RuleMatch
from .registry import register


# A 级：动态链接器与 shell 启动钩子。任何取值都能导致任意代码执行，
# 且用户看到值也无法判断安全性——ask 只会转移责任，所以 deny。
_SUBVERSIVE_ALWAYS = frozenset({
    # 动态链接器注入（.so/.dylib 在 main 之前执行）
    "LD_PRELOAD", "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES",
    # shell 启动时 source 任意文件
    "BASH_ENV", "ENV",
    # 改变 shell 自身行为（xtrace 展开会执行命令替换）
    "SHELLOPTS", "BASHOPTS", "PS4", "PROMPT_COMMAND",
})

# 合法构建/运行时常见的库搜索路径仍需确认，但不应与注入 .so 同级 deny。
_SUBVERSIVE_LIBRARY_PATHS = frozenset({
    "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH",
})

# B 级：空值是合法惯用法，明显不可信的非空 PATH 会劫持命令解析。
#   IFS=          `while IFS= read -r path` 的标准写法，语料 9 次
#   PATH=         明显不可信的替换仍直接拒绝；可解释的扩展至少需确认。
_SUBVERSIVE_UNLESS_EMPTY = frozenset({"PATH", "IFS"})

_SYSTEM_FIXED_PATHS = frozenset({"/bin", "/sbin", "/usr/bin", "/usr/sbin"})
_KNOWN_FIXED_PATHS = _SYSTEM_FIXED_PATHS | frozenset({
    "/usr/local/bin", "/usr/local/sbin", "/opt/homebrew/bin", "/opt/homebrew/sbin",
    "/opt/local/bin", "/opt/local/sbin",
})

_TRUSTED_LIBRARY_PREFIXES = (
    "/lib", "/usr/lib", "/usr/local/lib", "/opt/homebrew/lib", "/opt/local/lib",
)
_TEMP_PATH_PREFIXES = ("/tmp", "/var/tmp", "/private/tmp")

# 通过内建命令导出的等价形态：`export LD_PRELOAD=...` 不产生 assignment 节点，
# argv[0] 是 export/declare，赋值落在 args 里。
_EXPORT_BUILTINS = frozenset({"export", "declare", "typeset", "readonly"})
_PATH_INDEPENDENT_BUILTINS = frozenset({":", "true", "false", "echo", "printf", "test", "[", "read"})
_SAFE_BUILTIN_WRAPPERS = frozenset({"command", "builtin"})


def _path_extends_existing(value: str) -> bool:
    """PATH=$PATH:... / ${PATH} 是扩展，不是整段劫持。"""
    return "$PATH" in value or "${PATH}" in value


def _path_list(value: str) -> tuple[list[str], bool]:
    cleaned = value.strip().strip("\"'")
    if not cleaned:
        return [], False
    raw_parts = [item.strip().strip("\"'") for item in cleaned.split(":")]
    has_empty = any(not item for item in raw_parts)
    return [posixpath.normpath(item) for item in raw_parts if item], has_empty


def _fixed_path_level(value: str) -> str | None:
    parts, has_empty = _path_list(value)
    if has_empty:
        return "B"
    if not parts:
        return None
    if all(item in _SYSTEM_FIXED_PATHS for item in parts):
        return None
    if all(item in _KNOWN_FIXED_PATHS for item in parts):
        return "M"
    if any(
        not item.startswith("/")
        or item.startswith(("/tmp", "/var/tmp", "/private/tmp", "/Users/", "/home/", "$HOME", "~"))
        for item in parts
    ):
        return "B"
    return "M"


def _library_path_level(value: str) -> str:
    parts, has_empty = _path_list(value)
    if has_empty:
        return "A"
    trusted = all(
        any(item == prefix or item.startswith(prefix + "/") for prefix in _TRUSTED_LIBRARY_PREFIXES)
        for item in parts
    )
    return "M" if parts and trusted else "A"


def _path_extension_level(value: str) -> str:
    """扩展现有 PATH 是常见开发用法；临时目录前缀仍可直接劫持动词。"""
    parts, has_empty = _path_list(value)
    if has_empty:
        return "B"
    if any(item == prefix or item.startswith(prefix + "/") for item in parts for prefix in _TEMP_PATH_PREFIXES):
        return "B"
    return "M"


def _classify(name: str, value: str) -> str | None:
    """返回命中的级别（'A'/'B'），未命中返回 None。"""
    if name in _SUBVERSIVE_ALWAYS:
        return "A"
    if name in _SUBVERSIVE_LIBRARY_PATHS and value.strip():
        return _library_path_level(value)
    if name in _SUBVERSIVE_UNLESS_EMPTY and value.strip():
        if name == "PATH" and _path_extends_existing(value):
            marker = "$PATH" if "$PATH" in value else "${PATH}"
            before, _, _ = value.partition(marker)
            if value.strip().strip("\"'") in {"$PATH", "${PATH}"}:
                return None
            before = before.strip(" \"'")
            if before.endswith(":") and before != ":":
                before = before[:-1]
            return _path_extension_level(before)
        if name == "PATH":
            return _fixed_path_level(value)
        return "B"
    return None


@register
class BashEnvSubversion(Rule):
    id = "bash-env-subversion"
    severity = "high"
    applies_to = ("Bash",)
    description = "拦截 PATH/LD_PRELOAD/BASH_ENV 等改变命令解析语义的环境变量注入"

    @staticmethod
    def _benign_assignment(cmd, assignment) -> bool:
        """仅豁免直接调用的普通 shell builtin；wrapper 仍可能经 PATH 启动。"""
        if getattr(assignment, "origin", "") != "prefix":
            return False
        if assignment.name == "PATH" and _path_list(assignment.value_raw)[1]:
            return False
        wrappers = set(getattr(cmd, "wrappers", ()) or ())
        if wrappers - _SAFE_BUILTIN_WRAPPERS:
            return False
        words = list(getattr(cmd, "words", ()) or ())
        if not words:
            return False
        raw_name = str(getattr(words[0], "raw", ""))
        if "/" in raw_name:
            return False
        name = str(getattr(cmd, "name", "") or "")
        return name in _PATH_INDEPENDENT_BUILTINS

    def match(self, ctx: BashContext) -> RuleMatch | None:
        if ctx.ast is None:
            return None

        hits: list[tuple[str, str]] = []
        for cmd in ctx.ast.commands:
            for a in cmd.assignments:
                level = _classify(a.name, a.value_raw)
                if level and self._benign_assignment(cmd, a):
                    continue
                if level:
                    hits.append((f"{a.raw}（{a.origin}）", level))
            # export / declare 形态：赋值在 argv 里，不是 assignment 节点
            if cmd.name in _EXPORT_BUILTINS:
                for w in cmd.args:
                    raw = w.raw
                    if "=" not in raw or raw.startswith("-"):
                        continue
                    name, value = raw.split("=", 1)
                    level = _classify(name, value)
                    if (
                        level == "M"
                        and name == "PATH"
                        and cmd.name in _EXPORT_BUILTINS
                        and len(ctx.ast.commands) == 1
                    ):
                        continue
                    if level:
                        hits.append((f"{raw}（{cmd.name}）", level))

        if not hits:
            return None
        high = [text for text, level in hits if level in {"A", "B"}]
        shown = [text for text, _ in hits]
        return RuleMatch(
            rule_id=self.id,
            severity="high" if high else "medium",
            reason=(
                f"检测到会改变命令解析语义的环境变量注入：{', '.join(shown)}。"
                "这类变量能让 argv[0] 的字面量与实际执行的程序不一致，"
                "使所有按命令名分发的安全规则失效。"
            ),
            extra={"assignments": shown, "high": high},
        )
