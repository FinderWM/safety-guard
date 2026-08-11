r"""确定性展开 + 混淆路径检测。

四种针对折叠模型的攻击形态，全部要求还原到真实目标：
    ~/.ss{,}h/xxx          brace expansion
    ~/.\ss\h/config        backslash removal
    ~/.ss$'\x68'/config    ANSI-C quoting
    bash -c "$(printf …)"  运行时才成形的载荷

以及真实语料里合法的同构造用法必须保持 allow——多目录 rg、正则量词、
find -exec 占位符、printf 转义序列。
"""
from __future__ import annotations

from pathlib import Path

import pytest

from safety_guard import expand as E


# --- 展开层单测 ---------------------------------------------------------

EXPAND_CASES = [
    ("~/.ss{,}h/xxx",                       ["~/.ssh/xxx"]),
    ("~/.ss$'\\x68'/config",                ["~/.ssh/config"]),
    ("~/.\\ss\\h/config",                   ["~/.ssh/config"]),
    ("~/.ssh/config",                       ["~/.ssh/config"]),
    ("java/cn/lyy/{controller,service}",    ["java/cn/lyy/controller", "java/cn/lyy/service"]),
    ("f{1..3}.txt",                         ["f1.txt", "f2.txt", "f3.txt"]),
    ("x{a..c}",                             ["xa", "xb", "xc"]),
    ("./src",                               ["./src"]),
]


@pytest.mark.parametrize("raw,expected", EXPAND_CASES)
def test_expand_candidates(raw: str, expected: list[str]):
    assert E.candidates(raw) == expected


def test_ansi_c_octal_and_unicode():
    assert E.expand_ansi_c(r"$'\150\151'") == "hi"
    assert E.expand_ansi_c(r"$'\u0068'") == "h"


def test_empty_brace_is_not_expansion():
    """`{}` 是 find -exec 占位符，不是 brace expansion。"""
    assert E.candidates("{}") == ["{}"]


def test_regex_quantifier_not_expanded():
    """`.{141}` 是正则量词，没有顶层逗号，不该被当成 brace expansion。"""
    assert E.candidates(".{141}") == [".{141}"]


def test_brace_explosion_gives_up():
    """组合爆炸时返回空列表，调用方按不可解析处理，而不是静默放行。"""
    bomb = "{a,b}{c,d}{e,f}{g,h}{i,j}{k,l}{m,n}"
    assert E.expand_braces(bomb) == []


# --- 端到端：攻击形态 ---------------------------------------------------

OBFUSCATED_READS = [
    "cat ~/.ss{,}h/xxx",
    "cat ~/.\\ss\\h/config",
    "cat ~/.ss$'\\x68'/config",
    "cat ~/.ssh/config",
]


@pytest.mark.parametrize("command", OBFUSCATED_READS)
def test_obfuscated_outside_read_flagged(bash, cwd: Path, command: str):
    """混淆构造不能让 CWD 外读取绕过判定。"""
    decision, reason = bash(command, cwd)
    assert decision == "ask", f"{command!r} got {decision} ({reason})"
    assert "bash-outside-cwd-read" in (reason or "")


OPAQUE_PAYLOADS = [
    'bash -c "$(printf \'\\x63\\x61\\x74\')"',
    'sh -c "$(gen_command)"',
    'bash -lc "$(build_cmd)"',
    'zsh -c "$(echo ls)"',
]


@pytest.mark.parametrize("command", OPAQUE_PAYLOADS)
def test_opaque_inline_payload_flagged(bash, cwd: Path, command: str):
    """载荷运行时才成形——内层命令静态不可见，必须让用户看一眼。"""
    decision, reason = bash(command, cwd)
    assert decision in ("ask", "deny"), f"{command!r} got {decision}"
    assert "bash-opaque-inline-script" in (reason or "") or "bash-eval-from-network" in (reason or "")


def test_literal_payload_still_recurses(bash, cwd: Path):
    """字面量载荷仍要递归解析，内层危险命令照常拦截。"""
    decision, reason = bash("bash -c 'rm -rf /'", cwd)
    assert decision == "deny"
    assert "bash-rm-root-or-home" in (reason or "")


# 捆绑短选项：bash 允许 -cx / -xc / -cv 任意排序，实测全部执行载荷。
# 只认 -c/-lc/-ic 三个字面量的话，改一个字母就能让内层命令重新隐身。
BUNDLED_C_FLAGS = ["-cx", "-xc", "-cv", "-ce", "-cs"]


@pytest.mark.parametrize("flag", BUNDLED_C_FLAGS)
def test_bundled_c_flag_opaque_payload(bash, cwd: Path, flag: str):
    decision, reason = bash(f'bash {flag} "$(gen)"', cwd)
    assert decision == "ask", f"bash {flag} got {decision}"
    assert "bash-opaque-inline-script" in (reason or "")


@pytest.mark.parametrize("flag", BUNDLED_C_FLAGS)
def test_bundled_c_flag_literal_payload_recurses(bash, cwd: Path, flag: str):
    """捆绑选项下字面量载荷也要能递归——此前连这条路径都被绕过。"""
    decision, reason = bash(f"bash {flag} 'rm -rf /'", cwd)
    assert decision == "deny", f"bash {flag} got {decision}"
    assert "bash-rm-root-or-home" in (reason or "")


def test_long_option_not_treated_as_c(bash, cwd: Path):
    """--norc 含字母 c 但不吃载荷，不能误判。"""
    decision, _ = bash("bash --norc ./script.sh", cwd)
    assert decision == "allow"


# 解释器内联代码：与 sh -c 同构的威胁，载荷运行时才成形
INTERPRETER_OPAQUE = [
    'python3 -c "$(gen)"',
    'python -c "$(gen)"',
    'node -e "$(gen)"',
    'node -p "$(gen)"',
    'perl -e "$(gen)"',
    'ruby -e "$(gen)"',
    'php -r "$(gen)"',
    'rtk python3 -c "$(gen)"',
]


@pytest.mark.parametrize("command", INTERPRETER_OPAQUE)
def test_interpreter_opaque_payload_flagged(bash, cwd: Path, command: str):
    decision, reason = bash(command, cwd)
    assert decision == "ask", f"{command!r} got {decision}"
    assert "bash-opaque-inline-script" in (reason or "")


INTERPRETER_LITERAL = [
    "python3 -c 'print(1)'",
    'python3 -c "import json; print(json.dumps({}))"',
    "node -e 'console.log(1)'",
    "python3 ./script.py",
    "perl -e 'print 1'",
]


@pytest.mark.parametrize("command", INTERPRETER_LITERAL)
def test_interpreter_literal_payload_allowed(bash, cwd: Path, command: str):
    """字面量载荷是日常用法——真实语料 143 次全是这类，不能误伤。"""
    decision, reason = bash(command, cwd)
    assert decision == "allow", f"{command!r} got {decision} ({reason})"


# --- 端到端：合法用法不能误伤 -------------------------------------------

BENIGN = [
    "rg -n 'x' java/cn/lyy/open/{controller/merchant,service}",
    "rg -n '.{141}' ./src",
    "find . -name '*.java' -exec grep -l x {} ;",
    "printf '\\n--- workflow ---\\n'",
    "bash -c 'cat ./local.txt'",
    "sh ./script.sh",
    "rg --files . | rg '(^|/)(db|sql)/|\\.sql$'",
]


@pytest.mark.parametrize("command", BENIGN)
def test_benign_constructs_allowed(bash, cwd: Path, command: str):
    decision, reason = bash(command, cwd)
    assert decision == "allow", f"{command!r} got {decision} ({reason})"


def test_multi_dir_rg_stays_in_cwd(bash, cwd: Path):
    """真实语料里最常见的 brace 用法：多目录 rg，展开后仍在 CWD 内。"""
    (cwd / "src").mkdir()
    decision, reason = bash("rg -n 'x' src/{controller,service}", cwd)
    assert decision == "allow", f"got {decision} ({reason})"
