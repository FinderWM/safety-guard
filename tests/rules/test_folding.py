"""常量折叠层：把字面量赋值还原后交给已有路径规则判定。

设计意图（改动前 → 改动后）：
  A=$HOME/.s; B=sh; cat $A$B/id_rsa   ALLOW → ASK    补漏
  R=./src; grep foo "$R"              ALLOW → ALLOW  不炸噪音

折叠只处理**可确定**的字面量赋值；命令替换、未知变量一律放弃折叠，标记为
不可解析而不猜测。

放弃折叠之后由谁接手，经历过一次修正：本层最初的取舍是「退回 raw 行为，宁可
漏报也不误报」，等于把「算不出来」和「算出来且安全」判成同一个结论。
bash-unresolvable-path 接管了这个信号——折不出来且形态像路径拼装（含 `/`）的
一律 ASK，见 test_unresolvable_path.py。本文件只保留「折得出来」的用例。

安全：本文件只调用分析器，不执行任何被测命令；敏感路径全部是不存在的假标的。
"""
from __future__ import annotations

from pathlib import Path

import pytest

# 折叠后指向 CWD 外 / 敏感位置 —— 必须从 ALLOW 变为 ASK
FOLD_ASK = [
    # 报告里逐条列出的绕过形态
    'A=$HOME/.s; B=sh; cat "$A$B/id_ed25519_fake"',
    'A=$HOME/.ssh_fake; cat "$A/id_rsa_fake"',
    "P=/etc; cat $P/hosts",
    'D=$HOME/.aws_fake; cat "$D/credentials"',
    # 多级引用
    'A=$HOME; B=$A/.ssh_fake; cat "$B/key"',
    # 前缀赋值形式（同一条命令内）
    "cat $HOME/.ssh_fake/id_rsa_fake",
    # 写方向
    'T=$HOME/.claude_fake; cp ./a.txt "$T/b.txt"',
]

# 折叠后仍在 CWD 内 —— 必须保持 ALLOW（噪音防线）
FOLD_ALLOW = [
    "R=./src; grep foo $R",
    'D=./build; ls "$D"',
    "F=./out.txt; cat ./in.txt",
    'P=.; rg -n foo "$P"',
    # 折不出来且不含 / —— 无从判断是路径还是普通字符串，保持放行
    'F=$(mktemp); echo hi > "$F"',
    'D=$(pwd); ls "$D"',
    # 赋值被后续不可解析赋值覆盖 → 放弃折叠，同样不含 /
    'A=$HOME; A=$(pwd); ls "$A"',
]

# 折不出来、但形态是路径拼装（含 /）—— 移交 bash-unresolvable-path 处理。
# 留在这里是为了记录移交边界：折叠层的职责止于「算不出来就别猜」。
UNRESOLVABLE_HANDOFF = [
    'cat "$UNKNOWN_VAR/x"',
    'A=$(pwd); cat "$A/../../etc/hosts"',
]


@pytest.mark.parametrize("command", FOLD_ASK)
def test_folded_outside_path_asks(bash, cwd: Path, command: str):
    decision, reason = bash(command, cwd)
    assert decision == "ask", f"{command!r} 折叠后应 ASK，实际 {decision} ({reason})"


@pytest.mark.parametrize("command", FOLD_ALLOW)
def test_folded_inside_path_allows(bash, cwd: Path, command: str):
    decision, reason = bash(command, cwd)
    assert decision == "allow", f"{command!r} 应保持 ALLOW，实际 {decision} ({reason})"


@pytest.mark.parametrize("command", UNRESOLVABLE_HANDOFF)
def test_unresolvable_path_shape_hands_off(bash, cwd: Path, command: str):
    """折叠放弃 + 形态像路径 → 必须由 bash-unresolvable-path 接住，不能静默放行。"""
    decision, reason = bash(command, cwd)
    assert decision in ("ask", "deny"), f"{command!r} 应被接住，实际 {decision}"
    assert "bash-unresolvable-path" in (reason or ""), f"移交失败：{reason}"


def test_reason_shows_both_raw_and_folded(bash, cwd: Path):
    """可解释性：理由串必须同时给出原文和折叠结果，否则用户无法判断。"""
    decision, reason = bash('A=$HOME/.ssh_fake; cat "$A/id_rsa_fake"', cwd)
    assert decision == "ask"
    assert "→" in (reason or ""), f"理由缺少折叠展示：{reason}"
    assert ".ssh_fake/id_rsa_fake" in (reason or ""), reason


def test_folding_reaches_self_protection(bash, cwd: Path, tmp_path: Path):
    """high 级自保规则也必须走折叠，否则变量拼接可绕过 critical_paths。"""
    decision, reason = bash("A=~/.claude; rm $A/settings.json", cwd)
    assert decision in ("ask", "deny"), f"应拦截，实际 {decision} ({reason})"


def test_quoted_offsets_do_not_corrupt_fold(bash, cwd: Path):
    """引号坐标系陷阱：node.word 去引号而 parts.pos 是原文偏移，
    混用会折出 `$/Users/...` 之类的错位结果。"""
    decision, reason = bash('cat "$HOME"/.ssh_fake/id_rsa_fake', cwd)
    assert decision == "ask", f"{decision} ({reason})"
    assert "$/" not in (reason or ""), f"偏移错位：{reason}"


def test_folded_argv_zero_reenters_command_rules(bash, cwd: Path):
    decision, reason = bash("C=git; $C push --force origin main", cwd)

    assert decision == "deny"
    assert "bash-git-push-force-protected" in (reason or "")


def test_folded_wrapper_and_command_are_both_unwrapped(bash, cwd: Path):
    decision, reason = bash("W=env; C=git; $W $C push --force origin main", cwd)

    assert decision == "deny"
    assert "bash-git-push-force-protected" in (reason or "")
