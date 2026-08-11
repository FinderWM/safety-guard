"""bash-unresolvable-path：路径算不出来 = 无法证明安全。

这条规则的分界线不是「危险」而是「可解释」：能折叠出具体路径的照常走路径规则，
折叠不出来的才拦。所以正反两组测试的对照关系是本文件的重点——
`H=/abs; cat $H/f` 放行、`A=$(gen); cat $A/f` 拦下，差别只在能不能算出来。

安全：只调用分析器，不执行命令；标的一律用不存在的假路径。
"""
from __future__ import annotations

from pathlib import Path

import pytest

RULE = "bash-unresolvable-path"

FAKE = "/tmp/sg-probe/fakehome"  # 不存在的假家目录


# 路径由运行时才确定的表达式拼装 —— 静态无从判断指向哪
UNRESOLVABLE = [
    "cat $(printf /non)/x",
    "cat ${UNSET_VAR}/config",
    "A=$(printf /non); cat $A/key",
    "R=$(cat ./p); cp $R/f ./loot",
    "cat ${A#x}/k",                      # 参数展开的字符串操作不做运行时推断
    "echo x > $D/out",                   # 重定向目标同样要能解释
    "mkdir -p $Z/sub",
    "tar -cf ./o.tar $(gen)/src",
]


@pytest.mark.parametrize("cmd", UNRESOLVABLE)
def test_unresolvable_path_asks(bash, cwd: Path, cmd: str):
    decision, reason = bash(cmd, cwd)
    assert decision in ("ask", "deny"), f"{cmd!r} got {decision}"
    assert RULE in (reason or ""), f"{cmd!r} 未命中不可解析判定：{reason}"


def test_foldable_assignment_is_not_flagged(bash, cwd: Path):
    """能由上文赋值推出具体路径的，折叠层算得出来，本规则必须放过。

    与 UNRESOLVABLE 里的 `A=$(printf /non); cat $A/key` 构成对照：同样是变量
    拼路径，差别只在赋值的右值是不是字面量。这条断言守的是「可解释即放行」，
    一旦失守，规则就退化成「见变量就拦」，噪音会淹没真实信号。
    """
    decision, reason = bash(f"H={cwd}; cat $H/f", cwd)
    assert RULE not in (reason or ""), f"可折叠路径被误报：{reason}"


def test_folded_outside_path_still_caught_by_path_rule(bash, cwd: Path):
    """折叠成功但指向外部，应由路径规则拦下——不能因为「可解释」就放行。"""
    decision, reason = bash(f"H={FAKE}; cat $H/.ssh/id_rsa", cwd)
    assert decision in ("ask", "deny"), f"got {decision}"
    assert "bash-outside-cwd-read" in (reason or ""), f"折叠后应按越界读拦：{reason}"


# 不应命中：循环变量、URL、非路径槽位
BENIGN = [
    "for f in ./*.md; do cat $f; done",       # 裸 $f 是遍历本地文件的常规写法
    "while IFS= read -r f; do cat $f; done < ./list",
    "curl -sS https://x.test/$p.md",          # URL 不是文件路径
    "git clone https://github.test/$org/$repo.git",
    'git commit -m "$MSG"',                   # commit message 不是路径
    'rg "$pat" ./src',                        # pattern 槽位不是路径
    'sed -i "s/$a/$b/" ./f.txt',              # sed 脚本里的变量不是路径
    "cat ./a.txt",
    'echo "$HOME"',                           # 无 / 分隔符，且 echo 不碰文件系统
    'printf "%s\\n" "$x"',
]


@pytest.mark.parametrize("cmd", BENIGN)
def test_benign_not_flagged(bash, cwd: Path, cmd: str):
    decision, reason = bash(cmd, cwd)
    assert RULE not in (reason or ""), f"{cmd!r} 误报：{reason}"
