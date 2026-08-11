"""bash-interpreter-shell-escape：解释器内联载荷把控制权交给 shell。

判别式刻意只看「是否移交控制权给 shell」，不看载荷想干什么——后者要解析 Python
才做得到。所以负样本里必须包含**长得像但不是**的形态（`self.system(`、
`obj.exec(`），它们是判别式过宽时最先炸的地方。

安全：只调用分析器，不执行被测命令；载荷里的命令一律用无副作用的 `id`。
"""
from __future__ import annotations

from pathlib import Path

import pytest

RULE = "bash-interpreter-shell-escape"


ESCAPES = [
    'python3 -c "import os; os.system(\'id\')"',
    'python3 -c "__import__(\'os\').system(\'id\')"',
    'python3 -c "import subprocess; subprocess.run([\'id\'])"',
    'python3 -c "import os; os.popen(\'id\')"',
    'python3 -c "import pty; pty.spawn(\'/bin/sh\')"',
    'node -e "require(\'child_process\').execSync(\'id\')"',
    'node -e "const {spawnSync}=require(\'child_process\'); spawnSync(\'id\')"',
    "perl -e 'system(\"id\")'",
    "ruby -e 'system(\"id\")'",
    "ruby -e 'IO.popen(\"id\")'",
    'php -r "shell_exec(\'id\');"',
    "awk 'BEGIN{system(\"id\")}'",
    'awk \'BEGIN{"id" | getline x; print x}\'',
]


@pytest.mark.parametrize("cmd", ESCAPES)
def test_shell_escape_denied(bash, cwd: Path, cmd: str):
    decision, reason = bash(cmd, cwd)
    assert decision == "deny", f"{cmd!r} 应 deny，实际 {decision} ({reason})"
    assert RULE in (reason or ""), f"{cmd!r} 未命中逃逸判定：{reason}"


# 正常内联用法 —— 判别式过宽的话这些会最先炸
BENIGN = [
    'python3 -c "print(1+1)"',
    'python3 -c "import json,sys; print(json.load(sys.stdin))"',
    'python3 -c "import re; print(re.sub(r\'a\',\'b\',\'aa\'))"',
    'python3 -c "import os; print(os.getcwd())"',      # import os 本身无害
    "awk '{print $2}' ./f.txt",
    "awk -F, '{s+=$3}END{print s}' ./data.csv",
    'awk \'BEGIN{printf "%.2f\\n", 1/3}\'',
    "awk -f ./prog.awk ./data.txt",                     # -f 取脚本文件，位置参数是数据
    'node -e "console.log(process.version)"',
    "perl -e 'print 1+1'",
    "python3 ./scripts/run.py",                         # 非内联，不该进本规则
    # 业务方法名里含 system / exec —— 裸内建才算逃逸
    'python3 -c "self.system(1)"',
    'python3 -c "print(obj.exec(1))"',
]


@pytest.mark.parametrize("cmd", BENIGN)
def test_benign_inline_payload_allowed(bash, cwd: Path, cmd: str):
    decision, reason = bash(cmd, cwd)
    assert RULE not in (reason or ""), f"{cmd!r} 误报：{reason}"


def test_opaque_payload_not_double_reported(bash, cwd: Path):
    """载荷不是字面量时归 bash-opaque-inline-script，本规则不重复上报。"""
    decision, reason = bash('python3 -c "$(gen)"', cwd)
    assert decision in ("ask", "deny")
    assert RULE not in (reason or ""), f"不透明载荷被重复上报：{reason}"
