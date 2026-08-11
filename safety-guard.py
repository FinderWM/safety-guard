#!/usr/bin/env python3
"""Safety Guard Hook 与调试 CLI 的统一入口。"""
from __future__ import annotations

import os
import sys


def main() -> int:
    # 把入口脚本所在目录加入 sys.path，使 safety_guard 包可被导入
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)

    from safety_guard import cli, runner

    args = sys.argv[1:]
    if args[:1] == ["--adapter"]:
        if len(args) != 2:
            print("usage: safety-guard.py --adapter NAME", file=sys.stderr)
            return 2
        return runner.main_stdin(args[1])
    if args:
        return cli.main(args)
    return runner.main_stdin()


if __name__ == "__main__":
    raise SystemExit(main())
