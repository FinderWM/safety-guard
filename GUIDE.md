# Safety Guard 架构与扩展指南

Safety Guard 将不同工具平台的 Hook 输入统一转换为内部操作，再由同一套规则引擎完成检查。

核心目标：

- 多个平台共用一个规则引擎。
- 平台协议只存在于 Adapter。
- 规则只依赖规范化 Context。
- `__init__.py` 不负责导入、注册或自动加载。
- 新平台优先通过新增 Adapter 接入，不修改 Engine。
- 静态分析，不可解释 ⇒ 标记，不静默 allow；包装不降低防护等级。

## 运行链路

```text
平台 Hook JSON
    │
    ▼
Adapter.parse()
    │
    ▼
NormalizedRequest
    │
    ├── Operation 1
    ├── Operation 2
    └── Operation N
    │
    ▼
Engine.evaluate()
    │
    ├── Context.build()
    │     ├── Bash → bash_ast.parse/expand + folding + opaque 收集
    │     └── Write/Edit/NotebookEdit → paths.classify + disk lstat
    ├── Rules.match()
    └── Audit.write()
    │
    ▼
DecisionResult
    │
    ▼
Adapter.render()
    │
    ▼
平台原生 Hook JSON
```

Adapter 负责协议翻译，Engine 只处理统一数据结构。一个平台调用可以生成一个或多个
`Operation`，因此 Codex `apply_patch` 多文件操作无需 Engine 维护特殊分支。

入口：

| 调用 | 行为 |
| --- | --- |
| `python3 safety-guard.py` | stdin Hook 模式，默认 `claude` Adapter |
| `python3 safety-guard.py --adapter NAME` | stdin Hook 模式，指定 Adapter |
| `python3 safety-guard.py --list-rules / --explain / --selftest / --regression` | 调试 CLI（`cli.py`） |

## 项目结构

```text
safety-guard.py          # 统一入口：Hook stdin 或调试 CLI
safety_guard.toml        # 运行时配置（可随安装目录迁移）
GUIDE.md
tools/
└── replay.py            # 审计日志回放 / 决策基线对比
safety_guard/
├── adapters/
│   ├── base.py          # Adapter Protocol
│   ├── claude.py
│   ├── codex.py         # PreToolUse + PermissionRequest + apply_patch 解析
│   ├── grok.py          # Grok pre_tool_use / 顶层 decision
│   ├── fields.py        # tool_input / cwd 字段别名
│   └── registry.py
├── rules/
│   ├── base.py
│   ├── registry.py      # 按模块名字典序显式 import 并 @register
│   └── <rule>.py        # 当前 37 条
├── contracts.py         # Operation / NormalizedRequest / DecisionResult
├── runner.py            # stdin ↔ Adapter ↔ Engine
├── engine.py            # 聚合决策 + 审计
├── context.py           # BashContext / FileToolContext
├── config.py
├── audit.py
├── bash_ast.py          # bashlex 封装、wrapper 剥离、opaque 收集
├── expand.py            # brace / ANSI-C / 反斜杠确定性展开
├── folding.py           # 赋值序列常量折叠（$HOME 等）
├── interp.py            # 解释器 -c/-e 载荷抽路径/写删
├── paths.py             # in-cwd / instruction-zone / outside
├── helpers.py           # 规则共用：路径槽、只读判定、分支 glob 等
└── cli.py
tests/
├── rules/               # 规则与分析器回归
├── codex/               # Codex Adapter / apply_patch / hook 协议
├── grok/                # Grok Adapter / 原生 payload
├── fixtures/regression_commands.txt
├── test_runner.py
└── test_paths.py
```

| 模块 | 职责 |
| --- | --- |
| `contracts.py` | 定义统一输入、操作和决策 |
| `adapters/` | 解析平台输入并渲染平台输出 |
| `adapters/registry.py` | 注册和选择 Adapter |
| `runner.py` | 连接标准输入、Adapter 和 Engine |
| `engine.py` | 构造 Context、执行规则并聚合决策 |
| `context.py` | 将 Operation 转换为规则可消费的 Context |
| `bash_ast.py` | 解析命令、剥 wrapper、展开 `sh -c` 字面载荷、收集 opaque |
| `expand.py` | 路径槽位的 brace / ANSI-C 等确定性展开 |
| `folding.py` | 把 `A=$HOME/.s; cat $A$B` 折成确定字面量 |
| `paths.py` | 路径分类（不 follow symlink；链接位置决定归属） |
| `helpers.py` | 规则侧共用遍历与判定 |
| `rules/base.py` | 定义 Rule 和 RuleMatch |
| `rules/registry.py` | 显式加载并注册规则 |
| `audit.py` | 按日 jsonl + 轮转清理 |
| `cli.py` | `--list-rules` / `--explain` / `--selftest` / `--regression` |
| `tools/replay.py` | 用真实 audit 建基线、改规则前后对比 |

`safety_guard/__init__.py`、`adapters/__init__.py` 和
`rules/__init__.py` 均为空文件，只用于声明 Python 包。

## 统一协议

统一协议定义在 `safety_guard/contracts.py`。

### Operation

```python
Operation(
    tool="Bash",
    tool_input={"command": "git status"},
)
```

每个 Operation 是一项可独立执行规则检查的规范化操作。当前 Context 支持：

- `Bash`
- `Write`
- `Edit`
- `NotebookEdit`

不同平台的原始工具名不需要一致，只需由 Adapter 映射为这些内部操作。

`FileToolContext` 额外字段：

- `edit_mode`：NotebookEdit 的 `replace` / `insert` / `delete`
- `patch_action`：Codex apply_patch 映射后的 `add` / `update` / `delete`

### NormalizedRequest

```python
NormalizedRequest(
    adapter="codex-pretool",
    event="PreToolUse",
    tool="ApplyPatch",
    operations=(...),
    cwd="/workspace/project",
    audit_input="*** Begin Patch ...",
)
```

字段说明：

- `adapter`：产生该请求的 Adapter 名。
- `event`：平台事件名。
- `tool`：用于审计的顶层工具名（可与内部 Operation.tool 不同）。
- `operations`：Engine 实际检查的操作列表。
- `cwd`：本次调用的工作目录。
- `audit_input`：写入审计日志的原始输入。

### DecisionResult

```python
DecisionResult(
    decision="deny",
    reason="...",
)
```

Engine 只返回三种统一决策：

- `allow`
- `ask`
- `deny`

平台是否使用 `hookSpecificOutput`、`systemMessage` 或其他字段，由 Adapter 决定。

## Bash 分析栈

规则不直接碰 bashlex。`context.build()` 对 Bash 走：

```text
command
  → bash_ast.parse()
  → bash_ast.expand(wrappers)   # 剥 rtk/sudo/env…；展开字面 sh -c；收集 opaque
  → folding（赋值 env 回填 path_text）
  → paths.classify / expand.candidates（brace 等）
```

要点：

- **Wrapper 等价**：`rtk rm -rf /` 与 `rm -rf /` 同级拦截；任意 wrapper 可携带 `NAME=VALUE`。
- **argv0 规范化**：`helpers.normalize_cmd_name` 去掉 `/usr/bin/` 等前缀；AST 的 `CommandSpec.name` 在构建时已是裸名，`/bin/rm` 与 `rm` 同级匹配。
- **管道执行端**：`bash-pipe-to-shell` 终点含 shell、`busybox sh`、以及 python/node 等 `EXEC_INTERPRETERS`；起点含 curl/wget/nc 等（经 basename）。
- **stdin 拉码**：`bash -s < <(curl…)` / `zsh <(curl…)` / `source /dev/stdin <<< "$(curl…)"` → `bash-remote-stdin-exec`（high）；无网络字面时归 opaque。
- **`-c` 混淆**：`$'-c'` 等 ANSI-C 选项经 source 切片 + expand 后再识别；`env -S '…'` 字面载荷再 shlex 拆词。
- **outside 脚本执行**：`bash /out/x.sh`、`python3 /out/x.py` → `bash-outside-script-exec`。
- **审计/理由脱敏**：`redact_user_paths` 把真实家目录打成 `$HOME`，避免 jsonl/确认框泄漏用户名路径。
- **busybox/toybox 多调用**：`unwrap` 后剥成真实 applet（`busybox cat` → `cat`）；`xargs -a FILE` 继承读源。
- **折叠失败诚实**：算不出的 word `folded=None`，由 `bash-unresolvable-path` 等规则消费，不退回原文假装安全。
- **路径分类**：`in-cwd` / `instruction-zone` / `outside`；CWD 内 symlink 按链接位置算 in-cwd。
- **Parse 失败**：`parse_error` 非空时 Engine 默认 fail-closed → `deny`（可 `SAFETY_GUARD_FAIL_OPEN=1`）。

## Adapter 注册与选择

内置 Adapter 集中注册在 `safety_guard/adapters/registry.py`：

| Adapter 名 | 平台事件 | 输入工具 |
| --- | --- | --- |
| `claude` | Claude Code `PreToolUse` | `Bash` / `Write` / `Edit` / `NotebookEdit` / `Read` / `Grep` / `Glob` |
| `codex-pretool` | Codex `PreToolUse` | `Bash`/`shell` + `apply_patch` |
| `codex-permission` | Codex `PermissionRequest` | 同上 |
| `grok` | Grok `pre_tool_use` / `PreToolUse` | `run_terminal_command` / `write` / `search_replace` / `read_file` / `list_dir` / `grep`（及 Bash/Write/Edit/Read 别名） |

选择优先级：

1. 调用方显式传入 Adapter 名（`--adapter`）。
2. 环境变量 `SAFETY_GUARD_ADAPTER`。
3. 默认使用 `claude`。

正式调用方式：

```bash
python3 safety-guard.py --adapter codex-pretool
python3 safety-guard.py --adapter codex-permission
python3 safety-guard.py --adapter grok
```

### Claude 渲染

- `allow` → 空对象 `{}`（平台默认放行）
- `ask` / `deny` → `hookSpecificOutput.permissionDecision` + reason

### Codex 渲染

- `allow` → `{}`
- `ask` / `deny` + PreToolUse → `permissionDecision: deny`（medium 升 deny，避免只提示不拦）
- `ask` / `deny` + PermissionRequest → `decision.behavior: deny`

### Grok 渲染

- `allow` → `{"decision": "allow"}`
- `ask` / `deny` → `{"decision": "deny", "reason": "..."}`（无 ask UI，medium 升 deny）
- 输入兼容 camelCase（`hookEventName` / `toolName` / `toolInput`）与 snake_case
- `search_replace`：空 `old_string` → 内部 `Write`；非空 → 内部 `Edit`
- 原生工具名 `write`（小写）映射为内部 `Write`
- `read_file` / `list_dir` / `grep`（及 Claude `Read`/`Grep`/`Glob`）映射为内部 `Read`；指令区只读仍豁免
- `tool_input` 兼容 `arguments` / `input`；`cwd` 兼容 `workspace_path` / `working_directory`

### Codex `apply_patch` → 多 Operation

`codex.py` 解析 `*** Begin Patch` … `*** End Patch`：

| Patch 动作 | 内部 Operation |
| --- | --- |
| `Add File` | `Write` + `patch_action=add` |
| `Update File` | `Edit` + `patch_action=update` |
| `Delete File` | `Edit` + `patch_action=delete` |
| `Update` + `Move to` | 先 `delete` 旧路径，再 `add` 新路径 |

`file-patch-delete` 仅在 `patch_action=delete` 时 ask。

## 审计字段（优化拦截）

每次真实 Hook（未设 `SAFETY_GUARD_NO_AUDIT`）在 **render 之后** 写一行 jsonl：

| 字段 | 含义 |
| --- | --- |
| `adapter` | 平台适配器（`claude` / `grok` / `codex-*`） |
| `engine_decision` | 规则引擎结论 `allow`/`ask`/`deny` |
| `rendered_decision` | 写入平台后的对外结论（如 Grok 将 ask 升为 deny） |
| `decision` | 兼容旧字段，等于 `engine_decision`（`dry_run` 时带 `dry-run-` 前缀） |
| `cmd_body` | 脱敏后的完整输入（≤8192 字符时存在，供精确回放） |
| `cmd_truncated` | 超长为 true，此时仅有 `cmd_preview` |
| `cmd_preview` | 预览（保留换行；超长截断到 4096+…） |
| `hook_event` | 规范化事件名 |
| `matches` | 命中规则 id/severity/reason/extra |

`tools/replay.py` 优先用 `cmd_body`，并与 `engine_decision` 对比。

## 接入新平台

如果新平台可以映射到现有 Operation，只需新增 Adapter。

### 实现 Adapter

```python
from typing import Any

from .base import Adapter
from ..contracts import DecisionResult, NormalizedRequest, Operation


class ExampleAdapter:
    name = "example"

    def parse(self, stdin_json: dict[str, Any]) -> NormalizedRequest | None:
        if stdin_json.get("event") != "before_tool":
            return None

        command = stdin_json["input"]["command"]
        return NormalizedRequest(
            adapter=self.name,
            event="before_tool",
            tool="shell",
            operations=(Operation("Bash", {"command": command}),),
            cwd=stdin_json["cwd"],
            audit_input=command,
        )

    def render(self, result: DecisionResult) -> dict[str, Any]:
        return {
            "decision": result.decision,
            "reason": result.reason,
        }
```

Adapter 的约束：

- 无关事件返回 `None`。
- 非法输入抛出异常，由 Runner 按 `fail_open` 处理。
- 不直接执行规则。
- 不读取规则 Registry。
- 不写审计。
- 只负责平台协议与统一协议之间的转换。

### 注册 Adapter

在 `safety_guard/adapters/registry.py` 中注册一个实例：

```python
register(ExampleAdapter())
```

之后可直接调用：

```bash
python3 safety-guard.py --adapter example
```

不需要新增入口脚本或修改 Engine。

### 新增内部操作

只有当新平台能力无法映射到现有 `Bash`、`Write`、`Edit` 或
`NotebookEdit` 时，才新增内部 Operation 类型。

此时需要：

1. 在 `context.py` 中构造对应 Context。
2. 在规则的 `applies_to` 中声明新工具名。
3. 添加 Context 和规则测试。
4. 让目标 Adapter 生成该 Operation。

不要为平台原始工具名直接修改 Engine。

## 新增规则

规则协议和注册逻辑已经分离：

```python
from .base import Rule, RuleMatch
from .registry import register


@register
class ExampleRule(Rule):
    id = "example-rule"
    severity = "medium"
    applies_to = ("Bash",)
    description = "示例规则"

    def match(self, ctx):
        if "example" not in ctx.raw_command:
            return None
        return RuleMatch(
            rule_id=self.id,
            severity=self.severity,
            reason="检测到 example",
        )
```

`rules/registry.py` 会按模块名字典序显式加载规则模块（跳过 `base` /
`registry` / `_` 前缀）。`rules/__init__.py` 不执行自动发现。

规则只读 Context：Bash 用 `ctx.ast` / `ctx.opaque_payloads` /
`ctx.classify()`；文件工具用 `ctx.target_path` / `ctx.classification` /
`ctx.file_exists` / `ctx.patch_action`。共用逻辑放 `helpers.py`，不要在规则里重解析命令。

### 当前规则一览（37）

`python3 safety-guard.py --list-rules` 可打印完整描述。

### high → deny

| id | 工具 | 摘要 |
| --- | --- | --- |
| `bash-disable-safety-hook` | Bash | 写/删 safety-guard 自身或 critical_paths |
| `bash-env-subversion` | Bash | `PATH` / `LD_PRELOAD` / `BASH_ENV` 等语义颠覆 |
| `bash-eval-from-network` | Bash | `eval` / `sh -c` 包裹网络抓取 |
| `bash-find-delete-unbounded` | Bash | `find /` 或 `find ~` + `-delete` / `-exec rm` |
| `bash-git-push-force-protected` | Bash | `git push --force` 到保护分支 |
| `bash-interpreter-shell-escape` | Bash | 解释器内联载荷里再调 shell |
| `bash-pipe-to-shell` | Bash | `curl\|sh` / `curl\|/bin/bash` / `curl\|python3` / `nc\|bash` 等管道执行 |
| `bash-remote-stdin-exec` | Bash | shell/source 从 stdin/进程替换执行且含网络抓取 |
| `bash-rm-root-or-home` | Bash | `rm` 目标为 `/` 或 `$HOME` |
| `bash-sql-drop-database` | Bash | `DROP DATABASE` / `DROP SCHEMA` |
| `file-critical-path-write` | Write/Edit/NotebookEdit | 写入 critical_paths |
| `bash-interpreter-write` | Bash | 解释器 -c/-e 写/删 critical_paths |

### medium → ask

| id | 工具 | 摘要 |
| --- | --- | --- |
| `bash-cp-mv-overwrite-existing` | Bash | `cp`/`mv` 覆盖已存在目标 |
| `bash-credential-export` | Bash | gpg/security/kubectl 等凭据导出或密钥读取 |
| `bash-find-exec-rm` | Bash | 非根/家起点 `find -delete` 或 `-exec` + rm 家族 |
| `bash-interpreter-write` | Bash | 解释器 -c/-e 写/删非 critical 文件 |
| `bash-util-overwrite-existing` | Bash | `truncate` / `dd of=` 覆盖已存在文件 |
| `bash-gh-close` | Bash | `gh` 关闭/删除远端资源 |
| `bash-git-destructive` | Bash | `reset --hard` / `clean -f` / `branch -D` 等 |
| `bash-instruction-zone-write` | Bash | 写指令区 |
| `bash-interpreter-remote-exec` | Bash | 解释器载荷同时网络取指 + exec/eval |
| `bash-interpreter-outside-path` | Bash | 解释器 -c/-e 字面量越界路径 |
| `bash-opaque-inline-script` | Bash | 内联/占位/进程替换/stdin 脚本，内层静态不可见 |
| `bash-outside-cwd-read` | Bash | 读 CWD 外（指令区只读豁免） |
| `bash-outside-cwd-write` | Bash | 非只读命令碰 CWD 外 |
| `bash-outside-script-exec` | Bash | shell/解释器执行 CWD 外脚本文件 |
| `bash-redirect-overwrite-existing` | Bash | `>` 覆盖已存在文件 |
| `bash-rm-targeted` | Bash | 非根/家的 `rm` |
| `bash-sensitive-path-scan` | Bash | 敏感路径/密钥字面量（含 expand 候选） |
| `bash-sql-delete-truncate` | Bash | `DELETE` / `TRUNCATE` |
| `bash-symlink-create` | Bash | `ln` / `ln -s` / `cp -s` |
| `bash-tee-overwrite-existing` | Bash | 无 `-a` 的 `tee` |
| `bash-unresolvable-path` | Bash | 路径槽静态不可解释 |
| `file-instruction-zone-write` | Write/Edit/NotebookEdit | 写指令区 |
| `file-outside-cwd` | Write/Edit/NotebookEdit/Read | 目标在 CWD 外 |
| `file-overwrite-existing` | Write | 整文件覆盖 |
| `file-patch-delete` | Edit | apply_patch 删除 |
| `notebook-delete` | NotebookEdit | `edit_mode=delete` |

改包内文件时若命中自保，可临时把
`file-critical-path-write`（及必要时 `bash-disable-safety-hook`）写入
`disabled_rules`；改完务必清空并复检。

## 决策聚合

Engine 对一次请求中的全部 Operation 执行规则：

- 任意规则命中 `high`，最终结果为 `deny`。
- 没有 `high`，但存在 `medium`，最终结果为 `ask`。
- 没有规则命中，最终结果为 `allow`。
- `severity_overrides` 可在聚合前改写单条 severity。

规则执行异常会转换为 `high`，避免单条规则崩溃后静默放行。

Bash 解析失败默认 fail-closed。临时故障恢复可以使用：

```bash
SAFETY_GUARD_FAIL_OPEN=1 python3 safety-guard.py --adapter codex-pretool
```

`dry_run=true` 时仍写审计（决策前缀 `dry-run-`），但对平台始终返回 `allow`。

## 配置与环境变量

主要配置位于安装根目录的 `safety_guard.toml`。

查找顺序（`config.py`）：

1. `SAFETY_GUARD_CONFIG` 指向的文件
2. 安装根目录下的 `safety_guard.toml`

`load()` 永不抛：解析失败回退最小安全默认值，避免包损坏后无法再编辑自愈。
`critical_paths` 用户配置与默认**合并**（默认始终保护入口脚本 + `safety_guard/` 包目录）。

常用 TOML 字段：

| 字段 | 作用 |
| --- | --- |
| `disabled_rules` | 禁用规则 id 列表 |
| `severity_overrides` | `{ rule_id = "high"\|"medium" }` |
| `protected_branches` | force-push 保护分支 glob |
| `read_only_zones` | 指令区等：读豁免、写仍 ask |
| `read_only_commands` | 只读命令白名单 |
| `wrapper_commands` | 前缀包装命令（剥掉后按内层分发） |
| `wrapper_specs.<name>` | 包装剥层语义：`value_opts` / `skip_positional` / `subcommands` |
| `critical_paths` | 高危路径（与默认自保合并） |
| `fail_open` / `dry_run` | 行为开关 |
| `audit_dir` / `audit_retention_days` / `audit_max_*_mb` | 审计 |

| 环境变量 | 作用 |
| --- | --- |
| `SAFETY_GUARD_ADAPTER` | 选择 Adapter |
| `SAFETY_GUARD_CONFIG` | 指定配置文件路径 |
| `SAFETY_GUARD_FAIL_OPEN=1` | 内部异常 / 解析失败时放行 |
| `SAFETY_GUARD_DRY_RUN=1` | 记录决策但始终放行 |
| `SAFETY_GUARD_NO_AUDIT=1` | 禁用审计写入 |
| `SAFETY_GUARD_IGNORE_DISABLED_RULES=1` | 忽略 `disabled_rules`（测试用） |

## 不透明执行（expand 收集器）

`bash_ast.expand()` 除展开 wrapper 与 `sh -c` 字面载荷外，还会收集运行时才成形的执行形态，写入 `opaque_payloads`：

| kind | 形态 | 规则 |
| --- | --- | --- |
| `inline-script` | `bash -c "$(gen)"` / `eval "$(…)"` | `bash-opaque-inline-script`（medium） |
| `placeholder` | `xargs -I{} sh -c '{}'`（字面 `{}` 禁止再 parse） | 同上 |
| `process-subst` | `bash <(curl …)` / `source <(…)` / `. <(…)` | 同上 |
| `find-exec` | `find … -exec/-execdir …` | 仅结构标记；rm 家族由 `bash-find-exec-rm` ask |

`find / … -exec rm` 仍由 `bash-find-delete-unbounded`（high）deny；`find . -delete` 与 `find . -exec rm` 由 `bash-find-exec-rm` ask；`find . -exec grep` allow。

## 调试命令

```bash
python3 safety-guard.py --list-rules
python3 safety-guard.py --explain --tool Bash --command "git status"
python3 safety-guard.py --explain --tool Write --path ./existing.txt
python3 safety-guard.py --selftest
python3 safety-guard.py --regression

# 审计回放（改规则前后对比）
python3 tools/replay.py --save /tmp/before.json
python3 tools/replay.py --compare /tmp/before.json
python3 tools/replay.py --compare /tmp/before.json --rule bash-env-subversion
```

## 验证要求

修改核心链路后至少执行：

```bash
python3 -m pytest -q
SAFETY_GUARD_IGNORE_DISABLED_RULES=1 python3 safety-guard.py --regression
```

关键测试应覆盖：

- 每个 Adapter 的输入解析和输出渲染。
- 未知工具和非法输入的 fail-closed 行为。
- 多 Operation 聚合（含 apply_patch）。
- 真实 stdin 入口。
- 规则注册和禁用规则。
- Bash 解析失败及审计记录。
- Wrapper 等价（`test_equivalence.py`）。
- 不透明执行：placeholder / process-subst / find-exec-rm（`test_opaque_execution.py`）。
- 不可解析路径、环境变量颠覆、折叠/展开边界。

合成探针请用 `/nonexistent-probe/…`、`../../sibling/…`，不要读本机真实隐私路径。

## 设计边界

- Engine 不导入 Adapter Registry。
- Adapter 不导入规则或 Context。
- Runner 是平台入口与 Engine 之间唯一的编排层。
- Registry 负责注册，`__init__.py` 不负责注册。
- 不保留 Harness、ToolEvent 或 FanoutUnit 兼容类。
- 每个平台通过 `--adapter` 或 `SAFETY_GUARD_ADAPTER` 选择，不创建额外入口文件。
- 分析失败与规则崩溃默认 fail-closed；仅运维显式打开 `fail_open` / `dry_run` 时放宽。
