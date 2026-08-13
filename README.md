# Safety Guard

面向 AI 编程助手的 **PreToolUse 安全闸门**：在命令真正执行前，用静态分析拦截破坏性、越界与不可解释的操作。

它不是 OS sandbox，也不替代人工审查。目标是把「误删家目录 / force-push main / 管道执行远端脚本 / 改掉 hook 自身」等高代价失误，在 Hook 层挡下来或强制二次确认。

当前内置 **Claude Code**、**Codex** 与 **Grok** 适配器，**37** 条规则、同一套引擎。

## 它做什么

| 决策 | 含义 |
| --- | --- |
| `allow` | 放行 |
| `ask` | 需要用户确认（medium） |
| `deny` | 直接拒绝（high） |

典型拦截面：

- **整盘/整家删除**：`rm -rf /`、`find / -delete`、`find ~ -exec rm`
- **破坏性 git / 远端**：`git reset --hard`、`git push --force` 到保护分支、`gh pr close`
- **远程代码执行**：`curl | sh`、`curl | /bin/bash`、`curl | python3`、`eval "$(curl …)"`、`bash -s < <(curl…)`、解释器 urlopen+exec
- **环境颠覆**：`PATH=` / `LD_PRELOAD=` / `BASH_ENV=` 前缀赋值
- **越界读写**：CWD 外路径（含 `read_file` / `Read` / `grep`）；`~/.claude` / `~/.agents` 等指令区写入需确认
- **整文件覆盖 / 删格**：`Write` 覆盖已有文件、`NotebookEdit delete`、`apply_patch` 删除
- **自保**：拒绝改写 safety-guard 入口、包目录及配置中的 `critical_paths`
- **不可解释即标记**：路径槽静态算不清、内联/占位脚本运行时才成形 → ask，不静默放行
- **包装不降级**：`rtk rm -rf /`、`sudo env FOO=1 rm …` 与裸命令同级拦截

## 工作原理（一句话）

```text
平台 Hook JSON → Adapter.parse → Operation(s) → Engine + 规则 → Decision → Adapter.render → 平台 JSON
```

平台协议只活在 Adapter 里；规则只吃规范化 `Context`。Codex 的一次 `apply_patch` 会拆成多个 `Write`/`Edit` Operation，由同一引擎聚合决策。

更完整的架构、扩展 Adapter/规则、规则全表见 **[GUIDE.md](./GUIDE.md)**。

## 支持平台

| Adapter | 事件 | 工具 |
| --- | --- | --- |
| `claude`（默认） | Claude Code `PreToolUse` | `Bash` / `Write` / `Edit` / `NotebookEdit` / `Read` / `Grep` / `Glob` |
| `codex-pretool` | Codex `PreToolUse` | `Bash`/`shell`、`apply_patch` |
| `codex-permission` | Codex `PermissionRequest` | 同上 |
| `grok` | Grok `pre_tool_use` / `PreToolUse` | `run_terminal_command`、`write`、`search_replace`、`read_file`、`list_dir`、`grep`（及 Bash/Write/Edit/Read 别名） |

选择优先级：`--adapter` 参数 → 环境变量 `SAFETY_GUARD_ADAPTER` → 默认 `claude`。

## 快速开始

### 依赖

- Python **3.11+**（使用 `tomllib`）
- [bashlex](https://github.com/idank/bashlex)
- 开发/测试：`pytest`

```bash
pip install bashlex pytest
```

### 安装

把本仓库放到任意目录（示例 `~/src/safety-guard`），保证 `safety-guard.py` 与 `safety_guard/` 同级：

```text
safety-guard/
├── safety-guard.py
├── safety_guard.toml
├── safety_guard/
├── tests/
├── tools/
├── GUIDE.md
└── README.md
```

### 接入 Claude Code

在用户或项目的 settings 中注册 `PreToolUse` 命令钩子（路径改成你的安装位置）：

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Write|Edit|NotebookEdit|Read|Grep|Glob",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /path/to/safety-guard/safety-guard.py"
          }
        ]
      }
    ]
  }
}
```

### 接入 Codex

PreToolUse / PermissionRequest 分别指定 adapter：

```bash
python3 /path/to/safety-guard/safety-guard.py --adapter codex-pretool
python3 /path/to/safety-guard/safety-guard.py --adapter codex-permission
```

（具体挂载字段以你使用的 Codex Hook 配置为准；stdin 需为平台原生 JSON。）

### 接入 Grok

在 `~/.grok/config.toml`（或 `~/.grok/hooks/*.json`）注册 `PreToolUse`，**必须**指定 `--adapter grok`（默认 `claude` 认不出 Grok 的事件名/工具名，会静默放行）：

```toml
[[hooks.PreToolUse]]
matcher = "Bash|Write|write|Edit|run_terminal_command|search_replace|read_file|list_dir|grep"
hooks = [
  { type = "command", command = "python3 /path/to/safety-guard/safety-guard.py --adapter grok", timeout = 10 },
]
```

Grok 侧 `ask`（medium）会升为顶层 `{"decision":"deny","reason":"..."}`，因为 PreToolUse 没有 Claude 式确认 UI。

### 立刻试一次

```bash
# 列出全部规则
python3 safety-guard.py --list-rules

# 干跑一条命令（不输出 hook JSON，只打印决策）
python3 safety-guard.py --explain --tool Bash --command 'rm -rf /'
python3 safety-guard.py --explain --tool Bash --command 'git status'
python3 safety-guard.py --explain --tool Write --path ./README.md
```

## 配置

运行时读安装根目录的 `safety_guard.toml`（或 `SAFETY_GUARD_CONFIG` 指向的文件）。修改后**无需重启** CLI，下次 Hook 调用重新加载。

常用项：

| 字段 | 说明 |
| --- | --- |
| `disabled_rules` | 临时关掉某些规则 id |
| `severity_overrides` | 单条规则升/降级 |
| `protected_branches` | force-push 保护分支（默认 `main` / `master` / `release/*`） |
| `read_only_zones` | 读豁免区（写仍 ask） |
| `read_only_commands` | 只读命令白名单 |
| `wrapper_commands` | 前缀包装（`rtk` / `sudo` / `env` …）；只加名字即可当纯前缀剥 |
| `wrapper_specs.<name>` | 包装怎么剥：`value_opts` / `skip_positional` / `subcommands` |
| `critical_paths` | 高危路径（**与默认自保合并**，不会丢掉入口脚本保护） |
| `fail_open` / `dry_run` | 异常放行 / 只审计不拦截 |
| `audit_*` | 审计目录与保留策略 |

环境变量（优先级高于 TOML）：

| 变量 | 作用 |
| --- | --- |
| `SAFETY_GUARD_ADAPTER` | 选择 Adapter |
| `SAFETY_GUARD_CONFIG` | 指定配置文件 |
| `SAFETY_GUARD_FAIL_OPEN=1` | 内部异常/解析失败时放行（默认 fail-closed） |
| `SAFETY_GUARD_DRY_RUN=1` | 始终 allow，但仍写审计 |
| `SAFETY_GUARD_NO_AUDIT=1` | 不写审计（测试/回放） |
| `SAFETY_GUARD_IGNORE_DISABLED_RULES=1` | 忽略 `disabled_rules` |

审计默认写在安装目录下 `audit/audit-YYYY-MM-DD.jsonl`，含命令预览与决策，**上传仓库前请勿提交真实审计**（含本机路径与历史命令）。

## 调试与回归

```bash
python3 safety-guard.py --selftest      # pytest tests/
python3 safety-guard.py --regression    # fixtures/regression_commands.txt

python3 -m pytest -q
SAFETY_GUARD_IGNORE_DISABLED_RULES=1 python3 safety-guard.py --regression

# 用真实审计做改规则前后对比（可选）
python3 tools/replay.py --save /tmp/before.json
python3 tools/replay.py --compare /tmp/before.json
```

## 设计原则

1. **静态分析**，不是容器/权限沙箱。
2. **不可解释 ⇒ 标记，不静默 allow**。
3. **包装不降低防护等级**（`rtk`/`sudo`/`env` 等价于内层命令）。
4. **Adapter 与 Engine 解耦**：新平台优先加 Adapter，不改规则引擎。
5. **默认 fail-closed**：Bash 解析失败、规则崩溃 → deny（可用环境变量临时打开）。
6. **自保优先**：`critical_paths` 默认包含入口脚本与包目录，避免 hook 被自己改坏后无法修复。

## 项目结构

```text
safety-guard.py       # Hook stdin + 调试 CLI 统一入口
safety_guard.toml     # 配置
safety_guard/         # 引擎、Adapter、规则、bash 分析栈
tests/                # 单元 / 规则 / Codex 协议测试
tools/replay.py       # 审计回放
GUIDE.md              # 架构与扩展指南（给贡献者）
```

扩展新平台或新规则的步骤、规则 id 全表、opaque 执行说明 → **[GUIDE.md](./GUIDE.md)**。

## 局限（请先读）

- 只能看到 Hook 交给它的文本；运行时动态生成且未被捕获的载荷无法保证可见。
- 路径存在性类规则（覆盖已有文件等）依赖**当时**磁盘状态；回放审计时可能与历史不一致。
- 不是对恶意 Agent 的完整对抗方案；对抗目标主要是**失误与常见绕过形态**。
- 过严时用 `disabled_rules` / `severity_overrides` / `dry_run` 调参，而不是直接拆掉 Hook。

## 许可证

本项目采用 **[GNU GPLv3](./LICENSE)**（与运行时依赖 [bashlex](https://github.com/idank/bashlex) 的 GPLv3+ 对齐）。

**为何选 GPL 而不是 MIT/Apache：**

| 选项 | 结论 |
| --- | --- |
| **GPLv3**（采用） | 与 bashlex 同源 copyleft；再分发须保持自由软件义务；适合独立 Hook 工具 |
| MIT / Apache-2.0 | 自身宽松，但连带 bashlex 再分发仍受 GPLv3 约束，对外声明易误导 |
| AGPLv3 | 本项目是本地 CLI/Hook，无多租户网络服务场景，AGPL 过重 |
| 专有 / 不授权 | 不利于社区复用与审计规则贡献 |

简要义务：分发本软件（含修改版）时须提供对应源代码，并以 GPLv3 兼容方式授权；完整条文见 `LICENSE`。

## 相关

- 架构细节与贡献指南：[GUIDE.md](./GUIDE.md)
- Shell 解析：[bashlex](https://github.com/idank/bashlex)（GPLv3+）
- Claude Code Hooks 文档：以 Anthropic / Claude Code 官方说明为准
- Codex Hooks：以你所用 Codex 版本的 Hook 协议为准
