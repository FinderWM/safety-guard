# Safety Guard

面向 AI 编程助手的 **PreToolUse 安全闸门**：在命令真正执行前，用静态分析拦截破坏性、越界与不可解释的操作。

它不是 OS sandbox，也不替代人工审查。目标是把「误删家目录 / force-push main / 管道执行远端脚本 / 改掉 hook 自身」等高代价失误，在 Hook 层挡下来或强制二次确认。

当前内置 **Claude Code**、**Codex** 与 **Grok** 适配器，**43** 条规则、同一套引擎。

## 它做什么

| 决策 | 含义 |
| --- | --- |
| `allow` | 放行 |
| `ask` | 需要用户确认（medium） |
| `deny` | 直接拒绝（high） |
| `abstain` | 当前审查器不做决定，交还平台原生权限流程 |

典型拦截面：

- **整盘/整家删除**：`rm -rf /`、`find / -delete`、`find ~ -exec rm`
- **破坏性 git / 远端**：`git reset --hard`、`git push --force` 到保护分支、`gh pr close`
- **远程代码执行**：`curl | sh`、`curl | /bin/bash`、`curl | python3`、`eval "$(curl …)"`、`bash -s < <(curl…)`、解释器 urlopen+exec
- **环境颠覆**：`PATH=` / `LD_PRELOAD=` / `BASH_ENV=` 前缀赋值
- **越界读写**：CWD 外路径（含 `read_file` / `Read` / `grep`）；`~/.claude` / `~/.agents` 等指令区写入需确认
- **整文件覆盖 / 删格**：`Write` 覆盖已有文件、`NotebookEdit delete`、`apply_patch` 删除
- **外部上传**：工作区普通文件要求确认；敏感文件、CWD 外文件或 symlink 外传直接拒绝
- **自保**：文件工具写入 safety-guard 入口、包目录及 `critical_paths` 时要求确认；Bash 写删仍直接拒绝
- **已建模但不可解释即标记**：路径槽、动态 argv[0]、内联/命令槽载荷静态算不清 → medium/ask；可确定的二级命令重新进入完整规则分析
- **未知工具先审查**：进入可插拔 reviewer；reviewer 可 deny/ask，但 allow 只按 `abstain` 处理，不替代平台授权
- **包装不降级**：`rtk rm -rf /`、`sudo env FOO=1 rm …` 与裸命令同级拦截

## 工作原理（一句话）

```text
平台 Hook JSON → Adapter.parse → 已建模 Operation(s) / 未知 reviewer → Engine → Adapter.render → 平台 JSON
```

平台协议只活在 Adapter 里；规则只吃规范化 `Context`。Codex 的一次 `apply_patch` 或带多个本机路径的 MCP 调用会拆成多个 Operation，由同一引擎聚合决策。

更完整的架构、扩展 Adapter/规则、规则全表见 **[GUIDE.md](./GUIDE.md)**。

## 支持平台

| Adapter | 事件 | 工具 |
| --- | --- | --- |
| `claude`（默认） | Claude Code `PreToolUse` | `Bash` / `Write` / `Edit` / `NotebookEdit` / `Read` / `Grep` / `Glob` |
| `codex-pretool` | Codex `PreToolUse` | `Bash`/`shell`、`apply_patch`、`Edit`、`Write`、`Read`、`view_image`、当前 Chrome DevTools MCP 及未知本地工具入口 |
| `codex-permission` | Codex `PermissionRequest` | 同上 |
| `grok` | Grok `PreToolUse`（兼容 `pre_tool_use`） | `run_terminal_command`、`write`、`search_replace`、`read_file`、`list_dir`、`grep`（及 Bash/Write/Edit/Read 别名） |

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
├── safety_guard.toml.example
├── safety_guard/
├── tests/
├── tools/
├── GUIDE.md
└── README.md
```

复制示例生成本机配置；实际 `safety_guard.toml` 已被 Git 忽略：

```bash
cp safety_guard.toml.example safety_guard.toml
```

不创建配置文件时，程序使用 `safety_guard/config.py` 中的安全默认值。

### 接入 Claude Code

在用户或项目的 settings 中注册 `PreToolUse` 命令钩子（路径改成你的安装位置）：

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
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

在用户级 `~/.codex/hooks.json` 的 `hooks` 对象中为两个事件分别注册命令，并显式指定对应 Adapter；保留文件中已有的其它事件：

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": ".*",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /path/to/safety-guard/safety-guard.py --adapter codex-pretool",
            "timeout": 30,
            "statusMessage": "Checking safety guard"
          }
        ]
      }
    ],
    "PermissionRequest": [
      {
        "matcher": ".*",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /path/to/safety-guard/safety-guard.py --adapter codex-permission",
            "timeout": 30,
            "statusMessage": "Checking safety guard"
          }
        ]
      }
    ]
  }
}
```

不要用全局 `SAFETY_GUARD_ADAPTER` 替代命令行参数；两个 Hook 的事件协议不同，显式参数不会影响 Claude 或 Grok Adapter。

`matcher = ".*"` 让 Codex 当前支持的所有本地函数工具先经过 Adapter。截图、trace、network body 等显式输出路径复用文件写入规则；`upload_file` 根据路径位置和敏感性生成 ask/deny。无本机路径的已知工具直接继续，未知工具进入 reviewer，默认 `noop` 只返回 `abstain`。

Codex `PreToolUse` 目前不支持 `ask`：medium 结果不升级为 deny，而是通过 `systemMessage` / `additionalContext` 提示风险，不输出授权或阻断决定；`PermissionRequest` 的 medium/abstain 继续交给 Codex 原生审批。reviewer 的 allow 同样按 abstain 处理，不能跳过原生审批。

修改 Hook 定义后，在 Codex 中运行 `/hooks` 并重新信任变更；不要手动修改 `[hooks.state]` 的信任哈希。

### 接入 Grok

在 `~/.grok/hooks/safety-guard.json` 注册 `PreToolUse`，**必须**指定 `--adapter grok`。省略 matcher 会覆盖全部工具，使未知工具也能进入 reviewer：

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "python3 /path/to/safety-guard/safety-guard.py --adapter grok",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

Grok 只有显式 `{"decision":"deny"}` 会阻断。high 输出 deny；allow、medium ask 与默认 unknown abstain 均保持空输出，由 Grok 原生权限模式继续处理。

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

运行时读安装根目录下由使用者创建的 `safety_guard.toml`（或
`SAFETY_GUARD_CONFIG` 指向的文件）。仓库只提交
`safety_guard.toml.example`；没有实际配置文件时使用代码中的安全默认值。修改后
**无需重启** CLI，下次 Hook 调用重新加载。

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
| `critical_paths` | 高危路径（与默认自保合并）；文件工具写入需确认，Bash 写删直接拒绝 |
| `fail_open` / `dry_run` | 异常放行 / 只审计不拦截 |
| `unknown_reviewer` / `reviewer_timeout_ms` | 未知工具 reviewer 名称与超时；默认 `noop` / 250ms |
| `audit_include_body` | 是否把脱敏后的正文写入审计；默认 false |
| `audit_*` | 审计目录与保留策略 |

配置读取或解析失败时，会回退到 fail-closed 默认值，仍保护 Claude、Codex、Grok 的控制文件；审计只记录 `config_load_error` 类型，不记录底层异常详情。

环境变量（优先级高于 TOML）：

| 变量 | 作用 |
| --- | --- |
| `SAFETY_GUARD_ADAPTER` | 选择 Adapter |
| `SAFETY_GUARD_CONFIG` | 指定配置文件 |
| `SAFETY_GUARD_FAIL_OPEN=1` | 内部异常/解析失败时放行（默认 fail-closed） |
| `SAFETY_GUARD_DRY_RUN=1` | 本 Hook 不输出阻断，但仍写审计；原生权限流程保留 |
| `SAFETY_GUARD_AUDIT_INCLUDE_BODY=1` | 显式允许审计写入脱敏后的输入正文 |
| `SAFETY_GUARD_NO_AUDIT=1` | 不写审计（测试/回放） |
| `SAFETY_GUARD_IGNORE_DISABLED_RULES=1` | 忽略 `disabled_rules` |

审计默认写在安装目录下 `audit/audit-YYYY-MM-DD.jsonl`。新建目录使用 `0700`、日志文件使用 `0600`；既存目录若不是 `0700` 会拒绝写入，不会替用户改权限。轮转只管理带 Safety Guard schema 标记的日志。默认只保存 digest、字符数、行数、规则 id/severity 与决策，不保存命令、补丁、正文或 match 详情。只有显式启用 `audit_include_body` 才写脱敏正文；**不要提交真实审计**。

`rendered_decision=abstain` 表示 Adapter 没有向平台输出显式决策。Claude/Codex 的策略 allow 不会替代原生权限流程；Grok 协议则把退出 0 且无输出视为 allow。

## 调试与回归

```bash
python3 safety-guard.py --selftest      # pytest tests/
python3 safety-guard.py --regression    # fixtures/regression_commands.txt

python3 -m pytest -q
SAFETY_GUARD_IGNORE_DISABLED_RULES=1 python3 safety-guard.py --regression

# 仅在审计已显式保存正文时才能做精确回放（可选）
python3 tools/replay.py --save /tmp/before.json
python3 tools/replay.py --compare /tmp/before.json
```

## 设计原则

1. **静态分析**，不是容器/权限沙箱。
2. **只检测已建模行为**：未知工具进入 reviewer，默认 abstain，不由当前规则集拦截。
3. **包装不降低防护等级**（`rtk`/`sudo`/`env` 等价于内层命令）。
4. **Adapter 与 Engine 解耦**：新平台优先加 Adapter，不改规则引擎。
5. **已建模输入默认 fail-closed**：Bash 解析失败、规则崩溃 → deny（可用环境变量临时打开）。
6. **自保优先**：`critical_paths` 默认包含入口脚本与包目录，避免 hook 被自己改坏后无法修复。

## 项目结构

```text
safety-guard.py       # Hook stdin + 调试 CLI 统一入口
safety_guard.toml.example # 配置示例；复制为被忽略的 safety_guard.toml
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
