# EgressSentinel（出口哨兵）

[![CI](https://github.com/1wu-davy-2/EgressSentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/1wu-davy-2/EgressSentinel/actions/workflows/ci.yml)
[![Build](https://github.com/1wu-davy-2/EgressSentinel/actions/workflows/build.yml/badge.svg)](https://github.com/1wu-davy-2/EgressSentinel/actions/workflows/build.yml)
[![官网](https://img.shields.io/badge/官网-GitHub_Pages-2ea44f)](https://1wu-davy-2.github.io/EgressSentinel/)

> 本机 AI Agent 与应用程序外发流量审计系统（Windows 优先）。原名 AI-AGENT-AUDIT；Python 包与 CLI 仍为 `aaa`，可执行文件仍为 `ai-agent-audit`。

**名字含义**：Egress（出口流量）+ Sentinel（哨兵）——守在你机器的网络出口处，审计 AI Agent 与任意应用外发的每一个 HTTPS 请求，事中阻断密钥与代码的违规外发。

## 背景与问题

AI Agent（Claude Code / Cursor / Codex 类 CLI、IDE 插件、MCP 后台服务等）在本机拥有读写代码的权限，但它们外发 HTTPS 请求的内容对用户是不可见的：是否存在私自上传代码、泄露密钥 / `.env`、把敏感文件发给第三方端点，目前无法审计。现有手段各有缺口：

- **LLM 网关**（LiteLLM / Helicone 等）需要应用"自愿"接入，改不了 base_url 的进程完全逃逸；
- **企业端点 DLP** 面向大企业部署，重且无 AI 语义；
- **进程防火墙**（Portmaster / simplewall）只有元数据，看不到请求内容；
- 已有的 MITM 观测工具（如 llm-interceptor）只读、不可阻断、靠手工配置。

## 定位

一个部署在本机（Windows 10/11 优先）的**审计代理**：

1. 以 MITM 方式还原本机**任意进程**外发 HTTP(S) 请求/响应明文；
2. 将每条请求**归因到进程**（PID / exe 路径 / 签名信息）；
3. 用可配置规则从**域名 / 进程 / 内容 / 体量 / 时间窗**五个维度判定违规风险（密钥外发、整库代码上传、非 AI 进程访问 AI 端点等）；
4. 支持 **告警 / 交互确认 / 阻断** 响应，全程留痕、可回放、可导出报告；
5. 自带本地 Web 面板查看流量与审计结论。

不限于 AI Agent——本机任何应用程序的外发内容审计都适用。

## 架构总览

```
┌────────────────────────────────────────────────────────────────┐
│                        AI-AGENT-AUDIT                           │
│                                                                 │
│  采集层（双模式）                                                │
│  ┌───────────────────────────────┐  ┌────────────────────────┐  │
│  │ regular：显式本地代理          │  │ local：WinDivert 透明   │  │
│  │ 系统代理+环境变量注入，无需管理员│  │ 按进程/全网抓取，需管理员 │  │
│  └──────────────┬────────────────┘  └───────────┬────────────┘  │
│                 └──────────────┬─────────────────┘               │
│                                ▼                                 │
│  mitmproxy 审计引擎（addon：request/response 钩子）                │
│      + 进程归因（连接表反查 / local 模式原生 PID）                  │
│      + 规则引擎（五维求值 → allow/alert/confirm/block）            │
│      + 内容扫描（密钥 / PII / 代码外泄 / 体量 / 频率）             │
│                                ▼                                 │
│  存储（SQLite 事件库 + JSONL/证据文件，默认脱敏）                  │
│                                ▼                                 │
│  本地面板（FastAPI）+ CLI（setup / run / status / report …）      │
└────────────────────────────────────────────────────────────────┘
```

## 文档索引

| 文档 | 内容 | 读者 |
|---|---|---|
| [docs/01-research-report.md](docs/01-research-report.md) | 开源生态调研：流量抓取路线、AI 治理生态、Windows 工程可行性、竞品空白分析 | 所有贡献者 |
| [docs/02-technical-design.md](docs/02-technical-design.md) | 技术方案：总体架构、关键设计决策、数据模型、技术栈与许可 | 实现者 |
| [docs/03-execution-plan.md](docs/03-execution-plan.md) | 分阶段执行计划（任务卡 + 验收标准），**交给 glm5.3-flash 逐阶段实施** | 实现者 |

## 当前状态与分工

- [x] 开源生态调研（2026-10-24，GLM-5.3，含 3 个并行调研子任务）
- [x] 技术方案设计（GLM-5.3）
- [x] 执行计划编写（GLM-5.3）
- [x] 代码实现 P0-P5（GLM-5.3-Flash，经动态工作流逐阶段实施 + pytest 功能门禁 + 独立验收）
- [x] 可执行文件打包（`dist/ai-agent-audit.exe`，PyInstaller onefile，`--help` 冒烟通过）
- [x] 官网介绍页（`website/index.html`）
- [x] 安全深化 v0.2.0（洞察清单 ②）：仓库指纹、响应侧注入标注、LLM 辅助判定、证据加密、防火墙加固实装
- [ ] 后续强化（可选）：audit.db 整库加密、WFP 子层权重（绕过加固的 Allow 精确化）、服务化常驻

> 实现过程中的全部设计偏离与决策均记录在 `docs/notes/decisions.md`。

## 安装

**方式一：直接使用可执行文件**（无需 Python 环境）

`dist/ai-agent-audit.exe`（约 33MB，已内置全部依赖）。把它放到任意目录，加入 PATH 即可用下面所有命令（把 `aaa` 换成 `ai-agent-audit.exe`）。

**方式二：源码安装**

```powershell
cd AI-AGENT-AUDIT
python -m venv .venv
.venv\Scripts\pip install -e .          # 或 pip install -r <依赖清单见 pyproject.toml>
.venv\Scripts\aaa --help
```

## 快速开始

```text
aaa setup --dry-run        # ① 预览将要做的全部系统改动（推荐先看）
aaa setup                  # ② 交互确认后下发：CA 安装(CurrentUser)、WinINET 代理、环境变量
                           #    （含 NODE_EXTRA_CA_CERTS / REQUESTS_CA_BUNDLE 等，Node/Python 系 Agent 必需）
aaa run                    # ③ 启动审计代理（regular 模式，127.0.0.1:8080；出厂 dry-run 只告警不阻断）
aaa web                    # ④ 打开本地面板 http://127.0.0.1:8787（流量/告警/脱敏详情/导出）
aaa tail                   # 终端实时滚动事件（另开一个窗口）
aaa report --json          # 聚合报告（按判定/进程/域名/规则）
```

常用变体：

```text
aaa setup ca --store machine      # 机器级 CA（需管理员，覆盖 WinHTTP/服务进程）
aaa run --mode local --pid 1234   # 透明抓取指定进程（需管理员，WinDivert）
aaa policy lint                   # 校验策略文件
aaa run 的策略默认 policies/default.yaml（mode: dry-run 出厂默认）
                                   确认无误后把 mode 改为 enforce 才会真实阻断（403）
```

## 常驻与自愈（关机不断网）

针对「突发关机 → 开机后代理没跑 → 全机断网」的 VPN 式残留问题，v0.1.1 起三层防护：

| 层 | 机制 | 命令 |
|---|---|---|
| 优雅退出 | Windows 关机/注销/控制台关闭事件触发限时收尾（4s < 系统 5s 上限，绝不阻塞关机）；事件库每事件事务落盘，强退不丢数据 | `aaa run` 内置 |
| 开机自启 | 登录计划任务自动拉起 `aaa run`（`aaa setup` 最后一步默认询问，默认安装；日志 `data/autostart.log`） | `aaa autostart on / off / status` |
| 自检自愈 | 登录 30 秒后 watchdog 检测「代理已启用但 127.0.0.1:8080 不可达」，`--fix` 自动还原代理设置与代理环境变量（CA 无害保留），网络立刻恢复（日志 `data/watchdog.log`） | `aaa watchdog [--fix]` |

`aaa status` 已内置自检预警与自启任务状态；`aaa teardown` 会连计划任务一并还原。

## 告警通知（即时知道有人外发密钥）

v0.1.3 起，命中 `alert` 及以上判定的事件会**即时推送通知**——不用打开面板也第一时间知道：
默认通道是 Windows 系统通知（toast，本机、无外发），另支持 Webhook 与 SMTP 邮件。
配置在策略 YAML 的 `notifications` 段，**随策略热更新**（保存约 2 秒生效）：

```yaml
notifications:
  min_action: alert        # 通知门槛：alert | confirm | block
  toast:
    enabled: true          # Windows 系统通知（PowerShell WinRT，零依赖，出厂默认）
  webhook:
    enabled: false
    provider: generic      # generic | wecom | dingtalk | feishu | slack | discord
    url: ""                # 环境变量 AAA_WEBHOOK_URL 优先（token 不必写进文件）
  email:
    enabled: false
    smtp_host: ""          # 端口 465/SMTP_SSL 或 587+starttls（use_tls: false）
    username: ""
    password: ""           # 环境变量 AAA_SMTP_PASSWORD 优先
    to_addrs: []
  rate_limit:
    max_per_minute: 10     # 每通道滑动窗口；超出部分合并为一条 digest，绝不轰炸
```

要点：

- **通知正文与面板同一脱敏核心**：命中的密钥一律先打码（如 `AKIA****YZ`）再进通知，
  绝不把拦截到的明文密钥外发到 webhook/邮件；
- Webhook 直连不走本机代理（`trust_env=False`），避免被本工具自己拦截形成回环；
- 通道发送失败只记日志、绝不影响审计代理本身；退出时有界排空（flush 2s）；
- 老策略文件没有 `notifications` 段 = 通知全关（升级零惊扰）；
- 测试通道：`aaa notify test`（按配置发一条测试通知）或 `aaa notify test --channel webhook`；
  当前配置看 `aaa status` 的「通知」行。

## 安全深化（v0.2.0：指纹 / 注入标注 / LLM 判定 / 加密 / 防火墙）

v0.2.0 新增四项安全能力 + 防火墙加固实装。**全部默认关闭**，在策略 YAML 对应段落
显式开启（保存约 2 秒热更新生效；指纹库与加密开关在 `aaa run` 启动时装配，改完重启）。
老策略文件没有这些段 = 全关，升级零惊扰。

### 1. 仓库指纹比对（防整段代码外发）

把本地代码仓库按行滑窗切片（8 行窗口、去注释/空行、SHA1 入库，多仓库合并）建指纹库，
外发请求体与库比对——Agent 把源码整段发给第三方端点时即使绕过密钥/代码相似度规则，
也能按"逐字命中"报出仓库、文件与行号：

```text
aaa fingerprint build --repo E:\work\my-repo        # 建库/增量合并（可多次 --repo；--rebuild 从零重建）
aaa fingerprint build                                # 不带 --repo 时读策略 fingerprint.repos
```

```yaml
fingerprint:
  enabled: true
  repos: ["E:/work/my-repo", "E:/work/other-repo"]   # 建库路径清单（也可只由 CLI --repo 传入）
  min_hits: 1                                        # 命中多少个 8 行窗口算命中
```

```yaml
content:
  scanners: [secrets, pii, code_leak, repo_fingerprint]
  rules:
    - { id: repo-leak, scanner: repo_fingerprint, action: block, weight: 60 }
```

- 建库**纯本地、零外发**、不执行任何 git 命令（只读工作区文件，跳过 `.git`/二进制/
  超 5MB 文件，总片上限 200 万防 OOM）；命中证据固定 80 字符片段，事件与通知不携带
  更多原文；
- 指纹库 `data/fingerprints.bin` 是本地信任数据；损坏自动按"缺失"处理重建，`aaa run`
  启动时缺失会告警提示先 `aaa fingerprint build`（不自动遍历仓库拖慢启动）。

### 2. 响应侧注入标注（不阻断）

扫描**响应体**中的提示词注入特征（指令覆盖 ignore previous/无视之前的指令、角色伪造
`<system>`/DAN、越狱模板、零宽字符与 base64 隐藏载体、套取系统提示词），规则来自
promptfoo/garak 公开语料反推的高频特征，纯 regex 零网络：

```yaml
response:
  rules:
    - id: response-injection
      patterns: all        # all=任何注入特征命中 | high=仅高危（指令覆盖/隐藏载体）
      action: alert        # 响应侧只支持 alert——只标注、绝不阻断/改写响应（schema 强制）
```

命中事件的 `matched_rules` 增加 `dim=response` 条目（含严重度与命中等明细），
verdict 低于 alert 时抬到 alert（照常走通知门槛）；响应体**原样送达客户端**。

### 3. LLM 辅助判定（第二意见）

alert 级以上事件把**脱敏后**的摘要（复用通知同一打码核心，明文密钥绝不外发）发给
OpenAI 兼容 `/chat/completions` 端点，让模型对"是否构成安全违规"给出第二意见
（结论记事件 `judge_note`）：

```yaml
judge:
  enabled: true
  api_base: "https://api.openai.com/v1"   # 不含 /chat/completions
  model: "gpt-4o-mini"
  timeout: 8
  max_events_per_day: 200                 # 每日预算（只计成功取得结论的调用）
```

- API key 只从环境变量 `AAA_JUDGE_API_KEY` 读取，绝不落盘/进日志/进事件；
- 超时/非法输出/网络失败一律收敛为"判定不可用"，**绝不影响审计主流程**；
- 判定请求直连（不走系统代理），避免被本工具自己拦截回环；
- 开启前请确认摘要外发到你选择的端点符合你的数据策略——这是唯一的"内容外发"功能。

### 4. 证据静态加密

```yaml
encrypt:
  enabled: true
```

开启后请求 body 证据文件（`data/evidence/*.bin`）以 **AES-256-GCM** 落盘（`ES01`
魔数头）；密钥来源二选一：`data/.crypto-key` 自动生成（32B 随机，权限收紧），或环境
变量 `AAA_MASTER_PASSWORD` 口令 PBKDF2（200k 迭代）派生。

- **读取永远透明兼容**：旧明文证据原样可读；关闭加密后仍能解密历史密文；
- `sha256` 按落盘密文计算（无密钥也可复核完整性），`size/truncated` 描述明文；
- 密钥材料丢失 = 既有密文不可解：工具如实报错，绝不静默重建掩盖——请把 `data/`
  纳入备份策略；
- 开关在 `aaa run` 启动时生效（热更新不切换加密状态）；
- **边界**：`audit.db` 事件库（元数据/命中规则/摘要）暂不整库加密，需要整库保密请
  配合 BitLocker 等磁盘级加密（详见 docs/notes/decisions.md D-2026-10-24-39）。

### 5. 防火墙加固（`aaa harden`，需管理员）

把 443 出站收敛到本代理的唯一出口（堵 HTTPS 直连与 QUIC 绕行）：

```text
aaa harden on            # 创建 4 条 EgressSentinel- 前缀规则（journal-first，可还原）
aaa harden off           # 按记录精确删除（幂等）
aaa teardown firewall    # 等价：只还原防火墙类改动
```

- 规则集：放行代理与 svchost 443/TCP，阻止任意程序 443/TCP 与 443/UDP；
- `--proxy-exe` 可指定放行的代理程序（缺省 = 当前的 python/exe 自身）；
- **已知边界（如实警示）**：Windows 筛选平台 Block 优先于 Allow——any-Block 规则会
  同时命中代理与 svchost 白名单，`on` 后 443 出站可能全断（含本工具代理自身）；
  断网立即 `aaa harden off` 还原。真机启用前建议先在可还原环境演练
  （详见 docs/notes/decisions.md D-2026-10-24-38）。

## 卸载

```text
aaa teardown              # 按改动日志逆序幂等还原：删除 CA（按序列号精确匹配）、还原代理设置、
                          # 删除环境变量、删除防火墙规则、删除计划任务；即使 aaa run 中途崩溃，
                          # 重启后执行仍能完整还原
```

残留自检：`aaa status` 会显示"待还原改动"提示。

## GitHub（CI / 多平台构建 / 官网 Pages）

`.github/workflows/` 已内置三条流水线：

| Workflow | 触发 | 内容 |
|---|---|---|
| `ci.yml` | push / PR | ruff + 测试矩阵：Python 3.11/3.12/3.13 × **amd64/arm64** × **Linux/Windows/macOS**（Windows amd64 为严格门禁，其余平台为移植性回归，失败不阻塞） |
| `build.yml` | 推 `v*` 标签 / 手动 | 各平台 PyInstaller 单文件构建（`egress-sentinel-<os>-<arch>`），标签触发时自动发布 GitHub Release |
| `pages.yml` | `website/**` 变更 / 手动 | 把 `website/` 部署到 **GitHub Pages**，在线访问官网介绍页 |

仓库地址：<https://github.com/1wu-davy-2/EgressSentinel>（已用 SSH key 推送，remote 为 `git@github.com:1wu-davy-2/EgressSentinel.git`）。

1. 官网：仓库 **Settings → Pages → Source 选 "GitHub Actions"**，之后 `website/` 任何变更都会自动部署到 <https://1wu-davy-2.github.io/EgressSentinel/>；
2. 发布新版本：`git tag v0.1.0 && git push --tags`，Release 页会自动出现六个平台的单文件产物。

## 常见问题

- **怎么配置飞书 / 钉钉 / 企业微信机器人通知？** 三步：① 群里添加「自定义机器人」拿到
  webhook 地址（飞书：`https://open.feishu.cn/open-apis/bot/v2/hook/xxx`；钉钉：自定义
  webhook，安全设置建议选「自定义关键词」填 `EgressSentinel`；企业微信同 `wecom` 形态）；
  ② 策略 YAML `notifications.webhook` 填 `enabled: true` + `provider: feishu|dingtalk|wecom`
  （url 建议走环境变量 `AAA_WEBHOOK_URL`，不落盘）；③ `aaa notify test --channel webhook`
  验证群里收到测试消息（策略保存约 2 秒热更新生效，无需重启）。

- **突然关机后开机「断网」怎么办？** 系统代理仍指向 127.0.0.1:8080 而代理没跑。装了自启：开机自动起代理，起不来 watchdog 会在登录 30 秒后自动还原代理设置（网络自愈）。手动恢复一条命令：`aaa watchdog --fix`（或 `aaa teardown proxy`）。

- **某个 Agent 的流量没被捕获？** Node.js 系工具默认不读系统代理与系统证书，必须执行过 `aaa setup env`（注入 `NODE_USE_ENV_PROXY` / `NODE_EXTRA_CA_CERTS`）并**重启该 Agent 进程**；Python 系对应 `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE`。
- **看到 CERTIFICATE_VERIFY_FAILED？** 目标进程未信任本工具 CA——确认对应运行时的环境变量已下发。
- **杀毒软件报警？** 本地代理 + 根证书安装对应 MITRE T1553.004，属预期行为；regular 模式不加载任何驱动。请确认是你本人主动安装。
- **QUIC/HTTP3 流量？** 遵循代理设置的应用不会直连 QUIC；对硬编码直连的进程需要防火墙加固：`aaa harden on`（需管理员，见「安全深化」小节；注意 WFP 边界与还原方式）。

## 合规与使用边界

- 仅用于审计**自己拥有或被明确授权管理**的计算机。抓取本机 HTTPS 明文属于高权限监控行为，部署到他人设备前必须获得授权。
- 证据库含敏感信息：默认仅本地存储、UI 默认脱敏展示、保留期可配。
- 安装根证书对应 MITRE ATT&CK T1553.004，可能触发杀软/EDR 告警；工具不隐藏自身行为，并提供**完整卸载**（移除 CA、还原代理设置、删除防火墙规则）。
