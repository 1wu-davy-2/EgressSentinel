# 02 · 技术方案

> 前置阅读：`01-research-report.md`。本文档是实现的唯一权威设计依据；实现中若发现设计与现实冲突，将决策记录到 `docs/notes/decisions.md` 并同步修订本文。

## 1. 目标与非目标

### 1.1 目标（v1）

- G1 抓取：还原本机进程外发 HTTP(S) 请求/响应明文（含 body），HTTPS 为主战场；
- G2 归因：每条请求对应到发起进程（PID、exe 路径、命令行、签名者），未归因事件显式标记 `unknown`；
- G3 判定：五维规则（域名 / 进程 / 内容 / 体量 / 时间窗）求值，输出风险分与结论；
- G4 响应：allow / alert / confirm / block 四级动作，block 须事中生效（请求被拦截并返回合成响应）；
- G5 留痕：全事件入库（SQLite）+ 证据文件（截断脱敏可选），UI 默认脱敏，保留期可配；
- G6 易用：`aaa` CLI 一条命令安装/运行/卸载；本地 Web 面板查看；
- G7 可逆：卸载后系统设置（代理、CA、环境变量、防火墙规则）完整还原，teardown 幂等。

### 1.2 非目标（v1 不做）

- Linux/macOS 支持（代码保持可移植，平台相关逻辑集中在 `setup/` 与 `attribution/`）；
- 自研内核驱动；EDR 级防篡改（对手是"失控的 Agent"而非"刻意逃避检测的人"）；
- 解密带证书固定的程序（检测到校验失败即白名单直通，降级为元数据审计）；
- 流量转发/代理链（不是翻墙工具）；多机集中管理。

## 2. 总体架构

```
                本机进程（AI Agent CLI / IDE / 任意应用）
                    │ ①regular: 系统代理+环境变量        ②local: WinDivert 透明重定向
                    ▼                                   （需管理员）
        ┌─────────────────────────────────────────────────────┐
        │ aaa.capture  ── mitmproxy 引擎（Python 库嵌入）        │
        │   · addon 钩子: client_connected / request / response │
        │   · local 模式: --mode local[:pid|proc] 原生归因       │
        └──────┬──────────────────────────────┬───────────────┘
               │ Flow(A)                       │ Flow(A)+PID(local)
               ▼                               ▼
        ┌─────────────┐               ┌──────────────────────┐
        │ attribution │ peername 源端口 │ engine.AuditPipeline │
        │ 连接表反查PID │ ────────────▶ │  1 domain 规则        │
        └─────────────┘               │  2 process 规则       │
                                      │  3 scanners: secrets/ │
                                      │    PII/code_leak/size │
                                      │  4 time_window 速率    │
                                      │ → Verdict+risk_score  │
                                      └───────┬──────────────┘
                                              │ ③block: 合成403响应
                       ┌──────────────────────┼──────────────┐
                       ▼                      ▼              ▼
                ┌────────────┐        ┌────────────┐  ┌────────────┐
                │ store      │        │ web 面板    │  │ CLI 输出    │
                │ SQLite+JSONL│       │ FastAPI    │  │ rich 表格   │
                └────────────┘        └────────────┘  └────────────┘
```

组件职责：

| 组件 | 职责 | 关键依赖 |
|---|---|---|
| `aaa.capture` | 运行 mitmproxy（regular/local 双模式），挂载审计 addon，产出 Flow | mitmproxy(lib) |
| `aaa.attribution` | regular 模式下连接→进程归因；进程元信息缓存（exe/命令行/签名者） | psutil |
| `aaa.policy` | YAML 策略加载、pydantic 校验、热更新、lint | pydantic、pyyaml |
| `aaa.scanners` | 密钥（gitleaks 规则移植）/ PII / 代码外泄 / 体量扫描器 | 纯 regex+启发式 |
| `aaa.engine` | 五维求值、风险分合成、Verdict 判定、阻断执行 | — |
| `aaa.store` | 事件入库、证据文件（截断+哈希）、保留期清理 | sqlite3(stdlib) |
| `aaa.setup` | CA 安装/卸载、系统代理与环境变量下发/还原、防火墙加固开关 | certutil/netsh/注册表 |
| `aaa.web` | 本地只读面板：流量、事件、统计、导出、confirm 交互 | fastapi、uvicorn |
| `aaa.cli` | `aaa setup/run/status/tail/report/policy/teardown/trim` | typer、rich |
| `aaa.judge`（可选 P6） | LLM 辅助判定（脱敏摘要→结构化结论） | httpx |

## 3. 关键设计决策

### D1 双模式采集（regular 默认 / local 严格）

| | regular（默认） | local（严格） |
|---|---|---|
| 原理 | 显式本地代理 127.0.0.1:8080，系统代理（WinINET 用户级 + `netsh winhttp` 机器级）+ 用户环境变量组合下发 | mitmproxy `--mode local`（WinDivert 重定向），可限定 `--pid`/`--process` |
| 权限 | 普通用户（winhttp 与机器级 CA 需管理员，可选） | 必须管理员（UAC 提权） |
| 覆盖 | 遵循代理的应用（Chromium/Electron、认环境变量的 CLI） | 全部（无视应用代理设置） |
| 归因 | peername 源端口反查连接表 | mitmproxy 原生 PID |
| 风险 | 无驱动，AV 风险最低 | 根证书+驱动双重 AV 误报面 |

决策依据：调研 §1.1/§3.2——单一劫持手段必有漏网，但 v1 以"低摩擦默认可用"优先，local 模式给愿意付管理员权限的用户最强保证。环境变量下发清单（用户级）：`HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY=localhost,127.0.0.1`、`NODE_USE_ENV_PROXY=1`、`NODE_EXTRA_CA_CERTS=<CA pem>`、`REQUESTS_CA_BUNDLE`/`SSL_CERT_FILE=<含自建CA的合并PEM>`、`CURL_CA_BUNDLE`。

### D2 进程归因策略

- regular：`client_connected` 钩子取 `client_conn.peername` 的源端口，**立即**查 `psutil.net_connections()`（快照级延迟可接受，源端口在 TCP 生命周期内稳定）；查不到记 `unknown` 并对 unknown 速率单独告警。
- PID→进程元信息（exe、命令行、公司、签名者）经 LRU 缓存，签名者用 `win32` API 按需懒加载。
- local：直接使用 mitmproxy 提供的进程信息。
- 明确不承诺 100% 归因：短连接竞态与权限不足（非管理员看不到其他用户进程）是已知边界，事件里如实标记。

### D3 CA 信任部署矩阵

| 目标运行时 | 安装动作 |
|---|---|
| Windows 证书存储（Chromium/Electron/WinINET） | `certutil -addstore Root`（LocalMachine，管理员、无弹窗；或 CurrentUser .NET X509Store 静默导入） |
| Node.js 系 Agent | 用户环境变量 `NODE_EXTRA_CA_CERTS`（Node 默认不读系统证书库） |
| Python 系 Agent | `REQUESTS_CA_BUNDLE`/`SSL_CERT_FILE` 指向合并 PEM |
| curl/git/Go | `CURL_CA_BUNDLE`/`SSL_CERT_FILE` |
| Java | 文档指引 keytool（v1 不自动） |

teardown 逐一还原；证书校验失败（`CERTIFICATE_VERIFY_FAILED`、TLS handshake error）聚合成"疑似不信任 CA 的进程"报告，提示用户补对应变量或加白名单。

### D4 规则引擎：五维 + 四级动作

- 维度：**域名**（端点分类：known_ai_api / code_hosting / unknown / blocklist，未知首连告警）、**进程**（画像：agent_cli / browser / other；"非 AI 进程访问 AI 端点"类异常规则）、**内容**（secrets / pii / code_leak 扫描器命中）、**体量**（单请求字节数、分片聚合）、**时间窗**（滑动窗口速率）。
- 动作：`allow < alert < confirm < block`，多维命中取最高级；`risk_score = min(100, Σ weight)` 仅供排序展示。
- **默认 dry-run**（只告警不阻断），`mode: enforce` 显式切换；策略文件 mtime 监听热更新；`aaa policy lint` 校验。
- 内容扫描器 v1 全部为确定性 regex/启发式（无网络调用）：secrets 移植 gitleaks 核心 ~40 条（regex+熵+allowlist），pii 覆盖邮箱/手机号/身份证/银行卡，code_leak 检测本地绝对路径（`C:\Users\...`、`/home/...`）、代码密度（shebang/import/函数定义占比）、multipart 文件上传、超阈值 base64 块。

### D5 阻断语义与失败模式

- 事中阻断：`request` 钩子内直接合成响应 `flow.response = Response.make(403, {"aaa":"blocked", ...})`，请求**不会**到达目标服务器；同时写事件（action_taken=blocked-403）。
- TLS 之前可阻断：域名规则在 SNI/CONNECT 阶段即可 kill flow（用于 blocklist 域名，省去解密）。
- 失败模式默认 **fail-open**（引擎异常放行并记 error 事件），策略可配 fail-closed。
- 响应侧 v1 仅做元数据与体量检查；prompt-injection 特征标记进 P6。

### D6 存储与隐私

- SQLite `data/audit.db`：events 表（见 §6），索引 (ts, verdict, pid, host)。
- 证据文件 `data/evidence/<event_id>.bin`：请求 body 截断落盘（默认上限 256KB），存 sha256；UI 默认只展示脱敏摘要（命中的 secret 打码），查看原文需显式 `?reveal=1`。
- 保留期：`aaa trim --days 14` 手动 + 启动时自动清理；不联网上传任何数据。

### D7 LLM 辅助判定（可选，P6）

- 仅对规则引擎判 `alert/confirm` 的事件触发：截断+脱敏后的摘要 → OpenAI 兼容接口 → 结构化 JSON 结论（is_violation/reason/category）。
- 硬性约束：每事件 token 上限、每日成本上限、可整体关闭；判定结果只作参考不直接 block。

### D8 防绕过加固（可选，P6）

- `aaa harden on`：防火墙规则——仅放行本工具进程的 443/TCP 出站、拒绝其他进程 443/TCP、**拒绝 UDP 443**（逼 QUIC 回落 TLS）；`aaa harden off` 完整还原。
- 误伤保护：规则内置 svchost/Windows Update 白名单；启用前 dry-run 列出将受影响进程。

## 4. 代码结构

```
AI-AGENT-AUDIT/
├── pyproject.toml            # src 布局，Python >= 3.11
├── policies/default.yaml     # 默认策略（dry-run）
├── src/aaa/
│   ├── cli.py                # typer 入口
│   ├── config.py             # 路径、常量、运行配置
│   ├── capture/engine.py     # mitmproxy 嵌入、双模式
│   ├── capture/addon.py      # 审计 addon（钩子→管线）
│   ├── attribution/table.py  # 连接表反查 + 进程元信息缓存
│   ├── policy/{model,loader}.py
│   ├── scanners/{secrets,pii,code_leak,size}.py
│   ├── engine/{pipeline,verdict}.py
│   ├── store/{db,evidence}.py
│   ├── setup/{ca,proxy,firewall,envvars}.py
│   ├── judge/llm.py          # P6
│   └── web/{app,views}.py    # FastAPI + 静态页
├── tests/{unit,e2e}/
├── docs/notes/               # spike 与决策记录
└── data/                     # 运行时生成（git 忽略）
```

## 5. 策略文件 schema（示意）

```yaml
version: 1
mode: dry-run                 # dry-run | enforce
defaults: {fail_open: true, max_body_scan: 262144}

domains:
  classes:
    known_ai_api: [api.anthropic.com, api.openai.com, generativelanguage.googleapis.com,
                   api.deepseek.com, api.moonshot.cn, openrouter.ai, api.x.ai]
    code_hosting: [github.com, api.github.com, gitlab.com]
  rules:
    - {id: domain-unknown, match: {class: unknown}, action: alert, weight: 20}
    - {id: domain-blocklist, match: {host_regex: '\.example-mal\.com$'}, action: block, weight: 80}

processes:
  profiles:
    agent_cli: {exe_regex: '(?i)(claude|cursor|codex|copilot|node|python|java)'}
    browser:   {exe_regex: '(?i)(chrome|msedge|firefox)\.exe$'}
  rules:
    - {id: non-agent-to-ai-api, match: {profile_not: agent_cli, dest_class: known_ai_api},
       action: alert, weight: 30}

content:
  scanners: [secrets, pii, code_leak]
  rules:
    - {id: secret-leak, scanner: secrets, action: block, weight: 60}
    - {id: pii-bulk, scanner: pii, match: {hits_gt: 10}, action: confirm, weight: 40}
    - {id: code-bulk-upload, match: {body_size_gt: 512000, code_likeness_gt: 0.6},
       action: confirm, weight: 40}

volume:
  - {id: huge-body, match: {body_size_gt: 5242880}, action: alert, weight: 20}

time_window:
  - {id: burst, match: {requests_gt: 60, window_seconds: 60}, action: alert, weight: 20}
```

（实现时由 pydantic 严格化；权重与阈值为初始经验值，面板统计支撑后续调优。）

## 6. 事件数据模型

```json
{
  "id": "evt_01J8Z...",
  "ts": "2026-10-24T12:34:56.789+08:00",
  "mode": "regular",
  "verdict": "block",
  "risk_score": 80,
  "process": {"pid": 41233, "name": "node.exe", "exe": "C:\\...\\node.exe",
               "cmdline": "claude ...", "company": "OpenJS Foundation", "profile": "agent_cli"},
  "destination": {"host": "api.example.com", "ip": "203.0.113.7", "port": 443,
                   "classification": "unknown"},
  "request": {"method": "POST", "path": "/v1/chat/completions",
               "content_type": "application/json", "size": 210343},
  "matched_rules": [{"id": "secret-leak", "dim": "content",
                      "evidence": "AKIA****", "weight": 60}],
  "action_taken": "blocked-403",
  "evidence": {"file": "data/evidence/evt_....bin", "sha256": "...", "truncated": true},
  "policy_version": "7f3a"
}
```

## 7. 技术栈与许可合规

| 依赖 | 用途 | 许可 |
|---|---|---|
| Python ≥ 3.11 | — | PSF |
| mitmproxy ≥ 10.2（lib 嵌入） | 采集引擎 + local 模式 | **MIT（已核实）** |
| typer + rich | CLI | MIT |
| pydantic ≥ 2 | 策略/事件模型 | MIT |
| fastapi + uvicorn | 本地面板 | MIT/BSD |
| psutil | 连接表/进程信息 | BSD |
| pyyaml | 策略解析 | MIT |

密钥规则源自 gitleaks（MIT）移植；**不引入** GPL/AGPL 代码（Portmaster、simplewall、mihomo、trufflehog 均只作思路借鉴）；mihomo 等 GPL 工具即使将来作为独立进程调用也不链接其代码。

## 8. 风险登记表

| # | 风险 | 概率/影响 | 对策 |
|---|---|---|---|
| R1 | mitmproxy local 模式在目标机不可用/行为不符 | 中/中 | P0 spike 首先验证（T0.3），不可用则 v1 只发 regular 模式，归因器兜底 |
| R2 | 杀软/EDR 误报（根证书=MITRE T1553.004、WinDivert 驱动） | 中/高 | 默认 regular（无驱动）；安装全程显式确认+透明日志；完整卸载；提供 Defender 排除指引 |
| R3 | Node 系 Agent 不走系统代理或不信任 CA | 高/中 | 环境变量组合下发（NODE_USE_ENV_PROXY/NODE_EXTRA_CA_CERTS）；证书失败聚合报告；local 模式兜底 |
| R4 | QUIC/硬编码直连绕过 | 中/中 | P6 防火墙封 UDP 443；直连进程在连接表层可见（元数据告警"未覆盖流量"） |
| R5 | 大 body/高频导致性能问题 | 低/中 | 扫描截断（默认 256KB）、非审计目标域名跳过 body 扫描、异步落盘 |
| R6 | 抓全量明文的隐私/合规风险 | 中/高 | 仅授权设备使用；本地存储+脱敏展示+保留期；README 明示边界 |
| R7 | teardown 失败留残留 | 低/高 | 改动先落状态文件（data/setup-state.json），teardown 按记录幂等还原；崩溃后启动检测残留并提示 |
| R8 | 密钥规则误报（测试密钥、文档示例） | 高/低 | allowlist 机制 + dry-run 默认 + 面板一键加白 |

## 9. 与竞品差异（一句话版）

- vs llm-interceptor：不只读——**事中阻断**；不只靠手工配置代理——**setup 一键下发 + local 模式透明覆盖**；不只针对 LLM 域名——任意域名任意进程。
- vs CC-Monitor：支持 Windows、不绑定单一 Agent 工具、内容级而非仅元数据。
- vs LiteLLM 等网关：无需应用自愿接入，对不配合进程同样生效。
