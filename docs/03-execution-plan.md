# 03 · 执行计划

> **实施者：glm5.3-flash**。规划：GLM-5.3（2026-10-24）。
> 本文是逐阶段实施合同：按 P0→P5 顺序做，每阶段完成即满足其验收标准后才进入下一阶段。P6 为可选强化，按需排期。

## 0. 交接说明（实施前必读）

1. 阅读顺序：`README.md` → `02-technical-design.md`（设计权威）→ 本文档。
2. 环境：Windows 10/11，Python ≥ 3.11，Git Bash 或 PowerShell。依赖用 `pip`（或 `uv`）安装：`mitmproxy>=10.2, typer, rich, pydantic>=2, pyyaml, fastapi, uvicorn, psutil`；开发依赖：`pytest, ruff, httpx`。
3. 工作约定：
   - **小步快跑**：每个任务一个提交，conventional commits（`feat: ...` / `test: ...`）。
   - 每阶段结束时 `pytest` 全绿 + `ruff check src tests` 通过。
   - 设计有歧义或与现实冲突时：不要静默猜测——把决策写入 `docs/notes/decisions.md`（日期+问题+选择+理由），必要时修订 `02-technical-design.md` 并在提交说明中注明。
   - 涉及高权限/系统修改的代码只能放在 `src/aaa/setup/`，且**必须**配套 teardown 还原逻辑与状态文件记录（见 R7）。
   - 单元测试不得依赖真实网络与真实管理员权限；mitmproxy flow 用构造对象/fixture server 模拟。
4. 安全红线：默认 dry-run（只告警不阻断）是 v1 出厂默认；任何"自动删除/自动改防火墙"类动作必须用户显式命令触发。

## 1. 里程碑总览

| 阶段 | 目标 | 预估 | 核心验收 |
|---|---|---|---|
| P0 | 骨架 + 关键技术 spike | 0.5 天 | pytest 绿；local 模式可行性有结论 |
| P1 | 采集内核 MVP（regular） | 1.5 天 | 三类客户端流量被捕获留痕；teardown 还原 |
| P2 | 进程归因 + local 模式 | 1 天 | ≥90% 测试请求正确归因 |
| P3 | 策略引擎 + 内容扫描 + 阻断 | 2 天 | E2E：假密钥/代码外发被命中并（enforce 下）阻断 |
| P4 | 存储 + CLI 完整化 | 1 天 | 崩溃后 teardown 仍完整还原 |
| P5 | Web 面板 | 2 天 | 查看-脱敏-解锁-导出全流程 |
| P6 | 强化（可选） | 按需 | 见各任务卡 |

## 2. 任务卡

### P0 骨架与 spike

- **T0.1 仓库骨架**：按 02 文档 §4 建目录、`pyproject.toml`（src 布局）、`policies/default.yaml`（先放空骨架）、`.gitignore`（`data/`、`*.pyc`、`.venv`）、`tests/` 目录。`aaa --help` 可运行（空 CLI）。
- **T0.2 嵌入冒烟**：`tests/unit/test_capture_smoke.py`——用 mitmproxy 库（`DumpMaster` + 简单 addon）在本进程内起 regular 代理，`httpx` 经代理请求本地 fixture HTTP server，断言 addon 的 `request` 钩子收到 flow。验证"库嵌入"路线可行。
- **T0.3 local 模式 spike（关键）**：以管理员 PowerShell 手动运行 `mitmproxy --mode local --set confdir=...` 观察能否抓取（对照 mitmproxy 版本 ≥10.2）。结果（成功/失败/版本/现象）写入 `docs/notes/local-mode-spike.md`。失败则触发 R1 回退：v1 仅 regular 模式，P2 的 T2.2 改为实现"降级说明 + 引导文档"。
- 验收：`pytest` 全绿；spike 报告存在；`aaa --help` 正常。

### P1 采集内核（regular 模式）

- **T1.1 CaptureEngine**（`capture/engine.py`）：封装 mitmproxy 选项（listen_port、confdir 指向 `data/mitm/`、body 大小限制），加载 `AuditAddon`；`aaa run --mode regular` 阻塞运行，Ctrl+C 优雅退出。
- **T1.2 审计 addon 骨架**（`capture/addon.py`）：`client_connected` / `request` / `response` 钩子把关键字段写入内存事件对象并交给 store 接口（P1 先 JSONL 直写 `data/raw/YYYYMMDD.jsonl`）。body 截断落证据文件（默认 256KB，含 sha256）。
- **T1.3 CA 管理**（`setup/ca.py`）：定位/生成 CA（confdir 下）；`aaa setup ca [--store user|machine]`（CurrentUser 用 .NET X509Store 静默导入；LocalMachine 用 `certutil -addstore Root`，需管理员，自动提权提示）；`aaa teardown ca` 删除（按序列号精确定位，不误删）。
- **T1.4 代理与环境变量下发**（`setup/proxy.py`、`setup/envvars.py`）：WinINET 用户代理（注册表 + `InternetSetOption` 刷新或通知重启浏览器）；可选 `netsh winhttp set proxy`（管理员）；用户环境变量集（02 文档 D1 清单，`NO_PROXY=localhost,127.0.0.1`）。**所有改动写入 `data/setup-state.json`**。
- **T1.5 teardown 原型**：按状态文件逆序还原全部改动；`aaa teardown`（不带参数=全部）幂等。
- 验收（手工+E2E 脚本）：浏览器、Python requests、curl 三类客户端经代理访问外网（或本地 HTTPS fixture），JSONL 出现对应记录；teardown 后 `netsh winhttp show proxy`、注册表、环境变量与改动前一致。

### P2 进程归因 + local 模式

- **T2.1 ProcessAttributor**（`attribution/table.py`）：`client_connected` 时用 `client_conn.peername` 源端口查 `psutil.net_connections('inet')` 反查 PID；PID→(exe, cmdline, company, profile) LRU 缓存；未命中记 `unknown` + 计数。单测用注入的假连接表。
- **T2.2 local 模式集成**：`aaa run --mode local [--pid N | --process name]`——管理员检测（无则报错并给出 UAC 提升指引）、透传 mitmproxy local 参数、事件 `mode=local` 且带原生 PID。依赖 T0.3 结论。
- **T2.3 归因质量自检**：`tests/e2e` 用 python/node/curl 三种客户端发请求，断言归因准确率 ≥90%（regular 模式）。
- 验收：归因字段出现在事件中；自检通过；local 模式可运行（或按 R1 回退并记录）。

### P3 策略引擎与阻断

- **T3.1 Policy 模型与加载**（`policy/model.py`、`policy/loader.py`）：pydantic 严格化 02 文档 §5 schema；`aaa policy lint`；mtime 热更新（引擎轮询 2s）。
- **T3.2 五维求值器**（`engine/pipeline.py`）：domain（分类+unknown 首连）、process（profile 匹配）、volume、time_window（进程×域名滑动窗口计数）、content（调 scanners）；动作四级 + risk_score 合成；单测覆盖每维及组合取最高级逻辑。
- **T3.3 扫描器**（`scanners/`）：
  - `secrets.py`：移植 gitleaks 核心 ~40 条规则为内置 YAML/常量（AWS/GCP/Azure/OpenAI/Anthropic/GitHub/私钥头/JWT 等），regex + 熵 + allowlist（`AKIAIOSFODNN7EXAMPLE` 等官方示例默认白名单）；
  - `pii.py`：邮箱/手机号/身份证/银行卡，支持阈值（hits_gt）；
  - `code_leak.py`：本地路径模式、代码密度启发（shebang/import/def/class 占比）、multipart 文件段、base64 大块；
  - 全部无网络调用，纯函数便于测试。
- **T3.4 阻断执行**：dry-run/enforce 两模式（默认 dry-run）；enforce 下 `request` 钩子合成 403 JSON 响应（含命中规则 id）；域名 blocklist 在 CONNECT/SNI 阶段 kill flow；fail_open 可配。
- **T3.5 E2E 审计场景**：`tests/e2e/test_audit_pipeline.py`——本地 HTTPS fixture server 充当"AI 端点"；模拟 agent 客户端分别发送 ①含假 AWS key ②512KB 代码体 ③正常请求，断言 ①②命中（dry-run 告警；enforce 下 ①被 403）③放行，事件与证据齐全。
- 验收：上述测试全绿；`policies/default.yaml` 含 02 文档示例规则。

### P4 存储与 CLI 完整化

- **T4.1 SQLite store**（`store/db.py`）：events 表（02 文档 §6 字段）+ 索引；启动时 JSONL 与 DB 双写可收敛为仅 DB（保留 JSONL 开关）；`aaa trim --days N` 清理 + 启动自动清理。
- **T4.2 CLI 完整化**：`setup`（交互式引导：CA→代理→环境变量）、`run`、`status`（代理/CA/防火墙/策略版本/最近 5 事件）、`tail`（rich 实时滚动）、`report --since --json/csv`、`policy lint`、`harden on/off`（P6 前占位提示）、`teardown`。
- **T4.3 崩溃安全**：kill -9 模拟（E2E：设置改动后强杀进程），重启 `aaa teardown` 依据状态文件完整还原；状态文件记录带时间戳与旧值。
- 验收：T4.3 场景测试通过；`aaa status` 信息完整。

### P5 Web 面板

- **T5.1 只读 API**（`web/app.py`）：`GET /api/events`（分页+过滤：verdict/pid/host/dim/时间）、`GET /api/events/{id}`（body 默认脱敏——命中的 secret 打码；`?reveal=1` 显式解锁并记审计日志）、`GET /api/stats`（按进程/域名/规则聚合）、`GET /api/policy`、`GET /api/events/{id}/export`。仅监听 127.0.0.1。
- **T5.2 前端**：服务端渲染或原生 JS 静态页（**不引入重前端框架**）：流量列表+过滤器、事件详情（脱敏视图/解锁切换）、统计卡片、CSV/JSON 导出按钮。
- **T5.3 confirm 交互流**：verdict=confirm 的事件在面板列出，用户允许（记 allow 一次）/拒绝（后续同类升级 block 的缓存决策，TTL 可配）；决策走 `POST /api/decisions`。
- 验收：从面板完成「过滤→查看（脱敏）→解锁→导出」全流程 E2E（httpx 测 API 层即可，浏览器手工验证一次）。

### P6 强化（可选，按需独立排期）

- **T6.1 防绕过加固**（`setup/firewall.py`）：`aaa harden on/off`——放行本工具 443/TCP、拒绝其他进程 443/TCP、拒绝 UDP 443；svchost/Windows Update 白名单；启用前 dry-run 列受影响进程。进状态文件可还原。
- **T6.2 LLM judge**（`judge/llm.py`）：按 02 文档 D7 约束实现（脱敏+截断+成本上限+可关闭）。
- **T6.3 常驻与打包**：NSSM/计划任务安装为服务；PyInstaller 打包（注意 mitmproxy hiddenimports 清单）；托盘（独立进程 + 本地 IPC）。
- **T6.4 响应侧增强**：prompt-injection 特征标记（promptfoo 语料反向特征）；ETW 归因增强。

## 3. 开发规范

- Python ≥3.11，src 布局；全量类型注解；`ruff format` + `ruff check`（行宽 100）。
- 日志：stdlib `logging`，CLI 侧 rich 渲染；敏感值（密钥、token）打码后才能进日志。
- 配置优先级：CLI 参数 > 环境变量（`AAA_*`） > `policies/*.yaml`。
- 错误处理：引擎内任何异常捕获后 fail-open + error 事件（不崩代理进程）。
- 测试金字塔：扫描器/求值器全覆盖单测；capture/setup 层用接口注入+fixture server；每阶段至少 1 个 E2E。

## 4. 整体 E2E 验收剧本（最终演示）

`tests/e2e/test_full_scenario.py`，一条测试串起全部能力：

1. `aaa setup`（fixture 模式，CurrentUser CA + 代理设置，全部可还原）；
2. 起 mitmproxy regular 模式 + 本地 HTTPS "AI 端点" fixture；
3. 三个模拟客户端（python/node/curl）各发：正常请求 / 假 AWS key / 512KB 代码体；
4. 断言：归因正确、①放行 ②③告警（dry-run）；切 enforce 后重发 ② 得 403 且目标端点未收到；
5. `aaa status`/面板 API 可见事件；`aaa teardown` 后系统状态与初始快照一致。

## 5. 风险与回退（摘自 02 文档 §8，实施中动态维护）

| 触发 | 回退动作 |
|---|---|
| T0.3 local 模式不可用（R1） | v1 仅 regular；P2/T2.2 改为降级引导；文档标注 |
| 杀软误报严重（R2） | 默认不装机器级 CA、不用 local；提供 Defender 排除指引文档 |
| Node Agent 仍不走代理（R3） | 输出"未覆盖流量"诊断命令（`aaa status` 检查典型 Agent 进程环境变量） |
| teardown 残留（R7） | 状态文件 + 启动自检提示；提供 `aaa teardown --force`（按记录强还原） |

## 6. 交付物清单

- [ ] 可安装包（pip install -e .）+ `aaa` CLI
- [ ] `policies/default.yaml`（dry-run 出厂默认）
- [ ] 单测 + E2E（含 §4 剧本）全绿，`ruff` 干净
- [ ] `docs/notes/`：local-mode spike、decisions 日志
- [ ] `README.md` 补充：安装、快速开始、卸载、Defender 排除指引、FAQ（Agent 不走代理怎么办）
