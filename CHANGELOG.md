# 更新日志 Changelog

## [v0.3.0] - 2026-10-25

体验与生态（洞察清单 ③+④，docs/06-v030-experience-plan.md）：波次一 8 个并行模块
（服务化/托盘/安装器/性能/i18n/日报/规则市场/多机聚合）+ 波次二集成。**外发类能力
（hub 转发、gitleaks 下载）默认关闭**，升级零惊扰。

### 新增

- **Windows 服务化**（W1）：`aaa service install|uninstall|status`——ONSTART 计划任务
  （SYSTEM 账户、RunLevel 可选 `--highest/--limited`），开机无人登录即拉起代理
  （日志 `data/service.log`）；journal-first 记入 setup-state.json；与登录自启任务
  双开时互斥提示（建议而非强制）；`aaa teardown service` 可还原。需管理员（非提权
  exit 2 + UAC 指引）。
- **系统托盘**（W2）：`aaa tray`（extra `pip install -e .[tray]`，缺依赖退出码 2 +
  pip 提示）——状态只读展示 / 打开面板（端口去重）/ 启动·重启代理 / 退出；只读编排层
  绝不杀进程、不改代理设置；图标 svg→png→盾形绘制三级降级。
- **Inno Setup 安装器**（W3）：`installer/egress-sentinel.iss` + CI `installer` job
  （仅 windows-amd64，tag 触发）产出 `egress-sentinel-setup-v<版本>.exe`；卸载时先
  taskkill 结束常驻进程、执行 `teardown`（幂等还原）再删文件；用户数据 `data/` 保留；
  版本号经 `scripts/iss_version.py` 从 pyproject 注入，未注入编译即报 `#error`。
- **HTML 日报/周报**（W6）：`aaa report --daily|--weekly [--email] [--day] [--out]`——
  自包含单文件 HTML（按判定/进程/主机/规则聚合 + Top 事件 + 内联 SVG 趋势）；
  路径/进程名经通知同一脱敏核心打码、表格 HTML 转义、不含 body 原文；`--email`
  经策略 notifications.email 通道（注入式 SMTP）；`aaa teardown daily` 还原计划任务。
- **规则市场**（W7）：`aaa rules export|import <section> [--merge replace|union]`——
  策略段导出/导入，pydantic 三关校验全过才原子落盘（不合法绝不写）；union 按 id/键
  合并（导入者胜）。`aaa gitleaks sync <URL|路径>`——gitleaks TOML 转本引擎 secrets
  规则包（正则+熵+allowlist 映射、sha256 pin、不支持特性如实跳过并记录）。
- **多机聚合**（W8，默认关）：agent 端 Forwarder（脱敏摘要 + 队列 + 退避重试 +
  ≤50 条/批 + trust_env=False 直连）；中心端 `aaa hub serve`（Bearer 鉴权、
  内存缓冲 → `data/hub.db` 机器名维度、跨机聚合查询）；`aaa hub forward status`
  读取运行中 agent 的统计快照（`data/hub-forward.json`）。策略 `hub:` 段或
  `AAA_HUB_URL`/`AAA_HUB_TOKEN` 环境变量（试用意图收窄版：两者都由 env 补齐且策略
  从未配置才自动启用）。
- **多 profile 策略切换**：`aaa policy use <name>|--reset` + `aaa policy list`——
  `policies/profiles/*.yaml`（出厂自带 work/dev/strict 三份）拷贝为 `current.yaml`
  （校验不过不切换、保留 YAML 注释），存在即成为所有命令缺省策略，运行中 `aaa run`
  约 2 秒热更新生效；出厂 `policies/default.yaml` 永不被覆盖。
- **双语 CLI**（W5）：全部用户可见文案（含 typer 帮助与向导）经 `t()` 取词，
  `aaa --lang en <命令>` / `AAA_LANG=en` 切英文（en 全量翻译，`--help` 全英文）；
  默认 zh 输出与 v0.2.x 逐字一致；缺词条回落 zh 并计数，绝不中断命令。
- **性能**（W4）：事件批量落盘（`aaa run --db-batch N`，默认 20，整批单事务，
  阻断/fail-open/error 事件始终立即落盘）；内容扫描采样（策略 `sampling:` 段，默认关，
  body 超限时非豁免扫描器只扫头部字节，**secrets 豁免全扫不回退**）；SQLite WAL +
  synchronous=NORMAL（旧库打开自动迁移）；事件规则表覆盖索引。

### 变更

- 版本 0.2.0 → 0.3.0；`aaa --version` 输出随之更新。
- 策略 schema 新增 `sampling` / `hub` 两段（默认全关；老策略文件无这些段照常加载）；
  `policies/default.yaml` 追加两段注释说明 + `policies/profiles/` 三份示例。
- `aaa teardown` 目标新增 `service`（服务任务）与 `daily`（日报任务）。
- `aaa policy lint` 摘要新增 `sampling` / `hub` 行；`aaa run` 启动概要新增
  采样与 hub 转发两行。
- `aaa hub` 包 `__init__` 改为惰性导出（PEP 562）：`policy.model` 引用
  `HubConfig` 后，基础安装（无 web extra）不再因 collector 顶层 fastapi 导入而失败。
- ruff 对 `src/aaa/cli.py`（typer 参数默认值 DSL 的 B008 误报）与 `src/aaa/locales/*`
  （纯数据词条行）改为 per-file 豁免。
- 新增测试：`tests/unit/test_wave2_integration.py`（29 例，schtasks/网络全注入）、
  `tests/e2e/test_v030_experience_e2e.py`（6 例：profile 切换热更新真代理往返 /
  `--lang en` 子进程冒烟 / 日报渲染脱敏 / forwarder→collector 本机 TCP 往返）；
  `tests/conftest.py` 增 i18n 状态隔离夹具。

### 已知边界（如实登记）

- `aaa --lang` 影响运行时输出与（经启动期预扫描的）帮助文本；词条缺失回落 zh。
- hub 中心 `GET` 端点同样要求 Bearer（局域网监听、跨机审计数据从紧）；
  `hub.db`/`audit.db` 不整库加密（同 D-2026-10-24-39 边界，依赖磁盘级加密）。
- W7 导入为整文重写，原策略 YAML 注释丢失（命令输出提示，可先 export 备份）。
- 托盘 SVG 渲染依赖可选后端（cairosvg 未声明为依赖），缺省走 png/盾形兜底。

## [v0.2.0] - 2026-10-24

安全能力深化（洞察清单 ②，docs/05-security-deepening-plan.md）：四个新模块 + 全链路
集成，**全部默认关闭**——升级零惊扰，逐项显式开启。

### 新增

- **仓库指纹比对**（`aaa fingerprint build [--repo PATH] [--rebuild]`）：把本地 git
  仓库工作区按行滑窗切片建指纹库（`data/fingerprints.bin`，多仓库合并、5MB/文件与
  200 万片限流防 OOM）；策略 `fingerprint.enabled` 开启后，外发请求体与库比对——
  整段代码外发即命中，事件附指纹命中清单（repo/file/line + 80 字符片段）。建库纯
  本地、零外发、不执行任何 git 命令。
- **响应侧注入检测**：扫描响应体中的提示词注入特征（指令覆盖/角色伪造/越狱模板/
  隐藏载体/套取系统提示词，纯 regex 零网络）；策略 `response.rules` 配置标注规则
  （`patterns: all|high`），命中**仅 alert 级标注、绝不阻断响应**——响应体原样送达。
- **LLM 辅助判定**：alert 级以上事件把（脱敏后的）摘要发给 OpenAI 兼容端点做第二
  意见判定（是否违规/置信度/理由/类别），结论记事件 `judge_note`。异常/超时/非法
  输出一律收敛为"不可用"，绝不影响审计；API key 只从环境变量 `AAA_JUDGE_API_KEY`
  读取不落盘；每日预算封顶（默认 200 次，只计成功调用）；判定请求直连不走本机代理
  （防回环）。策略 `judge` 段配置，默认关。
- **证据静态加密**：策略 `encrypt.enabled` 开启后，请求 body 证据文件以 AES-256-GCM
  落盘（`ES01` 魔数头）；密钥自动生成 `data/.crypto-key`（32B，权限收紧）或环境变量
  `AAA_MASTER_PASSWORD` 口令 PBKDF2 派生；**读取永远透明兼容**——旧明文证据原样可读、
  关闭加密后仍能解密历史密文；`sha256` 按密文文件计算（无密钥也可复核完整性）。
  已知边界：`audit.db` 事件库元数据暂不整库加密（详见 docs/notes/decisions.md
  D-2026-10-24-39，需要整库保密请配合 BitLocker 等磁盘级加密）。
- **防火墙加固实装**（替换 v0.1.x 的 P6 占位）：`aaa harden on` 创建 4 条
  `EgressSentinel-` 前缀规则（放行代理/svchost 443/TCP、阻止任意程序 443 TCP/UDP），
  journal-first 记入 setup-state.json；`aaa harden off` / `aaa teardown firewall`
  幂等还原。需管理员。**已知边界**：Windows 筛选平台 Block 优先于 Allow，any-Block
  会同时命中代理与 svchost 白名单——加固后 443 出站可能全断（含本工具代理），命令
  输出与文档均如实警示，off 即还原（详见 decisions.md D-2026-10-24-38）。

### 变更

- `policy/model.py` 新增 `fingerprint` / `judge` / `response` / `encrypt` 四段
  （pydantic 严格校验，全部默认关/空；老策略文件无这些段照常加载）；`repo_fingerprint`
  成为合法内容扫描器名；`response.rules[].action` 只接受 `alert`（响应侧红线在
  schema 层固化）。
- `aaa run` 启动概要新增三行安全深化状态（指纹 / LLM 判定 / 证据加密，含当日判定
  预算用量）；`aaa status` 防火墙行改为真实加固状态，另加"安全深化"概要行；
  `aaa policy lint` 增列四新段。
- 证据存储 `EvidenceStore` 支持注入加密引擎（`crypto=` 参数）与 `read_body()` 透明
  读取；事件模型新增 `judge_note` 字段。
- 版本 0.1.3 → 0.2.0。

### 升级与兼容

- 老策略文件无需修改（新段缺省=全关）；加密开启前请确认 `data/` 目录已纳入备份——
  密钥材料丢失即无法解密既有密文（工具会如实报错，绝不静默重建掩盖）。
- `harden` 从占位变为实装：原先依赖其非零退出码的脚本需改为感知新行为。

## [v0.1.3] - 2026-10-24

### 新增

- **告警通知渠道**（洞察清单 ①-1）：block / alert / confirm 事件发生时**即时通知用户**，
  无需打开面板——审计的「最后一公里」：
  - **Windows 系统通知（toast）**：PowerShell WinRT 实现，零第三方依赖，出厂默认开启
    （本机通知、无外发）；
  - **Webhook**：generic / 企业微信 / 钉钉 / 飞书 / Slack / Discord 六种 payload 形态，
    3 秒超时、失败自动重试 1 次；`trust_env=False` 直连（绝不经本机代理，防回环）；
  - **SMTP 邮件**：SMTP_SSL / STARTTLS 纯文本摘要；
  - **防轰炸**：每通道滑动窗口限流（默认 10 条/分钟），超出部分自动合并为一条
    「另有 N 条事件被限流」摘要；代理退出时有界排空（flush 2s）不丢 digest。
- **通知正文与面板同一脱敏核心**：命中的密钥一律打码（`AKIA****YZ` 形态）后才出现在
  通知里——绝不把拦截到的明文密钥再外发到 webhook/邮件（安全红线）。
- **配置随策略热更新**：通知段在策略 YAML 的 `notifications` 段（pydantic 严格校验，
  拼写错误即 lint 报错），改完保存约 2 秒生效，无需重启；老策略文件无该段=全关兼容。
- **环境变量覆盖凭据**：`AAA_WEBHOOK_URL`、`AAA_SMTP_PASSWORD` 优先于策略文件——
  webhook 地址内嵌 token、SMTP 密码不必落盘。
- **`aaa notify test [--channel toast|webhook|email]`**：发一条测试通知（真实通道，
  用户显式触发；失败如实以非零退出码报告）；`aaa status` 增加通知配置概要行。

### 变更

- `aaa run` 启动概要新增通知行（启用通道/门槛/限流）；事件库新增通知入队与被限流统计。
- `policies/default.yaml` 新增 `notifications` 段（toast 开、webhook/email 关）。

## [v0.1.2] - 2026-10-24

### 新增

- **安装即守护**：`aaa setup` 完成后默认**立即后台启动审计代理**——五维规则与三大扫描器
  开箱全量监控，无需手动 `aaa run`，也无需等待重启触发自启。
- **策略热更新生效可见**：策略文件保存后约 2 秒自动生效（本就无需重启），现在版本变化
  会写入运行日志（控制台与 `data/autostart.log` 可见「策略已热更新：xxxx → yyyy」）。
- **Release 自动附更新说明**：打包 tag 的 GitHub Release 现在自动携带本文件对应版本段落
  （`scripts/release_notes.py` 提取）。

### 变更

- 官网补全 v0.1.1/v0.1.2 能力：常驻与自愈、开机即守护、策略热更新、断网自愈 FAQ（中英双语）。

## [v0.1.1] - 2026-10-24

### 新增

- **关机/注销优雅退出**：接管 Windows 关机、注销、控制台关闭事件，代理在 4 秒内限时收尾
  （低于系统 5 秒上限，绝不阻塞关机）；事件库每事件事务落盘，强退不丢已入库数据。
- **开机自启**：登录计划任务自动拉起 `aaa run`（`aaa setup` 末步默认询问安装；
  `aaa autostart on / off / status` 独立管理；日志 `data/autostart.log`）。
- **自检自愈 watchdog**：登录 30 秒后检测「系统代理已启用但代理端口不可达」的断网态，
  `--fix` 自动还原代理设置与代理环境变量（CA 保留），网络立刻恢复；`aaa status` 内置
  预警与自启状态；日志 `data/watchdog.log`。

### 变更

- `aaa teardown` 新增 `autostart` 目标（连计划任务一并还原）；`aaa run` 新增 `--log-file`。

## [v0.1.0] - 2026-10-24

首个版本。

- 双模式采集：regular（显式本地代理，无需管理员）/ local（WinDivert 透明抓取，需管理员）；
- HTTPS 明文级审计（mitmproxy，MIT 许可）+ 每请求归因到进程（PID/exe/命令行/签名者）；
- 五维规则引擎（域名/进程/内容/体量/时间窗）+ 43 条 gitleaks 移植密钥规则 + PII + 代码外泄检测；
- 四级动作 allow/alert/confirm/block，enforce 事中 403 阻断；出厂默认 dry-run 只告警；
- SQLite 事件库 + 截断证据文件（sha256）+ 面板脱敏展示（`?reveal=1` 显式解锁并记审计）；
- journal-first 全量系统改动记录与幂等 teardown（崩溃后仍完整还原）；
- 本地 Web 面板（FastAPI，仅 127.0.0.1）；CI 矩阵（Python 3.11-3.13 × amd64/arm64 ×
  Linux/Windows/macOS）；五平台单文件可执行；GitHub Pages 官网。
