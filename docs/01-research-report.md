# 01 · 开源生态调研报告

> 调研日期：2026-10-24（GLM-5.3，三个并行调研子任务汇总）
> 目标：为「Windows 上本机 AI Agent / 应用外发流量内容级审计工具」寻找可复用的开源项目与技术路线，明确竞品空白。

## 一、流量抓取与 TLS 还原路线

### 1.1 mitmproxy —— 主引擎选型

- 仓库：<https://github.com/mitmproxy/mitmproxy>（约 46k star，v12.x，活跃维护）
- 平台：Windows / macOS / Linux 官方一等支持，`pip install mitmproxy` 即用
- 原理：本地代理 + 自签 CA 做 TLS 拦截重组，还原完整 HTTP 明文
- 许可证：**MIT**（已核实 LICENSE 原文，可放心嵌入分发）
- 可复用点：
  - 可作为 **Python 库嵌入**（`options` + `DumpMaster` + asyncio），审计逻辑写成 addon（`request` / `response` / `client_connected` 钩子），可单测；
  - CA 首次运行生成于 `%USERPROFILE%\.mitmproxy\`，`certutil -addstore Root` 导入信任根；
  - **关键发现：mitmproxy 10.2 起内置 `--mode local[:pid|进程名]` 本地捕获模式**，Windows 上基于 WinDivert + mitmproxy_rs（用户态 TCP/IP 栈重组），由特权 redirector 子进程抓包并**原生按 PID 过滤/归因**，需管理员运行（官方文档：mitmproxy.org/posts/local-capture/windows）。
- 短板：显式代理模式下只看得到"连进本机端口的连接"，进程归因需自行补（见 §3.1）。

### 1.2 eBPF 明文抓取家族 —— Windows 不可用

- **eCapture**（<https://github.com/gojue/ecapture>，约 15.5k star，Apache-2.0）：uprobe 挂 `SSL_write/SSL_read`（OpenSSL/GnuTLS/BoringSSL/GoTLS），加密前取明文、免 CA。**README 明言不支持 Windows/macOS**（仅 Linux 4.18+ / Android），仅适合服务器侧审计。
- **alice**（eBPF 免证书 MITM）：仓库已下线（404），且本就 Linux-only。
- **Lantern**：多轮检索未找到有效的同名 eBPF TLS 项目，疑已删除/改名。
- **ebpf-for-windows**（<https://github.com/microsoft/ebpf-for-windows>，约 3.6k star，MIT）：仍不支持 uprobe / 任意用户态函数挂钩（issue #206 自 2021 年悬而未决），无法复刻 eCapture 方案。

### 1.3 Windows 原生路线

- **ETW-Schannel 密钥导出**（设想中的 "google/tlsetw"）：该仓库不存在，仅有 2018 年非官方技巧，**无成熟开源实现，不可依赖**。
- **WinDivert**（<https://github.com/basil00/WinDivert>，约 3.3k star，LGPL-3.0/GPL-2.0 双许可）：用户态 WFP 驱动，可捕获/改写/重定向任意包。v2.2.2 后基本停更但稳定；Python 绑定 pydivert 仍在维护。mitmproxy 的 local 模式已封装好这条路线，不必直接使用。
- **WFP**（Windows Filtering Platform）：按 exe 路径/签名做 per-app 过滤与阻断的官方机制，是进程级管控底座（见 1.4），也可用 `netsh advfirewall` 规则做防绕过（见 §3.2）。
- **ProcMon / Sysmon**：能力边界明确——**只记录进程↔IP:端口 元数据，看不到请求内容**（Sysmon EID 3 / ProcMon 网络事件均为元数据），仅可作行为基线与归因辅助。

### 1.4 进程级网络管控项目（架构范本，不直接复用）

- **Portmaster**（<https://github.com/safing/portmaster>，约 14k star，GPL-3.0）：内核 WFP callout 驱动拦截全部连接并识别归属进程，per-app 规则 + DNS 拦截。架构范本极佳，但 GPL-3.0 传染（直接复用代码需整体开源），且对单机 CLI 工具偏重。
- **simplewall**（<https://github.com/henrypp/simplewall>，约 9.2k star，GPL-3.0）：轻量 WFP 应用防火墙，无内容解析。
- 两者共同点：**只做管控/元数据，不做请求内容审计**。

### 1.5 TUN 透明代理（可选前置层）

- **mihomo / Clash.Meta**（<https://github.com/MetaCubeX/mihomo>，约 35k star，GPL-3.0）：TUN 模式（wintun）接管全系统流量，内置按进程匹配规则（`find-process-mode` + `PROCESS-NAME`），可把指定进程流量经 `dialer-proxy` 链式转发给 mitmproxy。作为独立二进制调用则 GPL 不传染。
- **sing-box**（39k star，GPL-3.0+附加条款）、**gost**（7.7k star，MIT）同类。
- 结论：仅当需要"全机流量治理"时才值得引入，单纯审计目的不划算（双驱动、链路长、排障复杂）。

### 1.6 SSLKEYLOGFILE + tshark 路线

仅对主动支持该变量的程序有效（浏览器、curl、Python 3.8+ stdlib）；**Node.js 不自动读取**，Schenl/.NET 原生栈不支持。适用边界：对"由我们启动的 Agent 子进程"可注入环境变量实现免 CA 解密，对不受控第三方进程不可用。

### 技术路线对比

| 路线 | 明文内容 | 进程归因 | Windows | 侵入性 | 许可风险 |
|---|---|---|---|---|---|
| **mitmproxy（显式代理 / local 模式）** | ✅ 完整 | local 原生 / 显式需补 | ✅ | 高（装 CA） | MIT，无 |
| eBPF（eCapture 等） | ✅ | ✅ 内核级 | ❌ | 低 | — |
| ebpf-for-windows | ❌ 无 uprobe | 部分 | ⚠️ 不成熟 | 中 | MIT |
| ETW-Schannel 密钥导出 | ⚠️ 无成熟实现 | ❌ | ❌ | 低 | — |
| WFP / WinDivert 管控 | ❌ 仅元数据/阻断 | ✅ | ✅ | 中 | LGPL/GPL |
| Sysmon / ProcMon | ❌ 仅元数据 | ✅ | ✅ | 低 | 可分发 |
| SSLKEYLOGFILE + tshark | ✅ | ⚠️ 需配合 | ⚠️ 部分程序 | 低 | 无 |

## 二、AI / LLM 审计与治理生态

### 2.1 LLM 网关/代理类 —— 均需应用"自愿接入"

| 项目 | 许可 | 机制 | 局限 |
|---|---|---|---|
| [LiteLLM](https://github.com/BerriAI/litellm) | MIT（enterprise 目录有边界争议） | config.yaml 声明 guardrails，pre_call 钩子可改写/拒绝请求，100+ logging callback | 应用须改 base_url 指向代理 |
| [Helicone](https://github.com/Helicone/helicone) | Apache-2.0（部分受限） | 代理 + 异步 SDK 记录 prompt/响应/成本 | 同上，维护趋缓 |
| [Langfuse](https://langfuse.com) | MIT | SDK 异步 tracing，纯观测不拦截 | 同上 |
| [Portkey Gateway](https://github.com/Portkey-AI/gateway) | MIT（平台闭源） | 路由 + guardrails + 限额 | 同上 |
| Cloudflare AI Gateway | 闭源 | 统一端点、日志、限流、guardrails | 流量须指向 CF 云端 |

**共性局限：全部依赖 SDK / 环境变量 / 显式代理自愿接入，无法覆盖不配合的本机进程。** 可借鉴：钩子抽象、密钥遮蔽、请求日志 schema、策略分层（限流/限额/内容扫描）。

### 2.2 LLM 安全/内容扫描类 —— 规则可移植

- **protectai/llm-guard**（MIT，**2026-07 已归档**）：输入/输出 scanner 框架（Anonymize/PII、Secrets、PromptInjection 等），scanner 接口设计与规则集可借鉴（注意无人维护）。
- **Guardrails AI**（Apache-2.0）：输出结构化校验，应用内嵌入。
- **NVIDIA NeMo Guardrails**（Apache-2.0）：Colang DSL 对话护栏，需嵌入应用。
- **promptfoo**（MIT）：红队扫描，100+ PII/jailbreak/injection 策略——**攻击语料可反向用作检测特征库**。
- **NVIDIA garak**（Apache-2.0）：LLM 漏洞 probes，部署前测试用。
- **protectai/rebuff**（2025-05 已归档）：仅启发式 + canary 思路可借鉴。

### 2.3 密钥/敏感信息检测 —— 规则库直接复用

- **[gitleaks](https://github.com/gitleaks/gitleaks)**（MIT）：TOML 规则（regex + entropy + allowlist），180+ 规则，**最适合直接移植为网络 payload 扫描规则源**。
- **[TruffleHog](https://github.com/trufflesecurity/trufflehog)**（AGPLv3）：代码复用有传染风险，仅可提取正则规则思路，特色是检测器 + 在线验证。
- **[Yelp detect-secrets](https://github.com/Yelp/detect-secrets)**（Apache-2.0）：YAML 插件式 regex + 熵检测 + baseline，引擎结构值得借鉴。

### 2.4 直接竞品检索（最接近但均有缺口）

| 项目 | 平台 | 能力 | 缺口 |
|---|---|---|---|
| [CC-Monitor](https://github.com/cn0xroot/cc-monitor)（MIT） | Linux/macOS | Claude Code hooks + eBPF（execve/connect）监控，可阻断 | 仅 Claude Code、**不支持 Windows**、正则规则 |
| [llm-interceptor](https://github.com/chouzz/llm-interceptor)（MIT） | 跨平台 | **基于 mitmproxy** 捕获 Claude Code/Cursor/Codex 的完整 prompt/响应，脱敏落盘 + Web UI | **只读不可阻断**、手工配代理 + CA、仅覆盖配置的域名 |
| agent-super-spy | — | 本地 LLM 观测栈 | 观测为主 |
| StepSecurity Harden-Runner | CI | GitHub Actions 场景 egress 白名单 | 仅 CI |

商业闭源同类：Aurascape 等企业 AI DLP、Microsoft Purview Endpoint DLP、Symantec/Forcepoint（驱动级采集 + 内容分类 + 分级动作的架构范式可借鉴）。

## 三、Windows 工程可行性

### 3.1 进程归因

- **psutil `net_connections()` / Win32 `GetExtendedTcpTable`**：有条件可行。需管理员权限才能看到全部连接；轮询式快照对短连接有竞态。**正确用法是在 `client_connected` 钩子里立刻用 `client_conn.peername` 的源端口反查连接表**（TCP 生命周期内源端口稳定，竞态窗口极小），作为 regular 模式的归因手段。
- **mitmproxy local 模式**：可行且最优——WinDivert 抓包原生带 PID 过滤/归因，无需自己反查（需管理员）。
- **ETW（Kernel-Network / TCPIP provider）**：可行但工程重（C# TraceEvent / krabsetw，Python 需桥接），适合后续做辅助遥测，v1 不做。

### 3.2 流量劫持方式对比

- **用户级系统代理（WinINET）**：覆盖 Chromium/Electron/多数桌面应用；不影响服务进程。
- **机器级 `netsh winhttp proxy`**：覆盖 WinHTTP 消费者（服务），与前者互补。
- **环境变量**：curl/git/Python/Go 默认遵循；**Node.js 内置 fetch 长期忽略 `HTTP(S)_PROXY`，v24 起需显式 `NODE_USE_ENV_PROXY=1`**；.NET 走 WinINET 不认环境变量；Java 需 -D 参数。→ **单一手段必有漏网，必须组合下发**。
- **绕过面**：QUIC/HTTP3（UDP 443）、硬编码直连进程。
- **防绕过**：`netsh advfirewall` 出站规则——放行代理进程的 443/TCP、拒绝其它进程 443/TCP、**封 UDP 443 逼 QUIC 回落 TLS**（Zscaler 等商用方案的标准做法；注意别误伤 svchost/Windows Update）。
- **mihomo TUN**：可行但为审计目的不划算（见 §1.5），不进 v1。

### 3.3 根 CA 信任与安全软件风险

- **导入方式**：LocalMachine 需管理员、无弹窗（`certutil -addstore Root` / PowerShell `Import-Certificate`）；CurrentUser 免管理员但 certutil 会弹确认框，用 .NET X509Store.Import 可静默。推荐管理员上下文装 LocalMachine。
- **运行时信任差异（重点）**：

| 运行时 | 代理获取 | 信任自建 CA 的方式 |
|---|---|---|
| Chromium / Electron | WinINET 系统代理 | Root 证书存储 |
| Python requests/httpx | `HTTP(S)_PROXY`（httpx 默认 trust_env） | `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE`（默认用 certifi 而非系统库） |
| Node.js | v24+ `NODE_USE_ENV_PROXY=1`（老版本内置 fetch 不认代理） | **`NODE_EXTRA_CA_CERTS`**（默认不读 Windows 证书库；`NODE_USE_SYSTEM_CA` 24+ 默认开） |
| Go | `HTTP(S)_PROXY` 默认遵循 | `SSL_CERT_FILE` |
| curl / git | 环境变量遵循 | `CURL_CA_BUNDLE` / `git http.sslCAInfo` |
| WinHTTP 服务 | `netsh winhttp proxy` | LocalMachine Root |
| Java | 需 `-Dhttp.proxyHost` | keytool 导入 |

- **AV/EDR 风险**：装根证书对应 MITRE T1553.004，主流 EDR 有检测规则；WinDivert/wintun 驱动有签名但可能被个别 AV 拦截。对策：安装动作透明化 + 用户显式确认 + 提供完整卸载；默认使用无驱动的 regular 模式，local 模式作为可选项。

### 3.4 HTTPS 内容还原替代路线与 pinning

- **SSLKEYLOGFILE**：Node.js 不自动读取（仅 keylog 事件需自行写文件），对不受控进程不可行，只作协作型进程的补充。
- **证书固定（pinning）**：openai-python、Anthropic SDK 等均基于 httpx/Node 标准 TLS 栈，**默认无 pinning**——信任根 CA 后 MITM 即成功；失败表现为 `CERTIFICATE_VERIFY_FAILED`，可据此检测并白名单直通（降级为仅元数据审计）。个别自带 pinning 的程序（部分 Google 服务/更新器）会硬失败，需白名单。

### 3.5 打包与常驻

- **PyInstaller + mitmproxy**：有条件可行，坑集中于动态导入（`mitmproxy.addons.*`、cryptography、brotli 等 hiddenimports）与数据文件；备选内嵌 Python 发行版。
- **常驻**：NSSM 包装服务最简（自动重启/日志）；注意 Session 0 隔离——核心服务与托盘 UI 分进程，经命名管道/本地 HTTP 通信。

## 四、竞品空白分析

**无人同时满足「本机任意进程 + 内容级审计 + 可阻断」**：

1. 网关类需自愿接 SDK，改不了 base_url 的进程完全逃逸；
2. MITM 类（llm-interceptor）只读、靠手工环境变量代理，无阻断；
3. hooks 类（CC-Monitor）绑定单一工具、不支持 Windows；
4. 扫描类是库形态，不能独立作用于网络流；
5. 密钥检测面向文件而非流式 payload；
6. 端点 DLP 无 LLM 语义与 AI 进程画像。

**Windows + 透明覆盖 + HTTPS 内容解析 + 事中阻断的交集是空白**——本项目即填补该空白。

## 五、结论与选型

- **采集引擎：mitmproxy（MIT 许可，作为 Python 库嵌入，审计逻辑写 addon）**，双模式：
  - regular：显式本地代理（系统代理 + 环境变量组合下发），无驱动、AV 风险最低，归因用连接表反查；
  - local：`--mode local`（WinDivert）透明抓取 + 原生 PID 归因，需管理员，防绕过最强。
- **内容扫描规则源：gitleaks（MIT）TOML 规则移植 + 自研 PII/代码外泄启发式**；promptfoo 攻击语料后续可作响应侧注入特征。
- **防绕过（可选加固）：netsh advfirewall 封直连 443/TCP 与 UDP 443**。
- **排除**：eBPF 类（Windows 无 uprobe）、ETW-Schannel 密钥导出（无成熟实现）、mihomo TUN 前置（过度设计）、Portmaster/simplewall 复用（GPL 传染）。

## 附录：主要来源

- mitmproxy：<https://docs.mitmproxy.org/stable/concepts/modes> · <https://www.mitmproxy.org/posts/local-capture/windows> · <https://docs.mitmproxy.org/stable/concepts/certificates>
- eCapture：<https://github.com/gojue/ecapture>；ebpf-for-windows：<https://github.com/microsoft/ebpf-for-windows>（issue #206）
- WinDivert：<https://github.com/basil00/WinDivert>；pydivert：<https://github.com/ffalcinelli/pydivert>
- Portmaster：<https://github.com/safing/portmaster>；simplewall：<https://github.com/henrypp/simplewall>
- mihomo TUN/进程规则：<https://wiki.metacubex.one/config/inbound/tun>
- Node 代理变量：<https://github.com/nodejs/undici/blob/main/docs/docs/api/EnvHttpProxyAgent.md>；Node CA：<https://nodejs.org/api/cli.html>
- gitleaks：<https://github.com/gitleaks/gitleaks>；detect-secrets：<https://github.com/Yelp/detect-secrets>
- LiteLLM guardrails：<https://docs.litellm.ai/docs/proxy/guardrails/custom_guardrail>
- QUIC 防绕过：<https://help.zscaler.com/zia/managing-quic-protocol>
- 根证书风险：<https://attack.mitre.org/techniques/T1553/004>
- WFP：<https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page>；Sysmon：<https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon>
