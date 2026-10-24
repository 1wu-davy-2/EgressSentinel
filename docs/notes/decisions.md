# 设计决策日志

> 依据 03 文档 §0：设计有歧义或与现实冲突时，把决策记录在此（日期+问题+选择+理由）。

## D-2026-10-24-01 store 层新增 events.py / jsonl.py

- 问题：02 文档 §4 代码结构中 store 只列出 `db.py`、`evidence.py`，但 T1.2 要求
  "事件对象 + JSONL 直写"。
- 选择：新增 `store/events.py`（02 文档 §6 事件模型的 pydantic 化，P1 子集）与
  `store/jsonl.py`（`data/raw/YYYYMMDD.jsonl` 直写）。
- 理由：事件模型被 capture/web/engine 多处共享，独立成模块；P4/T4.1 再加 `db.py`
  收敛双写。不与设计冲突，只是提前补齐存储接口。

## D-2026-10-24-02 setup 层新增 state.py / teardown.py / admin.py

- 问题：02 文档 §4 未列出状态文件管理与 teardown 的实现位置，T1.4/T1.5/T0.3 需要。
- 选择：新增 `setup/state.py`（setup-state.json 读写，pydantic 模型）、
  `setup/teardown.py`（逆序幂等还原 + RESTORERS 注册表）、`setup/admin.py`
  （ctypes 管理员检测）。
- 理由：03 文档明确要求这些行为；集中在 setup/ 符合"平台相关逻辑集中在 setup/"约定。

## D-2026-10-24-03 事件落盘时机：单流单行，response/error 时写入

- 问题：03 文档 T1.2 列出 client_connected/request/response 三钩子"产出事件对象，
  JSONL 直写"，未规定一行还是多行。
- 选择：`request` 钩子构建事件对象并保存 body 证据文件（不写 JSONL）；
  `response` 或 `error` 钩子补全后写一行完整事件（每条 flow 一行）。
- 理由：P4 收敛 SQLite 时一条 flow 对应一行最干净；error 钩子保证响应未达成的流
  也留痕。client_connected 记连接元数据（P2 归因接入点）。

## D-2026-10-24-04 P1 事件的 verdict/action_taken 取值

- 问题：02 文档 §6 的 verdict ∈ allow/alert/confirm/block，但策略引擎在 P3 才有。
- 选择：P1 事件 `verdict="unassessed"`、`action_taken="logged"`（流错误时
  `action_taken="error"`），`process=null`（P2 归因接入后填充）。
- 理由：如实反映"P1 尚无判定"，避免伪造判定结果。

## D-2026-10-24-05 setup 改动 journal-first（先记后改）

- 问题：03 文档 T4.3（P4）才做崩溃安全，但状态文件的写入时机现在就要定。
- 选择：所有 setup 改动**先读旧值 → 先写状态条目 → 再实施**；实施失败保留记录
  （teardown 重放为幂等 no-op）。
- 理由：write-ahead 日志语义，kill -9 也能依据记录还原；teardown 幂等使"记录了但
  没改成功"无害。

## D-2026-10-24-06 setup/teardown CLI 增加 --dry-run 标志

- 问题：02/03 文档未给 setup 命令 dry-run 选项；但工作约定红线要求开发/测试环境
  不得真实施改系统设置。
- 选择：`aaa setup ca/proxy/env` 与 `aaa teardown` 均支持 `--dry-run`（只打印计划
  动作，不写状态文件、不改系统）。
- 理由：满足红线下的可演示性；与"出厂默认 dry-run"（03 文档 §0，指策略 enforce
  模式）不冲突，属命令层附加安全阀。

## D-2026-10-24-07 CurrentUser CA 导入经 PowerShell 调 .NET X509Store

- 问题：03 文档 T1.3 要求"CurrentUser 用 .NET X509Store 静默导入"；纯 CPython 无
  pythonnet 时不能直接调 .NET。
- 选择：用 PowerShell（-NoProfile -NonInteractive）执行内嵌 .NET X509Store 脚本
  （`X509Store('Root','CurrentUser').Open('ReadWrite').Add(cert)`，静默无弹窗）；
  卸载脚本按 `SerialNumber -eq <serial>` 精确匹配，输出删除数量。
- 理由：满足"用 .NET X509Store"的字面要求且零新增依赖；序列号先经
  `^[0-9A-Fa-f]+$` 校验防注入。

## D-2026-10-24-08 NO_PROXY 采用文档字面值

- 问题：02 文档 D1 写 `NO_PROXY=localhost,127.0.0.1`；工程上常再加 `::1`。
- 选择：按文档字面值 `localhost,127.0.0.1` 实现（`envvars.NO_PROXY_VALUE`）。
- 理由：与设计文档保持一致；如需扩展在 P3+ 决策中再改。

## D-2026-10-24-09 证据 file 字段相对 data_dir

- 问题：02 文档 §6 示例为 `"file": "data/evidence/evt_....bin"`（相对项目根），
  但数据目录可经 `AAA_DATA_DIR`/`--data-dir` 改到任意位置。
- 选择：`EvidenceInfo.file` 存相对 **data_dir** 的 POSIX 路径（`evidence/<event_id>.bin`），
  解析时与 data_dir 拼接；目录层级（evidence/）与设计一致，仅去掉硬编码的 `data/` 前缀。
- 理由：数据目录可重定位；测试与生产解析逻辑一致。

## D-2026-10-24-10 SNI 阶段阻断改用 tls_start_client（mitmproxy 12 无 kill 属性）

- 问题：02 文档 D5 要求"域名 blocklist 在 CONNECT/SNI 阶段 kill flow"，但 mitmproxy 12.3.0
  的 `tls.ClientHelloData` 已无 `kill` 属性（仅 `ignore_connection`，语义是不拦截而非阻断）；
  实测在 `tls_clienthello` 钩子里设置 `context.client.error` 不会中断握手（探针验证：
  握手仍成功）。
- 选择：阻断点移到 `tls_start_client` 钩子——SNI 命中 blocklist 时设 `conn.error` 并保持
  `ssl_conn=None`，mitmproxy TLS 层会发出 `CloseConnection`（proxy/layers/tls.py 的
  既有关闭路径）。已用真实代理 + 原生 socket TLS 握手探针验证：连接被杀（UNEXPECTED_EOF）。
- 理由：利用框架已验证的关闭路径，不依赖未定义行为；SNI 在 ClientHello 解析后即可从
  `conn.sni` 读取，阻断时点不晚于设计要求。

## D-2026-10-24-11 connection_strategy 强制 lazy（阻断前不触达目标）

- 问题：mitmproxy 12 默认 `connection_strategy="eager"`，会在 TLS 握手前就建立上游 TCP
  连接——blocklist 域名在被 SNI 阻断前已经被接触，违背 D5 意图。
- 选择：`CaptureEngine.serve()` 在 master 构造后设置 `connection_strategy="lazy"`
  （该选项由 proxyserver addon 注册，不能在 `Options()` 构造期传入）。
- 理由：审计工具的安全语义优先；与 CONNECT 阶段 403/SNI kill 组合后，被阻断域名
  零 TCP 触达（e2e 中端点未收到被阻断请求）。

## D-2026-10-24-12 local 模式原生 PID：--pid/--process 规格 + pinned_process

- 问题：02 文档 D2 写"local：直接使用 mitmproxy 提供的进程信息"，但 mitmproxy 12.3.0 的
  `LiveConnectionHandler`（proxy/server.py）只把 Stream 的 peername/sockname/
  transport_protocol 拷入 `client_conn`，mitmproxy_rs 的 `get_extra_info("pid")` 并未暴露。
- 选择：`aaa run --mode local [--pid N | --process name]` 拼装 `local:pid=N` /
  `local:process=name` 规格（mitmproxy_rs `describe_spec` 已验证接受），由 WinDivert 在
  包层按 PID/进程名过滤——捕获到的流量天然属于该进程；CLI 启动时经 psutil 解析该进程
  元信息，作为 `pinned_process` 直接落事件（事件 mode=local 且带原生 PID）。
  未给 --pid/--process 时回落连接表归因。
- 理由：规格层过滤是 mitmproxy 原生能力（03 文档 T2.2"透传 mitmproxy local 参数"的字面
  实现）；事件归因不依赖 mitmproxy 未暴露的字段。真实管理员环境的行为列入
  local-mode-spike 的 needs-manual 清单。

## D-2026-10-24-13 unknown 首连的判定粒度：引擎实例内按主机全局记忆

- 问题：02 文档 D4"未知首连告警"未定义粒度（每进程？每主机？全局？）。
- 选择：管线内维护 seen_hosts 集合（引擎生命周期内）；`match: {class: unknown}` 的
  域名规则仅在"该主机首次出现"时命中，后续对该主机的 unknown 访问不再重复告警。
- 理由：首连告警的价值是"发现新的外联目标"，重复告警会造成噪音；跨引擎重启重新
  告警（内存态，不持久化）符合"首连"直觉。若后续需要每进程粒度，在规则 match 里
  加 `first_per_process: true` 一类条件即可扩展。

## D-2026-10-24-14 未归因事件的 process 形态：显式 unknown 而非 null

- 问题：02 文档 D2 要求"查不到记 unknown 并对 unknown 速率单独告警"，但事件模型
  `process` 是可空对象，null 与"查了但没查到"无法区分。
- 选择：配置了归因器时，未命中事件写 `process = {pid: null, name: "unknown",
  profile: "unknown"}`（显式标记）；未配置归因器（P1 行为/纯管线测试）保持 `null`。
  addon 增加 `unknown_attribution_count` 计数与 `attribution_summary()`。
- 理由：诚实区分"没查"与"没查到"；unknown 速率告警（02 文档 D2）有直接数据来源。

## D-2026-10-24-15 引擎异常的两种事件形态：fail-open 与 fail-closed

- 问题：02 文档 D5"fail-open（引擎异常放行并记 error 事件）"与"fail-closed 可配"
  未定义事件字段形态。
- 选择：求值出错时事件 `error` 字段记录异常摘要（含维度/扫描器名）；
  - fail_open=true（默认）：放行，`action_taken="fail-open"`（与流错误 `"error"` 区分）；
  - fail_open=false：按求值结果执行（通常 block → enforce 下 403），事件照常落盘。
  策略热更新解析失败时保留上一份好策略并记日志（不崩代理）。
- 理由：两种失败模式行为可区分、可审计；与 addons 的 fail-open 约定（异常不传播）
  一致。

## D-2026-10-24-16 run 落盘收敛为仅 SQLite（`--jsonl` 为可选镜像开关）

- 问题：03 文档 T4.1"启动时 JSONL 与 DB 双写可收敛为仅 DB（保留 JSONL 开关）"未定
  默认值。
- 选择：`aaa run` 默认仅写 `data/audit.db`（02 文档 D6），`--jsonl` 显式开启才镜像
  `data/raw/YYYYMMDD.jsonl`（`DbEventStore.mirror`）。采集侧 sink 以 `EventSink`
  Protocol（`store/db.py`）注入，既有 JSONL 测试不受影响。
- 理由：按 T4.1 字面"收敛为仅 DB"；SQLite 为唯一事实源，JSONL 降级为调试留痕。

## D-2026-10-24-17 confirm 决策语义：deny 缓存 (host, 命中规则集)，allow 一次性

- 问题：03 文档 T5.3"允许（记 allow 一次）/拒绝（后续同类升级 block 的缓存决策，
  TTL 可配）"未定义"同类"的键与 allow 的缓存语义。
- 选择：决策键 = `decision_key(host, sorted(rule_ids))`（`store/decisions.py`）；
  **deny** 写入 `data/decisions.json`（跨进程共享：采集与面板可能是两个进程），
  TTL 内 addon 在 confirm 判定上升级 block（enforce 下事中 403，dry-run 下仅判定
  升级）；**allow** 只落事件行（`events.decision`），不进缓存——后续同类请求再次
  confirm。TTL 默认 3600s，`POST /api/decisions.ttl_seconds` 或 `AAA_CONFIRM_TTL`
  可配。
- 理由：deny 缓存"同类"取"同主机+同命中规则"最贴近字面且避免按 host 过宽误伤；
  allow 按"记 allow 一次"字面实现为一次性放行，不静默扩大允许面。

## D-2026-10-24-18 body 默认脱敏：secrets 规则明文片段替换（与扫描器同一匹配核心）

- 问题：02 文档 D6"命中的 secret 打码"未定打码算法；`ScanHit.evidence` 是已打码
  值，无法据其还原原文位置。
- 选择：`scanners/secrets.py` 抽出 `iter_secret_spans()`（规则+allowlist+熵阈值
  的同一匹配核心，返回 `(rule, lineno, start, end)`），`scan_secrets` 与
  `web/masking.mask_secret_spans` 共用；脱敏替换为 `⟦规则id|mask_secret(片段)⟧`
  （`mask_secret` 与 evidence 打码约定一致）；重叠命中合并为一个区间。v1 仅对
  secrets 打码（任务卡字面"命中的密钥打码"），PII 不打码。
- 理由：单一匹配核心保证"扫描命中 ⇔ 脱敏命中"永不漂移；保留首尾字符的打码形态
  便于人工核对是否误报。

## D-2026-10-24-19 `aaa web` 独立命令作为面板启动入口

- 问题：02 文档 §2 的 CLI 命令清单（setup/run/status/tail/report/policy/teardown/
  trim）未包含面板启动入口，但 T5.x 需要可运行的面板。
- 选择：新增 `aaa web [--port 8787]`，宿主 `127.0.0.1`（非回环地址在参数层直接
  拒绝，`assert_loopback` 双保险）；`run` 不并起面板，保持采集进程单一职责。
- 理由：进程分离与 T5.3 的跨进程决策缓存设计一致；不改变 02 文档既有命令语义。

## D-2026-10-24-20 SQLite 冗余 ts_epoch 列 + rowid 游标

- 问题：事件 `ts` 是带时区的 ISO 字符串，字符串比较跨时区不可排序；`tail` 需要
  增量游标。
- 选择：events 表冗余 `ts_epoch`（unix 秒，索引列）用于时间过滤/排序；`tail` 以
  SQLite `rowid` 为游标（`poll_after`），`aaa status`/API 均按 `ts_epoch DESC` 取。
- 理由：时间维索引（02 文档 D6）落在可比数值列上；rowid 单调递增天然是落盘顺序
  游标，不依赖事件 ID 的字典序。

## D-2026-10-24-21 frozen 打包路径解析（PyInstaller onefile）

- 问题：exe 化后 `PROJECT_ROOT` 不存在；策略文件、静态资源、可写数据目录需要
  frozen 感知。
- 选择：`config.py` 在 `sys.frozen` 时：只读资源（policies/、web static）取
  `sys._MEIPASS`（build_exe.py 以 `--add-data` 打包），可写数据目录取
  exe 同级 `data/`；build_exe.py 以 `pkgutil.iter_modules` 在构建期枚举
  `mitmproxy.addons.*`/`mitmproxy.contentviews.*`/`mitmproxy.contrib.kaitaistruct.*`
  为 hiddenimports，另加 brotli/kaitaistruct/mitmproxy_rs/cryptography rust 后端。
- 理由：实测 onefile 构建 + 冒烟（`--version`/`policy lint`/`status`/真实代理转发
  一条请求并落库）全部通过；枚举式声明避免逐版本手工维护清单。

## D-2026-10-24-22 harden 占位命令以非零退出码如实报告未实施

- 问题：03 文档 T4.2 要求 `harden on/off` 占位提示，但占位命令的退出语义未定。
- 选择：`aaa harden on|off` 打印"P6 未实施"说明并以退出码 1 结束；任何参数都不
  触碰防火墙。
- 理由：退出 0 会向脚本谎报"加固成功"；诚实失败（03 文档 §0 安全红线）优先。

## D-2026-10-24-23 整体剧本落地：setup/teardown 走真实 CLI 代码路径 + 全系统后端注入假实现

- 问题：03 文档 §4 剧本要求 `aaa setup`（CurrentUser CA+代理+环境变量）的真实应用
  路径与 teardown 还原闭环，但安全红线禁止测试真实施改系统设置；此前向导仅覆盖
  dry-run/拒绝路径，"teardown 后与初始快照一致"只有库调用+假后端的模拟。
- 选择：`tests/e2e/test_full_scenario.py` 以真实 typer 入口执行 `aaa setup --yes` 与
  `aaa teardown`，但 `setup.envvars`/`setup.proxy` 的注册表与广播函数经共享夹具
  `fake_backends`（上移至 tests/conftest.py，unit 与 e2e 共用）注入 dict 后端；CA
  安装/卸载（PowerShell X509Store/certutil）以记录器假函数替换。teardown 后断言假
  注册表/环境变量与初始快照逐键一致、状态文件清空、工具创建的 PEM 已删、CA 按安装
  序列号精确卸载、二次 teardown 幂等。同时修复验收发现：test_cli_p4 的 CLI teardown
  测试此前只屏蔽广播、未注入假后端，会对真实 HKCU\Environment 调
  winreg.DeleteValue——现强制挂 `fake_backends`。
- 理由：验证的是"应用与还原逻辑本身"（向导 → journal-first → 状态文件 → RESTORERS
  全链路），绝不触碰真实系统；本机 HKCU\Environment 存在 HTTPS_PROXY/NO_PROXY 与
  明文 API key，真实执行任何还原都会造成不可逆数据丢失。

## D-2026-10-24-24 e2e fixture HTTPS 化（T3.5）+ 真实 TLS SNI kill 回归 + ProxyConfig.ssl_insecure

- 问题：T3.5 要求"本地 HTTPS fixture server 充当 AI 端点"，此前实现为明文 HTTP；
  mitmproxy TLS 解密路径（02 文档 G1"HTTPS 为主战场"）与 D-10 的 SNI kill 只有一期
  手工探针验证，无自动化回归防线（mitmproxy 升级改变 tls_start_client 语义不会被发现）。
- 选择：conftest 新增 `https_fixture_server`（cryptography 自签名证书只落 tmp_path，
  ThreadingHTTPServer + ssl 包装，请求记录与 HTTP fixture 一致）；test_audit_pipeline.py
  （T3.5）整体切换 HTTPS——客户端以 `verify=ssl.create_default_context(cafile=<mitmproxy
  CA>)` 严格校验（进程级注入信任，不改证书存储），请求能命中内容规则即证明流量经过
  CONNECT → TLS 拦截 → 解密 → 明文求值全链路；新增原生 socket CONNECT+TLS 握手探针
  测试（D-10 手工探针的自动化版）：enforce 下 SNI 命中 blocklist 握手必须被杀
  （OSError），对照组 SNI 握手正常，且两类探针不产生 HTTP 事件。为支持自签名上游，
  `ProxyConfig` 新增 `ssl_insecure: bool = False` 透传 mitmproxy 同名选项（mitmproxy 12
  默认 VERIFY_PEER 按 certifi 信任库校验上游证书，不认 fixture 自签名证书；生产默认值
  不变）。
- 理由：SNI kill 是 D5 的关键安全行为，必须有自动化回归；上游校验开关是引擎级配置
  而非测试后门，客户端侧校验在所有测试中保持开启。

## D-2026-10-24-25 三客户端 TLS 信任注入方式（python/node/curl）与 curl 回退

- 问题：§4 剧本三客户端都要经 mitmproxy TLS 拦截，但测试不能改系统证书存储；本机
  curl 7.63 为 Schannel 构建，`--cacert` 不生效（实测报 CERT_TRUST_IS_UNTRUSTED_ROOT，
  Schannel 校验的是 Windows 证书库而非指定 CA 文件）。
- 选择：httpx 用 `verify=` 严格校验 mitmproxy CA；node 用 `NODE_EXTRA_CA_CERTS` 严格
  校验（SNI 用 localhost——RFC 6066 禁止 SNI 放 IP 字面量，node 会 DEP0123 告警；CONNECT
  隧道目标仍为 127.0.0.1）；curl 先试 `--cacert`、失败自动回退 `-k`（本机 Schannel 必然
  回退；CONNECT+TLS 拦截解密路径两者完全相同，信任锚的强校验由 httpx/node 覆盖）。
  另外两个坑：curl 子进程必须剔除 NO_PROXY/HTTPS_PROXY 等代理类环境变量，否则本机
  用户级 `NO_PROXY=…,127.0.0.1,…` 会让 curl 绕过 `-x` 直连目标（与
  test_regular_capture_e2e `_env_without_proxy` 同一教训）；node 客户端不发
  `Connection: close`（代理侧关闭与响应送达存在竞态导致 ECONNRESET），读到响应后主动
  destroy。
- 理由：三条客户端路径都真实经过拦截与解密；信任校验的强断言放在支持严格校验的
  客户端上，curl 的回退行为如实记录、可被 --cacert 可用的 curl 构建直接用上。

## D-2026-10-24-30 · CI 跨平台矩阵落地记录（Linux/macOS 已知缺口登记）

- 背景：CI 矩阵（Python 3.11/3.12/3.13 × amd64/arm64 × Linux/Windows/macOS）+
  v0.1.0 六平台 Release（Build workflow）。annotation 通道（`::error::` 摘录 →
  公开 check-runs API）用于无 gh CLI 时排障。
- 本轮修复：①`build_exe.py --add-data` 分隔符改 `os.pathsep`（`;` 在 Linux/macOS
  非法）；②产物名非 Windows 无 `.exe` 后缀；③中文 `print` 在 runner 的 cp1252 控制台
  抛 UnicodeEncodeError（main 入口对 stdout/stderr `reconfigure(utf-8)`）；④CI 上
  click/typer/rich 的 ANSI 彩色输出插进中文报错文本破坏子串断言（conftest 会话级
  NO_COLOR+TERM=dumb，`_norm` 剥 ANSI 码）；⑤`ctypes.windll` 模拟用例在非 Windows
  `monkeypatch.setattr` 直接 AttributeError（skipif win32）；⑥macos-13 runner 已退役
  改用 macos-15-intel。
- 遗留缺口（posix 显式 skip，待专项修复后逐项放开）：
  1) 归因：Linux/macOS 无特权会话 psutil 无法把其他进程连接映射到 PID（/proc 扫描
     受权限限制），归因恒为 unknown——02 文档 D2 本就只对 Windows 承诺归因质量；
  2) 端口释放：stop 后监听 socket 收尾慢于 10s 有界等待（平台收尾语义差异）；
  3) confdir CA 生成时机：非 Windows 疑似首次 TLS 才懒生成（smoke 断言失败）；
  4) windows-arm64：部分依赖无 win-arm64 wheel，pip Install 即失败（保持 experimental）。
- 结果：Windows amd64（py3.11/3.12）严格门禁绿；Lint 绿；Linux/macOS/wind-arm64
  任务为实验层，缺口以显式 skip 呈现而非红错；Release v0.1.0 五平台可执行文件发布。

## D-2026-10-24-31 · v0.1.1 常驻与自愈（关机不断网三件套）

- 背景（用户问题）：setup 持久写 WinINET 代理指向 127.0.0.1:8080；突发关机后
  若自启失败/进程未跑，遵循系统代理的应用「断网」——与 VPN 残留同类。
- 实现：
  1) **优雅退出**（capture/engine.py）：SetConsoleCtrlHandler 接管
     CTRL_CLOSE(2)/CTRL_LOGOFF(5)/CTRL_SHUTDOWN(6)，stop 在后台线程限时 4s
     （< 系统 5s 上限）执行，超时 os._exit(0) 绝不阻塞关机；Ctrl+C(0) 不接管，
     仍走 KeyboardInterrupt 原路径；回调引用模块级保活防 GC；POSIX 对应 SIGTERM。
  2) **开机自启**（setup/autostart.py）：两个当前用户级登录计划任务（XML 定义，
     journal-first，schtasks 全经可注入 `_run_schtasks`）——AutoStart（venv 用
     pythonw 无窗口 / frozen 用 cmd start /min）跑 `aaa run --log-file`；
     Watchdog 延迟 30s 跑 `aaa watchdog --fix`。`aaa setup` 末步默认询问安装
     （全拒场景不追问）；`aaa autostart on/off/status` 独立管理；teardown 新增
     `autostart` 目标整体还原。
  3) **自检自愈**（setup/watchdog.py）：三态判定 idle/ok/degraded（从 journal 的
     WinINET 记录解析端点；含登录竞态有界等待）；degraded 时 `--fix` 还原网络类
     改动（WinINET/WinHTTP + 代理环境变量，CA 无害保留），等价 `teardown proxy env`；
     日志 data/watchdog.log；`aaa status` 内置预警与自启任务状态。
- 测试：test_autostart（假 schtasks：创建/journal/幂等删/teardown 还原/缺失容忍）、
  test_watchdog（三态矩阵 + fix 调用 kinds 断言 + 登录竞态不误还原）、
  test_shutdown_handlers（事件映射 + 引用保活）；run 命令对 stop 做防御式获取
  （getattr）兼容注入的假引擎。
- 版本：0.1.0 → 0.1.1（含官网文案同步）。

## D-2026-10-24-32 通知 digest 的发送时机：窗口通过时前置 + flush 兜底（无定时器）

- 问题：04 文档只说「超出部分合并为一条 digest：另有 N 条事件被限流」，未定 digest
  何时发出。若在**第一条被限流事件到达时立即发**，计数只有 1（N 失真）；若等窗口
  滚动，需要定时器且用户可能永远看不到 digest。
- 选择：被限流事件只计数不发送；digest 在两处补发——① 同通道下一次**通过限流窗口**
  的发送前（先 digest 后正文）；② `flush()`（优雅退出路径）兜底排空。为使
  「queue 空 + 持锁」⇒「无在途事件」，worker 取队列与处理共用 `_send_lock`，
  **空转等待放在锁外**（`get_nowait` + sleep）——实测持锁阻塞 `get(timeout)` 会让
  flush 的有界锁获取被热循环重新抢锁饿死（CPython Lock 非公平），digest 因此丢失
  （80 次压测 5 次复现后修正）。同名通道热更新重建时保留窗口与未上报计数（限流
  连续性），但**通道对象一律换新**（url/provider 可能已变，复用旧对象会拿陈旧配置）。
- 理由：N 如实反映被限流条数（T5 验收「20 连发 → ≤10 条 + 1 digest」的 digest
  恰为「另有 10 条」）；无定时器、无延迟线程；flush 有界绝不阻塞退出。

## D-2026-10-24-33 AAA_WEBHOOK_URL 环境变量单独设置即视为试用意图（启用 webhook）

- 问题：04 文档 §2「环境变量覆盖：AAA_WEBHOOK_URL、AAA_SMTP_PASSWORD（便于快速
  试用与凭据分离）」未定：策略 `webhook.enabled: false` 且 `url` 为空时，仅设环境
  变量是否生效？
- 选择：环境变量覆盖 **url 值**是绝对的（「环境变量优先」字面）；启用开关——策略
  已自配 url（含禁用）时以策略为准；策略 url 为空且未启用时，设置环境变量视为
  显式试用意图，自动启用 webhook。SMTP 密码只覆盖值，不改变 `email.enabled`。
- 理由：`AAA_WEBHOOK_URL=… aaa notify test --channel webhook` 不改文件即可试用
  （04 文档 T6 的字面场景）；`AAA_*` 前缀是本工具专属命名，误启用风险可忽略。

## D-2026-10-24-34 通知摘要字段的最小扩展：附加「方法 路径」行与打码 evidence

- 问题：04 文档 §3 T2 列出摘要字段「时间/动作/风险分/进程/主机/命中规则」，但：
  ① 「命中的密钥打码」在该字段集内没有实际载体（规则 id 不含密钥）；② 用户无法从
  通知分辨是哪个请求出的事。
- 选择：在必备字段外附加两处——主机行带「METHOD 路径」（路径查询串可能含密钥，
  正是 `iter_secret_spans` 同源打码核心的实际作用点）；命中规则行带扫描器输出的
  **已打码** evidence（`secret-leak(content)「AKIA****YZ」`）。整个摘要文本仍统一
  过一遍 `mask_secret_spans`（防线叠加）；generic webhook 外发前对事件 JSON 的
  自由文本字段（path/exe/cmdline/error）单独打码（对序列化后的整段 JSON 打码可能
  吞掉引号破坏 JSON 结构，故只处理字段值）。
- 理由：必备字段全部保留（超集不冲突）；「脱敏红线」有了可验证的落点（E2E 断言
  明文密钥不出现、打码指纹出现）；toast 前 3 行按 glance 价值排序。


