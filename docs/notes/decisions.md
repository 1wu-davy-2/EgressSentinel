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

## D-2026-10-24-35 证据静态加密（W5）的三个规格空档：盐文件落位 / 密钥解析优先级 / 包装元数据语义

- 问题：05 文档 W5 规定了 `derive_key(password, salt)`（PBKDF2 200k）与 keyfile/
  口令两种密钥来源，但有三处未定：① 口令派生模式的 **salt 从哪来**（规格未提）；
  ② "keyfile 优先"在 **keyfile 不存在而口令已设** 时如何取舍；③ `EncryptedFileStore`
  包装的 `sha256`/`size` 元数据描述明文还是密文。
- 选择：① 盐持久化为 `data/.crypto-salt`（16B 随机，权限收紧同 keyfile）——固定盐
  可被彩虹表预计算、逐文件盐则每次读取都要 200k 迭代 KDF，均不可取；**盐丢失 = 既有
  密文不可解**，引擎如实报 `CryptoError`，绝不静默重建。② 优先级定为：已有 keyfile >
  口令（显式参数 > `AAA_MASTER_PASSWORD` 环境变量）> 生成 keyfile（仅 `enabled=True`
  的写入路径）——已有 keyfile 必须优先（否则换机器设口令会丢旧密文访问权）；keyfile
  缺失而用户显式给了口令时按口令派生（静默生成 keyfile 会无视用户意图）；两者皆无才
  生成 keyfile。③ `sha256` = 实际落盘**密文**文件摘要（保留 evidence.py "与文件内容
  一致可复核"不变量，无密钥也能验完整性）；`size/original_size/truncated` 如实描述
  **明文**（对齐请求语义；截断发生在明文层，密文始终完整可解）。
- 理由：三处均为"规格未定"而非规格冲突；选型以"不静默破坏既有数据的可访问性、
  不伪造安全状态"为准绳。另：加密开启但密钥不可用时 fail-fast 报错而非静默写明文
  （宁可失败，不给"已加密"假象）；`decrypt_bytes` 为严格模式（无魔数报错），明文
  兼容判断只放在文件层（`decrypt_file`/`CryptoEngine.decrypt`/`EncryptedFileStore.
  read_body`），与"读取时无魔数则按明文返回"的 W5 字面一致。

## D-2026-10-24-36 LLM 辅助判定（W3）的规格空档：status 语义 / 预算默认值与口径 / 判定请求直连

- 问题：05 文档波次一 W3 中：① `JudgeVerdict` 字段只列了 is_violation/confidence/
  reason/category，但同一行又要求返回 `verdict(status="unavailable")`——status 字段
  存在但其取值集与非 ok 时的字段语义未定义；② `max_events_per_day` 预算未给默认值，
  也未说明超时/解析失败是否消耗预算；③ 未说明判定请求是否走系统代理。
- 选择：① `JudgeVerdict` 增加 `status: Literal["ok", "unavailable", "budget_exceeded"]`；
  非 ok 结论的 is_violation 恒为 False、confidence 恒为 0.0，集成方必须以
  `status == "ok"`（`is_ok` 属性）为采信判定字段的前提。② 预算默认 200 次/日（规格
  未定值）；口径为**只累计成功取得 ok 结论的调用**——超时/解析失败不计数，端点故障
  不会烧穿预算；按本地日期滚动、`data/judge-usage.json` 原子落盘（tmp+replace），
  文件损坏按 0 重新开始（预算是成本护栏不是安全护栏），落盘失败则按 W3 红线收敛为
  unavailable。③ 判定请求 `trust_env=False` 直连（与 notify/webhook 同一约定）：本
  工具自身就是系统代理，LLM 判定若走环境代理会回环进自己的采集。
- 理由：三处均为"规格未定"；status 三值让运营可分辨"API 不可用"与"预算用尽"；
  失败调用零产出不计费符合 max_events_per_day 的字面语义（按事件计，不按尝试计）。
  全部为 W3 模块内决策，不触碰共享文件；集成阶段组装 `policy.judge` 段时以本条为准。

## D-2026-10-24-37 W4 注入检测的误报治理取舍（05 文档波次一）

- 问题：W4 要求覆盖 developer mode / 越狱 / `<system>` / `## system` / ignore previous
  等特征，同时「正常技术文本零误报」是验收线——这些裸特征词在正常技术文本里高度歧义
  （Android「启用开发者模式」、iOS「越狱」文章、`## System Requirements` 标题、
  ASP.NET `<system.web>`、ATC 术语「Disregard previous transmission」、
  「decode the JWT」文档、emoji ZWJ 序列）。
- 选择（`src/aaa/scanners/injection.py`）：
  1) 歧义词一律带上下文才命中：developer mode 需 you are/I am in/reactivate 形态；
     「越狱」需 AI 词同现（chatgpt/gpt/大模型/提示词等）；`## system` 仅整行标题
     （冒号可选）；`<system>` 仅裸角色标签（`<system.web>` 实测不命中）；base64 需
     「解码并执行」指示语与 ≥32 字符 blob 同现，二者缺一不报；
  2) 零宽字符（U+200B-U+200D）全文可疑数 ≥2 才报（emoji ZWJ 序列白名单；1 个视为
     复制残留），2-5 low / 6-19 medium / ≥20 high；U+2060/U+FEFF 不计（BOM 误报面）；
  3) 已知残余误报面（探针实测确认、均为 low/medium 标注级）：讲解聊天模板的文档命中
     role-tag-template；「You are Dan（人名）」命中 persona-dan-en；用 ZWNJ 的
     波斯/乌尔都正文 ≥2 个即报 hidden-zero-width；引用攻击样例的安全文章命中
     override 类（样例即攻击文本本身，接受）。
- 其他：`InjectionHit` 用 frozen dataclass（与 `scanners/base.py` 一致，未引入
  pydantic）；除计划要求的 `scan_injection` 外提供 `scan_injection_result(body,
  max_bytes=)`（ScanResult 包装，与 engine/pipeline.py:40 的 ScannerFn 签名兼容，
  供波次二直接注册）；按「只新建」约定未改 `scanners/__init__.py`，集成阶段统一注册。

## D-2026-10-24-38 W2 防火墙加固：WFP「Block 优先于 Allow」与规则集设计的冲突（05 文档波次一）

- 问题：05 文档 W2 规则集为「①Allow 代理 exe TCP443；②Block any TCP443；③Block any
  UDP443；白名单 svchost/Windows Update」。但 Windows 筛选平台的文档语义是 **Block
  规则优先于 Allow 规则**（仅 IPsec authenticated bypass 例外，netsh 无优先级参数）——
  按 ②③ 的 any-Block 落地后，① 与 svchost 白名单同样被 Block 命中：代理自身与
  Windows Update 的 443 出站都会被断，`harden on` 实际效果是「全断 443」而非「收敛
  到代理」。多来源交叉确认（Microsoft 文档语义 + 运维实践：any-Block 会吞掉匹配的
  Allow 规则）。
- 选择（`src/aaa/setup/firewall.py`）：
  1) **按计划字面实现规则集**（本波次单测全 mock，不触真机，功能语义不在单测断言
     范围内），Allow 规则照常创建；
  2) **如实登记边界**：模块 docstring 与本条注明白名单对 any-Block 不生效；真机
     连通性验证列入 needs-manual；集成阶段（`aaa harden on` 接线）上真机前必须先
     做一次带 teardown 的实机演练，若确认全断，备选方案：a) Block 规则收窄到具体
     程序/网段范围（netsh 无排除语法，需枚举）；b) 改用 WFP 自定义子层权重
     （超出 netsh 能力）；c) IPsec authenticated bypass（需机器证书策略）。三个
     备选都超出本波次范围，留给集成阶段决策。
  3) 创建顺序 Allow 在前、Block 在后：创建中途崩溃时系统停留在「未加固」而非
     「全断 443」状态（最终态不受创建顺序影响）。
- 其他实现决策：apply 创建前先按名删除同名旧规则（`harden on` 可重复执行不产生
  重名规则；delete 容忍不存在）；restore 幂等不依赖 delete 返回码语义——delete 非 0
  时用 `show rule name=` 复核（本机只读探针实测：无匹配规则 show 返回码 1、非提权
  shell 的 delete 返回「请求的操作需要提升」且在匹配前就检查提权），规则已不在即视为
  成功；apply/restore 均设管理员门禁（复用 `setup.admin.is_current_process_elevated`），
  restore 拒绝删除非 `EgressSentinel-` 前缀规则（防 journal 被篡改后误删他名规则）；
  按「只新建」约定未改 `setup/__init__.py`，导出面在 `aaa.setup.firewall` 命名空间
  （plan_harden/apply_harden/restore_harden/KIND_FIREWALL_RULE 等），集成阶段直接
  `from aaa.setup.firewall import ...` 并向 teardown 注册 `KIND_FIREWALL_RULE` 还原器。

## D-2026-10-24-39 波次二集成的九处规格落位（05 文档波次二）

- 问题：05 文档波次二 9 条集成任务存在若干「方向明确但形态未定」的空档，集成时
  逐一落位如下（全部为"规格未定"而非规格冲突，不改变计划要求的行为）。
- 选择：
  1) **`response.rules[].patterns` 语义** = 命中严重度档位：`all`（任何注入特征命中
     即标注）| `high`（仅最高严重度为 high——指令覆盖/隐藏载体——才标注）。依据是
     W4 模块的 severity 分级（low/medium/high）与计划"rules: [{id, patterns: all|high,
     action: alert}]"的字面；`action` 在 schema 层固化为 Literal["alert"]——响应侧
     写 block/confirm 直接策略校验失败（05 文档"仅 alert 级标注，不阻断响应"红线）。
     响应侧命中规则 weight 恒 0：不抬高 risk_score，verdict 只在低于 alert 时抬到
     alert（绝不降级既有 block/confirm，也绝不升级为阻断）。
  2) **`repo_fingerprint` 扫描器形态**：`make_fingerprint_scanner(index)` 把指纹索引
     包装成 ScannerFn（签名与其余扫描器一致，`max_bytes` 先截断再比对）；命中条目
     evidence 用 W1 的 snippet（80 字符、空白压缩——W1 红线：事件外发不携带更长
     原文），结构化命中清单（repo/file/line/snippet）附进事件 matched_rules 的
     `extra.fingerprint_hits`（05 文档"命中→事件 evidence 附指纹命中清单"）。
     注册时机：`aaa run` 启动时策略 `fingerprint.enabled` 且 `data/fingerprints.bin`
     可加载 → 传入管线构造参数；**库缺失/损坏不自动重建**（重建需遍历用户仓库，
     大仓分钟级，静默做会拖慢启动且可能读到过期内容）——如实告警并提示
     `aaa fingerprint build`，构建后重启生效。
  3) **`aaa fingerprint build`**：纯本地、零外发，不要求 `fingerprint.enabled`（建库
     是显式维护动作）；缺省 `--repo` 时读策略 `fingerprint.repos`；同名仓库重复并入
     按 W1 语义拒绝 → CLI 提示跳过（幂等 no-op，退出 0）；`--rebuild` 丢弃旧库从零
     重建；全部仓库失败时退出 1 且不落盘。
  4) **judge 接线**：`policy.judge` 段直接复用 W3 `JudgeConfig`（同字段同默认，无
     第二份配置模型）；`aaa run` 启动时 `judge.enabled` 才构造 `LLMJudge`（预算文件
     随 `--data-dir` 落位）；判定摘要复用通知同一脱敏核心（`notify.summary.build_summary`
     → `mask_secret_spans`）——judge 红线 3 要求调用方先脱敏，这里是唯一落点；结论
     （含非 ok 状态）如实记事件 `judge_note`（AuditEvent 新增字段，DB raw JSON 自动
     携带），消费方以 `judge_note["status"] == "ok"` 为采信前提（D-36 语义）。
  5) **evidence 接入形态**：按计划"store/evidence.py 接入 CryptoEngine"字面，
     `EvidenceStore` 构造新增可选 `crypto` 参数（`CryptoLike` Protocol 解耦，
     避免与 store.crypto 的循环导入）；写入 = 明文截断后经引擎加密，`sha256` =
     实际落盘密文摘要（D-35 口径），`size/truncated` 描述明文；新增 `read_body()`
     透明读取（无魔数原样返回）。`aaa run` **无条件**注入引擎：关闭时写明文，
     读取仍透明兼容开启期间落盘的密文（"读取兼容与 enabled 无关"，D-35）。W5 的
     `EncryptedFileStore` 包装保留（独立可用，测试覆盖），生产装配走构造参数注入。
  6) **audit.db（事件库）暂不整库加密——边界如实声明**：W5 的加密范围是**证据文件**
     （请求 body 的 `data/evidence/*.bin`）；SQLite 库 `audit.db` 的元数据行（host/
     path/matched_rules/摘要等）仍为明文，理由：a) 05 文档 W5 只写"证据静态加密"，
     未要求库加密，波次二第 4 条也只点名 evidence.py；b) 整库加密需引入 SQLCipher
     类依赖或全库字节级加解密层（读取路径全变，与 WAL 并发/增量 trim/面板查询的
     兼容改造量大且风险高），不宜在本波次顺带做；c) 现有降险：库文件落用户数据目录、
     事件字段值在扫描/展示层已打码、保留期自动清理。**需要整库保密的用户，当前版本
     请依赖磁盘级加密（BitLocker）**；后续如做，需先定密钥轮换与面板只读进程的
     密钥分发方案（记录为待办而非既成事实）。
  7) **加密开关启动生效**：`encrypt.enabled` 与指纹库一样在 `aaa run` 启动时读取，
     策略热更新不切换加密状态（运行中切换会产出"同一目录新旧混杂且无开关语义"的
     中间态；读取侧本就双向兼容，切换只需重启）。README/`--help` 均注明。
  8) **`aaa harden on|off`**：替换 P6 占位（decisions D-22 的占位语义作废，
     `test_cli_p4` 同步改写）。on：管理员门禁（非提权 exit 2，与 run --mode local
     同样的 UAC 指引）→ plan_harden 清单先打印 → 确认/journal-first 逐条创建；
     `--proxy-exe` 缺省取当前解释器/可执行文件自身（源码运行 `aaa run` 的代理进程
     就是 python.exe；frozen 即 exe 本身）；控制台固定输出 WFP「Block 优先于 Allow」
     已知边界（D-38）与 `harden off` 还原指引。off：按 setup-state.json 的
     firewall_rule 记录逆序精确删除（复用 `restore_harden`，幂等；记录缺失=零操作
     成功）。`aaa teardown` 新增 `firewall` 目标（RESTORERS 注册同一还原器）。
  9) **run 启动概要**：新增三行——指纹（关/开+仓库数与片数/库缺失告警）、judge
     （关/开+model+当日预算用量）、证据加密（关/开+算法与 keyfile 路径）；`aaa status`
     的防火墙行从"P6 占位"改为真实状态（journal 中的规则计数），另加"安全深化"行。
- 理由：逐条以"不伪造安全状态、不静默扩大外发面、规格未定处选最保守且可逆的形态"
  为准绳；全部落位均有对应单测/契约断言（tests/unit/test_security_deepening.py、
  tests/e2e/test_security_deepening_e2e.py）。

## D-2026-10-25-40 W1 服务化（06 文档波次一）的规格空档落位：XML 形态 / SYSTEM 账户 / 提权门禁 / teardown 接线

- 规格原文："`install_service(state, data_dir)`：schtasks 创建 `EgressSentinel-Service`——
  `ONSTART` 触发、`RL HIGHEST` 可选参数、隐藏运行 `aaa run --log-file data/service.log`
  （复用 autostart_command 的解释器策略）；与既有 AutoStart/Watchdog 任务互斥提示；
  journal-first（kind=`service_task`）+ `restore_service`（幂等删任务）；`service_status()`"。
  未定处按最保守且与既有模块同构的形态落位（`src/aaa/setup/service.py`）：
  1) **XML 而非 schtasks 参数行**：用 `/Create /TN ... /XML ...` + `BootTrigger`
     （语义等价 `/SC ONSTART`），避开 `/TR` 261 字符上限与引号转义坑，与
     autostart.py 的任务创建同构；`RL HIGHEST` 落为 `<RunLevel>`，由
     `install_service(..., highest=True)` 可选参数控制（False→LeastPrivilege）。
  2) **SYSTEM 账户**：ONSTART 任务以 SYSTEM 运行（XML `<UserId>S-1-5-18</UserId>`），
     与 `schtasks /SC ONSTART` 的默认账户语义一致；无人登录的开机场景才能拉起代理。
  3) **提权门禁留给集成层**：创建 ONSTART+SYSTEM 任务需管理员；cli.py 全局禁改，
     库层不做门禁，仅创建失败时抛 `ServiceError`（journal 记录保留可重试，错误信息
     注明需管理员）。建议集成时仿 `aaa harden on`：`aaa service install` 非提权 exit 2
     （admin.is_current_process_elevated + UAC 指引）。
  4) **teardown 接线走扩展点**：teardown.py 为共享文件（不在 W1 独占清单），不改；
     `service.py` 经 `register_restorer(KIND_SERVICE_TASK, restore_service)` 自注册
     （teardown.py:71 提供的扩展点，CA 同款机制），import 本模块即生效。
     注意 `teardown_target_kinds` 的映射（teardown.py:91）尚无 `service` 目标——
     建议集成时 `aaa service uninstall` 直接调 `uninstall_service`，或在集成阶段
     给映射补 `"service": {KIND_SERVICE_TASK}`（W6 的 daily_task 同样面临此空档）。
  5) **解释器策略复制而非参数化**：`service_command` 复制 autostart_command 的
     策略（frozen→cmd start /min；venv→pythonw 缺失时退回当前解释器），仅日志名
     不同（service.log）；autostart.py 非本模块独占文件，不做侵入式改动。
  6) **互斥提示为建议不阻断**：双通道判定——journal 有 `autostart_task`/
     `watchdog_task` 记录（setup 装过）**或** schtasks /Query 任务存在（手动装过）
     都在返回值 `ServiceInstallResult.warnings` 中给出"建议 aaa teardown autostart"
     的提示；`service_status().conflict` 与 warnings 同一口径（布尔化），避免双标。
  7) **journal 元数据扩展**：`new` 记录在 autostart 四字段（task_name/xml/command/
     arguments）基础上加 `log_file` 与 `run_level`，供 `service_status` 只读展示。
- 对应单测：tests/unit/test_service.py（11 例：创建与 journal-first / ONSTART XML /
  解释器策略 / 互斥提示双通道 / 失败记录保留 / 卸载与还原幂等 / RESTORERS 注册 /
  状态查询），全部 mock `_run_schtasks`，绝不真实施改。

## D-2026-10-25-41 W2 托盘（06 文档波次一）的规格空档落位：SVG 图标渲染 / 状态只读口径 / 停止代理保守语义

- 规格原文："`run_tray(data_dir)`：lazy import pystray/Pillow（未装给出 pip 提示并退出码 2）；
  菜单：状态（调 watchdog/自检结果只读展示）/ 打开面板（起 `aaa web` 子进程）/
  启动代理（spawn_run_now）/ 停止代理（按端口探测 pid？保守：提示用 `aaa teardown`/
  结束进程树——v1 菜单项「重启代理」=spawn + 提示）/ 退出；图标：优先
  `website/icon.svg`→Pillow 渲染，缺省纯色盾形绘制；pystray Icon 全部注入式
  （`_icon_factory`）"。未定处按最保守且可测的形态落位（`src/aaa/tray.py`）：
  1) **SVG 图标渲染空档**：Pillow 本身不支持 SVG 栅格化（无内置渲染器，环境亦无
     cairosvg），"icon.svg→Pillow 渲染"字面不可达。落位为四级降级链，任何一级失败
     都降级到下一级（debug 日志，托盘总能拿到图）：icon.svg 经**可选**渲染后端
     （cairosvg，函数内 lazy import，非声明依赖——pyproject 全局禁改，不能加依赖）
     → `website/icon-192.png`（与 svg 同源位图，项目已有）→ 纯色盾形 Pillow 原语
     绘制（圆角底 #2BD6C3 取 svg 渐变中点色 + 白盾描边 + 外发箭头，几何近似 svg）。
     website/ 全局禁改：托盘只**读**其 icon.svg/icon-*.png，不写不改。
  2) **「状态」只读展示口径**：未直接调 `run_watchdog`——它每次运行追加写
     `data/watchdog.log`，而托盘状态行每次打开菜单都会求值文本，会产生日志噪音，
     与"只读展示"矛盾。落位：复用 watchdog 的判定原语（`proxy_endpoint` +
     `port_open`，三态语义一致 idle/ok/degraded），不写任何日志（单测断言
     watchdog.log 不产生）；状态文案为 callable，pystray 打开菜单时实时求值，
     无轮询线程。
  3) **停止/重启代理**：按 spec 保守口径，v1 不做真"停止"菜单项；落位「重启代理」
     = 复用 `autostart.spawn_run_now` + 气泡提示"旧进程未自动停止：请运行
     `aaa teardown` 或结束旧进程树"（托盘自身绝不杀进程/改代理设置，只读编排层）。
     「打开面板」先探测端口（复用 `watchdog.port_open`），8787 已在听则只提示
     URL 不重复拉起 `aaa web`；面板子进程与 spawn_run_now 同策略（frozen→exe，
     源码→pythonw 无窗口）+ DETACHED_PROCESS。
  4) **注入面比 spec 点名的更宽**：spec 只点名 `_icon_factory`，但单测要在
     **未装 pystray 的环境**验证"菜单构建/回调装配"，Menu/MenuItem 必须一并注入
     （`menu_cls`/`item_cls`，缺省在依赖加载成功后才从 pystray 取）；另有
     `_deps_loader`（依赖加载）、`_popen`/`_spawn_run_now`（子进程）、`_port_open`
     （端口探测）。真实 pystray 路径（默认从 pystray 取三原语）由
     `test_run_tray_full_assembly_with_fakes` 的假模块命名空间覆盖装配顺序。
  5) **退出码契约**：`run_tray` 返回 `int`——缺依赖 = `MISSING_DEPS_EXIT_CODE=2`
     （stderr 打印含 `pip install -e .[tray]` 的提示，typer 命令可直接把返回值当
     退出码）；正常退出（「退出」→`icon.stop()`）= 0。extras `tray=[pystray,Pillow]`
     由集成阶段加进 pyproject（波次二第 4 条，pyproject 本模块禁改）。
- 对应单测：tests/unit/test_tray.py（23 例：子进程验证模块导入零 GUI 依赖 / 缺依赖
  退出码 2 与 pip 提示（含 venv 真实缺 pystray 的真实路径）/ 图标四级降级 / 状态
  三态与零副作用 / 菜单 5 项与回调装配 / 面板端口去重 / 重启提示 / 全装配），全部
  假注入，绝不真起托盘、绝不真起子进程。

## D-2026-10-25-42 W7 规则市场（06 文档波次一）的规格空档落位：合并语义 / 落盘形态 / gitleaks 映射与跳过

- 问题：06 文档 W7 只给了函数名与模式名（`merge=replace|union`、`sync_gitleaks(source=url|path)`、
  「转换为内置 secrets 规则 YAML（正则+熵+allowlist 映射），附来源与 sha256 pin」），
  以下空档需落位（全部为「规格未定」，不改变计划要求的行为）。
- 选择：
  1) **export/import 的落盘形态**：`export_section(policy_doc, section) -> str` 输出
     **段内容本身**的 YAML（不带段名包裹），可直接回灌 `import_section` 的 `yaml_str`
     （往返格式）；`import_section` 签名保持计划原文（`current_yaml` 为策略 YAML
     **文本**），返回合并后的完整策略 YAML 文本，新增可选 `output_path`——三关校验
     （导入段 → 合并结果 → 完整策略）全过才原子写（tmp+replace），不合法绝不写且
     既有文件一字不动、不留 .tmp 残片。落盘为整文重写，原文件 YAML 注释会丢
     （注释不进 pydantic 模型；集成层 CLI 应向用户提示）。
  2) **union 合并的逐值语义**：映射递归按键合并（键冲突导入者胜，本方独有键保留
     ——部分字段导入只覆盖给出的字段，适配 notifications/defaults 嵌套段）；带字符串
     id 的规则列表按 id 合并（同 id 导入者胜=整条覆盖，新 id 按导入顺序追加，本方
     顺序不变）；无 id 列表（域名清单/收件人）去重并集（本方在前）；标量导入者胜。
     replace 即整段替换（省略字段回落 schema 出厂默认，与「段落存在但省略字段按
     字段默认」的既有口径一致）。
  3) **gitleaks 转换映射**：`regex→pattern`、`entropy→entropy`（对整段匹配生效）、
     `keywords→keywords`（统一转小写——本项目扫描器按行小写包含匹配）、
     `[allowlist]`/`[[rules.allowlists]]` 的 `regexes`→包级/规则级 allowlist；
     `paths/commits` 等文件维度条目对本引擎无意义，忽略。
  4) **不支持特性如实跳过（记包 meta.skipped：id+原因，绝不静默丢）**：带
     `secretGroup` 的规则（本引擎按整段匹配，熵守卫对含前缀整段会失真，宁跳过
     不带病转换）、Python 编译不过的 Go 正则、缺 id/regex、重复 id（保留首条）；
     坏 allowlist 正则只丢该条 allowlist（保守方向：至多多报、不漏报）。转换结果
     为空拒绝生成规则包（不落空包）。
  5) **规则包格式与扫描接线**：包为 pydantic 严格模型 `SecretsRulePack`
     （meta[source/sha256/synced_at/rule_count/skipped] + allowlist + rules），
     pattern/allowlist 构建即编译校验；sha256 pin=来源 TOML 原始字节的 sha256，
     同时落包 meta 与同步回执 `GitleaksSyncResult`。`scan_with_pack` 复用
     `scanners/secrets.iter_secret_spans` 匹配核心再叠加包 allowlist 过滤——
     **不改 scanners/secrets.py**（该目录无独占归属，为避免与并行模块冲突本波次
     不动它）；`to_secret_rules` 供集成侧按需装配为 `SecretRule` 元组。
  6) **网络注入面**：URL 下载走 `FetchClient` 协议 + `client_factory` 注入（默认
     httpx `trust_env=False` 直连防自代理回环，与 judge/webhook 同约定）；本地路径
     同步不触碰网络（连客户端工厂都不调用）。
- 对应单测：tests/unit/test_ruleshub.py（40 例：导出往返 / 段导出形态 / replace /
  union 按 id 合并与嵌套键保留 / 9 种非法导入不落盘不留 tmp / gitleaks 两条 TOML
  样本的映射与跳过 / pin 记录 / 假客户端 URL 同步 / HTTP 与网络异常不落盘 /
  包扫描 allowlist 端到端），零真实网络、落盘仅 tmp_path。

## D-2026-10-25-43 W3 安装器（06 文档波次一）的规格空档落位：iss_version 归属 / 卸载顺序 / 产物对账

- 背景：06 文档 W3 所有权表只列了「installer/ 新目录 + build.yml 唯一可改 +
  tests/unit/test_installer.py」，但正文提到 `scripts/iss_version.py`。落位如下：
  1) **`scripts/iss_version.py` 由 W3 创建**（06 文档 39 行明确「版本号从
     scripts/iss_version.py 注入（读 pyproject）」，且其他并行模块均未认领
     scripts/）。行为：tomllib 读 pyproject `[project] version` 后 stdout 输出；
     缺失/损坏时**非零退出**，绝不输出兜底版本号（错版安装包比失败构建更危险）。
  2) **卸载「先 teardown 再删文件」的机制**：Inno `[UninstallRun]` 官方语义保证
     在删除已安装文件**之前**执行、且默认逐条等待退出（jrsoftware.org/ishelp
     topic_runsection.htm；`waituntilterminated` 显式声明自证）。teardown 条目调
     用 `{app}` 下的 `ai-agent-audit.exe teardown`（幂等：状态文件为空即 no-op
     exit 0；个别还原失败 exit 1 不阻塞卸载，记录保留可重跑）。teardown 之前先
     taskkill 结束常驻进程：`aaa teardown` 本身不杀进程（cli.py 的 teardown 只还
     原注册表/任务/证书等），不先结束进程则 exe 被占用、删文件阶段必失败；
     taskkill 找不到进程返回非零，Inno 不校验退出码，无副作用。
  3) **卸载不删 data/**：`{app}` 下 data/（audit.db、evidence、日志）属用户数据，
     卸载刻意保留；teardown 只还原系统级改动，不删数据文件。
  4) **安装器绝不自动 setup**：[Run] 仅提供「查看 README」复选；CA/代理/环境变量
     等系统改动保持用户显式执行 `aaa setup`（与 03 文档「执行前打印 + 确认」红线
     一致）。
  5) **installer job 复用 build 产物**：needs: build + download-artifact
     `egress-sentinel-windows-amd64`（= build job 上传模板 `egress-sentinel-<os>-<arch>`
     在 windows/amd64 腿的解析结果，test_installer.py 做解析对账），还原到 ISS
     期望的 `dist/ai-agent-audit.exe` 后编译；不重复跑 PyInstaller 构建。
  6) **.iss 编码**：UTF-8 with BOM（中文内容在 <6.3 的 Inno 需要 BOM 才不会被当
     ANSI；≥6.3 BOM 可选，带 BOM 对所有 Unicode Inno 6 版本无歧义）；
     `ArchitecturesAllowed=x64compatible` 需 Inno ≥6.3（choco innosetup 装最新
     稳定版，满足）。.iss 段内条目不支持续行符，全部单行（test_installer.py 有
     回归断言）。
  7) **版本占位守卫**：.iss 顶部 `#ifndef MyAppVersion` 即 `#error`，杜绝未经注入
     直接编译产出错版安装包；OutputBaseFilename 为
     `egress-sentinel-setup-v{#MyAppVersion}`，与 build.yml installer job 的
     artifact/upload/release 模式 `dist/egress-sentinel-setup-*.exe` 对账（tag
     `v*` → 文件名 `egress-sentinel-setup-v<版本>.exe`）。
- 对应单测：tests/unit/test_installer.py（23 例：BOM/无续行/五段齐全/版本占位与
  #error/产物名 glob 对账/AppId 固定/安装内容与 build_exe.APP_NAME 一致/快捷方式/
  [UninstallRun] teardown 先行且仅此一处/iss_version 读取-异常-退出码/build.yml
  job 结构与 artifact 名解析对账），全静态校验，不执行 iscc、不联网。






## D-2026-10-25-44 W5 CLI i18n 的四处规格空档落位（06 文档波次一）

- 日期：2026-10-25；模块：W5（src/aaa/i18n.py + src/aaa/locales/{zh,en}.py）
- 问题与落位：
  1) **未知语言值的行为**：``AAA_LANG`` 或运行时 ``set_lang``（将来接 ``--lang``）
     收到 zh/en 之外的值时如何处理，规格未定。落位：**静默回落 zh 并继续**（不报
     错不退出）。理由：i18n 只影响文案语言，报错会把"拼错一个环境变量"升级成功能
     故障；默认 zh 与"出厂输出不变"一致。
  2) **缺 key 与插值失败的兜底**：``t()`` 在当前语言缺 key 时回落 zh 原文并计数告
     警（规格明示）；zh 也缺时返回 key 本身、``str.format`` 占位符与实参不匹配时
     返回未插值原文——均计数（``missing_counts()``，插值失败记 ``<key>#format``）
     且**绝不抛异常**（一次缺失只计一次，同一 key 的 warning 去重只发一次）。
     理由：集成阶段机械包裹 cli.py 后，词条问题绝不允许中断 CLI 主流程。
  3) **词条收录范围**：规格点名 console.print/err_console.print/BadParameter/help/
     docstring 首行四类。落位：另外收录 **typer.confirm 提问语**（wizard.confirm_step、
     cli.autostart_on.confirm、cli.harden.confirm 等属于用户可见交互文案）与
     **status/policy_lint 表格的字段标签行**（如 "version"/"fingerprint"，en 译文
     = 原文自身），保证集成阶段"机械包裹"无遗漏；**logging（``logger.warning``）与
     写文件日志（``_append_log`` 内容、watchdog.log）不计入**——非 CLI 渲染通道，
     且规格列举未含。``cli.status`` 安全深化四对开关原文为 f-string 内嵌条件
     （``f"指纹={'开' if doc.fingerprint.enabled else '关'}"``），目录抽成
     ``指纹=开``/``指纹=关`` 两键由集成按条件选择，属等价重构（AST 校验仅这 8 条
     非逐字，其余 279/287 条与源文件逐字可覆盖）。
  4) **``catalogue_coverage()`` 的 "key 数" 口径**：以 **zh 权威目录**为准（keys、
     untranslated= en 相对 zh 缺失数）；en 目录要求全量翻译交付（untranslated==0，
     单测锁定），后续新增词条若未译会在统计中如实暴露。
- 交付物：src/aaa/i18n.py、src/aaa/locales/（zh 287 条原文 / en 287 条译文）、
  tests/unit/test_i18n.py（22 条：语言优先级/回退/格式化/覆盖统计/占位符一致性）。
  测试全注入（monkeypatch env/内存目录），无网络无系统改动。

## D-2026-10-25-45 W6 日报（06 文档波次一）的五处规格空档落位：签名 / 聚合口径 / 周窗 / SMTP 复用方式 / 包文件

- 日期：2026-10-25；模块：W6（src/aaa/reporting/daily.py + tests/unit/test_daily_report.py）
- 问题与落位：
  1) **``install_daily_task`` 签名缺数据目录**：规格写 ``install_daily_task(state,
     hour=9)``，但任务命令行需显式 ``--data-dir``（与 ``autostart_command`` 同策略，
     否则计划任务在非默认布局下会读错库）。落位：``install_daily_task(state,
     data_dir, *, hour=9)``；命令行固定为 ``report --daily --email --data-dir <dir>``，
     解释器策略（venv→pythonw/-c、frozen→cmd start /min）照搬 ``autostart_command``。
  2) **聚合口径：自聚合而非 ``store.stats()``**：报告需小时级趋势（日报 24 桶）与
     Top 事件（风险分降序），``stats()`` 只有 by_verdict/process/host/rule/day 且
     ``until`` 为闭区间。落位：``_collect`` 单遍分页拉取（``query`` 500/页，上限
     ``MAX_EVENTS=50000`` 超限如实标注 truncated）在 Python 侧统一聚合，报告内所有
     数字单一口径；``since <= ts < until`` 左闭右开在渲染侧自保证（query 的闭区间
     边界事件被过滤，不计入总数）。规则计数取 ``matched_rules[].id/dim``（不展示
     evidence），与 db 侧 ``event_rules`` 同源。
  3) **``render_weekly`` 的"周"定义**：规格未定。落位：含 ``day`` 的 **ISO 自然周
     （周一为始，7 个天桶）**；标题标注起止日期。
  4) **``email_daily`` 对 notify 的复用方式**：规格说"复用 notify/channels 的注入式
     SMTP"，但 ``channels.send_email`` 固定纯文本（``set_content`` 无 subtype），
     而 **channels.py 是并行共享文件**（不在 W6 独占清单，改它有写冲突风险）且顶层
     ``import httpx``（非运行时依赖，日报不想连带）。落位：不改 channels.py，
     ``email_daily(config, html, *, subject, sender)`` 镜像其注入式模式（默认实现
     ``_send_html_email`` 同 SSL/starttls/超时 10s 形态，``set_content(subtype=
     "html")``）；``EmailConfig`` 直接复用 notify.model。配置不完整（缺
     smtp_host/to_addrs）**显式 ValueError** 而非 build_channels 的跳过——日报是
     显式动作，静默跳过会被误认为已发送。
  5) **``src/aaa/reporting/__init__.py``**：所有权表只列了 daily.py，包导入必需
     ``__init__.py``（仅 docstring，无逻辑），视为模块交付的隐含部分。
- 脱敏实现（规格红线）：Top 事件表的路径/进程名与 Top 进程榜的进程名先过
  ``notify.summary.mask_event_path``（与通知摘要同一脱敏核心，decisions D-18/D-34），
  所有表格单元格在 ``_table`` 单点 ``html.escape``；sparkline 为纯数值坐标的内联
  SVG，天然免注入；报告不渲染 body/证据原文。冒烟验证：事件 path 携带假 AWS key、
  ``matched_rules[].evidence`` 故意放未打码原文，HTML 中均无明文。
- 交付物：src/aaa/reporting/daily.py（render_daily/render_weekly/sparkline_svg/
  email_daily/install_daily_task/uninstall_daily_task/restore_daily_report_task，
  import 即注册 teardown 还原器——``setup/service.py`` 同款机制）、
  tests/unit/test_daily_report.py（18 条：聚合数字/趋势桶/Top 截断排序/脱敏/HTML
  转义/sparkline 边界/注入式 email（含默认 smtplib 假连接 subtype 断言）/任务安装
  journal-first 失败保留/hour 校验/卸载幂等/teardown 注册端到端/命令行策略）。
  schtasks 与 smtplib 全 mock，无真实网络、无真实系统改动。


## D-2026-10-25-46 W4 性能（06 文档波次一）的规格空档落位：采样配置归属 / secrets 不回退口径 / 批量 mirror 语义

- 背景：06 文档 W4 要求「db.py：WAL + synchronous=NORMAL + insert_events 批量事务；
  pipeline.py：内容扫描采样——body > defaults.max_body_scan 时除 secrets 首段全扫外，
  其余扫描器仅扫描前 256KB（可配 sampling: {head_bytes: 262144}）」，落位如下：
  1) **采样配置归属**：`policy/model.py` 在全局禁改清单（集成阶段专属），故
     `SamplingConfig`（pydantic，extra=forbid；`enabled: bool = True`、
     `head_bytes: int = Field(262144, ge=1)`）定义在 `engine/pipeline.py`，经构造器
     注入：`AuditPipeline(loader, sampling=SamplingConfig|dict|None)`（dict 便于
     波次二直传）。波次二接线：策略 `sampling:` 段（集成自行在 model.py 加字段）
     → 构造器；`PolicyDocument` extra=forbid，当前策略文件写 `sampling:` 段会校验
     失败——预期边界，由波次二放开；不传 = 出厂 SamplingConfig。
  2) **「secrets 行为不回退」的实现口径**：secrets 在采样下保持与既有**逐字节一致**
     的路径（完整 body + `max_bytes=max_body_scan`，截断仍由扫描器内部按字符执行，
     多字节边界不少扫）；采样只作用于非豁免扫描器（`SAMPLING_EXEMPT_SCANNERS =
     {"secrets"}`，即"secrets 首段全扫"的落位），且在管线侧**先按字节切片**
     `body[:min(head_bytes, max_body_scan)]` 再交扫描器——扫描器不再解码整个大
     body，这才是大上传低延迟的来源。`max_body_scan` 仍是硬上限：有效截断 =
     min(max, head)，采样只会少扫、绝不比既有行为多扫；触发条件保持规格原文
     （仅当 len(body) > max_body_scan，小 body 一律全量扫描）。
  3) **采样默认开（enabled=True）**：出厂 head_bytes(262144) == max_body_scan 出厂
     值，默认策略下零行为差异，不构成升级风险。波次二第 5 条「default.yaml：
     sampling/hub/ 段（默认关）」若按"采样默认关"解读，应在 default.yaml 显式写
     `enabled: false`——管线默认值与 default.yaml 默认值是两层独立默认。
  4) **insert_events 的 mirror/返回值/原子性语义**：整批单事务（`with self._conn`）
     提交，返回处理的事件数；JSONL mirror 在 DB 提交成功后**按序补写**，镜像异常
     不回滚 DB（与逐条 append 同语义：落库为准，addon 钩子层 fail-open 兜底）；
     空清单 no-op；同 id 重放 = INSERT OR REPLACE 覆盖（与逐条一致）；批内任一行
     失败整批回滚（test_perf.py 坏行注入验证）。
  5) **覆盖索引选型**（"stats/list 查询加 covering index 复核"）：新增 3 个复合
     索引——`idx_events_ts_id (ts_epoch, id)`（列表页 ORDER BY 免 TEMP B-TREE）、
     `idx_event_rules_event_dim (event_id, dim)`（dim 过滤 EXISTS 子查询
     index-only）、`idx_event_rules_rule_dim (rule_id, dim)`（by_rule 聚合免回表）；
     既有 4 个单列索引保留（test_db.py schema 断言与旧库兼容）。EXPLAIN QUERY
     PLAN 断言落在 tests/unit/test_perf.py（本机 SQLite 3.42 实测计划文案）。
  6) **已知限制与观测**：采样未命中时事件无"被采样"标注（miss 无 matched_rules
     条目可挂），观测走 `AuditPipeline.stats()["sampled_scans"]`（截头次数）与
     `stats()["sampling"]`（当前配置）；事务次数断言经 `set_trace_callback` 统计
     BEGIN/COMMIT（Python 3.12 sqlite3 隐式事务可见，test_perf.py `_TxnCounter`）。
- 交付物：src/aaa/store/db.py（synchronous=NORMAL 每连接重设 / insert_events /
  3 个覆盖索引 / append 抽出 _event_row/_rule_rows 共用）、src/aaa/engine/pipeline.py
  （SamplingConfig + _sample_body 采样 + sampled_scans 计数）、
  tests/unit/test_perf.py（20 条）。测试：test_perf.py 全绿；受影响既有单测
  （test_db/test_pipeline/test_engine/test_store/test_block/test_decisions/
  test_web_api/test_cli_p4/test_policy_hot_reload_log/test_security_deepening）
  合计 186 条全绿（junit：failures=0 errors=0 skipped=0）。无系统级操作、无网络。

## D-2026-10-25-47 W8 多机聚合（06 文档波次一）的八处规格空档落位：wire 形态 / 摘要字段 / 中心鉴权 / 配置归属 / 缓冲语义 / 重试耗尽 / 端口 / 不加密边界

- 日期：2026-10-25；模块：W8（src/aaa/hub/ + tests/unit/test_hub.py）
- 问题：06 文档 W8 只给方向（agent 端"脱敏事件摘要 POST，队列+重试+批量 ≤50、
  trust_env=False"；中心端"独立 FastAPI app、Bearer 校验、内存缓冲→SQLite
  hub.db、机器名维度、跨机聚合查询"），若干形态未定，逐一落位如下。
- 选择：
  1) **wire 形态**：`POST {基地址}/ingest`（`url` 结尾 `/` 容忍，`/ingest` 由
     Forwarder 追加）；鉴权**双重比对**——`Authorization: Bearer <token>` 请求头
     为权威校验，body `token` 字段（规格字面要求存在于 `{token, host, events}`）
     必须同时匹配，任一不匹配 401（`secrets.compare_digest` 恒时比较）。
     Forwarder 两侧同时携带，第三方客户端须按同协议实现。
  2) **摘要字段形态**（"脱敏事件摘要"的结构落位）：`summarize_event` = 事件结构
     化字段（verdict/risk_score/process/destination/request/matched_rules）+
     `build_summary` 脱敏文本（`summary` 键）。自由文本字段（path/exe/cmdline/
     name/error）过 `mask_event_path` 同一脱敏核心；`matched_rules` 白名单化为
     id/dim/action/weight/severity/evidence（evidence 扫描时已打码，外发前再打
     一道，防线叠加）；**丢弃 `evidence` 文件信息**（指向 agent 本机路径，hub
     侧无意义）与 `judge_note.reason`（模型理由可能引用请求内容），judge_note
     只留 status/is_violation/confidence/category 白名单。脱敏责任在 agent 侧，
     中心不二次脱敏、也拿不到 body（事件模型本就不含 body）。
  3) **中心 GET 端点也要求 Bearer**（规格只写 ingest 校验）：hub 监听局域网
     （要收多机上报，**不适用面板的回环限制**），事件摘要虽脱敏仍是跨机审计
     数据，只读接口 `/api/hub/events|stats|machines` 一律 401 保护。
  4) **配置归属**：`policy/model.py` 属全局禁改 → `HubConfig`（extra="forbid"，
     enabled/url/token/batch_size≤50/timeout）定义在 `hub/model.py`，波次二
     集成时挂到 PolicyDocument 或由集成层透传；env 覆盖 `AAA_HUB_URL/TOKEN`
     （D-33 试用意图的**收窄版**：仅当策略从未配置 url+token 而环境变量把两者
     都补齐才自动启用——策略显式 `enabled: false` 永远获胜；且只给 url 不启用，
     避免差 token 的 Forwarder 空转 401）。
  5) **内存缓冲语义**：ingest 先进内存缓冲，达 `flush_threshold`（默认 100）
     自动单事务落盘，`flush()`/`close()` 兜底；缓冲上限（默认 10000）防落盘
     持续失败时内存膨胀（丢最旧并计数）；SQLite 写失败事件退回缓冲、如实计
     `flush_errors`，绝不静默丢。落盘以 `(machine, id)` 为主键 INSERT OR
     REPLACE——同机同事件重发幂等去重；规则明细进 `hub_event_rules` 供按规则
     聚合（db.py `event_rules` 同款形态）；`trim(days)` 治理保留期。
  6) **重试耗尽语义**：整批丢弃并计数（dropped/send_errors/last_error），**不
     无限重排队列**——重排会让持续故障的 hub 拖垮本机队列进而丢新事件，与
     notify dispatcher"绝不影响代理主路径"同一取舍；线性退避（backoff×n），
     默认重试 2 次；enqueue 永不阻塞（队列满丢弃计数）。
  7) **默认端口 8788**：面板 8787 / 代理 8080 之外取相邻空闲段；`run_hub`
     （uvicorn 懒导入）由波次二 `aaa hub serve` 接线，host 缺省 0.0.0.0。
  8) **hub.db 不加密**：与 audit.db 同边界（D-2026-10-24-36 第 6 条理由全适用：
     库文件在中心机数据目录、内容为已脱敏摘要、有 trim 保留期），需要保密依赖
     磁盘级加密；不在本模块引入 SQLCipher 类依赖。
- 理由：全部落位以"脱敏红线不松动、主路径永不阻塞、鉴权从紧、失败如实计数"
  为准绳；全部有对应单测覆盖。
- 交付物：src/aaa/hub/（model.py 配置 / forwarder.py Forwarder+summarize_event /
  collector.py HubCollector+create_hub_app+run_hub）、tests/unit/test_hub.py
  （22 条：脱敏不外发 / 批量 50/50/20 与 wire 形态 / 重试与线性退避 / 耗尽整批
  丢弃 / 客户端工厂异常不杀 worker / 队列溢出丢弃 / close 后忽略入队 / 鉴权
  401 矩阵（无头/错头/错 scheme/body 不匹配）/ 422 校验矩阵 / 缓冲落盘与重启
  存活 / 阈值自动落盘 / 幂等去重 / trim / 跨机聚合 / since-until / TestClient
  进程内全链路往返含错 token 不污染中心库）。httpx 客户端全注入、TestClient
  进程内传输，零真实网络、零系统改动。

## D-2026-10-25-48 波次二集成（06 文档）的规格落位：--lang 双通道 / profile 拷贝语义 / 两层采样默认 / hub 接线形态 / 批量落盘边界

- 日期：2026-10-25；范围：06 文档波次二任务 1-8 的集成决策（波次一 D-40～D-47 的
  预留空档逐一兑现）。全部为「规格未定」落位，不改计划要求的行为。
- 选择：
  1) **--lang 双通道**：typer 的 help= 文本在装饰器求值（模块导入期）取词，
     命令行参数解析晚于此——``--lang en --help`` 想渲染英文帮助，唯一时机是
     导入期。落位：cli.py 在**装饰器之前**做模块级 argv 预扫描（``_prescan_lang``，
     只匹配子命令之前选项区的精确 ``--lang``/``--lang=`` token；pytest 等库导入
     场景 argv 无该 token，零副作用），``--lang`` 选项本体再挂 eager 回调兜底
     （进程内 CliRunner 路径）。``AAA_LANG`` 环境变量天然覆盖导入期（i18n.get_lang）。
     优先级：``--lang`` > ``AAA_LANG`` > zh。E2E 以子进程冒烟（``AAA_LANG=en
     python -m aaa.cli --help`` 与 ``--lang en <cmd> --help`` 双路径全英文断言）。
  2) **命令帮助形态**：typer 优先用显式 ``help=`` kwarg 而非 docstring——docstring
     是静态中文、无法走 i18n。落位：31 个命令/组装饰器全部传 ``help=t("<cmd>.doc")``
     （多行 docstring 的补充段落补 ``<cmd>.detail`` 词条，zh 与原 docstring 逐字一致，
     保证默认 ``--help`` 输出不变；en 提供全译文）。
  3) **词条占位符与 t() 签名冲突**：W5 目录里 ``{key}``/``{reg_key}`` 占位符与
     ``t(key, **fmt)`` 的形参名撞车（``t("...", key=...)`` 抛 TypeError）。落位：
     目录侧改名 ``{item_key}``（task_created/entry_line/rule_created/err_delete/
     rule_deleted）与 ``{reg_key}``（wizard.proxy.registry），zh/en 同步，en 译文
     不变——集成期对波次一交付物的最小修正，test_i18n 的占位符一致性校验兜底。
  4) **多 profile 的「current 软链/拷贝」落位**：Windows 软链需特权，取**拷贝语义**
     ——``policy use <name>`` 校验（PolicyLoader 全量 pydantic）通过后把
     ``profiles/<name>.yaml`` **原样文本拷贝**为 ``policies/current.yaml``
     （保留 YAML 注释；不落 pydantic round-trip）；``config.default_policy_file()``
     让 current.yaml 存在即成为全部命令的缺省策略，出厂 default.yaml 永不被覆盖
     （``--reset`` 删除 current.yaml 回出厂）。``policy list`` 的"当前生效"判定 =
     解析到的缺省文件与 profile 内容一致（换行归一后的文本比较——Windows write_text
     的 \r\n 与 atomic_write_text 的 \n 视为同内容）。热更新 E2E 用真代理验证：
     切换后新请求按新规则求值（切换瞬间在途请求按旧策略求值是 mtime 轮询的如实语义，
     测试以持续流量等待生效而非假设即时）。
  5) **sampling 两层默认（兑现 D-46 第 3 条预期）**：管线层出厂 ``SamplingConfig``
     enabled=True（head==max 零差异）；**策略段** ``SamplingSection`` 默认
     ``enabled=False``——老策略文件（无本段）升级后严格保持 v0.2.x 全量扫描行为
     （用户自定义了更大 max_body_scan 时尤其重要），出厂 default.yaml 显式写
     ``enabled: false``（任务 5 的"默认关"字面）。``aaa run`` 接线
     ``AuditPipeline(sampling=doc.sampling.model_dump())``，启动时生效（热更新不切换，
     与加密/judge 同口径）。
  6) **hub 转发接线**：``AuditAddon`` 新增可选 ``forwarder`` 注入；**全部已完成事件**
     （response/error/blocked-connect 落盘路径）入队转发——hub 是审计汇总通道而非
     告警通道（告警阈值语义已属 notifications），HubConfig 不加阈值字段（保持 W8
     模型不动），中心侧本就有 verdict 过滤查询与 trim 保留期。``aaa hub forward
     status`` 是独立进程、看不见 run 进程内存计数——落位为**统计快照文件**：
     ``_StatsDumpingForwarder(Forwarder)`` 子类在每批发送后与退出路径把 ``stats()``
     原子写 ``data/hub-forward.json``（失败静默，观测通道不碰主路径），status 命令
     读快照 + 打印当前生效配置（token 永不回显）。
  7) **addon 批量落盘边界**：``--db-batch N``（默认 20，1=逐条）——缓冲攒满或
     **重要事件**（verdict block/confirm，或 action_taken ∈ blocked-403/
     blocked-connect/fail-open/error）立即 ``insert_events`` 单事务冲刷；缓冲先换出
     再写入，失败不回灌（fail-open 记日志）；``done()`` 退出冲刷。batch_size=1 时
     走原 ``append`` 路径，v0.2.x 行为逐字节一致（test_addon/test_crash_safety 等既有
     测试零改动通过）。
  8) **hub 包惰性导出**：policy.model 挂 ``HubConfig`` 后，``import aaa.hub.model``
     会执行包 __init__ → collector 顶层 ``import fastapi``——基础安装（未装 web
     extra）连 ``aaa policy lint`` 都会 ModuleNotFoundError。落位：``aaa/hub/__init__.py``
     改 PEP 562 ``__getattr__`` 惰性导出（公开名与原 __all__ 一一对应，test_hub 的
     子模块直导不受影响），collector/forwarder 仅在真正访问时加载。
  9) **teardown 目标映射补齐**（D-40 第 4 条/D-45 预留）：``teardown_target_kinds``
     新增 ``service``（KIND_SERVICE_TASK）与 ``daily``（KIND_DAILY_REPORT_TASK）；
     延迟导入防环（service/daily 反向 import teardown 注册还原器），还原器仍由
     各模块 import 自注册（cli 顶层已 import）。
  10) **ruff per-file 豁免**：cli.py 的 B008（typer.Option/Argument 与 t() 均出现在
      参数默认值位置，DSL 惯用法；此前逐处 noqa，v0.3.0 命令量大改为文件级豁免）；
      locales/*.py 的 E501（纯数据词条行不改写不拆行，拆行会破坏"与源文件逐字一致"
      的可核对性）。
  11) **杂项落位**：``report --daily`` 缺省落 ``data/reports/{daily|weekly}-<日>.html``
      （``--out`` 可覆盖；``--day`` 选项便于复现指定日）；``gitleaks sync`` 缺省落
      ``data/rules/gitleaks.yaml``（包 meta 自带 sha256/synced_at pin）；rules
      export/import 的目标策略缺省走 current.yaml 解析；conftest 新增 autouse
      ``_reset_i18n_state``（语言选择是进程级状态，不隔离会泄漏到后续测试破坏既有
      中文断言）。
- 测试：tests/unit/test_wave2_integration.py（29 例）+ tests/e2e/
  test_v030_experience_e2e.py（6 例）；全量套件与 ruff 结果见提交时的验收记录。


## D-2026-10-24-49 仓库许可证落位：PolyForm Noncommercial 1.0.0（可免费使用，禁止商用）

- 日期：2026-10-24；范围：LICENSE / pyproject / README / 官网两页 / 本决策记录。
- **选型**：需求为「可下载使用、禁止商用」。放弃 CC BY-NC 4.0（Creative Commons
  官方不建议用于软件）；采用 PolyForm Noncommercial 1.0.0（专为软件设计的非商用
  协议，GitHub 可自动识别）。允许：任何非商业目的的使用/修改/再分发（含个人研究、
  爱好项目，及慈善/教育/公共科研/公共安全卫生/环保/政府机构）；禁止：一切商业用途
  （销售、商业授权、作为服务提供等），商用须另行书面授权。
- **Required Notice**：LICENSE 内以协议规定的 ``Required Notice:`` 机制声明
  ``Copyright (c) 2026 EgressSentinel contributors``，随再分发强制传递。
- **第三方边界**：mitmproxy/typer/pydantic 等依赖保持各自 MIT/BSD 原协议（MIT 允许
  与非商用上层协议叠加分发）；PolyForm NC 仅约束本项目自有代码。README「许可证」
  章节明示该边界。
- **同步修改**：pyproject ``license = PolyForm-Noncommercial-1.0.0``；官网
  index.html 的 meta description / OG / JSON-LD（license 指向
  polyformproject.org）/ stat 卡 / FAQ / 页脚共 11 处与 vibe.html 页脚，由 MIT
  声明改为非商用表述；README 加 License 徽章与章节。
- 影响：GitHub 仓库页将显示 "PolyForm Noncommercial 1.0.0"（非 OSI 开源，属
  source-available）；SEO 文案同步更新。


