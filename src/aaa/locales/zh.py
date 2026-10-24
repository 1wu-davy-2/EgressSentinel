"""zh 词条目录（06 文档波次一 W5）：**原文目录**，逐条取自 cli.py / setup/wizard.py。

key 命名约定：
- ``common.*``：多处复用的共享文案；
- ``cli.col_*``：status/tail 等表格列标题（跨命令复用）；
- ``opt.*``：typer 参数 ``help=`` 文本；
- ``cli.<命令>.*``：各命令的输出/报错/``BadParameter``/docstring 首行；
- ``wizard.*``：``setup/wizard.py`` 交互向导文案。

``{placeholder}`` 为运行时插值占位符，与 ``en.py`` 必须保持同名集合一致
（tests/unit/test_i18n.py 做占位符一致性校验）；rich markup（``[red]`` 等）原样保留。

红线：本文件只承载词条数据，不含任何逻辑、不做任何系统级操作。
"""

from __future__ import annotations

#: zh 词条目录：key → 原文（与 cli.py / setup/wizard.py 现有输出逐字一致）
CATALOGUE: dict[str, str] = {
    # ---- 共享 ----
    "common.dry_run_noop": "[yellow](dry-run)[/yellow] 未实施。",
    "common.cancelled": "已取消。",
    "common.task_created": "[green]已创建计划任务[/green] {item_key}",
    "common.err_plain": "[red]{exc}[/red]",
    "common.read_failed": "读取失败：{exc}",
    "common.notify_none": "全部关闭",
    "common.policy_load_failed": "[red]策略加载失败：{exc}[/red]",
    "common.state_installed": "已安装",
    "common.state_not_installed": "未安装",
    # ---- 表格列标题（status/tail/report 复用） ----
    "cli.col_id": "ID",
    "cli.col_time": "时间",
    "cli.col_verdict": "判定",
    "cli.col_risk": "风险",
    "cli.col_method": "方法",
    "cli.col_path": "路径",
    "cli.col_host": "主机",
    "cli.col_process": "进程",
    "cli.col_item": "项",
    "cli.col_value": "值",
    # ---- 根命令与通用参数 ----
    "cli.app.help": "AI-AGENT-AUDIT：本机 AI Agent 外发流量审计（Windows）",
    "cli.setup.group_help": "系统设置下发（改动全部记录到 setup-state.json）",
    "cli.policy.group_help": "策略文件管理与校验",
    "cli.autostart.group_help": "开机自启计划任务（aaa run + 登录自检 watchdog）",
    "cli.notify.group_help": "告警通知（toast/webhook/email，04 文档）",
    "cli.fingerprint.group_help": "仓库指纹库（05 文档 W1：本地代码外发比对）",
    "cli.root.doc": "AI-AGENT-AUDIT 命令行入口。",
    "opt.data_dir.help": "数据目录（默认 <项目>/data；也可用环境变量 AAA_DATA_DIR）",
    "opt.dry_run.help": "只显示将执行的动作，不实施任何系统改动",
    "opt.version.help": "显示版本号",
    "opt.policy.help": "策略 YAML 文件（默认 policies/default.yaml）",
    "opt.yes.help": "跳过确认（自动化用）",
    # ---- run ----
    "opt.run_mode.help": (
        "采集模式：regular（默认，系统代理）| "
        "local[:spec]（需管理员，见 docs/notes/local-mode-spike.md）"
    ),
    "opt.host.help": "监听地址",
    "opt.port.help": "监听端口",
    "opt.run_pid.help": "仅 local 模式：限定目标进程 PID（透传 local:pid=…）",
    "opt.run_process.help": "仅 local 模式：限定目标进程名（透传 local:process=…）",
    "opt.run_jsonl.help": "同时镜像写 JSONL（data/raw/YYYYMMDD.jsonl；默认仅 SQLite）",
    "opt.retention_days.help": "事件保留天数（启动自动清理；默认 14 或 AAA_RETENTION_DAYS）",
    "opt.run_log_file.help": "启动/退出信息镜像写入该文件（开机自启等无控制台场景排障用）",
    "cli.run.doc": "启动采集代理（阻塞运行；Ctrl+C 优雅退出；关机/注销自动限时收尾）。",
    "cli.run.err_pid_not_local": "--pid/--process 仅支持 --mode local",
    "cli.run.err_pid_mutex": "--pid 与 --process 互斥，只选其一",
    "cli.run.err_local_admin": (
        "[red]--mode local 需要管理员权限（WinDivert 透明重定向）。[/red]\n"
        "请以管理员身份运行 PowerShell / 终端后重试：\n"
        "  右键开始菜单 → 终端(管理员) 或 PowerShell(管理员)\n"
        "  然后执行：aaa run --mode local"
    ),
    "cli.run.banner": "[green]aaa {version}[/green] mode={mode} 监听 {host}:{port}",
    "cli.run.policy_line": "策略：{path}（mode={mode} version={version}，mtime 热更新轮询 2s）",
    "cli.run.pinned_line": "local 目标进程：pid={pid} name={name}",
    "cli.run.store_line": "事件库：{db_file}",
    "cli.run.jsonl_mirror": "  +JSONL 镜像 data/raw/",
    "cli.run.evidence_dir": "  证据：{evidence_dir}",
    "cli.run.trim_line": (
        "启动自动清理：删除 {events} 条过期事件（保留期 {days} 天，连带证据 {evidence} 个）"
    ),
    "cli.run.notify_line": (
        "通知：{enabled}{extra}；门槛 min_action={min_action}；"
        "限流 {max_per_minute} 条/分钟（超出合并为 digest）"
    ),
    "cli.run.notify_provider": "（provider={provider}）",
    "cli.run.fp_missing": (
        "[yellow]指纹比对：已启用但指纹库缺失/损坏——运行 "
        "aaa fingerprint build 构建后重启生效[/yellow]"
    ),
    "cli.run.fp_on": "指纹比对：开启（{repos} 仓库 {slices} 片 → data/{file_name}）",
    "cli.run.fp_off": "指纹比对：关闭（policy.fingerprint.enabled）",
    "cli.run.judge_on": (
        "LLM 判定：开启（model={model}，今日已用 {used}/{max_per_day}；key=环境变量只读不落盘）"
    ),
    "cli.run.judge_off": "LLM 判定：关闭（policy.judge.enabled）",
    "cli.run.crypto_on": "证据加密：开启（{algorithm}，keyfile={keyfile}；密钥首次写入后生成）",
    "cli.run.crypto_off": "证据加密：关闭（policy.encrypt.enabled；读取仍兼容历史密文）",
    "cli.run.hint_exit": "按 Ctrl+C 优雅退出；关机/注销时自动限时收尾（不阻塞系统关机）。",
    "cli.run.log_start": (
        "aaa {version} 启动 mode={mode} listen={host}:{port} policy={path}({policy_mode})"
    ),
    "cli.run.log_stop": "aaa 已停止（正常退出或收到关机信号）",
    # ---- setup（一键引导入口） ----
    "opt.setup_yes.help": "跳过逐步确认（自动化用）",
    "opt.machine_ca.help": "CA 安装到 LocalMachine（需管理员；默认 CurrentUser）",
    "cli.setup.doc": (
        "交互式一键引导：CA 根证书 → 系统代理 → 用户环境变量（每步先展示改动再确认）。"
    ),
    "cli.setup.ask_autostart": "安装开机自启与看门狗计划任务（{task_name} 等 2 项）？",
    "cli.setup.hint_autostart_retry": "可稍后 aaa autostart on 重试",
    "cli.setup.err_autostart": "[red]自启任务创建失败：{exc}[/red]（{hint}）",
    "cli.setup.ask_spawn": "立即启动审计代理（后台常驻；aaa status 查看 / aaa teardown 停止）？",
    "cli.setup.err_spawn": "[red]后台启动失败：{exc}[/red]（可手动前台运行 {hint}）",
    "cli.setup.spawned": (
        "[green]审计代理已后台启动[/green] pid={pid}（五维规则全量监控中；日志 data/autostart.log）"
    ),
    # ---- setup ca ----
    "opt.ca_store.help": (
        "证书存储：user（CurrentUser，无需管理员）| machine（LocalMachine，需管理员）"
    ),
    "cli.setup_ca.doc": "生成（如缺失）并安装 mitmproxy CA 到证书存储。",
    "cli.setup_ca.err_store": "--store 只支持 user|machine",
    "cli.setup_ca.ca_info": (
        "CA：{path}\n序列号：{serial}  指纹(SHA1)：{thumbprint}\n主题：{subject_cn}"
    ),
    "cli.setup_ca.will_do": "将执行：安装该 CA 到 {store} 证书存储，并记录到 setup-state.json。",
    "cli.setup_ca.dry_run": "[yellow](dry-run)[/yellow] 将安装到 {store} 证书存储，未实施。",
    "cli.setup_ca.err_machine_admin": (
        "[red]--store machine 需要管理员权限。[/red] "
        "请以管理员身份运行终端后重试，或使用 --store user（CurrentUser，无需管理员）。"
    ),
    "cli.setup_ca.installed": (
        "[green]已安装到 {store} 证书存储[/green]（teardown 可按序列号精确删除）。"
    ),
    # ---- setup proxy ----
    "opt.winhttp.help": "同时设置 WinHTTP 机器代理（需管理员）",
    "cli.setup_proxy.doc": "设置 WinINET 用户代理（可选 WinHTTP）。",
    "cli.setup_proxy.will_do": (
        "将设置 WinINET 用户代理 {host}:{port}（override=<local>;localhost;127.0.0.1）"
    ),
    "cli.setup_proxy.will_do_winhttp": "将设置 WinHTTP 机器代理 {host}:{port}（需管理员）",
    "cli.setup_proxy.done": "[green]代理设置完成[/green]；浏览器建议重启后生效。",
    # ---- setup env ----
    "cli.setup_env.doc": (
        "下发用户环境变量（HTTP_PROXY/NODE_*/REQUESTS_CA_BUNDLE 等，02 文档 D1 清单）。"
    ),
    "cli.setup_env.table_title": "将下发的用户环境变量",
    "cli.setup_env.col_name": "变量",
    "cli.setup_env.done": "[green]环境变量已下发[/green]；新开的终端/应用生效。",
    # ---- teardown ----
    "opt.teardown_targets.help": (
        "限定范围：ca | proxy | env | autostart | firewall | service | daily（可多选）；缺省=全部"
    ),
    "cli.teardown.doc": (
        "按 setup-state.json 逆序幂等还原全部（或指定类别的）改动（崩溃后仍完整还原）。"
    ),
    "cli.teardown.empty": "状态文件为空：没有需要还原的改动。",
    "cli.teardown.will_restore": "将按状态文件逆序还原 {count} 项改动：",
    "cli.teardown.entry_line": "  - {kind}:{item_key}（{ts}）",
    "cli.teardown.restored": "[green]已还原[/green] {item}",
    "cli.teardown.done": "[green]teardown 完成：全部改动已还原。[/green]",
    "cli.teardown.failed": "[red]teardown 存在失败项，记录已保留，可重跑 aaa teardown 重试。[/red]",
    # ---- autostart ----
    "cli.autostart_on.doc": (
        "创建两个登录计划任务：aaa run 常驻 + watchdog 自检（--fix 断网自动还原）。"
    ),
    "cli.autostart_on.will_create": (
        "将创建 2 个当前用户级计划任务（登录时触发，改动记入 setup-state.json）："
    ),
    "cli.autostart_on.task1": "  1) {name}：{cmd} {args}",
    "cli.autostart_on.task2": "  2) {name}（延迟 {delay}s）：{cmd} {args}",
    "cli.autostart_on.confirm": "确认创建？",
    "cli.autostart_on.effect": (
        "效果：开机自动起代理；若自启失败/进程被杀，登录 30s 后 watchdog 自动还原代理设置，"
        "避免「开机断网」。"
    ),
    "cli.autostart_off.doc": "删除自启与看门狗计划任务（幂等；不影响其余 setup 改动）。",
    "cli.autostart_off.removed": "[green]已删除计划任务并清理记录[/green]：{label}",
    "cli.autostart_off.label_none": "（本来就不存在）",
    "cli.autostart_status.doc": "查看自启/看门狗计划任务是否已安装。",
    "cli.autostart_status.line": "{name}：{state}",
    # ---- watchdog ----
    "opt.watchdog_fix.help": "断网态自动还原代理设置与代理环境变量（CA 无害保留）",
    "opt.watchdog_wait.help": "端口有界等待秒数（登录竞态保护）",
    "opt.watchdog_log.help": "自检日志文件（默认 data/watchdog.log）",
    "cli.watchdog.doc": (
        "开机自检：检测「系统代理已启用但本机代理端口不可达」的断网态（--fix 自动还原）。"
    ),
    "cli.watchdog.status_line": "[{style}]自检：{status}[/{style}]  {detail}",
    # ---- notify test ----
    "opt.notify_channel.help": "toast | webhook | email（缺省=策略启用的全部通道）",
    "cli.notify_test.doc": "发送一条测试通知（走真实通道，用户显式触发；04 文档 §5 T6）。",
    "cli.notify_test.summary": (
        "这是一条测试通知（aaa notify test）。\n"
        "通道 {channel} 工作正常；此后 block/alert 命中事件的摘要会经此送达。\n"
        "发送时间：{ts}"
    ),
    "cli.notify_test.err_channel": "--channel 只支持 {names}，收到 {channel!r}",
    "cli.notify_test.err_no_channels": (
        "[yellow]当前策略未启用任何通知通道。[/yellow]\n"
        "在策略 YAML 的 notifications 段启用（toast/webhook/email），"
        "或设置 AAA_WEBHOOK_URL 快速试用 webhook。"
    ),
    "cli.notify_test.err_channel_config": (
        "[red]通道 {name} 未启用或配置不完整。[/red]webhook 需 "
        "notifications.webhook.enabled: true 且 url 非空（或设 AAA_WEBHOOK_URL）；"
        "email 需 smtp_host 与 to_addrs。"
    ),
    "cli.notify_test.err_send": "[red]{name} 发送失败：{exc}[/red]",
    "cli.notify_test.sent": "[green]{name} 测试通知已发送[/green]",
    # ---- status ----
    "cli.status.doc": "当前状态：代理 / CA / 防火墙 / 策略版本 / 最近 5 事件 / 待还原改动。",
    "cli.status.table_title": "aaa {version} 状态（数据目录 {data_dir}）",
    "cli.status.proxy_on": "已启用 {server}",
    "cli.status.proxy_off": "未启用（server={server!r}）",
    "cli.status.winhttp_direct": "直连",
    "cli.status.winhttp_server": "server={server}",
    "cli.status.row_proxy_wininet": "代理 WinINET（用户）",
    "cli.status.row_proxy_winhttp": "代理 WinHTTP（机器）",
    "cli.status.ca_desc": "{subject_cn} serial={serial}（{pem}）",
    "cli.status.ca_missing": "尚未生成（aaa setup ca）",
    "cli.status.row_ca": "CA（confdir）",
    "cli.status.harden_on": "已加固 {count} 条规则（aaa harden off / teardown firewall 还原）",
    "cli.status.harden_off": "未启用（aaa harden on，需管理员）",
    "cli.status.row_harden": "防火墙加固（harden）",
    "cli.status.policy_desc": "mode={mode} version={version}",
    "cli.status.notify_desc": (
        "{enabled}；门槛 min_action={min_action}；限流 {max_per_minute} 条/分钟"
    ),
    "cli.status.notify_webhook": "；webhook provider={provider}",
    "cli.status.fp_on": "指纹=开",
    "cli.status.fp_off": "指纹=关",
    "cli.status.judge_on": "judge=开",
    "cli.status.judge_off": "judge=关",
    "cli.status.response_on": "响应标注=开",
    "cli.status.response_off": "响应标注=关",
    "cli.status.crypto_on": "证据加密=开",
    "cli.status.crypto_off": "证据加密=关",
    "cli.status.row_policy": "策略",
    "cli.status.row_notify": "通知",
    "cli.status.row_deepening": "安全深化",
    "cli.status.row_events": "事件库",
    "cli.status.events_desc": "{count} 条（confirm 待决策 {pending_confirm}；库 {db_file}）",
    "cli.status.open_failed": "打开失败：{exc}",
    "cli.status.recent_title": "最近 5 条事件",
    "cli.status.no_events": "(暂无事件)",
    "cli.status.pending_restore": (
        "[yellow]注意：状态文件有 {count} 项未还原改动（崩溃残留或未 teardown），"
        "运行 aaa teardown 还原。[/yellow]"
    ),
    "cli.status.degraded": (
        "[bold red]自检异常：系统代理仍启用但代理端口不可达（应用会『断网』）。"
        "恢复：aaa watchdog --fix / aaa teardown proxy / 重新 aaa run[/bold red]"
    ),
    "cli.status.selfcheck_skip": "(自检跳过：{exc})",
    "cli.status.hint_autostart_off": "aaa autostart off 关闭",
    "cli.status.hint_autostart_on": "aaa autostart on 开启",
    "cli.status.autostart_line": "开机自启：{state}（{hint}）",
    "cli.status.autostart_read_failed": "(开机自启状态读取失败：{exc})",
    # ---- tail ----
    "opt.tail_verdict.help": "只看指定判定",
    "opt.tail_interval.help": "轮询间隔秒",
    "opt.tail_from_start.help": "从最早事件开始（默认只看新事件）",
    "opt.tail_once.help": "只轮询一次后退出（测试/脚本用）",
    "cli.tail.doc": "实时滚动显示新事件（rich Live；Ctrl+C 退出）。",
    "cli.tail.listen_line": (
        "tail：监听新事件（verdict={verdict} pid={pid} host={host}），Ctrl+C 退出。"
    ),
    "cli.tail.filter_all": "全部",
    "cli.tail.table_title": "事件流（新→旧）",
    "cli.tail.new_event": "[green]+[/green] {id} {ts} {verdict} {method} {host}{path}",
    "cli.tail.exited": "tail 已退出。",
    # ---- report ----
    "opt.report_since.help": "起始：24h/30m/7d 或 ISO 时间",
    "opt.report_until.help": "截止：ISO 时间",
    "opt.report_json.help": "以 JSON 输出",
    "opt.report_csv.help": "以 CSV 输出",
    "opt.report_verify.help": "复核全部证据文件 sha256（大库较慢）",
    "cli.report.doc": "聚合报告：按判定/进程/主机/规则统计（03 文档 T4.2）。",
    "cli.report.err_json_csv": "--json 与 --csv 只能二选一",
    "cli.report.table_title": "报告（{since} ~ {until}，共 {total} 条）",
    "cli.report.window_all": "全部",
    "cli.report.window_now": "现在",
    "cli.report.col_dim": "维度",
    "cli.report.col_count": "数量",
    "cli.report.row_verdict": "判定",
    "cli.report.row_process": "进程",
    "cli.report.row_host": "主机",
    "cli.report.row_rule": "规则",
    "cli.report.integrity": "证据复核：检查 {checked} 个，缺失 {missing}，损坏 {corrupted}",
    # ---- trim ----
    "opt.trim_days.help": "保留最近 N 天，删除更早的事件与证据",
    "cli.trim.doc": "清理过期事件与证据文件（02 文档 D6 保留期；``run`` 启动时也会自动执行）。",
    "cli.trim.done": (
        "[green]trim 完成[/green]：删除 {events} 条事件、{evidence} 个证据文件"
        "（保留期 {days} 天）。"
    ),
    # ---- harden ----
    "opt.harden_action.help": "on | off",
    "opt.harden_proxy_exe.help": "on：放行的代理可执行文件（缺省=当前解释器/可执行文件自身）",
    "cli.harden.doc": "防火墙加固开关（05 文档波次一 W2/波次二 §5）：把 443 出站收敛到本代理。",
    "cli.harden.err_action": "harden 只支持 on | off",
    "cli.harden.err_admin": (
        "[red]harden 需要管理员权限（netsh advfirewall 需提升令牌）。[/red]\n"
        "请以管理员身份运行 PowerShell / 终端后重试：\n"
        "  右键开始菜单 → 终端(管理员) 或 PowerShell(管理员)\n"
        "  然后执行：aaa harden on"
    ),
    "cli.harden.err_proxy_missing": "[red]代理程序不存在：{exe}[/red]",
    "cli.harden.will_create": "将创建 {count} 条出站防火墙规则（名称前缀 EgressSentinel-）：",
    "cli.harden.rule_line": "  - {name}：{action} {protocol} {port} ← {program}",
    "cli.harden.program_any": "（任意程序）",
    "cli.harden.boundary": (
        "[yellow]已知边界：Windows 筛选平台 Block 优先于 Allow，any-Block 规则会同时"
        "命中代理与 svchost 白名单——加固后 443 出站可能全断（含本工具代理）。"
        "出现断网可立即执行 aaa harden off 还原。[/yellow]"
    ),
    "cli.harden.dry_run": "[yellow](dry-run)[/yellow] 未实施（未触达防火墙，未写状态文件）。",
    "cli.harden.confirm": "确认创建以上防火墙规则？",
    "cli.harden.cancelled_nochange": "已取消。未对系统做任何改动。",
    "cli.harden.err_apply": "[red]防火墙加固失败：{exc}[/red]",
    "cli.harden.rule_created": "[green]已创建防火墙规则[/green] {item_key}",
    "cli.harden.done": (
        "加固完成：{count} 条规则在案（setup-state.json）；"
        "还原：aaa harden off 或 aaa teardown firewall。"
    ),
    "cli.harden.off_no_records": "状态文件没有防火墙加固记录（本就未加固，无需还原）。",
    "cli.harden.will_delete": "将删除 {count} 条防火墙规则：",
    "cli.harden.err_delete": "[red]{kind}:{item_key} 删除失败：{exc}[/red]",
    "cli.harden.rule_deleted": "[green]已删除防火墙规则[/green] {item_key}",
    "cli.harden.err_delete_failed": (
        "[red]{count} 条规则删除失败（记录保留，可重跑 aaa harden off 重试）。[/red]"
    ),
    "cli.harden.off_done": "[green]防火墙加固已全部还原。[/green]",
    # ---- fingerprint build ----
    "opt.fp_repo.help": "仓库工作区路径（可多次传入；缺省读策略 fingerprint.repos）",
    "opt.fp_rebuild.help": "丢弃现有指纹库从零重建（缺省在既有库上增量合并）",
    "cli.fp_build.doc": "构建/增量合并仓库指纹库（data/fingerprints.bin）：纯本地，无任何外发。",
    "cli.fp_build.err_no_repos": (
        "[red]未指定仓库。[/red] 用 --repo PATH（可多次）或在策略 "
        "fingerprint.repos 配置仓库路径清单。"
    ),
    "cli.fp_build.msg_rebuild": "[yellow]--rebuild：丢弃现有指纹库，从零重建。[/yellow]",
    "cli.fp_build.msg_corrupt": "[yellow]现有指纹库缺失/损坏，将重建。[/yellow]",
    "cli.fp_build.skip_exists": "{name}：已在指纹库中（--rebuild 可从零重建）",
    "cli.fp_build.merged": "[green]已并入[/green] {repo}：索引 {files} 文件 / {slices} 片",
    "cli.fp_build.skipped_suffix": (
        "（跳过：过大 {too_large}、二进制 {binary}、读取失败 {errored}）"
    ),
    "cli.fp_build.slice_cap": (
        "[yellow]仓库 {repo} 触达总片上限（{total} 片），后续文件未入库。[/yellow]"
    ),
    "cli.fp_build.skip_line": "[yellow]跳过[/yellow] {note}",
    "cli.fp_build.fail_line": "[red]失败[/red] {error}",
    "cli.fp_build.err_all_failed": "[red]没有任何仓库被并入，指纹库未改动。[/red]",
    "cli.fp_build.no_new": "没有新增仓库（请求的仓库都已在指纹库中）；指纹库未改动。",
    "cli.fp_build.saved": (
        "[green]指纹库已保存[/green] {path}：{repos} 仓库 / {slices} 片 / {digests} 指纹。"
    ),
    "cli.fp_build.restart_hint": "（重启 aaa run 后生效）",
    # ---- web ----
    "opt.web_host.help": "监听地址（仅允许本地回环）",
    "cli.web.doc": "启动本地 Web 面板（只读 + confirm 决策；仅监听 127.0.0.1）。",
    "cli.web.err_not_loopback": "Web 面板只允许本地回环监听（{hosts}），收到 {host!r}",
    "cli.web.err_missing_dep": (
        "[red]Web 面板依赖缺失：{exc}[/red]\n"
        "请安装 web 扩展：pip install -e .[web]（fastapi + uvicorn）"
    ),
    "cli.web.err_policy_soft": "[yellow]策略加载失败（面板仍可查看事件）：{exc}[/yellow]",
    "cli.web.listening": (
        "[green]Web 面板[/green] http://{host}:{port}（仅本地访问；Ctrl+C 退出）"
    ),
    # ---- policy lint ----
    "cli.policy_lint.doc": (
        "校验策略文件（pydantic 严格 schema，03 文档 T3.1）：合法打印摘要，非法以 1 退出。"
    ),
    "cli.policy_lint.err_invalid": "[red]策略校验失败：{path}[/red]\n{exc}",
    "cli.policy_lint.table_title": "策略合法：{path}",
    "cli.policy_lint.row_version": "version",
    "cli.policy_lint.row_mode": "mode",
    "cli.policy_lint.row_policy_version": "policy_version",
    "cli.policy_lint.row_fail_open": "fail_open",
    "cli.policy_lint.row_max_body_scan": "max_body_scan",
    "cli.policy_lint.row_domain_classes": "domain classes",
    "cli.policy_lint.row_domain_rules": "domain rules",
    "cli.policy_lint.row_process_profiles": "process profiles",
    "cli.policy_lint.row_process_rules": "process rules",
    "cli.policy_lint.row_scanners": "scanners",
    "cli.policy_lint.row_content_rules": "content rules",
    "cli.policy_lint.row_volume_rules": "volume rules",
    "cli.policy_lint.row_time_window_rules": "time_window rules",
    "cli.policy_lint.row_fingerprint": "fingerprint",
    "cli.policy_lint.row_judge": "judge",
    "cli.policy_lint.row_response": "response",
    "cli.policy_lint.row_encrypt": "encrypt",
    "cli.policy_lint.fp_desc": "enabled={enabled}, repos={repos}, min_hits={min_hits}",
    "cli.policy_lint.judge_desc": "enabled={enabled}, model={model}, budget/day={budget}",
    "cli.policy_lint.response_ids": "（{ids}）",
    "cli.policy_lint.encrypt_desc": "enabled={enabled}",
    # ---- 交互向导（setup/wizard.py） ----
    "wizard.ca.title": "① CA 根证书",
    "wizard.ca.store_machine": "LocalMachine\\Root（需管理员）",
    "wizard.ca.store_user": "CurrentUser\\Root",
    "wizard.ca.header": "将证书安装到 {store_label} 证书存储：",
    "wizard.ca.file": "  CA 文件：{path}",
    "wizard.ca.serial": "  序列号：{serial}（teardown 按序列号精确删除，不误删其他证书）",
    "wizard.ca.thumbprint": "  指纹(SHA1)：{thumbprint}",
    "wizard.ca.record_to": "  记录改动到：{state_file}",
    "wizard.ca.machine_warning": "  ⚠ 机器级存储影响所有用户，需要管理员权限。",
    "wizard.proxy.title": "② 系统代理（WinINET 用户级）",
    "wizard.proxy.header": "将设置 WinINET 用户代理：{host}:{port}",
    "wizard.proxy.registry": "  注册表：HKCU\\{reg_key}",
    "wizard.proxy.values": (
        "  键值：ProxyEnable=1, ProxyServer={host}:{port}, "
        "ProxyOverride=<local>;localhost;127.0.0.1"
    ),
    "wizard.proxy.refresh": "  写入后 InternetSetOption 通知 WinINET 刷新（浏览器建议重启）",
    "wizard.proxy.record_to": "  旧值先记录到：{state_file}（teardown 还原）",
    "wizard.env.title": "③ 用户环境变量",
    "wizard.env.merged_pem": (
        "将创建合并 PEM：{path}（mitmproxy CA + 系统 CA，供 REQUESTS_CA_BUNDLE 等）"
    ),
    "wizard.env.header": "将写入以下用户环境变量（HKCU\\Environment，新终端生效）：",
    "wizard.env.line": "  {name} = {value}",
    "wizard.env.broadcast": "  并广播 WM_SETTINGCHANGE；全部记录到状态文件可还原",
    "wizard.welcome": "AI-AGENT-AUDIT 一键引导：以下步骤将修改系统设置，逐步确认执行。",
    "wizard.dry_run_banner": "[yellow](dry-run)[/yellow] 只展示计划，不实施任何改动。",
    "wizard.confirm_step": "{title}：执行该步骤？",
    "wizard.skipped": "  [dim]已跳过。[/dim]",
    "wizard.dry_run_step": "  [yellow](dry-run)[/yellow] 未实施。",
    "wizard.step_failed": "  [red]失败：{exc}[/red]（记录已保留，可 teardown 还原后重试）",
    "wizard.step_done": "  [green]完成。[/green]",
    "wizard.summary_applied": "向导结束：{applied}。可运行 aaa teardown 一键还原全部改动。",
    "wizard.summary_none": "向导结束：未执行任何改动。",
    # ------------------------------------------------------------------
    # v0.3.0 波次二新增（06 文档波次二）：新命令与 --lang。zh 为原文，
    # 与 cli.py 改造后的字面输出逐字一致（默认 zh 输出不变）。
    # ------------------------------------------------------------------
    # ---- --lang（根选项） ----
    "opt.lang.help": "界面语言：zh | en（也可用环境变量 AAA_LANG；帮助文本按启动时语言渲染）",
    # ---- service（W1 服务化） ----
    "cli.service.group_help": "Windows 服务化：ONSTART 计划任务 EgressSentinel-Service（06 文档 W1）",
    "opt.service_highest.help": "以最高权限运行（RunLevel=HIGHEST；缺省开启）",
    "cli.service_install.doc": "安装开机服务计划任务（ONSTART+SYSTEM；需管理员，改动记录 setup-state.json）。",
    "cli.service_install.will_do": (
        "将创建 ONSTART 服务计划任务 {task_name}（SYSTEM 账户；隐藏运行 aaa run，日志 {log_file}）："
    ),
    "cli.service_install.err_admin": (
        "[red]service install 需要管理员权限（ONSTART+SYSTEM 任务需提升令牌）。[/red]\n"
        "请以管理员身份运行 PowerShell / 终端后重试：\n"
        "  右键开始菜单 → 终端(管理员) 或 PowerShell(管理员)\n"
        "  然后执行：aaa service install"
    ),
    "cli.service_install.done": (
        "[green]服务计划任务已创建[/green] {task_name}（改动已记录；aaa service status 查看状态）"
    ),
    "cli.service_install.err": "[red]服务计划任务创建失败：{exc}[/red]",
    "cli.service_uninstall.doc": "删除服务计划任务并清理记录（幂等）。",
    "cli.service_uninstall.removed": "[green]已删除服务计划任务并清理记录[/green] {task_name}",
    "cli.service_uninstall.absent": "服务计划任务不存在（未安装，无需删除）。",
    "cli.service_status.doc": "查看服务计划任务安装状态与互斥提示（只读）。",
    "cli.service_status.line": (
        "{task_name}：{state}（命令 {command}，日志 {log_file}）"
    ),
    "cli.service_status.line_no_journal": "{task_name}：{state}",
    "cli.service_status.conflict": "[yellow]{warning}[/yellow]",
    "cli.service_install.confirm": "确认创建服务计划任务？",
    # ---- tray（W2 托盘） ----
    "cli.tray.doc": "启动系统托盘（依赖 pystray/Pillow：pip install -e .[tray]；缺依赖以退出码 2 结束）。",
    # ---- report --daily/--weekly/--email（W6 日报） ----
    "opt.report_daily.help": "渲染当日 HTML 日报（默认落 data/reports/）",
    "opt.report_weekly.help": "渲染该日所在 ISO 周（周一为始）HTML 周报",
    "opt.report_email.help": "渲染后经策略 notifications.email 通道发送（需完整 SMTP 配置）",
    "opt.report_day.help": "指定日期 YYYY-MM-DD（缺省今天；--weekly 取该日所在 ISO 周）",
    "opt.report_out.help": "HTML 输出路径（缺省 data/reports/daily-<日期>.html / weekly-<日期>.html）",
    "cli.report.err_daily_json": "--daily/--weekly 与 --json/--csv 不能同时使用",
    "cli.report.err_daily_both": "--daily 与 --weekly 只能二选一",
    "cli.report.err_day": "日期格式错误：{value!r}（应为 YYYY-MM-DD）",
    "cli.report.daily_saved": "[green]日报已生成[/green] {path}",
    "cli.report.weekly_saved": "[green]周报已生成[/green] {path}",
    "cli.report.email_sent": "[green]日报邮件已发送[/green] → {to}",
    "cli.report.email_failed": "[red]日报邮件发送失败：{exc}[/red]",
    "cli.report.render_failed": "[red]报告渲染失败：{exc}[/red]",
    # ---- rules export/import（W7 规则市场） ----
    "cli.rules.group_help": "规则市场：策略段导出/导入（06 文档 W7；校验不过绝不落盘）",
    "cli.rules_export.doc": "导出策略段为 YAML 文本（--out 落盘，缺省打印到 stdout）。",
    "opt.rules_out.help": "导出落盘路径（缺省打印 stdout）",
    "cli.rules_export.err": "[red]导出失败：{exc}[/red]",
    "cli.rules_export.done": "[green]段 {section} 已导出[/green] → {path}",
    "cli.rules_import.doc": "把 YAML 文件（``-`` 读 stdin）导入当前策略段：三关校验全过才原子落盘。",
    "opt.rules_merge.help": "合并模式：replace（整段替换，缺省）| union（按 id/键合并，导入者胜）",
    "opt.rules_policy.help": "目标策略文件（缺省当前生效策略；整文重写会丢失 YAML 注释）",
    "cli.rules_import.note_comments": (
        "[yellow]提示：导入按整文重写，原策略 YAML 注释会丢失（可先 aaa rules export 备份）。[/yellow]"
    ),
    "cli.rules_import.done": "[green]段 {section} 已导入[/green]（merge={merge}）→ {path}",
    "cli.rules_import.err": "[red]导入失败：{exc}[/red]",
    # ---- gitleaks（W7 上游同步） ----
    "cli.gitleaks.group_help": "gitleaks 上游规则同步：TOML → 本引擎 secrets 规则包（sha256 pin）",
    "cli.gitleaks_sync.doc": "从 URL 或本地 TOML 同步 gitleaks 规则并转换为规则包 YAML。",
    "opt.gitleaks_out.help": "规则包落盘路径（缺省 data/rules/gitleaks.yaml）",
    "cli.gitleaks_sync.done": (
        "[green]gitleaks 规则已同步[/green]：{converted} 条（跳过 {skipped}）"
        " sha256={sha256} → {path}"
    ),
    "cli.gitleaks_sync.err": "[red]gitleaks 同步失败：{exc}[/red]",
    # ---- hub（W8 多机聚合） ----
    "cli.hub.group_help": "多机聚合：中心收集端（hub serve）与 agent 转发状态（06 文档 W8）",
    "cli.hub_serve.doc": "启动 hub 中心收集服务（默认 0.0.0.0，Bearer 令牌鉴权）。",
    "opt.hub_host.help": "监听地址（缺省 0.0.0.0；收集多机上报）",
    "opt.hub_port.help": "监听端口（缺省 8788）",
    "opt.hub_token.help": "共享令牌（缺省环境变量 AAA_HUB_TOKEN；必填）",
    "cli.hub_serve.err_token": "[red]hub 中心需要共享令牌：用 --token 或环境变量 AAA_HUB_TOKEN。[/red]",
    "cli.hub_serve.err_dep": (
        "[red]hub 依赖缺失：{exc}[/red]\n请安装 web 扩展：pip install -e .[web]（fastapi + uvicorn）"
    ),
    "cli.hub_serve.db_line": "事件库：{db_file}（机器名维度；重启后历史保留）",
    "cli.hub_serve.listening": "[green]hub 中心[/green] http://{host}:{port}（Bearer 鉴权；Ctrl+C 退出）",
    "cli.hub_forward.doc": "查看 agent 端转发配置与最近统计（运行中的 aaa run 写 data/hub-forward.json）。",
    "cli.hub_forward.disabled": "hub 转发：关闭（policy hub.enabled 或 AAA_HUB_URL+AAA_HUB_TOKEN）",
    "cli.hub_forward.enabled": (
        "hub 转发：开启 → {url}（batch_size={batch_size}；token 经策略/环境变量，不回显）"
    ),
    "cli.hub_forward.no_stats": "（暂无运行时统计：aaa run 未运行或尚未转发）",
    "cli.hub_forward.stats_line": (
        "已发送 {sent_events} 条 / {sent_batches} 批；丢弃 {dropped}；重试 {retries_used}；"
        "错误 {send_errors}；队列 {queue_size}（更新于 {updated}）"
    ),
    "cli.hub_forward.last_error": "最近错误：{error}",
    # ---- policy use/list（多 profile） ----
    "cli.policy_use.doc": "切换当前策略 profile（拷贝 profiles/<名>.yaml → current.yaml，运行中 2s 热更新）。",
    "opt.policy_name.help": "profile 名（policies/profiles/ 下的 YAML 文件名，不带扩展名）",
    "opt.policy_reset.help": "清除 current.yaml，回到出厂 policies/default.yaml",
    "cli.policy_use.err_missing": "[red]profile 不存在：{path}[/red]（aaa policy list 查看可用清单）",
    "cli.policy_use.err_invalid": "[red]profile 校验失败：{exc}[/red]",
    "cli.policy_use.done": "[green]当前策略已切换[/green] → {name}（{path}）",
    "cli.policy_use.reset_done": "[green]已清除 current.yaml[/green]：当前策略回到出厂 policies/default.yaml",
    "cli.policy_use.no_current": "current.yaml 不存在（当前已是出厂默认策略）。",
    "cli.policy_list.doc": "列出可用策略 profile 与当前生效策略。",
    "cli.policy_list.title": "策略 profiles（{policies_dir}）",
    "cli.policy_list.col_name": "profile",
    "cli.policy_list.col_status": "状态",
    "cli.policy_list.current": "← 当前生效",
    "cli.policy_list.base_default": "出厂默认（current.yaml 未生效）",
    "cli.policy_list.none": "（policies/profiles/ 下暂无 profile；创建 YAML 后可 aaa policy use <名> 切换）",
    # ---- policy lint 新段行（sampling/hub） ----
    "cli.policy_lint.row_sampling": "sampling",
    "cli.policy_lint.sampling_desc": "enabled={enabled}, head_bytes={head_bytes}",
    "cli.policy_lint.row_hub": "hub",
    "cli.policy_lint.hub_desc": "enabled={enabled}, url={url}",
    # ---- run 接线（W4 采样 / W8 转发 / 批量落盘） ----
    "opt.run_db_batch.help": "事件批量落盘阈值（条；1=逐条即时落盘，默认 20）",
    "cli.run.sampling_on": "扫描采样：开启（head_bytes={head_bytes}，policy.sampling）",
    "cli.run.sampling_off": "扫描采样：关闭（policy.sampling.enabled）",
    "cli.run.hub_on": "hub 转发：开启 → {url}（批量 {batch_size} 条/次；token 经策略/环境变量）",
    "cli.run.hub_off": "hub 转发：关闭（policy.hub.enabled 或 AAA_HUB_URL+AAA_HUB_TOKEN）",
    # ---- 补充：参数帮助与 hub forward 组 ----
    "opt.rules_section.help": "策略段名（domains/content/notifications/sampling/hub 等；非法段名会列出全部可用段）",
    "opt.rules_source.help": "导入 YAML 文件路径，或 -（读 stdin）",
    "opt.gitleaks_source.help": "来源：URL（http/https）或本地 gitleaks TOML 文件路径",
    "cli.hub_forward.group_help": "agent 端事件转发（Forwarder）",
    "cli.hub_forward_status.doc": "查看 agent 端转发配置与最近统计（运行中的 aaa run 写 data/hub-forward.json）。",
    "cli.watchdog.restored": "  - 已还原 {action}",
    "common.deepening_join": "；",
    # ---- 多行 docstring 的补充段（typer help= 拼接；zh 与原 docstring 逐字一致） ----
    "cli.run.detail": "事件落 SQLite（02 文档 D6）。",
    "cli.report.detail": (
        "``--daily``/``--weekly``（06 文档波次二 W6）：渲染自包含 HTML 日报/周报落\n"
        "``data/reports/``，``--email`` 经策略 notifications.email 通道发送。"
    ),
    "cli.notify_test.detail": (
        "webhook/email 的实际送达取决于外部服务，失败会如实以非零退出码报告。"
    ),
    "cli.harden.detail": (
        "on：创建 4 条 ``EgressSentinel-`` 前缀规则（journal-first 记入 setup-state.json，\n"
        "可 ``harden off``/``aaa teardown`` 还原）；off：按记录精确删除（幂等）。\n"
        "需管理员权限。\n\n"
        "已知边界（firewall 模块如实登记）：Windows 筛选平台 Block 优先于 Allow，规则集\n"
        "里的 any-Block 同样命中代理与 svchost 白名单——``on`` 后 443 出站可能全断\n"
        "（含本工具代理自身）。上真机前请先在可还原环境演练（off 即还原），确认连通性。"
    ),
    "cli.fp_build.detail": (
        "同名仓库重复并入会被拒绝（--rebuild 可从零重建）；非 git 工作区需目录内含\n"
        "``.git``（建库仅读工作区文件，不执行任何 git 命令、不触网）。"
    ),
}
