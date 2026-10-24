"""``aaa`` CLI（typer，02 文档 §2 ``aaa.cli``）。

P4 完整化（03 文档 T4.2）：``setup``（交互向导）、``run``、``status``、``tail``、
``report``、``policy lint``、``trim``、``harden``（P6 占位）、``teardown``、``web``。

安全红线：setup/teardown 命令提供 ``--dry-run``；所有系统修改动作执行前打印将要做的
改动；全部改动 journal-first 记入 ``data/setup-state.json``；``--mode local`` 与机器级
操作需管理员，非管理员直接拒绝。
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.live import Live
from rich.table import Table

from aaa import __version__
from aaa.attribution.table import ProcessAttributor, resolve_pinned_process
from aaa.capture.addon import AuditAddon
from aaa.capture.engine import CaptureEngine, ProxyConfig, _validate_mode
from aaa.config import (
    DEFAULT_LISTEN_HOST,
    DEFAULT_LISTEN_PORT,
    DEFAULT_POLICY_FILE,
    DEFAULT_WEB_PORT,
    resolve_confirm_ttl,
    resolve_paths,
    resolve_retention_days,
)
from aaa.engine.pipeline import AuditPipeline
from aaa.policy.loader import PolicyError, PolicyLoader
from aaa.setup import ca as ca_mod
from aaa.setup import envvars as envvars_mod
from aaa.setup import proxy as proxy_mod
from aaa.setup import teardown as teardown_mod
from aaa.setup.admin import is_current_process_elevated
from aaa.setup.state import StateFile
from aaa.setup.wizard import collect_setup_plans, run_setup_wizard
from aaa.store.db import DbEventStore, parse_since
from aaa.store.decisions import DecisionStore
from aaa.store.evidence import EvidenceStore
from aaa.store.jsonl import JsonlEventStore

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help="AI-AGENT-AUDIT：本机 AI Agent 外发流量审计（Windows）",
)
setup_app = typer.Typer(
    no_args_is_help=True, help="系统设置下发（改动全部记录到 setup-state.json）"
)
app.add_typer(setup_app, name="setup")
policy_app = typer.Typer(no_args_is_help=True, help="策略文件管理与校验")
app.add_typer(policy_app, name="policy")

console = Console()
err_console = Console(stderr=True)

DataDirOpt = typer.Option(
    None,
    "--data-dir",
    help="数据目录（默认 <项目>/data；也可用环境变量 AAA_DATA_DIR）",
)
DryRunOpt = typer.Option(False, "--dry-run", help="只显示将执行的动作，不实施任何系统改动")

#: Web 面板只允许本地回环（03 文档 T5.1：仅监听 127.0.0.1）
_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"aaa {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="显示版本号"
    ),
) -> None:
    """AI-AGENT-AUDIT 命令行入口。"""


# --------------------------------------------------------------------------
# run：启动采集代理（03 文档 T1.1；P4：SQLite 落盘 + 启动自动清理 + 决策缓存）
# --------------------------------------------------------------------------


@app.command()
def run(
    mode: str = typer.Option(
        "regular",
        "--mode",
        help=(
            "采集模式：regular（默认，系统代理）| "
            "local[:spec]（需管理员，见 docs/notes/local-mode-spike.md）"
        ),
    ),
    host: str = typer.Option(DEFAULT_LISTEN_HOST, "--host", help="监听地址"),
    port: int = typer.Option(DEFAULT_LISTEN_PORT, "--port", help="监听端口"),
    pid: int | None = typer.Option(
        None, "--pid", help="仅 local 模式：限定目标进程 PID（透传 local:pid=…）"
    ),
    process: str | None = typer.Option(
        None, "--process", help="仅 local 模式：限定目标进程名（透传 local:process=…）"
    ),
    policy: Path | None = typer.Option(  # noqa: B008 - typer 惯用法
        None, "--policy", help="策略 YAML 文件（默认 policies/default.yaml）"
    ),
    data_dir: Path | None = DataDirOpt,
    jsonl: bool = typer.Option(
        False, "--jsonl", help="同时镜像写 JSONL（data/raw/YYYYMMDD.jsonl；默认仅 SQLite）"
    ),
    retention_days: int | None = typer.Option(
        None,
        "--retention-days",
        min=0,
        help="事件保留天数（启动自动清理；默认 14 或 AAA_RETENTION_DAYS）",
    ),
) -> None:
    """启动采集代理（阻塞运行，Ctrl+C 优雅退出）。事件落 SQLite（02 文档 D6）。"""
    is_local = mode == "local" or mode.startswith("local:")
    if (pid is not None or process is not None) and not is_local:
        raise typer.BadParameter("--pid/--process 仅支持 --mode local")
    if pid is not None and process is not None:
        raise typer.BadParameter("--pid 与 --process 互斥，只选其一")
    mode_spec = _local_mode_spec(mode, pid, process)
    try:
        _validate_mode(mode_spec)  # 尽早校验，避免进入事件循环后才失败
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    if is_local and not is_current_process_elevated():
        err_console.print(
            "[red]--mode local 需要管理员权限（WinDivert 透明重定向）。[/red]\n"
            "请以管理员身份运行 PowerShell / 终端后重试：\n"
            "  右键开始菜单 → 终端(管理员) 或 PowerShell(管理员)\n"
            "  然后执行：aaa run --mode local"
        )
        raise typer.Exit(code=2)
    try:
        paths = resolve_paths(data_dir)
        paths.ensure_runtime_dirs()
        policy_loader = _prepare_policy_loader(policy)
        pipeline = AuditPipeline(policy_loader)
        pinned = resolve_pinned_process(pid, process) if is_local else None
        store = DbEventStore(paths.db_file, evidence_dir=paths.evidence_dir)
        if jsonl:
            store.mirror = JsonlEventStore(paths.raw_dir)
        evidence = EvidenceStore(paths.evidence_dir, rel_base=paths.data_dir)
        addon = AuditAddon(
            store,
            evidence,
            mode=mode_spec.split(":", 1)[0],
            attributor=ProcessAttributor(),
            pipeline=pipeline,
            pinned_process=pinned,
            decisions=DecisionStore(paths.decisions_file, default_ttl=resolve_confirm_ttl(None)),
        )
        engine = CaptureEngine(
            ProxyConfig(
                listen_host=host,
                listen_port=port,
                confdir=paths.confdir,
                mode=mode_spec,
                data_dir=paths.data_dir,
            ),
            [addon],
        )
    except (ValueError, PolicyError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(f"[green]aaa {__version__}[/green] mode={mode_spec} 监听 {host}:{port}")
    console.print(
        f"策略：{policy_loader.path}（mode={policy_loader.current.mode} "
        f"version={policy_loader.current.policy_version}，mtime 热更新轮询 2s）"
    )
    if pinned is not None:
        console.print(f"local 目标进程：pid={pinned.pid} name={pinned.name}")
    console.print(
        f"事件库：{paths.db_file}"
        + ("  +JSONL 镜像 data/raw/" if jsonl else "")
        + f"  证据：{paths.evidence_dir}"
    )
    retention = resolve_retention_days(retention_days)
    trimmed = store.trim(retention)
    if trimmed["events"]:
        console.print(
            f"启动自动清理：删除 {trimmed['events']} 条过期事件"
            f"（保留期 {retention} 天，连带证据 {trimmed['evidence']} 个）"
        )
    console.print("按 Ctrl+C 优雅退出。")
    try:
        engine.run_blocking()
    finally:
        store.close()


def _local_mode_spec(mode: str, pid: int | None, process: str | None) -> str:
    """拼装 local 模式规格（透传 mitmproxy ``local:pid=…``/``local:process=…``）。

    非 local 模式原样返回（合法性交回 ``_validate_mode`` 校验）。
    """
    if not (mode == "local" or mode.startswith("local:")):
        return mode
    if mode.startswith("local:"):
        # 用户手写 spec（如 local:pid=1,process=x）原样透传
        if pid is not None or process is not None:
            raise ValueError("--pid/--process 不能与手写 local:spec 同用")
        return mode
    if pid is not None:
        return f"local:pid={pid}"
    if process is not None:
        return f"local:process={process}"
    return "local"


def _prepare_policy_loader(policy: Path | None) -> PolicyLoader:
    """解析策略文件路径并预加载（坏文件在启动期报错，不进引擎）。"""
    path = policy or DEFAULT_POLICY_FILE
    loader = PolicyLoader(path)
    loader.load()  # 校验失败抛 PolicyError → CLI 报错退出
    return loader


# --------------------------------------------------------------------------
# setup：交互式一键引导 + 分步子命令
# --------------------------------------------------------------------------


@setup_app.callback(invoke_without_command=True)
def setup(
    ctx: typer.Context,
    data_dir: Path | None = DataDirOpt,
    dry_run: bool = DryRunOpt,
    yes: bool = typer.Option(False, "--yes", "-y", help="跳过逐步确认（自动化用）"),
    machine_ca: bool = typer.Option(
        False, "--machine-ca", help="CA 安装到 LocalMachine（需管理员；默认 CurrentUser）"
    ),
    proxy_host: str = typer.Option(DEFAULT_LISTEN_HOST, "--proxy-host"),
    proxy_port: int = typer.Option(DEFAULT_LISTEN_PORT, "--proxy-port"),
) -> None:
    """交互式一键引导：CA 根证书 → 系统代理 → 用户环境变量（每步先展示改动再确认）。"""
    if ctx.invoked_subcommand is not None:
        return  # 子命令（ca/proxy/env）走各自实现
    paths = resolve_paths(data_dir)
    plans = collect_setup_plans(
        paths, machine_ca=machine_ca, proxy_host=proxy_host, proxy_port=proxy_port
    )
    confirm: Callable[[str], bool] = (lambda _msg: True) if yes else typer.confirm
    run_setup_wizard(plans, confirm=confirm, echo=console.print, dry_run=dry_run)


@setup_app.command("ca")
def setup_ca(
    store: str = typer.Option(
        "user",
        "--store",
        help="证书存储：user（CurrentUser，无需管理员）| machine（LocalMachine，需管理员）",
    ),
    data_dir: Path | None = DataDirOpt,
    dry_run: bool = DryRunOpt,
) -> None:
    """生成（如缺失）并安装 mitmproxy CA 到证书存储。"""
    if store not in ("user", "machine"):
        raise typer.BadParameter("--store 只支持 user|machine")
    paths = resolve_paths(data_dir)
    info = ca_mod.ensure_ca(paths.confdir)
    console.print(
        f"CA：{info.path}\n序列号：{info.serial}  指纹(SHA1)：{info.thumbprint}\n"
        f"主题：{info.subject_cn}"
    )
    # 执行前打印将要做的改动（工作约定：所有系统修改动作前必打印）
    console.print(f"将执行：安装该 CA 到 {store} 证书存储，并记录到 setup-state.json。")
    if dry_run:
        console.print(f"[yellow](dry-run)[/yellow] 将安装到 {store} 证书存储，未实施。")
        return
    if store == "machine" and not is_current_process_elevated():
        err_console.print(
            "[red]--store machine 需要管理员权限。[/red] "
            "请以管理员身份运行终端后重试，或使用 --store user（CurrentUser，无需管理员）。"
        )
        raise typer.Exit(code=2)
    state = StateFile(paths.setup_state_file)
    # journal-first：先记录（含序列号），再实施；失败保留记录供 teardown
    state.record(
        kind=teardown_mod.KIND_CA_USER if store == "user" else teardown_mod.KIND_CA_MACHINE,
        key=f"{store}:Root:{info.serial}",
        old=None,
        new={"store": store, "serial": info.serial, "path": str(info.path)},
    )
    try:
        ca_mod.install_cert(store, info.path)
    except ca_mod.SetupError as exc:
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    console.print(f"[green]已安装到 {store} 证书存储[/green]（teardown 可按序列号精确删除）。")


@setup_app.command("proxy")
def setup_proxy(
    host: str = typer.Option(DEFAULT_LISTEN_HOST, "--host"),
    port: int = typer.Option(DEFAULT_LISTEN_PORT, "--port"),
    winhttp: bool = typer.Option(False, "--winhttp", help="同时设置 WinHTTP 机器代理（需管理员）"),
    data_dir: Path | None = DataDirOpt,
    dry_run: bool = DryRunOpt,
) -> None:
    """设置 WinINET 用户代理（可选 WinHTTP）。"""
    paths = resolve_paths(data_dir)
    console.print(f"将设置 WinINET 用户代理 {host}:{port}（override=<local>;localhost;127.0.0.1）")
    if winhttp:
        console.print(f"将设置 WinHTTP 机器代理 {host}:{port}（需管理员）")
    if dry_run:
        console.print("[yellow](dry-run)[/yellow] 未实施。")
        return
    state = StateFile(paths.setup_state_file)
    try:
        proxy_mod.apply_user_proxy(state, host, port)
        if winhttp:
            proxy_mod.apply_winhttp_proxy(state, host, port)
    except Exception as exc:  # noqa: BLE001 - CLI 边界统一兜底
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    console.print("[green]代理设置完成[/green]；浏览器建议重启后生效。")


@setup_app.command("env")
def setup_env(
    host: str = typer.Option(DEFAULT_LISTEN_HOST, "--host"),
    port: int = typer.Option(DEFAULT_LISTEN_PORT, "--port"),
    data_dir: Path | None = DataDirOpt,
    dry_run: bool = DryRunOpt,
) -> None:
    """下发用户环境变量（HTTP_PROXY/NODE_*/REQUESTS_CA_BUNDLE 等，02 文档 D1 清单）。"""
    paths = resolve_paths(data_dir)
    ca_info = ca_mod.ensure_ca(paths.confdir)
    merged = paths.data_dir / ca_mod.MERGED_PEM_NAME
    values = envvars_mod.build_env_values(host, port, ca_info.path, merged)
    table = Table(title="将下发的用户环境变量")
    table.add_column("变量")
    table.add_column("值")
    for name in sorted(values):
        table.add_row(name, values[name])
    console.print(table)
    if dry_run:
        console.print("[yellow](dry-run)[/yellow] 未实施。")
        return
    state = StateFile(paths.setup_state_file)
    merged_path = ca_mod.ensure_merged_pem(paths.confdir, merged)
    envvars_mod.record_file_created(state, merged_path)
    try:
        envvars_mod.apply_user_envvars(state, values)
    except envvars_mod.EnvVarSetupError as exc:
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    console.print("[green]环境变量已下发[/green]；新开的终端/应用生效。")


@app.command()
def teardown(
    targets: list[str] | None = typer.Argument(  # noqa: B008 - typer 惯用法
        None, help="限定范围：ca | proxy | env（可多选）；缺省=全部"
    ),
    data_dir: Path | None = DataDirOpt,
    dry_run: bool = DryRunOpt,
) -> None:
    """按 setup-state.json 逆序幂等还原全部（或指定类别的）改动（崩溃后仍完整还原）。"""
    paths = resolve_paths(data_dir)
    try:
        kinds = teardown_mod.teardown_target_kinds(tuple(targets or ()))
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    entries = StateFile(paths.setup_state_file).entries()
    if not entries:
        console.print("状态文件为空：没有需要还原的改动。")
        return
    # 执行前打印将要做的改动（工作约定；也是 T4.3 崩溃还原的可视确认）
    console.print(f"将按状态文件逆序还原 {len(entries)} 项改动：")
    for entry in reversed(entries):
        if kinds is not None and entry.kind not in kinds:
            continue
        console.print(f"  - {entry.kind}:{entry.key}（{entry.ts}）")
    report = teardown_mod.run_teardown(paths.setup_state_file, kinds=kinds, dry_run=dry_run)
    for item in report.restored:
        console.print(f"[green]已还原[/green] {item}")
    for error in report.errors:
        (err_console if not dry_run else console).print(f"[red]{error}[/red]")
    if dry_run:
        console.print("[yellow](dry-run)[/yellow] 未实施。")
    elif report.ok:
        console.print("[green]teardown 完成：全部改动已还原。[/green]")
    else:
        err_console.print("[red]teardown 存在失败项，记录已保留，可重跑 aaa teardown 重试。[/red]")
        raise typer.Exit(code=1)


# --------------------------------------------------------------------------
# status / tail / report / trim（03 文档 T4.2）
# --------------------------------------------------------------------------


def _open_store(paths: Any) -> DbEventStore:
    return DbEventStore(paths.db_file, evidence_dir=paths.evidence_dir)


@app.command()
def status(
    data_dir: Path | None = DataDirOpt,
    policy: Path | None = typer.Option(  # noqa: B008 - typer 惯用法
        None, "--policy", help="策略 YAML 文件（默认 policies/default.yaml）"
    ),
) -> None:
    """当前状态：代理 / CA / 防火墙 / 策略版本 / 最近 5 事件 / 待还原改动。"""
    paths = resolve_paths(data_dir)
    table = Table(title=f"aaa {__version__} 状态（数据目录 {paths.data_dir}）")
    table.add_column("项", style="cyan", no_wrap=True)
    table.add_column("值")

    # —— 代理 ——
    try:
        wininet = proxy_mod.read_wininet()
        enabled = wininet.get("ProxyEnable")
        server = wininet.get("ProxyServer")
        proxy_desc = f"已启用 {server}" if enabled == 1 else f"未启用（server={server!r}）"
    except Exception as exc:  # noqa: BLE001 - 状态命令不因读失败中断
        proxy_desc = f"读取失败：{exc}"
    try:
        winhttp = proxy_mod.read_winhttp()
        winhttp_desc = "直连" if winhttp.get("direct") else f"server={winhttp.get('server')}"
    except Exception as exc:  # noqa: BLE001
        winhttp_desc = f"读取失败：{exc}"
    table.add_row("代理 WinINET（用户）", proxy_desc)
    table.add_row("代理 WinHTTP（机器）", winhttp_desc)

    # —— CA ——
    try:
        pem = paths.confdir / ca_mod.CA_CERT_PEM_NAME
        if pem.exists():
            info = ca_mod.load_ca_info(pem)
            ca_desc = f"{info.subject_cn} serial={info.serial}（{pem}）"
        else:
            ca_desc = "尚未生成（aaa setup ca）"
    except Exception as exc:  # noqa: BLE001
        ca_desc = f"读取失败：{exc}"
    table.add_row("CA（confdir）", ca_desc)

    # —— 防火墙（P6 占位）——
    table.add_row("防火墙加固（harden）", "未实施（P6 占位，见 03 文档 T6.1）")

    # —— 策略 ——
    try:
        doc = PolicyLoader(policy or DEFAULT_POLICY_FILE).load()
        policy_desc = f"mode={doc.mode} version={doc.policy_version}"
    except PolicyError as exc:
        policy_desc = f"策略加载失败：{exc}"
    table.add_row("策略", policy_desc)

    # —— 事件库 ——
    try:
        store = _open_store(paths)
        try:
            stats = store.stats()
            table.add_row(
                "事件库",
                f"{store.count()} 条（confirm 待决策 {stats['pending_confirm']}；"
                f"库 {paths.db_file}）",
            )
        finally:
            store.close()
    except Exception as exc:  # noqa: BLE001
        table.add_row("事件库", f"打开失败：{exc}")

    console.print(table)

    # —— 最近 5 事件 ——
    try:
        store = _open_store(paths)
        try:
            recent = store.latest(5)
        finally:
            store.close()
    except Exception:  # noqa: BLE001
        recent = []
    if recent:
        ev_table = Table(title="最近 5 条事件")
        for col in ("ID", "时间", "判定", "风险", "方法", "路径", "主机", "进程"):
            ev_table.add_column(col)
        for event in recent:
            ev_table.add_row(
                event.id,
                event.ts,
                str(event.verdict),
                str(event.risk_score),
                event.request.method,
                event.request.path,
                event.destination.host,
                _process_label(event),
            )
        console.print(ev_table)
    else:
        console.print("(暂无事件)")

    # —— 待还原改动（R7 崩溃残留提示）——
    entries = StateFile(paths.setup_state_file).entries()
    if entries:
        console.print(
            f"[yellow]注意：状态文件有 {len(entries)} 项未还原改动（崩溃残留或未 teardown），"
            f"运行 aaa teardown 还原。[/yellow]"
        )


def _process_label(event: Any) -> str:
    if event.process is None:
        return "-"
    name = event.process.name or "?"
    pid = event.process.pid if event.process.pid is not None else "?"
    return f"{name}({pid})"


@app.command()
def tail(
    verdict: str | None = typer.Option(None, "--verdict", help="只看指定判定"),
    pid: int | None = typer.Option(None, "--pid"),
    host: str | None = typer.Option(None, "--host"),
    interval: float = typer.Option(1.0, "--interval", min=0.1, help="轮询间隔秒"),
    from_start: bool = typer.Option(False, "--from-start", help="从最早事件开始（默认只看新事件）"),
    once: bool = typer.Option(False, "--once", help="只轮询一次后退出（测试/脚本用）"),
    data_dir: Path | None = DataDirOpt,
) -> None:
    """实时滚动显示新事件（rich Live；Ctrl+C 退出）。"""
    paths = resolve_paths(data_dir)
    store = _open_store(paths)
    cursor = 0 if from_start else store.max_rowid()
    console.print(
        f"tail：监听新事件（verdict={verdict or '全部'} pid={pid or '全部'} "
        f"host={host or '全部'}），Ctrl+C 退出。"
    )
    rows: list[list[str]] = []

    def _render() -> Table:
        table = Table(title="事件流（新→旧）")
        for col in ("时间", "判定", "风险", "方法", "路径", "主机", "进程"):
            table.add_column(col)
        for row in rows[-30:]:
            table.add_row(*row)
        return table

    try:
        with Live(_render(), console=console, refresh_per_second=4) as live:
            while True:
                events, cursor = store.poll_after(cursor, verdict=verdict, pid=pid, host=host)
                for event in events:
                    rows.append(
                        [
                            event.ts,
                            str(event.verdict),
                            str(event.risk_score),
                            event.request.method,
                            event.request.path,
                            event.destination.host,
                            _process_label(event),
                        ]
                    )
                    console.print(
                        f"[green]+[/green] {event.id} {event.ts} {event.verdict} "
                        f"{event.request.method} {event.destination.host}{event.request.path}"
                    )
                if once:
                    break
                live.update(_render())
                time.sleep(interval)
    except KeyboardInterrupt:
        console.print("tail 已退出。")
    finally:
        store.close()


@app.command()
def report(
    since: str | None = typer.Option(None, "--since", help="起始：24h/30m/7d 或 ISO 时间"),
    until: str | None = typer.Option(None, "--until", help="截止：ISO 时间"),
    json_out: bool = typer.Option(False, "--json", help="以 JSON 输出"),
    csv_out: bool = typer.Option(False, "--csv", help="以 CSV 输出"),
    verify_evidence: bool = typer.Option(
        False, "--verify-evidence", help="复核全部证据文件 sha256（大库较慢）"
    ),
    data_dir: Path | None = DataDirOpt,
) -> None:
    """聚合报告：按判定/进程/主机/规则统计（03 文档 T4.2）。"""
    if json_out and csv_out:
        raise typer.BadParameter("--json 与 --csv 只能二选一")
    try:
        since_dt = parse_since(since)
        until_dt = parse_since(until)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    paths = resolve_paths(data_dir)
    store = _open_store(paths)
    try:
        stats = store.stats(since=since_dt, until=until_dt)
        integrity = store.verify_evidence() if verify_evidence else None
    finally:
        store.close()
    window = {"since": since, "until": until}
    if json_out:
        payload: dict[str, Any] = {"window": window, **stats}
        if integrity is not None:
            payload["evidence_integrity"] = integrity
        console.print_json(json.dumps(payload, ensure_ascii=False))
        return
    if csv_out:
        lines = ["section,key,extra,count"]
        for verdict_value, count in stats["by_verdict"].items():
            lines.append(f"verdict,{verdict_value},,{count}")
        for row in stats["by_process"]:
            lines.append(f"process,{row['pid'] or '-'},{row['process_name']},{row['n']}")
        for row in stats["by_host"]:
            lines.append(f"host,{row['host']},,{row['n']}")
        for row in stats["by_rule"]:
            lines.append(f"rule,{row['rule_id']},{row['dim']},{row['n']}")
        for row in stats["by_day"]:
            lines.append(f"day,{row['day']},,{row['n']}")
        console.print("\n".join(lines))
        return
    table = Table(title=f"报告（{since or '全部'} ~ {until or '现在'}，共 {stats['total']} 条）")
    table.add_column("维度", style="cyan")
    table.add_column("项")
    table.add_column("数量", justify="right")
    for verdict_value, count in stats["by_verdict"].items():
        table.add_row("判定", verdict_value, str(count))
    for row in stats["by_process"]:
        table.add_row("进程", f"{row['pid'] or '-'} {row['process_name']}", str(row["n"]))
    for row in stats["by_host"]:
        table.add_row("主机", str(row["host"]), str(row["n"]))
    for row in stats["by_rule"]:
        table.add_row("规则", f"{row['rule_id']}（{row['dim']}）", str(row["n"]))
    console.print(table)
    if integrity is not None:
        console.print(
            f"证据复核：检查 {integrity['checked']} 个，缺失 {len(integrity['missing'])}，"
            f"损坏 {len(integrity['corrupted'])}"
        )


@app.command()
def trim(
    days: int = typer.Option(..., "--days", min=0, help="保留最近 N 天，删除更早的事件与证据"),
    data_dir: Path | None = DataDirOpt,
) -> None:
    """清理过期事件与证据文件（02 文档 D6 保留期；``run`` 启动时也会自动执行）。"""
    paths = resolve_paths(data_dir)
    store = _open_store(paths)
    try:
        result = store.trim(days)
    finally:
        store.close()
    console.print(
        f"[green]trim 完成[/green]：删除 {result['events']} 条事件、{result['evidence']} 个证据文件"
        f"（保留期 {days} 天）。"
    )


@app.command()
def harden(
    action: str = typer.Argument(..., help="on | off"),
) -> None:
    """防火墙加固开关（P6 占位，03 文档 T6.1：v1 未实施）。"""
    if action not in ("on", "off"):
        raise typer.BadParameter("harden 只支持 on | off")
    console.print(
        "[yellow]harden 尚未实施（P6，03 文档 T6.1）。[/yellow]\n"
        "规划能力：放行本工具 443/TCP、拒绝其他进程 443/TCP、拒绝 UDP 443，"
        "规则进状态文件可还原。本次未对系统做任何改动。"
    )
    raise typer.Exit(code=1)


# --------------------------------------------------------------------------
# web：本地面板（03 文档 T5.x）
# --------------------------------------------------------------------------


@app.command()
def web(
    host: str = typer.Option("127.0.0.1", "--host", help="监听地址（仅允许本地回环）"),
    port: int = typer.Option(DEFAULT_WEB_PORT, "--port"),
    data_dir: Path | None = DataDirOpt,
    policy: Path | None = typer.Option(  # noqa: B008 - typer 惯用法
        None, "--policy", help="策略 YAML 文件（默认 policies/default.yaml）"
    ),
) -> None:
    """启动本地 Web 面板（只读 + confirm 决策；仅监听 127.0.0.1）。"""
    if host not in _LOOPBACK_HOSTS:
        raise typer.BadParameter(
            f"Web 面板只允许本地回环监听（{', '.join(_LOOPBACK_HOSTS)}），收到 {host!r}"
        )
    try:
        from aaa.web.app import create_app  # 延迟导入：web 为可选依赖
    except ImportError as exc:
        err_console.print(
            f"[red]Web 面板依赖缺失：{exc}[/red]\n"
            "请安装 web 扩展：pip install -e .[web]（fastapi + uvicorn）"
        )
        raise typer.Exit(code=1) from exc
    paths = resolve_paths(data_dir)
    paths.ensure_runtime_dirs()
    store = _open_store(paths)
    loader = PolicyLoader(policy or DEFAULT_POLICY_FILE)
    try:
        loader.load()
    except PolicyError as exc:
        err_console.print(f"[yellow]策略加载失败（面板仍可查看事件）：{exc}[/yellow]")
    panel = create_app(
        db=store,
        evidence_dir=paths.evidence_dir,
        policy_loader=loader,
        decisions=DecisionStore(paths.decisions_file, default_ttl=resolve_confirm_ttl(None)),
        data_dir=paths.data_dir,
    )
    console.print(f"[green]Web 面板[/green] http://{host}:{port}（仅本地访问；Ctrl+C 退出）")
    try:
        import uvicorn

        uvicorn.run(panel, host=host, port=port, log_level="warning")
    finally:
        store.close()


# --------------------------------------------------------------------------
# policy lint
# --------------------------------------------------------------------------


@policy_app.command("lint")
def policy_lint(
    file: Path | None = typer.Argument(  # noqa: B008 - typer 惯用法
        None, help="策略 YAML 文件（默认 policies/default.yaml）"
    ),
) -> None:
    """校验策略文件（pydantic 严格 schema，03 文档 T3.1）：合法打印摘要，非法以 1 退出。"""
    path = file or DEFAULT_POLICY_FILE
    loader = PolicyLoader(path)
    try:
        doc = loader.load()
    except PolicyError as exc:
        err_console.print(f"[red]策略校验失败：{path}[/red]\n{exc}")
        raise typer.Exit(code=1) from exc
    table = Table(title=f"策略合法：{path}")
    table.add_column("项")
    table.add_column("值")
    table.add_row("version", str(doc.version))
    table.add_row("mode", doc.mode)
    table.add_row("policy_version", doc.policy_version)
    table.add_row("fail_open", str(doc.defaults.fail_open))
    table.add_row("max_body_scan", str(doc.defaults.max_body_scan))
    table.add_row("domain classes", ", ".join(sorted(doc.domains.classes)) or "-")
    table.add_row("domain rules", str(len(doc.domains.rules)))
    table.add_row("process profiles", ", ".join(sorted(doc.processes.profiles)) or "-")
    table.add_row("process rules", str(len(doc.processes.rules)))
    table.add_row("scanners", ", ".join(doc.content.scanners) or "-")
    table.add_row("content rules", str(len(doc.content.rules)))
    table.add_row("volume rules", str(len(doc.volume)))
    table.add_row("time_window rules", str(len(doc.time_window)))
    console.print(table)


def main() -> None:
    """``[project.scripts]`` 入口。"""
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
