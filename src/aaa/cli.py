"""``aaa`` CLI（typer，02 文档 §2 ``aaa.cli``）。

P4 完整化（03 文档 T4.2）：``setup``（交互向导）、``run``、``status``、``tail``、
``report``、``policy lint``、``trim``、``harden``、``teardown``、``web``。
v0.2.0 安全深化（05 文档波次二）：``fingerprint build`` 建库、``harden on|off``
防火墙加固（替换 P6 占位）、``run`` 启动概要含 judge/fingerprint/加密状态。
v0.3.0 体验与生态（06 文档波次二）：``service install|uninstall|status``（W1）、
``tray``（W2）、``report --daily|--weekly [--email]``（W6）、``rules export|import``
与 ``gitleaks sync``（W7）、``hub serve`` / ``hub forward status``（W8）、
``policy use|list``（多 profile）、全部文案 i18n（``--lang``/``AAA_LANG``，默认 zh
输出不变）；``run`` 接批量落盘/扫描采样/hub 转发。

安全红线：setup/teardown 命令提供 ``--dry-run``；所有系统修改动作执行前打印将要做的
改动；全部改动 journal-first 记入 ``data/setup-state.json``；``--mode local``、服务
安装与机器级操作（harden）需管理员，非管理员直接拒绝。
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from collections.abc import Callable
from datetime import date
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.live import Live
from rich.table import Table

from aaa import __version__
from aaa import config as config_mod
from aaa.attribution.table import ProcessAttributor, resolve_pinned_process
from aaa.capture.addon import AuditAddon
from aaa.capture.engine import (
    CaptureEngine,
    ProxyConfig,
    _validate_mode,
    install_shutdown_handlers,
)
from aaa.config import (
    CURRENT_POLICY_FILE_NAME,
    DEFAULT_LISTEN_HOST,
    DEFAULT_LISTEN_PORT,
    DEFAULT_WEB_PORT,
    PROFILES_DIR_NAME,
    resolve_confirm_ttl,
    resolve_paths,
    resolve_retention_days,
)
from aaa.engine.pipeline import AuditPipeline
from aaa.fingerprint import FINGERPRINTS_FILE_NAME, FingerprintIndex
from aaa.hub.forwarder import Forwarder
from aaa.hub.model import (
    HUB_TOKEN_ENV,
    HubConfig,
)
from aaa.hub.model import (
    apply_env_overrides as apply_hub_env_overrides,
)
from aaa.i18n import t
from aaa.judge import DEFAULT_JUDGE_USAGE_FILENAME, JudgeUsageStore, LLMJudge
from aaa.notify.channels import CHANNEL_NAMES, build_channels
from aaa.notify.dispatcher import Dispatcher, build_dispatcher, notify_config_from_policy
from aaa.notify.model import apply_env_overrides
from aaa.policy.loader import PolicyError, PolicyLoader
from aaa.policy.model import PolicyDocument
from aaa.reporting import daily as reporting_daily
from aaa.ruleshub.gitleaks import sync_gitleaks
from aaa.ruleshub.sections import (
    RulesHubError,
    atomic_write_text,
    export_section,
    import_section,
)
from aaa.setup import autostart as autostart_mod
from aaa.setup import ca as ca_mod
from aaa.setup import envvars as envvars_mod
from aaa.setup import firewall as firewall_mod
from aaa.setup import proxy as proxy_mod
from aaa.setup import service as service_mod
from aaa.setup import teardown as teardown_mod
from aaa.setup import watchdog as watchdog_mod
from aaa.setup.admin import is_current_process_elevated
from aaa.setup.firewall import FirewallError
from aaa.setup.state import StateFile
from aaa.setup.wizard import collect_setup_plans, run_setup_wizard
from aaa.store.crypto import CryptoEngine
from aaa.store.db import DbEventStore, parse_since
from aaa.store.decisions import DecisionStore
from aaa.store.events import AuditEvent, Destination, RequestInfo, new_event_id
from aaa.store.evidence import EvidenceStore
from aaa.store.jsonl import JsonlEventStore


def _prescan_lang(argv: list[str]) -> None:
    """启动期预扫描 ``--lang``（06 文档波次二：帮助文本双语）。

    命令注册（装饰器求值 ``t()``）发生在本模块导入期，早于任何参数解析——
    因此在**导入期**先扫一遍真实 ``sys.argv`` 把语言设好，``aaa --lang en --help``
    才能渲染出英文帮助。只在**子命令之前的选项区**匹配（根选项语义：
    ``aaa --lang en <命令>``）；``AAA_LANG`` 环境变量由 i18n 自行读取，无需处理。
    pytest 等把本模块当库导入的场景中 argv 不含 ``--lang``，此函数为零副作用。
    """
    for index, arg in enumerate(argv):
        if arg == "--lang":
            if index + 1 < len(argv):
                i18n_set_lang(argv[index + 1])
            return
        if arg.startswith("--lang="):
            i18n_set_lang(arg.split("=", 1)[1])
            return
        if not arg.startswith("-"):
            return  # 已进入子命令：--lang 只能出现在其之前


def i18n_set_lang(value: str) -> None:
    """设定运行时语言（prescan 与 ``--lang`` 选项回调共用；未知值回落 zh）。"""
    from aaa import i18n

    i18n.set_lang(value)


_prescan_lang(sys.argv[1:])

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help=t("cli.app.help"),
)
setup_app = typer.Typer(
    no_args_is_help=True, help=t("cli.setup.group_help")
)
app.add_typer(setup_app, name="setup")
policy_app = typer.Typer(no_args_is_help=True, help=t("cli.policy.group_help"))
app.add_typer(policy_app, name="policy")
autostart_app = typer.Typer(
    no_args_is_help=True, help=t("cli.autostart.group_help")
)
app.add_typer(autostart_app, name="autostart")
notify_app = typer.Typer(no_args_is_help=True, help=t("cli.notify.group_help"))
app.add_typer(notify_app, name="notify")
fingerprint_app = typer.Typer(
    no_args_is_help=True, help=t("cli.fingerprint.group_help")
)
app.add_typer(fingerprint_app, name="fingerprint")
service_app = typer.Typer(no_args_is_help=True, help=t("cli.service.group_help"))
app.add_typer(service_app, name="service")
rules_app = typer.Typer(no_args_is_help=True, help=t("cli.rules.group_help"))
app.add_typer(rules_app, name="rules")
gitleaks_app = typer.Typer(no_args_is_help=True, help=t("cli.gitleaks.group_help"))
app.add_typer(gitleaks_app, name="gitleaks")
hub_app = typer.Typer(no_args_is_help=True, help=t("cli.hub.group_help"))
app.add_typer(hub_app, name="hub")
hub_forward_app = typer.Typer(no_args_is_help=True, help=t("cli.hub_forward.group_help"))
hub_app.add_typer(hub_forward_app, name="forward")

console = Console()
err_console = Console(stderr=True)
logger = logging.getLogger(__name__)

DataDirOpt = typer.Option(
    None,
    "--data-dir",
    help=t("opt.data_dir.help"),
)
DryRunOpt = typer.Option(False, "--dry-run", help=t("opt.dry_run.help"))

#: Web 面板只允许本地回环（03 文档 T5.1：仅监听 127.0.0.1）
_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")

#: hub 中心默认端口（hub.collector.DEFAULT_HUB_PORT；直接引值避免顶层导入 fastapi）
_HUB_DEFAULT_PORT = 8788

#: 运行时统计快照文件名（``aaa hub forward status`` 读取；run 进程写入）
HUB_FORWARD_STATS_FILENAME = "hub-forward.json"


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"aaa {__version__}")
        raise typer.Exit()


def _lang_callback(value: str | None) -> None:
    """``--lang`` 选项回调（eager）：运行时输出语言（帮助文本在导入期已渲染）。"""
    if value is not None:
        i18n_set_lang(value)


@app.callback(help=t("cli.root.doc"))
def _root(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help=t("opt.version.help")
    ),
    lang: str | None = typer.Option(
        None, "--lang", callback=_lang_callback, is_eager=True, help=t("opt.lang.help")
    ),
) -> None:
    """AI-AGENT-AUDIT 命令行入口。"""


# --------------------------------------------------------------------------
# run：启动采集代理（03 文档 T1.1；P4：SQLite 落盘 + 启动自动清理 + 决策缓存）
# --------------------------------------------------------------------------


@app.command(help=t("cli.run.doc") + "\n\n" + t("cli.run.detail"))
def run(
    mode: str = typer.Option(
        "regular",
        "--mode",
        help=t("opt.run_mode.help"),
    ),
    host: str = typer.Option(DEFAULT_LISTEN_HOST, "--host", help=t("opt.host.help")),
    port: int = typer.Option(DEFAULT_LISTEN_PORT, "--port", help=t("opt.port.help")),
    pid: int | None = typer.Option(
        None, "--pid", help=t("opt.run_pid.help")
    ),
    process: str | None = typer.Option(
        None, "--process", help=t("opt.run_process.help")
    ),
    policy: Path | None = typer.Option(  # noqa: B008 - typer 惯用法
        None, "--policy", help=t("opt.policy.help")
    ),
    data_dir: Path | None = DataDirOpt,
    jsonl: bool = typer.Option(
        False, "--jsonl", help=t("opt.run_jsonl.help")
    ),
    retention_days: int | None = typer.Option(
        None,
        "--retention-days",
        min=0,
        help=t("opt.retention_days.help"),
    ),
    log_file: Path | None = typer.Option(  # noqa: B008 - typer 惯用法
        None,
        "--log-file",
        help=t("opt.run_log_file.help"),
    ),
    db_batch: int = typer.Option(
        20,
        "--db-batch",
        min=1,
        max=500,
        help=t("opt.run_db_batch.help"),
    ),
) -> None:
    """启动采集代理（阻塞运行；Ctrl+C 优雅退出；关机/注销自动限时收尾）。

    事件落 SQLite（02 文档 D6）。
    """
    is_local = mode == "local" or mode.startswith("local:")
    if (pid is not None or process is not None) and not is_local:
        raise typer.BadParameter(t("cli.run.err_pid_not_local"))
    if pid is not None and process is not None:
        raise typer.BadParameter(t("cli.run.err_pid_mutex"))
    mode_spec = _local_mode_spec(mode, pid, process)
    try:
        _validate_mode(mode_spec)  # 尽早校验，避免进入事件循环后才失败
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    if is_local and not is_current_process_elevated():
        err_console.print(t("cli.run.err_local_admin"))
        raise typer.Exit(code=2)
    try:
        paths = resolve_paths(data_dir)
        paths.ensure_runtime_dirs()
        policy_loader = _prepare_policy_loader(policy)
        doc = policy_loader.current
        fingerprint_index = _load_fingerprint_index(paths.data_dir, doc)
        # W4 采样接线（06 文档波次二）：策略 sampling 段 → 管线构造器；
        # 采样配置启动时生效（热更新不切换，与加密/判定同一口径，D-46）。
        pipeline = AuditPipeline(
            policy_loader,
            fingerprint_index=fingerprint_index,
            sampling=doc.sampling.model_dump(),
        )
        pinned = resolve_pinned_process(pid, process) if is_local else None
        store = DbEventStore(paths.db_file, evidence_dir=paths.evidence_dir)
        if jsonl:
            store.mirror = JsonlEventStore(paths.raw_dir)
        # 证据加密（05 文档 W5/波次二）：开关启动时生效；引擎始终注入——关闭时写明文，
        # 读取仍透明兼容开启期间落盘的密文（decisions.md D-2026-10-24-35/39）
        crypto_engine = CryptoEngine(paths.data_dir, enabled=doc.encrypt.enabled)
        evidence = EvidenceStore(paths.evidence_dir, rel_base=paths.data_dir, crypto=crypto_engine)
        dispatcher = build_dispatcher(policy_loader)
        # W8 hub 转发接线（06 文档波次二）：policy.hub 段 + AAA_HUB_* 环境变量；
        # 默认关（零外发）；统计快照落 data/hub-forward.json 供 hub forward status 读。
        hub_cfg = apply_hub_env_overrides(doc.hub)
        forwarder = _build_hub_forwarder(
            hub_cfg, stats_path=paths.data_dir / HUB_FORWARD_STATS_FILENAME
        )
        addon = AuditAddon(
            store,
            evidence,
            mode=mode_spec.split(":", 1)[0],
            attributor=ProcessAttributor(),
            pipeline=pipeline,
            pinned_process=pinned,
            decisions=DecisionStore(paths.decisions_file, default_ttl=resolve_confirm_ttl(None)),
            dispatcher=dispatcher,
            judge=_build_judge(doc, paths.data_dir),
            forwarder=forwarder,
            batch_size=db_batch,
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
    console.print(t("cli.run.banner", version=__version__, mode=mode_spec, host=host, port=port))
    console.print(
        t(
            "cli.run.policy_line",
            path=policy_loader.path,
            mode=policy_loader.current.mode,
            version=policy_loader.current.policy_version,
        )
    )
    if pinned is not None:
        console.print(t("cli.run.pinned_line", pid=pinned.pid, name=pinned.name))
    console.print(
        t("cli.run.store_line", db_file=paths.db_file)
        + (t("cli.run.jsonl_mirror") if jsonl else "")
        + t("cli.run.evidence_dir", evidence_dir=paths.evidence_dir)
    )
    retention = resolve_retention_days(retention_days)
    trimmed = store.trim(retention)
    if trimmed["events"]:
        console.print(
            t(
                "cli.run.trim_line",
                events=trimmed["events"],
                days=retention,
                evidence=trimmed["evidence"],
            )
        )
    console.print(_notify_summary_line(policy_loader, dispatcher))
    # v0.2.0 安全深化概要（05 文档波次二 §5）：judge / fingerprint / 加密状态
    for line in _deepening_summary_lines(doc, fingerprint_index, crypto_engine, paths.data_dir):
        console.print(line)
    # v0.3.0 接线概要（06 文档波次二）：采样 / hub 转发
    if doc.sampling.enabled:
        console.print(t("cli.run.sampling_on", head_bytes=doc.sampling.head_bytes))
    else:
        console.print(t("cli.run.sampling_off"))
    if forwarder is not None:
        console.print(t("cli.run.hub_on", url=hub_cfg.url, batch_size=hub_cfg.batch_size))
    else:
        console.print(t("cli.run.hub_off"))
    console.print(t("cli.run.hint_exit"))
    if log_file is not None:
        _append_log(
            log_file,
            t(
                "cli.run.log_start",
                version=__version__,
                mode=mode_spec,
                host=host,
                port=port,
                path=policy_loader.path,
                policy_mode=policy_loader.current.mode,
            ),
        )
    stop_cb = getattr(engine, "stop", None)
    if callable(stop_cb):
        install_shutdown_handlers(stop_cb)
    try:
        engine.run_blocking()
    finally:
        # 04 文档 §5：退出时 flush 通知（在 engine 停止后、store.close 前，有界 2s）
        dispatcher.flush(2.0)
        if forwarder is not None:
            try:
                forwarder.flush(2.0)
            finally:
                forwarder.dump_stats()
        store.close()
        if log_file is not None:
            _append_log(log_file, t("cli.run.log_stop"))


class _StatsDumpingForwarder(Forwarder):
    """带统计快照的 Forwarder（run 进程内装配）：每次发送结果后写
    ``data/hub-forward.json``（tmp+replace），供 ``aaa hub forward status``
    跨进程读取。写失败只记 debug 日志——统计是观测通道，绝不影响转发。"""

    def __init__(self, *args: Any, stats_path: Path, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._stats_path = stats_path

    def _send_batch(self, events: list[AuditEvent]) -> None:
        try:
            super()._send_batch(events)
        finally:
            self.dump_stats()

    def dump_stats(self) -> None:
        """把当前统计快照原子落盘（退出路径/每批发送后调用；失败静默）。"""
        try:
            self._stats_path.parent.mkdir(parents=True, exist_ok=True)
            payload = json.dumps(
                {"updated": _now_iso_ms(), "stats": self.stats()}, ensure_ascii=False
            )
            tmp = self._stats_path.with_name(self._stats_path.name + ".tmp")
            tmp.write_text(payload, encoding="utf-8")
            tmp.replace(self._stats_path)
        except OSError:
            logger.debug("hub 统计快照写入失败（忽略）：%s", self._stats_path, exc_info=True)


def _build_hub_forwarder(config: HubConfig, *, stats_path: Path) -> Forwarder | None:
    """按（已应用环境变量覆盖的）配置构造带统计快照的 Forwarder。

    与 ``hub.forwarder.build_forwarder`` 同一守卫（默认关；url/token 不全告警不转发）；
    换用子类以获得统计快照落盘能力（``hub forward status`` 的数据来源）。
    """
    if not config.enabled:
        return None
    if not config.url or not config.token:
        logger.warning("hub 已启用但 url/token 不完整（可设 AAA_HUB_URL/AAA_HUB_TOKEN），不转发")
        return None
    return _StatsDumpingForwarder(
        config.url,
        config.token,
        batch_size=config.batch_size,
        timeout=config.timeout,
        stats_path=stats_path,
    )


def _notify_summary_line(policy_loader: PolicyLoader, dispatcher: Dispatcher) -> str:
    """启动概要的通知行（04 文档 §5：启动打印通知通道概要）。"""
    config = notify_config_from_policy(policy_loader)
    channels = config.enabled_channel_names()
    enabled = ", ".join(channels) if channels else t("common.notify_none")
    extra = ""
    if config.webhook.enabled and config.webhook.url:
        extra = t("cli.run.notify_provider", provider=config.webhook.provider)
    return t(
        "cli.run.notify_line",
        enabled=enabled,
        extra=extra,
        min_action=config.min_action,
        max_per_minute=config.rate_limit.max_per_minute,
    )


# --------------------------------------------------------------------------
# v0.2.0 安全深化：指纹库装配 / judge 装配 / 启动概要（05 文档波次二 §5）
# --------------------------------------------------------------------------


def _load_fingerprint_index(data_dir: Path, doc: PolicyDocument) -> FingerprintIndex | None:
    """策略启用指纹时加载指纹库；缺失/损坏时给出可操作的指引（不自动重建）。

    - 自动重建需要遍历用户仓库（大仓可达分钟级），静默做会拖慢 ``aaa run`` 启动
      且可能读到过期内容——如实交给显式的 ``aaa fingerprint build``（05 文档 §5）；
    - 未启用时返回 None（管线不注册 repo_fingerprint 扫描器）。
    """
    if not doc.fingerprint.enabled:
        return None
    store_path = data_dir / FINGERPRINTS_FILE_NAME
    index = FingerprintIndex.load(store_path)
    if index is None:
        logger.warning("指纹库缺失或损坏：%s（aaa fingerprint build 构建后重启生效）", store_path)
    return index


def _build_judge(doc: PolicyDocument, data_dir: Path) -> LLMJudge | None:
    """策略启用 judge 时构造判定器（预算文件随 --data-dir 落位）；未启用返回 None。"""
    if not doc.judge.enabled:
        return None
    return LLMJudge(doc.judge, usage_path=data_dir / DEFAULT_JUDGE_USAGE_FILENAME)


def _deepening_summary_lines(
    doc: PolicyDocument,
    fingerprint_index: FingerprintIndex | None,
    crypto_engine: CryptoEngine,
    data_dir: Path,
) -> list[str]:
    """启动概要的三行安全深化状态（judge / 指纹 / 加密；05 文档波次二 §5）。"""
    lines: list[str] = []
    if doc.fingerprint.enabled:
        if fingerprint_index is None:
            lines.append(t("cli.run.fp_missing"))
        else:
            lines.append(
                t(
                    "cli.run.fp_on",
                    repos=len(fingerprint_index.repos),
                    slices=fingerprint_index.total_slices,
                    file_name=FINGERPRINTS_FILE_NAME,
                )
            )
    else:
        lines.append(t("cli.run.fp_off"))
    if doc.judge.enabled:
        used = JudgeUsageStore(data_dir / DEFAULT_JUDGE_USAGE_FILENAME).today_count()
        lines.append(
            t(
                "cli.run.judge_on",
                model=doc.judge.model or "-",
                used=used,
                max_per_day=doc.judge.max_events_per_day,
            )
        )
    else:
        lines.append(t("cli.run.judge_off"))
    if crypto_engine.enabled:
        describe = crypto_engine.describe()
        lines.append(
            t("cli.run.crypto_on", algorithm=describe["algorithm"], keyfile=describe["keyfile"])
        )
    else:
        lines.append(t("cli.run.crypto_off"))
    return lines


def _append_log(log_file: Path, message: str) -> None:
    """追加一行带时间戳的运行日志（无控制台场景的排障通道，失败静默）。"""
    from datetime import datetime

    try:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().astimezone().isoformat(timespec="seconds")
        with log_file.open("a", encoding="utf-8") as fh:
            fh.write(f"{ts}\t{message}\n")
    except OSError:  # noqa: BLE001 - 日志失败不影响主流程
        pass


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
    """解析策略文件路径并预加载（坏文件在启动期报错，不进引擎）。

    缺省路径为当前生效策略：``policies/current.yaml``（``aaa policy use`` 产物）
    优先，否则出厂 ``policies/default.yaml``（06 文档波次二多 profile）。
    """
    path = policy or config_mod.default_policy_file()
    loader = PolicyLoader(path)
    loader.load()  # 校验失败抛 PolicyError → CLI 报错退出
    return loader


# --------------------------------------------------------------------------
# setup：交互式一键引导 + 分步子命令
# --------------------------------------------------------------------------


@setup_app.callback(invoke_without_command=True, help=t("cli.setup.doc"))
def setup(
    ctx: typer.Context,
    data_dir: Path | None = DataDirOpt,
    dry_run: bool = DryRunOpt,
    yes: bool = typer.Option(False, "--yes", "-y", help=t("opt.setup_yes.help")),
    machine_ca: bool = typer.Option(
        False, "--machine-ca", help=t("opt.machine_ca.help")
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
    if not dry_run and StateFile(paths.setup_state_file).entries():
        # 用户需求：setup 默认附带开机自启（可拒绝；改动同样 journal-first）。
        # 全部步骤都被拒绝时不追问（保持「零改动」语义）。
        task_name = autostart_mod.AUTOSTART_TASK_NAME
        if confirm(t("cli.setup.ask_autostart", task_name=task_name)):
            state = StateFile(paths.setup_state_file)
            try:
                entries = autostart_mod.enable_autostart(state, paths.data_dir)
            except autostart_mod.AutostartError as exc:
                hint = t("cli.setup.hint_autostart_retry")
                err_console.print(t("cli.setup.err_autostart", exc=exc, hint=hint))
            else:
                for entry in entries:
                    console.print(t("common.task_created", item_key=entry.key))
        # 安装即守护：全部监控默认开启，setup 末步默认立即后台启动审计代理
        if confirm(t("cli.setup.ask_spawn")):
            try:
                proc = autostart_mod.spawn_run_now(paths.data_dir)
            except OSError as exc:
                hint = "aaa run"
                err_console.print(t("cli.setup.err_spawn", exc=exc, hint=hint))
            else:
                console.print(t("cli.setup.spawned", pid=proc.pid))


@setup_app.command("ca", help=t("cli.setup_ca.doc"))
def setup_ca(
    store: str = typer.Option(
        "user",
        "--store",
        help=t("opt.ca_store.help"),
    ),
    data_dir: Path | None = DataDirOpt,
    dry_run: bool = DryRunOpt,
) -> None:
    """生成（如缺失）并安装 mitmproxy CA 到证书存储。"""
    if store not in ("user", "machine"):
        raise typer.BadParameter(t("cli.setup_ca.err_store"))
    paths = resolve_paths(data_dir)
    info = ca_mod.ensure_ca(paths.confdir)
    console.print(
        t(
            "cli.setup_ca.ca_info",
            path=info.path,
            serial=info.serial,
            thumbprint=info.thumbprint,
            subject_cn=info.subject_cn,
        )
    )
    # 执行前打印将要做的改动（工作约定：所有系统修改动作前必打印）
    console.print(t("cli.setup_ca.will_do", store=store))
    if dry_run:
        console.print(t("cli.setup_ca.dry_run", store=store))
        return
    if store == "machine" and not is_current_process_elevated():
        err_console.print(t("cli.setup_ca.err_machine_admin"))
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
        err_console.print(t("common.err_plain", exc=exc))
        raise typer.Exit(code=1) from exc
    console.print(t("cli.setup_ca.installed", store=store))


@setup_app.command("proxy", help=t("cli.setup_proxy.doc"))
def setup_proxy(
    host: str = typer.Option(DEFAULT_LISTEN_HOST, "--host"),
    port: int = typer.Option(DEFAULT_LISTEN_PORT, "--port"),
    winhttp: bool = typer.Option(False, "--winhttp", help=t("opt.winhttp.help")),
    data_dir: Path | None = DataDirOpt,
    dry_run: bool = DryRunOpt,
) -> None:
    """设置 WinINET 用户代理（可选 WinHTTP）。"""
    paths = resolve_paths(data_dir)
    console.print(t("cli.setup_proxy.will_do", host=host, port=port))
    if winhttp:
        console.print(t("cli.setup_proxy.will_do_winhttp", host=host, port=port))
    if dry_run:
        console.print(t("common.dry_run_noop"))
        return
    state = StateFile(paths.setup_state_file)
    try:
        proxy_mod.apply_user_proxy(state, host, port)
        if winhttp:
            proxy_mod.apply_winhttp_proxy(state, host, port)
    except Exception as exc:  # noqa: BLE001 - CLI 边界统一兜底
        err_console.print(t("common.err_plain", exc=exc))
        raise typer.Exit(code=1) from exc
    console.print(t("cli.setup_proxy.done"))


@setup_app.command("env", help=t("cli.setup_env.doc"))
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
    table = Table(title=t("cli.setup_env.table_title"))
    table.add_column(t("cli.setup_env.col_name"))
    table.add_column(t("cli.col_value"))
    for name in sorted(values):
        table.add_row(name, values[name])
    console.print(table)
    if dry_run:
        console.print(t("common.dry_run_noop"))
        return
    state = StateFile(paths.setup_state_file)
    merged_path = ca_mod.ensure_merged_pem(paths.confdir, merged)
    envvars_mod.record_file_created(state, merged_path)
    try:
        envvars_mod.apply_user_envvars(state, values)
    except envvars_mod.EnvVarSetupError as exc:
        err_console.print(t("common.err_plain", exc=exc))
        raise typer.Exit(code=1) from exc
    console.print(t("cli.setup_env.done"))


@app.command(help=t("cli.teardown.doc"))
def teardown(
    targets: list[str] | None = typer.Argument(  # noqa: B008 - typer 惯用法
        None, help=t("opt.teardown_targets.help")
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
        console.print(t("cli.teardown.empty"))
        return
    # 执行前打印将要做的改动（工作约定；也是 T4.3 崩溃还原的可视确认）
    console.print(t("cli.teardown.will_restore", count=len(entries)))
    for entry in reversed(entries):
        if kinds is not None and entry.kind not in kinds:
            continue
        console.print(
            t("cli.teardown.entry_line", kind=entry.kind, item_key=entry.key, ts=entry.ts)
        )
    report = teardown_mod.run_teardown(paths.setup_state_file, kinds=kinds, dry_run=dry_run)
    for item in report.restored:
        console.print(t("cli.teardown.restored", item=item))
    for error in report.errors:
        (err_console if not dry_run else console).print(t("common.err_plain", exc=error))
    if dry_run:
        console.print(t("common.dry_run_noop"))
    elif report.ok:
        console.print(t("cli.teardown.done"))
    else:
        err_console.print(t("cli.teardown.failed"))
        raise typer.Exit(code=1)


# --------------------------------------------------------------------------
# autostart / watchdog（v0.1.1：关机优雅退出 + 开机自启 + 自检自愈）
# --------------------------------------------------------------------------


@autostart_app.command("on", help=t("cli.autostart_on.doc"))
def autostart_on(
    data_dir: Path | None = DataDirOpt,
    yes: bool = typer.Option(False, "--yes", "-y", help=t("opt.yes.help")),
) -> None:
    """创建两个登录计划任务：aaa run 常驻 + watchdog 自检（--fix 断网自动还原）。"""
    paths = resolve_paths(data_dir)
    cmd, args = autostart_mod.autostart_command(paths.data_dir)
    wcmd, wargs = autostart_mod.watchdog_command(paths.data_dir)
    console.print(t("cli.autostart_on.will_create"))
    console.print(
        t(
            "cli.autostart_on.task1",
            name=autostart_mod.AUTOSTART_TASK_NAME,
            cmd=cmd,
            args=" ".join(args),
        )
    )
    console.print(
        t(
            "cli.autostart_on.task2",
            name=autostart_mod.WATCHDOG_TASK_NAME,
            delay=autostart_mod.WATCHDOG_DELAY_SECONDS,
            cmd=wcmd,
            args=" ".join(wargs),
        )
    )
    if not yes and not typer.confirm(t("cli.autostart_on.confirm"), default=True):
        console.print(t("common.cancelled"))
        raise typer.Exit()
    state = StateFile(paths.setup_state_file)
    try:
        entries = autostart_mod.enable_autostart(state, paths.data_dir)
    except autostart_mod.AutostartError as exc:
        err_console.print(t("common.err_plain", exc=exc))
        raise typer.Exit(code=1) from exc
    for entry in entries:
        console.print(t("common.task_created", item_key=entry.key))
    console.print(t("cli.autostart_on.effect"))


@autostart_app.command("off", help=t("cli.autostart_off.doc"))
def autostart_off(data_dir: Path | None = DataDirOpt) -> None:
    """删除自启与看门狗计划任务（幂等；不影响其余 setup 改动）。"""
    paths = resolve_paths(data_dir)
    removed = autostart_mod.disable_autostart(StateFile(paths.setup_state_file))
    label = ", ".join(removed) if removed else t("cli.autostart_off.label_none")
    console.print(t("cli.autostart_off.removed", label=label))


@autostart_app.command("status", help=t("cli.autostart_status.doc"))
def autostart_status() -> None:
    """查看自启/看门狗计划任务是否已安装。"""
    for name in (autostart_mod.AUTOSTART_TASK_NAME, autostart_mod.WATCHDOG_TASK_NAME):
        installed = autostart_mod.task_exists(name)
        console.print(
            t(
                "cli.autostart_status.line",
                name=name,
                state=t("common.state_installed") if installed else t("common.state_not_installed"),
            )
        )


@app.command(help=t("cli.watchdog.doc"))
def watchdog(
    fix: bool = typer.Option(
        False, "--fix", help=t("opt.watchdog_fix.help")
    ),
    wait: float = typer.Option(
        20.0, "--wait", min=0.0, help=t("opt.watchdog_wait.help")
    ),
    data_dir: Path | None = DataDirOpt,
    log_file: Path | None = typer.Option(  # noqa: B008 - typer 惯用法
        None, "--log-file", help=t("opt.watchdog_log.help")
    ),
) -> None:
    """开机自检：检测「系统代理已启用但本机代理端口不可达」的断网态（--fix 自动还原）。"""
    paths = resolve_paths(data_dir)
    report = watchdog_mod.run_watchdog(
        paths.setup_state_file,
        fix=fix,
        wait_seconds=wait,
        log_path=log_file or (paths.data_dir / "watchdog.log"),
    )
    style = {"idle": "dim", "ok": "green", "degraded": "bold red", "recovered": "yellow"}[
        report.status
    ]
    console.print(
        t("cli.watchdog.status_line", style=style, status=report.status, detail=report.detail)
    )
    for action in report.actions:
        console.print(t("cli.watchdog.restored", action=action))
    if report.status == "degraded":
        raise typer.Exit(code=1)  # 供计划任务/脚本感知断网态


# --------------------------------------------------------------------------
# notify：告警通知（04 文档 T6：真实通道需用户显式触发）
# --------------------------------------------------------------------------


def _build_test_event() -> AuditEvent:
    """合成一条测试事件（``aaa notify test`` 用；不含任何真实数据）。"""
    return AuditEvent(
        id=new_event_id(),
        ts=_now_iso_ms(),
        mode="test",
        verdict="block",
        risk_score=100,
        destination=Destination(host="notify-test.example", port=443),
        request=RequestInfo(method="POST", path="/aaa/notify/test", size=0),
    )


def _now_iso_ms() -> str:
    from datetime import datetime

    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def _test_summary_text(channel_name: str) -> str:
    from aaa.notify.summary import SUMMARY_MAX_CHARS

    return t("cli.notify_test.summary", channel=channel_name, ts=_now_iso_ms())[:SUMMARY_MAX_CHARS]


@notify_app.command("test", help=t("cli.notify_test.doc") + "\n\n" + t("cli.notify_test.detail"))
def notify_test(
    channel: str | None = typer.Option(  # noqa: B008 - typer 惯用法
        None, "--channel", help=t("opt.notify_channel.help")
    ),
    data_dir: Path | None = DataDirOpt,
    policy: Path | None = typer.Option(  # noqa: B008 - typer 惯用法
        None, "--policy", help=t("opt.policy.help")
    ),
) -> None:
    """发送一条测试通知（走真实通道，用户显式触发；04 文档 §5 T6）。

    webhook/email 的实际送达取决于外部服务，失败会如实以非零退出码报告。
    """
    if channel is not None and channel not in CHANNEL_NAMES:
        raise typer.BadParameter(
            t("cli.notify_test.err_channel", names="|".join(CHANNEL_NAMES), channel=channel)
        )
    try:
        loader = PolicyLoader(policy or config_mod.default_policy_file())
        loader.load()
    except PolicyError as exc:
        err_console.print(t("common.policy_load_failed", exc=exc))
        raise typer.Exit(code=1) from exc
    config = notify_config_from_policy(loader)
    names = [channel] if channel is not None else config.enabled_channel_names()
    if not names:
        err_console.print(t("cli.notify_test.err_no_channels"))
        raise typer.Exit(code=1)
    built = {ch.name: ch for ch in build_channels(config)}
    event = _build_test_event()
    failed = False
    for name in names:
        target = built.get(name)
        if target is None:
            err_console.print(t("cli.notify_test.err_channel_config", name=name))
            failed = True
            continue
        try:
            target.send_checked(_test_summary_text(name), event)
        except Exception as exc:  # noqa: BLE001 - CLI 边界如实报告失败
            err_console.print(t("cli.notify_test.err_send", name=name, exc=exc))
            failed = True
        else:
            console.print(t("cli.notify_test.sent", name=name))
    if failed:
        raise typer.Exit(code=1)


# --------------------------------------------------------------------------
# status / tail / report / trim（03 文档 T4.2；06 波次二：report --daily/--weekly）
# --------------------------------------------------------------------------


def _open_store(paths: Any) -> DbEventStore:
    return DbEventStore(paths.db_file, evidence_dir=paths.evidence_dir)


@app.command(help=t("cli.status.doc"))
def status(
    data_dir: Path | None = DataDirOpt,
    policy: Path | None = typer.Option(  # noqa: B008 - typer 惯用法
        None, "--policy", help=t("opt.policy.help")
    ),
) -> None:
    """当前状态：代理 / CA / 防火墙 / 策略版本 / 最近 5 事件 / 待还原改动。"""
    paths = resolve_paths(data_dir)
    table = Table(title=t("cli.status.table_title", version=__version__, data_dir=paths.data_dir))
    table.add_column(t("cli.col_item"), style="cyan", no_wrap=True)
    table.add_column(t("cli.col_value"))

    # —— 代理 ——
    try:
        wininet = proxy_mod.read_wininet()
        enabled = wininet.get("ProxyEnable")
        server = wininet.get("ProxyServer")
        proxy_desc = (
            t("cli.status.proxy_on", server=server)
            if enabled == 1
            else t("cli.status.proxy_off", server=server)
        )
    except Exception as exc:  # noqa: BLE001 - 状态命令不因读失败中断
        proxy_desc = t("common.read_failed", exc=exc)
    try:
        winhttp = proxy_mod.read_winhttp()
        winhttp_desc = (
            t("cli.status.winhttp_direct")
            if winhttp.get("direct")
            else t("cli.status.winhttp_server", server=winhttp.get("server"))
        )
    except Exception as exc:  # noqa: BLE001
        winhttp_desc = t("common.read_failed", exc=exc)
    table.add_row(t("cli.status.row_proxy_wininet"), proxy_desc)
    table.add_row(t("cli.status.row_proxy_winhttp"), winhttp_desc)

    # —— CA ——
    try:
        pem = paths.confdir / ca_mod.CA_CERT_PEM_NAME
        if pem.exists():
            info = ca_mod.load_ca_info(pem)
            ca_desc = t(
                "cli.status.ca_desc", subject_cn=info.subject_cn, serial=info.serial, pem=pem
            )
        else:
            ca_desc = t("cli.status.ca_missing")
    except Exception as exc:  # noqa: BLE001
        ca_desc = t("common.read_failed", exc=exc)
    table.add_row(t("cli.status.row_ca"), ca_desc)

    # —— 防火墙加固（v0.2.0 实装，05 文档波次二）——
    try:
        fw_entries = [
            e
            for e in StateFile(paths.setup_state_file).entries()
            if e.kind == firewall_mod.KIND_FIREWALL_RULE
        ]
        if fw_entries:
            harden_desc = t("cli.status.harden_on", count=len(fw_entries))
        else:
            harden_desc = t("cli.status.harden_off")
    except Exception as exc:  # noqa: BLE001 - 状态命令不因读失败中断
        harden_desc = t("common.read_failed", exc=exc)
    table.add_row(t("cli.status.row_harden"), harden_desc)

    # —— 策略 ——
    notify_desc = "-"
    deepening_desc = "-"
    try:
        doc = PolicyLoader(policy or config_mod.default_policy_file()).load()
        policy_desc = t(
            "cli.status.policy_desc", mode=doc.mode, version=doc.policy_version
        )
        # 通知配置概要（04 文档 T6；不含 url/密码——webhook url 内嵌 token 属凭据）
        notify_cfg = apply_env_overrides(doc.notifications)
        enabled = ", ".join(notify_cfg.enabled_channel_names()) or t("common.notify_none")
        notify_desc = t(
            "cli.status.notify_desc",
            enabled=enabled,
            min_action=notify_cfg.min_action,
            max_per_minute=notify_cfg.rate_limit.max_per_minute,
        )
        if notify_cfg.webhook.enabled:
            notify_desc += t("cli.status.notify_webhook", provider=notify_cfg.webhook.provider)
        # 安全深化概要（05 文档波次二；只报开/关，不展开密钥与仓库内容）
        deepening_desc = t("common.deepening_join").join(
            (
                t("cli.status.fp_on" if doc.fingerprint.enabled else "cli.status.fp_off"),
                t("cli.status.judge_on" if doc.judge.enabled else "cli.status.judge_off"),
                t("cli.status.response_on" if doc.response.rules else "cli.status.response_off"),
                t("cli.status.crypto_on" if doc.encrypt.enabled else "cli.status.crypto_off"),
            )
        )
    except PolicyError as exc:
        policy_desc = t("common.policy_load_failed", exc=exc)
    table.add_row(t("cli.status.row_policy"), policy_desc)
    table.add_row(t("cli.status.row_notify"), notify_desc)
    table.add_row(t("cli.status.row_deepening"), deepening_desc)

    # —— 事件库 ——
    try:
        store = _open_store(paths)
        try:
            stats = store.stats()
            table.add_row(
                t("cli.status.row_events"),
                t(
                    "cli.status.events_desc",
                    count=store.count(),
                    pending_confirm=stats["pending_confirm"],
                    db_file=paths.db_file,
                ),
            )
        finally:
            store.close()
    except Exception as exc:  # noqa: BLE001
        table.add_row(t("cli.status.row_events"), t("cli.status.open_failed", exc=exc))

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
        ev_table = Table(title=t("cli.status.recent_title"))
        for col in (
            t("cli.col_id"),
            t("cli.col_time"),
            t("cli.col_verdict"),
            t("cli.col_risk"),
            t("cli.col_method"),
            t("cli.col_path"),
            t("cli.col_host"),
            t("cli.col_process"),
        ):
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
        console.print(t("cli.status.no_events"))

    # —— 待还原改动（R7 崩溃残留提示）——
    entries = StateFile(paths.setup_state_file).entries()
    if entries:
        console.print(t("cli.status.pending_restore", count=len(entries)))

    # —— 开机自检（v0.1.1：代理已启用但端口不可达 = 断网态预警）——
    try:
        self_check = watchdog_mod.run_watchdog(
            paths.setup_state_file,
            fix=False,
            wait_seconds=0.0,
            log_path=paths.data_dir / "watchdog.log",
        )
        if self_check.status == "degraded":
            console.print(t("cli.status.degraded"))
    except Exception as exc:  # noqa: BLE001 - 状态命令不因自检失败中断
        console.print(t("cli.status.selfcheck_skip", exc=exc))

    # —— 开机自启任务状态 ——
    try:
        auto_installed = autostart_mod.task_exists(autostart_mod.AUTOSTART_TASK_NAME)
        hint = (
            t("cli.status.hint_autostart_off")
            if auto_installed
            else t("cli.status.hint_autostart_on")
        )
        console.print(
            t(
                "cli.status.autostart_line",
                state=t("common.state_installed")
                if auto_installed
                else t("common.state_not_installed"),
                hint=hint,
            )
        )
    except Exception as exc:  # noqa: BLE001
        console.print(t("cli.status.autostart_read_failed", exc=exc))


def _process_label(event: Any) -> str:
    if event.process is None:
        return "-"
    name = event.process.name or "?"
    pid = event.process.pid if event.process.pid is not None else "?"
    return f"{name}({pid})"


@app.command(help=t("cli.tail.doc"))
def tail(
    verdict: str | None = typer.Option(None, "--verdict", help=t("opt.tail_verdict.help")),
    pid: int | None = typer.Option(None, "--pid"),
    host: str | None = typer.Option(None, "--host"),
    interval: float = typer.Option(1.0, "--interval", min=0.1, help=t("opt.tail_interval.help")),
    from_start: bool = typer.Option(False, "--from-start", help=t("opt.tail_from_start.help")),
    once: bool = typer.Option(False, "--once", help=t("opt.tail_once.help")),
    data_dir: Path | None = DataDirOpt,
) -> None:
    """实时滚动显示新事件（rich Live；Ctrl+C 退出）。"""
    paths = resolve_paths(data_dir)
    store = _open_store(paths)
    cursor = 0 if from_start else store.max_rowid()
    filter_all = t("cli.tail.filter_all")
    console.print(
        t(
            "cli.tail.listen_line",
            verdict=verdict or filter_all,
            pid=pid or filter_all,
            host=host or filter_all,
        )
    )
    rows: list[list[str]] = []

    def _render() -> Table:
        table = Table(title=t("cli.tail.table_title"))
        for col in (
            t("cli.col_time"),
            t("cli.col_verdict"),
            t("cli.col_risk"),
            t("cli.col_method"),
            t("cli.col_path"),
            t("cli.col_host"),
            t("cli.col_process"),
        ):
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
                        t(
                            "cli.tail.new_event",
                            id=event.id,
                            ts=event.ts,
                            verdict=event.verdict,
                            method=event.request.method,
                            host=event.destination.host,
                            path=event.request.path,
                        )
                    )
                if once:
                    break
                live.update(_render())
                time.sleep(interval)
    except KeyboardInterrupt:
        console.print(t("cli.tail.exited"))
    finally:
        store.close()


@app.command(help=t("cli.report.doc") + "\n\n" + t("cli.report.detail"))
def report(
    since: str | None = typer.Option(None, "--since", help=t("opt.report_since.help")),
    until: str | None = typer.Option(None, "--until", help=t("opt.report_until.help")),
    json_out: bool = typer.Option(False, "--json", help=t("opt.report_json.help")),
    csv_out: bool = typer.Option(False, "--csv", help=t("opt.report_csv.help")),
    verify_evidence: bool = typer.Option(
        False, "--verify-evidence", help=t("opt.report_verify.help")
    ),
    daily: bool = typer.Option(False, "--daily", help=t("opt.report_daily.help")),
    weekly: bool = typer.Option(False, "--weekly", help=t("opt.report_weekly.help")),
    email: bool = typer.Option(False, "--email", help=t("opt.report_email.help")),
    day: str | None = typer.Option(None, "--day", help=t("opt.report_day.help")),
    out: Path | None = typer.Option(None, "--out", help=t("opt.report_out.help")),
    policy: Path | None = typer.Option(None, "--policy", help=t("opt.policy.help")),
    data_dir: Path | None = DataDirOpt,
) -> None:
    """聚合报告：按判定/进程/主机/规则统计（03 文档 T4.2）。

    ``--daily``/``--weekly``（06 文档波次二 W6）：渲染自包含 HTML 日报/周报落
    ``data/reports/``，``--email`` 经策略 notifications.email 通道发送。
    """
    if (daily or weekly) and (json_out or csv_out):
        raise typer.BadParameter(t("cli.report.err_daily_json"))
    if daily and weekly:
        raise typer.BadParameter(t("cli.report.err_daily_both"))
    report_day = date.today()
    if day is not None:
        try:
            report_day = date.fromisoformat(day)
        except ValueError as exc:
            raise typer.BadParameter(t("cli.report.err_day", value=day)) from exc
    if daily or weekly:
        _render_html_report(
            resolve_paths(data_dir),
            policy,
            report_day,
            weekly=weekly,
            send_email=email,
            out=out,
        )
        return
    if json_out and csv_out:
        raise typer.BadParameter(t("cli.report.err_json_csv"))
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
    table = Table(
        title=t(
            "cli.report.table_title",
            since=since or t("cli.report.window_all"),
            until=until or t("cli.report.window_now"),
            total=stats["total"],
        )
    )
    table.add_column(t("cli.report.col_dim"), style="cyan")
    table.add_column(t("cli.col_item"))
    table.add_column(t("cli.report.col_count"), justify="right")
    for verdict_value, count in stats["by_verdict"].items():
        table.add_row(t("cli.report.row_verdict"), verdict_value, str(count))
    for row in stats["by_process"]:
        table.add_row(
            t("cli.report.row_process"), f"{row['pid'] or '-'} {row['process_name']}", str(row["n"])
        )
    for row in stats["by_host"]:
        table.add_row(t("cli.report.row_host"), str(row["host"]), str(row["n"]))
    for row in stats["by_rule"]:
        table.add_row(t("cli.report.row_rule"), f"{row['rule_id']}（{row['dim']}）", str(row["n"]))
    console.print(table)
    if integrity is not None:
        console.print(
            t(
                "cli.report.integrity",
                checked=integrity["checked"],
                missing=len(integrity["missing"]),
                corrupted=len(integrity["corrupted"]),
            )
        )


def _render_html_report(
    paths: Any,
    policy: Path | None,
    report_day: date,
    *,
    weekly: bool,
    send_email: bool,
    out: Path | None,
) -> None:
    """渲染（可选邮件发送）HTML 日报/周报（06 文档波次二 W6；数据只读本机库）。"""
    store = _open_store(paths)
    try:
        html = (
            reporting_daily.render_weekly(store, report_day)
            if weekly
            else reporting_daily.render_daily(store, report_day)
        )
    finally:
        store.close()
    suffix = "weekly" if weekly else "daily"
    target = out or (paths.data_dir / "reports" / f"{suffix}-{report_day.isoformat()}.html")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(html, encoding="utf-8")
    except OSError as exc:
        err_console.print(t("cli.report.render_failed", exc=exc))
        raise typer.Exit(code=1) from exc
    console.print(
        t("cli.report.weekly_saved" if weekly else "cli.report.daily_saved", path=target)
    )
    if not send_email:
        return
    try:
        doc = PolicyLoader(policy or config_mod.default_policy_file()).load()
    except PolicyError as exc:
        err_console.print(t("common.policy_load_failed", exc=exc))
        raise typer.Exit(code=1) from exc
    email_config = apply_env_overrides(doc.notifications).email
    subject = reporting_daily.WEEKLY_TITLE if weekly else reporting_daily.DAILY_TITLE
    try:
        reporting_daily.email_daily(email_config, html, subject=subject)
    except Exception as exc:  # noqa: BLE001 - 邮件失败如实以非零退出报告
        err_console.print(t("cli.report.email_failed", exc=exc))
        raise typer.Exit(code=1) from exc
    console.print(t("cli.report.email_sent", to=", ".join(email_config.to_addrs)))


@app.command(help=t("cli.trim.doc"))
def trim(
    days: int = typer.Option(..., "--days", min=0, help=t("opt.trim_days.help")),
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
        t("cli.trim.done", events=result["events"], evidence=result["evidence"], days=days)
    )


@app.command(help=t("cli.harden.doc") + "\n\n" + t("cli.harden.detail"))
def harden(
    action: str = typer.Argument(..., help=t("opt.harden_action.help")),
    proxy_exe: Path | None = typer.Option(  # noqa: B008 - typer 惯用法
        None,
        "--proxy-exe",
        help=t("opt.harden_proxy_exe.help"),
    ),
    data_dir: Path | None = DataDirOpt,
    dry_run: bool = DryRunOpt,
    yes: bool = typer.Option(False, "--yes", "-y", help=t("opt.yes.help")),
) -> None:
    """防火墙加固开关（05 文档波次一 W2/波次二 §5）：把 443 出站收敛到本代理。

    on：创建 4 条 ``EgressSentinel-`` 前缀规则（journal-first 记入 setup-state.json，
    可 ``harden off``/``aaa teardown`` 还原）；off：按记录精确删除（幂等）。
    需管理员权限。

    已知边界（firewall 模块如实登记）：Windows 筛选平台 Block 优先于 Allow，规则集
    里的 any-Block 同样命中代理与 svchost 白名单——``on`` 后 443 出站可能全断
    （含本工具代理自身）。上真机前请先在可还原环境演练（off 即还原），确认连通性。
    """
    paths = resolve_paths(data_dir)
    if action == "on":
        _harden_on(paths, proxy_exe, dry_run=dry_run, yes=yes)
        return
    if action == "off":
        _harden_off(paths, dry_run=dry_run)
        return
    raise typer.BadParameter(t("cli.harden.err_action"))


def _require_admin_for_harden() -> None:
    """管理员门禁（与 run --mode local 同样的 UAC 指引；非提权 netsh 必然失败）。"""
    if not is_current_process_elevated():
        err_console.print(t("cli.harden.err_admin"))
        raise typer.Exit(code=2)


def _harden_on(
    paths: Any, proxy_exe: Path | None, *, dry_run: bool, yes: bool
) -> None:
    """``harden on``：先展示规则清单（dry-run 概念）→ 确认 → journal-first 逐条创建。"""
    exe = proxy_exe if proxy_exe is not None else Path(sys.executable)
    if not exe.is_file():
        err_console.print(t("cli.harden.err_proxy_missing", exe=exe))
        raise typer.Exit(code=1)
    rules = firewall_mod.plan_harden(exe)
    console.print(t("cli.harden.will_create", count=len(rules)))
    for rule in rules:
        program = rule.program if rule.program else t("cli.harden.program_any")
        console.print(
            t(
                "cli.harden.rule_line",
                name=rule.name,
                action=rule.action.upper(),
                protocol=rule.protocol,
                port=rule.remote_port,
                program=program,
            )
        )
    console.print(t("cli.harden.boundary"))
    if dry_run:
        console.print(t("cli.harden.dry_run"))
        return
    _require_admin_for_harden()
    if not yes and not typer.confirm(t("cli.harden.confirm"), default=False):
        console.print(t("cli.harden.cancelled_nochange"))
        raise typer.Exit()
    state = StateFile(paths.setup_state_file)
    try:
        entries = firewall_mod.apply_harden(state, exe)
    except FirewallError as exc:
        err_console.print(t("cli.harden.err_apply", exc=exc))
        raise typer.Exit(code=1) from exc
    for entry in entries:
        console.print(t("cli.harden.rule_created", item_key=entry.key))
    console.print(t("cli.harden.done", count=len(entries)))


def _harden_off(paths: Any, *, dry_run: bool) -> None:
    """``harden off``：按状态文件记录精确删除本工具创建的防火墙规则（幂等）。"""
    entries = [e for e in StateFile(paths.setup_state_file).entries()
               if e.kind == firewall_mod.KIND_FIREWALL_RULE]
    if not entries:
        console.print(t("cli.harden.off_no_records"))
        return
    console.print(t("cli.harden.will_delete", count=len(entries)))
    for entry in entries:
        console.print(
            t("cli.teardown.entry_line", kind=entry.kind, item_key=entry.key, ts=entry.ts)
        )
    if dry_run:
        console.print(t("common.dry_run_noop"))
        return
    _require_admin_for_harden()
    state = StateFile(paths.setup_state_file)
    failed = 0
    for entry in reversed(entries):
        try:
            firewall_mod.restore_harden(state, entry)
        except FirewallError as exc:
            failed += 1
            err_console.print(
                t("cli.harden.err_delete", kind=entry.kind, item_key=entry.key, exc=exc)
            )
        else:
            console.print(t("cli.harden.rule_deleted", item_key=entry.key))
    if failed:
        err_console.print(t("cli.harden.err_delete_failed", count=failed))
        raise typer.Exit(code=1)
    console.print(t("cli.harden.off_done"))


# --------------------------------------------------------------------------
# fingerprint：仓库指纹库（05 文档波次一 W1/波次二 §5）
# --------------------------------------------------------------------------


@fingerprint_app.command("build", help=t("cli.fp_build.doc") + "\n\n" + t("cli.fp_build.detail"))
def fingerprint_build(
    repo: list[Path] | None = typer.Option(  # noqa: B008 - typer 惯用法
        None,
        "--repo",
        help=t("opt.fp_repo.help"),
    ),
    rebuild: bool = typer.Option(
        False, "--rebuild", help=t("opt.fp_rebuild.help")
    ),
    policy: Path | None = typer.Option(  # noqa: B008 - typer 惯用法
        None, "--policy", help=t("opt.policy.help")
    ),
    data_dir: Path | None = DataDirOpt,
) -> None:
    """构建/增量合并仓库指纹库（data/fingerprints.bin）：纯本地，无任何外发。

    同名仓库重复并入会被拒绝（--rebuild 可从零重建）；非 git 工作区需目录内含
    ``.git``（建库仅读工作区文件，不执行任何 git 命令、不触网）。
    """
    paths = resolve_paths(data_dir)
    try:
        doc = PolicyLoader(policy or config_mod.default_policy_file()).load()
    except PolicyError as exc:
        err_console.print(t("common.policy_load_failed", exc=exc))
        raise typer.Exit(code=1) from exc
    repos = list(repo) if repo else [Path(p) for p in doc.fingerprint.repos]
    if not repos:
        err_console.print(t("cli.fp_build.err_no_repos"))
        raise typer.Exit(code=1)
    store_path = paths.data_dir / FINGERPRINTS_FILE_NAME
    index: FingerprintIndex | None = None if rebuild else FingerprintIndex.load(store_path)
    if index is None:
        if rebuild:
            console.print(t("cli.fp_build.msg_rebuild"))
        elif store_path.exists():
            console.print(t("cli.fp_build.msg_corrupt"))
        index = FingerprintIndex()

    failed: list[str] = []
    skipped: list[str] = []
    merged = 0
    for repo_path in repos:
        name = repo_path.name or str(repo_path)
        try:
            stats = index.add_repo(repo_path)
        except NotADirectoryError as exc:
            failed.append(f"{name}：{exc}")
            continue
        except ValueError as exc:
            message = str(exc)
            if "已在索引中" in message:
                skipped.append(t("cli.fp_build.skip_exists", name=name))
                continue
            failed.append(f"{name}：{exc}")
            continue
        merged += 1
        console.print(
            t(
                "cli.fp_build.merged",
                repo=stats.repo,
                files=stats.files_indexed,
                slices=stats.slices_added,
            )
            + (
                t(
                    "cli.fp_build.skipped_suffix",
                    too_large=stats.files_skipped_too_large,
                    binary=stats.files_skipped_binary,
                    errored=stats.files_errored,
                )
                if (
                    stats.files_skipped_too_large
                    or stats.files_skipped_binary
                    or stats.files_errored
                )
                else ""
            )
        )
        if stats.slice_cap_reached:
            console.print(
                t("cli.fp_build.slice_cap", repo=stats.repo, total=stats.total_slices)
            )
    for note in skipped:
        console.print(t("cli.fp_build.skip_line", note=note))
    for error in failed:
        err_console.print(t("cli.fp_build.fail_line", error=error))
    if merged == 0 and failed:
        # 全部仓库都失败：如实以非零退出报告，不落盘（库内容未变）
        err_console.print(t("cli.fp_build.err_all_failed"))
        raise typer.Exit(code=1)
    if merged == 0:
        # 重复执行（请求的仓库都已在库中）：幂等 no-op，成功返回
        console.print(t("cli.fp_build.no_new"))
        return
    index.save(store_path)
    console.print(
        t(
            "cli.fp_build.saved",
            path=store_path,
            repos=len(index.repos),
            slices=index.total_slices,
            digests=index.digest_count,
        )
        + (t("cli.fp_build.restart_hint") if doc.fingerprint.enabled else "")
    )
    if failed:
        raise typer.Exit(code=1)


# --------------------------------------------------------------------------
# service：Windows 服务化（06 文档波次一 W1 / 波次二接线）
# --------------------------------------------------------------------------


@service_app.command("install", help=t("cli.service_install.doc"))
def service_install(
    highest: bool = typer.Option(
        True, "--highest/--limited", help=t("opt.service_highest.help")
    ),
    data_dir: Path | None = DataDirOpt,
    yes: bool = typer.Option(False, "--yes", "-y", help=t("opt.yes.help")),
) -> None:
    """安装开机服务计划任务（ONSTART+SYSTEM；需管理员，改动记录 setup-state.json）。"""
    paths = resolve_paths(data_dir)
    log_file = paths.data_dir / service_mod.SERVICE_LOG_NAME
    console.print(
        t(
            "cli.service_install.will_do",
            task_name=service_mod.SERVICE_TASK_NAME,
            log_file=log_file,
        )
    )
    if not is_current_process_elevated():
        err_console.print(t("cli.service_install.err_admin"))
        raise typer.Exit(code=2)
    if not yes and not typer.confirm(t("cli.service_install.confirm"), default=False):
        console.print(t("common.cancelled"))
        raise typer.Exit()
    state = StateFile(paths.setup_state_file)
    try:
        result = service_mod.install_service(state, paths.data_dir, highest=highest)
    except service_mod.ServiceError as exc:
        err_console.print(t("cli.service_install.err", exc=exc))
        raise typer.Exit(code=1) from exc
    for warning in result.warnings:
        err_console.print(t("cli.service_status.conflict", warning=warning))
    console.print(t("cli.service_install.done", task_name=result.task_name))


@service_app.command("uninstall", help=t("cli.service_uninstall.doc"))
def service_uninstall(data_dir: Path | None = DataDirOpt) -> None:
    """删除服务计划任务并清理记录（幂等）。"""
    paths = resolve_paths(data_dir)
    removed = service_mod.uninstall_service(StateFile(paths.setup_state_file))
    if removed:
        console.print(
            t("cli.service_uninstall.removed", task_name=service_mod.SERVICE_TASK_NAME)
        )
    else:
        console.print(t("cli.service_uninstall.absent"))


@service_app.command("status", help=t("cli.service_status.doc"))
def service_status_cmd(data_dir: Path | None = DataDirOpt) -> None:
    """查看服务计划任务安装状态与互斥提示（只读）。"""
    paths = resolve_paths(data_dir)
    result = service_mod.service_status(StateFile(paths.setup_state_file))
    installed = result.task_exists or result.journaled
    if result.command is not None and result.log_file is not None:
        console.print(
            t(
                "cli.service_status.line",
                task_name=result.task_name,
                state=t("common.state_installed") if installed else t("common.state_not_installed"),
                command=result.command,
                log_file=result.log_file,
            )
        )
    else:
        console.print(
            t(
                "cli.service_status.line_no_journal",
                task_name=result.task_name,
                state=t("common.state_installed") if installed else t("common.state_not_installed"),
            )
        )
    for warning in result.warnings:
        err_console.print(t("cli.service_status.conflict", warning=warning))


# --------------------------------------------------------------------------
# tray：系统托盘（06 文档波次一 W2 / 波次二接线）
# --------------------------------------------------------------------------


@app.command(help=t("cli.tray.doc"))
def tray(data_dir: Path | None = DataDirOpt) -> None:
    """启动系统托盘（依赖 pystray/Pillow：pip install -e .[tray]；缺依赖以退出码 2 结束）。"""
    from aaa.tray import run_tray  # 延迟导入：托盘为可选功能

    paths = resolve_paths(data_dir)
    code = run_tray(paths.data_dir)
    if code:
        raise typer.Exit(code=code)


# --------------------------------------------------------------------------
# rules：规则市场导出/导入（06 文档波次一 W7 / 波次二接线）
# --------------------------------------------------------------------------


@rules_app.command("export", help=t("cli.rules_export.doc"))
def rules_export(
    section: str = typer.Argument(..., help=t("opt.rules_section.help")),
    out: Path | None = typer.Option(None, "--out", help=t("opt.rules_out.help")),
    policy: Path | None = typer.Option(None, "--policy", help=t("opt.policy.help")),
) -> None:
    """导出策略段为 YAML 文本（--out 落盘，缺省打印到 stdout）。"""
    doc = _load_policy_or_exit(policy)
    try:
        text = export_section(doc, section)
    except RulesHubError as exc:
        err_console.print(t("cli.rules_export.err", exc=exc))
        raise typer.Exit(code=1) from exc
    if out is None:
        console.print(text, markup=False, highlight=False)
        return
    try:
        atomic_write_text(out, text)
    except OSError as exc:
        err_console.print(t("common.err_plain", exc=exc))
        raise typer.Exit(code=1) from exc
    console.print(t("cli.rules_export.done", section=section, path=out))


@rules_app.command("import", help=t("cli.rules_import.doc"))
def rules_import(
    section: str = typer.Argument(..., help=t("opt.rules_section.help")),
    source: str = typer.Argument(..., help=t("opt.rules_source.help")),
    merge: str = typer.Option("replace", "--merge", help=t("opt.rules_merge.help")),
    policy: Path | None = typer.Option(None, "--policy", help=t("opt.rules_policy.help")),
) -> None:
    """把 YAML 文件（``-`` 读 stdin）导入当前策略段：三关校验全过才原子落盘。"""
    target = policy or config_mod.default_policy_file()
    try:
        current_yaml = target.read_text(encoding="utf-8")
    except OSError as exc:
        err_console.print(t("common.read_failed", exc=exc))
        raise typer.Exit(code=1) from exc
    if source == "-":
        yaml_str = sys.stdin.read()
    else:
        try:
            yaml_str = Path(source).read_text(encoding="utf-8")
        except OSError as exc:
            err_console.print(t("common.read_failed", exc=exc))
            raise typer.Exit(code=1) from exc
    console.print(t("cli.rules_import.note_comments"))
    try:
        import_section(current_yaml, section, yaml_str, merge=merge, output_path=target)
    except RulesHubError as exc:
        err_console.print(t("cli.rules_import.err", exc=exc))
        raise typer.Exit(code=1) from exc
    console.print(t("cli.rules_import.done", section=section, merge=merge, path=target))


# --------------------------------------------------------------------------
# gitleaks：上游 secrets 规则同步（06 文档波次一 W7 / 波次二接线）
# --------------------------------------------------------------------------


@gitleaks_app.command("sync", help=t("cli.gitleaks_sync.doc"))
def gitleaks_sync(
    source: str = typer.Argument(..., help=t("opt.gitleaks_source.help")),
    out: Path | None = typer.Option(None, "--out", help=t("opt.gitleaks_out.help")),
    data_dir: Path | None = DataDirOpt,
) -> None:
    """从 URL 或本地 TOML 同步 gitleaks 规则并转换为规则包 YAML。"""
    paths = resolve_paths(data_dir)
    target = out or (paths.data_dir / "rules" / "gitleaks.yaml")
    try:
        result = sync_gitleaks(source, output_path=target)
    except RulesHubError as exc:
        err_console.print(t("cli.gitleaks_sync.err", exc=exc))
        raise typer.Exit(code=1) from exc
    console.print(
        t(
            "cli.gitleaks_sync.done",
            converted=result.converted,
            skipped=len(result.skipped),
            sha256=result.sha256[:12],
            path=result.output_path,
        )
    )


# --------------------------------------------------------------------------
# hub：多机聚合（06 文档波次一 W8 / 波次二接线）
# --------------------------------------------------------------------------


@hub_app.command("serve", help=t("cli.hub_serve.doc"))
def hub_serve(
    host: str = typer.Option("0.0.0.0", "--host", help=t("opt.hub_host.help")),
    port: int = typer.Option(_HUB_DEFAULT_PORT, "--port", help=t("opt.hub_port.help")),
    token: str | None = typer.Option(None, "--token", help=t("opt.hub_token.help")),
    data_dir: Path | None = DataDirOpt,
) -> None:
    """启动 hub 中心收集服务（默认 0.0.0.0，Bearer 令牌鉴权）。"""
    shared_token = token or os.environ.get(HUB_TOKEN_ENV, "")
    if not shared_token:
        err_console.print(t("cli.hub_serve.err_token"))
        raise typer.Exit(code=2)
    try:
        from aaa.hub.collector import HubCollector, run_hub  # 延迟导入：hub 为可选依赖
    except ImportError as exc:
        err_console.print(t("cli.hub_serve.err_dep", exc=exc))
        raise typer.Exit(code=1) from exc
    paths = resolve_paths(data_dir)
    paths.ensure_runtime_dirs()
    collector = HubCollector(paths.data_dir / "hub.db", shared_token)
    console.print(t("cli.hub_serve.db_line", db_file=paths.data_dir / "hub.db"))
    console.print(t("cli.hub_serve.listening", host=host, port=port))
    try:
        run_hub(collector, host=host, port=port)
    finally:
        collector.close()


@hub_forward_app.command("status", help=t("cli.hub_forward_status.doc"))
def hub_forward_status(
    data_dir: Path | None = DataDirOpt,
    policy: Path | None = typer.Option(None, "--policy", help=t("opt.policy.help")),
) -> None:
    """查看 agent 端转发配置与最近统计（运行中的 aaa run 写 data/hub-forward.json）。"""
    paths = resolve_paths(data_dir)
    try:
        doc = PolicyLoader(policy or config_mod.default_policy_file()).load()
    except PolicyError as exc:
        err_console.print(t("common.policy_load_failed", exc=exc))
        raise typer.Exit(code=1) from exc
    config = apply_hub_env_overrides(doc.hub)
    if not config.enabled:
        console.print(t("cli.hub_forward.disabled"))
    else:
        console.print(
            t("cli.hub_forward.enabled", url=config.url, batch_size=config.batch_size)
        )
    stats_file = paths.data_dir / HUB_FORWARD_STATS_FILENAME
    snapshot: dict[str, Any] | None = None
    try:
        loaded = json.loads(stats_file.read_text(encoding="utf-8"))
        if isinstance(loaded, dict) and isinstance(loaded.get("stats"), dict):
            snapshot = loaded
    except (OSError, ValueError):
        snapshot = None
    if snapshot is None:
        console.print(t("cli.hub_forward.no_stats"))
        return
    stats = snapshot["stats"]
    console.print(
        t(
            "cli.hub_forward.stats_line",
            sent_events=stats.get("sent_events", 0),
            sent_batches=stats.get("sent_batches", 0),
            dropped=stats.get("dropped", 0),
            retries_used=stats.get("retries_used", 0),
            send_errors=stats.get("send_errors", 0),
            queue_size=stats.get("queue_size", 0),
            updated=snapshot.get("updated", "-"),
        )
    )
    if stats.get("last_error"):
        console.print(t("cli.hub_forward.last_error", error=stats["last_error"]))


# --------------------------------------------------------------------------
# policy：lint / use / list（多 profile，06 文档波次二）
# --------------------------------------------------------------------------


@policy_app.command("use", help=t("cli.policy_use.doc"))
def policy_use(
    name: str | None = typer.Argument(None, help=t("opt.policy_name.help")),
    reset: bool = typer.Option(False, "--reset", help=t("opt.policy_reset.help")),
) -> None:
    """切换当前策略 profile（拷贝 profiles/<名>.yaml → current.yaml，运行中 2s 热更新）。"""
    policies_dir = config_mod.DEFAULT_POLICIES_DIR
    current = policies_dir / CURRENT_POLICY_FILE_NAME
    if reset:
        if current.exists():
            current.unlink()
            console.print(t("cli.policy_use.reset_done"))
        else:
            console.print(t("cli.policy_use.no_current"))
        return
    if not name:
        raise typer.BadParameter(t("opt.policy_name.help"))
    profile = policies_dir / PROFILES_DIR_NAME / f"{name}.yaml"
    if not profile.is_file():
        err_console.print(t("cli.policy_use.err_missing", path=profile))
        raise typer.Exit(code=1)
    try:
        PolicyLoader(profile).load()  # 校验不过绝不切换
    except PolicyError as exc:
        err_console.print(t("cli.policy_use.err_invalid", exc=exc))
        raise typer.Exit(code=1) from exc
    try:
        # 拷贝语义（06 文档波次二：current 软链/拷贝）：原样拷贝文本，保留 YAML 注释
        atomic_write_text(current, profile.read_text(encoding="utf-8"))
    except OSError as exc:
        err_console.print(t("common.err_plain", exc=exc))
        raise typer.Exit(code=1) from exc
    console.print(t("cli.policy_use.done", name=name, path=current))


@policy_app.command("list", help=t("cli.policy_list.doc"))
def policy_list() -> None:
    """列出可用策略 profile 与当前生效策略。"""
    policies_dir = config_mod.DEFAULT_POLICIES_DIR
    profiles_dir = policies_dir / PROFILES_DIR_NAME
    active = config_mod.default_policy_file()
    profiles = sorted(profiles_dir.glob("*.yaml")) if profiles_dir.is_dir() else []
    if not profiles:
        console.print(t("cli.policy_list.none"))
        return
    table = Table(title=t("cli.policy_list.title", policies_dir=profiles_dir))
    table.add_column(t("cli.policy_list.col_name"), style="cyan")
    table.add_column(t("cli.policy_list.col_status"), no_wrap=True)
    current_text = t("cli.policy_list.current")
    for profile in profiles:
        is_current = profile == active or (
            active.is_file()
            and active.name == CURRENT_POLICY_FILE_NAME
            and _files_equal(profile, active)
        )
        table.add_row(profile.stem, current_text if is_current else "-")
    console.print(table)
    if active.name != CURRENT_POLICY_FILE_NAME:
        console.print(t("cli.policy_list.base_default"))


def _files_equal(left: Path, right: Path) -> bool:
    """两文件内容是否一致（profile 与 current.yaml 对账；换行差异归一——
    Windows 文本写出的 \\r\\n 与 atomic_write_text 的 \\n 视为同一内容）。"""
    try:
        return left.read_text(encoding="utf-8") == right.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False


def _load_policy_or_exit(policy: Path | None) -> PolicyDocument:
    """加载（当前生效）策略文档；失败打印并以退出码 1 结束。"""
    try:
        return PolicyLoader(policy or config_mod.default_policy_file()).load()
    except PolicyError as exc:
        err_console.print(t("common.policy_load_failed", exc=exc))
        raise typer.Exit(code=1) from exc


# --------------------------------------------------------------------------
# web：本地面板（03 文档 T5.x）
# --------------------------------------------------------------------------


@app.command(help=t("cli.web.doc"))
def web(
    host: str = typer.Option("127.0.0.1", "--host", help=t("opt.web_host.help")),
    port: int = typer.Option(DEFAULT_WEB_PORT, "--port"),
    data_dir: Path | None = DataDirOpt,
    policy: Path | None = typer.Option(  # noqa: B008 - typer 惯用法
        None, "--policy", help=t("opt.policy.help")
    ),
) -> None:
    """启动本地 Web 面板（只读 + confirm 决策；仅监听 127.0.0.1）。"""
    if host not in _LOOPBACK_HOSTS:
        raise typer.BadParameter(
            t("cli.web.err_not_loopback", hosts=", ".join(_LOOPBACK_HOSTS), host=host)
        )
    try:
        from aaa.web.app import create_app  # 延迟导入：web 为可选依赖
    except ImportError as exc:
        err_console.print(t("cli.web.err_missing_dep", exc=exc))
        raise typer.Exit(code=1) from exc
    paths = resolve_paths(data_dir)
    paths.ensure_runtime_dirs()
    store = _open_store(paths)
    loader = PolicyLoader(policy or config_mod.default_policy_file())
    try:
        loader.load()
    except PolicyError as exc:
        err_console.print(t("cli.web.err_policy_soft", exc=exc))
    panel = create_app(
        db=store,
        evidence_dir=paths.evidence_dir,
        policy_loader=loader,
        decisions=DecisionStore(paths.decisions_file, default_ttl=resolve_confirm_ttl(None)),
        data_dir=paths.data_dir,
    )
    console.print(t("cli.web.listening", host=host, port=port))
    try:
        import uvicorn

        uvicorn.run(panel, host=host, port=port, log_level="warning")
    finally:
        store.close()


# --------------------------------------------------------------------------
# policy lint
# --------------------------------------------------------------------------


@policy_app.command("lint", help=t("cli.policy_lint.doc"))
def policy_lint(
    file: Path | None = typer.Argument(  # noqa: B008 - typer 惯用法
        None, help=t("opt.policy.help")
    ),
) -> None:
    """校验策略文件（pydantic 严格 schema，03 文档 T3.1）：合法打印摘要，非法以 1 退出。"""
    path = file or config_mod.default_policy_file()
    loader = PolicyLoader(path)
    try:
        doc = loader.load()
    except PolicyError as exc:
        err_console.print(t("cli.policy_lint.err_invalid", path=path, exc=exc))
        raise typer.Exit(code=1) from exc
    table = Table(title=t("cli.policy_lint.table_title", path=path))
    table.add_column(t("cli.col_item"))
    table.add_column(t("cli.col_value"))
    table.add_row(t("cli.policy_lint.row_version"), str(doc.version))
    table.add_row(t("cli.policy_lint.row_mode"), doc.mode)
    table.add_row(t("cli.policy_lint.row_policy_version"), doc.policy_version)
    table.add_row(t("cli.policy_lint.row_fail_open"), str(doc.defaults.fail_open))
    table.add_row(t("cli.policy_lint.row_max_body_scan"), str(doc.defaults.max_body_scan))
    table.add_row(
        t("cli.policy_lint.row_domain_classes"), ", ".join(sorted(doc.domains.classes)) or "-"
    )
    table.add_row(t("cli.policy_lint.row_domain_rules"), str(len(doc.domains.rules)))
    table.add_row(
        t("cli.policy_lint.row_process_profiles"), ", ".join(sorted(doc.processes.profiles)) or "-"
    )
    table.add_row(t("cli.policy_lint.row_process_rules"), str(len(doc.processes.rules)))
    table.add_row(t("cli.policy_lint.row_scanners"), ", ".join(doc.content.scanners) or "-")
    table.add_row(t("cli.policy_lint.row_content_rules"), str(len(doc.content.rules)))
    table.add_row(t("cli.policy_lint.row_volume_rules"), str(len(doc.volume)))
    table.add_row(t("cli.policy_lint.row_time_window_rules"), str(len(doc.time_window)))
    table.add_row(
        t("cli.policy_lint.row_fingerprint"),
        t(
            "cli.policy_lint.fp_desc",
            enabled=doc.fingerprint.enabled,
            repos=len(doc.fingerprint.repos),
            min_hits=doc.fingerprint.min_hits,
        ),
    )
    table.add_row(
        t("cli.policy_lint.row_judge"),
        t(
            "cli.policy_lint.judge_desc",
            enabled=doc.judge.enabled,
            model=doc.judge.model or "-",
            budget=doc.judge.max_events_per_day,
        ),
    )
    table.add_row(
        t("cli.policy_lint.row_response"),
        f"{len(doc.response.rules)} rules"
        + (
            t("cli.policy_lint.response_ids", ids=", ".join(r.id for r in doc.response.rules))
            if doc.response.rules
            else ""
        ),
    )
    table.add_row(
        t("cli.policy_lint.row_encrypt"),
        t("cli.policy_lint.encrypt_desc", enabled=doc.encrypt.enabled),
    )
    # v0.3.0 新段（06 文档波次二）：sampling / hub
    table.add_row(
        t("cli.policy_lint.row_sampling"),
        t(
            "cli.policy_lint.sampling_desc",
            enabled=doc.sampling.enabled,
            head_bytes=doc.sampling.head_bytes,
        ),
    )
    table.add_row(
        t("cli.policy_lint.row_hub"),
        t("cli.policy_lint.hub_desc", enabled=doc.hub.enabled, url=doc.hub.url),
    )
    console.print(table)


def main() -> None:
    """``[project.scripts]`` 入口。"""
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
