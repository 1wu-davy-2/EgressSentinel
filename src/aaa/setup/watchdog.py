"""开机自检 watchdog：检测「系统代理已启用但本机代理端口不可达」并可选自动还原。

背景（用户场景）：setup 把系统代理持久指向 127.0.0.1:8080，若突发关机后
自启失败/进程未跑，遵循系统代理的应用会「断网」——与 VPN 残留同类问题。

判定（三态）：
- ``idle``：journal 无代理记录 → 无可守护对象；
- ``ok``：端口可达（含登录竞态下的有界等待）；
- ``degraded``：代理仍启用但端口不可达 → 网络已受影响。

动作：默认只报告；``fix=True`` 还原网络相关改动（WinINET/WinHTTP 代理 +
代理类环境变量；CA 无害保留），等价 ``aaa teardown proxy env``。
每次运行追加一行到 ``data/watchdog.log``。
"""

from __future__ import annotations

import logging
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from aaa.setup.envvars import KIND_ENV_VAR, KIND_FILE_CREATED
from aaa.setup.proxy import KIND_WINHTTP, KIND_WININET
from aaa.setup.state import StateFile
from aaa.setup.teardown import run_teardown

logger = logging.getLogger(__name__)

#: fix 时还原的网络相关 kind（代理设置 + 代理环境变量；CA 无害保留）
NETWORK_KINDS = {KIND_WININET, KIND_WINHTTP, KIND_ENV_VAR, KIND_FILE_CREATED}

#: 端口探测默认单次超时（秒）
PROBE_TIMEOUT = 0.5


@dataclass
class WatchdogReport:
    """自检结果。status ∈ idle | ok | degraded | recovered。"""

    status: str
    detail: str
    actions: list[str] = field(default_factory=list)

    @property
    def network_broken(self) -> bool:
        return self.status == "degraded"


def proxy_endpoint(entries) -> tuple[str, int] | None:
    """从 journal 的 WinINET 记录解析代理端点（host, port）。"""
    for entry in entries:
        if entry.kind != KIND_WININET or not isinstance(entry.new, dict):
            continue
        server = entry.new.get("ProxyServer")
        if isinstance(server, str) and ":" in server:
            host, _, port = server.rpartition(":")
            if port.isdigit():
                return host, int(port)
    return None


def port_open(host: str, port: int, timeout: float = PROBE_TIMEOUT) -> bool:
    """本机代理端口是否可连（连接被拒/超时都视为不可达）。"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0


def _append_log(log_path: Path, report: WatchdogReport) -> None:
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().astimezone().isoformat(timespec="seconds")
        actions = ";".join(report.actions) or "-"
        log_path.open("a", encoding="utf-8").write(
            f"{ts}\t{report.status}\t{actions}\t{report.detail}\n"
        )
    except OSError:  # noqa: BLE001 - 日志失败不影响主流程
        logger.debug("watchdog 日志写入失败：%s", log_path, exc_info=True)


def run_watchdog(
    state_file: Path,
    *,
    fix: bool = False,
    wait_seconds: float = 20.0,
    log_path: Path | None = None,
    _port_open=port_open,
    _teardown=run_teardown,
) -> WatchdogReport:
    """执行一次自检；``wait_seconds`` 为登录竞态预留的有界等待。"""
    entries = StateFile(state_file).entries()
    endpoint = proxy_endpoint(entries)
    if log_path is None:
        log_path = state_file.parent / "watchdog.log"

    if endpoint is None:
        report = WatchdogReport("idle", "journal 无代理记录，无需守护")
        _append_log(log_path, report)
        return report

    host, port = endpoint
    deadline = time.monotonic() + max(0.0, wait_seconds)
    reachable = False
    while True:
        if _port_open(host, port):
            reachable = True
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(0.5)

    if reachable:
        report = WatchdogReport("ok", f"代理运行中（{host}:{port} 可达）")
        _append_log(log_path, report)
        return report

    if not fix:
        report = WatchdogReport(
            "degraded",
            f"代理设置仍启用但 {host}:{port} 不可达——遵循系统代理的应用会断网。"
            f"恢复：aaa watchdog --fix 或 aaa teardown proxy，或重新 aaa run。",
        )
        _append_log(log_path, report)
        return report

    teardown_report = _teardown(state_file, kinds=set(NETWORK_KINDS))
    detail = (
        "已还原网络相关改动（代理设置与代理环境变量；CA 无害保留）"
        if teardown_report.ok
        else f"部分还原失败：{'; '.join(teardown_report.failed)}（记录保留可重试）"
    )
    report = WatchdogReport("recovered", detail, actions=list(teardown_report.restored))
    _append_log(log_path, report)
    return report
