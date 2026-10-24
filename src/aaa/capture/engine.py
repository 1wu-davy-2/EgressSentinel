"""CaptureEngine：以 Python 库方式嵌入 mitmproxy（03 文档 T1.1，02 文档 §2）。

- 封装 mitmproxy 选项：listen_host=127.0.0.1、listen_port 可配、confdir 指向 data/mitm/；
- 加载审计 addon（``aaa.capture.addon.AuditAddon`` 等）；
- ``run_blocking()`` 阻塞运行，Ctrl+C 优雅退出；
- ``start_in_background()`` 供测试/嵌入场景在后台线程起代理。

local 模式（需管理员）见 ``docs/notes/local-mode-spike.md``（T0.3）。
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import socket
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mitmproxy import options as mitm_options
from mitmproxy.tools.dump import DumpMaster

from aaa.config import (
    DEFAULT_LISTEN_HOST,
    DEFAULT_LISTEN_PORT,
    DEFAULT_POLICIES_DIR,
    AppPaths,
    resolve_paths,
)

logger = logging.getLogger(__name__)

#: 支持的 mitmproxy 模式前缀：regular（默认）/ local（需管理员，T0.3 spike）
_SUPPORTED_MODES = ("regular", "local")


@dataclass(frozen=True)
class ProxyConfig:
    """采集引擎配置。``confdir`` 为 ``None`` 时解析为 ``<data>/mitm``。"""

    listen_host: str = DEFAULT_LISTEN_HOST
    listen_port: int = DEFAULT_LISTEN_PORT
    confdir: Path | None = None
    mode: str = "regular"
    data_dir: Path | None = None
    policies_dir: Path = DEFAULT_POLICIES_DIR
    #: 透传 mitmproxy ``ssl_insecure``（-k）：不校验上游服务器证书。
    #: mitmproxy 12 默认 VERIFY_PEER（certifi 信任库）；本地 HTTPS fixture 用自签名
    #: 证书时必须开启（测试专用）。生产环境保持 False，不改变默认行为。
    ssl_insecure: bool = False

    def resolved_confdir(self) -> Path:
        if self.confdir is not None:
            return self.confdir
        return resolve_paths(self.data_dir).confdir


def _validate_mode(mode: str) -> str:
    """校验模式字符串（``regular`` 或 ``local[:spec]``），返回透传给 mitmproxy 的 spec。"""
    if mode == _SUPPORTED_MODES[0] or mode.startswith("regular:"):
        return mode
    if mode == _SUPPORTED_MODES[1] or mode.startswith("local:"):
        # local 需要管理员（02 文档 D1；调用方负责权限检查，见 aaa.setup.admin）
        return mode
    raise ValueError(f"不支持的代理模式：{mode!r}（支持 regular / local[:spec]）")


# --------------------------------------------------------------------------
# 优雅退出：Windows 关机/注销/控制台关闭（用户需求：突发关机不得阻塞、不得残留半写状态）
# --------------------------------------------------------------------------

_CTRL_CLOSE_EVENT = 2
_CTRL_LOGOFF_EVENT = 5
_CTRL_SHUTDOWN_EVENT = 6

#: SetConsoleCtrlHandler 回调引用必须保活（防 GC 导致失效）
_HANDLER_REFS: list[Any] = []


def is_shutdown_event(ctrl_type: int) -> bool:
    """是否为需要接管优雅退出的控制台事件。

    Ctrl+C（0）不在此列——仍走 KeyboardInterrupt 原路径；CTRL_BREAK(1) 交给
    默认处理。接管 2/5/6：关机、注销、控制台关闭（点 X 关窗口）。
    """
    return ctrl_type in (_CTRL_CLOSE_EVENT, _CTRL_LOGOFF_EVENT, _CTRL_SHUTDOWN_EVENT)


def _bounded_exit(on_stop: Callable[[], None], timeout: float) -> None:
    """后台线程限时执行 stop：Windows 关机只给约 5 秒，超时强制退出绝不阻塞。"""
    thread = threading.Thread(target=on_stop, daemon=True)
    thread.start()
    thread.join(timeout)
    os._exit(0)


def install_shutdown_handlers(on_stop: Callable[[], None], timeout: float = 4.0) -> None:
    """注册关机/注销/控制台关闭的优雅退出（POSIX 上对应 SIGTERM）。

    stop 在独立线程限时执行（默认 4s < 系统 5s 上限），到点 ``os._exit(0)``；
    事件库 SQLite 每事件事务落盘，强退不丢已入库数据。
    """
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        def _dispatch(ctrl_type: int) -> bool:
            if not is_shutdown_event(ctrl_type):
                return False  # 交给默认处理（含 mitmproxy 自身的 Ctrl+C）
            threading.Thread(
                target=_bounded_exit, args=(on_stop, timeout), daemon=True
            ).start()
            return True  # 已接管，阻止默认立即终止

        handler = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)(_dispatch)
        if not ctypes.windll.kernel32.SetConsoleCtrlHandler(handler, True):
            logger.warning("SetConsoleCtrlHandler 注册失败，关机时退化为默认终止")
        _HANDLER_REFS.append(handler)
        logger.debug("已注册控制台关机优雅退出处理器")
    else:

        def _sig_handler(signum: int, _frame: object) -> None:
            _bounded_exit(on_stop, timeout)

        signal.signal(signal.SIGTERM, _sig_handler)


class CaptureEngine:
    """mitmproxy 采集引擎封装。"""

    def __init__(self, config: ProxyConfig, addons: Sequence[Any] = ()) -> None:
        self.config = config
        self.addons: list[Any] = list(addons)
        self.master: DumpMaster | None = None

    def build_options(self) -> mitm_options.Options:
        """构造 mitmproxy 选项（03 文档 T1.1：listen_host/port、confdir、mode）。"""
        mode_spec = _validate_mode(self.config.mode)
        return mitm_options.Options(
            listen_host=self.config.listen_host,
            listen_port=self.config.listen_port,
            confdir=str(self.config.resolved_confdir()),
            mode=[mode_spec],
            ssl_insecure=self.config.ssl_insecure,
        )

    def _apply_lazy_connection_strategy(self, master: DumpMaster) -> None:
        """``connection_strategy="lazy"``：上游连接尽可能延迟建立。

        保证 blocklist 域名在 CONNECT/SNI 阶段被 kill 时**完全不会**发起对目标的
        TCP 连接（02 文档 D5）。该选项由 proxyserver addon 在加载时注册，
        因此只能在 master 构造后设置。
        """
        try:
            master.options.update(connection_strategy="lazy")
        except KeyError:  # pragma: no cover - mitmproxy 未来版本变更选项名
            logger.warning("mitmproxy 无 connection_strategy 选项，保持默认")

    async def serve(self) -> None:
        """启动并阻塞直到 ``should_exit``（由 Ctrl+C 或 ``master.shutdown()`` 触发）。"""
        opts = self.build_options()
        # with_termlog/with_dumper 关闭：CLI 已自行渲染日志；测试进程无终端
        master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        self._apply_lazy_connection_strategy(master)
        master.addons.add(*self.addons)
        self.master = master
        logger.info(
            "capture engine: listen=%s:%d mode=%s confdir=%s",
            self.config.listen_host,
            self.config.listen_port,
            self.config.mode,
            self.config.resolved_confdir(),
        )
        await master.run()

    def run_blocking(self) -> None:
        """阻塞运行直到 Ctrl+C（优雅退出：DoneHook 在 ``asyncio.run`` 收尾时触发）。"""
        try:
            asyncio.run(self.serve())
        except KeyboardInterrupt:
            logger.info("收到 Ctrl+C，采集代理已优雅退出")


@dataclass
class ProxyHandle:
    """后台线程代理句柄（测试与嵌入场景）。"""

    engine: CaptureEngine
    thread: threading.Thread
    listen_host: str
    listen_port: int
    _error: list[BaseException] = field(default_factory=list)

    def stop(self, timeout: float = 15.0) -> None:
        """线程安全地请求代理退出并等待线程结束（可重复调用，幂等）。"""
        deadline = time.monotonic() + min(timeout, 5.0)
        while self.engine.master is None and time.monotonic() < deadline:
            if not self.thread.is_alive():
                break
            time.sleep(0.02)
        master = self.engine.master
        if master is not None and self.thread.is_alive():
            try:
                # master.shutdown() 线程安全（should_exit 置位）；线程恰好刚结束时
                # 事件循环已关闭，call_soon_threadsafe 会抛 RuntimeError——按已退出处理
                master.shutdown()
            except RuntimeError:
                logger.debug("capture proxy loop already closed; treat as stopped")
        if self.thread.is_alive():
            self.thread.join(timeout)
        if self.thread.is_alive():
            raise RuntimeError("capture proxy thread did not exit in time")
        if self._error:
            raise self._error[0]


def _port_accepts(host: str, port: int, timeout: float = 0.25) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def start_in_background(
    config: ProxyConfig,
    addons: Sequence[Any],
    *,
    wait_timeout: float = 30.0,
) -> ProxyHandle:
    """在后台线程中启动 CaptureEngine，端口可连接后返回句柄。"""
    engine = CaptureEngine(config, addons)
    error_box: list[BaseException] = []

    def _target() -> None:
        try:
            asyncio.run(engine.serve())
        except BaseException as exc:  # noqa: BLE001 - 需要把线程内异常带回主线程
            error_box.append(exc)
            if not isinstance(exc, asyncio.CancelledError):
                logger.exception("capture proxy thread crashed")

    thread = threading.Thread(target=_target, name="aaa-capture-proxy", daemon=True)
    thread.start()

    deadline = time.monotonic() + wait_timeout
    while time.monotonic() < deadline:
        if error_box:
            break
        if _port_accepts(config.listen_host, config.listen_port):
            return ProxyHandle(
                engine=engine,
                thread=thread,
                listen_host=config.listen_host,
                listen_port=config.listen_port,
                _error=error_box,
            )
        if not thread.is_alive():
            break
        time.sleep(0.05)
    detail = f"proxy did not become ready on {config.listen_host}:{config.listen_port}"
    if error_box:
        detail += f"; thread error: {error_box[0]!r}"
    raise RuntimeError(detail)


def paths_from_config(config: ProxyConfig) -> AppPaths:
    """由 ProxyConfig 解析出的运行时路径（CLI 与测试共用）。"""
    return resolve_paths(config.data_dir)
