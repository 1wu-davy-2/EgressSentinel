"""连接表反查 PID + 进程元信息 LRU 缓存（02 文档 D2，03 文档 T2.1）。

归因策略（02 文档 D2）：
- regular 模式在 ``client_connected`` 钩子取 ``client_conn.peername`` 的源端口，
  **立即**查 ``psutil.net_connections(kind='inet')`` 快照反查 PID（源端口在 TCP
  生命周期内稳定，快照级延迟可接受）；
- PID→进程元信息（exe/命令行/公司/画像）经 LRU 缓存；
- 查不到记 ``unknown`` 并计数（明确不承诺 100% 归因，短连接竞态与权限是已知边界）。

依赖注入：``ConnectionTable`` 与 ``ProcessInfoReader`` 都是窄接口，单测注入假实现，
不需要真实网络连接与真实进程。
"""

from __future__ import annotations

import ctypes
import logging
import os
import re
from collections import OrderedDict
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from aaa.store.events import ProcessInfo

logger = logging.getLogger(__name__)

# 进程画像内置默认规则（与 02 文档 §5 processes.profiles 初始值一致）
_PROFILE_AGENT_CLI = re.compile(r"(?i)(claude|cursor|codex|copilot|node|python|java)")
_PROFILE_BROWSER = re.compile(r"(?i)(chrome|msedge|firefox)\.exe$")

UNKNOWN_NAME = "unknown"
UNKNOWN_PROFILE = "unknown"
OTHER_PROFILE = "other"


@dataclass(frozen=True)
class ProcessIdentity:
    """归因结果：PID + 进程元信息；``pid is None`` 表示未归因（unknown）。"""

    pid: int | None = None
    name: str | None = None
    exe: str | None = None
    cmdline: tuple[str, ...] | None = None
    company: str | None = None
    profile: str = UNKNOWN_PROFILE

    @property
    def is_unknown(self) -> bool:
        return self.pid is None

    def to_process_info(self) -> ProcessInfo:
        """转事件模型 ``ProcessInfo``（unknown 也显式落事件）。"""
        return ProcessInfo(
            pid=self.pid,
            name=self.name or (UNKNOWN_NAME if self.is_unknown else None),
            exe=self.exe,
            cmdline=list(self.cmdline) if self.cmdline is not None else None,
            company=self.company,
            profile=self.profile,
        )


#: 未归因（unknown）的哨兵值
UNKNOWN_IDENTITY = ProcessIdentity()


def classify_profile(name: str | None, exe: str | None) -> str:
    """按进程名/exe 做画像分类（agent_cli / browser / other，02 文档 §5 默认值）。"""
    for candidate in (name, exe):
        if not candidate:
            continue
        if _PROFILE_AGENT_CLI.search(candidate):
            return "agent_cli"
        if _PROFILE_BROWSER.search(candidate):
            return "browser"
    return OTHER_PROFILE


# --------------------------------------------------------------------- 连接表


@dataclass(frozen=True)
class ConnectionEntry:
    """``psutil.net_connections`` 单条记录的窄视图（只保留归因所需字段）。"""

    laddr_port: int | None
    raddr_port: int | None
    pid: int | None

    @classmethod
    def from_psutil(cls, conn: Any) -> ConnectionEntry:
        """从 psutil sconn 对象提取端口与 PID（容忍 addr 缺失/None）。"""
        laddr = getattr(conn, "laddr", None)
        raddr = getattr(conn, "raddr", None)
        lport = getattr(laddr, "port", None) if laddr else None
        rport = getattr(raddr, "port", None) if raddr else None
        return cls(laddr_port=lport, raddr_port=rport, pid=getattr(conn, "pid", None))


class ConnectionTable(Protocol):
    """连接表快照接口（可注入假实现）。"""

    def snapshot(self) -> Sequence[ConnectionEntry]:
        """返回当前连接表快照。"""
        ...


class PsutilConnectionTable:
    """默认实现：``psutil.net_connections(kind)``（Windows 普通用户可用）。"""

    def __init__(self, kind: str = "inet") -> None:
        self._kind = kind

    def snapshot(self) -> Sequence[ConnectionEntry]:
        import psutil  # 延迟导入：保持模块可移植、加速测试收集

        return [ConnectionEntry.from_psutil(conn) for conn in psutil.net_connections(self._kind)]


# ---------------------------------------------------------------- 进程信息读取


class ProcessInfoReader(Protocol):
    """PID → 进程元信息接口（可注入假实现）。"""

    def read(self, pid: int) -> ProcessIdentity:
        """读取进程元信息；读不到信息时抛异常由调用方兜底。"""
        ...


class PsutilProcessInfoReader:
    """默认实现：psutil 取 name/exe/cmdline，公司名取 exe 版本信息，画像内置规则。"""

    def __init__(
        self,
        company_reader: Callable[[str], str | None] | None = None,
    ) -> None:
        self._company_reader = company_reader or read_file_company

    def read(self, pid: int) -> ProcessIdentity:
        import psutil  # 延迟导入

        proc = psutil.Process(pid)
        name = proc.name()
        try:
            exe = proc.exe()
        except psutil.Error:
            exe = None
        try:
            cmdline = tuple(proc.cmdline())
        except psutil.Error:
            cmdline = None
        company = self._company_reader(exe) if exe else None
        return ProcessIdentity(
            pid=pid,
            name=name,
            exe=exe,
            cmdline=cmdline or None,
            company=company,
            profile=classify_profile(name, exe),
        )


def read_file_company(exe_path: str) -> str | None:
    """读 exe 的 ``CompanyName`` 版本信息（Windows version API，只读文件、无弹窗）。

    非 Windows 或任何失败返回 ``None``（公司名是尽力而为字段）。
    """
    if os.name != "nt" or not exe_path:
        return None
    try:
        return _read_company_via_version_api(exe_path)
    except Exception:  # noqa: BLE001 - 版本信息读取任何失败都按缺失处理
        logger.debug("读取版本信息失败: %s", exe_path, exc_info=True)
        return None


def _read_company_via_version_api(exe_path: str) -> str | None:
    version = ctypes.windll.version  # type: ignore[attr-defined]
    size = version.GetFileVersionInfoSizeW(exe_path, None)
    if not size:
        return None
    data = ctypes.create_string_buffer(size)
    if not version.GetFileVersionInfoW(exe_path, 0, size, data):
        return None
    # \VarFileInfo\Translation: N 个 (lang_id, codepage) 二元组，各 2 字节
    ptr = ctypes.c_void_p()
    length = ctypes.c_uint()
    if not version.VerQueryValueW(
        data, r"\VarFileInfo\Translation", ctypes.byref(ptr), ctypes.byref(length)
    ):
        return None
    if not ptr.value or length.value < 4:
        return None
    words = (ctypes.c_uint16 * (length.value // 2)).from_address(ptr.value)
    lang_id, codepage = words[0], words[1]
    sub_block = rf"\StringFileInfo\{lang_id:04x}{codepage:04x}\CompanyName"
    val_ptr = ctypes.c_void_p()
    val_len = ctypes.c_uint()
    if version.VerQueryValueW(data, sub_block, ctypes.byref(val_ptr), ctypes.byref(val_len)):
        if val_ptr.value and val_len.value:
            return ctypes.wstring_at(val_ptr) or None
    return None


# -------------------------------------------------------------------- 归因器


@dataclass
class AttributionStats:
    """归因计数（unknown 速率告警的数据来源，02 文档 D2）。"""

    total: int = 0
    resolved: int = 0
    unknown: int = 0
    pid_cache_hits: int = 0
    pid_cache_misses: int = 0


@dataclass
class ProcessAttributor:
    """peername 源端口 → PID → 进程元信息（LRU）的归因器（03 文档 T2.1）。

    ``client_connected`` 时调用 ``attribute(client.peername)``；未命中返回
    ``UNKNOWN_IDENTITY`` 并计数。连接表与进程读取器均可注入（单测不打真实网络）。
    """

    connection_table: ConnectionTable = field(default_factory=PsutilConnectionTable)
    process_reader: ProcessInfoReader = field(default_factory=PsutilProcessInfoReader)
    pid_cache_size: int = 1024

    def __post_init__(self) -> None:
        self._pid_cache: OrderedDict[int, ProcessIdentity] = OrderedDict()
        self.stats = AttributionStats()

    def attribute(self, peername: Sequence[int] | None) -> ProcessIdentity:
        """用 client 源端口查连接表反查 PID；未命中记 unknown 并计数。

        任何异常都按 unknown 处理（fail-open，不崩代理进程）。
        """
        self.stats.total += 1
        try:
            port = peername[1] if peername else None
            pid = self._find_pid_by_source_port(int(port)) if port else None
            if pid is None:
                self.stats.unknown += 1
                return UNKNOWN_IDENTITY
            identity = self._pid_info(pid)
            self.stats.resolved += 1
            return identity
        except Exception:  # noqa: BLE001 - 归因异常不传播（03 文档 §3 错误处理）
            logger.exception("进程归因异常（按 unknown 处理）")
            self.stats.unknown += 1
            return UNKNOWN_IDENTITY

    def _find_pid_by_source_port(self, port: int) -> int | None:
        for entry in self.connection_table.snapshot():
            if entry.laddr_port == port and entry.pid is not None:
                return entry.pid
        return None

    def _pid_info(self, pid: int) -> ProcessIdentity:
        cached = self._pid_cache.get(pid)
        if cached is not None:
            self._pid_cache.move_to_end(pid)
            self.stats.pid_cache_hits += 1
            return cached
        self.stats.pid_cache_misses += 1
        identity = self._read_identity(pid)
        self._pid_cache[pid] = identity
        while len(self._pid_cache) > self.pid_cache_size:
            self._pid_cache.popitem(last=False)
        return identity

    def _read_identity(self, pid: int) -> ProcessIdentity:
        """读取进程元信息；读取失败（如权限不足）降级为"仅 PID 已知"。"""
        try:
            return self.process_reader.read(pid)
        except Exception:  # noqa: BLE001 - psutil.Error 等 → 只保留 PID
            logger.debug("进程 %s 元信息读取失败，降级为仅 PID", pid, exc_info=True)
            return ProcessIdentity(pid=pid, profile=UNKNOWN_PROFILE)


def resolve_pinned_process(pid: int | None = None, name: str | None = None) -> ProcessInfo | None:
    """local 模式 ``--pid/--process`` 的事件原生归因（03 文档 T2.2）。

    ``local:pid=N``/``local:process=name`` 规格由 mitmproxy_rs 在包层过滤，
    捕获到的流量天然属于该进程；这里把该进程元信息解析出来供事件直接携带。
    两者都未给返回 ``None``（回落到连接表归因）。
    """
    if pid is None and name is None:
        return None
    import psutil

    if pid is not None:
        try:
            proc = psutil.Process(pid)
            pname = proc.name()
            try:
                exe: str | None = proc.exe()
            except psutil.Error:
                exe = None
            try:
                cmdline: list[str] | None = proc.cmdline() or None
            except psutil.Error:
                cmdline = None
            return ProcessInfo(
                pid=pid,
                name=pname or name,
                exe=exe,
                cmdline=cmdline,
                company=read_file_company(exe) if exe else None,
                profile=classify_profile(pname, exe),
            )
        except psutil.NoSuchProcess:
            logger.warning("local --pid=%s 进程不存在，事件仅携带 PID", pid)
            return ProcessInfo(pid=pid, name=name, profile=UNKNOWN_PROFILE)
    # 按进程名匹配（大小写不敏感精确匹配；多实例取 PID 最小者保证确定性）
    target = (name or "").lower()
    best: psutil.Process | None = None
    for proc in psutil.process_iter(["name"]):
        try:
            pname = proc.info.get("name") or ""
        except psutil.Error:  # pragma: no cover - 进程瞬时消失
            continue
        if pname.lower() == target and (best is None or proc.pid < best.pid):
            best = proc
    if best is None:
        logger.warning("local --process=%s 未找到进程，事件仅携带进程名", name)
        return ProcessInfo(pid=None, name=name, profile=UNKNOWN_PROFILE)
    return resolve_pinned_process(pid=best.pid)
