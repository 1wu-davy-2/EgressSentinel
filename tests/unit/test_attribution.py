"""ProcessAttributor 单测（03 文档 T2.1）：注入假连接表与假进程读取器。"""

from __future__ import annotations

from typing import Any

import pytest

from aaa.attribution.table import (
    UNKNOWN_IDENTITY,
    ConnectionEntry,
    ProcessAttributor,
    ProcessIdentity,
    classify_profile,
)


class FakeConnectionTable:
    """按源端口 → PID 的假连接表。"""

    def __init__(self, mapping: dict[int, int] | None = None) -> None:
        self.mapping = dict(mapping or {})
        self.snapshot_calls = 0

    def snapshot(self) -> list[ConnectionEntry]:
        self.snapshot_calls += 1
        return [
            ConnectionEntry(laddr_port=port, raddr_port=443, pid=pid)
            for port, pid in self.mapping.items()
        ]


class FakeProcessReader:
    """PID → 进程元信息的假读取器（可配置抛异常）。"""

    def __init__(self, info: dict[int, ProcessIdentity] | None = None) -> None:
        self.info = dict(info or {})
        self.read_calls: list[int] = []

    def read(self, pid: int) -> ProcessIdentity:
        self.read_calls.append(pid)
        identity = self.info.get(pid)
        if identity is None:
            raise PermissionError(f"pid {pid} denied")
        return identity


def _identity(pid: int, **kw: Any) -> ProcessIdentity:
    return ProcessIdentity(pid=pid, **kw)


def test_attribute_resolves_pid_by_source_port() -> None:
    table = FakeConnectionTable({52341: 4242})
    reader = FakeProcessReader(
        {
            4242: _identity(
                4242,
                name="python.exe",
                exe=r"C:\Python\python.exe",
                cmdline=("python", "-m", "agent"),
                company="Python Software Foundation",
                profile="agent_cli",
            )
        }
    )
    attributor = ProcessAttributor(connection_table=table, process_reader=reader)  # type: ignore[arg-type]
    identity = attributor.attribute(("127.0.0.1", 52341))
    assert identity.pid == 4242
    assert identity.name == "python.exe"
    assert identity.cmdline == ("python", "-m", "agent")
    assert identity.company == "Python Software Foundation"
    assert identity.profile == "agent_cli"
    assert not identity.is_unknown
    assert attributor.stats.resolved == 1
    assert attributor.stats.unknown == 0


def test_attribute_miss_records_unknown_and_counts() -> None:
    attributor = ProcessAttributor(
        connection_table=FakeConnectionTable({}),  # type: ignore[arg-type]
        process_reader=FakeProcessReader(),  # type: ignore[arg-type]
    )
    for _ in range(3):
        identity = attributor.attribute(("127.0.0.1", 65000))
        assert identity.is_unknown
        assert identity is UNKNOWN_IDENTITY
        assert identity.profile == "unknown"
    assert attributor.stats.unknown == 3
    assert attributor.stats.resolved == 0
    assert attributor.stats.total == 3


def test_attribute_none_peername_is_unknown() -> None:
    attributor = ProcessAttributor(
        connection_table=FakeConnectionTable({1: 1}),  # type: ignore[arg-type]
        process_reader=FakeProcessReader(),  # type: ignore[arg-type]
    )
    identity = attributor.attribute(None)
    assert identity.is_unknown
    assert attributor.stats.unknown == 1


def test_pid_info_lru_cache() -> None:
    """同一 PID 只读一次进程信息；缓存淘汰遵循 LRU。"""
    table = FakeConnectionTable({100: 7, 200: 7})
    reader = FakeProcessReader({7: _identity(7, name="node.exe", exe="node.exe")})
    attributor = ProcessAttributor(
        connection_table=table,  # type: ignore[arg-type]
        process_reader=reader,  # type: ignore[arg-type]
        pid_cache_size=2,
    )
    attributor.attribute(("127.0.0.1", 100))
    attributor.attribute(("127.0.0.1", 200))  # 命中缓存（同 PID 7）
    assert reader.read_calls == [7]
    assert attributor.stats.pid_cache_hits == 1
    assert attributor.stats.pid_cache_misses == 1

    # 淘汰：插入两个新 PID，最早的 7 被逐出
    table.mapping = {300: 8, 400: 9}
    attributor.attribute(("127.0.0.1", 300))
    attributor.attribute(("127.0.0.1", 400))
    assert sorted(reader.read_calls) == [7, 8, 9]
    assert len(attributor._pid_cache) == 2  # noqa: SLF001 - 白盒断言 LRU 上限


def test_reader_failure_falls_back_to_pid_only() -> None:
    """进程信息读取失败（如 AccessDenied）→ 降级为仅 PID，仍算 resolved。"""
    attributor = ProcessAttributor(
        connection_table=FakeConnectionTable({100: 7}),  # type: ignore[arg-type]
        process_reader=FakeProcessReader(),  # type: ignore[arg-type]
    )
    identity = attributor.attribute(("127.0.0.1", 100))
    assert identity.pid == 7
    assert identity.name is None
    assert not identity.is_unknown
    assert attributor.stats.resolved == 1


def test_connection_table_crash_is_fail_open_unknown() -> None:
    class BoomTable:
        def snapshot(self) -> list[ConnectionEntry]:
            raise RuntimeError("table down")

    attributor = ProcessAttributor(connection_table=BoomTable(), process_reader=FakeProcessReader())  # type: ignore[arg-type]
    identity = attributor.attribute(("127.0.0.1", 100))
    assert identity.is_unknown
    assert attributor.stats.unknown == 1


def test_unknown_identity_to_process_info() -> None:
    info = UNKNOWN_IDENTITY.to_process_info()
    assert info.pid is None
    assert info.name == "unknown"
    assert info.profile == "unknown"


def test_identity_to_process_info_roundtrip() -> None:
    identity = _identity(
        5, name="n.exe", exe="n.exe", cmdline=("n",), company="C", profile="browser"
    )
    info = identity.to_process_info()
    assert info.pid == 5
    assert info.name == "n.exe"
    assert info.cmdline == ["n"]
    assert info.company == "C"
    assert info.profile == "browser"


@pytest.mark.parametrize(
    ("name", "exe", "expected"),
    [
        ("claude.exe", None, "agent_cli"),
        ("node.exe", None, "agent_cli"),
        ("python3.12.exe", None, "agent_cli"),
        ("chrome.exe", None, "browser"),
        ("msedge.EXE", None, "browser"),
        ("notepad.exe", None, "other"),
        (None, r"C:\tools\codex.exe", "agent_cli"),
        (None, None, "other"),
    ],
)
def test_classify_profile(name: str | None, exe: str | None, expected: str) -> None:
    assert classify_profile(name, exe) == expected


def test_from_psutil_tolerates_missing_fields() -> None:
    class FakeConn:
        laddr = None
        raddr = None
        pid = 9

    entry = ConnectionEntry.from_psutil(FakeConn())
    assert entry.laddr_port is None
    assert entry.raddr_port is None
    assert entry.pid == 9


# ------------------------------------------------------- local 模式 pinned 归因


class _FakePsutilProcess:
    def __init__(self, pid: int, name: str, exe: str | None) -> None:
        self.pid = pid
        self._name = name
        self._exe = exe
        self.info = {"name": name}

    def name(self) -> str:
        return self._name

    def exe(self) -> str:
        if self._exe is None:
            import psutil

            raise psutil.AccessDenied()
        return self._exe

    def cmdline(self) -> list[str]:
        return ["x", "--y"]


def test_resolve_pinned_process_none_inputs(monkeypatch) -> None:
    """--pid/--process 都未给：返回 None（回落连接表归因）。"""
    from aaa.attribution.table import resolve_pinned_process

    assert resolve_pinned_process(None, None) is None


def test_resolve_pinned_process_by_pid(monkeypatch) -> None:
    """local --pid：事件原生携带 PID + 进程元信息（03 文档 T2.2）。"""
    import psutil

    from aaa.attribution.table import resolve_pinned_process

    monkeypatch.setattr(
        psutil, "Process", lambda pid: _FakePsutilProcess(pid, "node.exe", r"C:\bin\node.exe")
    )
    info = resolve_pinned_process(pid=4242)
    assert info is not None
    assert info.pid == 4242
    assert info.name == "node.exe"
    assert info.exe == r"C:\bin\node.exe"
    assert info.cmdline == ["x", "--y"]
    assert info.profile == "agent_cli"


def test_resolve_pinned_process_exe_denied(monkeypatch) -> None:
    """exe 读取被拒：仍携带 pid/name（诚实降级）。"""
    import psutil

    from aaa.attribution.table import resolve_pinned_process

    monkeypatch.setattr(psutil, "Process", lambda pid: _FakePsutilProcess(pid, "agent.exe", None))
    info = resolve_pinned_process(pid=7)
    assert info is not None
    assert info.pid == 7
    assert info.exe is None


def test_resolve_pinned_process_by_name(monkeypatch) -> None:
    import psutil

    from aaa.attribution.table import resolve_pinned_process

    procs = [
        _FakePsutilProcess(10, "other.exe", "other.exe"),
        _FakePsutilProcess(30, "NODE.EXE", "node30.exe"),
        _FakePsutilProcess(20, "node.exe", "node20.exe"),
    ]
    monkeypatch.setattr(psutil, "process_iter", lambda attrs=None: procs)
    monkeypatch.setattr(
        psutil, "Process", lambda pid: _FakePsutilProcess(pid, "node.exe", f"node{pid}.exe")
    )
    info = resolve_pinned_process(name="Node.exe")
    assert info is not None
    assert info.pid == 20  # 多实例取最小 PID（确定性）

    # 未找到：仅携带进程名
    monkeypatch.setattr(psutil, "process_iter", lambda attrs=None: procs)
    missing = resolve_pinned_process(name="ghost.exe")
    assert missing is not None
    assert missing.pid is None
    assert missing.name == "ghost.exe"
