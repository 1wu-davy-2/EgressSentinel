"""代理设置单测（03 文档 T1.4）。

红线：注册表与 netsh 全部走假实现（注入），绝不真实施改系统代理设置。
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from aaa.setup import proxy
from aaa.setup.state import StateFile


@pytest.fixture
def fake_wininet(monkeypatch: pytest.MonkeyPatch) -> tuple[dict[str, object], list[bool]]:
    """内存注册表 + 刷新记录器。"""
    registry: dict[str, object] = {}
    monkeypatch.setattr(proxy, "_reg_read", lambda name: registry.get(name))
    monkeypatch.setattr(proxy, "_reg_write", lambda name, value: registry.__setitem__(name, value))
    monkeypatch.setattr(proxy, "_reg_delete", lambda name: registry.pop(name, None))
    refreshed: list[bool] = []
    monkeypatch.setattr(proxy, "refresh_wininet", lambda: refreshed.append(True))
    return registry, refreshed


def _ok(cmd: list[str], stdout: bytes = b"Ok.\n") -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(cmd, 0, stdout, b"")


def test_apply_user_proxy_sets_and_records_old_values(
    fake_wininet: tuple[dict[str, object], list[bool]], tmp_path: Path
) -> None:
    registry, refreshed = fake_wininet
    registry["ProxyEnable"] = 0
    registry["ProxyServer"] = "old-proxy:3128"
    state = StateFile(tmp_path / "setup-state.json")

    entry = proxy.apply_user_proxy(state, "127.0.0.1", 8080)

    assert registry["ProxyEnable"] == 1
    assert registry["ProxyServer"] == "127.0.0.1:8080"
    assert registry["ProxyOverride"] == "<local>;localhost;127.0.0.1"
    assert refreshed == [True]
    assert entry.old == {"ProxyEnable": 0, "ProxyServer": "old-proxy:3128", "ProxyOverride": None}
    assert entry.kind == proxy.KIND_WININET
    assert entry.ts  # 时间戳已记录
    (recorded,) = state.entries()
    assert recorded.key == proxy.WININET_KEY


def test_restore_user_proxy_restores_old_and_drops_entry(
    fake_wininet: tuple[dict[str, object], list[bool]], tmp_path: Path
) -> None:
    registry, refreshed = fake_wininet
    registry["ProxyEnable"] = 0
    registry["ProxyServer"] = "old-proxy:3128"
    state = StateFile(tmp_path / "setup-state.json")
    entry = proxy.apply_user_proxy(state, "127.0.0.1", 8080)

    proxy.restore_user_proxy(state, entry)

    assert registry["ProxyEnable"] == 0
    assert registry["ProxyServer"] == "old-proxy:3128"
    assert "ProxyOverride" not in registry  # 原先不存在 → 删除
    assert len(refreshed) == 2  # 设置与还原各刷新一次
    assert state.entries() == []


WINHTTP_SHOW_PROXY = (
    "Current WinHTTP proxy settings:\n\n"
    "    Proxy Server(s) :  10.0.0.1:8888\n"
    "    Bypass List     :  foo.local\n"
)
WINHTTP_SHOW_DIRECT = "Current WinHTTP proxy settings:\n\n    Direct access (no proxy server).\n"


def test_parse_winhttp_show() -> None:
    assert proxy.parse_winhttp_show(WINHTTP_SHOW_PROXY) == {
        "direct": False,
        "server": "10.0.0.1:8888",
        "bypass": "foo.local",
    }
    assert proxy.parse_winhttp_show(WINHTTP_SHOW_DIRECT)["direct"] is True


def test_apply_winhttp_proxy_records_old_output(tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def fake_runner(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(cmd)
        is_show = cmd[-1] == "proxy" and cmd[-2] == "show"
        stdout = WINHTTP_SHOW_PROXY.encode() if is_show else b"Ok.\n"
        return _ok(cmd, stdout)

    state = StateFile(tmp_path / "setup-state.json")
    entry = proxy.apply_winhttp_proxy(state, "127.0.0.1", 8080, runner=fake_runner)

    assert calls[0] == ["netsh", "winhttp", "show", "proxy"]
    assert calls[1][:4] == ["netsh", "winhttp", "set", "proxy"]
    assert entry.old["server"] == "10.0.0.1:8888"  # type: ignore[index]
    assert entry.old["raw"] == WINHTTP_SHOW_PROXY  # type: ignore[index]


def test_restore_winhttp_direct_resets(tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def fake_runner(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(cmd)
        return _ok(cmd, WINHTTP_SHOW_DIRECT.encode() if cmd[-2:-1] == ["show"] else b"Ok.\n")

    state = StateFile(tmp_path / "setup-state.json")
    entry = proxy.apply_winhttp_proxy(state, "127.0.0.1", 8080, runner=fake_runner)
    proxy.restore_winhttp_proxy(state, entry, runner=fake_runner)
    assert calls[-1] == ["netsh", "winhttp", "reset", "proxy"]
    assert state.entries() == []


def test_restore_winhttp_with_old_server(tmp_path: Path) -> None:
    commands: list[list[str]] = []

    def fake_runner(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        commands.append(list(cmd))
        if cmd[-2:-1] == ["show"]:
            return _ok(cmd, WINHTTP_SHOW_PROXY.encode())
        return _ok(cmd)

    state = StateFile(tmp_path / "setup-state.json")
    entry = proxy.apply_winhttp_proxy(state, "127.0.0.1", 8080, runner=fake_runner)
    proxy.restore_winhttp_proxy(state, entry, runner=fake_runner)
    assert commands[-1][:4] == ["netsh", "winhttp", "set", "proxy"]
    assert any("proxy-server=10.0.0.1:8888" in part for part in commands[-1])


def test_restore_winhttp_unparseable_raises(tmp_path: Path) -> None:
    state = StateFile(tmp_path / "setup-state.json")
    unparseable = {
        "raw": "本地化的输出，无法解析",
        "direct": False,
        "server": None,
        "bypass": None,
    }
    entry = state.record(kind=proxy.KIND_WINHTTP, key="winhttp", old=unparseable)
    with pytest.raises(proxy.ProxySetupError, match="人工"):
        proxy.restore_winhttp_proxy(state, entry, runner=lambda *a, **k: _ok(list(a[0])))  # type: ignore[arg-type,return-value]
    assert state.entries()  # 记录保留


def test_apply_user_proxy_keeps_journal_on_failure(
    fake_wininet: tuple[dict[str, object], list[bool]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """journal-first：写入失败时记录保留，teardown 仍可安全还原。"""
    registry, _refreshed = fake_wininet

    def broken_write(name: str, value: object) -> None:
        raise OSError("registry locked")

    monkeypatch.setattr(proxy, "_reg_write", broken_write)
    state = StateFile(tmp_path / "setup-state.json")
    with pytest.raises(proxy.ProxySetupError):
        proxy.apply_user_proxy(state, "127.0.0.1", 8080)
    assert len(state.entries()) == 1
