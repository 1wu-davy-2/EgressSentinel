"""watchdog 自检单测：端口探测与 teardown 全注入，绝不触网、绝不真实施改。"""

from __future__ import annotations

from pathlib import Path

from aaa.setup import watchdog as watchdog_mod
from aaa.setup.proxy import KIND_WININET
from aaa.setup.state import StateFile


class FakeTeardown:
    def __init__(self) -> None:
        self.calls: list[Path | None] = []

    def __call__(self, state_file: Path, *, kinds=None, dry_run: bool = False):  # noqa: ANN001
        from aaa.setup.teardown import TeardownReport

        self.calls.append(state_file)
        self.last_kinds = kinds
        report = TeardownReport()
        report.restored = ["wininet:Internet Settings", "env_var:HTTP_PROXY"]
        return report


def _record_proxy(state: StateFile) -> None:
    state.record(
        kind=KIND_WININET,
        key="Internet Settings",
        old={"ProxyEnable": 0},
        new={"ProxyEnable": 1, "ProxyServer": "127.0.0.1:18080", "ProxyOverride": "<local>"},
    )


def test_idle_when_no_proxy_entries(tmp_path: Path) -> None:
    report = watchdog_mod.run_watchdog(
        tmp_path / "state.json", _port_open=lambda *_: True, _teardown=FakeTeardown()
    )
    assert report.status == "idle"
    assert (tmp_path / "watchdog.log").exists()


def test_ok_when_port_reachable(tmp_path: Path) -> None:
    state = StateFile(tmp_path / "state.json")
    _record_proxy(state)
    report = watchdog_mod.run_watchdog(
        state.path, wait_seconds=0, _port_open=lambda *_: True, _teardown=FakeTeardown()
    )
    assert report.status == "ok"
    assert "127.0.0.1:18080" in report.detail


def test_degraded_reports_without_fix(tmp_path: Path) -> None:
    state = StateFile(tmp_path / "state.json")
    _record_proxy(state)
    fake_teardown = FakeTeardown()
    report = watchdog_mod.run_watchdog(
        state.path,
        fix=False,
        wait_seconds=0,
        _port_open=lambda *_: False,
        _teardown=fake_teardown,
    )
    assert report.status == "degraded"
    assert not fake_teardown.calls  # 未授权绝不自动改系统
    assert "断网" in report.detail


def test_fix_restores_network_kinds(tmp_path: Path) -> None:
    state = StateFile(tmp_path / "state.json")
    _record_proxy(state)
    fake_teardown = FakeTeardown()
    report = watchdog_mod.run_watchdog(
        state.path, fix=True, wait_seconds=0, _port_open=lambda *_: False, _teardown=fake_teardown
    )
    assert report.status == "recovered"
    assert fake_teardown.calls == [state.path]
    # 只还原网络相关（代理 + 代理环境变量），CA 不动
    assert fake_teardown.last_kinds == set(watchdog_mod.NETWORK_KINDS)
    assert "wininet:Internet Settings" in report.actions


def test_wait_loop_survives_logon_race(tmp_path: Path) -> None:
    """登录竞态：前两次探测失败、端口随后打开 → 判 ok（不误还原）。"""
    state = StateFile(tmp_path / "state.json")
    _record_proxy(state)
    fake_teardown = FakeTeardown()
    probes = {"n": 0}

    def flaky(_host: str, _port: int) -> bool:
        probes["n"] += 1
        return probes["n"] >= 3

    report = watchdog_mod.run_watchdog(
        state.path, fix=True, wait_seconds=3.0, _port_open=flaky, _teardown=fake_teardown
    )
    assert report.status == "ok"
    assert not fake_teardown.calls
    assert probes["n"] == 3


def test_proxy_endpoint_parsing() -> None:
    state = StateFile(Path("unused"))
    entries = state.load().entries  # 空状态
    assert watchdog_mod.proxy_endpoint(entries) is None
