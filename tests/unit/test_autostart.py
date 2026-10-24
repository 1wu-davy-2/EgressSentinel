"""autostart 计划任务单测：全部经 monkeypatch 的假 schtasks，绝不真实施改。"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from aaa.setup import autostart as autostart_mod
from aaa.setup import teardown as teardown_mod
from aaa.setup.state import StateFile


class FakeSchtasks:
    """记录调用的假 schtasks；Query 可配置存在性。"""

    def __init__(self, exists: set[str] | None = None) -> None:
        self.calls: list[list[str]] = []
        self.exists = exists or set()

    def __call__(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(args))
        if args[:2] == ["/Query", "/TN"]:
            ok = args[2] in self.exists
            return subprocess.CompletedProcess(args, 0 if ok else 1, "", "" if ok else "找不到")
        return subprocess.CompletedProcess(args, 0, "", "")


@pytest.fixture
def state(tmp_path: Path) -> StateFile:
    return StateFile(tmp_path / "setup-state.json")


def test_enable_autostart_creates_two_tasks_and_journals(
    monkeypatch: pytest.MonkeyPatch, state: StateFile, tmp_path: Path
) -> None:
    fake = FakeSchtasks()
    monkeypatch.setattr(autostart_mod, "_run_schtasks", fake)
    entries = autostart_mod.enable_autostart(state, tmp_path / "data")

    assert [e.kind for e in entries] == [
        autostart_mod.KIND_AUTOSTART_TASK,
        autostart_mod.KIND_WATCHDOG_TASK,
    ]
    creates = [c for c in fake.calls if c[0] == "/Create"]
    assert len(creates) == 2
    assert {c[2] for c in creates} == {
        autostart_mod.AUTOSTART_TASK_NAME,
        autostart_mod.WATCHDOG_TASK_NAME,
    }
    # journal-first：记录在案，可 teardown
    assert len(state.entries()) == 2


def test_task_xml_content(state: StateFile, tmp_path: Path) -> None:
    xml = autostart_mod.build_task_xml("C:\\x\\pythonw.exe", ["-c", "main()", "run"])
    assert "<LogonTrigger>" in xml
    assert "<Delay>" not in xml  # 无延迟
    assert "C:\\x\\pythonw.exe" in xml
    assert "main() run" in xml.replace("  ", " ") or "main()" in xml

    delayed = autostart_mod.build_task_xml(
        "cmd.exe", ["/c", "x"], delay_seconds=autostart_mod.WATCHDOG_DELAY_SECONDS
    )
    assert f"PT{autostart_mod.WATCHDOG_DELAY_SECONDS}S</Delay>" in delayed
    assert "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>" in delayed


def test_enable_failure_keeps_journal_for_retry(
    monkeypatch: pytest.MonkeyPatch, state: StateFile, tmp_path: Path
) -> None:
    def failing(args: list[str]) -> subprocess.CompletedProcess[str]:
        if args[0] == "/Create":
            return subprocess.CompletedProcess(args, 1, "", "拒绝访问")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(autostart_mod, "_run_schtasks", failing)
    with pytest.raises(autostart_mod.AutostartError):
        autostart_mod.enable_autostart(state, tmp_path / "data")
    # journal-first：创建失败记录保留，teardown/重试可用
    assert len(state.entries()) >= 1


def test_disable_is_idempotent(
    monkeypatch: pytest.MonkeyPatch, state: StateFile, tmp_path: Path
) -> None:
    fake = FakeSchtasks()
    monkeypatch.setattr(autostart_mod, "_run_schtasks", fake)
    autostart_mod.enable_autostart(state, tmp_path / "data")
    removed = autostart_mod.disable_autostart(state)
    assert set(removed) == {autostart_mod.AUTOSTART_TASK_NAME, autostart_mod.WATCHDOG_TASK_NAME}
    assert state.entries() == []
    # 再删一次：幂等 no-op
    assert autostart_mod.disable_autostart(state) == []


def test_teardown_restores_tasks(
    monkeypatch: pytest.MonkeyPatch, state: StateFile, tmp_path: Path
) -> None:
    fake = FakeSchtasks()
    monkeypatch.setattr(autostart_mod, "_run_schtasks", fake)
    autostart_mod.enable_autostart(state, tmp_path / "data")
    kinds = teardown_mod.teardown_target_kinds(("autostart",))
    report = teardown_mod.run_teardown(state.path, kinds=kinds)
    assert report.ok, report.errors
    assert len(report.restored) == 2
    deletes = [c for c in fake.calls if c[0] == "/Delete"]
    assert len(deletes) == 2


def test_restore_scheduled_task_tolerates_missing(
    monkeypatch: pytest.MonkeyPatch, state: StateFile, tmp_path: Path
) -> None:
    fake = FakeSchtasks()  # Query/Delete 全部「不存在」
    monkeypatch.setattr(autostart_mod, "_run_schtasks", fake)
    entry = state.record(
        kind=autostart_mod.KIND_AUTOSTART_TASK,
        key=autostart_mod.AUTOSTART_TASK_NAME,
        new={"task_name": autostart_mod.AUTOSTART_TASK_NAME},
    )
    autostart_mod.restore_scheduled_task(state, entry)  # 不抛异常
    assert state.entries() == []
