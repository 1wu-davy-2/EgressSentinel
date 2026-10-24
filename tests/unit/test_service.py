"""service 服务化单测：全部经 monkeypatch 的假 schtasks，绝不真实施改（06 文档 W1）。

覆盖：任务创建与 journal-first / ONSTART XML 内容 / 互斥提示（journal 与
任务存在双通道）/ 创建失败记录保留 / 还原与卸载幂等 / teardown 注册 / 状态查询。
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from aaa.setup import autostart as autostart_mod
from aaa.setup import service as service_mod
from aaa.setup import teardown as teardown_mod
from aaa.setup.state import StateFile


class FakeSchtasks:
    """记录调用的假 schtasks：模拟任务生命周期（Create 建号、Delete 删号、Query 查号）。"""

    def __init__(
        self, exists: set[str] | None = None, fail_create: bool = False
    ) -> None:
        self.calls: list[list[str]] = []
        self.exists = set(exists) if exists else set()
        self.fail_create = fail_create

    def __call__(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(args))
        if args[:2] == ["/Query", "/TN"]:
            ok = args[2] in self.exists
            return subprocess.CompletedProcess(args, 0 if ok else 1, "", "" if ok else "找不到")
        if args[0] == "/Create":
            if self.fail_create:
                return subprocess.CompletedProcess(args, 1, "", "拒绝访问")
            self.exists.add(args[2])
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[0] == "/Delete":
            ok = args[2] in self.exists
            self.exists.discard(args[2])
            return subprocess.CompletedProcess(args, 0 if ok else 1, "", "" if ok else "找不到")
        return subprocess.CompletedProcess(args, 0, "", "")

    def creates(self) -> list[list[str]]:
        return [c for c in self.calls if c[0] == "/Create"]

    def deletes(self) -> list[list[str]]:
        return [c for c in self.calls if c[0] == "/Delete"]


@pytest.fixture
def state(tmp_path: Path) -> StateFile:
    return StateFile(tmp_path / "setup-state.json")


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    return tmp_path / "data"


def test_install_creates_task_and_journals(
    monkeypatch: pytest.MonkeyPatch, state: StateFile, data_dir: Path
) -> None:
    fake = FakeSchtasks()
    monkeypatch.setattr(service_mod, "_run_schtasks", fake)
    result = service_mod.install_service(state, data_dir)

    assert result.task_name == service_mod.SERVICE_TASK_NAME
    assert result.entry.kind == service_mod.KIND_SERVICE_TASK
    assert result.entry.key == service_mod.SERVICE_TASK_NAME
    assert len(fake.creates()) == 1
    create = fake.creates()[0]
    assert create[:2] == ["/Create", "/TN"]
    assert create[2] == service_mod.SERVICE_TASK_NAME
    # XML 落盘且内容为 ONSTART 任务
    xml_path = data_dir / "tasks" / f"{service_mod.SERVICE_TASK_NAME}.xml"
    assert xml_path.exists()
    assert "<BootTrigger>" in xml_path.read_text(encoding="utf-16")
    # journal-first：恰好一条记录，元数据齐备
    entries = state.entries()
    assert len(entries) == 1
    meta = entries[0].new
    assert meta["task_name"] == service_mod.SERVICE_TASK_NAME
    assert meta["log_file"] == str(data_dir / service_mod.SERVICE_LOG_NAME)
    assert meta["run_level"] == "HIGHEST"


def test_install_failure_keeps_journal_for_retry(
    monkeypatch: pytest.MonkeyPatch, state: StateFile, data_dir: Path
) -> None:
    fake = FakeSchtasks(fail_create=True)
    monkeypatch.setattr(service_mod, "_run_schtasks", fake)
    with pytest.raises(service_mod.ServiceError, match="拒绝访问"):
        service_mod.install_service(state, data_dir)
    # journal-first：创建失败记录保留，teardown/重试可用
    assert len(state.entries()) == 1
    assert state.entries()[0].kind == service_mod.KIND_SERVICE_TASK


def test_service_xml_content(
    monkeypatch: pytest.MonkeyPatch, state: StateFile, data_dir: Path
) -> None:
    monkeypatch.setattr(service_mod, "_run_schtasks", FakeSchtasks())
    service_mod.install_service(state, data_dir)
    xml = (data_dir / "tasks" / f"{service_mod.SERVICE_TASK_NAME}.xml").read_text(encoding="utf-16")
    assert "<BootTrigger><Enabled>true</Enabled></BootTrigger>" in xml  # ONSTART 触发
    assert f"<UserId>{service_mod.SYSTEM_SID}</UserId>" in xml  # SYSTEM 账户
    assert "<RunLevel>HighestAvailable</RunLevel>" in xml  # 默认 /RL HIGHEST
    assert "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>" in xml  # 服务常驻不限时
    assert "run --data-dir" in xml

    # /RL HIGHEST 为可选参数：highest=False → LeastPrivilege
    limited = service_mod.build_service_task_xml("pythonw.exe", ["-c", "x"], highest=False)
    assert "<RunLevel>LeastPrivilege</RunLevel>" in limited


def test_service_command_reuses_interpreter_strategy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # 非 frozen：venv 策略（pythonw 不存在于测试环境 → 退回当前解释器）
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    command, args = service_mod.service_command(tmp_path)
    assert command in (str(sys.executable), str(Path(sys.executable).with_name("pythonw.exe")))
    assert args[0] == "-c"
    assert "run" in args
    assert args[args.index("--log-file") + 1] == str(tmp_path / service_mod.SERVICE_LOG_NAME)

    # frozen：cmd start /min 最小化隐藏运行
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    command, args = service_mod.service_command(tmp_path)
    assert command == "cmd.exe"
    assert args[:3] == ["/c", "start", ""]
    assert "/min" in args


def test_conflict_warning_with_journaled_login_tasks(
    monkeypatch: pytest.MonkeyPatch, state: StateFile, data_dir: Path
) -> None:
    fake = FakeSchtasks()
    monkeypatch.setattr(service_mod, "_run_schtasks", fake)
    # setup 曾装过两个登录任务（journal 有记录）
    state.record(
        kind=autostart_mod.KIND_AUTOSTART_TASK, key=autostart_mod.AUTOSTART_TASK_NAME
    )
    state.record(
        kind=autostart_mod.KIND_WATCHDOG_TASK, key=autostart_mod.WATCHDOG_TASK_NAME
    )
    result = service_mod.install_service(state, data_dir)
    joined = "\n".join(result.warnings)
    assert autostart_mod.AUTOSTART_TASK_NAME in joined
    assert autostart_mod.WATCHDOG_TASK_NAME in joined
    assert "aaa teardown autostart" in joined  # 给出关闭登录任务的指引
    # 提示不阻断：任务照常创建
    assert len(fake.creates()) == 1


def test_conflict_warning_with_existing_tasks_only(
    monkeypatch: pytest.MonkeyPatch, state: StateFile, data_dir: Path
) -> None:
    # journal 无记录，但用户手动装过登录任务（schtasks /Query 命中）
    fake = FakeSchtasks(exists={autostart_mod.AUTOSTART_TASK_NAME})
    monkeypatch.setattr(service_mod, "_run_schtasks", fake)
    result = service_mod.install_service(state, data_dir)
    assert len(result.warnings) == 1
    assert autostart_mod.AUTOSTART_TASK_NAME in result.warnings[0]


def test_no_warning_when_clean(
    monkeypatch: pytest.MonkeyPatch, state: StateFile, data_dir: Path
) -> None:
    monkeypatch.setattr(service_mod, "_run_schtasks", FakeSchtasks())
    result = service_mod.install_service(state, data_dir)
    assert result.warnings == []


def test_uninstall_is_idempotent(
    monkeypatch: pytest.MonkeyPatch, state: StateFile, data_dir: Path
) -> None:
    fake = FakeSchtasks()
    monkeypatch.setattr(service_mod, "_run_schtasks", fake)
    service_mod.install_service(state, data_dir)
    assert service_mod.uninstall_service(state) is True
    assert state.entries() == []
    assert len(fake.deletes()) == 1
    # 再删一次：幂等 no-op（不报错、journal 仍空）；schtasks 层仍会尝试 /Delete
    assert service_mod.uninstall_service(state) is False
    assert state.entries() == []


def test_restore_service_tolerates_missing(
    monkeypatch: pytest.MonkeyPatch, state: StateFile
) -> None:
    fake = FakeSchtasks()  # Query/Delete 全部「不存在」
    monkeypatch.setattr(service_mod, "_run_schtasks", fake)
    entry = state.record(
        kind=service_mod.KIND_SERVICE_TASK,
        key=service_mod.SERVICE_TASK_NAME,
        new={"task_name": service_mod.SERVICE_TASK_NAME},
    )
    service_mod.restore_service(state, entry)  # 不抛异常
    assert state.entries() == []


def test_restorer_registered_and_teardown_restores_service(
    monkeypatch: pytest.MonkeyPatch, state: StateFile, data_dir: Path
) -> None:
    assert (
        teardown_mod.RESTORERS[service_mod.KIND_SERVICE_TASK] is service_mod.restore_service
    )
    fake = FakeSchtasks()
    monkeypatch.setattr(service_mod, "_run_schtasks", fake)
    service_mod.install_service(state, data_dir)
    report = teardown_mod.run_teardown(state.path, kinds={service_mod.KIND_SERVICE_TASK})
    assert report.ok, report.errors
    assert report.restored == [f"{service_mod.KIND_SERVICE_TASK}:{service_mod.SERVICE_TASK_NAME}"]
    assert len(fake.deletes()) == 1
    assert state.entries() == []


def test_service_status_before_and_after_install(
    monkeypatch: pytest.MonkeyPatch, state: StateFile, data_dir: Path
) -> None:
    fake = FakeSchtasks()
    monkeypatch.setattr(service_mod, "_run_schtasks", fake)

    # 未安装：全空状态
    status = service_mod.service_status(state)
    assert status.task_exists is False
    assert status.journaled is False
    assert status.command is None
    assert status.log_file is None
    assert status.conflict is False
    assert status.warnings == []

    # 安装后：任务存在 + journal 有记录 + 命令行/日志路径就绪
    service_mod.install_service(state, data_dir)
    status = service_mod.service_status(state)
    assert status.task_exists is True
    assert status.journaled is True
    assert status.task_name == service_mod.SERVICE_TASK_NAME
    assert status.command is not None
    assert Path(status.command).name in ("pythonw.exe", "python.exe", "cmd.exe")
    assert status.log_file == data_dir / service_mod.SERVICE_LOG_NAME
    assert status.conflict is False

    # 装完服务后又出现登录任务 → conflict + 提示（状态查询只读，不改状态）
    state.record(
        kind=autostart_mod.KIND_AUTOSTART_TASK, key=autostart_mod.AUTOSTART_TASK_NAME
    )
    status = service_mod.service_status(state)
    assert status.conflict is True
    assert any(autostart_mod.AUTOSTART_TASK_NAME in w for w in status.warnings)
    assert len(state.entries()) == 2  # 状态查询未产生新记录
