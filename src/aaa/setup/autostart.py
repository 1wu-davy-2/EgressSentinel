"""开机自启计划任务（用户需求：默认随登录启动 aaa run + 看门狗自检任务）。

- 两个计划任务（当前用户级、登录触发）：
  - ``EgressSentinel-AutoStart``：启动 ``aaa run``（venv 用 pythonw 无窗口；
    frozen exe 经 ``cmd start /min`` 最小化），日志落 ``data/autostart.log``；
  - ``EgressSentinel-Watchdog``：登录 30 秒后跑 ``aaa watchdog --fix``（见
    watchdog.py），突发关机后自动还原代理设置，避免「开机断网」。
- journal-first：先记 ``setup-state.json`` 再创建任务；删除容忍任务不存在
  （幂等）；``aaa teardown`` 的 ``autostart`` 目标可整体还原。
- 安全红线：真实 schtasks 只经 ``_run_schtasks``（测试注入点），单测全 mock。
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path
from xml.sax.saxutils import escape as _xml_escape

from aaa.setup.state import StateEntry, StateFile

logger = logging.getLogger(__name__)

KIND_AUTOSTART_TASK = "autostart_task"
KIND_WATCHDOG_TASK = "watchdog_task"

AUTOSTART_TASK_NAME = "EgressSentinel-AutoStart"
WATCHDOG_TASK_NAME = "EgressSentinel-Watchdog"

#: 看门狗延迟（秒）：等自启代理先起来，避免登录竞态误判「断网」
WATCHDOG_DELAY_SECONDS = 30


class AutostartError(RuntimeError):
    """计划任务创建/删除失败。"""


def _run_schtasks(args: list[str]) -> subprocess.CompletedProcess[str]:
    """执行 schtasks（测试注入点：monkeypatch 本函数，绝不真实施改）。"""
    return subprocess.run(
        ["schtasks", *args], capture_output=True, text=True, encoding="oem", errors="replace"
    )


def _quote(value: str) -> str:
    return f'"{value}"' if (" " in value or not value) else value


def autostart_command(data_dir: Path) -> tuple[str, list[str]]:
    """开机启动 ``aaa run`` 的命令行：venv→pythonw（无窗口），frozen→cmd start /min。"""
    log_file = data_dir / "autostart.log"
    run_args = ["run", "--data-dir", str(data_dir), "--log-file", str(log_file)]
    if getattr(sys, "frozen", False):  # PyInstaller exe：控制台程序，最小化启动
        return "cmd.exe", ["/c", "start", "", "/min", sys.executable, *run_args]
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    launcher = str(pythonw if pythonw.exists() else Path(sys.executable))
    return launcher, ["-c", "from aaa.cli import main; main()", *run_args]


def watchdog_command(data_dir: Path) -> tuple[str, list[str]]:
    """登录自检 ``aaa watchdog --fix`` 的命令行（同上策略）。"""
    wd_args = [
        "watchdog",
        "--fix",
        "--data-dir",
        str(data_dir),
        "--log-file",
        str(data_dir / "watchdog.log"),
    ]
    if getattr(sys, "frozen", False):
        return "cmd.exe", ["/c", "start", "", "/min", sys.executable, *wd_args]
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    launcher = str(pythonw if pythonw.exists() else Path(sys.executable))
    return launcher, ["-c", "from aaa.cli import main; main()", *wd_args]


def build_task_xml(command: str, arguments: list[str], *, delay_seconds: int = 0) -> str:
    """登录触发计划任务 XML（ExecutionTimeLimit=0 不限时，断电续航均可启动）。"""
    arg_line = " ".join(_quote(a) for a in arguments)
    delay = f"<Delay>PT{delay_seconds}S</Delay>" if delay_seconds > 0 else ""
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled>{delay}</LogonTrigger>
  </Triggers>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{_xml_escape(command)}</Command>
      <Arguments>{_xml_escape(arg_line)}</Arguments>
    </Exec>
  </Actions>
</Task>
"""


def create_task(
    state: StateFile,
    *,
    kind: str,
    task_name: str,
    command: str,
    arguments: list[str],
    xml_dir: Path,
    delay_seconds: int = 0,
) -> StateEntry:
    """journal-first 创建单个计划任务：先记录，再 schtasks /Create。"""
    xml = build_task_xml(command, arguments, delay_seconds=delay_seconds)
    xml_dir.mkdir(parents=True, exist_ok=True)
    xml_path = xml_dir / f"{task_name}.xml"
    xml_path.write_text(xml, encoding="utf-16")
    entry = state.record(
        kind=kind,
        key=task_name,
        old=None,
        new={
            "task_name": task_name,
            "xml": str(xml_path),
            "command": command,
            "arguments": " ".join(_quote(a) for a in arguments),
        },
    )
    result = _run_schtasks(["/Create", "/TN", task_name, "/XML", str(xml_path)])
    if result.returncode != 0:
        raise AutostartError(
            f"创建计划任务失败 {task_name}（记录保留，teardown 可重试）："
            f"{(result.stderr or result.stdout).strip()}"
        )
    logger.info("计划任务已创建：%s（delay=%ds）", task_name, delay_seconds)
    return entry


def enable_autostart(state: StateFile, data_dir: Path) -> list[StateEntry]:
    """创建自启 + 看门狗两个计划任务（XML 落 ``data_dir/tasks/``）。"""
    xml_dir = data_dir / "tasks"
    cmd, args = autostart_command(data_dir)
    wcmd, wargs = watchdog_command(data_dir)
    return [
        create_task(
            state,
            kind=KIND_AUTOSTART_TASK,
            task_name=AUTOSTART_TASK_NAME,
            command=cmd,
            arguments=args,
            xml_dir=xml_dir,
        ),
        create_task(
            state,
            kind=KIND_WATCHDOG_TASK,
            task_name=WATCHDOG_TASK_NAME,
            command=wcmd,
            arguments=wargs,
            xml_dir=xml_dir,
            delay_seconds=WATCHDOG_DELAY_SECONDS,
        ),
    ]


def delete_task(task_name: str) -> bool:
    """删除计划任务；任务不存在视为已删除（幂等）。"""
    result = _run_schtasks(["/Delete", "/TN", task_name, "/F"])
    if result.returncode == 0:
        return True
    logger.debug("删除计划任务 %s 未执行（可能不存在）：%s", task_name, result.stderr)
    return False


def task_exists(task_name: str) -> bool:
    return _run_schtasks(["/Query", "/TN", task_name]).returncode == 0


def disable_autostart(state: StateFile) -> list[str]:
    """删除两个计划任务并清掉 journal 记录（幂等）。"""
    removed: list[str] = []
    for kind, name in (
        (KIND_AUTOSTART_TASK, AUTOSTART_TASK_NAME),
        (KIND_WATCHDOG_TASK, WATCHDOG_TASK_NAME),
    ):
        delete_task(name)
        if state.drop(kind, name):
            removed.append(name)
    return removed


def spawn_run_now(
    data_dir: Path,
    *,
    _popen=subprocess.Popen,  # type: ignore[assignment]
) -> subprocess.Popen[str]:
    """立即后台启动 ``aaa run``（与开机自启同一命令行：pythonw/最小化 + --log-file）。

    Windows 用 DETACHED_PROCESS 脱离当前控制台（关掉终端代理仍在跑）；
    测试经 ``_popen`` 注入假实现，绝不真起进程。
    """
    command, args = autostart_command(data_dir)
    creationflags = 0
    if os.name == "nt":
        creationflags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    return _popen(
        [command, *args],
        creationflags=creationflags,
        close_fds=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def restore_scheduled_task(state: StateFile, entry: StateEntry) -> None:
    """teardown 还原函数：删除 entry 对应计划任务（容忍不存在）并移除记录。"""
    meta = entry.new if isinstance(entry.new, dict) else {}
    task_name = str(meta.get("task_name") or entry.key)
    delete_task(task_name)
    state.drop(entry.kind, entry.key)
