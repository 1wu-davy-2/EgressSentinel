"""Windows 服务化：开机（ONSTART）计划任务形式的常驻代理（06 文档波次一 W1）。

- ``EgressSentinel-Service``：BootTrigger（等价 ``schtasks /SC ONSTART``）、
  RunLevel 由 ``highest`` 控制（对应可选参数 ``/RL HIGHEST``，默认开启——
  开机时无人登录也需以最高权限运行）、SYSTEM 账户（ONSTART 任务的标准形态）；
  隐藏运行 ``aaa run --log-file data/service.log``（解释器策略与
  ``autostart_command`` 相同：venv→pythonw 无窗口，frozen→cmd start /min）。
- journal-first（kind=``service_task``）：先记 ``setup-state.json`` 再创建任务；
  创建失败记录保留，teardown/重试可清理（与 autostart 同语义）。
- 与既有登录任务（AutoStart/Watchdog）互斥提示：装服务则建议关闭登录任务
  （提示不阻断——服务与登录自启双开会双实例抢占代理端口）。
- ``restore_service`` 幂等删任务并清 journal，经 ``register_restorer`` 注册进
  teardown RESTORERS（teardown.py 为共享文件、不在本模块独占清单，故走扩展点
  注册而非直改；teardown 目标映射同样留给集成层，见 docs/notes/decisions.md）。
- 红线：真实 schtasks 只经 ``_run_schtasks``（测试注入点），单测全 mock，
  绝不真实施改；ONSTART+SYSTEM 任务创建需管理员，提权门禁由 CLI 集成层负责
  （cli.py 全局禁改），schtasks 拒绝访问时走 ``ServiceError`` 报错路径。
"""

from __future__ import annotations

import logging
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from xml.sax.saxutils import escape as _xml_escape

from aaa.setup.autostart import (
    AUTOSTART_TASK_NAME,
    KIND_AUTOSTART_TASK,
    KIND_WATCHDOG_TASK,
    WATCHDOG_TASK_NAME,
)
from aaa.setup.state import StateEntry, StateFile
from aaa.setup.teardown import register_restorer

logger = logging.getLogger(__name__)

#: journal 记录类型（``data/setup-state.json`` 的 kind）
KIND_SERVICE_TASK = "service_task"

#: 服务计划任务名（与 AutoStart/Watchdog 命名风格一致）
SERVICE_TASK_NAME = "EgressSentinel-Service"

#: 服务运行日志文件名（落 ``data_dir/service.log``）
SERVICE_LOG_NAME = "service.log"

#: ONSTART 任务以 SYSTEM 运行（schtasks /SC ONSTART 的默认账户语义）
SYSTEM_SID = "S-1-5-18"


class ServiceError(RuntimeError):
    """服务计划任务创建/删除失败。"""


def _run_schtasks(args: list[str]) -> subprocess.CompletedProcess[str]:
    """执行 schtasks（测试注入点：monkeypatch 本函数，绝不真实施改）。"""
    return subprocess.run(
        ["schtasks", *args], capture_output=True, text=True, encoding="oem", errors="replace"
    )


def _quote(value: str) -> str:
    """参数引号包裹（与 autostart._quote 同规则，保持任务命令行一致）。"""
    return f'"{value}"' if (" " in value or not value) else value


def service_command(data_dir: Path) -> tuple[str, list[str]]:
    """服务运行 ``aaa run`` 的命令行，日志落 ``data/service.log``。

    解释器策略复用 autostart（autostart.py 非 W1 独占文件，故复制策略而非
    参数化改动）：frozen exe 经 ``cmd start /min`` 最小化启动；venv 用
    pythonw 无窗口运行，缺 pythonw 时退回当前解释器。
    """
    log_file = data_dir / SERVICE_LOG_NAME
    run_args = ["run", "--data-dir", str(data_dir), "--log-file", str(log_file)]
    if getattr(sys, "frozen", False):  # PyInstaller exe：控制台程序，最小化启动
        return "cmd.exe", ["/c", "start", "", "/min", sys.executable, *run_args]
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    launcher = str(pythonw if pythonw.exists() else Path(sys.executable))
    return launcher, ["-c", "from aaa.cli import main; main()", *run_args]


def build_service_task_xml(command: str, arguments: list[str], *, highest: bool = True) -> str:
    """ONSTART 触发计划任务 XML。

    - ``BootTrigger`` 等价 ``schtasks /SC ONSTART``（开机触发，无需用户登录）；
    - ``highest`` 对应可选参数 ``/RL HIGHEST``：True→``HighestAvailable``，
      False→``LeastPrivilege``；账户固定 SYSTEM（S-1-5-18）；
    - ``ExecutionTimeLimit=PT0S`` 不限时（服务常驻），其余设置与登录任务一致。
    """
    arg_line = " ".join(_quote(a) for a in arguments)
    run_level = "HighestAvailable" if highest else "LeastPrivilege"
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <BootTrigger><Enabled>true</Enabled></BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{SYSTEM_SID}</UserId>
      <RunLevel>{run_level}</RunLevel>
    </Principal>
  </Principals>
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


@dataclass
class ServiceInstallResult:
    """install_service 结果：journal 条目 + 互斥提示（提示不阻断安装）。"""

    entry: StateEntry
    task_name: str
    warnings: list[str] = field(default_factory=list)


def _task_exists(task_name: str) -> bool:
    """计划任务是否已存在（走本模块 ``_run_schtasks``，与 autostart 的同名函数
    分开注入，单测只需 monkeypatch ``aaa.setup.service._run_schtasks`` 一处）。"""
    return _run_schtasks(["/Query", "/TN", task_name]).returncode == 0


def _delete_task(task_name: str) -> bool:
    """删除计划任务；任务不存在视为已删除（幂等）。"""
    result = _run_schtasks(["/Delete", "/TN", task_name, "/F"])
    if result.returncode == 0:
        return True
    logger.debug("删除计划任务 %s 未执行（可能不存在）：%s", task_name, result.stderr)
    return False


def login_task_warnings(state: StateFile) -> list[str]:
    """检测与既有 AutoStart/Watchdog 登录任务的互斥情况，返回提示列表。

    双通道判定：journal 有记录（setup 装过）**或** schtasks /Query 存在
    （用户手动装过）都提示；提示不阻断安装（互斥语义 = 建议而非强制）。
    """
    kinds = {entry.kind for entry in state.entries()}
    warnings: list[str] = []
    if KIND_AUTOSTART_TASK in kinds or _task_exists(AUTOSTART_TASK_NAME):
        warnings.append(
            f"检测到登录自启任务 {AUTOSTART_TASK_NAME}：服务与登录自启功能重复，"
            f"双开会双实例抢占代理端口。建议 aaa teardown autostart 关闭登录任务后再用服务。"
        )
    if KIND_WATCHDOG_TASK in kinds or _task_exists(WATCHDOG_TASK_NAME):
        warnings.append(
            f"检测到看门狗任务 {WATCHDOG_TASK_NAME}：服务模式下开机即自启代理，"
            f"无需看门狗兜底。建议 aaa teardown autostart 一并关闭。"
        )
    return warnings


def install_service(
    state: StateFile,
    data_dir: Path,
    *,
    highest: bool = True,
) -> ServiceInstallResult:
    """journal-first 创建服务计划任务（XML 落 ``data_dir/tasks/``）。

    - 先收集与登录任务的互斥提示（用创建前的 journal 状态），再先记录后创建；
    - ``highest`` 见 :func:`build_service_task_xml`；
    - 创建失败抛 ``ServiceError``，journal 记录保留（teardown/重试可清理）。
    """
    warnings = login_task_warnings(state)
    command, args = service_command(data_dir)
    log_file = data_dir / SERVICE_LOG_NAME
    xml = build_service_task_xml(command, args, highest=highest)
    xml_dir = data_dir / "tasks"
    xml_dir.mkdir(parents=True, exist_ok=True)
    xml_path = xml_dir / f"{SERVICE_TASK_NAME}.xml"
    xml_path.write_text(xml, encoding="utf-16")
    entry = state.record(
        kind=KIND_SERVICE_TASK,
        key=SERVICE_TASK_NAME,
        old=None,
        new={
            "task_name": SERVICE_TASK_NAME,
            "xml": str(xml_path),
            "command": command,
            "arguments": " ".join(_quote(a) for a in args),
            "log_file": str(log_file),
            "run_level": "HIGHEST" if highest else "LIMITED",
        },
        note="ONSTART+SYSTEM 服务任务；与登录任务互斥（见 warnings）",
    )
    result = _run_schtasks(["/Create", "/TN", SERVICE_TASK_NAME, "/XML", str(xml_path)])
    if result.returncode != 0:
        raise ServiceError(
            f"创建服务计划任务失败 {SERVICE_TASK_NAME}（记录保留，teardown 可重试；"
            f"ONSTART 任务需管理员权限）：{(result.stderr or result.stdout).strip()}"
        )
    logger.info("服务计划任务已创建：%s（run_level=%s）", SERVICE_TASK_NAME, entry.new["run_level"])
    return ServiceInstallResult(entry=entry, task_name=SERVICE_TASK_NAME, warnings=warnings)


def uninstall_service(state: StateFile) -> bool:
    """删除服务计划任务并清 journal 记录（幂等）。

    返回是否有实际动作（任务删除成功或记录被清）；本就不存在时返回 False。
    """
    removed_task = _delete_task(SERVICE_TASK_NAME)
    dropped = state.drop(KIND_SERVICE_TASK, SERVICE_TASK_NAME)
    return removed_task or dropped > 0


def restore_service(state: StateFile, entry: StateEntry) -> None:
    """teardown 还原函数：删除 entry 对应服务任务（容忍不存在）并移除记录。"""
    meta = entry.new if isinstance(entry.new, dict) else {}
    task_name = str(meta.get("task_name") or entry.key)
    _delete_task(task_name)
    state.drop(entry.kind, entry.key)


@dataclass
class ServiceStatus:
    """service_status 结果：只读状态 + 互斥提示（不改动任何系统状态）。"""

    task_name: str
    #: schtasks /Query 是否存在该任务
    task_exists: bool
    #: journal 是否有安装记录
    journaled: bool
    #: journal 记录的任务命令行（未安装为 None）
    command: str | None
    #: journal 记录的日志路径（未安装为 None）
    log_file: Path | None
    #: 与登录任务的互斥提示（空列表 = 无冲突）
    warnings: list[str] = field(default_factory=list)
    #: 两个登录任务当前是否仍存在（schtasks 层面）
    autostart_task_exists: bool = False
    watchdog_task_exists: bool = False

    @property
    def conflict(self) -> bool:
        """服务与登录任务是否互斥冲突。

        与 ``warnings`` 同一判定（journal 有记录 **或** schtasks 任务存在），
        避免同一模块输出两种口径；存在孤儿 journal 记录时保守提示。
        """
        return bool(self.warnings)


def service_status(state: StateFile) -> ServiceStatus:
    """只读查询服务任务状态：任务存在性 / journal 记录 / 登录任务互斥情况。"""
    entry = next(
        (
            e
            for e in state.entries()
            if e.kind == KIND_SERVICE_TASK and e.key == SERVICE_TASK_NAME
        ),
        None,
    )
    meta = entry.new if entry is not None and isinstance(entry.new, dict) else {}
    log_value = meta.get("log_file")
    return ServiceStatus(
        task_name=SERVICE_TASK_NAME,
        task_exists=_task_exists(SERVICE_TASK_NAME),
        journaled=entry is not None,
        command=str(meta["command"]) if "command" in meta else None,
        log_file=Path(str(log_value)) if log_value else None,
        warnings=login_task_warnings(state),
        autostart_task_exists=_task_exists(AUTOSTART_TASK_NAME),
        watchdog_task_exists=_task_exists(WATCHDOG_TASK_NAME),
    )


#: 注册 teardown 还原器（teardown.py 提供的扩展点，CA 同款机制）；
#: import 本模块即生效——集成层 CLI 需 import ``aaa.setup.service``。
register_restorer(KIND_SERVICE_TASK, restore_service)
