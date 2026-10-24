"""teardown：按状态文件逆序幂等还原全部 setup 改动（03 文档 T1.5，02 文档 R7）。

- 逆序：后做的改动先还原（嵌套覆盖语义安全）；
- 幂等：还原成功即从状态文件移除记录；记录不存在 ⇒ 无操作；
- 容错：单条还原失败不中断整体，保留记录供下次重试（``--force``/重跑 teardown）。
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from aaa.setup.autostart import (
    KIND_AUTOSTART_TASK,
    KIND_WATCHDOG_TASK,
    restore_scheduled_task,
)
from aaa.setup.envvars import (
    KIND_ENV_VAR,
    KIND_FILE_CREATED,
    restore_file_created,
    restore_user_envvar,
)
from aaa.setup.proxy import (
    KIND_WINHTTP,
    KIND_WININET,
    restore_user_proxy,
    restore_winhttp_proxy,
)
from aaa.setup.state import StateEntry, StateFile

logger = logging.getLogger(__name__)

#: CA 证书记录类型（aaa setup ca 写入）
KIND_CA_USER = "ca_cert_user"
KIND_CA_MACHINE = "ca_cert_machine"

Restorer = Callable[[StateFile, StateEntry], None]


@dataclass
class TeardownReport:
    """teardown 结果。"""

    restored: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    dry_run: bool = False

    @property
    def ok(self) -> bool:
        return not self.failed


#: kind → 还原函数；CA 的还原在 ca 记录模块注册（cli/setup 流程内），此处先登记通用六类
RESTORERS: dict[str, Restorer] = {
    KIND_ENV_VAR: restore_user_envvar,
    KIND_FILE_CREATED: restore_file_created,
    KIND_WININET: restore_user_proxy,
    KIND_WINHTTP: restore_winhttp_proxy,
    KIND_AUTOSTART_TASK: restore_scheduled_task,
    KIND_WATCHDOG_TASK: restore_scheduled_task,
}


def register_restorer(kind: str, restorer: Restorer) -> None:
    """注册还原函数（供 CA 等模块扩展）。"""
    RESTORERS[kind] = restorer


def restore_ca_entry(state: StateFile, entry: StateEntry) -> None:
    """还原 CA 证书记录：按 store 与序列号精确删除（不误删其他证书）。"""
    from aaa.setup.ca import uninstall_cert  # 延迟导入避免循环依赖

    meta = entry.new if isinstance(entry.new, dict) else {}
    store = str(meta.get("store") or entry.key.split(":", 1)[0])
    serial = str(meta.get("serial") or entry.key.split(":", 1)[-1])
    uninstall_cert(store, serial)
    state.drop(entry.kind, entry.key)


def teardown_target_kinds(targets: tuple[str, ...] | None) -> set[str] | None:
    """把 CLI 目标（ca/proxy/env/all）映射到 kind 集合；None/空 = 全部。"""
    if not targets:
        return None
    mapping: dict[str, set[str]] = {
        "ca": {KIND_CA_USER, KIND_CA_MACHINE},
        "proxy": {KIND_WININET, KIND_WINHTTP},
        "env": {KIND_ENV_VAR, KIND_FILE_CREATED},
        "autostart": {KIND_AUTOSTART_TASK, KIND_WATCHDOG_TASK},
    }
    kinds: set[str] = set()
    for target in targets:
        normalized = target.strip().lower()
        if normalized not in mapping:
            raise ValueError(f"未知 teardown 目标：{target!r}（支持 ca/proxy/env/autostart）")
        kinds |= mapping[normalized]
    return kinds


def run_teardown(
    state_file: Path,
    *,
    kinds: set[str] | None = None,
    dry_run: bool = False,
) -> TeardownReport:
    """执行 teardown：逆序还原并从状态文件移除已还原记录。

    ``kinds`` 限定还原范围（None = 全部）；``dry_run`` 只列出将执行的还原。
    """
    state = StateFile(state_file)
    report = TeardownReport(dry_run=dry_run)
    entries = state.entries()
    # 逆序：后改的先还原
    for entry in reversed(entries):
        if kinds is not None and entry.kind not in kinds:
            continue
        label = f"{entry.kind}:{entry.key}"
        restorer = RESTORERS.get(entry.kind)
        if restorer is None and entry.kind in (KIND_CA_USER, KIND_CA_MACHINE):
            restorer = restore_ca_entry
        if restorer is None:
            report.failed.append(label)
            report.errors.append(f"未知改动类型，无法自动还原：{label}（ts={entry.ts}）")
            continue
        if dry_run:
            report.restored.append(f"(dry-run) {label}")
            continue
        try:
            restorer(state, entry)
            report.restored.append(label)
        except Exception as exc:  # noqa: BLE001 - 单条失败不中断整体
            report.failed.append(label)
            report.errors.append(f"{label} 还原失败：{exc}（记录保留，可重试）")
            logger.exception("teardown 还原失败：%s", label)
    if not dry_run:
        logger.info(
            "teardown 完成：restored=%d failed=%d", len(report.restored), len(report.failed)
        )
    return report
