"""``aaa setup`` 交互式引导（03 文档 T4.2：CA → 代理 → 环境变量，全程确认提示）。

结构：
- ``collect_setup_plans``：收集三步的计划（标题 + **将要执行的改动明细** + 应用动作），
  不做任何系统改动——满足"所有系统修改动作执行前必须打印将要做的改动"；
- ``run_setup_wizard``：逐步打印计划 → 征求确认 → 应用；``confirm``/``echo`` 可注入
  （CLI 用 typer.confirm/rich，单测用假实现，绝不真实施改）。

应用动作与 ``aaa setup ca/proxy/env`` 子命令共用同一实现（journal-first，全部记录到
``data/setup-state.json``，可被 ``aaa teardown`` 幂等还原）。

i18n（06 文档波次二）：全部用户可见文案经 ``t()`` 取词（zh 目录与原文逐字一致，
默认输出不变；``--lang``/``AAA_LANG`` 切英文）。``t()`` 绝不抛异常，缺词条回落 zh。
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field

from aaa.config import AppPaths
from aaa.i18n import t
from aaa.setup import ca as ca_mod
from aaa.setup import envvars as envvars_mod
from aaa.setup import proxy as proxy_mod
from aaa.setup.state import StateFile

logger = logging.getLogger(__name__)

Echo = Callable[[str], None]
Confirm = Callable[[str], bool]


@dataclass
class SetupPlan:
    """一步 setup 计划：``lines`` 是将要执行的改动（执行前必打印）。"""

    title: str
    lines: list[str] = field(default_factory=list)
    apply: Callable[[], None] = lambda: None


def collect_setup_plans(
    paths: AppPaths,
    *,
    machine_ca: bool = False,
    proxy_host: str = "127.0.0.1",
    proxy_port: int = 8080,
) -> list[SetupPlan]:
    """收集 CA/代理/环境变量三步计划（只读信息收集，无系统改动）。

    ``machine_ca``：CA 安装到 LocalMachine（需管理员）而非 CurrentUser。
    """
    plans: list[SetupPlan] = []
    state = StateFile(paths.setup_state_file)
    ca_info = ca_mod.ensure_ca(paths.confdir)

    # --- 第 1 步：CA ---
    store_name = "machine" if machine_ca else "user"
    store_label = (
        t("wizard.ca.store_machine") if machine_ca else t("wizard.ca.store_user")
    )
    plan_lines = [
        t("wizard.ca.header", store_label=store_label),
        t("wizard.ca.file", path=ca_info.path),
        t("wizard.ca.serial", serial=ca_info.serial),
        t("wizard.ca.thumbprint", thumbprint=ca_info.thumbprint),
        t("wizard.ca.record_to", state_file=paths.setup_state_file),
    ]
    if machine_ca:
        plan_lines.append(t("wizard.ca.machine_warning"))

    def _apply_ca() -> None:
        state.record(
            kind=("ca_cert_machine" if machine_ca else "ca_cert_user"),
            key=f"{store_name}:Root:{ca_info.serial}",
            old=None,
            new={"store": store_name, "serial": ca_info.serial, "path": str(ca_info.path)},
        )
        ca_mod.install_cert(store_name, ca_info.path)

    plans.append(SetupPlan(title=t("wizard.ca.title"), lines=plan_lines, apply=_apply_ca))

    # --- 第 2 步：系统代理（WinINET 用户级） ---
    proxy_lines = [
        t("wizard.proxy.header", host=proxy_host, port=proxy_port),
        t("wizard.proxy.registry", reg_key=proxy_mod.WININET_KEY),
        t("wizard.proxy.values", host=proxy_host, port=proxy_port),
        t("wizard.proxy.refresh"),
        t("wizard.proxy.record_to", state_file=paths.setup_state_file),
    ]

    def _apply_proxy() -> None:
        proxy_mod.apply_user_proxy(state, proxy_host, proxy_port)

    plans.append(SetupPlan(title=t("wizard.proxy.title"), lines=proxy_lines, apply=_apply_proxy))

    # --- 第 3 步：用户环境变量（02 文档 D1 清单） ---
    merged = paths.data_dir / ca_mod.MERGED_PEM_NAME
    values = envvars_mod.build_env_values(proxy_host, proxy_port, ca_info.path, merged)
    env_lines = [
        t("wizard.env.merged_pem", path=merged),
        t("wizard.env.header"),
        *[t("wizard.env.line", name=name, value=values[name]) for name in sorted(values)],
        t("wizard.env.broadcast"),
    ]

    def _apply_env() -> None:
        ca_mod.ensure_merged_pem(paths.confdir, merged)
        envvars_mod.record_file_created(state, merged)
        envvars_mod.apply_user_envvars(state, values)

    plans.append(SetupPlan(title=t("wizard.env.title"), lines=env_lines, apply=_apply_env))
    return plans


def run_setup_wizard(
    plans: list[SetupPlan],
    *,
    confirm: Confirm,
    echo: Echo,
    dry_run: bool = False,
) -> list[str]:
    """逐步执行向导：打印计划 → 确认 → 应用。

    返回已应用（或 dry-run 下将应用）的步骤标题列表。单步失败打印错误并继续
    （journal-first：失败步骤的记录保留，teardown 重放为幂等 no-op）。
    """
    applied: list[str] = []
    echo(t("wizard.welcome"))
    if dry_run:
        echo(t("wizard.dry_run_banner"))
    for plan in plans:
        echo("")
        echo(f"[bold cyan]{plan.title}[/bold cyan]")
        for line in plan.lines:
            echo(f"  {line}")
        if not confirm(t("wizard.confirm_step", title=plan.title)):
            echo(t("wizard.skipped"))
            continue
        if dry_run:
            echo(t("wizard.dry_run_step"))
            applied.append(plan.title)
            continue
        try:
            plan.apply()
        except Exception as exc:  # noqa: BLE001 - 单步失败不中断向导
            echo(t("wizard.step_failed", exc=exc))
            logger.exception("setup 向导步骤失败：%s", plan.title)
            continue
        echo(t("wizard.step_done"))
        applied.append(plan.title)
    echo("")
    if applied:
        echo(t("wizard.summary_applied", applied="、".join(applied)))
    else:
        echo(t("wizard.summary_none"))
    return applied
