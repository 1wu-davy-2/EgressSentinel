"""``aaa setup`` 交互式引导（03 文档 T4.2：CA → 代理 → 环境变量，全程确认提示）。

结构：
- ``collect_setup_plans``：收集三步的计划（标题 + **将要执行的改动明细** + 应用动作），
  不做任何系统改动——满足"所有系统修改动作执行前必须打印将要做的改动"；
- ``run_setup_wizard``：逐步打印计划 → 征求确认 → 应用；``confirm``/``echo`` 可注入
  （CLI 用 typer.confirm/rich，单测用假实现，绝不真实施改）。

应用动作与 ``aaa setup ca/proxy/env`` 子命令共用同一实现（journal-first，全部记录到
``data/setup-state.json``，可被 ``aaa teardown`` 幂等还原）。
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field

from aaa.config import AppPaths
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
    store_label = "LocalMachine\\Root（需管理员）" if machine_ca else "CurrentUser\\Root"
    plan_lines = [
        f"将证书安装到 {store_label} 证书存储：",
        f"  CA 文件：{ca_info.path}",
        f"  序列号：{ca_info.serial}（teardown 按序列号精确删除，不误删其他证书）",
        f"  指纹(SHA1)：{ca_info.thumbprint}",
        f"  记录改动到：{paths.setup_state_file}",
    ]
    if machine_ca:
        plan_lines.append("  ⚠ 机器级存储影响所有用户，需要管理员权限。")

    def _apply_ca() -> None:
        state.record(
            kind=("ca_cert_machine" if machine_ca else "ca_cert_user"),
            key=f"{store_name}:Root:{ca_info.serial}",
            old=None,
            new={"store": store_name, "serial": ca_info.serial, "path": str(ca_info.path)},
        )
        ca_mod.install_cert(store_name, ca_info.path)

    plans.append(SetupPlan(title="① CA 根证书", lines=plan_lines, apply=_apply_ca))

    # --- 第 2 步：系统代理（WinINET 用户级） ---
    proxy_lines = [
        f"将设置 WinINET 用户代理：{proxy_host}:{proxy_port}",
        f"  注册表：HKCU\\{proxy_mod.WININET_KEY}",
        "  键值：ProxyEnable=1, "
        f"ProxyServer={proxy_host}:{proxy_port}, ProxyOverride=<local>;localhost;127.0.0.1",
        "  写入后 InternetSetOption 通知 WinINET 刷新（浏览器建议重启）",
        f"  旧值先记录到：{paths.setup_state_file}（teardown 还原）",
    ]

    def _apply_proxy() -> None:
        proxy_mod.apply_user_proxy(state, proxy_host, proxy_port)

    plans.append(
        SetupPlan(title="② 系统代理（WinINET 用户级）", lines=proxy_lines, apply=_apply_proxy)
    )

    # --- 第 3 步：用户环境变量（02 文档 D1 清单） ---
    merged = paths.data_dir / ca_mod.MERGED_PEM_NAME
    values = envvars_mod.build_env_values(proxy_host, proxy_port, ca_info.path, merged)
    env_lines = [
        f"将创建合并 PEM：{merged}（mitmproxy CA + 系统 CA，供 REQUESTS_CA_BUNDLE 等）",
        "将写入以下用户环境变量（HKCU\\Environment，新终端生效）：",
        *[f"  {name} = {values[name]}" for name in sorted(values)],
        "  并广播 WM_SETTINGCHANGE；全部记录到状态文件可还原",
    ]

    def _apply_env() -> None:
        ca_mod.ensure_merged_pem(paths.confdir, merged)
        envvars_mod.record_file_created(state, merged)
        envvars_mod.apply_user_envvars(state, values)

    plans.append(SetupPlan(title="③ 用户环境变量", lines=env_lines, apply=_apply_env))
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
    echo("AI-AGENT-AUDIT 一键引导：以下步骤将修改系统设置，逐步确认执行。")
    if dry_run:
        echo("[yellow](dry-run)[/yellow] 只展示计划，不实施任何改动。")
    for plan in plans:
        echo("")
        echo(f"[bold cyan]{plan.title}[/bold cyan]")
        for line in plan.lines:
            echo(f"  {line}")
        if not confirm(f"{plan.title}：执行该步骤？"):
            echo("  [dim]已跳过。[/dim]")
            continue
        if dry_run:
            echo("  [yellow](dry-run)[/yellow] 未实施。")
            applied.append(plan.title)
            continue
        try:
            plan.apply()
        except Exception as exc:  # noqa: BLE001 - 单步失败不中断向导
            echo(f"  [red]失败：{exc}[/red]（记录已保留，可 teardown 还原后重试）")
            logger.exception("setup 向导步骤失败：%s", plan.title)
            continue
        echo("  [green]完成。[/green]")
        applied.append(plan.title)
    echo("")
    if applied:
        echo(f"向导结束：{'、'.join(applied)}。可运行 aaa teardown 一键还原全部改动。")
    else:
        echo("向导结束：未执行任何改动。")
    return applied
