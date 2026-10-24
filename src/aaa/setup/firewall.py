r"""防火墙加固（05 文档波次一 W2）：把 443 出站收敛到本地代理的唯一出口。

规则集（名称一律 ``EgressSentinel-`` 前缀、出站方向）：

  1. Allow：代理程序（``proxy_exe``）出站 TCP 443 —— 唯一合法出口；
  2. Allow：svchost.exe（Windows Update 服务宿主）出站 TCP 443 —— 尽力保活系统更新；
  3. Block：任意程序（any）出站 TCP 443 —— 堵 HTTPS 直连（强制经代理）；
  4. Block：任意程序（any）出站 UDP 443 —— 堵 QUIC/H3 绕行。

**已知边界（如实记录，详见 docs/notes/decisions.md D-2026-10-24-35）**：Windows
筛选平台的文档语义是「Block 规则优先于 Allow 规则」（仅 IPsec authenticated
bypass 例外），因此第 3/4 条的 any-Block 同样命中代理与 svchost——netsh 能力内
白名单对 any-Block 不生效。Allow 规则仍然创建：一旦集成阶段把 Block 收窄到具体
程序范围（或改用 WFP 子层权重），Allow 即自动生效；上真机前的连通性验证列入
needs-manual 清单。

- ``plan_harden``：dry-run 概念——只返回将创建的规则清单，绝不触达系统；
- ``apply_harden``：journal-first（每条规则先记 setup-state.json 再创建，
  kind=firewall_rule）；创建前先按名清除同名旧规则（重复执行 ``harden on``
  幂等，不产生重名规则）；创建顺序为 Allow 在前、Block 在后（中途崩溃的系统
  停留在「未加固」而非「全断 443」状态）；
- ``restore_harden``：按规则名精确 ``netsh advfirewall firewall delete rule
  name=...``；幂等容忍不存在（delete 返回非 0 时用 ``show rule`` 复核——本机
  实测「无匹配规则」返回码为 1，规则已不在即视为成功）；拒绝删除非本工具前缀
  的规则，防止 journal 记录被篡改后误删他名规则；
- 管理员门禁：apply/restore 复用 ``setup.admin.is_current_process_elevated``，
  非管理员直接拒绝（本机实测非提权 shell 的 delete 返回「请求的操作需要提升」，
  提前拒绝可避免把「拒绝访问」误判为「规则不存在」）。

安全红线：真实 netsh 只经 ``_run_netsh``（测试注入点），单测一律 mock，绝不
真实施改防火墙。
"""

from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path

from pydantic import BaseModel

from aaa.setup.admin import is_current_process_elevated
from aaa.setup.state import StateEntry, StateFile

logger = logging.getLogger(__name__)

#: journal 记录类型（teardown 注册表按 kind 分发，集成阶段接线）
KIND_FIREWALL_RULE = "firewall_rule"

#: 本工具防火墙规则名前缀（还原时按前缀校验，防误删他名规则）
RULE_NAME_PREFIX = "EgressSentinel-"

RULE_ALLOW_PROXY = f"{RULE_NAME_PREFIX}Allow-Proxy-TCPOut-443"
RULE_ALLOW_SVCHOST = f"{RULE_NAME_PREFIX}Allow-Svchost-TCPOut-443"
RULE_BLOCK_TCP_ANY = f"{RULE_NAME_PREFIX}Block-Any-TCPOut-443"
RULE_BLOCK_UDP_ANY = f"{RULE_NAME_PREFIX}Block-Any-UDPOut-443"

#: 加固目标端口（v1 仅 443：HTTPS/QUIC）
HARDEN_PORT = 443


class FirewallError(RuntimeError):
    """防火墙规则创建/删除失败。"""


class FirewallRule(BaseModel):
    """一条将要创建的防火墙规则（plan/apply/journal 共用同一形态）。"""

    name: str
    action: str  # "allow" | "block"
    protocol: str  # "TCP" | "UDP"
    remote_port: int
    program: str | None = None  # None => 任意程序（netsh program=any）
    description: str = ""
    direction: str = "out"


def _svchost_program() -> str:
    """Windows Update 服务宿主路径（``%SystemRoot%`` 可被环境变量覆盖，测试友好）。"""
    return str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "svchost.exe")


def plan_harden(proxy_exe: str | os.PathLike[str]) -> list[FirewallRule]:
    """列出将创建的防火墙规则清单（dry-run 概念：纯函数，绝不触达系统）。

    ``proxy_exe`` 为本地代理可执行文件（``aaa run`` 的宿主：源码运行即
    ``sys.executable``，frozen 即打包 exe）。Allow 在前、Block 在后（见模块
    docstring 的创建顺序说明）。
    """
    proxy = str(Path(proxy_exe))
    return [
        FirewallRule(
            name=RULE_ALLOW_PROXY,
            action="allow",
            protocol="TCP",
            remote_port=HARDEN_PORT,
            program=proxy,
            description=f"EgressSentinel：代理程序唯一放行的 {HARDEN_PORT}/TCP 出站",
        ),
        FirewallRule(
            name=RULE_ALLOW_SVCHOST,
            action="allow",
            protocol="TCP",
            remote_port=HARDEN_PORT,
            program=_svchost_program(),
            description=f"EgressSentinel：svchost/Windows Update 白名单（{HARDEN_PORT}/TCP）",
        ),
        FirewallRule(
            name=RULE_BLOCK_TCP_ANY,
            action="block",
            protocol="TCP",
            remote_port=HARDEN_PORT,
            program=None,
            description=f"EgressSentinel：阻止任意程序 {HARDEN_PORT}/TCP 直连（强制经代理）",
        ),
        FirewallRule(
            name=RULE_BLOCK_UDP_ANY,
            action="block",
            protocol="UDP",
            remote_port=HARDEN_PORT,
            program=None,
            description=f"EgressSentinel：阻止任意程序 {HARDEN_PORT}/UDP（QUIC/H3 绕行）",
        ),
    ]


def _run_netsh(args: list[str]) -> subprocess.CompletedProcess[str]:
    """执行 netsh（测试注入点：monkeypatch 本函数，绝不真实施改防火墙）。"""
    return subprocess.run(
        ["netsh", *args], capture_output=True, text=True, encoding="oem", errors="replace"
    )


def _require_elevated(action: str) -> None:
    """管理员门禁：非提权直接拒绝（复用 setup.admin 的检测）。"""
    if not is_current_process_elevated():
        raise FirewallError(f"{action}需要管理员权限（netsh advfirewall 需提升令牌）")


def _resolve_proxy_exe(proxy_exe: str | os.PathLike[str]) -> str:
    """校验代理程序存在并归一化路径（创建指不存在路径的规则毫无意义）。"""
    path = Path(proxy_exe)
    if not path.is_file():
        raise FirewallError(f"代理程序不存在：{path}")
    return str(path)


def _add_rule_args(rule: FirewallRule) -> list[str]:
    """``netsh advfirewall firewall add rule`` 参数（list 形式，无需手工引号）。"""
    return [
        "advfirewall",
        "firewall",
        "add",
        "rule",
        f"name={rule.name}",
        f"dir={rule.direction}",
        f"action={rule.action}",
        f"protocol={rule.protocol}",
        f"remoteport={rule.remote_port}",
        f"program={rule.program if rule.program else 'any'}",
        "enable=yes",
        "profile=any",
        f"description={rule.description}",
    ]


def _rule_exists(name: str) -> bool:
    """按名查询规则是否仍存在（``show rule``：本机实测无匹配时返回码为 1）。"""
    result = _run_netsh(["advfirewall", "firewall", "show", "rule", f"name={name}"])
    return result.returncode == 0


def apply_harden(state: StateFile, proxy_exe: str | os.PathLike[str]) -> list[StateEntry]:
    """journal-first 逐条创建规则（05 文档 W2）：先记录，再清除同名旧规则，再创建。

    单条创建失败即抛 ``FirewallError``（记录保留，teardown/重试可清理）；已完成
    的规则已各自在案，剩余规则不再尝试。
    """
    _require_elevated("应用防火墙加固")
    proxy = _resolve_proxy_exe(proxy_exe)
    entries: list[StateEntry] = []
    for rule in plan_harden(proxy):
        entry = state.record(
            kind=KIND_FIREWALL_RULE,
            key=rule.name,
            old=None,
            new=rule.model_dump(),
            note="journal-first：防火墙加固规则",
        )
        # 清除同名旧规则使 apply 可重复执行（幂等）；容忍不存在，失败不阻塞
        stale = _run_netsh(["advfirewall", "firewall", "delete", "rule", f"name={rule.name}"])
        if stale.returncode != 0:
            logger.debug("清除同名旧规则 %s 未成功（可能不存在）", rule.name)
        result = _run_netsh(["advfirewall", "firewall", "add", "rule", *_add_rule_args(rule)])
        if result.returncode != 0:
            raise FirewallError(
                f"创建防火墙规则失败 {rule.name}（记录保留，teardown 可重试）："
                f"{(result.stderr or result.stdout).strip()}"
            )
        entries.append(entry)
        logger.info("防火墙规则已创建：%s", rule.name)
    return entries


def restore_harden(state: StateFile, entry: StateEntry) -> None:
    """teardown 还原函数：按规则名精确删除（幂等容忍不存在），成功后移除记录。"""
    _require_elevated("还原防火墙规则")
    meta = entry.new if isinstance(entry.new, dict) else {}
    name = str(meta.get("name") or entry.key)
    if not name.startswith(RULE_NAME_PREFIX):
        raise FirewallError(
            f"拒绝删除非 {RULE_NAME_PREFIX} 前缀规则：{name!r}（journal 记录可能被篡改）"
        )
    result = _run_netsh(["advfirewall", "firewall", "delete", "rule", f"name={name}"])
    if result.returncode != 0 and _rule_exists(name):
        raise FirewallError(
            f"删除防火墙规则失败 {name}（记录保留，可重试）："
            f"{(result.stderr or result.stdout).strip()}"
        )
    state.drop(entry.kind, entry.key)
    logger.info("防火墙规则已删除（或本就不存在）：%s", name)


__all__ = [
    "HARDEN_PORT",
    "KIND_FIREWALL_RULE",
    "RULE_ALLOW_PROXY",
    "RULE_ALLOW_SVCHOST",
    "RULE_BLOCK_TCP_ANY",
    "RULE_BLOCK_UDP_ANY",
    "RULE_NAME_PREFIX",
    "FirewallError",
    "FirewallRule",
    "apply_harden",
    "is_current_process_elevated",
    "plan_harden",
    "restore_harden",
]
