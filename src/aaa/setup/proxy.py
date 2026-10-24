"""代理设置下发：WinINET 用户代理 + 可选 WinHTTP（03 文档 T1.4，02 文档 D1）。

- WinINET（用户级，无需管理员）：注册表 ``HKCU\\...\\Internet Settings`` 的
  ``ProxyEnable``/``ProxyServer``/``ProxyOverride``，写入后用
  ``InternetSetOption`` 通知 WinINET 刷新；
- WinHTTP（机器级，需管理员）：``netsh winhttp set/reset proxy``，可选启用；
- 全部改动先读旧值、先记入 ``data/setup-state.json``（journal-first），再实施。

安全红线：单元测试通过注入假注册表/假 runner 完成，绝不真实施改系统设置。
"""

from __future__ import annotations

import ctypes
import logging
import re

from aaa.setup.ca import Runner, _check, _default_runner
from aaa.setup.state import StateEntry, StateFile

logger = logging.getLogger(__name__)

WININET_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
WININET_VALUE_NAMES = ("ProxyEnable", "ProxyServer", "ProxyOverride")

KIND_WININET = "wininet_proxy"
KIND_WINHTTP = "winhttp_proxy"

#: InternetSetOption 选项码（wininet.h）
_INTERNET_OPTION_SETTINGS_CHANGED = 39
_INTERNET_OPTION_REFRESH = 37

_DEFAULT_WINHTTP_BYPASS = "localhost;127.0.0.1;<local>"


class ProxySetupError(RuntimeError):
    """代理设置失败。"""


# --------------------------------------------------------------------------
# 注册表访问层（模块级函数，测试注入假实现）
# --------------------------------------------------------------------------


def _reg_read(name: str) -> str | int | None:
    """读 HKCU WinINET 注册表值；不存在返回 None。"""
    import winreg

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, WININET_KEY) as key:
        try:
            value, _value_type = winreg.QueryValueEx(key, name)
            return value
        except FileNotFoundError:
            return None


def _reg_write(name: str, value: str | int) -> None:
    """写 HKCU WinINET 注册表值（int→REG_DWORD，str→REG_SZ）。"""
    import winreg

    reg_type = winreg.REG_DWORD if isinstance(value, int) else winreg.REG_SZ
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, WININET_KEY) as key:
        winreg.SetValueEx(key, name, 0, reg_type, value)


def _reg_delete(name: str) -> None:
    """删除 HKCU WinINET 注册表值（不存在为幂等 no-op）。"""
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, WININET_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, name)
    except FileNotFoundError:
        pass


def read_wininet() -> dict[str, str | int | None]:
    """读当前 WinINET 用户代理设置（``aaa status`` 用，只读不改）。"""
    return {name: _reg_read(name) for name in WININET_VALUE_NAMES}


def refresh_wininet() -> None:
    """InternetSetOption 通知 WinINET 设置已变更（03 文档 T1.4：刷新或通知重启浏览器）。"""
    wininet = ctypes.windll.wininet  # type: ignore[attr-defined]
    wininet.InternetSetOptionW(None, _INTERNET_OPTION_SETTINGS_CHANGED, None, 0)
    wininet.InternetSetOptionW(None, _INTERNET_OPTION_REFRESH, None, 0)


# --------------------------------------------------------------------------
# WinINET 用户代理
# --------------------------------------------------------------------------


def apply_user_proxy(
    state: StateFile,
    host: str,
    port: int,
    *,
    override: str = "<local>;localhost;127.0.0.1",
    refresh: bool = True,
) -> StateEntry:
    """设置 WinINET 用户代理并记录旧值（journal-first）。"""
    old = {name: _reg_read(name) for name in WININET_VALUE_NAMES}
    new = {"ProxyEnable": 1, "ProxyServer": f"{host}:{port}", "ProxyOverride": override}
    entry = state.record(kind=KIND_WININET, key=WININET_KEY, old=old, new=new)
    try:
        _reg_write("ProxyEnable", 1)
        _reg_write("ProxyServer", f"{host}:{port}")
        _reg_write("ProxyOverride", override)
        if refresh:
            refresh_wininet()
    except Exception as exc:
        raise ProxySetupError(
            f"写入 WinINET 代理失败（记录保留，可 teardown 还原）：{exc}"
        ) from exc
    logger.info("WinINET 用户代理已设置：%s:%d", host, port)
    return entry


def restore_user_proxy(state: StateFile, entry: StateEntry, *, refresh: bool = True) -> None:
    """按记录还原 WinINET 用户代理（幂等），成功后移除记录。"""
    old = entry.old if isinstance(entry.old, dict) else {}
    for name in WININET_VALUE_NAMES:
        value = old.get(name)
        if value is None:
            _reg_delete(name)
        else:
            _reg_write(name, value)
    if refresh:
        refresh_wininet()
    state.drop(entry.kind, entry.key)
    logger.info("WinINET 用户代理已还原")


# --------------------------------------------------------------------------
# WinHTTP（机器级，需管理员，可选）
# --------------------------------------------------------------------------


def parse_winhttp_show(text: str) -> dict[str, object]:
    """解析 ``netsh winhttp show proxy`` 输出（英文为主；解析失败字段为 None）。"""
    result: dict[str, object] = {"direct": False, "server": None, "bypass": None}
    for line in text.splitlines():
        stripped = line.strip()
        if "Direct access" in stripped:
            result["direct"] = True
        match = re.match(r"Proxy Server\(s\)\s*:\s*(.+)$", stripped)
        if match:
            result["server"] = match.group(1).strip()
        match = re.match(r"Bypass List\s*:\s*(.+)$", stripped)
        if match:
            result["bypass"] = match.group(1).strip()
    return result


def _winhttp_show(runner: Runner) -> str:
    completed = runner(["netsh", "winhttp", "show", "proxy"])
    out = _check(completed, "netsh winhttp show proxy")
    return out


def read_winhttp(runner: Runner = _default_runner) -> dict[str, object]:
    """读取当前 WinHTTP 代理设置（``aaa status`` 用）。"""
    return parse_winhttp_show(_winhttp_show(runner))


def apply_winhttp_proxy(
    state: StateFile,
    host: str,
    port: int,
    *,
    bypass: str = _DEFAULT_WINHTTP_BYPASS,
    runner: Runner = _default_runner,
) -> StateEntry:
    """设置 WinHTTP 机器代理（需管理员），旧值解析后记录（含原文）。"""
    show = _winhttp_show(runner)
    old = {"raw": show, **parse_winhttp_show(show)}
    new = {"server": f"{host}:{port}", "bypass": bypass}
    entry = state.record(kind=KIND_WINHTTP, key="winhttp", old=old, new=new, note="需管理员权限")
    completed = runner(
        [
            "netsh",
            "winhttp",
            "set",
            "proxy",
            f"proxy-server={host}:{port}",
            f"bypass-list={bypass}",
        ]
    )
    _check(completed, "netsh winhttp set proxy")
    logger.info("WinHTTP 机器代理已设置：%s:%d", host, port)
    return entry


def restore_winhttp_proxy(
    state: StateFile, entry: StateEntry, *, runner: Runner = _default_runner
) -> None:
    """按记录还原 WinHTTP 代理（幂等），成功后移除记录。"""
    old = entry.old if isinstance(entry.old, dict) else {}
    if old.get("direct"):
        completed = runner(["netsh", "winhttp", "reset", "proxy"])
        _check(completed, "netsh winhttp reset proxy")
    elif old.get("server"):
        cmd = ["netsh", "winhttp", "set", "proxy", f"proxy-server={old['server']}"]
        if old.get("bypass"):
            cmd.append(f"bypass-list={old['bypass']}")
        completed = runner(cmd)
        _check(completed, "netsh winhttp set proxy（还原）")
    else:
        raw = old.get("raw", "")
        raise ProxySetupError(
            "无法解析旧 WinHTTP 设置（netsh 输出可能被本地化），请人工执行 "
            f"'netsh winhttp show proxy' 核对后还原。原始输出片段：{raw[:200]!r}"
        )
    state.drop(entry.kind, entry.key)
    logger.info("WinHTTP 代理已还原")


__all__ = [
    "KIND_WINHTTP",
    "KIND_WININET",
    "ProxySetupError",
    "WININET_KEY",
    "WININET_VALUE_NAMES",
    "apply_user_proxy",
    "apply_winhttp_proxy",
    "parse_winhttp_show",
    "read_winhttp",
    "read_wininet",
    "refresh_wininet",
    "restore_user_proxy",
    "restore_winhttp_proxy",
]
