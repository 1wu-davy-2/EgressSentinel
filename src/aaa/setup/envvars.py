"""用户环境变量下发（03 文档 T1.4，02 文档 D1 清单）。

写入 ``HKCU\\Environment``（用户级、持久化），并广播 ``WM_SETTINGCHANGE``
通知资源管理器与新进程（等价于 setx 的生效机制，且无 1024 字符截断）。
全部改动先读旧值、先记入 ``data/setup-state.json``（journal-first），再实施。

安全红线：单元测试注入假注册表/假广播，绝不真实施改用户环境变量。
"""

from __future__ import annotations

import ctypes
import logging
import os
from pathlib import Path

from aaa.setup.state import StateEntry, StateFile

logger = logging.getLogger(__name__)

ENV_KEY = "Environment"
KIND_ENV_VAR = "env_var"
KIND_FILE_CREATED = "file_created"

#: 02 文档 D1 环境变量清单（用户级）
ENV_VAR_NAMES: tuple[str, ...] = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "NODE_USE_ENV_PROXY",
    "NODE_EXTRA_CA_CERTS",
    "REQUESTS_CA_BUNDLE",
    "SSL_CERT_FILE",
    "CURL_CA_BUNDLE",
)

#: 02 文档 D1：NO_PROXY=localhost,127.0.0.1
NO_PROXY_VALUE = "localhost,127.0.0.1"

_HWND_BROADCAST = 0xFFFF
_WM_SETTINGCHANGE = 0x001A
_SMTO_ABORTIFHUNG = 0x0002


class EnvVarSetupError(RuntimeError):
    """环境变量设置失败。"""


# --------------------------------------------------------------------------
# 注册表访问层（模块级函数，测试注入假实现）
# --------------------------------------------------------------------------


def _env_read(name: str) -> str | None:
    """读用户环境变量（HKCU\\Environment）；不存在返回 None。"""
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, ENV_KEY) as key:
            value, _value_type = winreg.QueryValueEx(key, name)
            return str(value)
    except FileNotFoundError:
        return None


def _env_write(name: str, value: str) -> None:
    """写用户环境变量（REG_SZ）。"""
    import winreg

    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, ENV_KEY) as key:
        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)


def _env_delete(name: str) -> None:
    """删除用户环境变量（不存在为幂等 no-op）。"""
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, ENV_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, name)
    except FileNotFoundError:
        pass


def broadcast_env_change() -> None:
    """广播 ``WM_SETTINGCHANGE``，让资源管理器/新进程感知环境变量变化。"""
    if os.name != "nt":  # 非 Windows 无资源管理器可通知，静默跳过
        logger.debug("非 Windows 平台，跳过 WM_SETTINGCHANGE 广播")
        return
    from ctypes import wintypes  # 仅 Windows 可导入，延迟到函数内

    user32 = ctypes.windll.user32  # type: ignore[attr-defined]
    result = wintypes.DWORD()
    user32.SendMessageTimeoutW(
        _HWND_BROADCAST,
        _WM_SETTINGCHANGE,
        wintypes.WPARAM(0),
        wintypes.LPARAM(ctypes.addressof(ctypes.create_unicode_buffer("Environment"))),
        _SMTO_ABORTIFHUNG,
        5000,
        ctypes.byref(result),
    )


# --------------------------------------------------------------------------
# 值构造与应用
# --------------------------------------------------------------------------


def build_env_values(
    proxy_host: str,
    proxy_port: int,
    ca_cert_pem: Path,
    merged_pem: Path,
) -> dict[str, str]:
    """按 02 文档 D1 构造需要下发的用户环境变量值。"""
    proxy = f"http://{proxy_host}:{proxy_port}"
    return {
        "HTTP_PROXY": proxy,
        "HTTPS_PROXY": proxy,
        "NO_PROXY": NO_PROXY_VALUE,
        "NODE_USE_ENV_PROXY": "1",
        "NODE_EXTRA_CA_CERTS": str(ca_cert_pem),
        "REQUESTS_CA_BUNDLE": str(merged_pem),
        "SSL_CERT_FILE": str(merged_pem),
        "CURL_CA_BUNDLE": str(merged_pem),
    }


def apply_user_envvars(
    state: StateFile,
    values: dict[str, str],
    *,
    names: tuple[str, ...] | None = None,
    broadcast: bool = True,
) -> list[StateEntry]:
    """逐个写入用户环境变量并记录旧值（journal-first），返回记录列表。"""
    entries: list[StateEntry] = []
    try:
        for name in names or tuple(sorted(values)):
            old = _env_read(name)
            new_value = str(values[name])
            entries.append(state.record(kind=KIND_ENV_VAR, key=name, old=old, new=new_value))
            _env_write(name, new_value)
    except Exception as exc:
        raise EnvVarSetupError(
            f"写入用户环境变量失败（已写入部分可 teardown 还原）：{exc}"
        ) from exc
    if broadcast:
        broadcast_env_change()
    logger.info("用户环境变量已下发：%s", ", ".join(sorted(values)))
    return entries


def restore_user_envvar(state: StateFile, entry: StateEntry, *, broadcast: bool = True) -> None:
    """按记录还原单个用户环境变量（幂等），成功后移除记录。"""
    if entry.old is None:
        _env_delete(entry.key)
    else:
        _env_write(entry.key, str(entry.old))
    state.drop(entry.kind, entry.key)
    if broadcast:
        broadcast_env_change()
    logger.info("用户环境变量已还原：%s", entry.key)


def record_file_created(state: StateFile, path: Path) -> StateEntry:
    """记录本工具创建的文件（如合并 PEM），teardown 时删除。"""
    return state.record(
        kind=KIND_FILE_CREATED,
        key=str(path),
        old=None,
        new=str(path),
    )


def restore_file_created(state: StateFile, entry: StateEntry) -> None:
    """删除本工具创建的文件（幂等），成功后移除记录。"""
    path = Path(entry.key)
    if path.exists() and path.is_file():
        path.unlink()
    state.drop(entry.kind, entry.key)
    logger.info("已删除工具创建的文件：%s", entry.key)


__all__ = [
    "ENV_KEY",
    "ENV_VAR_NAMES",
    "EnvVarSetupError",
    "KIND_ENV_VAR",
    "KIND_FILE_CREATED",
    "NO_PROXY_VALUE",
    "apply_user_envvars",
    "broadcast_env_change",
    "build_env_values",
    "record_file_created",
    "restore_file_created",
    "restore_user_envvar",
]
