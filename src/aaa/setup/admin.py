"""管理员权限检测（03 文档 T0.3，仅 Windows 有效）。

local 模式（mitmproxy --mode local / WinDivert）必须管理员权限；
非管理员时 CLI 必须拒绝运行并给出 UAC 提升指引，绝不能半途失败。
"""

from __future__ import annotations

import ctypes
import logging
import os

logger = logging.getLogger(__name__)

TOKEN_QUERY = 0x0008
_TOKEN_ELEVATION = 20


def is_current_process_elevated() -> bool:
    """当前进程是否以管理员令牌运行。

    非 Windows 平台恒为 ``False``（02 文档 §1.2：v1 仅 Windows）；
    ``IsUserAnAdmin`` 不可用时回退到 ``GetTokenInformation(TokenElevation)``。
    """
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001 - 任何 ctypes 失败都走令牌兜底
        logger.debug("IsUserAnAdmin 不可用，回退 GetTokenInformation", exc_info=True)
        return _elevated_via_token()


def _elevated_via_token() -> bool:
    """通过 advapi32 ``GetTokenInformation(TokenElevation)`` 判断提权状态。"""
    from ctypes import wintypes  # 非 Windows 无法导入，延迟到仅 nt 路径执行的函数内

    try:
        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32
        handle = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(handle)
        ):
            return False
        try:
            elevation = wintypes.DWORD()
            returned = wintypes.DWORD()
            ok = advapi32.GetTokenInformation(
                handle,
                _TOKEN_ELEVATION,
                ctypes.byref(elevation),
                ctypes.sizeof(elevation),
                ctypes.byref(returned),
            )
            return bool(ok) and bool(elevation.value)
        finally:
            kernel32.CloseHandle(handle)
    except Exception:  # noqa: BLE001 - 检测本身绝不抛异常
        logger.exception("令牌提权检测失败，按非管理员处理")
        return False
