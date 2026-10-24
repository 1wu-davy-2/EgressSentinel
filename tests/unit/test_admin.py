"""管理员检测单测（03 文档 T0.3）：ctypes 路径全部用假 windll 模拟。"""

from __future__ import annotations

import ctypes

import pytest

from aaa.setup import admin


class FakeShell32:
    def __init__(self, result: int | Exception) -> None:
        self._result = result

    def IsUserAnAdmin(self) -> int:
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


class FakeAdvapi32:
    def __init__(self, open_ok: bool) -> None:
        self._open_ok = open_ok

    def OpenProcessToken(self, *args: object) -> int:
        return 1 if self._open_ok else 0

    def GetTokenInformation(self, *args: object) -> int:  # pragma: no cover - 本组测试不触达
        return 0


class FakeKernel32:
    def GetCurrentProcess(self) -> int:  # pragma: no cover - 不会被断言
        return 0

    def CloseHandle(self, handle: object) -> int:
        return 1


class FakeWinDLL:
    def __init__(self, shell32: object = None, advapi32: object = None) -> None:
        self.shell32 = shell32 if shell32 is not None else FakeShell32(0)
        self.advapi32 = advapi32 if advapi32 is not None else FakeAdvapi32(False)
        self.kernel32 = FakeKernel32()


def test_windows_admin_true(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ctypes, "windll", FakeWinDLL(shell32=FakeShell32(1)))
    assert admin.is_current_process_elevated() is True


def test_windows_non_admin_false(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ctypes, "windll", FakeWinDLL(shell32=FakeShell32(0)))
    assert admin.is_current_process_elevated() is False


def test_is_user_an_admin_failure_falls_back_to_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ctypes, "windll", FakeWinDLL(shell32=FakeShell32(OSError("missing entry point")))
    )
    # 兜底路径 OpenProcessToken 失败 → False（检测绝不抛异常）
    assert admin.is_current_process_elevated() is False


def test_non_windows_platform_returns_false(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(admin.os, "name", "posix")
    assert admin.is_current_process_elevated() is False


def test_real_detection_returns_bool() -> None:
    """真实调用冒烟：本进程检测结果必须是 bool（不抛异常）。

    在非管理员 CI 会话中恒为 False；在管理员会话中为 True——只断言类型契约。
    """
    assert isinstance(admin.is_current_process_elevated(), bool)


@pytest.mark.parametrize("open_ok", [True, False])
def test_token_fallback_never_raises(monkeypatch: pytest.MonkeyPatch, open_ok: bool) -> None:
    monkeypatch.setattr(
        ctypes,
        "windll",
        FakeWinDLL(shell32=FakeShell32(OSError("boom")), advapi32=FakeAdvapi32(open_ok)),
    )
    result = admin._elevated_via_token()
    assert isinstance(result, bool)
