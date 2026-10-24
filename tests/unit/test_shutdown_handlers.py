"""关机/注销优雅退出处理器单测（纯逻辑，不触发真实 os._exit）。"""

from __future__ import annotations

import sys

import pytest

from aaa.capture import engine


def test_is_shutdown_event_mapping() -> None:
    # 接管：CTRL_CLOSE(2) / CTRL_LOGOFF(5) / CTRL_SHUTDOWN(6)
    assert engine.is_shutdown_event(2) is True
    assert engine.is_shutdown_event(5) is True
    assert engine.is_shutdown_event(6) is True
    # 不接管：Ctrl+C(0) 交给 KeyboardInterrupt 原路径；CTRL_BREAK(1) 默认处理
    assert engine.is_shutdown_event(0) is False
    assert engine.is_shutdown_event(1) is False
    assert engine.is_shutdown_event(3) is False


@pytest.mark.skipif(sys.platform != "win32", reason="SetConsoleCtrlHandler 仅 Windows")
def test_install_registers_handler_and_keeps_ref() -> None:
    before = len(engine._HANDLER_REFS)
    engine.install_shutdown_handlers(lambda: None, timeout=1.0)
    assert len(engine._HANDLER_REFS) == before + 1  # 回调引用保活，防 GC 失效
