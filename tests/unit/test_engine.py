"""CaptureEngine 单测（03 文档 T1.1）：选项封装、模式校验、Ctrl+C 优雅退出。"""

from __future__ import annotations

from pathlib import Path

from aaa.capture.engine import CaptureEngine, ProxyConfig, _validate_mode


def test_build_options_defaults_and_overrides(tmp_path: Path) -> None:
    confdir = tmp_path / "mitm"
    engine = CaptureEngine(ProxyConfig(listen_host="127.0.0.1", listen_port=8080, confdir=confdir))
    opts = engine.build_options()
    assert opts.listen_host == "127.0.0.1"
    assert opts.listen_port == 8080
    assert opts.confdir == str(confdir)
    assert list(opts.mode) == ["regular"]


def test_build_options_port_configurable(tmp_path: Path) -> None:
    engine = CaptureEngine(
        ProxyConfig(listen_port=18080, confdir=tmp_path / "mitm", data_dir=tmp_path)
    )
    assert engine.build_options().listen_port == 18080


def test_confdir_defaults_to_data_mitm(tmp_path: Path) -> None:
    config = ProxyConfig(data_dir=tmp_path / "data")
    assert config.resolved_confdir() == tmp_path / "data" / "mitm"


def test_mode_local_passthrough(tmp_path: Path) -> None:
    """local 模式规格透传给 mitmproxy（实际运行需管理员，T0.3 spike）。"""
    engine = CaptureEngine(ProxyConfig(confdir=tmp_path / "mitm", mode="local"))
    assert list(engine.build_options().mode) == ["local"]


def test_mode_validation_rejects_unknown() -> None:
    import pytest

    with pytest.raises(ValueError, match="不支持的代理模式"):
        _validate_mode("wireguard")


def test_run_blocking_swallows_keyboard_interrupt(tmp_path: Path, monkeypatch) -> None:
    """Ctrl+C（KeyboardInterrupt）被优雅处理，不向外传播。"""

    engine = CaptureEngine(ProxyConfig(confdir=tmp_path / "mitm"))

    def fake_serve() -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(engine, "serve", fake_serve)
    engine.run_blocking()  # 不应抛出
