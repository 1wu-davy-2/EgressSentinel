"""CLI 单测：--help 可运行（T0.1 验收）、local 模式管理员门禁、setup/teardown dry-run。

红线：测试只调用 --dry-run 或被管理员门禁拒绝的路径，绝不真实施改系统设置。
"""

from __future__ import annotations

import re
from pathlib import Path

from typer.testing import CliRunner

from aaa.cli import app

runner = CliRunner()

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _norm(text: str) -> str:
    """去掉 ANSI 颜色码与空白差异（rich 换行/CI 彩色输出不影响断言）。"""
    return " ".join(_ANSI_RE.sub("", text).split())


def test_aaa_help_runs() -> None:
    """T0.1 验收：aaa --help 可运行，包含 P1 全部命令。"""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    out = _norm(result.output)
    for command in ("run", "setup", "teardown"):
        assert command in out


def test_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "0.1.1" in result.output


def test_run_local_rejected_without_admin(monkeypatch) -> None:
    """T0.3：非管理员拒绝 --mode local，并给出 UAC 指引（不进入 mitmproxy）。"""
    import aaa.cli as cli_mod

    monkeypatch.setattr(cli_mod, "is_current_process_elevated", lambda: False)
    result = runner.invoke(app, ["run", "--mode", "local"])
    assert result.exit_code == 2
    assert "管理员" in _norm(result.output)
    assert "UAC" in _norm(result.output) or "终端(管理员)" in _norm(result.output)


def test_run_local_allowed_when_admin_mocked(monkeypatch, tmp_path: Path) -> None:
    """管理员（mock）时通过门禁，进入引擎路径（不真正起代理——注入退出）。"""
    import aaa.cli as cli_mod

    monkeypatch.setattr(cli_mod, "is_current_process_elevated", lambda: True)
    started: list[str] = []

    class FakeEngine:
        def __init__(self, config: object, addons: list[object]) -> None:
            started.append("built")

        def run_blocking(self) -> None:
            started.append("ran")

    monkeypatch.setattr(cli_mod, "CaptureEngine", FakeEngine)
    result = runner.invoke(app, ["run", "--mode", "local", "--data-dir", str(tmp_path / "data")])
    assert result.exit_code == 0
    assert started == ["built", "ran"]


def test_run_invalid_mode_rejected(tmp_path: Path) -> None:
    result = runner.invoke(app, ["run", "--mode", "bogus", "--data-dir", str(tmp_path / "d")])
    assert result.exit_code != 0
    assert "不支持的代理模式" in _norm(result.output)


def test_local_mode_spec_passthrough_and_rejects_mix() -> None:
    """T2.2：--pid/--process 拼装 local 规格；非 local 原样透传。"""
    from aaa.cli import _local_mode_spec

    assert _local_mode_spec("regular", None, None) == "regular"
    assert _local_mode_spec("bogus", None, None) == "bogus"  # 回归：不得变成 local
    assert _local_mode_spec("local", None, None) == "local"
    assert _local_mode_spec("local", 123, None) == "local:pid=123"
    assert _local_mode_spec("local", None, "node.exe") == "local:process=node.exe"
    assert _local_mode_spec("local:pid=1,process=x", None, None) == "local:pid=1,process=x"
    import pytest

    with pytest.raises(ValueError, match="不能与手写"):
        _local_mode_spec("local:pid=1", 2, None)


def test_run_pid_process_require_local_mode(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["run", "--mode", "regular", "--pid", "123", "--data-dir", str(tmp_path / "d")]
    )
    assert result.exit_code != 0
    assert "仅支持 --mode local" in _norm(result.output)


def test_run_pid_and_process_mutually_exclusive(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "run",
            "--mode",
            "local",
            "--pid",
            "1",
            "--process",
            "x",
            "--data-dir",
            str(tmp_path / "d"),
        ],
    )
    assert result.exit_code != 0
    assert "互斥" in _norm(result.output)


def test_run_local_with_pid_passes_gate_and_builds_spec(monkeypatch, tmp_path: Path) -> None:
    """管理员（mock）下 --pid 透传 local:pid=…，事件带原生 PID（pinned process）。"""
    import aaa.cli as cli_mod
    from aaa.store.events import ProcessInfo

    monkeypatch.setattr(cli_mod, "is_current_process_elevated", lambda: True)
    monkeypatch.setattr(
        cli_mod, "resolve_pinned_process", lambda pid, name: ProcessInfo(pid=pid, name=name)
    )
    seen: dict[str, object] = {}

    class FakeEngine:
        def __init__(self, config, addons):  # type: ignore[no-untyped-def]
            seen["mode"] = config.mode  # type: ignore[attr-defined]
            seen["addon"] = addons[0]

        def run_blocking(self) -> None:
            seen["ran"] = True

    monkeypatch.setattr(cli_mod, "CaptureEngine", FakeEngine)
    result = runner.invoke(
        app,
        ["run", "--mode", "local", "--pid", "4242", "--data-dir", str(tmp_path / "d")],
    )
    assert result.exit_code == 0
    assert seen["mode"] == "local:pid=4242"
    addon = seen["addon"]
    assert addon.pinned_process is not None  # type: ignore[attr-defined]
    assert addon.pinned_process.pid == 4242  # type: ignore[attr-defined]
    assert seen.get("ran") is True


def test_run_regular_starts_with_attribution_and_pipeline(monkeypatch, tmp_path: Path) -> None:
    """regular 模式 CLI 装配：addon 带归因器与策略管线。"""
    import aaa.cli as cli_mod

    monkeypatch.setattr(cli_mod, "is_current_process_elevated", lambda: True)
    seen: dict[str, object] = {}

    class FakeEngine:
        def __init__(self, config, addons):  # type: ignore[no-untyped-def]
            seen["addon"] = addons[0]

        def run_blocking(self) -> None:
            pass

    monkeypatch.setattr(cli_mod, "CaptureEngine", FakeEngine)
    result = runner.invoke(app, ["run", "--data-dir", str(tmp_path / "d")])
    assert result.exit_code == 0
    addon = seen["addon"]
    assert addon.attributor is not None  # type: ignore[attr-defined]
    assert addon.pipeline is not None  # type: ignore[attr-defined]
    assert addon.pipeline.policy.mode == "dry-run"  # type: ignore[attr-defined]
    assert addon.pinned_process is None  # type: ignore[attr-defined]


def test_run_bad_policy_file_rejected(tmp_path: Path) -> None:
    """策略文件非法：启动期报错退出，不进入引擎。"""
    bad = tmp_path / "bad.yaml"
    bad.write_text("mode: bogus\n", encoding="utf-8")
    result = runner.invoke(app, ["run", "--policy", str(bad), "--data-dir", str(tmp_path / "d")])
    assert result.exit_code != 0
    assert "策略校验失败" in _norm(result.output)


def test_setup_ca_dry_run_generates_ca_but_touches_nothing(tmp_path: Path) -> None:
    """dry-run：CA 文件生成在 data/mitm（文件系统），但证书存储与状态文件不动。"""
    data = tmp_path / "data"
    result = runner.invoke(
        app, ["setup", "ca", "--store", "user", "--dry-run", "--data-dir", str(data)]
    )
    assert result.exit_code == 0
    assert "dry-run" in _norm(result.output)
    assert (data / "mitm" / "mitmproxy-ca-cert.pem").exists()
    assert not (data / "setup-state.json").exists()  # 未写状态文件


def test_setup_ca_invalid_store_rejected(tmp_path: Path) -> None:
    result = runner.invoke(app, ["setup", "ca", "--store", "floppy", "--data-dir", str(tmp_path)])
    assert result.exit_code != 0


def test_setup_ca_machine_requires_admin(monkeypatch, tmp_path: Path) -> None:
    import aaa.cli as cli_mod

    monkeypatch.setattr(cli_mod, "is_current_process_elevated", lambda: False)
    result = runner.invoke(app, ["setup", "ca", "--store", "machine", "--data-dir", str(tmp_path)])
    assert result.exit_code == 2
    assert "管理员" in _norm(result.output)


def test_setup_proxy_dry_run(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["setup", "proxy", "--port", "8080", "--dry-run", "--data-dir", str(tmp_path / "d")]
    )
    assert result.exit_code == 0
    assert "8080" in _norm(result.output)
    assert "dry-run" in _norm(result.output)


def test_setup_env_dry_run_lists_vars(tmp_path: Path) -> None:
    result = runner.invoke(app, ["setup", "env", "--dry-run", "--data-dir", str(tmp_path / "d")])
    assert result.exit_code == 0
    out = _norm(result.output)
    for name in ("HTTP_PROXY", "NODE_USE_ENV_PROXY", "REQUESTS_CA_BUNDLE", "NO_PROXY"):
        assert name in out
    assert "dry-run" in out


def test_teardown_empty_state_is_noop(tmp_path: Path) -> None:
    result = runner.invoke(app, ["teardown", "--data-dir", str(tmp_path / "d")])
    assert result.exit_code == 0
    assert "没有需要还原" in _norm(result.output)


def test_teardown_dry_run_lists_without_executing(tmp_path: Path) -> None:
    from aaa.setup.state import StateFile

    data = tmp_path / "data"
    StateFile(data / "setup-state.json").record(kind="env_var", key="HTTP_PROXY", old=None, new="x")
    result = runner.invoke(app, ["teardown", "--dry-run", "--data-dir", str(data)])
    assert result.exit_code == 0
    assert "env_var:HTTP_PROXY" in _norm(result.output)
    assert len(StateFile(data / "setup-state.json").entries()) == 1  # 记录未删


def test_teardown_unknown_target_rejected(tmp_path: Path) -> None:
    result = runner.invoke(app, ["teardown", "bogus", "--data-dir", str(tmp_path)])
    assert result.exit_code != 0
