"""P4 CLI 单测（03 文档 T4.2）：status/report/trim/tail/harden/setup 向导/teardown 计划打印。

红线：系统相关路径一律 dry-run 或注入假后端；不真实施改系统设置。
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aaa.cli import app
from aaa.store.db import DbEventStore
from aaa.store.events import (
    AuditEvent,
    Destination,
    ProcessInfo,
    RequestInfo,
)

runner = CliRunner()


@pytest.fixture
def wide(monkeypatch: pytest.MonkeyPatch) -> None:
    """加宽 CLI console：避免 rich 在 80 列下截断单元格内容影响断言。"""
    from rich.console import Console

    import aaa.cli as cli_mod

    monkeypatch.setattr(cli_mod, "console", Console(width=300))


def _norm(text: str) -> str:
    return " ".join(text.split())


def _seed_db(data: Path, *, verdicts: tuple[str, ...] = ("allow", "confirm")) -> DbEventStore:
    store = DbEventStore(data / "audit.db", evidence_dir=data / "evidence")
    for i, verdict in enumerate(verdicts):
        store.append(
            AuditEvent(
                id=f"evt_{i}",
                ts=f"2026-10-24T10:0{i}:00+08:00",
                mode="regular",
                verdict=verdict,
                risk_score=60 if verdict == "confirm" else 10,
                process=ProcessInfo(pid=100 + i, name="node.exe", profile="agent_cli"),
                destination=Destination(host=f"h{i}.example.com", port=443),
                request=RequestInfo(method="GET", path=f"/p{i}", size=10),
            )
        )
    return store


@pytest.fixture
def data(tmp_path: Path) -> Path:
    data = tmp_path / "data"
    store = _seed_db(data)
    store.close()
    return data


def test_status_shows_proxy_ca_policy_and_recent_events(data: Path, wide: None) -> None:
    result = runner.invoke(app, ["status", "--data-dir", str(data)])
    assert result.exit_code == 0, result.output
    out = _norm(result.output)
    for label in ("WinINET", "WinHTTP", "CA", "防火墙加固", "策略"):
        assert label in out, f"status 缺少 {label} 段"
    assert "dry-run" in out, "策略版本/模式应展示"
    assert "evt_0" in out and "evt_1" in out, "最近事件（5 条内）应展示"
    assert "node.exe(100)" in out
    assert "2 条" in out, "事件计数应展示"


def test_status_warns_about_pending_state_entries(data: Path) -> None:
    """R7：状态文件有未还原记录时提示（崩溃残留自检）。"""
    from aaa.setup.state import StateFile

    StateFile(data / "setup-state.json").record(kind="env_var", key="HTTP_PROXY", old=None, new="x")
    result = runner.invoke(app, ["status", "--data-dir", str(data)])
    assert result.exit_code == 0
    assert "未还原" in _norm(result.output) and "teardown" in _norm(result.output)


def test_status_empty_data_dir(tmp_path: Path) -> None:
    result = runner.invoke(app, ["status", "--data-dir", str(tmp_path / "empty")])
    assert result.exit_code == 0
    assert "0 条" in _norm(result.output)


def test_trim_command_deletes_old_events(data: Path) -> None:
    store = _seed_db(data, verdicts=("allow",))
    # 追加一条过期事件
    from aaa.store.events import Destination as D
    from aaa.store.events import RequestInfo as R

    store.append(
        AuditEvent(
            id="evt_old",
            ts="2026-10-01T00:00:00+08:00",
            mode="regular",
            destination=D(host="old.com", port=80),
            request=R(method="GET", path="/", size=0),
        )
    )
    store.close()
    result = runner.invoke(app, ["trim", "--days", "7", "--data-dir", str(data)])
    assert result.exit_code == 0, result.output
    assert "1 条事件" in _norm(result.output)
    fresh = DbEventStore(data / "audit.db")
    try:
        assert fresh.count() == 2, "只删过期事件（evt_0/evt_1 在保留期内）"
        assert fresh.get("evt_old") is None
    finally:
        fresh.close()


def test_report_rich_json_csv(data: Path) -> None:
    result = runner.invoke(app, ["report", "--data-dir", str(data)])
    assert result.exit_code == 0, result.output
    assert "confirm" in _norm(result.output) and "h0.example.com" in _norm(result.output)

    result = runner.invoke(app, ["report", "--json", "--data-dir", str(data)])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["total"] == 2
    assert payload["by_verdict"]["confirm"] == 1

    result = runner.invoke(app, ["report", "--csv", "--since", "24h", "--data-dir", str(data)])
    assert result.exit_code == 0
    lines = result.output.strip().splitlines()
    assert lines[0] == "section,key,extra,count"
    assert any(line.startswith("verdict,confirm") for line in lines)

    both = runner.invoke(app, ["report", "--json", "--csv", "--data-dir", str(data)])
    assert both.exit_code != 0, "--json 与 --csv 互斥"
    bad = runner.invoke(app, ["report", "--since", "bogus", "--data-dir", str(data)])
    assert bad.exit_code != 0


def test_report_verify_evidence_flag(data: Path) -> None:
    result = runner.invoke(app, ["report", "--json", "--verify-evidence", "--data-dir", str(data)])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["evidence_integrity"]["checked"] == 0  # 无证据文件


def test_tail_once_polls_and_exits(data: Path, wide: None) -> None:
    result = runner.invoke(app, ["tail", "--once", "--from-start", "--data-dir", str(data)])
    assert result.exit_code == 0, result.output
    out = _norm(result.output)
    assert "evt_0" in out and "evt_1" in out
    assert "GET h0.example.com/p0" in out
    # 默认游标 = 当前末尾：不加 --from-start 时看不到已有事件
    default_cursor = runner.invoke(app, ["tail", "--once", "--data-dir", str(data)])
    assert default_cursor.exit_code == 0
    assert "evt_0" not in _norm(default_cursor.output)
    # 过滤参数透传
    filtered = runner.invoke(
        app, ["tail", "--once", "--from-start", "--verdict", "confirm", "--data-dir", str(data)]
    )
    assert filtered.exit_code == 0
    assert "evt_1" in _norm(filtered.output)
    assert "evt_0" not in _norm(filtered.output)


def test_harden_placeholder_replaced_by_real_command(monkeypatch, tmp_path: Path) -> None:
    """v0.2.0：harden 已实装（05 文档波次二）。旧占位行为（恒 exit 1 + 提示未实施）不再存在。

    红线：netsh 全 mock（绝不真实施改防火墙）；非管理员路径走门禁拒绝（exit 2）。
    """
    from aaa.setup import firewall as fw

    monkeypatch.setattr("aaa.cli.is_current_process_elevated", lambda: False)
    monkeypatch.setattr(fw, "is_current_process_elevated", lambda: False)
    calls: list[list[str]] = []

    def fake_netsh(args: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(list(args))
        return subprocess.CompletedProcess(args, 0, "确定。", "")

    monkeypatch.setattr(fw, "_run_netsh", fake_netsh)
    # off 无记录：无需管理员，零改动成功
    result = runner.invoke(app, ["harden", "off", "--data-dir", str(tmp_path / "d")])
    assert result.exit_code == 0
    assert "没有防火墙加固记录" in _norm(result.output)
    assert calls == [], "无记录时不得触达 netsh"
    # on：非管理员被门禁拒绝（exit 2），不触达 netsh
    result = runner.invoke(app, ["harden", "on", "--data-dir", str(tmp_path / "d")])
    assert result.exit_code == 2
    assert "管理员" in _norm(result.output)
    assert calls == []
    # 非法参数仍被拒
    assert runner.invoke(app, ["harden", "bogus"]).exit_code != 0


def test_teardown_prints_plan_before_executing(
    data: Path, fake_backends: tuple[dict[str, str], dict[str, object]]
) -> None:
    """执行前打印将要还原的改动清单（工作约定）。

    红线：必须挂 ``fake_backends``——CLI teardown 会真实执行 ``teardown.RESTORERS``
    还原函数（调用时才解析模块级 ``_env_delete`` 等），不注入假后端就会对真实
    ``HKCU\\Environment`` 调 ``winreg.DeleteValue``，可能删掉用户真实的环境变量。
    """
    from aaa.setup.state import StateFile

    StateFile(data / "setup-state.json").record(
        kind="env_var", key="HTTP_PROXY", old=None, new="http://127.0.0.1:8080"
    )
    result = runner.invoke(app, ["teardown", "--data-dir", str(data)])
    assert result.exit_code == 0, result.output
    out = _norm(result.output)
    assert "将按状态文件逆序还原 1 项改动" in out
    assert "env_var:HTTP_PROXY" in out, "计划清单必须先于执行打印"
    assert "已还原" in out
    # 还原发生在假后端上：dict 被清空（old=None → 删除），真实系统未被触碰
    env_registry, _inet_registry = fake_backends
    assert "HTTP_PROXY" not in env_registry


def test_setup_wizard_dry_run_executes_nothing(tmp_path: Path) -> None:
    """向导 dry-run：只打印计划，不写状态文件、不改系统。"""
    result = runner.invoke(app, ["setup", "--dry-run", "--yes", "--data-dir", str(tmp_path / "d")])
    assert result.exit_code == 0, result.output
    out = _norm(result.output)
    for title in ("CA 根证书", "系统代理", "用户环境变量"):
        assert title in out, f"向导缺少 {title} 步骤"
    assert "未实施" in out
    assert not (tmp_path / "d" / "setup-state.json").exists()


def test_setup_wizard_declined_steps_touch_nothing(tmp_path: Path) -> None:
    """全程拒绝确认：向导完成但零改动。"""
    result = runner.invoke(app, ["setup", "--data-dir", str(tmp_path / "d")], input="n\nn\nn\n")
    assert result.exit_code == 0, result.output
    assert "未执行任何改动" in _norm(result.output)
    assert not (tmp_path / "d" / "setup-state.json").exists()


def test_setup_wizard_subcommands_still_work(tmp_path: Path) -> None:
    """`aaa setup ca --dry-run` 子命令路径不受向导回调影响。"""
    result = runner.invoke(
        app, ["setup", "ca", "--store", "user", "--dry-run", "--data-dir", str(tmp_path / "d")]
    )
    assert result.exit_code == 0
    assert "dry-run" in _norm(result.output)


def test_web_command_rejects_non_loopback(tmp_path: Path) -> None:
    """03 文档 T5.1：面板仅允许 127.0.0.1/localhost/::1。"""
    result = runner.invoke(app, ["web", "--host", "0.0.0.0", "--data-dir", str(tmp_path)])
    assert result.exit_code != 0
    assert "本地回环" in _norm(result.output)
    result = runner.invoke(app, ["web", "--host", "192.168.1.5", "--data-dir", str(tmp_path)])
    assert result.exit_code != 0
