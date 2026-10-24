"""P4 T4.3 崩溃安全 E2E：「设置改动后强杀进程，重启 teardown 依据状态文件完整还原」。

不真实施改系统（红线）：
- 注册表/环境变量经 ``fake_backends`` 注入假实现（dict 后端）；
- "强杀进程" = 改动落盘（journal-first 状态文件）后**不做任何还原**就结束本阶段，
  模拟进程携带内存状态消失；所有持久化都在磁盘上，可被"新进程"接手；
- "重启" = 全新 ``StateFile``/CLI 调用重新从磁盘读状态文件。

场景：
1. 三类改动（WinINET 代理、用户环境变量、CA 记录）落盘 → 模拟强杀 → 新进程
   ``aaa teardown`` 全量还原，注册表/环境变量与改动前逐键一致；
2. journal-first 语义：记录已写、改动**未实施**即"崩溃" → teardown 幂等 no-op，
   系统仍与改动前一致；
3. 状态文件记录带时间戳与旧值（03 文档 T4.3 要求）。

``fake_backends`` 夹具见 tests/conftest.py（unit 与 e2e 共享）。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aaa.cli import app
from aaa.setup import ca as ca_mod
from aaa.setup import envvars, proxy, teardown
from aaa.setup.state import StateFile

runner = CliRunner()


def test_crash_then_restart_teardown_restores_everything(
    fake_backends: tuple[dict[str, str], dict[str, object]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """改动落盘 → 强杀 → 新进程 aaa teardown 完整还原（含 CA 记录）。"""
    env_registry, inet_registry = fake_backends
    env_registry["NODE_USE_ENV_PROXY"] = "0"
    env_registry["HTTP_PROXY"] = "http://old-proxy:3128"
    env_before = dict(env_registry)
    inet_before = dict(inet_registry)
    state_file = tmp_path / "setup-state.json"

    # —— "进程 A"：执行 setup 改动（journal-first 落盘）——
    state = StateFile(state_file)
    proxy.apply_user_proxy(state, "127.0.0.1", 8080)
    envvars.apply_user_envvars(
        state,
        {
            "HTTP_PROXY": "http://127.0.0.1:8080",
            "NODE_USE_ENV_PROXY": "1",
            "NEW_VAR_WITHOUT_OLD": "x",
        },
        broadcast=False,
    )
    uninstalled: list[str] = []
    monkeypatch.setattr(
        ca_mod, "uninstall_user_root", lambda serial, **_kw: uninstalled.append(serial) or 1
    )
    ca_serial = "0ABCDEF1234567890"
    state.record(
        kind=teardown.KIND_CA_USER,
        key=f"user:Root:{ca_serial}",
        old=None,
        new={"store": "user", "serial": ca_serial, "path": "data/mitm/mitmproxy-ca-cert.pem"},
    )
    assert inet_registry["ProxyEnable"] == 1
    assert env_registry["HTTP_PROXY"] == "http://127.0.0.1:8080"
    # —— 强杀：到此为止，不做任何还原（进程 A 终止）——

    # 落盘校验：状态文件在磁盘上、带时间戳与旧值（03 文档 T4.3）
    on_disk = json.loads(state_file.read_text(encoding="utf-8"))
    assert len(on_disk["entries"]) == 5
    for entry in on_disk["entries"]:
        assert entry["ts"], "每条记录必须带时间戳"
    by_key = {e["key"]: e for e in on_disk["entries"]}
    assert by_key["HTTP_PROXY"]["old"] == "http://old-proxy:3128", "必须记录旧值"
    assert by_key["NODE_USE_ENV_PROXY"]["old"] == "0"
    assert by_key["NEW_VAR_WITHOUT_OLD"]["old"] is None

    # —— "进程 B"（重启）：CLI teardown 依据状态文件还原 ——
    result = runner.invoke(app, ["teardown", "--data-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "teardown 完成" in result.output

    # 系统状态与改动前逐键一致
    assert env_registry == env_before, f"环境变量必须完整还原：{env_registry}"
    assert inet_registry == inet_before, f"注册表必须完整还原：{inet_registry}"
    assert uninstalled == [ca_serial], "CA 必须按序列号精确卸载"
    assert StateFile(state_file).entries() == [], "还原后记录清空"

    # —— 幂等：再跑一次 teardown 无操作 ——
    result2 = runner.invoke(app, ["teardown", "--data-dir", str(tmp_path)])
    assert result2.exit_code == 0
    assert "没有需要还原" in result2.output


def test_crash_between_journal_and_apply_is_idempotent_restore(
    fake_backends: tuple[dict[str, str], dict[str, object]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """journal-first：记录落盘后、改动实施前"崩溃" → teardown 重放为幂等 no-op。"""
    env_registry, inet_registry = fake_backends
    env_before = dict(env_registry)
    inet_before = dict(inet_registry)
    state_file = tmp_path / "setup-state.json"

    # 模拟：apply 第一步写注册表就"被 kill"（异常模拟进程消失）
    def _explode(name: str, value: object) -> None:
        raise KeyboardInterrupt("simulated kill -9 between journal and apply")

    monkeypatch.setattr(proxy, "_reg_write", _explode)
    with pytest.raises(KeyboardInterrupt):
        proxy.apply_user_proxy(StateFile(state_file), "127.0.0.1", 8080)

    # "崩溃"后：记录已在磁盘上，但注册表未被改动
    assert len(StateFile(state_file).entries()) == 1
    assert inet_registry == inet_before, "记录已写但改动未实施"

    # 重启进程：teardown 依据记录还原 → 幂等 no-op（删除不存在的值），系统仍一致
    result = runner.invoke(app, ["teardown", "--data-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert inet_registry == inet_before
    assert env_registry == env_before
    assert StateFile(state_file).entries() == []
