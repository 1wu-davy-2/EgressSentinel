"""teardown 单测（03 文档 T1.5）：逆序幂等还原。

核心场景：「改两项 → 还原 → 再还原」幂等；全部基于注入的假注册表（红线：不碰系统）。
``fake_backends`` 夹具见 tests/conftest.py（共享：unit 与 e2e 的 CLI teardown 同用）。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aaa.setup import envvars, proxy, teardown
from aaa.setup.state import StateFile


def test_modify_two_restore_then_restore_again_is_idempotent(
    fake_backends: tuple[dict[str, str], dict[str, object]], tmp_path: Path
) -> None:
    env_registry, inet_registry = fake_backends
    env_registry["NODE_USE_ENV_PROXY"] = "0"  # 预置一个将被覆盖的旧值
    env_before = dict(env_registry)
    inet_before = dict(inet_registry)
    state_file = tmp_path / "setup-state.json"
    state = StateFile(state_file)

    # —— 改动两项：WinINET 代理 + 环境变量（2 个）——
    proxy.apply_user_proxy(state, "127.0.0.1", 8080)
    envvars.apply_user_envvars(
        state, {"HTTP_PROXY": "http://127.0.0.1:8080", "NODE_USE_ENV_PROXY": "1"}
    )
    assert inet_registry["ProxyEnable"] == 1
    assert env_registry["HTTP_PROXY"] == "http://127.0.0.1:8080"
    assert env_registry["NODE_USE_ENV_PROXY"] == "1"
    assert len(state.entries()) == 3

    # —— 第一次还原 ——
    report1 = teardown.run_teardown(state_file)
    assert report1.ok, report1.errors
    assert sorted(report1.restored) == sorted(
        [
            f"{proxy.KIND_WININET}:{proxy.WININET_KEY}",
            f"{envvars.KIND_ENV_VAR}:HTTP_PROXY",
            f"{envvars.KIND_ENV_VAR}:NODE_USE_ENV_PROXY",
        ]
    )
    assert env_registry == env_before, "环境变量必须与改动前一致"
    assert inet_registry == inet_before, "注册表必须与改动前一致"
    assert state.entries() == [], "还原成功后记录必须清空"

    # —— 第二次还原：无记录 → 无操作（幂等）——
    report2 = teardown.run_teardown(state_file)
    assert report2.restored == []
    assert report2.failed == []
    assert env_registry == env_before
    assert inet_registry == inet_before


def test_teardown_restores_in_reverse_order(
    fake_backends: tuple[dict[str, str], dict[str, object]], tmp_path: Path
) -> None:
    """逆序：后改的先还原（如先预置 HTTP_PROXY 旧值再下发，应还原为旧值）。"""
    env_registry, _inet = fake_backends
    state_file = tmp_path / "setup-state.json"
    state = StateFile(state_file)
    envvars.apply_user_envvars(state, {"HTTP_PROXY": "http://first:1"}, broadcast=False)
    envvars.apply_user_envvars(state, {"HTTP_PROXY": "http://second:2"}, broadcast=False)

    report = teardown.run_teardown(state_file)
    assert report.ok
    # 逆序还原：entry2(old="first") 先还原 → "first"；entry1(old=None) 再还原 → 删除。
    # 若实现为正序，entry1 先删、entry2 再写 "first"，会残留旧值——此处以「回到不存在」断言区分。
    assert "HTTP_PROXY" not in env_registry, "必须逆序还原到最初状态（不存在）"


def test_teardown_kind_filter(
    fake_backends: tuple[dict[str, str], dict[str, object]], tmp_path: Path
) -> None:
    env_registry, inet_registry = fake_backends
    state_file = tmp_path / "setup-state.json"
    state = StateFile(state_file)
    proxy.apply_user_proxy(state, "127.0.0.1", 8080)
    envvars.apply_user_envvars(state, {"HTTP_PROXY": "http://127.0.0.1:8080"}, broadcast=False)

    report = teardown.run_teardown(state_file, kinds={"env_var"})
    assert report.ok
    assert env_registry == {}, "env 已还原"
    assert inet_registry["ProxyEnable"] == 1, "proxy 不在范围内，保持不动"
    assert [e.kind for e in state.entries()] == [proxy.KIND_WININET]


def test_teardown_invalid_target_rejected() -> None:
    with pytest.raises(ValueError, match="ca/proxy/env"):
        teardown.teardown_target_kinds(("bogus",))
    assert teardown.teardown_target_kinds(("ca", "env")) == {
        teardown.KIND_CA_USER,
        teardown.KIND_CA_MACHINE,
        envvars.KIND_ENV_VAR,
        envvars.KIND_FILE_CREATED,
    }
    assert teardown.teardown_target_kinds(None) is None


def test_teardown_failure_keeps_entry_for_retry(
    fake_backends: tuple[dict[str, str], dict[str, object]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_file = tmp_path / "setup-state.json"
    state = StateFile(state_file)
    envvars.apply_user_envvars(state, {"HTTP_PROXY": "http://127.0.0.1:8080"}, broadcast=False)

    original_restorer = teardown.RESTORERS[envvars.KIND_ENV_VAR]

    def broken(state: StateFile, entry: object) -> None:
        raise RuntimeError("restore failed")

    monkeypatch.setitem(teardown.RESTORERS, envvars.KIND_ENV_VAR, broken)
    report1 = teardown.run_teardown(state_file)
    assert not report1.ok
    assert state.entries(), "失败记录必须保留"

    monkeypatch.setitem(teardown.RESTORERS, envvars.KIND_ENV_VAR, original_restorer)
    # 恢复原始 restorer 后重试成功（还原为「不存在」）
    report2 = teardown.run_teardown(state_file)
    assert report2.ok
    assert state.entries() == []


def test_teardown_unknown_kind_reported(tmp_path: Path) -> None:
    state_file = tmp_path / "setup-state.json"
    state = StateFile(state_file)
    state.record(kind="alien_kind", key="x", old=None, new=None)
    report = teardown.run_teardown(state_file)
    assert not report.ok
    assert "无法自动还原" in report.errors[0]
    assert state.entries()  # 记录保留（不静默丢弃）
