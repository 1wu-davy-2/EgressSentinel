"""setup 向导核心逻辑单测（03 文档 T4.2）：计划收集 / 确认流 / 失败继续。

注入假 confirm/echo 与假 apply（``SetupPlan.apply`` 被替换），
绝不真实施改系统设置。
"""

from __future__ import annotations

import pytest

from aaa.setup.wizard import SetupPlan, collect_setup_plans, run_setup_wizard


@pytest.fixture
def plans(paths) -> list[SetupPlan]:  # type: ignore[name-defined]
    return collect_setup_plans(paths)


def test_collect_plans_covers_ca_proxy_env(paths) -> None:  # type: ignore[name-defined]
    """三步计划齐全，且计划行给出将要执行的改动明细（执行前必打印的素材）。"""
    plans = collect_setup_plans(paths)
    titles = [p.title for p in plans]
    assert len(titles) == 3
    assert "CA 根证书" in titles[0]
    assert "系统代理" in titles[1]
    assert "用户环境变量" in titles[2]
    ca_lines = "\n".join(plans[0].lines)
    assert "CurrentUser" in ca_lines and "序列号" in ca_lines
    proxy_lines = "\n".join(plans[1].lines)
    assert "127.0.0.1:8080" in proxy_lines and "setup-state.json" in proxy_lines
    env_lines = "\n".join(plans[2].lines)
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "NODE_EXTRA_CA_CERTS", "NO_PROXY"):
        assert var in env_lines
    # 计划收集本身不改系统：状态文件不应存在
    assert not paths.setup_state_file.exists()


def test_collect_plans_machine_ca_label(paths) -> None:  # type: ignore[name-defined]
    plans = collect_setup_plans(paths, machine_ca=True)
    assert "LocalMachine" in "\n".join(plans[0].lines)
    assert "管理员" in "\n".join(plans[0].lines)


def test_wizard_confirms_then_applies_in_order(paths) -> None:  # type: ignore[name-defined]
    applied: list[str] = []
    plans = [
        SetupPlan(title=f"step{i}", lines=[f"改动{i}"], apply=lambda i=i: applied.append(i))
        for i in range(3)
    ]
    echoes: list[str] = []
    result = run_setup_wizard(plans, confirm=lambda msg: True, echo=echoes.append)
    assert result == ["step0", "step1", "step2"]
    assert applied == [0, 1, 2]
    # 每步执行前都打印了计划行（改动明细）
    text = "\n".join(echoes)
    for i in range(3):
        assert f"改动{i}" in text
    assert "teardown" in text, "结尾提示可还原"


def test_wizard_decline_skips_apply(paths) -> None:  # type: ignore[name-defined]
    applied: list[str] = []
    plans = [
        SetupPlan(title="a", lines=[], apply=lambda: applied.append("a")),
        SetupPlan(title="b", lines=[], apply=lambda: applied.append("b")),
    ]
    answers = iter([True, False])
    result = run_setup_wizard(plans, confirm=lambda msg: next(answers), echo=lambda s: None)
    assert result == ["a"] and applied == ["a"]


def test_wizard_dry_run_never_applies(paths) -> None:  # type: ignore[name-defined]
    applied: list[str] = []
    plans = [SetupPlan(title="a", lines=["x"], apply=lambda: applied.append("a"))]
    result = run_setup_wizard(plans, confirm=lambda msg: True, echo=lambda s: None, dry_run=True)
    assert result == ["a"] and applied == []


def test_wizard_step_failure_continues(paths) -> None:  # type: ignore[name-defined]
    """单步失败：打印错误、继续下一步（journal-first 记录保留）。"""

    def _boom() -> None:
        raise RuntimeError("simulated failure")

    plans = [
        SetupPlan(title="bad", lines=[], apply=_boom),
        SetupPlan(title="good", lines=[], apply=lambda: None),
    ]
    echoes: list[str] = []
    result = run_setup_wizard(plans, confirm=lambda msg: True, echo=echoes.append)
    assert result == ["good"], "失败步骤不计入已应用"
    assert any("simulated failure" in e for e in echoes)
