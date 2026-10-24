"""W5 CLI i18n 单测（06 文档波次一）：回退 / 格式化 / 覆盖统计 / 语言来源优先级。

红线：全注入式——``AAA_LANG`` 用 pytest ``monkeypatch`` 环境注入，缺词条场景用
``monkeypatch`` 向内存目录注入临时 key；绝不触网、绝不做系统级操作。
"""

from __future__ import annotations

import logging
import re

import pytest

from aaa import i18n
from aaa.locales import CATALOGUES, DEFAULT_LANG, LANGS

#: 与 i18n.t 的插值口径一致：``{name}`` / ``{name!r}`` / ``{name:>4}``
_PLACEHOLDER_RE = re.compile(r"\{(\w+)(?:![rsa])?(?::[^{}]+)?\}")


@pytest.fixture(autouse=True)
def _reset_i18n_state() -> None:
    """每条测试前后重置语言与缺失计数（模块级状态隔离）。"""
    i18n.reset_state()
    yield
    i18n.reset_state()


# --------------------------------------------------------------------------
# 语言来源优先级：set_lang > AAA_LANG env > 默认 zh
# --------------------------------------------------------------------------


def test_default_lang_is_zh_without_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """无 AAA_LANG、未 set_lang 时默认 zh（出厂输出不变）。"""
    monkeypatch.delenv(i18n.LANG_ENV_VAR, raising=False)
    assert i18n.get_lang() == "zh"
    assert i18n.t("cli.app.help") == "AI-AGENT-AUDIT：本机 AI Agent 外发流量审计（Windows）"


def test_env_lang_selects_en(monkeypatch: pytest.MonkeyPatch) -> None:
    """AAA_LANG=en 生效（大小写与首尾空白容错），取到 en 译文。"""
    monkeypatch.setenv(i18n.LANG_ENV_VAR, " EN ")
    assert i18n.get_lang() == "en"
    assert i18n.t("common.cancelled") == "Cancelled."


def test_env_lang_unknown_falls_back_to_zh(monkeypatch: pytest.MonkeyPatch) -> None:
    """AAA_LANG 非法值（fr / 空串）保守回落 zh，不报错。"""
    monkeypatch.setenv(i18n.LANG_ENV_VAR, "fr")
    assert i18n.get_lang() == "zh"
    monkeypatch.setenv(i18n.LANG_ENV_VAR, "")
    assert i18n.get_lang() == "zh"


def test_set_lang_overrides_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """运行时 set_lang 优先级高于 AAA_LANG env（集成阶段 --lang 接线点）。"""
    monkeypatch.setenv(i18n.LANG_ENV_VAR, "en")
    i18n.set_lang("zh")
    assert i18n.get_lang() == "zh"
    assert i18n.t("common.cancelled") == "已取消。"
    i18n.set_lang("EN")
    assert i18n.get_lang() == "en"


def test_set_lang_unknown_falls_back_to_zh() -> None:
    """set_lang 未知语言值不报错，回落 zh。"""
    i18n.set_lang("fr")
    assert i18n.get_lang() == "zh"


def test_available_langs() -> None:
    """支持语言清单 = 目录键（zh/en），与 CATALOGUES 键集合一致。"""
    assert i18n.available_langs() == ("zh", "en")
    assert set(LANGS) == set(CATALOGUES)


# --------------------------------------------------------------------------
# 缺 key 回落 + 计数告警（W5 验收：回退）
# --------------------------------------------------------------------------


def test_missing_key_in_en_falls_back_to_zh_and_counts(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """en 缺 key：回落 zh 原文，计数 + 告警一次。"""
    monkeypatch.setitem(CATALOGUES["zh"], "test.only_zh", "只有中文")
    i18n.set_lang("en")
    caplog.set_level(logging.WARNING, logger="aaa.i18n")
    assert i18n.t("test.only_zh") == "只有中文"
    assert i18n.missing_counts() == {"test.only_zh": 1}
    assert [r.getMessage() for r in caplog.records] == [
        "i18n 缺词条：test.only_zh（已回落 zh 或键名）"
    ]


def test_missing_key_everywhere_returns_key_and_counts(caplog: pytest.LogCaptureFixture) -> None:
    """两语言都缺 key：返回 key 本身（绝不抛异常），计数一次、告警一次。"""
    caplog.set_level(logging.WARNING, logger="aaa.i18n")
    assert i18n.t("no.such.key.i18n") == "no.such.key.i18n"
    assert i18n.missing_counts() == {"no.such.key.i18n": 1}
    assert len(caplog.records) == 1


def test_missing_key_warns_once_but_counts_every_call(caplog: pytest.LogCaptureFixture) -> None:
    """同一 key 多次缺失：告警去重（1 条），计数逐次累加。"""
    caplog.set_level(logging.WARNING, logger="aaa.i18n")
    for _ in range(3):
        assert i18n.t("no.such.key.repeat") == "no.such.key.repeat"
    assert i18n.missing_counts() == {"no.such.key.repeat": 3}
    assert len(caplog.records) == 1
    assert caplog.records[0].getMessage() == "i18n 缺词条：no.such.key.repeat（已回落 zh 或键名）"


def test_coverage_records_format_misses() -> None:
    """占位符插值失败计数记为 ``<key>#format``（与缺 key 区分）。"""
    assert i18n.t("cli.run.banner", version="x") == (  # 缺 mode/host/port → 插值失败
        "[green]aaa {version}[/green] mode={mode} 监听 {host}:{port}"
    )
    assert i18n.missing_counts() == {"cli.run.banner#format": 1}


# --------------------------------------------------------------------------
# 格式化（W5 验收：格式化）
# --------------------------------------------------------------------------


def test_formatting_zh() -> None:
    """zh 默认语言下占位符插值正确（rich markup 原样保留）。"""
    got = i18n.t("cli.run.banner", version="0.3.0", mode="regular", host="127.0.0.1", port=8080)
    assert got == "[green]aaa 0.3.0[/green] mode=regular 监听 127.0.0.1:8080"


def test_formatting_en() -> None:
    """en 下插值正确且输出为译文。"""
    i18n.set_lang("en")
    got = i18n.t("cli.teardown.will_restore", count=3)
    assert got == "Will restore 3 changes in reverse state-file order:"


def test_formatting_repr_conversion() -> None:
    """``{name!r}`` 占位符与 str.format 口径一致。"""
    assert i18n.t("cli.status.proxy_off", server="1.2.3.4:8") == "未启用（server='1.2.3.4:8'）"


def test_no_placeholder_ignores_extra_fmt() -> None:
    """原文无占位符时多余 fmt 被忽略（fmt 非空才 format，避免字面花括号误伤）。"""
    assert i18n.t("common.cancelled", bogus=1) == "已取消。"


def test_format_unknown_kwarg_returns_raw_and_counts() -> None:
    """fmt 提供未知占位符名（原文有 {x} 却传 y）：返回原文不抛，计数 #format。"""
    monkey_key = "wizard.env.line"
    assert i18n.t(monkey_key, wrong=1) == "  {name} = {value}"
    assert i18n.missing_counts() == {f"{monkey_key}#format": 1}


# --------------------------------------------------------------------------
# 覆盖统计（W5 验收：覆盖统计 + catalogue_coverage）
# --------------------------------------------------------------------------


def test_catalogue_coverage_delivered_state_is_fully_translated() -> None:
    """交付态：en 全量翻译 → untranslated == 0，key 数为正且等于 zh 目录大小。"""
    coverage = i18n.catalogue_coverage()
    assert coverage.keys == len(CATALOGUES[DEFAULT_LANG])
    assert coverage.keys > 0
    assert coverage.untranslated == 0
    assert coverage.missing_translations == []
    assert coverage.translated == coverage.keys


def test_catalogue_coverage_detects_untranslated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """人为删除 en 中一个 key：统计如实报告未翻译清单（含计数快照）。"""
    victim = "cli.status.no_events"
    monkeypatch.delitem(CATALOGUES["en"], victim)
    coverage = i18n.catalogue_coverage()
    assert coverage.untranslated == 1
    assert coverage.missing_translations == [victim]
    assert coverage.translated == coverage.keys - 1
    assert isinstance(coverage.missing_counts, dict)


def test_zh_catalogue_is_verbatim_source() -> None:
    """zh 目录取自 cli.py / wizard.py 原文：抽查代表性文案逐字一致。"""
    zh = CATALOGUES["zh"]
    assert zh["cli.app.help"] == "AI-AGENT-AUDIT：本机 AI Agent 外发流量审计（Windows）"
    assert zh["cli.run.err_pid_mutex"] == "--pid 与 --process 互斥，只选其一"
    assert zh["cli.harden.err_action"] == "harden 只支持 on | off"
    assert zh["wizard.welcome"] == "AI-AGENT-AUDIT 一键引导：以下步骤将修改系统设置，逐步确认执行。"
    assert zh["cli.teardown.empty"] == "状态文件为空：没有需要还原的改动。"


def test_placeholder_sets_match_between_zh_and_en() -> None:
    """每个 key 在 zh/en 的占位符集合一致（防译文丢占位符导致集成插值炸掉）。"""
    zh, en = CATALOGUES["zh"], CATALOGUES["en"]
    assert set(zh) == set(en), "zh/en key 集合必须一致"
    for key, text in zh.items():
        assert _PLACEHOLDER_RE.findall(text) == _PLACEHOLDER_RE.findall(en[key]), key


def test_catalogue_entries_are_nonempty_strings() -> None:
    """词条值全部是非空 str（含空串会把清空输出伪装成正常文案）。"""
    for catalogue in CATALOGUES.values():
        for key, text in catalogue.items():
            assert isinstance(text, str) and text.strip(), key


def test_reset_state_clears_lang_and_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    """reset_state：清掉 set_lang 的显式语言与缺失计数（回退 env/默认）。"""
    monkeypatch.setenv(i18n.LANG_ENV_VAR, "en")  # reset 后应回落 env
    i18n.set_lang("zh")
    i18n.t("no.such.key.reset")
    assert i18n.missing_counts()
    i18n.reset_state()
    assert i18n.get_lang() == "en"
    assert i18n.missing_counts() == {}


def test_reset_state_without_env_falls_back_to_zh(monkeypatch: pytest.MonkeyPatch) -> None:
    """无 env 时 reset_state 回落默认 zh。"""
    monkeypatch.delenv(i18n.LANG_ENV_VAR, raising=False)
    i18n.set_lang("en")
    i18n.reset_state()
    assert i18n.get_lang() == "zh"
