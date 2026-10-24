"""CLI 国际化取词（06 文档波次一 W5）。

- ``t(key, **fmt)``：按当前语言取词条；当前语言缺 key 时**回落 zh 原文**并计数告警
  （zh 也缺则返回 key 本身）——``t()`` 绝不抛异常，保证集成阶段（波次二第 2 条）
  机械包裹 cli.py + wizard.py 后输出永不因词条问题中断；
- 语言来源（优先级从高到低）：``set_lang()`` 运行时设置（集成阶段接 ``--lang``）
  > ``AAA_LANG`` 环境变量 > 默认 ``zh``（出厂输出不变）；未知语言一律回落 zh；
- ``catalogue_coverage()``：词条目录覆盖统计（key 总数 / 未翻译数 / 缺失清单），
  运行中的缺 key 计数经 ``missing_counts()`` 观察。

词条目录见 ``aaa/locales/``：zh 为原文（取自 cli.py / setup/wizard.py 用户可见文案），
en 为译文。覆盖统计以 zh 目录为权威（key 总数与未翻译均相对 zh 计算）。

红线：本模块不做任何系统级操作；只做纯取词与计数，日志告警走 ``logging``（不污染
CLI 输出），缺词条永不中断主流程。
"""

from __future__ import annotations

import logging
import os
from typing import Any, Final

from pydantic import BaseModel, Field

from aaa.locales import CATALOGUES, DEFAULT_LANG, LANGS

logger = logging.getLogger(__name__)

#: 语言环境变量名（docs/03 §3：环境变量统一 ``AAA_*`` 前缀）
LANG_ENV_VAR: Final[str] = "AAA_LANG"

# 运行时显式语言（set_lang 设置；None=未设置，回落 AAA_LANG/默认）
_explicit_lang: str | None = None
# 缺 key 计数（key → 调用次数；含回落 zh 与回落 key 本身两种缺失）
_missing_counts: dict[str, int] = {}
# 已告警过的 key（同一 key 只 logging.warning 一次，避免刷屏）
_warned_keys: set[str] = set()


class CatalogueCoverage(BaseModel):
    """词条目录覆盖统计（W5 验收字段：key 数与未翻译数）。"""

    keys: int
    """zh 权威目录的 key 总数。"""

    translated: int
    """en 目录已覆盖的 key 数。"""

    untranslated: int
    """en 目录缺失（未翻译）的 key 数。"""

    missing_translations: list[str] = Field(default_factory=list)
    """未翻译 key 清单（排序）。"""

    missing_counts: dict[str, int] = Field(default_factory=dict)
    """运行中 ``t()`` 缺 key 的计数快照（key → 次数）。"""


def _normalize_lang(lang: str | None) -> str:
    """规范化语言值：未知/空白一律回落默认 zh（保守语义，不报错）。"""
    normalized = (lang or "").strip().lower()
    return normalized if normalized in LANGS else DEFAULT_LANG


def set_lang(lang: str) -> None:
    """运行时设置语言（集成阶段接 CLI ``--lang``；优先级高于 ``AAA_LANG``）。

    未知语言值不报错，静默回落 ``zh``（与 ``AAA_LANG`` 非法值同一保守语义）。
    """
    global _explicit_lang
    _explicit_lang = _normalize_lang(lang)


def get_lang() -> str:
    """当前生效语言：``set_lang()`` 显式值 > ``AAA_LANG`` env > 默认 ``zh``。"""
    if _explicit_lang is not None:
        return _explicit_lang
    return _normalize_lang(os.environ.get(LANG_ENV_VAR))


def available_langs() -> tuple[str, ...]:
    """支持的语言清单（``LANGS``：zh / en）。"""
    return LANGS


def reset_state() -> None:
    """重置语言选择与缺失计数（测试隔离用；生产 CLI 不调用）。"""
    global _explicit_lang
    _explicit_lang = None
    _missing_counts.clear()
    _warned_keys.clear()


def _record_missing(key: str) -> None:
    """缺 key 计数 + 首次告警（同一 key 只 warning 一次，计数每次累加）。"""
    _missing_counts[key] = _missing_counts.get(key, 0) + 1
    if key not in _warned_keys:
        _warned_keys.add(key)
        logger.warning("i18n 缺词条：%s（已回落 zh 或键名）", key)


def t(key: str, **fmt: Any) -> str:
    """按当前语言取词条（``t`` 是 ``translate`` 的缩写；集成阶段机械包裹用）。

    - 当前语言目录命中 → ``str.format(**fmt)`` 插值（``fmt`` 为空时原样返回，
      避免原文含字面花括号时误格式化）；
    - 当前语言缺 key → 计数 + 告警一次，回落 zh 原文；zh 也缺 → 返回 key 本身
      （一次缺失只计一次，绝不抛异常）；
    - 占位符与 ``fmt`` 不匹配（缺参/错名）→ 返回未插值原文，计数 + 告警（绝不抛）。
    """
    lang = get_lang()
    text = CATALOGUES.get(lang, {}).get(key)
    if text is None:
        _record_missing(key)
        text = CATALOGUES[DEFAULT_LANG].get(key)
        if text is None:
            return key
    if fmt:
        try:
            return text.format(**fmt)
        except (KeyError, IndexError, ValueError):
            _record_missing(f"{key}#format")
    return text


def missing_counts() -> dict[str, int]:
    """运行中 ``t()`` 缺 key 的计数快照（key → 次数；含 ``<key>#format``）。"""
    return dict(sorted(_missing_counts.items()))


def catalogue_coverage() -> CatalogueCoverage:
    """词条目录覆盖统计：以 zh 权威目录为准，报告 key 总数与 en 未翻译数。"""
    zh = CATALOGUES[DEFAULT_LANG]
    en = CATALOGUES.get("en", {})
    missing = sorted(k for k in zh if k not in en)
    return CatalogueCoverage(
        keys=len(zh),
        translated=len(zh) - len(missing),
        untranslated=len(missing),
        missing_translations=missing,
        missing_counts=missing_counts(),
    )
