"""词条目录聚合（06 文档波次一 W5）。

``zh`` 为原文目录（逐字取自 cli.py / setup/wizard.py 的用户可见文案），``en`` 为译文
目录；集成阶段（波次二第 2 条）以 ``t(key)`` 机械包裹 cli.py + wizard.py，接
``--lang`` / ``AAA_LANG``（默认 zh，输出不变）。

红线：本包只承载词条数据，不含任何逻辑、不做任何系统级操作。
"""

from __future__ import annotations

from typing import Final

from aaa.locales.en import CATALOGUE as _EN_CATALOGUE
from aaa.locales.zh import CATALOGUE as _ZH_CATALOGUE

#: 默认语言：出厂中文（AAA_LANG / 运行时 --lang 可切换；未知值一律回落 zh）
DEFAULT_LANG: Final[str] = "zh"

#: 支持的语言清单（目录键；与 CATALOGUES 的键一一对应）
LANGS: Final[tuple[str, ...]] = ("zh", "en")

#: 语言 → 词条目录（key → 文案；zh 为原文，en 为译文；dict 便于测试注入/统计）
CATALOGUES: Final[dict[str, dict[str, str]]] = {
    "zh": _ZH_CATALOGUE,
    "en": _EN_CATALOGUE,
}

__all__ = ["CATALOGUES", "DEFAULT_LANG", "LANGS"]
