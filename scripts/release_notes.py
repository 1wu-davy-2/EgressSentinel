"""从 CHANGELOG.md 提取指定 tag 的更新说明，供 GitHub Release body 使用。

用法：``python scripts/release_notes.py v0.1.2`` → stdout 输出该版本段落（Markdown）。
找不到对应段落时输出通用兜底文案（不失败，不阻塞 Release 发布）。
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

CHANGELOG = Path(__file__).resolve().parent.parent / "CHANGELOG.md"
_FALLBACK = "详见 [CHANGELOG.md](https://github.com/1wu-davy-2/EgressSentinel/blob/main/CHANGELOG.md)。"


def normalize_version(tag: str) -> str:
    """v0.1.2 / 0.1.2 / refs/tags/v0.1.2 → 0.1.2。"""
    version = tag.strip().split("/")[-1]
    return version[1:] if version.startswith("v") else version


def extract_section(text: str, version: str) -> str | None:
    """提取 ``## [vX.Y.Z] - 日期`` 段落（到下一个 ``## `` 为止）；未找到返回 None。"""
    pattern = re.compile(
        rf"^##\s*\[?v?{re.escape(version)}\]?(?:\s*-.*)?$", re.MULTILINE
    )
    match = pattern.search(text)
    if match is None:
        return None
    rest = text[match.end() :]
    nxt = re.search(r"^##\s", rest, re.MULTILINE)
    section = rest[: nxt.start()] if nxt else rest
    section = section.strip()
    # 去掉段落里的二级锚（## [v...] - 日期 已在上面正则消费）
    return section or None


def main(argv: list[str]) -> int:
    # Windows runner 的重定向 stdout 可能是 cp1252，中文会 UnicodeEncodeError
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    tag = argv[1] if len(argv) > 1 else ""
    if not tag:
        print(_FALLBACK)
        return 0
    if not CHANGELOG.exists():
        print(_FALLBACK)
        return 0
    section = extract_section(CHANGELOG.read_text(encoding="utf-8"), normalize_version(tag))
    print(section if section else _FALLBACK)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
