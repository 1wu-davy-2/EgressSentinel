"""release_notes 提取逻辑单测（CHANGELOG → Release body）。"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = str(Path(__file__).resolve().parents[2])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from scripts.release_notes import extract_section, normalize_version  # noqa: E402

_SAMPLE = """# 更新日志

## [v0.1.2] - 2026-10-24

### 新增

- 安装即守护
- 策略热更新可见

## [v0.1.1] - 2026-10-24

### 新增

- 关机优雅退出
- 开机自启 + watchdog

## [v0.1.0] - 2026-10-24

首个版本。
"""


def test_normalize_version_variants() -> None:
    assert normalize_version("v0.1.2") == "0.1.2"
    assert normalize_version("0.1.2") == "0.1.2"
    assert normalize_version("refs/tags/v0.1.2") == "0.1.2"


def test_extract_first_section() -> None:
    section = extract_section(_SAMPLE, "v0.1.2")
    assert section is not None
    assert "安装即守护" in section
    assert "关机优雅退出" not in section  # 不得跨段


def test_extract_middle_section() -> None:
    section = extract_section(_SAMPLE, "0.1.1")
    assert section is not None
    assert "watchdog" in section
    assert "安装即守护" not in section


def test_extract_last_section() -> None:
    section = extract_section(_SAMPLE, "v0.1.0")
    assert section is not None
    assert "首个版本" in section


def test_extract_missing_returns_none() -> None:
    assert extract_section(_SAMPLE, "9.9.9") is None
