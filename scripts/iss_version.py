"""从 pyproject.toml 读取项目版本，供 Inno Setup 安装器版本注入（06 文档 W3）。

用法：``python scripts/iss_version.py`` → stdout 输出版本号（如 ``0.2.0``）。
CI 用法（.github/workflows/build.yml installer job）::

    VERSION=$(python scripts/iss_version.py)
    iscc /DMyAppVersion=$VERSION installer/egress-sentinel.iss

设计要点：
- 用标准库 ``tomllib`` 解析（requires-python >= 3.11），不做手写正则；
- 版本缺失/文件缺失时**非零退出**（CI 立即失败），绝不输出兜底版本号——
  错误版本号的安装包比失败的构建更危险。
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = PROJECT_ROOT / "pyproject.toml"


def read_version(pyproject: Path | None = None) -> str:
    """读取 pyproject.toml 的 ``[project] version``；缺失或无法解析时抛 RuntimeError。

    红线：绝不返回猜测的兜底版本（如 "0.0.0"）——调用方应让构建失败而非发布错版。
    ``pyproject`` 缺省时取模块级 ``PYPROJECT``（调用时解析，便于测试注入替换）。
    """
    path = pyproject if pyproject is not None else PYPROJECT
    if not path.is_file():
        raise RuntimeError(f"pyproject.toml 不存在：{path}")
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8-sig"))
    except (tomllib.TOMLDecodeError, OSError) as exc:
        raise RuntimeError(f"pyproject.toml 解析失败：{exc}") from exc
    version = data.get("project", {}).get("version")
    if not version or not isinstance(version, str):
        raise RuntimeError("pyproject.toml 缺少 [project] version 字段")
    return version


def main(argv: list[str]) -> int:
    """CLI 入口：stdout 输出版本号；失败时 stderr 说明原因并返回 1。"""
    # CI runner 的 stdout 可能是 cp1252，中文报错会 UnicodeEncodeError
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    if len(argv) > 1:
        print("用法：python scripts/iss_version.py（无参数）", file=sys.stderr)
        return 2
    try:
        print(read_version())
    except RuntimeError as exc:
        print(f"版本号读取失败：{exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
