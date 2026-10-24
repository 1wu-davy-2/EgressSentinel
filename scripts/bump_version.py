"""一次性版本升级脚本：0.1.0 -> 0.1.1（代码 + pyproject + 官网文案）。"""

import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent

for rel, old, new in [
    ("src/aaa/__init__.py", '__version__ = "0.1.0"', '__version__ = "0.1.1"'),
    ("pyproject.toml", 'version = "0.1.0"', 'version = "0.1.1"'),
    ("website/index.html", "v0.1.0 正式发布", "v0.1.1 正式发布"),
    ("website/index.html", "v0.1.0 released", "v0.1.1 released"),
    ("website/index.html", "v0.1.0 · 五平台可执行文件", "v0.1.1 · 五平台可执行文件"),
    ("website/index.html", "EgressSentinel v0.1.0 · mode=dry-run", "EgressSentinel v0.1.1 · mode=dry-run"),
]:
    p = ROOT / rel
    text = p.read_text(encoding="utf-8")
    if old in text:
        p.write_text(text.replace(old, new), encoding="utf-8")
        print(f"bumped: {rel}: {old[:40]}")
    else:
        print(f"skip (not found): {rel}: {old[:40]}")
