"""打包设计/执行文档为 zip（本地与 build.yml 的 docs job 共用）。

产物：dist/EgressSentinel-docs-v<版本>.zip，内含顶层目录
EgressSentinel-docs-v<版本>/：
  docs/**（调研/设计/执行计划/发布清单/决策日志）
  README.md / CHANGELOG.md / LICENSE / pyproject.toml
用法：python scripts/package_docs.py [--out-dir dist]
"""
import re
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INCLUDE_FILES = ["README.md", "CHANGELOG.md", "LICENSE", "pyproject.toml"]
INCLUDE_DIRS = ["docs"]


def read_version() -> str:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    if not m:
        raise SystemExit("pyproject.toml 中未找到 version")
    return m.group(1)


def main() -> None:
    out_dir = ROOT / "dist"
    if "--out-dir" in sys.argv:
        out_dir = Path(sys.argv[sys.argv.index("--out-dir") + 1])
    out_dir.mkdir(parents=True, exist_ok=True)

    version = read_version()
    stem = f"EgressSentinel-docs-v{version}"
    zip_path = out_dir / f"{stem}.zip"

    n = 0
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for rel in INCLUDE_DIRS:
            base = ROOT / rel
            for p in sorted(base.rglob("*")):
                if p.is_file():
                    zf.write(p, f"{stem}/{p.relative_to(ROOT).as_posix()}")
                    n += 1
        for rel in INCLUDE_FILES:
            p = ROOT / rel
            if p.is_file():
                zf.write(p, f"{stem}/{rel}")
                n += 1

    print(f"packaged {n} files -> {zip_path} ({zip_path.stat().st_size // 1024} KiB)")


if __name__ == "__main__":
    main()
