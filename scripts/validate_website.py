"""官网发布校验（docs/07 第 5/6 项）：EN 字典覆盖 + JSON-LD 合法 + 关键内容存在。"""

import json
import re
import sys
from pathlib import Path

html = (Path(__file__).resolve().parent.parent / "website" / "index.html").read_text(
    encoding="utf-8"
)
keys = set(re.findall(r'data-i18n="([a-z0-9_.]+)"', html))
m = re.search(r"var I18N_EN = \{(.*?)\n\};", html, re.S)
assert m, "EN dict not found"
en = set(re.findall(r'"([a-z0-9_.]+)":', m.group(1)))
missing = sorted(k for k in keys if k not in en)
print("html keys:", len(keys), "| EN missing:", missing if missing else "NONE")

blocks = re.findall(r'ld\+json">(.*?)</script>', html, re.S)
for b in blocks:
    json.loads(b)
print("JSON-LD valid x", len(blocks))

checks = {
    "badge v0.3.0": "v0.3.0 正式发布" in html,
    "stats 650+": "650+" in html,
    "roadmap all done": html.count("✅ v0.3.0") == 2,
    "card c10": 'data-i18n="feat.c10t"' in html,
    "no v0.2.0 badge left": "v0.2.0 ·" not in html and "v0.2.0 正式" not in html,
}
bad = [k for k, v in checks.items() if not v]
print("content checks:", "ALL OK" if not bad else f"FAILED: {bad}")
sys.exit(1 if missing or bad else 0)
