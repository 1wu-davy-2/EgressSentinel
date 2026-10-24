"""准备 GitHub Pages 用户站（1wu-davy-2.github.io）内容：

把 website/ 复制到 ../es-user-site，并把所有指向
https://1wu-davy-2.github.io/EgressSentinel/ 的绝对引用改为根路径
https://1wu-davy-2.github.io/（canonical / og:url / og:image / JSON-LD url /
robots Sitemap / sitemap loc），避免双站点重复内容。
"""

from __future__ import annotations

import pathlib
import shutil

SRC = pathlib.Path(__file__).resolve().parent.parent / "website"
DST = pathlib.Path(__file__).resolve().parent.parent.parent / "es-user-site"

OLD = "https://1wu-davy-2.github.io/EgressSentinel"
NEW = "https://1wu-davy-2.github.io"

if DST.exists():
    shutil.rmtree(DST)
shutil.copytree(SRC, DST)
count = 0
for p in DST.rglob("*"):
    if p.is_file():
        text = p.read_text(encoding="utf-8", errors="surrogateescape")
        if OLD in text:
            p.write_text(text.replace(OLD, NEW), encoding="utf-8", errors="surrogateescape")
            count += 1
            print("rewritten:", p.name)
print(f"done: {count} files rewritten -> {DST}")
