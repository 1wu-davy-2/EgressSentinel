"""发布期官网同步（docs/07 检查单 2-7 项）：v0.3.0 徽标/路线图/统计/新卡/vibe 数字。"""

import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
site = ROOT / "website" / "index.html"
vibe = ROOT / "website" / "vibe.html"

t = site.read_text(encoding="utf-8")
pairs = [
    # 1) 徽标（zh hero / en hero / zh cta / en cta）
    ("v0.2.0 正式发布 · 五平台可执行文件已上线", "v0.3.0 正式发布 · 五平台可执行文件 + Windows 安装包"),
    ("v0.2.0 released · executables for 5 platforms", "v0.3.0 released · executables + Windows installer"),
    ("v0.2.0 · 五平台可执行文件", "v0.3.0 · 五平台可执行文件 + 安装包"),
    ("v0.2.0 · executables for 5 platforms", "v0.3.0 · executables + installer, 5 platforms"),
    # 2) 统计
    ('<div class="n grad-text">585+</div>', '<div class="n grad-text">650+</div>'),
    # 3) 路线图：③④ 转已落地
    ('<span class="tag confirm" style="font-size:.78rem">🚧 v0.3.0</span>\n        <div style="flex:1;min-width:280px"><b data-i18n="rm.3t">③ 工程与体验（进行中）</b>',
     '<span class="tag allow" style="font-size:.78rem">✅ v0.3.0</span>\n        <div style="flex:1;min-width:280px"><b data-i18n="rm.3t">③ 工程与体验</b>'),
    ('<span class="tag confirm" style="font-size:.78rem">🚧 v0.3.0</span>\n        <div style="flex:1;min-width:280px"><b data-i18n="rm.4t">④ 数据与生态（进行中）</b>',
     '<span class="tag allow" style="font-size:.78rem">✅ v0.3.0</span>\n        <div style="flex:1;min-width:280px"><b data-i18n="rm.4t">④ 数据与生态</b>'),
    ("③ Engineering & experience (in progress)", "③ Engineering & experience"),
    ("④ Data & ecosystem (in progress)", "④ Data & ecosystem"),
    # 4) 新卡：软件形态与生态（加在仓库指纹卡之后）
    ('另有 LLM 辅助判定、响应侧注入检测与证据 AES-256-GCM 加密（v0.2.0，默认关闭按需开启）。</p></div>',
     '另有 LLM 辅助判定、响应侧注入检测与证据 AES-256-GCM 加密（v0.2.0，默认关闭按需开启）。</p></div>\n      <div class="card"><div class="ic">📦</div><h3 data-i18n="feat.c10t">软件形态与生态</h3><p data-i18n="feat.c10p">Windows 安装包（卸载自动还原系统）、开机服务与系统托盘、多策略 profile 一键切换、CLI 中英双语（<code>--lang</code>）、HTML 日报周报邮件投递、规则导入导出与 gitleaks 同步、多机中心化聚合（v0.3.0）。</p></div>'),
]
for old, new in pairs:
    if old in t:
        t = t.replace(old, new)
        print("ok:", old[:44].replace("\n", " "))
    else:
        print("MISS:", old[:44].replace("\n", " "))
# 5) EN 词条
en_pairs = [
    ('"rm.3t": "③ Engineering & experience",', '"rm.3t": "③ Engineering & experience",'),
    ('"feat.c9p": "Pre-scan', '"feat.c9p": "Pre-scan'),
    ('  "rm.4t": "④ Data & ecosystem (in progress)", "rm.4p": "daily & weekly reports / rule import-export + gitleaks sync / multi-machine aggregation",',
     '  "rm.4t": "④ Data & ecosystem", "rm.4p": "daily & weekly reports (email) / rule import-export + gitleaks sync / multi-machine aggregation",\n  "feat.c10t": "Software form & ecosystem", "feat.c10p": "Windows installer (uninstall auto-restores system), boot service & tray, policy profiles, bilingual CLI (<code>--lang</code>), HTML daily/weekly email reports, rule import-export with gitleaks sync, multi-machine aggregation (v0.3.0).",'),
]
for old, new in en_pairs:
    if old in t and old != new:
        t = t.replace(old, new)
        print("ok-en:", old[:40])
site.write_text(t, encoding="utf-8")

v = vibe.read_text(encoding="utf-8")
for old, new in [
    ("0 → v0.2.0", "0 → v0.3.0"),
    ('data-count="4"', 'data-count="5"'),
    ('data-count="300" data-suffix="+"', 'data-count="650" data-suffix="+"'),
]:
    if old in v:
        v = v.replace(old, new)
        print("vibe ok:", old)
vibe.write_text(v, encoding="utf-8")
print("done")
