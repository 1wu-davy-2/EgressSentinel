"""仓库指纹（05 文档 W1）：本地代码仓库指纹库与外发请求体片段比对。

用法（集成阶段由 ``aaa fingerprint build`` 建库、内容扫描器比对）::

    from aaa.fingerprint import FingerprintIndex, FINGERPRINTS_FILE_NAME

    idx = FingerprintIndex.load(data_dir / FINGERPRINTS_FILE_NAME)  # 损坏 → None → 重建
    if idx is None:
        idx = FingerprintIndex()
        idx.add_repo(Path("E:/work/my-repo"))
        idx.save(data_dir / FINGERPRINTS_FILE_NAME)
    hits = idx.scan_body(request_body_text)  # list[FingerprintHit]，≤20 条

红线说明：
- 指纹库 ``fingerprints.bin`` 是本地信任数据，pickle 仅用于本工具自建文件，
  绝不加载来源不明的文件；损坏一律重建（见 ``index`` 模块红线）；
- 命中证据 ``FingerprintHit.snippet`` 截断 80 字符，事件/通知外发不携带更多原文；
- 全模块无网络调用。
"""

from __future__ import annotations

from aaa.fingerprint.index import (
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_SLICES,
    DEFAULT_WINDOW,
    FINGERPRINTS_FILE_NAME,
    MAX_SCAN_HITS,
    SKIP_DIRS,
    SNIPPET_MAX_CHARS,
    BuildStats,
    FileReader,
    FingerprintHit,
    FingerprintIndex,
    digest_slice,
    iter_slices,
)

__all__ = [
    "DEFAULT_MAX_FILE_BYTES",
    "DEFAULT_MAX_SLICES",
    "DEFAULT_WINDOW",
    "FINGERPRINTS_FILE_NAME",
    "MAX_SCAN_HITS",
    "SKIP_DIRS",
    "SNIPPET_MAX_CHARS",
    "BuildStats",
    "FileReader",
    "FingerprintHit",
    "FingerprintIndex",
    "digest_slice",
    "iter_slices",
]
