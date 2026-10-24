"""证据文件：请求 body 截断落盘 + sha256（02 文档 D6，03 文档 T1.2）。"""

from __future__ import annotations

import hashlib
import threading
from pathlib import Path

from aaa.config import DEFAULT_BODY_EVIDENCE_LIMIT
from aaa.store.events import EvidenceInfo


class EvidenceStore:
    """把请求 body 截断写入 ``data/evidence/<event_id>.bin``。

    sha256 按实际写入（截断后）的内容计算，与文件内容一致可复核；
    ``original_size`` 保留原始 body 长度。
    """

    def __init__(
        self,
        evidence_dir: Path,
        max_bytes: int = DEFAULT_BODY_EVIDENCE_LIMIT,
        rel_base: Path | None = None,
    ) -> None:
        self._dir = evidence_dir
        self._max_bytes = max_bytes
        # file 字段相对该目录展示（通常为 data_dir，对齐 02 文档 §6 "data/evidence/..."）
        self._rel_base = rel_base
        self._lock = threading.Lock()
        evidence_dir.mkdir(parents=True, exist_ok=True)

    @property
    def max_bytes(self) -> int:
        return self._max_bytes

    def _display_path(self, path: Path) -> str:
        if self._rel_base is not None:
            try:
                return path.relative_to(self._rel_base).as_posix()
            except ValueError:
                pass
        return str(path)

    def save_body(self, event_id: str, body: bytes | None) -> EvidenceInfo:
        """保存（截断后的）请求 body，返回证据元信息。"""
        if not body:
            return EvidenceInfo(file=None, sha256=None, truncated=False, size=0, original_size=0)
        original_size = len(body)
        data = body[: self._max_bytes]
        digest = hashlib.sha256(data).hexdigest()
        path = self._dir / f"{event_id}.bin"
        with self._lock, path.open("wb") as fh:
            fh.write(data)
        return EvidenceInfo(
            file=self._display_path(path),
            sha256=digest,
            truncated=original_size > len(data),
            size=len(data),
            original_size=original_size,
        )

    def path_of(self, event_id: str) -> Path:
        return self._dir / f"{event_id}.bin"
