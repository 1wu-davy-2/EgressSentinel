"""证据文件：请求 body 截断落盘 + sha256（02 文档 D6，03 文档 T1.2）。

v0.2.0（05 文档波次二 §4）接入 :class:`~aaa.store.crypto.CryptoEngine`：

- ``crypto`` 参数注入加密引擎（可选，None = 行为与 v0.1.x 完全一致）；
- 写入：明文先按 ``max_bytes`` 截断，再经 ``crypto.encrypt``（按引擎当前配置——
  未开启加密时原样返回）落盘；``sha256`` 按实际落盘字节计算（加密时即密文摘要，
  无密钥也可复核文件完整性，decisions.md D-2026-10-24-35）；
- 读取：:meth:`read_body` 透明兼容——文件无 ES01 魔数（旧明文证据）按原样返回，
  有魔数经引擎解密（与加密开关无关，decisions.md D-2026-10-24-35）。

红线：密文文件头 ``ES01`` 是识别依据（见 store.crypto）；密钥材料绝不进事件/日志；
加密开启但密钥不可用时 fail-fast（CryptoError 上抛，绝不静默写明文）。
"""

from __future__ import annotations

import hashlib
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from aaa.config import DEFAULT_BODY_EVIDENCE_LIMIT
from aaa.store.events import EvidenceInfo

if TYPE_CHECKING:  # 仅类型检查期导入：crypto 反向依赖本模块，运行时经 Protocol 解耦
    from aaa.store.crypto import CryptoEngine


class CryptoLike(Protocol):
    """加密引擎最小协议（生产为 ``CryptoEngine``；避免 store.evidence ←→ crypto 循环导入）。"""

    def encrypt(self, data: bytes) -> bytes:
        """按当前配置加密（未开启时原样返回）。"""
        ...

    def decrypt(self, blob: bytes) -> bytes:
        """透明解密：无魔数按明文返回，有魔数解密。"""
        ...


class EvidenceStore:
    """把请求 body 截断写入 ``data/evidence/<event_id>.bin``（可选加密，v0.2.0）。

    sha256 按实际写入（截断、加密后）的内容计算，与文件内容一致可复核；
    ``original_size`` 保留原始 body 长度；``size``/``truncated`` 描述明文长度
    （截断发生在明文层，密文始终完整可解，decisions.md D-2026-10-24-35）。
    """

    def __init__(
        self,
        evidence_dir: Path,
        max_bytes: int = DEFAULT_BODY_EVIDENCE_LIMIT,
        rel_base: Path | None = None,
        crypto: CryptoLike | CryptoEngine | None = None,
    ) -> None:
        self._dir = evidence_dir
        self._max_bytes = max_bytes
        # file 字段相对该目录展示（通常为 data_dir，对齐 02 文档 §6 "data/evidence/..."）
        self._rel_base = rel_base
        self._crypto = crypto
        self._lock = threading.Lock()
        evidence_dir.mkdir(parents=True, exist_ok=True)

    @property
    def max_bytes(self) -> int:
        return self._max_bytes

    @property
    def crypto(self) -> CryptoLike | CryptoEngine | None:
        """注入的加密引擎（未注入为 None）。"""
        return self._crypto

    def _display_path(self, path: Path) -> str:
        if self._rel_base is not None:
            try:
                return path.relative_to(self._rel_base).as_posix()
            except ValueError:
                pass
        return str(path)

    def save_body(self, event_id: str, body: bytes | None) -> EvidenceInfo:
        """保存（截断后的）请求 body：先按引擎配置加密再落盘，返回证据元信息。"""
        if not body:
            return EvidenceInfo(file=None, sha256=None, truncated=False, size=0, original_size=0)
        original_size = len(body)
        data = body[: self._max_bytes]
        stored = self._crypto.encrypt(data) if self._crypto is not None else data
        digest = hashlib.sha256(stored).hexdigest()
        path = self._dir / f"{event_id}.bin"
        with self._lock, path.open("wb") as fh:
            fh.write(stored)
        return EvidenceInfo(
            file=self._display_path(path),
            sha256=digest,
            truncated=original_size > len(data),
            size=len(data),
            original_size=original_size,
        )

    def path_of(self, event_id: str) -> Path:
        return self._dir / f"{event_id}.bin"

    def read_body(self, event_id: str) -> bytes:
        """透明读取证据明文（v0.2.0）：旧明文原样返回，ES01 密文自动解密。

        未注入加密引擎时按原始字节返回（与 v0.1.x 读盘一致）；文件不存在抛
        ``FileNotFoundError``（与常规 IO 一致）。
        """
        blob = self.path_of(event_id).read_bytes()
        if self._crypto is not None:
            return self._crypto.decrypt(blob)
        return blob
