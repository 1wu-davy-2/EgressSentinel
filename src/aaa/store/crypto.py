"""证据静态加密（05 文档波次一 W5）：AES-256-GCM + ``ES01`` 魔数头。

密文文件格式：``ES01(4B) | nonce(12B) | ciphertext || tag(16B)``（AAD 为空）。
主密钥来源二选一（keyfile 优先）：``data/.crypto-key``（32B 随机）或
``AAA_MASTER_PASSWORD`` 口令经 PBKDF2-HMAC-SHA256（200k 迭代）派生
（盐落 ``data/.crypto-salt``，16B 随机，decisions.md D-2026-10-24-35）。

红线说明：
- **默认关闭**（05 文档 W5）：``enabled=False`` 时写入不加密（原样落盘），
  向后兼容旧明文证据——读取遇无魔数文件按明文原样返回；
- 密钥材料（keyfile/salt）只落数据目录，绝不进事件、日志、通知或代码库；
  材料丢失即无法解密既有密文（如实报错，绝不静默重建掩盖）；
- 口令只从环境变量 ``AAA_MASTER_PASSWORD`` 或调用方显式参数读取，不落盘；
- 开启加密后密钥不可用属 fail-fast：抛 ``CryptoError`` 而非静默写明文
  （宁可失败，不给"已加密"的假象；集成方决定如何处置）；
- 本波次不改 ``store/evidence.py``：集成经 ``decrypt_file``/``encrypt_file``
  级 API 或 ``EncryptedFileStore`` 包装接入（05 文档波次二第 4 条）；
- 测试纪律：所有密钥材料与密文只落 tmp_path，绝不触碰真实 ``data/``。
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import threading
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from aaa.store.events import EvidenceInfo
from aaa.store.evidence import EvidenceStore

#: 密文魔数（文件头 4 字节，05 文档 W5）
MAGIC = b"ES01"
#: AES-256 密钥长度（字节）
KEY_SIZE = 32
#: GCM 标准 nonce 长度（字节）
NONCE_SIZE = 12
#: PBKDF2 盐长度（字节）
SALT_SIZE = 16
#: GCM 认证标签长度（cryptography 固定 16B，追加在密文尾部）
TAG_SIZE = 16
#: PBKDF2-HMAC-SHA256 迭代次数（05 文档 W5：200k）
KDF_ITERATIONS = 200_000

#: 随机 keyfile 文件名（相对数据目录，05 文档 W5）
KEYFILE_NAME = ".crypto-key"
#: 口令派生盐文件名（decisions.md D-2026-10-24-35）
SALTFILE_NAME = ".crypto-salt"
#: 主口令环境变量（对齐 W3 ``AAA_JUDGE_API_KEY`` 模式：只读环境变量，不落盘）
MASTER_PASSWORD_ENV = "AAA_MASTER_PASSWORD"


class CryptoError(RuntimeError):
    """密钥材料缺失/损坏、密文结构非法或认证失败。如实抛出，绝不静默降级。"""


# ------------------------------------------------------------------ 密钥派生


def derive_key(password: str | bytes, salt: bytes, *, iterations: int = KDF_ITERATIONS) -> bytes:
    """PBKDF2-HMAC-SHA256 派生 256 位主密钥（05 文档 W5：200k 迭代）。

    同一 (password, salt, iterations) 恒等输出；str 口令按 UTF-8 编码。
    空口令/空盐拒绝派生（防御性，调用方应视为"未配置"）。
    """
    if isinstance(password, str):
        password = password.encode("utf-8")
    if not password:
        raise CryptoError("口令为空，拒绝派生密钥")
    if not salt:
        raise CryptoError("盐为空，拒绝派生密钥")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password)


# ------------------------------------------------------------------ 字节级加解密


def _check_key(key: bytes) -> None:
    if len(key) != KEY_SIZE:
        raise CryptoError(f"密钥长度异常：{len(key)}B（AES-256 要求 {KEY_SIZE}B）")


def is_encrypted(blob: bytes) -> bool:
    """魔数识别：blob 是否为本模块密文格式（前缀 ``ES01``）。"""
    return blob.startswith(MAGIC)


def encrypt_bytes(key: bytes, data: bytes) -> bytes:
    """AES-256-GCM 加密：返回 ``MAGIC + nonce + ciphertext+tag``（nonce 每次随机）。"""
    _check_key(key)
    nonce = os.urandom(NONCE_SIZE)
    ct = AESGCM(key).encrypt(nonce, data, None)
    return MAGIC + nonce + ct


def decrypt_bytes(key: bytes, blob: bytes) -> bytes:
    """AES-256-GCM 解密（严格模式：无魔数/结构不完整/认证失败均抛 ``CryptoError``）。

    明文兼容判断（无魔数按明文返回）在文件层做——见 ``decrypt_file``。
    """
    _check_key(key)
    if not is_encrypted(blob):
        raise CryptoError("缺少 ES01 魔数：不是本模块生成的密文（明文兼容请在文件层判断）")
    header = len(MAGIC) + NONCE_SIZE
    if len(blob) < header + TAG_SIZE:
        raise CryptoError("密文结构不完整（过短，缺少 nonce 或认证标签）")
    nonce = blob[len(MAGIC) : header]
    try:
        return AESGCM(key).decrypt(nonce, blob[header:], None)
    except InvalidTag as exc:
        raise CryptoError("解密失败：密钥错误或密文被篡改") from exc


# ------------------------------------------------------------------ 文件级 API


def encrypt_file(path: Path, key: bytes) -> bool:
    """就地加密文件（tmp 写入 + 原子替换）；已带魔数则为幂等 no-op。

    返回 True 表示本次执行了加密，False 表示文件已是密文（未动）。
    供集成迁移历史明文证据用；调用方持有 key 的生命周期。
    """
    path = Path(path)
    blob = path.read_bytes()
    if is_encrypted(blob):
        return False
    tmp = Path(f"{path}.tmp")
    tmp.write_bytes(encrypt_bytes(key, blob))
    os.replace(tmp, path)
    return True


def decrypt_file(path: Path, key: bytes) -> bytes:
    """读取证据文件并透明解密（05 文档 W5 导出的集成 API）。

    无魔数（旧明文证据/加密未开启时期写入）→ **按明文原样返回**；
    有魔数 → AES-256-GCM 解密（密钥错误/篡改抛 ``CryptoError``）。
    """
    blob = Path(path).read_bytes()
    if not is_encrypted(blob):
        return blob
    return decrypt_bytes(key, blob)


# ------------------------------------------------------------------ 密钥材料落盘


def _tighten_permissions(path: Path) -> None:
    """尽力收紧密钥材料文件权限（05 文档 W5"权限尽力收紧"）。

    POSIX：chmod 0600；Windows：icacls 移除继承并仅授予当前用户完全控制。
    任何失败（icacls 缺失/拒绝/超时）都静默容忍——"尽力而为"语义，
    绝不因权限收紧失败而中断密钥写入。
    """
    try:
        if os.name == "posix":
            os.chmod(path, 0o600)
        else:
            user = os.environ.get("USERNAME", "")
            if not user:
                return
            subprocess.run(
                ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"],
                check=False,
                capture_output=True,
                timeout=10,
            )
    except (OSError, subprocess.SubprocessError):
        pass


def _write_private_file(path: Path, data: bytes) -> None:
    """密钥材料原子落盘：tmp 写入 → 收紧权限 → 原子替换 → 对最终文件再收紧一次。

    常规平台 rename 保留源文件属性（tmp 已收紧），对最终文件重复收紧属
    防御性冗余（替换语义跨平台差异时的兜底），开销仅在首次生成密钥材料时发生。
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = Path(f"{path}.tmp")
    tmp.write_bytes(data)
    _tighten_permissions(tmp)
    os.replace(tmp, path)
    _tighten_permissions(path)


# ------------------------------------------------------------------ 引擎


class CryptoEngine:
    """证据加密引擎：密钥生命周期 + 按配置加解密（05 文档 W5）。

    - 密钥解析优先级：已有 keyfile > 口令（显式参数 > ``AAA_MASTER_PASSWORD``）
      > 生成 keyfile（仅写入路径且 ``enabled=True`` 时）；
    - ``enabled=False``（默认）：``encrypt`` 原样返回（写入按当前配置），
      ``decrypt`` 仍能解密既有密文（读取透明兼容与开关无关）；
    - 线程安全：密钥惰性解析全程持锁。
    """

    def __init__(
        self,
        data_dir: Path,
        *,
        enabled: bool = False,
        password: str | bytes | None = None,
    ) -> None:
        self._data_dir = Path(data_dir)
        self._enabled = enabled
        self._password = password
        self._key: bytes | None = None
        self._key_source: str | None = None
        self._lock = threading.Lock()

    # -------------------------------------------------------------- 状态

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def data_dir(self) -> Path:
        return self._data_dir

    @property
    def keyfile_path(self) -> Path:
        return self._data_dir / KEYFILE_NAME

    @property
    def salt_path(self) -> Path:
        return self._data_dir / SALTFILE_NAME

    @property
    def key(self) -> bytes:
        """主密钥（惰性解析，绝不生成新密钥材料；无来源抛 ``CryptoError``）。"""
        key = self._resolve_key(create=False)
        if key is None:
            raise CryptoError(
                "无可用密钥来源：keyfile 缺失且未设置口令（AAA_MASTER_PASSWORD）"
            )
        return key

    @property
    def key_source(self) -> str | None:
        """已解析密钥的来源：``keyfile``/``password``/``generated``，未解析为 None。"""
        return self._key_source

    def describe(self) -> dict[str, object]:
        """加密状态概要（run 启动概要/status 用；无副作用，不解析密钥）。"""
        return {
            "enabled": self._enabled,
            "key_source": self._key_source,
            "keyfile": str(self.keyfile_path),
            "algorithm": "AES-256-GCM",
            "kdf": f"PBKDF2-HMAC-SHA256({KDF_ITERATIONS})",
        }

    # -------------------------------------------------------------- 加解密

    def encrypt(self, data: bytes) -> bytes:
        """按当前配置加密：未开启或空数据 → 原样返回；开启 → ES01 密文。"""
        if not self._enabled or not data:
            return data
        key = self._resolve_key(create=True)
        if key is None:  # 理论不可达：create=True 必产出或抛异常；防御性兜底
            return data
        return encrypt_bytes(key, data)

    def decrypt(self, blob: bytes) -> bytes:
        """透明读取（05 文档 W5）：无魔数按明文返回；有魔数解密（与 enabled 无关）。"""
        if not is_encrypted(blob):
            return blob
        key = self._resolve_key(create=False)
        if key is None:
            raise CryptoError(
                "密文需要密钥：keyfile 缺失且未设置口令（读取兼容与 enabled 无关）"
            )
        return decrypt_bytes(key, blob)

    # -------------------------------------------------------------- 文件级

    def read_file(self, path: Path) -> bytes:
        """透明读取文件：无魔数原样返回（不触发密钥解析）；有魔数解密。"""
        return self.decrypt(Path(path).read_bytes())

    def encrypt_file(self, path: Path) -> bool:
        """按当前配置就地加密文件：未开启加密时不动文件（返回 False）。"""
        if not self._enabled:
            return False
        key = self._resolve_key(create=True)
        if key is None:  # 理论不可达，防御性兜底
            return False
        return encrypt_file(path, key)

    # -------------------------------------------------------------- 内部

    def _resolve_password(self) -> str | bytes | None:
        """口令解析：显式参数 > 环境变量；空串视为未设置。"""
        if self._password is not None:
            return self._password
        return os.environ.get(MASTER_PASSWORD_ENV) or None

    def _load_salt(self, *, create: bool) -> bytes | None:
        """读盐文件；``create=True`` 时缺失则生成（写入路径），否则返回 None。"""
        path = self.salt_path
        if path.exists():
            raw = path.read_bytes()
            if len(raw) != SALT_SIZE:
                raise CryptoError(f"盐文件长度异常：{len(raw)}B（应为 {SALT_SIZE}B）：{path}")
            return raw
        if not create:
            return None
        salt = os.urandom(SALT_SIZE)
        _write_private_file(path, salt)
        return salt

    def _resolve_key(self, *, create: bool) -> bytes | None:
        """解析主密钥。``create=True`` 允许生成密钥材料（写入路径）；否则无来源返回 None。"""
        with self._lock:
            if self._key is not None:
                return self._key
            keyfile = self.keyfile_path
            if keyfile.exists():
                raw = keyfile.read_bytes()
                if len(raw) != KEY_SIZE:
                    raise CryptoError(
                        f"keyfile 长度异常：{len(raw)}B（应为 {KEY_SIZE}B），"
                        f"拒绝使用（重建会丢失既有密文的访问能力）：{keyfile}"
                    )
                self._key, self._key_source = raw, "keyfile"
                return raw
            password = self._resolve_password()
            if password:
                salt = self._load_salt(create=create)
                if salt is None:
                    raise CryptoError(
                        f"口令派生缺少盐文件：{self.salt_path}"
                        f"（盐丢失则既有密文不可解，绝不静默重建）"
                    )
                self._key, self._key_source = derive_key(password, salt), "password"
                return self._key
            if not create:
                return None
            key = os.urandom(KEY_SIZE)
            _write_private_file(keyfile, key)
            self._key, self._key_source = key, "generated"
            return key


# ------------------------------------------------------------------ 证据存储包装


class EncryptedFileStore:
    """``EvidenceStore`` 的最小侵入加密包装（组合，不改 evidence.py——05 文档 W5）。

    - ``save_body``：明文先按内层 ``max_bytes`` 截断，再经 ``CryptoEngine.encrypt``
      （按当前配置）落盘；``size/original_size/truncated`` 如实描述**明文**，
      ``sha256`` 为**实际落盘文件**（密文）摘要——无密钥也可复核文件完整性；
    - ``read_body``：透明读取（旧明文证据原样返回，密文自动解密）；
    - 未开启加密时行为与内层 ``EvidenceStore`` 等价（写明文、读明文）。
    """

    def __init__(
        self,
        inner: EvidenceStore,
        engine: CryptoEngine,
        *,
        rel_base: Path | None = None,
    ) -> None:
        self._inner = inner
        self._engine = engine
        self._rel_base = rel_base
        self._lock = threading.Lock()

    @property
    def inner(self) -> EvidenceStore:
        return self._inner

    @property
    def engine(self) -> CryptoEngine:
        return self._engine

    @property
    def max_bytes(self) -> int:
        return self._inner.max_bytes

    def path_of(self, event_id: str) -> Path:
        return self._inner.path_of(event_id)

    def _display_path(self, path: Path) -> str:
        if self._rel_base is not None:
            try:
                return path.relative_to(self._rel_base).as_posix()
            except ValueError:
                pass
        return str(path)

    def save_body(self, event_id: str, body: bytes | None) -> EvidenceInfo:
        """保存（截断后的）请求 body：先按配置加密再落盘，返回证据元信息。"""
        if not body:
            return EvidenceInfo(file=None, sha256=None, truncated=False, size=0, original_size=0)
        original_size = len(body)
        data = body[: self._inner.max_bytes]
        stored = self._engine.encrypt(data)
        digest = hashlib.sha256(stored).hexdigest()
        path = self._inner.path_of(event_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, path.open("wb") as fh:
            fh.write(stored)
        return EvidenceInfo(
            file=self._display_path(path),
            sha256=digest,
            truncated=original_size > len(data),
            size=len(data),
            original_size=original_size,
        )

    def read_body(self, event_id: str) -> bytes:
        """透明读取证据明文（文件不存在抛 ``FileNotFoundError``，与常规 IO 一致）。"""
        return self._engine.read_file(self._inner.path_of(event_id))


__all__ = [
    "KEYFILE_NAME",
    "KDF_ITERATIONS",
    "KEY_SIZE",
    "MAGIC",
    "MASTER_PASSWORD_ENV",
    "NONCE_SIZE",
    "SALTFILE_NAME",
    "SALT_SIZE",
    "TAG_SIZE",
    "CryptoEngine",
    "CryptoError",
    "EncryptedFileStore",
    "decrypt_bytes",
    "decrypt_file",
    "derive_key",
    "encrypt_bytes",
    "encrypt_file",
    "is_encrypted",
]
