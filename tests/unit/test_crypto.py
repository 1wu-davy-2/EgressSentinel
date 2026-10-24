"""store.crypto 单测（05 文档波次一 W5）。

覆盖：往返加解密 / 错误密钥失败 / ES01 魔数识别与明文兼容 /
keyfile 与口令派生一致性 / 引擎开关语义 / EncryptedFileStore 包装。

红线：所有密钥材料与密文只落 tmp_path（conftest ``data_dir`` 夹具），
绝不触碰真实 ``data/``；口令经参数或 monkeypatch 环境变量注入，不留真实凭据。
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from aaa.store import crypto
from aaa.store.crypto import (
    KDF_ITERATIONS,
    KEY_SIZE,
    MAGIC,
    NONCE_SIZE,
    SALT_SIZE,
    CryptoEngine,
    CryptoError,
    EncryptedFileStore,
    decrypt_bytes,
    decrypt_file,
    derive_key,
    encrypt_bytes,
    encrypt_file,
    is_encrypted,
)
from aaa.store.evidence import EvidenceStore

# ---------------------------------------------------------------- 常量与派生


def test_magic_and_constants() -> None:
    """05 文档 W5 规格：ES01 魔数、AES-256、12B nonce、200k 迭代。"""
    assert MAGIC == b"ES01"
    assert KEY_SIZE == 32
    assert NONCE_SIZE == 12
    assert SALT_SIZE == 16
    assert KDF_ITERATIONS == 200_000


def test_derive_key_deterministic_and_length() -> None:
    salt = b"0123456789abcdef"
    assert derive_key("pw", salt) == derive_key("pw", salt)
    assert derive_key(b"pw", salt) == derive_key("pw", salt)  # str/bytes 等价
    assert len(derive_key("pw", salt)) == KEY_SIZE


def test_derive_key_differs_by_password_and_salt() -> None:
    salt_a = b"a" * 16
    salt_b = b"b" * 16
    assert derive_key("pw1", salt_a) != derive_key("pw2", salt_a)
    assert derive_key("pw1", salt_a) != derive_key("pw1", salt_b)


def test_derive_key_rejects_empty_password_or_salt() -> None:
    with pytest.raises(CryptoError, match="口令为空"):
        derive_key("", b"x" * 16)
    with pytest.raises(CryptoError, match="盐为空"):
        derive_key("pw", b"")


# ---------------------------------------------------------------- 字节级往返


@pytest.mark.parametrize(
    "data",
    [b"x", b"hello world", os.urandom(1024), os.urandom(3 * 1024 + 17), b""],
    ids=["1B", "短文本", "1KB", "跨块", "空"],
)
def test_encrypt_decrypt_roundtrip(data: bytes) -> None:
    key = os.urandom(KEY_SIZE)
    blob = encrypt_bytes(key, data)
    assert is_encrypted(blob)
    assert decrypt_bytes(key, blob) == data


def test_ciphertext_format_and_random_nonce() -> None:
    key = os.urandom(KEY_SIZE)
    data = b"same-plaintext"
    blob1 = encrypt_bytes(key, data)
    blob2 = encrypt_bytes(key, data)
    # 格式：ES01(4) + nonce(12) + ct + tag(16)
    assert blob1[:4] == MAGIC
    assert len(blob1) == 4 + NONCE_SIZE + len(data) + 16
    # nonce 随机 → 同明文两次密文不同，但都可解
    assert blob1 != blob2
    assert decrypt_bytes(key, blob1) == decrypt_bytes(key, blob2) == data


def test_wrong_key_fails() -> None:
    key1 = os.urandom(KEY_SIZE)
    key2 = os.urandom(KEY_SIZE)
    blob = encrypt_bytes(key1, b"secret")
    with pytest.raises(CryptoError, match="密钥错误或密文被篡改"):
        decrypt_bytes(key2, blob)


def test_tampered_or_truncated_ciphertext_fails() -> None:
    key = os.urandom(KEY_SIZE)
    blob = bytearray(encrypt_bytes(key, b"secret-body"))
    blob[-1] ^= 0xFF  # 篡改 tag
    with pytest.raises(CryptoError):
        decrypt_bytes(key, bytes(blob))
    blob2 = bytearray(encrypt_bytes(key, b"secret-body"))
    blob2[10] ^= 0xFF  # 篡改 nonce
    with pytest.raises(CryptoError):
        decrypt_bytes(key, bytes(blob2))
    with pytest.raises(CryptoError, match="结构不完整"):
        decrypt_bytes(key, blob2[:10])


def test_decrypt_bytes_requires_magic() -> None:
    key = os.urandom(KEY_SIZE)
    with pytest.raises(CryptoError, match="缺少 ES01 魔数"):
        decrypt_bytes(key, b"plain text without magic")
    with pytest.raises(CryptoError, match="密钥长度异常"):
        decrypt_bytes(b"short-key", encrypt_bytes(os.urandom(KEY_SIZE), b"x"))


# ---------------------------------------------------------------- 文件级与明文兼容


def test_encrypt_file_decrypt_file_roundtrip(data_dir: Path) -> None:
    path = data_dir / "evidence" / "evt_r.bin"
    path.parent.mkdir(parents=True)
    original = b"evidence-bytes-123"
    path.write_bytes(original)
    key = derive_key("pw", b"s" * 16)
    assert encrypt_file(path, key) is True
    assert is_encrypted(path.read_bytes())
    assert decrypt_file(path, key) == original


def test_encrypt_file_idempotent(data_dir: Path) -> None:
    path = data_dir / "f.bin"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"plain")
    key = os.urandom(KEY_SIZE)
    assert encrypt_file(path, key) is True
    encrypted = path.read_bytes()
    assert encrypt_file(path, key) is False  # 已带魔数 → no-op
    assert path.read_bytes() == encrypted


def test_decrypt_file_plaintext_passthrough(data_dir: Path) -> None:
    """旧明文证据兼容（05 文档 W5）：无魔数按明文原样返回。"""
    path = data_dir / "legacy.bin"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"legacy-plaintext-evidence")
    assert decrypt_file(path, os.urandom(KEY_SIZE)) == b"legacy-plaintext-evidence"
    empty = data_dir / "empty.bin"
    empty.write_bytes(b"")
    assert decrypt_file(empty, os.urandom(KEY_SIZE)) == b""


def test_decrypt_file_wrong_key_on_encrypted(data_dir: Path) -> None:
    path = data_dir / "enc.bin"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"data")
    encrypt_file(path, os.urandom(KEY_SIZE))
    with pytest.raises(CryptoError):
        decrypt_file(path, os.urandom(KEY_SIZE))


# ---------------------------------------------------------------- 引擎：keyfile 模式


def test_engine_generates_keyfile_and_reuses_across_instances(data_dir: Path) -> None:
    """keyfile 派生一致性：首个引擎生成，后续实例复用同一密钥。"""
    engine1 = CryptoEngine(data_dir, enabled=True)
    blob = engine1.encrypt(b"cross-instance-secret")
    keyfile = data_dir / ".crypto-key"
    assert keyfile.exists()
    key_on_disk = keyfile.read_bytes()
    assert len(key_on_disk) == KEY_SIZE
    assert engine1.key_source == "generated"

    engine2 = CryptoEngine(data_dir, enabled=True)
    assert engine2.decrypt(blob) == b"cross-instance-secret"
    assert engine2.key == key_on_disk
    assert engine2.key_source == "keyfile"
    # 不重建 keyfile
    assert keyfile.read_bytes() == key_on_disk


def test_keyfile_priority_over_password(data_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """keyfile 优先（05 文档 W5）：keyfile 存在时口令被忽略。"""
    data_dir.mkdir(parents=True, exist_ok=True)
    keyfile = data_dir / ".crypto-key"
    known_key = os.urandom(KEY_SIZE)
    keyfile.write_bytes(known_key)
    monkeypatch.setenv("AAA_MASTER_PASSWORD", "env-password")

    engine = CryptoEngine(data_dir, enabled=True, password="explicit-password")
    blob = engine.encrypt(b"secret")
    assert decrypt_bytes(known_key, blob) == b"secret"
    assert engine.key_source == "keyfile"
    assert not (data_dir / ".crypto-salt").exists()  # 未走口令派生分支


def test_invalid_keyfile_length_rejected(data_dir: Path) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / ".crypto-key").write_bytes(b"short")
    engine = CryptoEngine(data_dir, enabled=True)
    with pytest.raises(CryptoError, match="keyfile 长度异常"):
        engine.encrypt(b"x")


def test_keyfile_write_tightens_permissions(
    data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[Path] = []
    monkeypatch.setattr(crypto, "_tighten_permissions", calls.append)
    CryptoEngine(data_dir, enabled=True).encrypt(b"x")
    assert (data_dir / ".crypto-key") in calls


@pytest.mark.skipif(os.name != "posix", reason="POSIX 权限语义")
def test_keyfile_mode_0600_posix(data_dir: Path) -> None:
    CryptoEngine(data_dir, enabled=True).encrypt(b"x")
    assert ((data_dir / ".crypto-key").stat().st_mode & 0o777) == 0o600


# ---------------------------------------------------------------- 引擎：口令派生模式


def test_password_mode_cross_instance(data_dir: Path) -> None:
    engine1 = CryptoEngine(data_dir, enabled=True, password="pw-alpha")
    blob = engine1.encrypt(b"password-secret")
    salt_file = data_dir / ".crypto-salt"
    assert salt_file.exists() and len(salt_file.read_bytes()) == SALT_SIZE
    assert engine1.key == derive_key("pw-alpha", salt_file.read_bytes())
    assert engine1.key_source == "password"

    engine2 = CryptoEngine(data_dir, enabled=True, password="pw-alpha")
    assert engine2.decrypt(blob) == b"password-secret"
    wrong = CryptoEngine(data_dir, enabled=True, password="pw-beta")
    with pytest.raises(CryptoError):
        wrong.decrypt(blob)


def test_password_from_env_and_param_overrides_env(
    data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """口令只从 ``AAA_MASTER_PASSWORD`` 环境变量读（不落盘）；显式参数优先。"""
    monkeypatch.setenv("AAA_MASTER_PASSWORD", "env-pw")
    engine = CryptoEngine(data_dir, enabled=True)
    blob = engine.encrypt(b"env-secret")
    assert engine.key_source == "password"
    assert engine.key == derive_key("env-pw", (data_dir / ".crypto-salt").read_bytes())

    same = CryptoEngine(data_dir, enabled=True, password="env-pw")
    assert same.decrypt(blob) == b"env-secret"
    other = CryptoEngine(data_dir, enabled=True, password="other-pw")
    with pytest.raises(CryptoError):
        other.decrypt(blob)


def test_missing_salt_for_decrypt_fails(data_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """盐文件丢失 → 如实报错，绝不静默重建掩盖（红线）。"""
    monkeypatch.setenv("AAA_MASTER_PASSWORD", "pw")
    engine1 = CryptoEngine(data_dir, enabled=True)
    blob = engine1.encrypt(b"secret")
    (data_dir / ".crypto-salt").unlink()
    engine2 = CryptoEngine(data_dir, enabled=True)
    with pytest.raises(CryptoError, match="盐文件"):
        engine2.decrypt(blob)


def test_empty_password_treated_as_unset(data_dir: Path) -> None:
    """空串口令视为未设置 → 走生成 keyfile 分支。"""
    engine = CryptoEngine(data_dir, enabled=True, password="")
    engine.encrypt(b"x")
    assert (data_dir / ".crypto-key").exists()
    assert not (data_dir / ".crypto-salt").exists()


# ---------------------------------------------------------------- 引擎：开关语义


def test_engine_disabled_by_default_writes_plaintext(data_dir: Path) -> None:
    """默认关闭（05 文档 W5）：encrypt 原样返回，不生成任何密钥材料。"""
    engine = CryptoEngine(data_dir)
    assert engine.enabled is False
    data = b"plain-evidence"
    assert engine.encrypt(data) == data
    assert not (data_dir / ".crypto-key").exists()
    assert not (data_dir / ".crypto-salt").exists()
    assert engine.key_source is None
    assert engine.describe()["enabled"] is False


def test_engine_disabled_still_reads_encrypted(data_dir: Path) -> None:
    """读取透明兼容与 enabled 无关：关闭后仍能解密历史密文。"""
    writer = CryptoEngine(data_dir, enabled=True)
    path = data_dir / "evt.bin"
    path.write_bytes(writer.encrypt(b"ciphertext-evidence"))

    reader = CryptoEngine(data_dir, enabled=False)
    assert reader.decrypt(path.read_bytes()) == b"ciphertext-evidence"
    assert reader.read_file(path) == b"ciphertext-evidence"


def test_engine_decrypt_needs_key_for_ciphertext(data_dir: Path) -> None:
    engine = CryptoEngine(data_dir, enabled=False)
    with pytest.raises(CryptoError, match="需要密钥"):
        engine.decrypt(MAGIC + b"\x00" * 40)
    assert engine.decrypt(b"no magic") == b"no magic"


def test_engine_encrypt_file_respects_enabled(data_dir: Path) -> None:
    path = data_dir / "f.bin"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"plain")
    off = CryptoEngine(data_dir, enabled=False)
    assert off.encrypt_file(path) is False
    assert path.read_bytes() == b"plain"
    on = CryptoEngine(data_dir, enabled=True)
    assert on.encrypt_file(path) is True
    assert is_encrypted(path.read_bytes())
    assert on.read_file(path) == b"plain"


def test_engine_describe_reports_key_source(data_dir: Path) -> None:
    engine = CryptoEngine(data_dir, enabled=True)
    summary = engine.describe()
    assert summary["enabled"] is True
    assert summary["key_source"] is None  # 未用前不解析
    engine.encrypt(b"x")
    assert engine.describe()["key_source"] == "generated"
    assert "AES-256-GCM" in str(engine.describe()["algorithm"])


# ---------------------------------------------------------------- EncryptedFileStore


def test_encrypted_file_store_roundtrip(data_dir: Path) -> None:
    inner = EvidenceStore(data_dir / "evidence", rel_base=data_dir)
    engine = CryptoEngine(data_dir, enabled=True)
    store = EncryptedFileStore(inner, engine, rel_base=data_dir)

    body = b"request-body-secret"
    info = store.save_body("evt_1", body)
    assert info.file == "evidence/evt_1.bin"  # 相对 data_dir（D-09）
    assert info.truncated is False
    assert info.size == len(body)
    assert info.original_size == len(body)
    path = data_dir / "evidence" / "evt_1.bin"
    # sha256 描述实际落盘的密文文件（无密钥也可复核完整性）
    assert info.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert is_encrypted(path.read_bytes())
    assert store.read_body("evt_1") == body


def test_encrypted_file_store_disabled_writes_plaintext(data_dir: Path) -> None:
    inner = EvidenceStore(data_dir / "evidence")
    store = EncryptedFileStore(inner, CryptoEngine(data_dir, enabled=False))
    info = store.save_body("evt_2", b"plain-body")
    path = inner.path_of("evt_2")
    assert path.read_bytes() == b"plain-body"  # 未开启 → 明文
    assert not is_encrypted(path.read_bytes())
    assert store.read_body("evt_2") == b"plain-body"
    assert info.sha256 == hashlib.sha256(b"plain-body").hexdigest()


def test_encrypted_file_store_truncates_plaintext(data_dir: Path) -> None:
    inner = EvidenceStore(data_dir / "evidence", max_bytes=16)
    store = EncryptedFileStore(inner, CryptoEngine(data_dir, enabled=True))
    body = b"B" * 100
    info = store.save_body("evt_big", body)
    assert info.truncated is True
    assert info.size == 16
    assert info.original_size == 100
    # 截断发生在明文层 → 密文完整可解
    assert store.read_body("evt_big") == b"B" * 16


def test_encrypted_file_store_empty_body(data_dir: Path) -> None:
    inner = EvidenceStore(data_dir / "evidence")
    store = EncryptedFileStore(inner, CryptoEngine(data_dir, enabled=True))
    info = store.save_body("evt_empty", None)
    assert info.file is None and info.sha256 is None
    assert not inner.path_of("evt_empty").exists()


def test_encrypted_file_store_reads_legacy_plaintext(data_dir: Path) -> None:
    """加密开启后旧明文证据仍可读（05 文档 W5 明文兼容）。"""
    inner = EvidenceStore(data_dir / "evidence")
    legacy = inner.path_of("evt_legacy")
    legacy.write_bytes(b"old-plaintext-evidence")
    store = EncryptedFileStore(inner, CryptoEngine(data_dir, enabled=True))
    assert store.read_body("evt_legacy") == b"old-plaintext-evidence"


def test_encrypted_file_store_missing_file_raises(data_dir: Path) -> None:
    inner = EvidenceStore(data_dir / "evidence")
    store = EncryptedFileStore(inner, CryptoEngine(data_dir, enabled=True))
    with pytest.raises(FileNotFoundError):
        store.read_body("evt_missing")
