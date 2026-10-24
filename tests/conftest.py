"""pytest 公共夹具：临时数据目录、本地 fixture HTTP(S) 服务器、假系统后端、流模拟。

安全红线：任何测试都不得真实施改系统设置（系统代理、注册表、证书存储、防火墙、
用户环境变量）。setup 模块的测试一律经 ``fake_backends`` 注入假注册表/假广播，
setup 代码路径本身只允许以 dry-run / 注入方式执行。
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from aaa.config import AppPaths


def free_port() -> int:
    """向系统要一个空闲 TCP 端口（测试专用，不依赖真实外网）。"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    """独立数据目录（data/ 惯例布局），不触碰真实项目 data/。"""
    return tmp_path / "data"


@pytest.fixture
def paths(data_dir: Path) -> AppPaths:
    return AppPaths(data_dir=data_dir)


class _EchoHandler(BaseHTTPRequestHandler):
    """本地 fixture：回 200 与固定 body；记录收到的请求。"""

    server_version = "aaa-fixture/1.0"

    def do_GET(self) -> None:  # noqa: N802 - http.server 约定
        self.server.requests.append((self.command, self.path))  # type: ignore[attr-defined]
        body = b"fixture-ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        payload = self.rfile.read(length)
        self.server.requests.append((self.command, self.path, payload))  # type: ignore[attr-defined]
        body = b"fixture-received"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        """静默：测试输出保持干净。"""


@pytest.fixture
def http_fixture_server():
    """进程内 fixture HTTP 服务器，返回 (port, requests)。"""
    server = ThreadingHTTPServer(("127.0.0.1", free_port()), _EchoHandler)
    server.requests = []  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, name="aaa-fixture-http", daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def https_fixture_server(tmp_path: Path):
    """进程内 fixture **HTTPS** 服务器（03 文档 T3.5：本地 HTTPS fixture 充当"AI 端点"）。

    自签名证书只落在 ``tmp_path``（不进任何系统证书存储）；客户端信任经各客户端的
    进程级机制注入（httpx ``verify=``、curl ``--cacert``、node ``NODE_EXTRA_CA_CERTS``），
    绝不改系统证书库。行为与 ``http_fixture_server`` 一致：回 200 并记录收到的请求。
    """
    cert_file, key_file = _write_self_signed_cert(tmp_path)
    server = ThreadingHTTPServer(("127.0.0.1", free_port()), _EchoHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.requests = []  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, name="aaa-fixture-https", daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


def _write_self_signed_cert(tmp_path: Path) -> tuple[Path, Path]:
    """生成测试专用自签名证书（CN/SAN = 127.0.0.1 + localhost），仅 fixture TLS 使用。"""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = _dt.datetime.now(_dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(days=1))
        .not_valid_after(now + _dt.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    x509.DNSName("localhost"),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_file = tmp_path / "fixture-cert.pem"
    key_file = tmp_path / "fixture-key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert_file, key_file


@pytest.fixture
def fake_backends(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[dict[str, str], dict[str, object]]:
    """假注册表/假广播后端（安全红线：测试绝不真实施改系统设置）。

    把 ``setup.envvars``（HKCU\\Environment 读写删 + WM_SETTINGCHANGE）与
    ``setup.proxy``（WinINET 注册表 + InternetSetOption 刷新）的模块级访问函数
    全部替换为 dict 后端。凡是会执行 apply/restore 的测试——包括 **CLI 层**
    ``aaa setup``/``aaa teardown``（``teardown.RESTORERS`` 在调用时才解析模块级
    ``_env_delete``/``_reg_write``）——必须先挂载本夹具，否则会对真实系统实施
    注册表删除/写入。
    """
    from aaa.setup import envvars, proxy

    env_registry: dict[str, str] = {}
    monkeypatch.setattr(envvars, "_env_read", lambda name: env_registry.get(name))
    monkeypatch.setattr(
        envvars, "_env_write", lambda name, value: env_registry.__setitem__(name, value)
    )
    monkeypatch.setattr(envvars, "_env_delete", lambda name: env_registry.pop(name, None))
    monkeypatch.setattr(envvars, "broadcast_env_change", lambda: None)

    inet_registry: dict[str, object] = {}
    monkeypatch.setattr(proxy, "_reg_read", lambda name: inet_registry.get(name))
    monkeypatch.setattr(
        proxy, "_reg_write", lambda name, value: inet_registry.__setitem__(name, value)
    )
    monkeypatch.setattr(proxy, "_reg_delete", lambda name: inet_registry.pop(name, None))
    monkeypatch.setattr(proxy, "refresh_wininet", lambda: None)
    return env_registry, inet_registry


def wait_until(predicate, timeout: float = 10.0, interval: float = 0.05) -> bool:
    """轮询等待条件成立（事件异步落盘场景）。"""
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()
