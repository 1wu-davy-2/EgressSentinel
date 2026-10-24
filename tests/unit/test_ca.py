"""CA 管理单测（03 文档 T1.3）。

红线：证书生成只发生在 tmp 目录（文件系统操作，不触碰系统证书存储）；
所有安装/卸载测试用注入的假 runner（mock），绝不真实施改证书存储。
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from aaa.setup import ca


def test_ensure_ca_generates_in_confdir(tmp_path: Path) -> None:
    confdir = tmp_path / "mitm"
    info = ca.ensure_ca(confdir)
    assert info.path == confdir / ca.CA_CERT_PEM_NAME
    assert info.path.exists()
    assert re.fullmatch(r"[0-9A-F]+", info.serial)
    assert len(info.thumbprint) == 40  # SHA1 hex
    assert info.subject_cn


def test_ensure_ca_locates_without_regeneration(tmp_path: Path) -> None:
    confdir = tmp_path / "mitm"
    first = ca.ensure_ca(confdir)
    ca_file = confdir / ca.CA_KEY_PEM_NAME
    mtime_before = ca_file.stat().st_mtime_ns
    second = ca.ensure_ca(confdir)
    assert second.serial == first.serial
    assert ca_file.stat().st_mtime_ns == mtime_before  # 未重新生成


def test_ensure_merged_pem_contains_ca_and_system_bundle(tmp_path: Path) -> None:
    confdir = tmp_path / "mitm"
    merged = ca.ensure_merged_pem(confdir, out_path=tmp_path / "ca-bundle.pem")
    content = merged.read_bytes()
    # 至少含 mitmproxy CA + certifi 系统 bundle 两段证书
    assert content.count(b"BEGIN CERTIFICATE") >= 2
    assert "BEGIN CERTIFICATE" in ca.ensure_ca(confdir).path.read_text(encoding="utf-8")


def test_ps_scripts_are_silent_dotnet_x509store(tmp_path: Path) -> None:
    cert = tmp_path / "ca.pem"
    script = ca.ps_install_user_root(cert)
    assert "System.Security.Cryptography.X509Certificates.X509Store" in script
    assert "'Root', 'CurrentUser'" in script
    assert "$store.Add($cert)" in script
    assert str(cert) in script

    remove = ca.ps_remove_user_root("0ABCDEF")
    assert "$_.SerialNumber -eq '0ABCDEF'" in remove  # 按序列号精确匹配
    assert "Write-Output $found.Count" in remove


def test_install_user_root_uses_powershell_dotnet(tmp_path: Path) -> None:
    calls: list[tuple[list[str], dict]] = []

    def fake_runner(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append((cmd, kwargs))
        return subprocess.CompletedProcess(cmd, 0, b"aaa-ca-install-ok\n", b"")

    cert = tmp_path / "ca.pem"
    cert.write_bytes(b"-----BEGIN CERTIFICATE-----")
    ca.install_user_root(cert, runner=fake_runner)
    (cmd, _kwargs) = calls[0]
    assert cmd[0] == "powershell"
    assert "-NoProfile" in cmd and "-NonInteractive" in cmd
    assert "X509Store" in cmd[-1]


def test_install_machine_root_uses_certutil_addstore(tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def fake_runner(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, b"db=Root\n", b"")

    ca.install_machine_root(tmp_path / "ca.pem", runner=fake_runner)
    assert calls[0][:3] == ["certutil", "-addstore", "Root"]


def test_uninstall_user_root_by_serial_returns_count() -> None:
    def fake_runner(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(cmd, 0, b"2\n", b"")

    assert ca.uninstall_user_root("ABCD", runner=fake_runner) == 2


def test_uninstall_machine_root_by_serial() -> None:
    calls: list[list[str]] = []

    def fake_runner(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, b"deleted\n", b"")

    ca.uninstall_machine_root("abcd", runner=fake_runner)
    assert calls[0] == ["certutil", "-delstore", "Root", "ABCD"]  # 大写规范化


def test_serial_injection_is_rejected() -> None:
    with pytest.raises(ca.SetupError, match="非法证书序列号"):
        ca.uninstall_machine_root("ABCD; -delstore CA", runner=lambda *a, **k: None)  # type: ignore[arg-type,return-value]
    with pytest.raises(ca.SetupError, match="非法证书序列号"):
        ca.ps_remove_user_root("XYZ 12")  # 空格非法


def test_runner_failure_raises_setup_error(tmp_path: Path) -> None:
    def failing_runner(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(cmd, 1, b"", b"certutil boom")

    with pytest.raises(ca.SetupError, match="certutil boom"):
        ca.install_machine_root(tmp_path / "x.pem", runner=failing_runner)


def test_install_cert_rejects_unknown_store() -> None:
    with pytest.raises(ca.SetupError, match="user|machine"):
        ca.install_cert("floppy", Path("x.pem"), runner=lambda *a, **k: None)  # type: ignore[arg-type,return-value]
