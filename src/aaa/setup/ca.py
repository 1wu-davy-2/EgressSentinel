r"""CA 管理：定位/生成/安装/卸载（03 文档 T1.3，02 文档 D3 信任部署矩阵）。

- 生成：与采集引擎共用同一 confdir（``data/mitm/``），用 mitmproxy ``CertStore``
  生成/定位 ``mitmproxy-ca-cert.pem``；
- 安装 CurrentUser\Root：调用 .NET ``X509Store``（经 PowerShell），静默导入无弹窗；
- 安装 LocalMachine\Root：``certutil -addstore Root``（需管理员）；
- 卸载：按证书序列号精确定位删除，不误删同主题其他证书。

安全红线：本模块的测试一律注入假 runner / mock 子进程，不真实施改证书存储。
"""

from __future__ import annotations

import logging
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from mitmproxy.certs import CertStore

logger = logging.getLogger(__name__)

#: mitmproxy confdir 内 CA 相关文件名（CertStore.create_store 生成）
CA_BASENAME = "mitmproxy"
CA_CERT_PEM_NAME = "mitmproxy-ca-cert.pem"
CA_CERT_CER_NAME = "mitmproxy-ca-cert.cer"
CA_KEY_PEM_NAME = "mitmproxy-ca.pem"

#: 默认合并 PEM 输出位置（data/ca-bundle.pem），供 REQUESTS_CA_BUNDLE 等
MERGED_PEM_NAME = "ca-bundle.pem"

#: 证书序列号（十六进制）合法格式——防止注入 certutil/PowerShell 参数
_SERIAL_RE = re.compile(r"^[0-9A-Fa-f]+$")

#: 子进程 runner 类型（测试注入假 runner）
Runner = Callable[..., subprocess.CompletedProcess[bytes]]


class SetupError(RuntimeError):
    """setup 子命令失败。"""


@dataclass(frozen=True)
class CAInfo:
    """CA 证书元信息。"""

    path: Path
    serial: str
    thumbprint: str
    subject_cn: str


def load_ca_info(cert_path: Path) -> CAInfo:
    """用 cryptography 解析 CA 证书，得到序列号/指纹/主题。"""
    der_or_pem = cert_path.read_bytes()
    try:
        cert = x509.load_pem_x509_certificate(der_or_pem)
    except ValueError:
        cert = x509.load_der_x509_certificate(der_or_pem)
    serial = format(cert.serial_number, "X")
    thumbprint = cert.fingerprint(hashes.SHA1()).hex().upper()
    cn_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    subject_cn = cn_attrs[0].value if cn_attrs else cert.subject.rfc4514_string()
    return CAInfo(path=cert_path, serial=serial, thumbprint=thumbprint, subject_cn=str(subject_cn))


def ensure_ca(confdir: Path) -> CAInfo:
    """confdir 下定位 CA；不存在则经 mitmproxy CertStore 生成（与采集引擎一致）。"""
    confdir.mkdir(parents=True, exist_ok=True)
    pem_path = confdir / CA_CERT_PEM_NAME
    if not pem_path.exists():
        logger.info("confdir 下未找到 CA，开始生成：%s", confdir)
        # from_store：ca 文件缺失时自动 create_store（2048 位，mitmproxy 默认）
        CertStore.from_store(confdir, CA_BASENAME, 2048)
    if not pem_path.exists():
        # 极老版本只生成 .cer；做一个兼容回退
        cer_path = confdir / CA_CERT_CER_NAME
        if cer_path.exists():
            return load_ca_info(cer_path)
        raise SetupError(f"CA 生成失败：{confdir} 下未找到 {CA_CERT_PEM_NAME}")
    return load_ca_info(pem_path)


def ensure_merged_pem(confdir: Path, out_path: Path | None = None) -> Path:
    """生成合并 PEM：mitmproxy CA + 系统 CA（certifi）→ 供 Python/curl/Go 客户端使用。

    合并而非覆盖系统 bundle，保证走代理与不走代理的 HTTPS 都能校验通过（02 文档 D3）。
    """
    ca = ensure_ca(confdir)
    ca_bytes = ca.path.read_bytes()
    merged_path = out_path if out_path is not None else confdir.parent / MERGED_PEM_NAME
    try:
        import certifi

        system_bundle = Path(certifi.where()).read_bytes()
    except Exception:  # noqa: BLE001 - certifi 缺失时仅落 CA 本身
        logger.warning("certifi 不可用，合并 PEM 仅含 mitmproxy CA")
        system_bundle = b""
    content = ca_bytes.rstrip(b"\n") + b"\n\n" + system_bundle
    merged_path.parent.mkdir(parents=True, exist_ok=True)
    merged_path.write_bytes(content)
    return merged_path


# --------------------------------------------------------------------------
# PowerShell 脚本（CurrentUser Root，.NET X509Store 静默导入，02 文档 D3）
# --------------------------------------------------------------------------


def _ps_quote(value: str) -> str:
    """PowerShell 单引号字符串转义。"""
    return "'" + value.replace("'", "''") + "'"


def ps_install_user_root(cert_path: Path) -> str:
    r"""生成 CurrentUser\Root 导入脚本（.NET X509Store，静默）。"""
    return (
        "$ErrorActionPreference = 'Stop'\n"
        f"$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("
        f"{_ps_quote(str(cert_path))})\n"
        "$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("
        "'Root', 'CurrentUser')\n"
        "$store.Open('ReadWrite')\n"
        "$store.Add($cert)\n"
        "$store.Close()\n"
        "Write-Output 'aaa-ca-install-ok'\n"
    )


def ps_remove_user_root(serial: str) -> str:
    r"""生成按序列号精确删除 CurrentUser\Root 证书的脚本，输出删除数量。"""
    _validate_serial(serial)
    return (
        "$ErrorActionPreference = 'Stop'\n"
        "$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("
        "'Root', 'CurrentUser')\n"
        "$store.Open('ReadWrite')\n"
        f"$found = @($store.Certificates | Where-Object {{ $_.SerialNumber -eq "
        f"{_ps_quote(serial.upper())} }})\n"
        "$found | ForEach-Object { $store.Remove($_) }\n"
        "$store.Close()\n"
        "Write-Output $found.Count\n"
    )


def _validate_serial(serial: str) -> None:
    if not _SERIAL_RE.match(serial):
        raise SetupError(f"非法证书序列号：{serial!r}")


# --------------------------------------------------------------------------
# 子进程执行
# --------------------------------------------------------------------------


def _default_runner(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
    kwargs.setdefault("capture_output", True)
    return subprocess.run(cmd, **kwargs)  # type: ignore[arg-type]


def _check(completed: subprocess.CompletedProcess[bytes], action: str) -> str:
    if completed.returncode != 0:
        stderr = (completed.stderr or b"").decode("utf-8", "replace").strip()
        stdout = (completed.stdout or b"").decode("utf-8", "replace").strip()
        raise SetupError(f"{action} 失败（exit={completed.returncode}）：{stderr or stdout}")
    return (completed.stdout or b"").decode("utf-8", "replace")


_POWERSHELL_CMD = ("powershell", "-NoProfile", "-NonInteractive", "-Command")


def install_user_root(cert_path: Path, *, runner: Runner = _default_runner) -> None:
    r"""安装到 CurrentUser\Root（.NET X509Store 静默导入，无需管理员）。"""
    completed = runner([*_POWERSHELL_CMD, ps_install_user_root(cert_path)])
    _check(completed, f"导入 CurrentUser Root（{cert_path}）")


def install_machine_root(cert_path: Path, *, runner: Runner = _default_runner) -> None:
    r"""安装到 LocalMachine\Root（certutil，需管理员）。"""
    completed = runner(["certutil", "-addstore", "Root", str(cert_path)])
    _check(completed, f"certutil -addstore Root（{cert_path}）")


def uninstall_user_root(serial: str, *, runner: Runner = _default_runner) -> int:
    r"""从 CurrentUser\Root 按序列号删除证书，返回删除数量（0 表示本就不存在）。"""
    completed = runner([*_POWERSHELL_CMD, ps_remove_user_root(serial)])
    out = _check(completed, f"按序列号删除 CurrentUser Root 证书（serial={serial}）")
    for line in reversed(out.strip().splitlines()):
        line = line.strip()
        if line.isdigit():
            return int(line)
    logger.warning("无法从 PowerShell 输出解析删除数量：%r", out)
    return 0


def uninstall_machine_root(serial: str, *, runner: Runner = _default_runner) -> None:
    r"""从 LocalMachine\Root 按序列号删除证书（certutil -delstore，需管理员）。"""
    _validate_serial(serial)
    completed = runner(["certutil", "-delstore", "Root", serial.upper()])
    _check(completed, f"certutil -delstore Root（serial={serial}）")


def install_cert(store: str, cert_path: Path, *, runner: Runner = _default_runner) -> None:
    """按 ``store``（user|machine）安装 CA。"""
    if store == "user":
        install_user_root(cert_path, runner=runner)
    elif store == "machine":
        install_machine_root(cert_path, runner=runner)
    else:
        raise SetupError(f"--store 只支持 user|machine，收到：{store!r}")


def uninstall_cert(store: str, serial: str, *, runner: Runner = _default_runner) -> None:
    """按 ``store``（user|machine）与序列号卸载 CA。"""
    if store == "user":
        uninstall_user_root(serial, runner=runner)
    elif store == "machine":
        uninstall_machine_root(serial, runner=runner)
    else:
        raise SetupError(f"--store 只支持 user|machine，收到：{store!r}")
