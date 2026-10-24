"""内容扫描器（02 文档 D4，03 文档 T3.3）：全部纯函数、无网络调用。

- ``secrets``：gitleaks 核心 ~40 条规则移植（regex+熵+allowlist，MIT 来源，02 文档 §7）；
- ``pii``：邮箱/手机号/身份证/银行卡，支持 hits 阈值；
- ``code_leak``：本地绝对路径、代码密度启发、multipart 文件段、base64 大块。
"""

from aaa.scanners.base import ScanHit, ScanResult
from aaa.scanners.code_leak import scan_code_leak
from aaa.scanners.pii import scan_pii
from aaa.scanners.secrets import scan_secrets

__all__ = ["ScanHit", "ScanResult", "scan_code_leak", "scan_pii", "scan_secrets"]
