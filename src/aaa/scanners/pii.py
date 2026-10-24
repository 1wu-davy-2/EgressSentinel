"""PII 扫描器：邮箱/手机号（中国大陆）/身份证/银行卡（03 文档 T3.3）。

- 身份证：18 位格式 + GB 11643 校验位验证，削减误报；
- 银行卡：13-19 位数字 + Luhn 校验；
- 全部纯函数、无网络调用；``metrics["hits"]`` 供策略 ``hits_gt`` 阈值匹配。
"""

from __future__ import annotations

import re

from aaa.scanners.base import ScanHit, ScanResult

SCANNER_NAME = "pii"

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
_ID_CARD_RE = re.compile(
    r"(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)"
)
_BANK_CARD_RE = re.compile(r"(?<!\d)\d{13,19}(?!\d)")

#: GB 11643 身份证校验位权重与映射
_ID_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_ID_CHECK = "10X98765432"


def _id_card_checksum_ok(digits17: str, check: str) -> bool:
    total = sum(int(d) * w for d, w in zip(digits17, _ID_WEIGHTS, strict=True))
    return _ID_CHECK[total % 11] == check.upper()


def _luhn_ok(number: str) -> bool:
    digits = [int(ch) for ch in number]
    checksum = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _mask(value: str) -> str:
    """打码：保留前 3 后 2（邮箱保留首字符与域名）。"""
    if "@" in value:
        local, _, domain = value.partition("@")
        head = local[:2] if len(local) > 2 else local
        return f"{head}***@{domain}"
    if len(value) <= 5:
        return "*" * len(value)
    return f"{value[:3]}****{value[-2:]}"


def scan_pii(
    body: bytes | str | None,
    *,
    max_bytes: int | None = None,
) -> ScanResult:
    """扫描 PII：邮箱 / 手机号 / 身份证（含校验位）/ 银行卡（Luhn）。

    身份证优先于银行卡判定（18 位串不会再进银行卡通道）。
    """
    if not body:
        return ScanResult(scanner=SCANNER_NAME)
    text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body
    if max_bytes is not None and len(text) > max_bytes:
        text = text[:max_bytes]

    hits: list[ScanHit] = []
    counts = {"email": 0, "phone": 0, "id_card": 0, "bank_card": 0}

    for lineno, line in enumerate(text.splitlines(), start=1):
        for match in _EMAIL_RE.finditer(line):
            counts["email"] += 1
            hits.append(ScanHit(SCANNER_NAME, "email", _mask(match.group(0)), lineno, "邮箱地址"))
        for match in _PHONE_RE.finditer(line):
            counts["phone"] += 1
            hits.append(ScanHit(SCANNER_NAME, "phone", _mask(match.group(0)), lineno, "手机号"))

        bank_candidates: list[tuple[int, str]] = []
        for match in _BANK_CARD_RE.finditer(line):
            number = match.group(0)
            if len(set(number)) == 1:
                continue  # 全同数字
            bank_candidates.append((match.start(), number))
        id_spans: set[int] = set()
        for match in _ID_CARD_RE.finditer(line):
            value = match.group(0)
            if not _id_card_checksum_ok(value[:17], value[17]):
                continue
            id_spans.add(match.start())
            counts["id_card"] += 1
            hits.append(ScanHit(SCANNER_NAME, "id_card", _mask(value), lineno, "身份证号"))
        # 未被身份证认领的数字串再走银行卡（Luhn）
        for start, number in bank_candidates:
            if any(abs(start - s) < 3 for s in id_spans):
                continue
            if not _luhn_ok(number):
                continue
            counts["bank_card"] += 1
            hits.append(ScanHit(SCANNER_NAME, "bank_card", _mask(number), lineno, "银行卡号"))

    total = sum(counts.values())
    metrics: dict[str, float] = {k: float(v) for k, v in counts.items()}
    metrics["hits"] = float(total)
    return ScanResult(scanner=SCANNER_NAME, hits=tuple(hits), metrics=metrics)
