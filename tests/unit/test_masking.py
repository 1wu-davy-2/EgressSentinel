"""body 脱敏单测（03 文档 T5.1：命中的密钥打码；?reveal=1 显式解锁）。"""

from __future__ import annotations

from aaa.scanners.secrets import OFFICIAL_EXAMPLE_SECRETS, scan_secrets
from aaa.web.masking import MASK_CLOSE, MASK_OPEN, mask_secret_spans

SECRET = "AKIAQ2FZV3TQPE8KX9YZ"  # 假 AWS key（非官方示例）
TEXT = f'{{"model": "gpt-x", "api_key": "{SECRET}", "note": "hello"}}'


def test_mask_replaces_secret_and_keeps_rest() -> None:
    masked = mask_secret_spans(TEXT)
    assert SECRET not in masked.text, "明文密钥不得出现在脱敏结果"
    assert MASK_OPEN in masked.text and MASK_CLOSE in masked.text
    assert "aws-access-token" in masked.hits and masked.hits["aws-access-token"] == 1
    assert '"note": "hello"' in masked.text, "非密钥内容保持原样"
    assert masked.original_size == len(TEXT)
    assert masked.truncated is False


def test_mask_consistent_with_scanner_verdict() -> None:
    """打码片段与 scan_secrets 命中同一批规则（同一匹配核心）。"""
    masked = mask_secret_spans(TEXT)
    scanner_rules = {h.rule_id for h in scan_secrets(TEXT).hits}
    assert set(masked.hits) == scanner_rules


def test_allowlisted_examples_not_masked() -> None:
    """官方示例密钥（allowlist）不打码（与扫描器口径一致）。"""
    text = f'{{"key": "{next(iter(OFFICIAL_EXAMPLE_SECRETS))}"}}'
    masked = mask_secret_spans(text)
    assert masked.hits == {}
    assert masked.text == text


def test_overlapping_matches_merge_into_one_span() -> None:
    """generic-api-key 与具体规则重叠：合并为一个打码区间，各规则分别计数。"""
    text = f'{{"api_key": "{SECRET}"}}'
    masked = mask_secret_spans(text)
    assert masked.hits.get("aws-access-token") == 1
    assert masked.hits.get("generic-api-key") == 1
    assert masked.text.count(MASK_OPEN) == 1, "重叠命中合并为一个打码区间"
    assert SECRET not in masked.text


def test_private_key_line_masked() -> None:
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowABC==\n-----END RSA PRIVATE KEY-----"
    masked = mask_secret_spans(text)
    assert masked.hits.get("private-key-header") == 1
    assert "-----BEGIN RSA PRIVATE KEY-----" not in masked.text


def test_no_hits_returns_original_text() -> None:
    text = "nothing sensitive here"
    masked = mask_secret_spans(text)
    assert masked.hits == {}
    assert masked.text == text
