"""扫描器单测（03 文档 T3.3）：全部纯函数、无网络。"""

from __future__ import annotations

import pytest

from aaa.scanners import scan_code_leak, scan_pii, scan_secrets
from aaa.scanners.secrets import OFFICIAL_EXAMPLE_SECRETS, SECRET_RULES, rule_ids


def _luhn_number(length: int = 16) -> str:
    """构造一个 Luhn 校验通过的卡号。"""
    body = "6222" + "0" * (length - 5) + "1"  # 任意 body，最后算校验位
    digits = [int(c) for c in body]
    checksum = 0
    for i, d in enumerate(reversed(digits + [0])):  # 校验位先按 0 占位
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    check = (10 - checksum % 10) % 10
    return body + str(check)


def _id_card() -> str:
    body17 = "11010119900307753"
    weights = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
    check_map = "10X98765432"
    total = sum(int(d) * w for d, w in zip(body17, weights, strict=True))
    return body17 + check_map[total % 11]


# --------------------------------------------------------------------- secrets


def test_secret_rule_count_at_least_40() -> None:
    """02 文档 D4：gitleaks 核心 ~40 条移植。"""
    assert len(SECRET_RULES) >= 40
    ids = rule_ids()
    assert len(ids) == len(set(ids)), "规则 id 不得重复"


def test_detects_aws_access_key() -> None:
    result = scan_secrets("key=AKIAQ2FZV3TQPE8KX9YZ\n")
    ids = {h.rule_id for h in result.hits}
    assert "aws-access-token" in ids
    hit = next(h for h in result.hits if h.rule_id == "aws-access-token")
    assert hit.evidence.startswith("AKIA")  # 打码保留前缀
    assert "Q2FZV3TQPE8KX9YZ" not in hit.evidence  # 不含完整密钥


def test_official_example_keys_allowlisted() -> None:
    """官方示例密钥默认白名单（02 文档 R8）。"""
    text = "\n".join(sorted(OFFICIAL_EXAMPLE_SECRETS)) + "\nAKIAIOSFODNN7EXAMPLE\n"
    result = scan_secrets(text)
    assert result.hit_count == 0


def test_placeholder_words_allowlisted() -> None:
    result = scan_secrets("token = FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n")
    assert result.hit_count == 0


def test_detects_openai_and_anthropic_keys() -> None:
    text = (
        "sk-aaaaaaaaaaaaaaaaaaaaT3BlbkFJbbbbbbbbbbbbbbbbbbbb\n"
        "sk-ant-api03-Zx9yWq7vUt5rOp3nMl1kJh8Gf6Dd4Sa2BcQeNrTm\n"
    )
    ids = {h.rule_id for h in scan_secrets(text).hits}
    assert "openai-api-key" in ids
    assert "anthropic-api-key" in ids


def test_detects_github_tokens() -> None:
    text = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8" + "\n"  # 36 chars
    assert "github-pat" in {h.rule_id for h in scan_secrets(text).hits}
    fine = "github_pat_" + "a" * 22 + "_" + "b" * 59  # 82 chars after prefix
    assert "github-fine-grained-pat" in {h.rule_id for h in scan_secrets(fine).hits}


def test_detects_private_key_header() -> None:
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----\n"
    assert "private-key-header" in {h.rule_id for h in scan_secrets(text).hits}


def test_detects_jwt() -> None:
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    )
    assert "jwt" in {h.rule_id for h in scan_secrets(f"Bearer {jwt}").hits}


def test_low_entropy_generic_assignment_not_flagged() -> None:
    """generic-api-key 熵守卫：低熵赋值不报。"""
    assert scan_secrets('api_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n').hit_count == 0


def test_high_entropy_generic_assignment_flagged() -> None:
    secret = "Zm9vYmFyYmF6cXV1eGNvcmdlZWllaGljax0="  # 高熵
    result = scan_secrets(f"api_key = {secret}\n")
    assert "generic-api-key" in {h.rule_id for h in result.hits}


def test_keywords_guard_requires_keyword_in_line() -> None:
    """带 keywords 的规则：关键词不在行内则不匹配。"""
    # azure storage AccountKey 形态但没有 "accountkey" 关键词（走 generic 也不该撞）
    assert scan_secrets("data=AccountKey=[A-Za-z0-9+/]{86}==\n").hit_count == 0


def test_secrets_empty_and_bytes_input() -> None:
    assert scan_secrets(None).hit_count == 0
    assert scan_secrets(b"").hit_count == 0
    assert scan_secrets(b"AKIAQ2FZV3TQPE8KX9YZ").hit_count == 1
    # max_bytes 截断
    assert scan_secrets("AKIAQ2FZV3TQPE8KX9YZ", max_bytes=4).hit_count == 0


def test_same_rule_same_line_deduplicated() -> None:
    result = scan_secrets("AKIAQ2FZV3TQPE8KX9YZ AKIAQ2FZV3TQPE8KX9YZ\n")
    aws_hits = [h for h in result.hits if h.rule_id == "aws-access-token"]
    assert len(aws_hits) == 1


# ------------------------------------------------------------------------- PII


def test_pii_email_and_phone() -> None:
    result = scan_pii("contact bob.smith@example.com or call 13812345678")
    ids = {h.rule_id for h in result.hits}
    assert ids == {"email", "phone"}
    assert result.metrics["email"] == 1
    assert result.metrics["phone"] == 1
    assert result.metrics["hits"] == 2


def test_pii_id_card_with_checksum() -> None:
    valid = _id_card()
    result = scan_pii(f"身份证：{valid}")
    assert "id_card" in {h.rule_id for h in result.hits}
    # 校验位错误的不报
    bad = valid[:-1] + ("0" if valid[-1] != "0" else "1")
    assert scan_pii(f"身份证：{bad}").hit_count == 0


def test_pii_bank_card_luhn() -> None:
    number = _luhn_number()
    result = scan_pii(f"card: {number}")
    assert "bank_card" in {h.rule_id for h in result.hits}
    # Luhn 不过不报
    digits = str(int(number) + 1).zfill(len(number))
    assert scan_pii(f"card: {digits}").hit_count == 0


def test_pii_hits_gt_metric_for_policy() -> None:
    """策略 hits_gt 阈值依赖 metrics['hits']。"""
    text = " ".join(f"user{i}@corp{i}.example.com" for i in range(15))
    result = scan_pii(text)
    assert result.metrics["hits"] == 15


def test_pii_empty_input() -> None:
    assert scan_pii(None).hit_count == 0
    assert scan_pii("").hit_count == 0


def test_pii_masking() -> None:
    hit = scan_pii("call 13812345678").hits[0]
    assert hit.evidence == "138****78"


# ------------------------------------------------------------------- code_leak


def test_code_leak_local_paths() -> None:
    text = r"see C:\Users\alice\secret\project\main.py and /home/bob/.ssh/id_rsa"
    result = scan_code_leak(text)
    ids = {h.rule_id for h in result.hits}
    assert "windows-local-path" in ids
    assert "posix-local-path" in ids
    assert result.metrics["local_paths"] == 2


def test_code_leak_code_likeness_high() -> None:
    code = "\n".join([f"import os\ndef func_{i}(x):\n    return x + {i}" for i in range(40)])
    result = scan_code_leak(code)
    assert result.metrics["code_likeness"] > 0.6


def test_code_leak_code_likeness_low_for_prose() -> None:
    prose = "\n".join("just a normal sentence about things" for _ in range(40))
    result = scan_code_leak(prose)
    assert result.metrics["code_likeness"] < 0.2


def test_code_leak_multipart_file_segment() -> None:
    text = (
        '--boundary\r\nContent-Disposition: form-data; name="file"; filename="report.pdf"\r\n'
        "Content-Type: application/pdf\r\n\r\n%PDF-1.4\r\n--boundary--\r\n"
    )
    result = scan_code_leak(text)
    ids = {h.rule_id for h in result.hits}
    assert "multipart-file-upload" in ids


def test_code_leak_base64_bulk_block() -> None:
    blob = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ei" * 4
    result = scan_code_leak(f"data:image/png;base64,{blob}")
    assert "base64-bulk-block" in {h.rule_id for h in result.hits}


def test_code_leak_empty_input() -> None:
    assert scan_code_leak(None).hit_count == 0
    assert scan_code_leak(b"").metrics["code_likeness"] == 0


@pytest.mark.parametrize(
    "scanner_fn", [scan_secrets, scan_pii, scan_code_leak], ids=["secrets", "pii", "code_leak"]
)
def test_scanners_accept_bytes_and_str(scanner_fn) -> None:  # type: ignore[no-untyped-def]
    """bytes 与 str 输入等价（addon 传 bytes）。"""
    a = scanner_fn("AKIAQ2FZV3TQPE8KX9YZ hello@x.com")
    b = scanner_fn(b"AKIAQ2FZV3TQPE8KX9YZ hello@x.com")
    assert a.metrics == b.metrics
    assert {h.rule_id for h in a.hits} == {h.rule_id for h in b.hits}
