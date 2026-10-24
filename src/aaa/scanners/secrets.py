"""密钥扫描器：gitleaks 核心 ~40 条规则移植（regex + 熵 + allowlist）。

- 规则来源：gitleaks（MIT 许可，02 文档 §7 合规）核心规则人工移植为常量表；
- allowlist：官方示例密钥（``AKIAIOSFODNN7EXAMPLE`` 等）与占位/测试词默认白名单
  （02 文档 R8：密钥规则误报治理）；
- 熵：高熵要求只用于关键词守卫类通用规则（对齐 gitleaks generic-api-key 思路）；
- 纯函数、无网络调用。
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterator
from dataclasses import dataclass

from aaa.scanners.base import ScanHit, ScanResult

SCANNER_NAME = "secrets"


@dataclass(frozen=True)
class SecretRule:
    """一条密钥检测规则（gitleaks 移植）。"""

    id: str
    description: str
    pattern: re.Pattern[str]
    entropy: float = 0.0
    """>0 时要求匹配串香农熵不低于该值（bit/字符）。"""
    keywords: tuple[str, ...] = ()
    """非空时：所在行包含任一关键词才尝试匹配（gitleaks keywords 语义）。"""
    allow_entire_line: bool = False
    """供跨行模式（如私钥头）使用：按整块文本匹配而非逐行。"""


# ---------------------------------------------------------------- 规则清单

_R = re.compile

SECRET_RULES: tuple[SecretRule, ...] = (
    # --- AWS ---
    SecretRule(
        "aws-access-token",
        "AWS Access Key（AKIA/ASIA 等）",
        _R(r"\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b"),
    ),
    SecretRule(
        "aws-secret-token",
        "AWS 临时凭证（FpYA.../qz...）",
        _R(r"\b(?:FpYA[A-Za-z0-9+/]{40,50}|qz[A-Za-z0-9]{40,50})\b"),
    ),
    SecretRule(
        "aws-secret-assignment",
        "AWS secret access key 赋值",
        _R(r"(?i)aws.{0,20}?['\"]?[0-9a-zA-Z/+]{40}['\"]?"),
        keywords=("aws",),
    ),
    # --- GCP / Google ---
    SecretRule(
        "gcp-api-key",
        "Google/GCP API Key",
        _R(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    ),
    SecretRule(
        "google-oauth-client-id",
        "Google OAuth Client ID",
        _R(r"\b[0-9]+-[0-9a-z_]{32}\.apps\.googleusercontent\.com\b"),
    ),
    SecretRule(
        "google-oauth-refresh-token",
        "Google OAuth Refresh Token",
        _R(r"\b1//[0-9a-z_-]{33}\b"),
    ),
    SecretRule(
        "gcp-service-account",
        "GCP 服务账号 JSON 私钥",
        _R(r'"type"\s*:\s*"service_account"'),
        allow_entire_line=False,
    ),
    # --- Azure / Microsoft ---
    SecretRule(
        "azure-storage-account-key",
        "Azure Storage AccountKey",
        _R(r"AccountKey=[A-Za-z0-9+/]{86,88}={0,2}"),
        keywords=("accountkey",),
    ),
    SecretRule(
        "azure-ad-client-secret",
        "Azure AD Client Secret",
        _R(r"(?i)(?:client_?secret|CLIENT_SECRET)['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9~._\-]{27,}"),
        keywords=("client_secret", "clientsecret"),
    ),
    # --- OpenAI / Anthropic / AI 端点 ---
    SecretRule(
        "openai-api-key",
        "OpenAI API Key（sk-…T3BlbkFJ…）",
        _R(r"\bsk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}\b"),
    ),
    SecretRule(
        "openai-project-key",
        "OpenAI 项目 API Key（sk-proj-…）",
        _R(r"\bsk-proj-[A-Za-z0-9_-]{40,}\b"),
    ),
    SecretRule(
        "anthropic-api-key",
        "Anthropic API Key（sk-ant-…）",
        _R(r"\bsk-ant-[A-Za-z0-9_-]{24,}\b"),
    ),
    SecretRule(
        "huggingface-token",
        "Hugging Face Token（hf_…）",
        _R(r"\bhf_[a-zA-Z0-9]{34}\b"),
    ),
    SecretRule(
        "deepseek-api-key",
        "DeepSeek API Key 赋值",
        _R(r"(?i)deepseek.{0,20}['\"]?sk-[a-zA-Z0-9]{24,}['\"]?"),
        keywords=("deepseek",),
    ),
    SecretRule(
        "moonshot-api-key",
        "Moonshot/Kimi API Key 赋值",
        _R(r"(?i)moonshot.{0,30}['\"]?sk-[a-zA-Z0-9]{24,}['\"]?"),
        keywords=("moonshot", "kimi"),
    ),
    # --- 代码托管 ---
    SecretRule(
        "github-pat",
        "GitHub Personal Access Token（ghp_）",
        _R(r"\bghp_[0-9a-zA-Z]{36}\b"),
    ),
    SecretRule(
        "github-oauth",
        "GitHub OAuth Token（gho_）",
        _R(r"\bgho_[0-9a-zA-Z]{36}\b"),
    ),
    SecretRule(
        "github-app-token",
        "GitHub App/User-to-server Token（ghu_/ghs_）",
        _R(r"\bgh[us]_[0-9a-zA-Z]{36}\b"),
    ),
    SecretRule(
        "github-fine-grained-pat",
        "GitHub Fine-grained PAT（github_pat_）",
        _R(r"\bgithub_pat_[0-9a-zA-Z_]{82}\b"),
    ),
    SecretRule(
        "gitlab-pat",
        "GitLab Personal Access Token（glpat-）",
        _R(r"\bglpat-[0-9a-zA-Z\-_]{20}\b"),
    ),
    SecretRule(
        "gitlab-runner-token",
        "GitLab Runner Token（glrt-）",
        _R(r"\bglrt-[0-9a-zA-Z_-]{20,}\b"),
    ),
    # --- 消息/协作 ---
    SecretRule(
        "slack-bot-token",
        "Slack Token（xox[baprs]-…）",
        _R(r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b"),
    ),
    SecretRule(
        "slack-webhook-url",
        "Slack Webhook URL",
        _R(r"hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9]+"),
    ),
    SecretRule(
        "discord-bot-token",
        "Discord Bot Token",
        _R(r"\b[MNO][a-zA-Z\d_-]{23,32}\.[a-zA-Z\d_-]{6}\.[a-zA-Z\d_-]{27}\b"),
    ),
    SecretRule(
        "telegram-bot-token",
        "Telegram Bot Token",
        _R(r"\b[0-9]{8,10}:AA[0-9A-Za-z_-]{33}\b"),
    ),
    # --- 支付/云服务 ---
    SecretRule(
        "stripe-secret-key",
        "Stripe Secret Key（sk_live_）",
        _R(r"\b[sr]k_live_[0-9a-zA-Z]{24}\b"),
    ),
    SecretRule(
        "stripe-publishable-key",
        "Stripe Publishable Key（pk_live_）",
        _R(r"\bpk_live_[0-9a-zA-Z]{24}\b"),
    ),
    SecretRule(
        "twilio-api-key",
        "Twilio API Key（SK+32hex）",
        _R(r"\bSK[0-9a-fA-F]{32}\b"),
    ),
    SecretRule(
        "sendgrid-api-token",
        "SendGrid API Token（SG.…）",
        _R(r"\bSG\.[a-zA-Z0-9_-]{16,32}\.[a-zA-Z0-9_-]{16,64}\b"),
    ),
    SecretRule(
        "mailgun-signing-key",
        "Mailgun Signing Key（key-…）",
        _R(r"\bkey-[0-9a-zA-Z]{32}\b"),
        keywords=("mailgun",),
    ),
    SecretRule(
        "alibaba-access-key",
        "阿里云 AccessKey（LTAI…）",
        _R(r"\bLTAI[a-zA-Z0-9]{12,20}\b"),
    ),
    SecretRule(
        "tencent-secret-id",
        "腾讯云 SecretId（AKID…）",
        _R(r"\bAKID[0-9A-Za-z]{13,20}\b"),
    ),
    SecretRule(
        "npm-access-token",
        "npm Access Token（npm_）",
        _R(r"\bnpm_[0-9a-zA-Z]{36}\b"),
    ),
    SecretRule(
        "pypi-upload-token",
        "PyPI Upload Token（pypi-…）",
        _R(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]+\b"),
    ),
    SecretRule(
        "postman-api-token",
        "Postman API Token（PMAK-）",
        _R(r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b"),
    ),
    SecretRule(
        "databricks-api-token",
        "Databricks API Token（dapi…）",
        _R(r"\bdapi[0-9a-f]{32}\b"),
    ),
    SecretRule(
        "grafana-service-account-token",
        "Grafana Service Account Token（glsa_）",
        _R(r"\bglsa_[A-Za-z0-9]{32}\b"),
    ),
    SecretRule(
        "terraform-cloud-token",
        "Terraform Cloud/Enterprise Token（atlasv1）",
        _R(r"\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9]{60,70}\b"),
    ),
    SecretRule(
        "shopify-token",
        "Shopify Token（shpat_/shpss_/shpca_）",
        _R(r"\bshp(?:at|ss|ca)_[a-fA-F0-9]{40}\b"),
    ),
    SecretRule(
        "vercel-token",
        "Vercel Token（vercel_）",
        _R(r"\bvercel_[a-z0-9]{24}\b"),
    ),
    # --- 结构化/通用 ---
    SecretRule(
        "private-key-header",
        "私钥文件头（BEGIN … PRIVATE KEY）",
        _R(
            r"-----BEGIN (?:[A-Z0-9]+ ?)*PRIVATE KEY(?: BLOCK)?-----",
        ),
        allow_entire_line=True,
    ),
    SecretRule(
        "jwt",
        "JWT（三段 base64url）",
        _R(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"),
        entropy=3.0,
    ),
    SecretRule(
        "generic-api-key",
        "通用 API key/secret/token 关键词赋值（熵守卫）",
        _R(
            r"(?i)(?:api[_-]?key|apikey|secret|token|auth|credential|passwd|password)"
            r"['\"]?\s*(?:[:=]|=>)\s*['\"]?[A-Za-z0-9+/_\-=]{16,}"
        ),
        entropy=3.7,
    ),
)

assert len(SECRET_RULES) >= 40, "设计要求 ~40 条规则（02 文档 D4）"

# ------------------------------------------------------------------ allowlist

#: 官方文档示例密钥（默认白名单，02 文档 R8）
OFFICIAL_EXAMPLE_SECRETS: frozenset[str] = frozenset(
    {
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEYEXAMPLE",
        "sk-proj-EXAMPLESECRETKEY0123456789",
        "sk-ant-api03-EXAMPLE",
    }
)

#: 占位/示例词：匹配串包含即白名单（对齐 gitleaks 全局 allowlist 思路）
_PLACEHOLDER_RE = re.compile(
    r"(?i)(example|sample|fake|dummy|placeholder|redacted|not_?a[_-]?real|"
    r"your[_-]?(?:api[_-]?key|token|secret|key)|xxxxx?|0000+|test[_-]?key|1234567890)"
)
#: 全同字符（AAAAAAAAAA…）
_ALL_SAME_RE = re.compile(r"^(.)\1+$")
#: 纯递增/递减序列片段
_SEQUENTIAL_RE = re.compile(r"(?:0123456789|abcdefghijklmnopqrstuvwxyz)")


def _is_allowlisted(secret: str) -> bool:
    """官方示例/占位符/平凡串默认白名单。"""
    if secret in OFFICIAL_EXAMPLE_SECRETS:
        return True
    if _PLACEHOLDER_RE.search(secret):
        return True
    if _ALL_SAME_RE.match(secret):
        return True
    if _SEQUENTIAL_RE.search(secret.lower()):
        return True
    return False


def shannon_entropy(value: str) -> float:
    """字符串香农熵（bit/字符）。"""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def mask_secret(secret: str, *, head: int = 4, tail: int = 2) -> str:
    """打码：保留首尾少量字符（evidence 字段永不携带完整密钥，02 文档 D6）。"""
    if len(secret) <= head + tail:
        return "*" * len(secret)
    return f"{secret[:head]}****{secret[-tail:]}"


def scan_secrets(
    body: bytes | str | None,
    *,
    max_bytes: int | None = None,
    rules: tuple[SecretRule, ...] = SECRET_RULES,
) -> ScanResult:
    """扫描文本中的疑似密钥。逐行匹配 + 关键词守卫 + allowlist + 熵阈值。"""
    if not body:
        return ScanResult(scanner=SCANNER_NAME)
    text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body
    if max_bytes is not None and len(text) > max_bytes:
        text = text[:max_bytes]
    hits: list[ScanHit] = []
    seen: set[tuple[str, int]] = set()
    for rule, lineno, start, end in iter_secret_spans(text, rules=rules):
        key = (rule.id, lineno)
        if key in seen:
            continue
        seen.add(key)
        hits.append(
            ScanHit(
                scanner=SCANNER_NAME,
                rule_id=rule.id,
                evidence=mask_secret(text[start:end].strip()),
                line=lineno,
                detail=rule.description,
            )
        )
    metrics: dict[str, float] = {"hits": float(len(hits))}
    return ScanResult(scanner=SCANNER_NAME, hits=tuple(hits), metrics=metrics)


def iter_secret_spans(
    text: str,
    *,
    rules: tuple[SecretRule, ...] = SECRET_RULES,
) -> Iterator[tuple[SecretRule, int, int, int]]:
    """疑似密钥的**明文片段**位置：``(rule, lineno, start, end)``（web 脱敏用）。

    与 ``scan_secrets`` 同一匹配核心（关键词守卫 + allowlist + 熵阈值）；
    同一行同一规则可能产出多个片段，由调用方决定去重（scan_secrets 每行每规则
    取第一条，与历史行为一致）。``allow_entire_line`` 规则（私钥头）片段为整行。
    """
    offset = 0
    for lineno, line in enumerate(text.splitlines(), start=1):
        start_of_line = text.find(line, offset)
        if start_of_line < 0:  # 理论不可达（splitlines 产物必然是子串）；防御性兜底
            start_of_line = offset
        offset = start_of_line + len(line)
        lowered = line.lower()
        for rule in rules:
            if rule.keywords and not any(k in lowered for k in rule.keywords):
                continue
            if rule.allow_entire_line:
                if rule.pattern.search(line):
                    yield rule, lineno, start_of_line, start_of_line + len(line)
                continue
            for match in rule.pattern.finditer(line):
                secret = match.group(0)
                if _is_allowlisted(secret):
                    continue
                if rule.entropy > 0 and shannon_entropy(secret) < rule.entropy:
                    continue
                yield rule, lineno, start_of_line + match.start(), start_of_line + match.end()


def rule_ids() -> tuple[str, ...]:
    """内置规则 id 列表（lint/自检用）。"""
    return tuple(rule.id for rule in SECRET_RULES)
