"""事件 body 的默认脱敏（02 文档 D6：UI 默认只展示脱敏摘要，查看原文需显式 ``?reveal=1``）。

基于 secrets 扫描器同一匹配核心（``iter_secret_spans``：规则 + allowlist + 熵阈值）
定位明文片段，替换为 ``⟦规则id|打码⟧`` 形态——与事件 ``matched_rules[].evidence``
一致的打码约定（``mask_secret`` 保留首尾少量字符）。
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from aaa.scanners.secrets import SECRET_RULES, SecretRule, iter_secret_spans, mask_secret

#: 脱敏替换的包裹符（UI 与 API 文档可据此识别已脱敏区间）
MASK_OPEN = "⟦"
MASK_CLOSE = "⟧"


@dataclass
class MaskedBody:
    """脱敏结果。"""

    text: str
    """脱敏后的文本（原始文本中疑似密钥片段被替换）。"""
    original_size: int
    """原始文本字符数。"""
    hits: dict[str, int] = field(default_factory=dict)
    """``{rule_id: 打码次数}``。"""
    truncated: bool = False
    """输入是否因展示上限被截断（语义与证据文件的 truncated 一致）。"""


def mask_secret_spans(
    text: str,
    *,
    rules: tuple[SecretRule, ...] = SECRET_RULES,
    truncated: bool = False,
) -> MaskedBody:
    """把 ``text`` 中的疑似密钥片段替换为打码标记（保留其余内容原样）。

    重叠片段（如 generic 规则与具体规则同时命中）合并为一个打码区间，各规则分别计数。
    """
    hits: dict[str, int] = {}
    parts: list[str] = []
    pos = 0
    covered_until = -1
    for rule, _lineno, start, end in sorted(
        _dedupe(iter_secret_spans(text, rules=rules)), key=lambda s: (s[2], s[3])
    ):
        if start < covered_until:
            # 与已打码区间重叠：合并区间，规则单独计数
            covered_until = max(covered_until, end)
            hits[rule.id] = hits.get(rule.id, 0) + 1
            continue
        parts.append(text[pos:start])
        parts.append(f"{MASK_OPEN}{rule.id}|{mask_secret(text[start:end])}{MASK_CLOSE}")
        covered_until = end
        pos = end
        hits[rule.id] = hits.get(rule.id, 0) + 1
    parts.append(text[pos:])
    return MaskedBody(text="".join(parts), original_size=len(text), hits=hits, truncated=truncated)


def _dedupe(spans: Iterable[tuple[SecretRule, int, int, int]]):  # type: ignore[no-untyped-def]
    """同一行同一规则只保留首个片段（与 scan_secrets 的去重语义一致）。"""
    seen: set[tuple[str, int]] = set()
    for rule, lineno, start, end in spans:
        key = (rule.id, lineno)
        if key in seen:
            continue
        seen.add(key)
        yield rule, lineno, start, end


__all__ = ["MASK_CLOSE", "MASK_OPEN", "MaskedBody", "mask_secret_spans"]
