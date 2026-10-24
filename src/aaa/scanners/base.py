"""扫描器共享类型：命中与结果（全部纯数据）。"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ScanHit:
    """一次内容命中（进事件 ``matched_rules[].evidence``，值必须打码）。"""

    scanner: str
    rule_id: str
    evidence: str
    """打码后的证据片段（如 ``AKIA****``，不含完整密钥，02 文档 D6）。"""
    line: int | None = None
    """命中所在行号（1 起，整文扫描时）。"""
    detail: str = ""
    """人类可读说明（如规则描述）。"""
    extra: Mapping[str, Any] = field(default_factory=dict)
    """附加结构化信息（如熵值、文件名、命中数）。"""

    def masked(self) -> dict[str, Any]:
        """事件里 ``matched_rules`` 条目的形态（不含明文）。"""
        return {
            "scanner": self.scanner,
            "rule_id": self.rule_id,
            "evidence": self.evidence,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class ScanResult:
    """单个扫描器对一份 body 的结果。"""

    scanner: str
    hits: tuple[ScanHit, ...] = ()
    metrics: Mapping[str, float] = field(default_factory=dict)
    """数值指标（如 ``code_likeness``、``hits``），供策略 match 条件引用。"""

    @property
    def hit_count(self) -> int:
        return len(self.hits)
