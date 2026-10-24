"""判定结果模型与动作等级（02 文档 D4：allow < alert < confirm < block）。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from aaa.policy.model import action_rank

ALLOW = "allow"
ALERT = "alert"
CONFIRM = "confirm"
BLOCK = "block"

#: 维度名（事件 matched_rules[].dim）
DIM_DOMAIN = "domain"
DIM_PROCESS = "process"
DIM_CONTENT = "content"
DIM_VOLUME = "volume"
DIM_TIME_WINDOW = "time_window"


@dataclass(frozen=True)
class MatchedRule:
    """一条命中的策略规则（事件 ``matched_rules[]``，值已打码）。"""

    id: str
    dim: str
    action: str
    weight: int
    evidence: str = ""
    detail: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """事件 JSON 形态（02 文档 §6：id/dim/evidence/weight）。"""
        data: dict[str, Any] = {
            "id": self.id,
            "dim": self.dim,
            "action": self.action,
            "weight": self.weight,
        }
        if self.evidence:
            data["evidence"] = self.evidence
        if self.detail:
            data["detail"] = self.detail
        if self.extra:
            data["extra"] = self.extra
        return data


@dataclass(frozen=True)
class EvaluationResult:
    """一次五维求值结果。"""

    verdict: str
    risk_score: int
    matched: tuple[MatchedRule, ...] = ()
    error: str | None = None
    """引擎异常描述（fail_open 时放行并记 error 事件，02 文档 D5）。"""

    @property
    def should_block(self) -> bool:
        return self.verdict == BLOCK

    @classmethod
    def from_matched(cls, matched: list[MatchedRule]) -> EvaluationResult:
        """按最高动作 + 权重和合成（02 文档 D4）。"""
        if not matched:
            return cls(verdict=ALLOW, risk_score=0)
        verdict = max(matched, key=lambda m: action_rank(m.action)).action
        risk = min(100, sum(m.weight for m in matched))
        return cls(verdict=verdict, risk_score=risk, matched=tuple(matched))
