"""策略引擎（02 文档 §2 ``aaa.engine``）：五维求值、判定、阻断执行。"""

from aaa.engine.pipeline import AuditPipeline, EvaluationInput, ScannerFn
from aaa.engine.verdict import (
    ALERT,
    ALLOW,
    BLOCK,
    CONFIRM,
    DIM_CONTENT,
    DIM_DOMAIN,
    DIM_PROCESS,
    DIM_TIME_WINDOW,
    DIM_VOLUME,
    EvaluationResult,
    MatchedRule,
)

__all__ = [
    "ALLOW",
    "ALERT",
    "BLOCK",
    "CONFIRM",
    "DIM_CONTENT",
    "DIM_DOMAIN",
    "DIM_PROCESS",
    "DIM_TIME_WINDOW",
    "DIM_VOLUME",
    "AuditPipeline",
    "EvaluationInput",
    "EvaluationResult",
    "MatchedRule",
    "ScannerFn",
]
