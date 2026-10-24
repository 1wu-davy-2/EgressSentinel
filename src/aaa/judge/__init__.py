"""LLM 辅助判定子模块（05 安全深化计划 波次一 W3）。

红线：``LLMJudge.judge`` 任何异常都收敛为 ``status="unavailable"`` 结论，绝不影响
审计主流程；API key 只读环境变量 ``AAA_JUDGE_API_KEY`` 且不落盘；判定默认关闭
（``JudgeConfig.enabled=False``）。导出干净 API 供波次二集成（``policy.judge`` 段 →
``LLMJudge``；``aaa run`` 启动概要用 ``today_usage``/``JudgeConfig``）。
"""

from __future__ import annotations

from aaa.judge.llm import (
    DEFAULT_JUDGE_USAGE_FILENAME,
    DEFAULT_MAX_EVENTS_PER_DAY,
    DEFAULT_TIMEOUT_SECONDS,
    JUDGE_API_KEY_ENV,
    REASON_MAX_CHARS,
    SYSTEM_PROMPT,
    JudgeClient,
    JudgeClientFactory,
    JudgeConfig,
    JudgeUsage,
    JudgeUsageStore,
    JudgeVerdict,
    LLMJudge,
    VerdictStatus,
    default_judge_client_factory,
)

__all__ = [
    "DEFAULT_JUDGE_USAGE_FILENAME",
    "DEFAULT_MAX_EVENTS_PER_DAY",
    "DEFAULT_TIMEOUT_SECONDS",
    "JUDGE_API_KEY_ENV",
    "REASON_MAX_CHARS",
    "SYSTEM_PROMPT",
    "JudgeClient",
    "JudgeClientFactory",
    "JudgeConfig",
    "JudgeUsage",
    "JudgeUsageStore",
    "JudgeVerdict",
    "LLMJudge",
    "VerdictStatus",
    "default_judge_client_factory",
]
