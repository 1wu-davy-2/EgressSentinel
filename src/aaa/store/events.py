"""审计事件数据模型（02 文档 §6 事件模型的 P1 子集）。

P1 阶段策略引擎（P3）尚未接入，故 ``verdict`` 为 ``unassessed``、
``process`` 为 ``None``（P2 进程归因接入后填充）、``matched_rules`` 为空。
"""

from __future__ import annotations

import os
import time
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class ProcessInfo(BaseModel):
    """归因到的进程信息（02 文档 §6 ``process``）。"""

    pid: int | None = None
    name: str | None = None
    exe: str | None = None
    cmdline: list[str] | None = None
    company: str | None = None
    profile: str | None = None


class Destination(BaseModel):
    """目标端点（02 文档 §6 ``destination``）。"""

    host: str
    ip: str | None = None
    port: int
    classification: str = "unknown"


class RequestInfo(BaseModel):
    """请求元数据（02 文档 §6 ``request``）。"""

    method: str
    path: str
    content_type: str | None = None
    size: int


class ResponseInfo(BaseModel):
    """响应元数据（02 文档 §6 未单列，P1 记录状态码与体量）。"""

    status_code: int
    size: int
    content_type: str | None = None


class EvidenceInfo(BaseModel):
    """证据文件信息（02 文档 §6 ``evidence``）。"""

    file: str | None = None
    sha256: str | None = None
    truncated: bool = False
    size: int = 0
    original_size: int = 0


class AuditEvent(BaseModel):
    """一条审计事件（02 文档 §6）。"""

    id: str
    ts: str
    mode: str
    verdict: str = "unassessed"
    risk_score: int = 0
    process: ProcessInfo | None = None
    destination: Destination
    request: RequestInfo
    response: ResponseInfo | None = None
    matched_rules: list[dict[str, Any]] = Field(default_factory=list)
    action_taken: str = "logged"
    evidence: EvidenceInfo | None = None
    policy_version: str | None = None
    error: str | None = None
    judge_note: dict[str, Any] | None = None
    """LLM 辅助判定结论（05 文档 W3/波次二 §3）：``JudgeVerdict`` 的 JSON 形态
    （status/is_violation/confidence/reason/category）。未判定为 ``None``；非 ok
    状态（不可用/预算用尽）也如实记录——**未取得有效结论不等于"无违规"**，
    消费方必须以 ``judge_note["status"] == "ok"`` 为采信前提。"""


def new_event_id(now: datetime | None = None) -> str:
    """生成 ``evt_`` 前缀、毫秒时间开头、随机尾部的可排序唯一 ID。

    形态对齐 02 文档 §6 示例（``evt_01J8Z...``）。
    """
    stamp = int((now or datetime.now()).timestamp() * 1000)
    return f"evt_{stamp:013d}{os.urandom(5).hex()}{time.monotonic_ns() % 10:01d}"
