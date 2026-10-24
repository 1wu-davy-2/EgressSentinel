"""本地 Web 面板 API（03 文档 T5.1/T5.3，02 文档 G6/D6）。

- 只读事件查询：分页 + 过滤（verdict/pid/host/dim/时间）；
- 事件详情：body 默认脱敏（命中的密钥打码）；``?reveal=1`` 显式解锁并记审计日志；
- 聚合统计 / 策略 / 单事件与列表导出（JSON/CSV）；
- confirm 交互流：``POST /api/decisions``（allow 一次性 / deny 缓存升级 block，TTL 可配）。

安全边界：面板只允许本地回环监听（``assert_loopback`` 供 ``aaa web`` 启动前校验）；
所有写操作仅限本地决策与审计日志，不改系统设置。
"""

from __future__ import annotations

import csv
import io
import logging
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field

from aaa.policy.loader import PolicyLoader
from aaa.store.db import DbEventStore, parse_since
from aaa.store.decisions import DECISION_ALLOW, DECISION_DENY, DecisionStore, decision_key
from aaa.store.events import AuditEvent
from aaa.web.masking import mask_secret_spans
from aaa.web.views import STATIC_DIR, index_page

logger = logging.getLogger(__name__)

#: 事件列表分页上限
MAX_PAGE_LIMIT = 500

#: 详情 body 展示上限（字符；证据文件本身已按 256KB 截断）
MAX_BODY_DISPLAY = 262144


def assert_loopback(host: str) -> None:
    """面板监听地址必须是本地回环（03 文档 T5.1）。非法地址抛 ``ValueError``。"""
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError(f"Web 面板只允许本地回环监听（127.0.0.1/localhost/::1），收到 {host!r}")


class DecisionRequest(BaseModel):
    """``POST /api/decisions`` 请求体（T5.3）。"""

    event_id: str = Field(min_length=1)
    decision: Literal["allow", "deny"]
    ttl_seconds: int | None = Field(default=None, gt=0)


def create_app(
    *,
    db: DbEventStore,
    evidence_dir: Path,
    policy_loader: PolicyLoader | None = None,
    decisions: DecisionStore | None = None,
    data_dir: Path | None = None,
) -> FastAPI:
    """构建面板应用。依赖注入式构造（单测用临时目录，不依赖真实运行数据）。"""
    app = FastAPI(title="AI-AGENT-AUDIT panel", docs_url=None, redoc_url=None)
    state: dict[str, Any] = {
        "db": db,
        "evidence_dir": evidence_dir,
        "policy_loader": policy_loader,
        "decisions": decisions,
        "data_dir": data_dir,
    }

    # ------------------------------------------------------------- 事件列表

    @app.get("/api/events")
    def list_events(
        verdict: str | None = None,
        pid: int | None = None,
        host: str | None = None,
        dim: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = Query(default=50, ge=1, le=MAX_PAGE_LIMIT),
        offset: int = Query(default=0, ge=0),
    ) -> dict[str, Any]:
        try:
            since_dt = parse_since(since)
            until_dt = parse_since(until)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        store: DbEventStore = state["db"]
        events, total = store.query(
            verdict=verdict,
            pid=pid,
            host=host,
            dim=dim,
            since=since_dt,
            until=until_dt,
            limit=limit,
            offset=offset,
        )
        decision_map = store.decisions_for([event.id for event in events])
        items = [{**event.model_dump(), **decision_map.get(event.id, {})} for event in events]
        return {"total": total, "limit": limit, "offset": offset, "items": items}

    # ------------------------------------------------------------- 事件详情
    # 注意：``/api/events/export``（列表导出）必须先于 ``/api/events/{event_id}`` 注册，
    # 否则 "export" 会被当作 event_id 匹配。

    @app.get("/api/events/export")
    def export_events(
        format: Literal["json", "csv"] = "json",
        verdict: str | None = None,
        pid: int | None = None,
        host: str | None = None,
        dim: str | None = None,
        since: str | None = None,
        until: str | None = None,
    ) -> Response:
        """按当前过滤条件导出（T5.2 前端导出按钮；上限 5000 条防误全量）。"""
        try:
            since_dt = parse_since(since)
            until_dt = parse_since(until)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        store: DbEventStore = state["db"]
        events, total = store.query(
            verdict=verdict,
            pid=pid,
            host=host,
            dim=dim,
            since=since_dt,
            until=until_dt,
            limit=5000,
            offset=0,
        )
        if format == "csv":
            csv_text = _events_to_csv([(event, {}) for event in events])
            return PlainTextResponse(
                csv_text,
                media_type="text/csv; charset=utf-8",
                headers={"Content-Disposition": 'attachment; filename="aaa-events.csv"'},
            )
        return JSONResponse(
            {"total": total, "exported": len(events), "items": [e.model_dump() for e in events]},
            headers={"Content-Disposition": 'attachment; filename="aaa-events.json"'},
        )

    @app.get("/api/events/{event_id}")
    def event_detail(event_id: str, reveal: bool = False) -> dict[str, Any]:
        store: DbEventStore = state["db"]
        event = store.get(event_id)
        if event is None:
            raise HTTPException(status_code=404, detail=f"事件不存在：{event_id}")
        meta = store.decisions_for([event_id]).get(event_id, {})
        payload: dict[str, Any] = {**event.model_dump(), **meta}
        payload["body"] = _body_payload(state, event, reveal=reveal)
        return payload

    @app.get("/api/events/{event_id}/export")
    def export_event(
        event_id: str, format: Literal["json", "csv"] = "json", reveal: bool = False
    ) -> Response:
        store: DbEventStore = state["db"]
        event = store.get(event_id)
        if event is None:
            raise HTTPException(status_code=404, detail=f"事件不存在：{event_id}")
        meta = store.decisions_for([event_id]).get(event_id, {})
        if reveal:
            _log_reveal(state, event_id, f"export:{format}")
        if format == "csv":
            csv_text = _events_to_csv([(event, meta)])
            return PlainTextResponse(
                csv_text,
                media_type="text/csv; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="{event_id}.csv"'},
            )
        payload = {**event.model_dump(), **meta}
        payload["body"] = _body_payload(state, event, reveal=reveal)
        return JSONResponse(
            payload,
            headers={"Content-Disposition": f'attachment; filename="{event_id}.json"'},
        )

    # ------------------------------------------------------------- 统计/策略

    @app.get("/api/stats")
    def stats(
        since: str | None = None,
        until: str | None = None,
    ) -> dict[str, Any]:
        try:
            since_dt = parse_since(since)
            until_dt = parse_since(until)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        store: DbEventStore = state["db"]
        return store.stats(since=since_dt, until=until_dt)

    @app.get("/api/policy")
    def policy_view() -> dict[str, Any]:
        loader: PolicyLoader | None = state["policy_loader"]
        if loader is None:
            raise HTTPException(status_code=404, detail="面板未配置策略文件")
        try:
            doc = loader.load()
        except Exception as exc:  # noqa: BLE001 - 面板不因坏策略 500
            raise HTTPException(status_code=503, detail=f"策略加载失败：{exc}") from exc
        rule_count = (
            len(doc.domains.rules)
            + len(doc.processes.rules)
            + len(doc.content.rules)
            + len(doc.volume)
            + len(doc.time_window)
        )
        return {
            "path": str(loader.path),
            "mode": doc.mode,
            "policy_version": doc.policy_version,
            "fail_open": doc.defaults.fail_open,
            "classes": doc.domains.classes,
            "rule_count": rule_count,
            "document": doc.model_dump(mode="json", by_alias=True),
        }

    # ------------------------------------------------------------- 决策流

    @app.post("/api/decisions")
    def post_decision(body: DecisionRequest, request: Request) -> dict[str, Any]:
        store: DbEventStore = state["db"]
        event = store.get(body.event_id)
        if event is None:
            raise HTTPException(status_code=404, detail=f"事件不存在：{body.event_id}")
        if event.verdict != "confirm":
            raise HTTPException(
                status_code=409,
                detail=f"仅 verdict=confirm 的事件需要人工决策（该事件 verdict={event.verdict}）",
            )
        if body.decision == DECISION_ALLOW:
            # 允许：一次性，只记到事件，不进缓存（03 文档 T5.3）
            store.set_decision(event.id, DECISION_ALLOW)
            client_host = request.client.host if request.client else "unknown"
            store.log_access(event.id, "decision", detail=f"allow by panel ({client_host})")
            return {"event_id": event.id, "decision": DECISION_ALLOW, "cached": False}
        # 拒绝：缓存 deny（TTL 可配），后续同类请求升级 block
        decisions: DecisionStore | None = state["decisions"]
        rule_ids = [
            str(rule.get("id", "")) for rule in event.matched_rules if isinstance(rule, dict)
        ]
        key = decision_key(event.destination.host, rule_ids)
        ttl = body.ttl_seconds
        entry: dict[str, Any] | None = None
        if decisions is not None:
            entry = decisions.set(key, DECISION_DENY, ttl_seconds=ttl)
        store.set_decision(event.id, DECISION_DENY)
        store.log_access(event.id, "decision", detail=f"deny key={key}")
        return {
            "event_id": event.id,
            "decision": DECISION_DENY,
            "cached": entry is not None,
            "key": key,
            "ttl_seconds": (entry or {}).get("ttl_seconds"),
        }

    @app.get("/api/decisions")
    def list_decisions() -> dict[str, Any]:
        store: DbEventStore = state["db"]
        decisions: DecisionStore | None = state["decisions"]
        return {
            "decided_events": store.list_decisions(),
            "cached_denies": decisions.list_active() if decisions else [],
        }

    # ------------------------------------------------------------- 静态页

    @app.get("/", include_in_schema=False)
    def index() -> Response:
        return index_page()

    @app.get("/static/{name}", include_in_schema=False)
    def static_file(name: str) -> Response:
        path = STATIC_DIR / name
        if not path.is_file() or "/" in name or "\\" in name or ".." in name:
            raise HTTPException(status_code=404)
        media = "text/html" if name.endswith(".html") else None
        return FileResponse(path, media_type=media)

    return app


# ------------------------------------------------------------------ 内部工具


def _evidence_path(state: dict[str, Any], evidence_file: str) -> Path | None:
    """证据文件解析：``EvidenceInfo.file`` 相对 **data_dir**（decisions.md D-2026-10-24-09）。

    依次尝试 data_dir 拼接、绝对路径、evidence_dir 直拼（兼容旧记录），取存在者。
    """
    data_dir: Path | None = state.get("data_dir")
    evidence_dir: Path = state["evidence_dir"]
    candidates: list[Path] = []
    if data_dir is not None:
        candidates.append(data_dir / evidence_file)
    candidates.append(Path(evidence_file))
    candidates.append(evidence_dir / evidence_file)
    candidates.append(evidence_dir / Path(evidence_file).name)
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _body_payload(state: dict[str, Any], event: AuditEvent, *, reveal: bool) -> dict[str, Any]:
    """事件详情的 body 段：默认脱敏；``reveal`` 显式解锁并记审计日志。"""
    evidence = event.evidence
    if evidence is None or not evidence.file:
        return {
            "content": None,
            "masked": False,
            "hits": {},
            "truncated": False,
            "original_size": 0,
            "sha256": evidence.sha256 if evidence else None,
        }
    path = _evidence_path(state, evidence.file)
    if path is None:
        return {
            "content": None,
            "masked": False,
            "hits": {},
            "missing": True,
            "truncated": evidence.truncated,
            "original_size": evidence.original_size,
            "sha256": evidence.sha256,
        }
    raw = path.read_bytes()[:MAX_BODY_DISPLAY]
    text = raw.decode("utf-8", errors="replace")
    if reveal:
        _log_reveal(state, event.id, f"body evidence={evidence.file}")
        return {
            "content": text,
            "masked": False,
            "hits": {},
            "truncated": evidence.truncated,
            "original_size": evidence.original_size,
            "sha256": evidence.sha256,
        }
    masked = mask_secret_spans(text, truncated=evidence.truncated)
    return {
        "content": masked.text,
        "masked": bool(masked.hits),
        "hits": masked.hits,
        "truncated": masked.truncated,
        "original_size": masked.original_size,
        "sha256": evidence.sha256,
    }


def _log_reveal(state: dict[str, Any], event_id: str, detail: str) -> None:
    """解锁查看原文：记审计日志（03 文档 T5.1）。"""
    store: DbEventStore = state["db"]
    store.log_access(event_id, "reveal", detail=detail)
    logger.info("面板解锁查看原文：event=%s detail=%s", event_id, detail)


_CSV_COLUMNS = (
    "id",
    "ts",
    "mode",
    "verdict",
    "risk_score",
    "action_taken",
    "decision",
    "host",
    "ip",
    "port",
    "classification",
    "method",
    "path",
    "content_type",
    "request_size",
    "pid",
    "process_name",
    "process_profile",
    "policy_version",
    "error",
)


def _event_csv_row(event: AuditEvent, meta: dict[str, Any] | None = None) -> dict[str, Any]:
    process = event.process
    return {
        "id": event.id,
        "ts": event.ts,
        "mode": event.mode,
        "verdict": event.verdict,
        "risk_score": event.risk_score,
        "action_taken": event.action_taken,
        "decision": (meta or {}).get("decision") or "",
        "host": event.destination.host,
        "ip": event.destination.ip or "",
        "port": event.destination.port,
        "classification": event.destination.classification,
        "method": event.request.method,
        "path": event.request.path,
        "content_type": event.request.content_type or "",
        "request_size": event.request.size,
        "pid": process.pid if process else "",
        "process_name": process.name if process else "",
        "process_profile": process.profile if process else "",
        "policy_version": event.policy_version or "",
        "error": event.error or "",
    }


def _events_to_csv(pairs: list[tuple[AuditEvent, dict[str, Any]]]) -> str:
    """事件列表 → CSV（列表导出与单事件导出共用；``meta`` 提供 decision 列）。"""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(_CSV_COLUMNS))
    writer.writeheader()
    for event, meta in pairs:
        writer.writerow(_event_csv_row(event, meta))
    return buffer.getvalue()
