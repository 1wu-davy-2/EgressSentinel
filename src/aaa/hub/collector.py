"""中心端聚合收集器（06 文档 W8：独立 FastAPI app，``aaa hub serve`` 由集成接线）。

- ``POST /ingest``：Bearer token 校验（请求头 + body token **双重比对**，
  decisions D-2026-10-25-47）→ 内存缓冲 → 按阈值/显式 flush 落 SQLite ``hub.db``
  （机器名维度，``(machine, id)`` 主键幂等去重）；
- ``GET /api/hub/events``：跨机器事件查询（machine/verdict/host/since/limit/offset）；
- ``GET /api/hub/stats``：跨机器聚合（按机器/判定/进程/主机/规则/日）；
- ``GET /api/hub/machines``：上报机器清单（最后上报时间与累计条数）。

安全边界：hub 监听在局域网（**区别于面板的回环限制**——要收多台机器的上报），
因此**所有端点都要求 Bearer 令牌**（含只读查询：事件摘要虽经 agent 侧脱敏，
仍是跨机审计数据，不应匿名可读）；中心库只存 agent 已脱敏的摘要，脱敏责任在
Forwarder（``hub.forwarder.summarize_event``），中心不做二次脱敏、也拿不到原文
body（事件模型本就不含 body，evidence 文件不出 agent 机器）。
"""

from __future__ import annotations

import json
import logging
import secrets
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from aaa.store.db import parse_since

logger = logging.getLogger(__name__)

#: hub 默认监听端口（面板 8787 / 代理 8080 之外取相邻空闲段）
DEFAULT_HUB_PORT = 8788

#: 事件保留期默认值（与 agent 侧 audit.db 同口径，trim 复用同语义）
DEFAULT_RETENTION_DAYS = 14

#: 单次 ingest 事件数上限（agent 侧批量 ≤50；此处为防滥用的宽松上限）
MAX_INGEST_BATCH = 1000

#: flush 阈值默认值：缓冲事件数达到即落盘（内存缓冲 → SQLite）
DEFAULT_FLUSH_THRESHOLD = 100

#: 缓冲上限：落盘一直失败时防止内存无限增长（丢弃最旧并计数）
DEFAULT_BUFFER_MAXSIZE = 10000

#: 查询分页上限
MAX_PAGE_LIMIT = 500

_SCHEMA = """
CREATE TABLE IF NOT EXISTS hub_events (
    machine       TEXT NOT NULL,
    id            TEXT NOT NULL,
    ts            TEXT NOT NULL,
    ts_epoch      REAL NOT NULL,
    verdict       TEXT NOT NULL DEFAULT 'unassessed',
    risk_score    INTEGER NOT NULL DEFAULT 0,
    process_name  TEXT,
    pid           INTEGER,
    host          TEXT,
    method        TEXT,
    path          TEXT,
    summary       TEXT,
    raw           TEXT NOT NULL,
    received_ts   TEXT NOT NULL,
    PRIMARY KEY (machine, id)
);

CREATE INDEX IF NOT EXISTS idx_hub_events_ts      ON hub_events (ts_epoch);
CREATE INDEX IF NOT EXISTS idx_hub_events_machine ON hub_events (machine);
CREATE INDEX IF NOT EXISTS idx_hub_events_verdict ON hub_events (verdict);
CREATE INDEX IF NOT EXISTS idx_hub_events_host    ON hub_events (host);

CREATE TABLE IF NOT EXISTS hub_event_rules (
    machine  TEXT NOT NULL,
    event_id TEXT NOT NULL,
    rule_id  TEXT NOT NULL,
    dim      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hub_event_rules_machine ON hub_event_rules (machine);
CREATE INDEX IF NOT EXISTS idx_hub_event_rules_rule    ON hub_event_rules (rule_id);
CREATE INDEX IF NOT EXISTS idx_hub_event_rules_dim     ON hub_event_rules (dim);

CREATE TABLE IF NOT EXISTS hub_agents (
    machine   TEXT PRIMARY KEY,
    last_seen TEXT NOT NULL,
    events    INTEGER NOT NULL DEFAULT 0
);
"""


class HubAuthError(Exception):
    """ingest 鉴权失败（body token 与中心配置不匹配；端点层转 401）。"""


class HubEventIn(BaseModel):
    """单条事件摘要（agent 端 ``summarize_event`` 产物；宽容解析，未知字段保留）。"""

    model_config = ConfigDict(extra="allow")

    id: str = Field(min_length=1)
    ts: str = Field(min_length=1)
    verdict: str = "unassessed"
    risk_score: int = 0


class IngestEnvelope(BaseModel):
    """``POST /ingest`` 请求体（06 文档 W8：``{token, host, events}``）。"""

    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=1)
    host: str = Field(min_length=1, max_length=255)
    events: list[HubEventIn] = Field(min_length=1, max_length=MAX_INGEST_BATCH)


def _ts_epoch(ts: str) -> float:
    """事件 ISO 时间戳 → unix epoch（解析失败按当前时间，保证可排序）。"""
    try:
        return datetime.fromisoformat(ts).timestamp()
    except ValueError:
        return datetime.now(UTC).astimezone().timestamp()


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def _and(base: list[str], extra: str) -> str:
    """``WHERE`` 子句组装：base 条件 + 附加条件（base 空时只留附加；db.py 同款）。"""
    return f"WHERE {' AND '.join([*base, extra])}"


class HubCollector:
    """中心收集器：内存缓冲 + SQLite hub.db（线程安全；TestClient/uvicorn 共用）。"""

    def __init__(
        self,
        db_path: Path,
        token: str,
        *,
        flush_threshold: int = DEFAULT_FLUSH_THRESHOLD,
        buffer_maxsize: int = DEFAULT_BUFFER_MAXSIZE,
    ) -> None:
        if not token:
            raise ValueError("hub token 为空（中心端必须有共享令牌才监听网络）")
        self._token = token
        self._flush_threshold = max(1, flush_threshold)
        self._buffer_maxsize = max(1, buffer_maxsize)
        self._lock = threading.RLock()
        self._buffer: list[tuple[Any, ...]] = []
        self._rule_buffer: list[tuple[str, str, str, str]] = []
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(_SCHEMA)
            self._conn.commit()
        # 统计（观测/诊断用）
        self.accepted = 0
        self.persisted = 0
        self.dropped = 0
        self.flush_errors = 0
        self.ingest_batches = 0

    @property
    def token(self) -> str:
        """共享令牌（Bearer 校验用；不进日志与查询结果）。"""
        return self._token

    # ------------------------------------------------------------- 写入路径

    def ingest(self, envelope: IngestEnvelope) -> dict[str, int]:
        """接收一批事件摘要：鉴权（body token）→ 入内存缓冲 → 达阈值落盘。

        返回 ``{"accepted": n, "buffered": 当前缓冲数, "persisted_total": 累计落盘}``。
        Bearer 请求头的校验在端点层（``_require_bearer``）；body token 在这里比。
        """
        if not secrets.compare_digest(envelope.token, self._token):
            raise HubAuthError("body token 与 hub 令牌不匹配")
        rows: list[tuple[Any, ...]] = []
        rule_rows: list[tuple[str, str, str, str]] = []
        received = _now_iso()
        for event in envelope.events:
            rows.append(self._event_row(envelope.host, event, received))
            rule_rows.extend(self._rule_rows(envelope.host, event))
        with self._lock:
            self.accepted += len(rows)
            self.ingest_batches += 1
            self._buffer.extend(rows)
            self._rule_buffer.extend(rule_rows)
            while len(self._buffer) > self._buffer_maxsize:
                self._buffer.pop(0)
                self.dropped += 1
            if len(self._buffer) >= self._flush_threshold:
                self.flush()
        return {
            "accepted": len(rows),
            "buffered": len(self._buffer),
            "persisted_total": self.persisted,
        }

    def _event_row(self, machine: str, event: HubEventIn, received: str) -> tuple[Any, ...]:
        raw = event.model_dump(mode="json")
        process = raw.get("process") if isinstance(raw.get("process"), dict) else {}
        request = raw.get("request") if isinstance(raw.get("request"), dict) else {}
        destination = raw.get("destination") if isinstance(raw.get("destination"), dict) else {}
        return (
            machine,
            event.id,
            event.ts,
            _ts_epoch(event.ts),
            event.verdict,
            event.risk_score,
            process.get("name"),
            process.get("pid"),
            destination.get("host"),
            request.get("method"),
            request.get("path"),
            raw.get("summary") if isinstance(raw.get("summary"), str) else None,
            json.dumps(raw, ensure_ascii=False),
            received,
        )

    @staticmethod
    def _rule_rows(machine: str, event: HubEventIn) -> list[tuple[str, str, str, str]]:
        raw = event.model_dump(mode="json")
        rules = raw.get("matched_rules")
        if not isinstance(rules, list):
            return []
        rows: list[tuple[str, str, str, str]] = []
        for rule in rules:
            if isinstance(rule, dict) and rule.get("id"):
                rows.append((machine, event.id, str(rule["id"]), str(rule.get("dim", ""))))
        return rows

    def flush(self) -> int:
        """把内存缓冲整批落盘（单事务）；返回本次落盘条数。失败计数不抛出。"""
        with self._lock:
            if not self._buffer:
                return 0
            rows = self._buffer
            rule_rows = self._rule_buffer
            self._buffer = []
            self._rule_buffer = []
            try:
                self._conn.execute("BEGIN")
                self._conn.executemany(
                    "INSERT OR REPLACE INTO hub_events ("
                    "machine, id, ts, ts_epoch, verdict, risk_score, process_name, "
                    "pid, host, method, path, summary, raw, received_ts"
                    ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    rows,
                )
                keys = {(row[0], row[1]) for row in rows}
                self._conn.executemany(
                    "DELETE FROM hub_event_rules WHERE machine = ? AND event_id = ?",
                    list(keys),
                )
                self._conn.executemany(
                    "INSERT INTO hub_event_rules (machine, event_id, rule_id, dim) "
                    "VALUES (?,?,?,?)",
                    rule_rows,
                )
                per_machine: dict[str, int] = {}
                for row in rows:
                    per_machine[row[0]] = per_machine.get(row[0], 0) + 1
                self._conn.executemany(
                    "INSERT INTO hub_agents (machine, last_seen, events) VALUES (?,?,?) "
                    "ON CONFLICT(machine) DO UPDATE SET "
                    "last_seen = excluded.last_seen, events = events + excluded.events",
                    [
                        (machine, _now_iso(), count)
                        for machine, count in per_machine.items()
                    ],
                )
                self._conn.commit()
                self.persisted += len(rows)
                return len(rows)
            except sqlite3.Error:
                self._conn.rollback()
                # 落盘失败：事件退回缓冲（容量上限处丢弃最旧），如实计数
                self._buffer = [*rows, *self._buffer][: self._buffer_maxsize]
                self.flush_errors += 1
                logger.exception("hub flush 落盘失败（事件保留在内存缓冲）")
                return 0

    def trim(self, days: int) -> int:
        """删除 ``days`` 天前的 hub 事件（保留期治理；返回删除行数）。"""
        if days < 0:
            raise ValueError("days 不能为负")
        cutoff = datetime.now(UTC).astimezone().timestamp() - days * 86400
        with self._lock:
            cursor = self._conn.execute("DELETE FROM hub_events WHERE ts_epoch < ?", (cutoff,))
            self._conn.execute(
                "DELETE FROM hub_event_rules WHERE NOT EXISTS ("
                "SELECT 1 FROM hub_events e WHERE e.machine = hub_event_rules.machine "
                "AND e.id = hub_event_rules.event_id)"
            )
            self._conn.commit()
            return int(cursor.rowcount)

    # ------------------------------------------------------------- 读取路径

    def query_events(
        self,
        *,
        machine: str | None = None,
        verdict: str | None = None,
        host: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        """跨机器分页查询（返回 ``(items, total)``，``total`` 为过滤条件下的总数）。"""
        where: list[str] = []
        params: list[Any] = []
        if machine:
            where.append("machine = ?")
            params.append(machine)
        if verdict:
            where.append("verdict = ?")
            params.append(verdict)
        if host:
            where.append("host = ?")
            params.append(host)
        if since is not None:
            where.append("ts_epoch >= ?")
            params.append(since.timestamp())
        if until is not None:
            where.append("ts_epoch <= ?")
            params.append(until.timestamp())
        where_sql = f"WHERE {' AND '.join(where)}" if where else ""
        with self._lock:
            total = int(
                self._conn.execute(
                    f"SELECT COUNT(*) FROM hub_events {where_sql}", params
                ).fetchone()[0]
            )
            rows = self._conn.execute(
                f"SELECT machine, raw, received_ts FROM hub_events {where_sql} "
                "ORDER BY ts_epoch DESC, machine, id LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()
        items = []
        for row in rows:
            payload = json.loads(row["raw"])
            payload["machine"] = row["machine"]
            payload["received_ts"] = row["received_ts"]
            items.append(payload)
        return items, total

    def stats(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        top: int = 10,
    ) -> dict[str, Any]:
        """跨机器聚合统计（按判定/机器/主机/进程/规则/日）。"""
        base: list[str] = []
        params: list[Any] = []
        if since is not None:
            base.append("ts_epoch >= ?")
            params.append(since.timestamp())
        if until is not None:
            base.append("ts_epoch <= ?")
            params.append(until.timestamp())
        base_sql = f"WHERE {' AND '.join(base)}" if base else ""
        # by_rule 联表查询：条件列限定到 ``events e`` 别名（hub_event_rules 无同名列）
        rule_base = [cond.replace("ts_epoch", "e.ts_epoch") for cond in base]
        rule_where = " AND ".join(rule_base) if rule_base else "1=1"
        with self._lock:
            by_verdict = {
                row["verdict"]: row["n"]
                for row in self._conn.execute(
                    f"SELECT verdict, COUNT(*) AS n FROM hub_events {base_sql} "
                    "GROUP BY verdict ORDER BY n DESC",
                    params,
                ).fetchall()
            }
            by_machine = {
                row["machine"]: row["n"]
                for row in self._conn.execute(
                    f"SELECT machine, COUNT(*) AS n FROM hub_events {base_sql} "
                    "GROUP BY machine ORDER BY n DESC",
                    params,
                ).fetchall()
            }
            by_host = [
                dict(row)
                for row in self._conn.execute(
                    f"SELECT host, COUNT(*) AS n FROM hub_events {_and(base, 'host IS NOT NULL')} "
                    "GROUP BY host ORDER BY n DESC LIMIT ?",
                    [*params, top],
                ).fetchall()
            ]
            by_process = [
                dict(row)
                for row in self._conn.execute(
                    f"SELECT pid, process_name, COUNT(*) AS n FROM hub_events "
                    f"{_and(base, 'process_name IS NOT NULL')} "
                    "GROUP BY pid, process_name ORDER BY n DESC LIMIT ?",
                    [*params, top],
                ).fetchall()
            ]
            by_rule = [
                dict(row)
                for row in self._conn.execute(
                    "SELECT r.rule_id, r.dim, COUNT(*) AS n FROM hub_event_rules r "
                    "JOIN hub_events e ON e.machine = r.machine AND e.id = r.event_id "
                    f"WHERE {rule_where} "
                    "GROUP BY r.rule_id, r.dim ORDER BY n DESC LIMIT ?",
                    [*params, top],
                ).fetchall()
            ]
            by_day = [
                dict(row)
                for row in self._conn.execute(
                    f"SELECT date(ts_epoch, 'unixepoch', 'localtime') AS day, COUNT(*) AS n "
                    f"FROM hub_events {base_sql} GROUP BY day ORDER BY day DESC LIMIT 30",
                    params,
                ).fetchall()
            ]
        return {
            "total": sum(by_verdict.values()),
            "by_verdict": by_verdict,
            "by_machine": by_machine,
            "by_host": by_host,
            "by_process": by_process,
            "by_rule": by_rule,
            "by_day": by_day,
            "machines": self.machines(),
        }

    def machines(self) -> list[dict[str, Any]]:
        """上报机器清单（``hub_agents``：最后上报时间与累计条数，新者在前）。"""
        with self._lock:
            rows = self._conn.execute(
                "SELECT machine, last_seen, events FROM hub_agents "
                "ORDER BY last_seen DESC"
            ).fetchall()
        return [dict(row) for row in rows]

    def buffered(self) -> int:
        """当前内存缓冲中的事件数（``aaa hub serve`` 状态展示用）。"""
        with self._lock:
            return len(self._buffer)

    def counters(self) -> dict[str, int]:
        """接收/落盘/丢弃计数（观测用）。"""
        return {
            "accepted": self.accepted,
            "persisted": self.persisted,
            "dropped": self.dropped,
            "flush_errors": self.flush_errors,
            "ingest_batches": self.ingest_batches,
            "buffered": len(self._buffer),
        }

    def close(self) -> None:
        """flush 后关闭连接（退出路径；flush 失败不阻断关闭）。"""
        try:
            self.flush()
        except Exception:  # noqa: BLE001 - 关闭路径绝不抛出
            logger.exception("hub close 前的 flush 异常（已忽略）")
        with self._lock:
            self._conn.close()


# ------------------------------------------------------------------ FastAPI app


def _require_bearer(request: Request, collector: HubCollector) -> None:
    """Bearer 校验（所有端点共用；失败 401 + ``WWW-Authenticate: Bearer``）。"""
    header = request.headers.get("authorization") or ""
    scheme, _, value = header.partition(" ")
    if (
        scheme.lower() != "bearer"
        or not value.strip()
        or not secrets.compare_digest(value.strip(), collector.token)
    ):
        raise HTTPException(
            status_code=401,
            detail="Bearer 令牌缺失或不匹配",
            headers={"WWW-Authenticate": "Bearer"},
        )


def create_hub_app(collector: HubCollector) -> FastAPI:
    """构建 hub 中心应用（依赖注入式构造；单测用临时目录，不依赖真实运行数据）。"""
    app = FastAPI(title="EgressSentinel hub", docs_url=None, redoc_url=None)

    @app.post("/ingest")
    def ingest(envelope: IngestEnvelope, request: Request) -> dict[str, int]:
        _require_bearer(request, collector)
        try:
            return collector.ingest(envelope)
        except HubAuthError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc

    @app.get("/api/hub/events")
    def hub_events(
        request: Request,
        machine: str | None = None,
        verdict: str | None = None,
        host: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = Query(default=50, ge=1, le=MAX_PAGE_LIMIT),
        offset: int = Query(default=0, ge=0),
    ) -> dict[str, Any]:
        _require_bearer(request, collector)
        try:
            since_dt = parse_since(since)
            until_dt = parse_since(until)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        items, total = collector.query_events(
            machine=machine,
            verdict=verdict,
            host=host,
            since=since_dt,
            until=until_dt,
            limit=limit,
            offset=offset,
        )
        return {"total": total, "limit": limit, "offset": offset, "items": items}

    @app.get("/api/hub/stats")
    def hub_stats(
        request: Request,
        since: str | None = None,
        until: str | None = None,
    ) -> dict[str, Any]:
        _require_bearer(request, collector)
        try:
            since_dt = parse_since(since)
            until_dt = parse_since(until)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return collector.stats(since=since_dt, until=until_dt)

    @app.get("/api/hub/machines")
    def hub_machines(request: Request) -> dict[str, Any]:
        _require_bearer(request, collector)
        return {
            "machines": collector.machines(),
            "buffered": collector.buffered(),
            "counters": collector.counters(),
        }

    return app


def run_hub(
    collector: HubCollector,
    *,
    host: str = "0.0.0.0",
    port: int = DEFAULT_HUB_PORT,
) -> None:
    """阻塞式启动 hub 中心（``aaa hub serve`` 集成接线用；uvicorn 懒导入）。"""
    import uvicorn

    uvicorn.run(create_hub_app(collector), host=host, port=port, log_level="info")
