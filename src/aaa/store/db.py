"""SQLite 事件库（02 文档 D6/§6，03 文档 T4.1）。

- ``data/audit.db``：events 表（02 文档 §6 全字段）+ event_rules（维度/规则命中明细，
  供 dim 过滤与按规则聚合）+ access_log（面板 reveal/决策审计日志）；
- 索引：ts / verdict / pid / host（02 文档 D6）；
- ``append`` 即事件写入入口（与 JSONL 同签名，可经 ``mirror`` 双写收敛开关）；
- ``trim(days)``：删除过期事件行并连带清理对应证据文件（启动自动清理与
  ``aaa trim --days N`` 共用本实现）；
- 证据文件哈希管理：``verify_evidence`` 按 DB 记录复核 evidence 文件存在性与 sha256。
"""

from __future__ import annotations

import hashlib
import logging
import sqlite3
import threading
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from aaa.store.events import AuditEvent, new_event_id

logger = logging.getLogger(__name__)

#: 事件保留期默认值（02 文档 D6：``aaa trim --days 14`` 手动 + 启动自动清理）
DEFAULT_RETENTION_DAYS = 14


class EventSink(Protocol):
    """事件落盘入口的窄接口（AuditAddon 依赖的最小面）。"""

    def append(self, event: AuditEvent) -> None:
        """写入一条事件。"""
        ...


_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id              TEXT PRIMARY KEY,
    ts              TEXT NOT NULL,
    ts_epoch        REAL NOT NULL,
    mode            TEXT NOT NULL,
    verdict         TEXT NOT NULL,
    risk_score      INTEGER NOT NULL DEFAULT 0,
    pid             INTEGER,
    process_json    TEXT,
    process_name    TEXT,
    host            TEXT NOT NULL,
    ip              TEXT,
    port            INTEGER,
    classification  TEXT,
    method          TEXT NOT NULL,
    path            TEXT NOT NULL,
    content_type    TEXT,
    request_size    INTEGER NOT NULL DEFAULT 0,
    response_json   TEXT,
    matched_rules   TEXT NOT NULL DEFAULT '[]',
    action_taken    TEXT NOT NULL,
    evidence_file   TEXT,
    evidence_sha256 TEXT,
    evidence_truncated INTEGER NOT NULL DEFAULT 0,
    evidence_size   INTEGER,
    evidence_original_size INTEGER,
    policy_version  TEXT,
    error           TEXT,
    decision        TEXT,
    decision_ts     TEXT,
    raw             TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_ts_epoch ON events (ts_epoch);
CREATE INDEX IF NOT EXISTS idx_events_verdict  ON events (verdict);
CREATE INDEX IF NOT EXISTS idx_events_pid      ON events (pid);
CREATE INDEX IF NOT EXISTS idx_events_host     ON events (host);

CREATE TABLE IF NOT EXISTS event_rules (
    event_id TEXT NOT NULL,
    rule_id  TEXT NOT NULL,
    dim      TEXT NOT NULL,
    action   TEXT,
    weight   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_event_rules_dim    ON event_rules (dim);
CREATE INDEX IF NOT EXISTS idx_event_rules_rule   ON event_rules (rule_id);
CREATE INDEX IF NOT EXISTS idx_event_rules_event  ON event_rules (event_id);

CREATE TABLE IF NOT EXISTS access_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       TEXT NOT NULL,
    event_id TEXT NOT NULL,
    action   TEXT NOT NULL,
    detail   TEXT
);
CREATE INDEX IF NOT EXISTS idx_access_log_event ON access_log (event_id);
"""


def parse_since(value: str | None) -> datetime | None:
    """解析 ``--since``：相对时长（``24h``/``30m``/``7d``）或 ISO 日期时间。

    非法输入抛 ``ValueError``（CLI 层转参数错误）。
    """
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    lowered = text.lower()
    if lowered[-1] in ("s", "m", "h", "d") and lowered[:-1].isdigit():
        amount = int(lowered[:-1])
        unit = {"s": 1, "m": 60, "h": 3600, "d": 86400}[lowered[-1]]
        return datetime.now(UTC).astimezone() - timedelta(seconds=amount * unit)
    try:
        return datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(
            f"无法解析时间：{value!r}（支持 24h/30m/7d 相对时长或 ISO 8601，"
            f"如 2026-10-24 或 2026-10-24T12:00:00）"
        ) from exc


class DbEventStore:
    """线程安全 SQLite 事件存储（mitmproxy 钩子线程写、CLI/API 读）。"""

    def __init__(
        self,
        db_path: Path,
        *,
        evidence_dir: Path | None = None,
        mirror: EventSink | None = None,
    ) -> None:
        self._path = db_path
        self._evidence_dir = evidence_dir
        self._mirror = mirror
        self._lock = threading.RLock()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            # WAL：代理线程写与 CLI/API 读并发不互斥
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    @property
    def path(self) -> Path:
        return self._path

    @property
    def evidence_dir(self) -> Path | None:
        return self._evidence_dir

    @property
    def mirror(self) -> EventSink | None:
        """JSONL 镜像写（``--jsonl`` 开关，02 文档 D6 收敛语义）。"""
        return self._mirror

    @mirror.setter
    def mirror(self, sink: EventSink | None) -> None:
        self._mirror = sink

    # ---------------------------------------------------------------- 写入

    def append(self, event: AuditEvent) -> None:
        """写入一条事件（02 文档 §6 字段落列，完整 JSON 落 ``raw``）。"""
        process = event.process
        row = (
            event.id,
            event.ts,
            _ts_epoch(event.ts),
            event.mode,
            event.verdict,
            event.risk_score,
            process.pid if process else None,
            process.model_dump_json() if process else None,
            process.name if process else None,
            event.destination.host,
            event.destination.ip,
            event.destination.port,
            event.destination.classification,
            event.request.method,
            event.request.path,
            event.request.content_type,
            event.request.size,
            event.response.model_dump_json() if event.response else None,
            _dumps(event.matched_rules),
            event.action_taken,
            event.evidence.file if event.evidence else None,
            event.evidence.sha256 if event.evidence else None,
            int(event.evidence.truncated) if event.evidence else 0,
            event.evidence.size if event.evidence else None,
            event.evidence.original_size if event.evidence else None,
            event.policy_version,
            event.error,
            event.model_dump_json(),
        )
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO events (
                    id, ts, ts_epoch, mode, verdict, risk_score, pid, process_json,
                    process_name, host, ip, port, classification, method, path,
                    content_type, request_size, response_json, matched_rules,
                    action_taken, evidence_file, evidence_sha256, evidence_truncated,
                    evidence_size, evidence_original_size, policy_version, error, raw
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                row,
            )
            self._conn.executemany(
                "INSERT INTO event_rules (event_id, rule_id, dim, action, weight) "
                "VALUES (?,?,?,?,?)",
                [
                    (
                        event.id,
                        str(rule.get("id", "")),
                        str(rule.get("dim", "")),
                        str(rule.get("action", "")) if rule.get("action") else None,
                        int(rule["weight"]) if isinstance(rule.get("weight"), int) else None,
                    )
                    for rule in event.matched_rules
                    if isinstance(rule, dict)
                ],
            )
            self._conn.commit()
        if self._mirror is not None:
            self._mirror.append(event)

    # ---------------------------------------------------------------- 读取

    def get(self, event_id: str) -> AuditEvent | None:
        """按 ID 取事件（完整 JSON 还原）。"""
        with self._lock:
            row = self._conn.execute("SELECT raw FROM events WHERE id = ?", (event_id,)).fetchone()
        if row is None:
            return None
        return AuditEvent.model_validate_json(row["raw"])

    def get_row(self, event_id: str) -> dict[str, Any] | None:
        """按 ID 取事件行（含 ``decision``/``decision_ts`` 等 DB 层字段）。"""
        with self._lock:
            row = self._conn.execute(
                "SELECT id, ts, decision, decision_ts FROM events WHERE id = ?", (event_id,)
            ).fetchone()
        if row is None:
            return None
        return dict(row)

    def set_decision(self, event_id: str, decision: str, *, ts: str | None = None) -> bool:
        """记录用户对（verdict=confirm）事件的人工决策（T5.3）。事件不存在返回 False。"""
        stamp = ts or datetime.now().astimezone().isoformat(timespec="milliseconds")
        with self._lock:
            cursor = self._conn.execute(
                "UPDATE events SET decision = ?, decision_ts = ? WHERE id = ?",
                (decision, stamp, event_id),
            )
            self._conn.commit()
            return cursor.rowcount > 0

    def list_decisions(self) -> list[dict[str, Any]]:
        """已决策事件列表（面板回显）。"""
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, ts, host, path, decision, decision_ts FROM events "
                "WHERE decision IS NOT NULL ORDER BY decision_ts DESC LIMIT 200"
            ).fetchall()
        return [dict(row) for row in rows]

    def decisions_for(self, event_ids: list[str]) -> dict[str, dict[str, str | None]]:
        """批量取事件的用户决策（列表页合并展示用）。"""
        if not event_ids:
            return {}
        placeholders = ",".join("?" * len(event_ids))
        with self._lock:
            rows = self._conn.execute(
                f"SELECT id, decision, decision_ts FROM events WHERE id IN ({placeholders})",
                event_ids,
            ).fetchall()
        return {
            row["id"]: {"decision": row["decision"], "decision_ts": row["decision_ts"]}
            for row in rows
        }

    def query(
        self,
        *,
        verdict: str | None = None,
        pid: int | None = None,
        host: str | None = None,
        dim: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[AuditEvent], int]:
        """分页 + 过滤查询（03 文档 T5.1：verdict/pid/host/dim/时间）。

        返回 ``(events, total)``：``total`` 为过滤条件下的总数（分页前）。
        """
        where, params = self._filters(
            verdict=verdict, pid=pid, host=host, dim=dim, since=since, until=until
        )
        where_sql = f"WHERE {' AND '.join(where)}" if where else ""
        with self._lock:
            total = int(
                self._conn.execute(f"SELECT COUNT(*) FROM events {where_sql}", params).fetchone()[0]
            )
            rows = self._conn.execute(
                f"SELECT raw FROM events {where_sql} ORDER BY ts_epoch DESC, id DESC "
                f"LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()
        return [AuditEvent.model_validate_json(row["raw"]) for row in rows], total

    def latest(self, count: int = 5) -> list[AuditEvent]:
        """最近 N 条事件（``aaa status``）。"""
        events, _total = self.query(limit=count, offset=0)
        return events

    def max_rowid(self) -> int:
        """当前最大 rowid（``aaa tail`` 增量游标起点）。"""
        with self._lock:
            row = self._conn.execute("SELECT COALESCE(MAX(rowid), 0) AS m FROM events").fetchone()
        return int(row["m"])

    def poll_after(
        self,
        rowid: int,
        *,
        verdict: str | None = None,
        pid: int | None = None,
        host: str | None = None,
        limit: int = 200,
    ) -> tuple[list[AuditEvent], int]:
        """取 ``rowid`` 之后的新事件（``aaa tail`` 增量轮询）。

        返回 ``(events, new_cursor)``；``new_cursor`` 供下次调用。
        """
        where = ["rowid > ?"]
        params: list[Any] = [rowid]
        if verdict:
            where.append("verdict = ?")
            params.append(verdict)
        if pid is not None:
            where.append("pid = ?")
            params.append(pid)
        if host:
            where.append("host = ?")
            params.append(host)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT rowid, raw FROM events WHERE {' AND '.join(where)} ORDER BY rowid LIMIT ?",
                [*params, limit],
            ).fetchall()
            new_cursor = int(rows[-1]["rowid"]) if rows else rowid
        return [AuditEvent.model_validate_json(row["raw"]) for row in rows], new_cursor

    @staticmethod
    def _filters(
        *,
        verdict: str | None,
        pid: int | None,
        host: str | None,
        dim: str | None,
        since: datetime | None,
        until: datetime | None,
    ) -> tuple[list[str], list[Any]]:
        where: list[str] = []
        params: list[Any] = []
        if verdict:
            where.append("verdict = ?")
            params.append(verdict)
        if pid is not None:
            where.append("pid = ?")
            params.append(pid)
        if host:
            where.append("host = ?")
            params.append(host)
        if dim:
            where.append(
                "EXISTS (SELECT 1 FROM event_rules r WHERE r.event_id = events.id AND r.dim = ?)"
            )
            params.append(dim)
        if since is not None:
            where.append("ts_epoch >= ?")
            params.append(since.timestamp())
        if until is not None:
            where.append("ts_epoch <= ?")
            params.append(until.timestamp())
        return where, params

    def count(self) -> int:
        with self._lock:
            return int(self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def stats(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        top: int = 10,
    ) -> dict[str, Any]:
        """聚合统计（03 文档 T5.1：按进程/域名/规则）。"""
        base, params = self._filters(
            verdict=None, pid=None, host=None, dim=None, since=since, until=until
        )
        where_sql = f"WHERE {' AND '.join(base)}" if base else ""
        with self._lock:
            by_verdict = {
                row["verdict"]: row["n"]
                for row in self._conn.execute(
                    f"SELECT verdict, COUNT(*) AS n FROM events {where_sql} "
                    "GROUP BY verdict ORDER BY n DESC",
                    params,
                ).fetchall()
            }
            by_process = [
                dict(row)
                for row in self._conn.execute(
                    f"SELECT pid, process_name, COUNT(*) AS n FROM events "
                    f"{_and(base, 'process_name IS NOT NULL')} "
                    "GROUP BY pid, process_name ORDER BY n DESC LIMIT ?",
                    [*params, top],
                ).fetchall()
            ]
            by_host = [
                dict(row)
                for row in self._conn.execute(
                    f"SELECT host, COUNT(*) AS n FROM events {where_sql} "
                    "GROUP BY host ORDER BY n DESC LIMIT ?",
                    [*params, top],
                ).fetchall()
            ]
            by_rule = [
                dict(row)
                for row in self._conn.execute(
                    "SELECT r.rule_id, r.dim, COUNT(*) AS n FROM event_rules r "
                    "JOIN events e ON e.id = r.event_id "
                    f"WHERE {_qualify(base)} "
                    "GROUP BY r.rule_id, r.dim ORDER BY n DESC LIMIT ?",
                    [*params, top],
                ).fetchall()
            ]
            by_day = [
                dict(row)
                for row in self._conn.execute(
                    f"SELECT date(ts_epoch, 'unixepoch', 'localtime') AS day, COUNT(*) AS n "
                    f"FROM events {where_sql} GROUP BY day ORDER BY day DESC LIMIT 30",
                    params,
                ).fetchall()
            ]
        return {
            "total": sum(by_verdict.values()),
            "by_verdict": by_verdict,
            "by_process": by_process,
            "by_host": by_host,
            "by_rule": by_rule,
            "by_day": by_day,
            "pending_confirm": by_verdict.get("confirm", 0),
        }

    def iter_all(self, *, batch: int = 500) -> Iterator[AuditEvent]:
        """全量遍历（report/证据复核用，分批读取避免大结果集驻留）。"""
        offset = 0
        while True:
            events, _ = self.query(limit=batch, offset=offset)
            if not events:
                return
            yield from events
            offset += batch

    def log_access(
        self,
        event_id: str,
        action: str,
        *,
        detail: str | None = None,
        ts: str | None = None,
    ) -> None:
        """面板审计日志（reveal 解锁、人工决策等敏感操作，03 文档 T5.1）。"""
        stamp = ts or datetime.now().astimezone().isoformat(timespec="milliseconds")
        with self._lock:
            self._conn.execute(
                "INSERT INTO access_log (ts, event_id, action, detail) VALUES (?,?,?,?)",
                (stamp, event_id, action, detail),
            )
            self._conn.commit()

    def list_access_log(
        self, *, event_id: str | None = None, limit: int = 50
    ) -> list[dict[str, Any]]:
        with self._lock:
            if event_id:
                rows = self._conn.execute(
                    "SELECT ts, event_id, action, detail FROM access_log "
                    "WHERE event_id = ? ORDER BY id DESC LIMIT ?",
                    (event_id, limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT ts, event_id, action, detail FROM access_log ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [dict(row) for row in rows]

    # ---------------------------------------------------------------- 清理

    def trim(self, days: int, *, now: datetime | None = None) -> dict[str, int]:
        """删除 ``days`` 天前的事件与对应证据文件（03 文档 T4.1：保留期）。

        返回 ``{"events": 删除行数, "evidence": 删除证据文件数}``。
        """
        if days < 0:
            raise ValueError("--days 不能为负")
        stamp = (now or datetime.now(UTC).astimezone()).timestamp() - days * 86400
        removed_evidence = 0
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, evidence_file FROM events WHERE ts_epoch < ?", (stamp,)
            ).fetchall()
            if not rows:
                return {"events": 0, "evidence": 0}
            self._conn.execute("DELETE FROM events WHERE ts_epoch < ?", (stamp,))
            self._conn.execute(
                f"DELETE FROM event_rules WHERE event_id IN ({','.join('?' * len(rows))})",
                [row["id"] for row in rows],
            )
            self._conn.commit()
        for row in rows:
            evidence_file = row["evidence_file"]
            if not evidence_file or self._evidence_dir is None:
                continue
            path = self._evidence_dir / evidence_file
            try:
                path.unlink()
                removed_evidence += 1
            except FileNotFoundError:
                pass
            except OSError:
                logger.warning("证据文件删除失败：%s", path, exc_info=True)
        logger.info("trim：删除 %d 条事件、%d 个证据文件", len(rows), removed_evidence)
        return {"events": len(rows), "evidence": removed_evidence}

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # --------------------------------------------------------- 证据哈希管理

    def verify_evidence(self, *, event_id: str | None = None) -> dict[str, Any]:
        """复核证据文件哈希（02 文档 D6：存 sha256 可复核）。

        返回 ``{"checked", "missing", "corrupted"}``，``missing``/``corrupted``
        为 ``{event_id: 详情}``。``evidence_dir`` 未配置时返回 ``checked=0``。
        """
        result: dict[str, Any] = {"checked": 0, "missing": {}, "corrupted": {}}
        if self._evidence_dir is None:
            return result
        if event_id is not None:
            sql = (
                "SELECT id, evidence_file, evidence_sha256 FROM events "
                "WHERE id = ? AND evidence_file IS NOT NULL"
            )
            params: list[Any] = [event_id]
        else:
            sql = (
                "SELECT id, evidence_file, evidence_sha256 FROM events "
                "WHERE evidence_file IS NOT NULL"
            )
            params = []
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        for row in rows:
            result["checked"] += 1
            path = self._evidence_dir / row["evidence_file"]
            if not path.exists():
                result["missing"][row["id"]] = str(row["evidence_file"])
                continue
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest != row["evidence_sha256"]:
                result["corrupted"][row["id"]] = (
                    f"sha256 不一致（db={row['evidence_sha256']} file={digest}）"
                )
        return result


def _ts_epoch(ts: str) -> float:
    """事件 ISO 时间戳 → unix epoch（解析失败按当前时间，保证可排序）。"""
    try:
        return datetime.fromisoformat(ts).timestamp()
    except ValueError:
        return datetime.now(UTC).astimezone().timestamp()


def _and(base: list[str], extra: str) -> str:
    """``WHERE`` 子句组装：base 条件 + 附加条件（base 空时只留附加）。"""
    return f"WHERE {' AND '.join([*base, extra])}"


def _qualify(base: list[str]) -> str:
    """by_rule 联表查询的 WHERE 体：条件列在 ``events e`` 别名上仍可解析（无歧义列名）。

    注意：``_filters`` 的 dim 子查询含 ``events.id``，与 ``e`` 别名不兼容，
    故聚合统计不接受 dim 过滤（调用方约定）。
    """
    return " AND ".join(base) if base else "1=1"


def _dumps(value: Any) -> str:
    import json

    return json.dumps(value, ensure_ascii=False)


def open_default_store(data_dir: Path) -> DbEventStore:
    """按惯例布局打开事件库（``data/audit.db``），证据目录随之确定。"""
    return DbEventStore(data_dir / "audit.db", evidence_dir=data_dir / "evidence")


__all__ = [
    "DEFAULT_RETENTION_DAYS",
    "DbEventStore",
    "EventSink",
    "new_event_id",
    "open_default_store",
    "parse_since",
]
