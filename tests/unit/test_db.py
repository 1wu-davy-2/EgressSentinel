"""SQLite 事件库单测（03 文档 T4.1）：字段/索引/查询过滤/分页/trim/证据哈希/决策。"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from aaa.store.db import DEFAULT_RETENTION_DAYS, DbEventStore, parse_since
from aaa.store.events import (
    AuditEvent,
    Destination,
    EvidenceInfo,
    ProcessInfo,
    RequestInfo,
)


def _event(
    event_id: str,
    *,
    ts: str = "2026-10-23T12:00:00+08:00",  # 默认在过去：trim(0) 必须能清掉
    verdict: str = "allow",
    host: str = "api.openai.com",
    pid: int | None = 123,
    dim_rules: list[dict] | None = None,
    evidence_file: str | None = None,
    evidence_sha: str | None = None,
) -> AuditEvent:
    return AuditEvent(
        id=event_id,
        ts=ts,
        mode="regular",
        verdict=verdict,
        risk_score=60 if verdict == "confirm" else 20,
        process=ProcessInfo(pid=pid, name="node.exe", profile="agent_cli") if pid else None,
        destination=Destination(host=host, port=443, classification="known_ai_api"),
        request=RequestInfo(method="POST", path="/v1/x", content_type="application/json", size=10),
        matched_rules=dim_rules or [],
        evidence=(
            EvidenceInfo(file=evidence_file, sha256=evidence_sha, size=8, original_size=8)
            if evidence_file
            else None
        ),
    )


@pytest.fixture
def store(tmp_path: Path) -> DbEventStore:
    ev_dir = tmp_path / "evidence"
    ev_dir.mkdir()
    return DbEventStore(tmp_path / "audit.db", evidence_dir=ev_dir)


def test_schema_and_indexes(tmp_path: Path) -> None:
    """02 文档 D6：索引 (ts, verdict, pid, host)。"""
    store = DbEventStore(tmp_path / "audit.db")
    names = {
        row[0] for row in store._conn.execute("SELECT name FROM sqlite_master WHERE type='index'")
    }
    assert {f"idx_events_{c}" for c in ("ts_epoch", "verdict", "pid", "host")} <= names
    store.close()


def test_append_roundtrip_full_fields(store: DbEventStore) -> None:
    event = _event(
        "evt_a",
        verdict="block",
        dim_rules=[{"id": "secret-leak", "dim": "content", "action": "block", "weight": 60}],
    )
    store.append(event)
    loaded = store.get("evt_a")
    assert loaded is not None
    assert loaded.model_dump() == event.model_dump(), "raw JSON 必须完整还原 02 §6 全字段"
    assert loaded.matched_rules[0]["id"] == "secret-leak"


def test_query_filters_and_pagination(store: DbEventStore) -> None:
    store.append(_event("evt_1", verdict="confirm", host="a.com", pid=1))
    store.append(
        _event(
            "evt_2",
            verdict="block",
            host="b.com",
            pid=2,
            ts="2026-10-24T13:00:00+08:00",
            dim_rules=[{"id": "secret-leak", "dim": "content", "action": "block", "weight": 60}],
        )
    )
    store.append(_event("evt_3", verdict="alert", host="a.com", pid=1))

    events, total = store.query(verdict="confirm")
    assert [e.id for e in events] == ["evt_1"] and total == 1
    events, total = store.query(host="a.com")
    assert total == 2
    events, total = store.query(pid=2)
    assert [e.id for e in events] == ["evt_2"]
    events, total = store.query(dim="content")
    assert [e.id for e in events] == ["evt_2"], "dim 过滤经 event_rules 联表"
    events, total = store.query(limit=1, offset=1)
    assert total == 3 and len(events) == 1, "分页：total 为过滤后总数"

    # 时间窗口（since/until）：evt_1/evt_3 在 10-23 12:00+08:00，evt_2 在 10-24 13:00+08:00
    from datetime import timezone

    tz_cn = timezone(timedelta(hours=8))
    events, total = store.query(since=datetime(2026, 10, 24, 12, 30, tzinfo=tz_cn))
    assert [e.id for e in events] == ["evt_2"]
    events, total = store.query(until=datetime(2026, 10, 23, 23, 59, tzinfo=tz_cn))
    assert total == 2


def test_query_ordering_newest_first(store: DbEventStore) -> None:
    store.append(_event("evt_old", ts="2026-10-20T00:00:00+08:00"))
    store.append(_event("evt_new", ts="2026-10-24T00:00:00+08:00"))
    events, _ = store.query()
    assert [e.id for e in events] == ["evt_new", "evt_old"]


def test_trim_removes_old_events_and_evidence(store: DbEventStore, tmp_path: Path) -> None:
    body = b"evidence-bytes"
    digest = hashlib.sha256(body).hexdigest()
    (tmp_path / "evidence" / "evt_old.bin").write_bytes(body)
    (tmp_path / "evidence" / "evt_new.bin").write_bytes(body)
    store.append(
        _event(
            "evt_old",
            ts="2026-10-01T00:00:00+08:00",
            evidence_file="evt_old.bin",
            evidence_sha=digest,
        )
    )
    store.append(_event("evt_new", evidence_file="evt_new.bin", evidence_sha=digest))
    result = store.trim(7)
    assert result == {"events": 1, "evidence": 1}
    assert store.count() == 1
    assert store.get("evt_old") is None
    assert not (tmp_path / "evidence" / "evt_old.bin").exists()
    assert (tmp_path / "evidence" / "evt_new.bin").exists()
    with pytest.raises(ValueError):
        store.trim(-1)


def test_trim_zero_days_clears_all(store: DbEventStore) -> None:
    store.append(_event("evt_x"))
    assert store.trim(0)["events"] == 1


def test_verify_evidence_detects_missing_and_corrupted(store: DbEventStore, tmp_path: Path) -> None:
    good = b"good"
    (tmp_path / "evidence" / "evt_ok.bin").write_bytes(good)
    (tmp_path / "evidence" / "evt_bad.bin").write_bytes(b"tampered")
    store.append(
        _event("evt_ok", evidence_file="evt_ok.bin", evidence_sha=hashlib.sha256(good).hexdigest())
    )
    store.append(
        _event(
            "evt_bad",
            evidence_file="evt_bad.bin",
            evidence_sha=hashlib.sha256(good).hexdigest(),
        )
    )
    store.append(_event("evt_none"))  # 无证据
    report = store.verify_evidence()
    assert report["checked"] == 2
    assert report["missing"] == {}
    assert set(report["corrupted"]) == {"evt_bad"}, "内容被篡改的文件必须被检出"
    (tmp_path / "evidence" / "evt_ok.bin").unlink()
    report = store.verify_evidence()
    assert "evt_ok" in report["missing"]
    report = store.verify_evidence(event_id="evt_bad")
    assert report["checked"] == 1 and "evt_bad" in report["corrupted"]


def test_mirror_fanout(store: DbEventStore, tmp_path: Path) -> None:
    """``--jsonl`` 双写开关：mirror 同步收到事件。"""
    from aaa.store.jsonl import JsonlEventStore

    mirror = JsonlEventStore(tmp_path / "raw")
    store.mirror = mirror
    store.append(_event("evt_m"))
    assert [e.id for e in mirror.read_all()] == ["evt_m"]


def test_poll_after_tail_cursor(store: DbEventStore) -> None:
    assert store.max_rowid() == 0
    store.append(_event("evt_1"))
    store.append(_event("evt_2"))
    cursor = store.max_rowid()
    events, cursor2 = store.poll_after(0)
    assert [e.id for e in events] == ["evt_1", "evt_2"] and cursor2 == cursor
    events, cursor3 = store.poll_after(cursor)
    assert events == [] and cursor3 == cursor
    store.append(_event("evt_3", verdict="block"))
    events, cursor4 = store.poll_after(cursor, verdict="block")
    assert [e.id for e in events] == ["evt_3"]
    events, _ = store.poll_after(cursor, verdict="confirm")
    assert events == []
    events, _ = store.poll_after(cursor, pid=999)
    assert events == []


def test_stats_aggregates(store: DbEventStore) -> None:
    store.append(
        _event(
            "evt_1",
            verdict="confirm",
            dim_rules=[{"id": "secret-leak", "dim": "content", "action": "block", "weight": 60}],
        )
    )
    store.append(_event("evt_2", verdict="allow", host="b.com"))
    stats = store.stats()
    assert stats["total"] == 2
    assert stats["by_verdict"] == {"confirm": 1, "allow": 1}
    assert stats["pending_confirm"] == 1
    assert stats["by_process"][0]["process_name"] == "node.exe"
    assert stats["by_rule"][0]["rule_id"] == "secret-leak"
    assert {row["host"] for row in stats["by_host"]} == {"api.openai.com", "b.com"}


def test_decisions_and_access_log(store: DbEventStore) -> None:
    store.append(_event("evt_c", verdict="confirm"))
    assert store.set_decision("evt_c", "allow") is True
    assert store.set_decision("evt_missing", "allow") is False
    row = store.get_row("evt_c")
    assert row["decision"] == "allow" and row["decision_ts"]
    store.log_access("evt_c", "reveal", detail="panel")
    log = store.list_access_log(event_id="evt_c")
    assert len(log) == 1 and log[0]["action"] == "reveal"
    decided = store.list_decisions()
    assert decided[0]["id"] == "evt_c"


def test_default_retention_constant() -> None:
    """02 文档 D6：保留期默认 14 天。"""
    assert DEFAULT_RETENTION_DAYS == 14


def test_parse_since_relative_and_iso() -> None:
    now = datetime.now(UTC).astimezone()
    delta = now - (parse_since("24h") or now)
    assert 23 * 3600 < delta.total_seconds() <= 25 * 3600
    assert parse_since("30m") is not None
    assert parse_since("7d") is not None
    assert parse_since("2026-10-24") == datetime(2026, 10, 24)
    assert parse_since("2026-10-24T12:00:00+08:00").hour == 12
    assert parse_since(None) is None and parse_since("") is None
    with pytest.raises(ValueError, match="无法解析时间"):
        parse_since("bogus")


def test_concurrent_append_thread_safety(store: DbEventStore) -> None:
    """mitmproxy 钩子线程写 + 主线程读不崩（check_same_thread=False + 锁）。"""
    import threading

    def worker(prefix: str) -> None:
        for i in range(20):
            store.append(_event(f"evt_{prefix}_{i}"))

    threads = [threading.Thread(target=worker, args=(str(n),)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert store.count() == 80
