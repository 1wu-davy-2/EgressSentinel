"""store 层单测：事件模型、JSONL 直写、证据截断（03 文档 T1.2）。"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path

from aaa.config import DEFAULT_BODY_EVIDENCE_LIMIT
from aaa.store.events import AuditEvent, Destination, RequestInfo, new_event_id
from aaa.store.evidence import EvidenceStore
from aaa.store.jsonl import JsonlEventStore


def _make_event() -> AuditEvent:
    return AuditEvent(
        id=new_event_id(),
        ts="2026-10-24T12:34:56.789+08:00",
        mode="regular",
        destination=Destination(host="api.example.com", port=443),
        request=RequestInfo(
            method="POST", path="/v1/chat", content_type="application/json", size=1234
        ),
    )


def test_new_event_id_unique_and_sorted() -> None:
    ids = [new_event_id() for _ in range(1000)]
    assert len(set(ids)) == 1000
    assert all(i.startswith("evt_") for i in ids)
    # 毫秒时间戳前缀非递减（同毫秒内随机尾导致整体无严格序）
    stamps = [int(i[4:17]) for i in ids]
    assert stamps == sorted(stamps)


def test_jsonl_write_and_read_roundtrip(data_dir: Path) -> None:
    store = JsonlEventStore(data_dir / "raw")
    event = _make_event()
    path = store.append(event, now=datetime(2026, 10, 24, 12, 0, 0))
    assert path.name == "20261024.jsonl"  # data/raw/YYYYMMDD.jsonl
    raw_line = json.loads(path.read_text(encoding="utf-8").strip())
    assert raw_line["id"] == event.id
    assert raw_line["destination"]["host"] == "api.example.com"
    events = store.read_all()
    assert len(events) == 1
    assert events[0].model_dump() == event.model_dump()


def test_jsonl_append_across_days(data_dir: Path) -> None:
    store = JsonlEventStore(data_dir / "raw")
    store.append(_make_event(), now=datetime(2026, 10, 23, 23, 59, 59))
    store.append(_make_event(), now=datetime(2026, 10, 24, 0, 0, 1))
    assert sorted(p.name for p in (data_dir / "raw").glob("*.jsonl")) == [
        "20261023.jsonl",
        "20261024.jsonl",
    ]


def test_evidence_save_small_body(data_dir: Path) -> None:
    store = EvidenceStore(data_dir / "evidence", rel_base=data_dir)
    body = b"request-body-123"
    info = store.save_body("evt_x", body)
    assert info.file is not None
    assert info.sha256 == hashlib.sha256(body).hexdigest()
    assert info.truncated is False
    assert info.size == len(body)
    file_path = data_dir / info.file
    assert file_path.read_bytes() == body


def test_evidence_truncates_to_default_limit(data_dir: Path) -> None:
    store = EvidenceStore(data_dir / "evidence", rel_base=data_dir)
    big = b"A" * (DEFAULT_BODY_EVIDENCE_LIMIT + 1024)
    info = store.save_body("evt_big", big)
    assert info.truncated is True
    assert info.size == DEFAULT_BODY_EVIDENCE_LIMIT
    assert info.original_size == len(big)
    file_path = data_dir / info.file
    assert file_path.stat().st_size == DEFAULT_BODY_EVIDENCE_LIMIT
    assert info.sha256 == hashlib.sha256(big[:DEFAULT_BODY_EVIDENCE_LIMIT]).hexdigest()


def test_evidence_empty_body_no_file(data_dir: Path) -> None:
    store = EvidenceStore(data_dir / "evidence", rel_base=data_dir)
    info = store.save_body("evt_empty", None)
    assert info.sha256 is None and info.file is None


def test_event_model_matches_design_fields() -> None:
    """02 文档 §6 关键字段存在。"""
    event = _make_event()
    data = json.loads(event.model_dump_json())
    for key in (
        "id",
        "ts",
        "mode",
        "verdict",
        "risk_score",
        "process",
        "destination",
        "request",
        "matched_rules",
        "action_taken",
        "evidence",
    ):
        assert key in data
    assert data["destination"]["classification"] == "unknown"


def test_audit_event_rejects_missing_destination() -> None:
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        AuditEvent(id="evt_x", ts="t", mode="regular")  # type: ignore[call-arg]


def test_event_id_format() -> None:
    assert re.fullmatch(r"evt_\d+[0-9a-f]+\d", new_event_id())
