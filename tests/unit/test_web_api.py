"""Web 面板 API 单测（03 文档 T5.1/T5.3；httpx TestClient 测 API 层）。

覆盖：分页过滤、详情默认脱敏、reveal 解锁记审计日志、stats/policy、
JSON/CSV 导出、POST /api/decisions（allow 一次性 / deny 缓存 + TTL）、
回环监听守卫、静态页。
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from aaa.policy.loader import PolicyLoader
from aaa.store.db import DbEventStore
from aaa.store.decisions import DECISION_DENY, DecisionStore
from aaa.store.events import (
    AuditEvent,
    Destination,
    ProcessInfo,
    RequestInfo,
    new_event_id,
)
from aaa.store.evidence import EvidenceStore
from aaa.web.app import assert_loopback, create_app

SECRET = "AKIAQ2FZV3TQPE8KX9YZ"
SECRET_BODY = json.dumps({"api_key": SECRET}).encode()

POLICY_DOC: dict = {
    "version": 1,
    "mode": "dry-run",
    "domains": {
        "classes": {"known_ai_api": ["api.openai.com"]},
        "rules": [{"id": "domain-unknown", "match": {"class": "unknown"}, "action": "alert"}],
    },
}


@pytest.fixture
def env(tmp_path: Path):
    """临时事件库 + 证据目录 + 策略 + 决策缓存 → TestClient。"""
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    store = DbEventStore(tmp_path / "audit.db", evidence_dir=evidence_dir)
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(POLICY_DOC), encoding="utf-8")
    decisions = DecisionStore(tmp_path / "decisions.json", default_ttl=60)
    app = create_app(
        db=store,
        evidence_dir=evidence_dir,
        policy_loader=PolicyLoader(policy_path),
        decisions=decisions,
        data_dir=tmp_path,
    )
    yield {
        "client": TestClient(app),
        "store": store,
        "evidence_dir": evidence_dir,
        "decisions": decisions,
        "tmp_path": tmp_path,
    }
    store.close()


def _put_event(
    store: DbEventStore,
    evidence_dir: Path,
    *,
    event_id: str | None = None,
    verdict: str = "allow",
    host: str = "api.openai.com",
    pid: int | None = 4242,
    body: bytes | None = None,
    ts: str = "2026-10-24T10:00:00+08:00",
    rules: list[dict] | None = None,
    data_dir: Path | None = None,
) -> AuditEvent:
    event_id = event_id or new_event_id()
    evidence = None
    if body is not None:
        # 走真实 EvidenceStore：file 语义为相对 data_dir（decisions.md D-2026-10-24-09）
        base = data_dir if data_dir is not None else evidence_dir.parent
        evidence = EvidenceStore(base / "evidence", rel_base=base).save_body(event_id, body)
    event = AuditEvent(
        id=event_id,
        ts=ts,
        mode="regular",
        verdict=verdict,
        risk_score=60 if verdict == "confirm" else 20,
        process=ProcessInfo(pid=pid, name="node.exe", exe="C:/x/node.exe", profile="agent_cli")
        if pid
        else None,
        destination=Destination(host=host, port=443, classification="known_ai_api"),
        request=RequestInfo(
            method="POST", path="/v1/chat", content_type="application/json", size=len(body or b"")
        ),
        matched_rules=rules or [],
        evidence=evidence,
        policy_version="7f3a",
    )
    store.append(event)
    return event


# ------------------------------------------------------------------ 事件列表


def test_list_events_filters_and_pagination(env) -> None:
    store, evidence_dir = env["store"], env["evidence_dir"]
    _put_event(store, evidence_dir, event_id="e1", verdict="confirm", host="a.com", pid=1)
    _put_event(
        store,
        evidence_dir,
        event_id="e2",
        verdict="block",
        host="b.com",
        pid=2,
        ts="2026-10-24T11:00:00+08:00",
    )
    _put_event(
        store,
        evidence_dir,
        event_id="e3",
        verdict="alert",
        host="a.com",
        pid=1,
        rules=[{"id": "pii-bulk", "dim": "content"}],
    )
    client = env["client"]

    data = client.get("/api/events").json()
    assert data["total"] == 3 and len(data["items"]) == 3

    assert client.get("/api/events", params={"verdict": "confirm"}).json()["total"] == 1
    assert client.get("/api/events", params={"host": "a.com"}).json()["total"] == 2
    assert client.get("/api/events", params={"pid": 2}).json()["items"][0]["id"] == "e2"
    assert client.get("/api/events", params={"dim": "content"}).json()["items"][0]["id"] == "e3"
    # 时间过滤
    r = client.get("/api/events", params={"since": "2026-10-24T10:30:00+08:00"})
    assert [item["id"] for item in r.json()["items"]] == ["e2"]
    # 分页
    r = client.get("/api/events", params={"limit": 2, "offset": 0}).json()
    assert r["total"] == 3 and len(r["items"]) == 2
    r = client.get("/api/events", params={"limit": 2, "offset": 2}).json()
    assert len(r["items"]) == 1
    # 非法分页/时间参数
    assert client.get("/api/events", params={"limit": 0}).status_code == 422
    assert client.get("/api/events", params={"limit": 501}).status_code == 422
    assert client.get("/api/events", params={"since": "bogus"}).status_code == 400


def test_list_items_merge_decision_fields(env) -> None:
    store, evidence_dir = env["store"], env["evidence_dir"]
    _put_event(store, evidence_dir, event_id="e1", verdict="confirm")
    env["store"].set_decision("e1", "allow")
    item = env["client"].get("/api/events").json()["items"][0]
    assert item["decision"] == "allow" and item["decision_ts"]


# ------------------------------------------------------------------ 详情与脱敏


def test_detail_body_masked_by_default(env) -> None:
    store, evidence_dir = env["store"], env["evidence_dir"]
    _put_event(store, evidence_dir, event_id="e_secret", body=SECRET_BODY)
    data = env["client"].get("/api/events/e_secret").json()
    content = data["body"]["content"]
    assert SECRET not in content, "默认视图不得泄漏明文密钥（02 文档 D6）"
    assert data["body"]["masked"] is True
    assert data["body"]["hits"].get("aws-access-token") == 1
    assert data["body"]["sha256"] == hashlib.sha256(SECRET_BODY).hexdigest()


def test_detail_reveal_returns_plaintext_and_logs(env) -> None:
    store, evidence_dir = env["store"], env["evidence_dir"]
    _put_event(store, evidence_dir, event_id="e_r", body=SECRET_BODY)
    data = env["client"].get("/api/events/e_r", params={"reveal": "1"}).json()
    assert data["body"]["content"] == SECRET_BODY.decode()
    assert data["body"]["masked"] is False
    log = env["store"].list_access_log(event_id="e_r")
    assert len(log) == 1 and log[0]["action"] == "reveal", "解锁必须记审计日志（T5.1）"


def test_detail_without_body_or_missing_evidence(env) -> None:
    store, evidence_dir = env["store"], env["evidence_dir"]
    _put_event(store, evidence_dir, event_id="e_no_body", body=None)
    data = env["client"].get("/api/events/e_no_body").json()
    assert data["body"]["content"] is None
    _put_event(store, evidence_dir, event_id="e_gone", body=b"x")
    (evidence_dir / "e_gone.bin").unlink()
    data = env["client"].get("/api/events/e_gone").json()
    assert data["body"]["content"] is None and data["body"]["missing"] is True


def test_detail_404(env) -> None:
    assert env["client"].get("/api/events/nope").status_code == 404


# ------------------------------------------------------------------ 导出


def test_export_single_event_json_and_csv(env) -> None:
    store, evidence_dir = env["store"], env["evidence_dir"]
    _put_event(store, evidence_dir, event_id="e_exp", body=SECRET_BODY, verdict="confirm")
    client = env["client"]
    r = client.get("/api/events/e_exp/export")
    assert r.status_code == 200
    payload = r.json()
    assert payload["id"] == "e_exp"
    assert SECRET not in r.text, "导出默认同样脱敏"

    r = client.get("/api/events/e_exp/export", params={"format": "csv"})
    assert "text/csv" in r.headers["content-type"]
    lines = r.text.strip().splitlines()
    assert lines[0].startswith("id,ts,mode,verdict")
    assert "e_exp" in lines[1]


def test_export_list_csv_and_json(env) -> None:
    store, evidence_dir = env["store"], env["evidence_dir"]
    _put_event(store, evidence_dir, event_id="e1", verdict="block")
    _put_event(store, evidence_dir, event_id="e2", verdict="block")
    client = env["client"]
    r = client.get("/api/events/export", params={"format": "csv", "verdict": "block"})
    assert len(r.text.strip().splitlines()) == 3, "表头 + 2 行"
    r = client.get("/api/events/export", params={"format": "json", "verdict": "block"})
    payload = r.json()
    assert payload["total"] == 2 and payload["exported"] == 2
    assert client.get("/api/events/export", params={"format": "xml"}).status_code == 422


# ------------------------------------------------------------------ 统计与策略


def test_stats_endpoint(env) -> None:
    store, evidence_dir = env["store"], env["evidence_dir"]
    _put_event(store, evidence_dir, event_id="e1", verdict="confirm")
    _put_event(store, evidence_dir, event_id="e2", verdict="allow", host="b.com")
    stats = env["client"].get("/api/stats").json()
    assert stats["total"] == 2
    assert stats["by_verdict"] == {"confirm": 1, "allow": 1}
    assert stats["pending_confirm"] == 1
    assert stats["by_rule"] == []  # 本测试数据无命中规则
    assert stats["by_process"][0]["process_name"] == "node.exe"
    assert env["client"].get("/api/stats", params={"since": "bad"}).status_code == 400


def test_policy_endpoint(env) -> None:
    data = env["client"].get("/api/policy").json()
    assert data["mode"] == "dry-run"
    assert data["policy_version"]
    assert data["rule_count"] == 1
    assert data["document"]["domains"]["classes"]["known_ai_api"] == ["api.openai.com"]


def test_policy_endpoint_404_without_loader(tmp_path: Path) -> None:
    store = DbEventStore(tmp_path / "a.db")
    app = create_app(db=store, evidence_dir=tmp_path, policy_loader=None)
    client = TestClient(app)
    assert client.get("/api/policy").status_code == 404
    store.close()


# ------------------------------------------------------------------ 决策 T5.3


def test_decision_allow_is_one_shot(env) -> None:
    store, evidence_dir = env["store"], env["evidence_dir"]
    event = _put_event(store, evidence_dir, event_id="e_c", verdict="confirm")
    r = env["client"].post("/api/decisions", json={"event_id": event.id, "decision": "allow"})
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "allow" and body["cached"] is False
    assert store.get_row(event.id)["decision"] == "allow"
    assert env["decisions"].list_active() == [], "allow 一次性，不进缓存"


def test_decisiondeny_caches_with_ttl(env) -> None:
    store, evidence_dir = env["store"], env["evidence_dir"]
    event = _put_event(
        store,
        evidence_dir,
        event_id="e_d",
        verdict="confirm",
        rules=[{"id": "secret-leak", "dim": "content", "action": "confirm", "weight": 60}],
    )
    r = env["client"].post(
        "/api/decisions",
        json={"event_id": event.id, "decision": "deny", "ttl_seconds": 120},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["cached"] is True and body["ttl_seconds"] == 120
    assert body["key"] == f"{event.destination.host}|secret-leak"
    active = env["decisions"].list_active()
    assert len(active) == 1 and active[0]["decision"] == DECISION_DENY
    assert store.get_row(event.id)["decision"] == "deny"
    assert store.list_access_log(event_id=event.id)[0]["action"] == "decision"


def test_decision_rejects_non_confirm_and_missing(env) -> None:
    store, evidence_dir = env["store"], env["evidence_dir"]
    allow_event = _put_event(store, evidence_dir, event_id="e_ok", verdict="allow")
    assert (
        env["client"]
        .post("/api/decisions", json={"event_id": allow_event.id, "decision": "deny"})
        .status_code
        == 409
    )
    assert (
        env["client"]
        .post("/api/decisions", json={"event_id": "missing", "decision": "deny"})
        .status_code
        == 404
    )
    assert (
        env["client"]
        .post("/api/decisions", json={"event_id": "x", "decision": "maybe"})
        .status_code
        == 422
    )


def test_decisions_listing_endpoint(env) -> None:
    store, evidence_dir = env["store"], env["evidence_dir"]
    event = _put_event(store, evidence_dir, event_id="e_c", verdict="confirm")
    env["client"].post("/api/decisions", json={"event_id": event.id, "decision": "deny"})
    data = env["client"].get("/api/decisions").json()
    assert data["decided_events"][0]["id"] == event.id
    assert len(data["cached_denies"]) == 1


# ------------------------------------------------------------------ 边界


def test_assert_loopback_guard() -> None:
    """03 文档 T5.1：面板仅监听 127.0.0.1。"""
    for host in ("127.0.0.1", "localhost", "::1"):
        assert_loopback(host)
    with pytest.raises(ValueError, match="本地回环"):
        assert_loopback("0.0.0.0")
    with pytest.raises(ValueError):
        assert_loopback("192.168.1.5")


def test_index_page_served(env) -> None:
    r = env["client"].get("/")
    assert r.status_code == 200
    assert "AI-AGENT-AUDIT" in r.text
    r = env["client"].get("/static/app.js")
    assert r.status_code == 200 and "currentFilters" in r.text
    assert env["client"].get("/static/style.css").status_code == 200
    assert env["client"].get("/static/..%2Fapp.py").status_code in (404, 1004)
    assert env["client"].get("/static/nope.js").status_code == 404
