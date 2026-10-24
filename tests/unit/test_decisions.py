"""confirm 决策流单测（03 文档 T5.3）：DecisionStore TTL 语义 + addon 升级集成。"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from mitmproxy.test import tflow

from aaa.capture.addon import AuditAddon
from aaa.engine.pipeline import AuditPipeline
from aaa.policy.loader import PolicyLoader
from aaa.store.db import DbEventStore
from aaa.store.decisions import (
    DECISION_ALLOW,
    DECISION_DENY,
    DEFAULT_DECISION_TTL_SECONDS,
    DecisionStore,
    decision_key,
)
from aaa.store.evidence import EvidenceStore

CONFIRM_POLICY: dict = {
    "version": 1,
    "mode": "enforce",
    "defaults": {"fail_open": True, "max_body_scan": 65536},
    "domains": {"classes": {}, "rules": []},
    "processes": {"profiles": {}, "rules": []},
    "content": {
        "scanners": ["secrets"],
        "rules": [{"id": "secret-leak", "scanner": "secrets", "action": "confirm", "weight": 60}],
    },
    "volume": [],
    "time_window": [],
}


def _policy_path(tmp_path: Path) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(CONFIRM_POLICY), encoding="utf-8")
    return path


def _make_addon(tmp_path: Path, decisions: DecisionStore | None) -> AuditAddon:
    store = DbEventStore(tmp_path / "audit.db", evidence_dir=tmp_path / "evidence")
    addon = AuditAddon(
        store,
        EvidenceStore(tmp_path / "evidence", rel_base=tmp_path),
        mode="regular",
        pipeline=AuditPipeline(PolicyLoader(_policy_path(tmp_path))),
        decisions=decisions,
    )
    addon._test_store = store  # type: ignore[attr-defined]  # 测试取事件用
    return addon


def _secret_flow(path: str = "/v1/chat") -> object:
    flow = tflow.tflow(resp=True)
    flow.request.path = path
    flow.request.content = b'{"api_key": "AKIAQ2FZV3TQPE8KX9YZ"}'
    return flow


def test_decision_key_is_host_plus_sorted_rules() -> None:
    assert decision_key("API.Example.com.", ["b-rule", "a-rule"]) == "api.example.com|a-rule,b-rule"
    assert decision_key("api.example.com", ["b", "a"]) == decision_key(
        "api.example.com", ["a", "b"]
    )


def test_decision_store_set_active_expiry(tmp_path: Path) -> None:
    store = DecisionStore(tmp_path / "decisions.json")
    key = "api.example.com|secret-leak"
    entry = store.set(key, DECISION_DENY, ttl_seconds=60)
    assert entry["ttl_seconds"] == 60
    assert store.active(key) == DECISION_DENY
    assert [d["key"] for d in store.list_active()] == [key]
    # 重复 set 同 key 覆盖（不累积）
    store.set(key, DECISION_DENY, ttl_seconds=1)
    assert len(store.list_active()) == 1
    # 过期：惰性清除
    expired = datetime.now(UTC).astimezone() - timedelta(seconds=5)
    store.set(key, DECISION_DENY, ttl_seconds=10, now=expired - timedelta(seconds=20))
    assert store.active(key, now=datetime.now(UTC).astimezone() + timedelta(seconds=30)) is None
    assert store.list_active() == []
    # allow 不入缓存（一次性）
    with pytest.raises(ValueError):
        store.set(key, DECISION_ALLOW)
    assert store.active("other|key") is None


def test_decision_store_persists_across_instances(tmp_path: Path) -> None:
    """采集进程与面板进程分离：文件持久化 + mtime 感知。"""
    path = tmp_path / "decisions.json"
    first = DecisionStore(path)
    first.set("h|k", DECISION_DENY, ttl_seconds=100)
    second = DecisionStore(path)
    assert second.active("h|k") == DECISION_DENY
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["decisions"][0]["decision"] == "deny"


def test_decision_store_default_ttl(tmp_path: Path) -> None:
    store = DecisionStore(tmp_path / "d.json")
    assert store.default_ttl == DEFAULT_DECISION_TTL_SECONDS == 3600
    entry = store.set("h|k", DECISION_DENY)
    assert entry["ttl_seconds"] == 3600


def test_addon_deny_decision_upgrades_confirm_to_block(tmp_path: Path) -> None:
    """用户拒绝后：TTL 内同类请求 verdict 升级 block（enforce 下 403）。"""
    decisions = DecisionStore(tmp_path / "decisions.json")
    addon = _make_addon(tmp_path, decisions)

    flow = _secret_flow()
    addon.request(flow)  # type: ignore[attr-defined]
    addon.response(flow)  # type: ignore[attr-defined]
    (event,) = addon._test_store.latest(1)  # type: ignore[attr-defined]
    assert event.verdict == "confirm", "无决策时 confirm 只告警"
    assert flow.response.status_code == 200  # type: ignore[attr-defined]

    key = decision_key(event.destination.host, [r["id"] for r in event.matched_rules])
    decisions.set(key, DECISION_DENY, ttl_seconds=300)

    flow2 = _secret_flow()
    addon.request(flow2)  # type: ignore[attr-defined]
    addon.response(flow2)  # type: ignore[attr-defined]
    (event2,) = [e for e in addon._test_store.latest(2) if e.id != event.id]  # type: ignore[attr-defined]
    assert event2.verdict == "block", "缓存 deny 必须升级为 block"
    assert "decision-deny" in {r["id"] for r in event2.matched_rules}
    assert flow2.response.status_code == 403, "enforce 模式下升级 block 必须事中 403"  # type: ignore[attr-defined]
    assert event2.action_taken == "blocked-403"


def test_addon_allow_decision_is_one_shot(tmp_path: Path) -> None:
    """允许是一次性：只记事件，不缓存——后续同类请求再次 confirm。"""
    addon = _make_addon(tmp_path, DecisionStore(tmp_path / "decisions.json"))
    flow = _secret_flow()
    addon.request(flow)  # type: ignore[attr-defined]
    addon.response(flow)  # type: ignore[attr-defined]
    (event,) = addon._test_store.latest(1)  # type: ignore[attr-defined]
    assert event.verdict == "confirm"
    addon._test_store.set_decision(event.id, DECISION_ALLOW)  # type: ignore[attr-defined]
    # 无缓存条目 → 下一个同类请求仍 confirm
    flow2 = _secret_flow()
    addon.request(flow2)  # type: ignore[attr-defined]
    addon.response(flow2)  # type: ignore[attr-defined]
    events = addon._test_store.latest(2)  # type: ignore[attr-defined]
    assert all(e.verdict == "confirm" for e in events)


def test_addon_without_decisions_store_keeps_confirm(tmp_path: Path) -> None:
    addon = _make_addon(tmp_path, None)
    flow = _secret_flow()
    addon.request(flow)  # type: ignore[attr-defined]
    addon.response(flow)  # type: ignore[attr-defined]
    (event,) = addon._test_store.latest(1)  # type: ignore[attr-defined]
    assert event.verdict == "confirm"
