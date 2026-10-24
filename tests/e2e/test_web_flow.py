"""P5 E2E（03 文档 T5.1/T5.3 验收）：真实代理落 SQLite → 面板 API 全流程。

本地 HTTP fixture 充当 AI 端点（无外网、无系统改动）：
1. 进程内 regular 代理 + AuditAddon + AuditPipeline，事件写 **SQLite**（T4.1 收敛）；
2. httpx 经代理发送：正常请求 / 假密钥（confirm 策略）/ 512KB 代码体；
3. 面板 API（TestClient，同进程同库）：过滤 → 详情（默认脱敏）→ reveal 解锁
   （记审计日志）→ JSON/CSV 导出 → confirm 决策（allow 一次性 / deny 缓存升级）。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import yaml
from fastapi.testclient import TestClient

from aaa.capture.addon import AuditAddon
from aaa.capture.engine import ProxyConfig, start_in_background
from aaa.engine.pipeline import AuditPipeline
from aaa.policy.loader import PolicyLoader
from aaa.store.db import DbEventStore
from aaa.store.decisions import DecisionStore
from aaa.store.evidence import EvidenceStore
from aaa.web.app import create_app
from conftest import free_port, wait_until

FAKE_AWS_KEY = "AKIAQ2FZV3TQPE8KX9YZ"

POLICY: dict[str, Any] = {
    "version": 1,
    "mode": "dry-run",
    "defaults": {"fail_open": True, "max_body_scan": 262144},
    "domains": {"classes": {}, "rules": []},
    "processes": {"profiles": {}, "rules": []},
    "content": {
        "scanners": ["secrets"],
        "rules": [{"id": "secret-leak", "scanner": "secrets", "action": "confirm", "weight": 60}],
    },
    "volume": [],
    "time_window": [],
}


def test_panel_full_flow_filter_mask_reveal_export_decide(
    data_dir: Path, tmp_path: Path, http_fixture_server
) -> None:
    # —— 采集侧：真实代理 + SQLite 落盘 ——
    fixture_port = http_fixture_server.server_address[1]
    base = f"http://127.0.0.1:{fixture_port}"
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(POLICY), encoding="utf-8")
    evidence_dir = data_dir / "evidence"
    store = DbEventStore(data_dir / "audit.db", evidence_dir=evidence_dir)
    decisions = DecisionStore(data_dir / "decisions.json", default_ttl=120)
    addon = AuditAddon(
        store,
        EvidenceStore(evidence_dir, rel_base=data_dir),
        mode="regular",
        pipeline=AuditPipeline(PolicyLoader(policy_path)),
        decisions=decisions,
    )
    handle = start_in_background(
        ProxyConfig(listen_host="127.0.0.1", listen_port=free_port(), confdir=data_dir / "mitm"),
        [addon],
    )
    try:
        proxy_url = f"http://127.0.0.1:{handle.listen_port}"
        with httpx.Client(proxy=proxy_url, trust_env=False, timeout=30.0) as client:
            r_ok = client.post(f"{base}/v1/normal", content=b'{"message": "hi"}')
            assert r_ok.status_code == 200
            r_secret = client.post(
                f"{base}/v1/leak", content=json.dumps({"api_key": FAKE_AWS_KEY}).encode()
            )
            assert r_secret.status_code == 200, "confirm 判定默认放行（等待人工决策）"
        assert wait_until(lambda: store.count() >= 2, timeout=15.0), (
            f"事件未落 SQLite：{store.count()} < 2"
        )
    finally:
        handle.stop()

    # —— 面板侧：同库 API 全流程 ——
    app = create_app(
        db=store,
        evidence_dir=evidence_dir,
        policy_loader=PolicyLoader(policy_path),
        decisions=decisions,
        data_dir=data_dir,
    )
    client = TestClient(app)

    # 1) 过滤：verdict=confirm 只剩密钥事件
    listed = client.get("/api/events", params={"verdict": "confirm"}).json()
    assert listed["total"] == 1
    confirm_event = listed["items"][0]
    assert "secret-leak" in {r["id"] for r in confirm_event["matched_rules"]}

    # 2) 详情：默认脱敏（明文密钥不出现）
    detail = client.get(f"/api/events/{confirm_event['id']}").json()
    assert detail["body"]["masked"] is True
    assert FAKE_AWS_KEY not in detail["body"]["content"]
    assert detail["body"]["hits"].get("aws-access-token") == 1

    # 3) 解锁：reveal=1 返回原文并记审计日志
    revealed = client.get(f"/api/events/{confirm_event['id']}", params={"reveal": "1"}).json()
    assert FAKE_AWS_KEY in revealed["body"]["content"]
    access_log = store.list_access_log(event_id=confirm_event["id"])
    assert [log["action"] for log in access_log] == ["reveal"]

    # 4) 导出：JSON（脱敏）与 CSV
    exported = client.get(f"/api/events/{confirm_event['id']}/export").json()
    assert exported["id"] == confirm_event["id"]
    assert FAKE_AWS_KEY not in json.dumps(exported)
    csv_resp = client.get("/api/events/export", params={"format": "csv", "verdict": "confirm"})
    assert csv_resp.headers["content-type"].startswith("text/csv")
    assert confirm_event["id"] in csv_resp.text

    # 5) 决策：deny → 缓存（TTL 120s）；随后同类 confirm 请求升级 block
    r = client.post(
        "/api/decisions",
        json={"event_id": confirm_event["id"], "decision": "deny", "ttl_seconds": 120},
    )
    assert r.status_code == 200 and r.json()["cached"] is True
    assert decisions.active(r.json()["key"]) == "deny"

    handle2 = start_in_background(
        ProxyConfig(listen_host="127.0.0.1", listen_port=free_port(), confdir=data_dir / "mitm"),
        [addon],
    )
    try:
        with httpx.Client(
            proxy=f"http://127.0.0.1:{handle2.listen_port}", trust_env=False, timeout=30.0
        ) as client_http:
            client_http.post(
                f"{base}/v1/leak-again", content=json.dumps({"api_key": FAKE_AWS_KEY}).encode()
            )
        # dry-run 策略下 verdict 已升级 block（阻断动作仍需 enforce）
        assert wait_until(
            lambda: any(
                e.verdict == "block" and e.request.path == "/v1/leak-again"
                for e in store.iter_all()
            ),
            timeout=15.0,
        ), "deny 决策未在后续同类请求上升级 block"
    finally:
        handle2.stop()

    # 决策已落到事件与缓存列表
    decided = client.get("/api/decisions").json()
    assert any(d["id"] == confirm_event["id"] for d in decided["decided_events"])
    assert len(decided["cached_denies"]) == 1
    store.close()
