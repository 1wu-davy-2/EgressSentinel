"""阻断执行与 addon 集成单测（03 文档 T2.1/T2.2/T3.4）。

用 mitmproxy.test.tflow 构造 flow；策略经临时 YAML 注入。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from mitmproxy.test import tflow

from aaa.attribution.table import ProcessAttributor, ProcessIdentity
from aaa.capture.addon import AuditAddon, make_block_response
from aaa.engine.pipeline import AuditPipeline
from aaa.policy.loader import PolicyLoader
from aaa.store.evidence import EvidenceStore
from aaa.store.jsonl import JsonlEventStore

BASE_POLICY: dict[str, Any] = {
    "version": 1,
    "mode": "dry-run",
    "defaults": {"fail_open": True, "max_body_scan": 65536},
    "domains": {
        "classes": {"known_ai_api": ["api.openai.com"]},
        "rules": [
            {
                "id": "domain-unknown",
                "match": {"class": "unknown"},
                "action": "alert",
                "weight": 20,
            },
            {
                "id": "domain-blocklist",
                "match": {"host_regex": r"\.mal\.com$"},
                "action": "block",
                "weight": 80,
            },
        ],
    },
    "processes": {"profiles": {}, "rules": []},
    "content": {
        "scanners": ["secrets"],
        "rules": [{"id": "secret-leak", "scanner": "secrets", "action": "block", "weight": 60}],
    },
    "volume": [],
    "time_window": [],
}


def _write_policy(tmp_path: Path, doc: dict[str, Any]) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(doc, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return path


def _make_addon(
    tmp_path: Path,
    doc: dict[str, Any] | None = None,
    *,
    attributor: ProcessAttributor | None = None,
    pinned_process: Any = None,
) -> AuditAddon:
    doc = doc if doc is not None else BASE_POLICY
    loader = PolicyLoader(_write_policy(tmp_path, doc))
    pipeline = AuditPipeline(loader)
    events = JsonlEventStore(tmp_path / "raw")
    evidence = EvidenceStore(tmp_path / "evidence", rel_base=tmp_path)
    return AuditAddon(
        events,
        evidence,
        mode="regular",
        attributor=attributor,
        pipeline=pipeline,
        pinned_process=pinned_process,
    )


def _secret_flow() -> Any:
    flow = tflow.tflow()  # 不带预设响应：阻断测试要观察 addon 合成的响应
    flow.request.host = "api.openai.com"
    flow.request.port = 443
    flow.request.method = "POST"
    flow.request.path = "/v1/chat/completions"
    flow.request.content = b'{"api_key": " AKIAQ2FZV3TQPE8KX9YZ "}'
    return flow


# ---------------------------------------------------------------- dry-run 默认


def test_dry_run_secret_hits_but_not_blocked(tmp_path: Path) -> None:
    """默认 dry-run：命中告警但请求放行（02 文档 §0）。"""
    addon = _make_addon(tmp_path)
    flow = _secret_flow()
    addon.request(flow)
    addon.response(flow)
    (event,) = addon.events.read_all()
    assert event.verdict == "block"
    assert {r["id"] for r in event.matched_rules} == {"secret-leak"}
    assert event.action_taken == "alerted"  # 未阻断
    assert flow.response is None  # 没有合成 403


def test_normal_request_is_logged(tmp_path: Path) -> None:
    addon = _make_addon(tmp_path)
    flow = _secret_flow()
    flow.request.content = b"hello world"
    addon.request(flow)
    addon.response(flow)
    (event,) = addon.events.read_all()
    assert event.verdict in ("allow", "alert")  # unknown 域首连会 alert
    assert event.action_taken in ("logged", "alerted")
    assert event.risk_score < 60


# ------------------------------------------------------------------- enforce


def test_enforce_blocks_with_403_json(tmp_path: Path) -> None:
    """enforce：block 判定合成 403 JSON（含规则 id），事件 action_taken=blocked-403。"""
    doc = json.loads(json.dumps(BASE_POLICY))
    doc["mode"] = "enforce"
    addon = _make_addon(tmp_path, doc)
    flow = _secret_flow()
    addon.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403
    body = json.loads(flow.response.content)
    assert body["aaa"] == "blocked"
    assert body["rules"] == ["secret-leak"]
    addon.response(flow)  # 合成响应也走 response 钩子落盘
    (event,) = addon.events.read_all()
    assert event.action_taken == "blocked-403"
    assert event.verdict == "block"


def test_enforce_confirm_alert_not_blocked(tmp_path: Path) -> None:
    """enforce 下 alert/confirm 只告警不阻断。"""
    doc = json.loads(json.dumps(BASE_POLICY))
    doc["mode"] = "enforce"
    addon = _make_addon(tmp_path, doc)
    flow = _secret_flow()
    flow.request.content = b"plain"
    flow.request.host = "unknown.host.example"  # unknown 首连 → domain-unknown alert
    addon.request(flow)
    assert flow.response is None  # 未被阻断
    addon.response(flow)
    (event,) = addon.events.read_all()
    assert event.verdict == "alert"
    assert event.action_taken == "alerted"


def test_policy_switch_to_enforce_via_hot_reload(tmp_path: Path) -> None:
    """mtime 热更新切换 dry-run → enforce 后阻断生效（02 文档 D4）。"""
    import os

    path = _write_policy(tmp_path, BASE_POLICY)
    loader = PolicyLoader(path)
    pipeline = AuditPipeline(loader)
    events = JsonlEventStore(tmp_path / "raw")
    evidence = EvidenceStore(tmp_path / "evidence", rel_base=tmp_path)
    addon = AuditAddon(events, evidence, mode="regular", pipeline=pipeline)

    flow = _secret_flow()
    addon.request(flow)
    assert flow.response is None  # dry-run 不阻断

    path.write_text(
        yaml.safe_dump({**BASE_POLICY, "mode": "enforce"}, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    stat = os.stat(path)
    os.utime(path, (stat.st_atime + 5, stat.st_mtime + 5))
    loader._last_check = 0.0  # 跳过 2s 轮询限频（等价于等了 2 秒）
    flow2 = _secret_flow()
    addon.request(flow2)  # pipeline.policy 触发 maybe_reload
    assert flow2.response is not None and flow2.response.status_code == 403


# ---------------------------------------------------------------- CONNECT/SNI


def test_http_connect_blocklist_blocked_in_enforce(tmp_path: Path) -> None:
    """CONNECT 阶段域名 blocklist → 403 + 事件（02 文档 D5）。"""
    doc = json.loads(json.dumps(BASE_POLICY))
    doc["mode"] = "enforce"
    addon = _make_addon(tmp_path, doc)
    flow = tflow.tflow()
    flow.request.method = "CONNECT"
    flow.request.host = "c2.evil.mal.com"
    flow.request.port = 443
    addon.http_connect(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403
    assert json.loads(flow.response.content)["rules"] == ["domain-blocklist"]
    events = addon.events.read_all()
    assert len(events) == 1
    assert events[0].action_taken == "blocked-connect"
    assert events[0].destination.host == "c2.evil.mal.com"


def test_http_connect_not_blocked_in_dry_run(tmp_path: Path) -> None:
    addon = _make_addon(tmp_path)  # dry-run
    flow = tflow.tflow()
    flow.request.method = "CONNECT"
    flow.request.host = "c2.evil.mal.com"
    addon.http_connect(flow)
    assert flow.response is None  # dry-run 不动 CONNECT
    assert addon.events.read_all() == []


def test_tls_start_client_kills_blocklisted_sni(tmp_path: Path) -> None:
    """SNI 阶段：enforce 下 blocklist 域名 → client.error + ssl_conn=None（已验证 kill 路径）。"""
    doc = json.loads(json.dumps(BASE_POLICY))
    doc["mode"] = "enforce"
    addon = _make_addon(tmp_path, doc)
    data = tflow.tclient_conn()  # 构造 TlsData 所需连接
    tls_data = _fake_tls_data(data)
    tls_data.conn.sni = "c2.evil.mal.com"
    addon.tls_start_client(tls_data)
    assert tls_data.conn.error is not None
    assert "blocklist" in tls_data.conn.error
    assert tls_data.ssl_conn is None


def test_tls_start_client_noop_in_dry_run(tmp_path: Path) -> None:
    addon = _make_addon(tmp_path)
    tls_data = _fake_tls_data(tflow.tclient_conn())
    tls_data.conn.sni = "c2.evil.mal.com"
    addon.tls_start_client(tls_data)
    assert tls_data.conn.error is None
    assert tls_data.ssl_conn is not None


class _FakeTlsData:
    """TlsData 形状的桩（conn + ssl_conn 字段）。"""

    def __init__(self, conn: Any) -> None:
        from mitmproxy import connection

        self.conn = conn
        self.ssl_conn = connection.Client(
            peername=("127.0.0.1", 1), sockname=("127.0.0.1", 2), tls=True
        )


def _fake_tls_data(conn: Any) -> Any:
    return _FakeTlsData(conn)


# ------------------------------------------------------------------ fail_open


def test_engine_exception_fail_open_allows_and_records(tmp_path: Path) -> None:
    """fail_open（默认）：引擎异常放行，事件带 error 与 action_taken=fail-open（02 文档 D5）。"""
    doc = json.loads(json.dumps(BASE_POLICY))
    doc["mode"] = "enforce"
    doc["content"]["scanners"] = ["secrets", "pii"]
    addon = _make_addon(tmp_path, doc)

    # 注入一个坏扫描器
    def boom(body: object, max_bytes: int | None = None) -> object:
        raise RuntimeError("pii scanner down")

    addon.pipeline._scanners["pii"] = boom  # type: ignore[union-attr]
    flow = _secret_flow()
    addon.request(flow)
    addon.response(flow)
    (event,) = addon.events.read_all()
    assert event.verdict == "allow"  # fail-open 放行
    assert event.error is not None and "pii scanner down" in event.error
    assert event.action_taken == "fail-open"
    assert flow.response is None  # 请求未被阻断


def test_engine_exception_fail_closed_blocks(tmp_path: Path) -> None:
    doc = json.loads(json.dumps(BASE_POLICY))
    doc["mode"] = "enforce"
    doc["defaults"] = {"fail_open": False, "max_body_scan": 65536}
    addon = _make_addon(tmp_path, doc)

    def boom(body: object, max_bytes: int | None = None) -> object:
        raise RuntimeError("secrets scanner down")

    addon.pipeline._scanners["secrets"] = boom  # type: ignore[union-attr]
    flow = _secret_flow()
    addon.request(flow)
    assert flow.response is not None and flow.response.status_code == 403
    addon.response(flow)
    (event,) = addon.events.read_all()
    assert event.verdict == "block"


# -------------------------------------------------------------------- 归因集成


class FakeTable:
    def __init__(self, mapping: dict[int, int]) -> None:
        self.mapping = mapping

    def snapshot(self) -> list[Any]:
        from aaa.attribution.table import ConnectionEntry

        return [
            ConnectionEntry(laddr_port=p, raddr_port=443, pid=pid)
            for p, pid in self.mapping.items()
        ]


class FakeReader:
    def read(self, pid: int) -> ProcessIdentity:
        return ProcessIdentity(
            pid=pid,
            name="python.exe",
            exe=r"C:\Python\python.exe",
            cmdline=("python", "-m", "agent"),
            profile="agent_cli",
        )


def test_client_connected_attributes_process_into_event(tmp_path: Path) -> None:
    """T2.1：client_connected 源端口归因 → 事件 process 字段（02 文档 D2）。"""
    attributor = ProcessAttributor(
        connection_table=FakeTable({52341: 4242}),  # type: ignore[arg-type]
        process_reader=FakeReader(),  # type: ignore[arg-type]
    )
    addon = _make_addon(tmp_path, attributor=attributor)
    flow = tflow.tflow(resp=True)
    flow.client_conn.peername = ("127.0.0.1", 52341)
    addon.client_connected(flow.client_conn)
    addon.request(flow)
    addon.response(flow)
    (event,) = addon.events.read_all()
    assert event.process is not None
    assert event.process.pid == 4242
    assert event.process.name == "python.exe"
    assert event.process.profile == "agent_cli"


def test_attribution_miss_records_unknown(tmp_path: Path) -> None:
    attributor = ProcessAttributor(
        connection_table=FakeTable({}),  # type: ignore[arg-type]
        process_reader=FakeReader(),  # type: ignore[arg-type]
    )
    addon = _make_addon(tmp_path, attributor=attributor)
    flow = tflow.tflow(resp=True)
    flow.client_conn.peername = ("127.0.0.1", 65501)
    addon.client_connected(flow.client_conn)
    addon.request(flow)
    addon.response(flow)
    (event,) = addon.events.read_all()
    assert event.process is not None
    assert event.process.pid is None
    assert event.process.name == "unknown"  # 未归因显式标记（02 文档 D2）
    assert addon.attribution_summary()["unknown_attribution"] == 1


def test_pinned_process_for_local_mode(tmp_path: Path) -> None:
    """T2.2：local --pid 原生归因直接落事件。"""
    from aaa.store.events import ProcessInfo

    pinned = ProcessInfo(pid=4321, name="target.exe", exe=r"C:\x\target.exe", profile="other")
    addon = _make_addon(tmp_path, pinned_process=pinned)
    flow = tflow.tflow(resp=True)
    addon.request(flow)
    addon.response(flow)
    (event,) = addon.events.read_all()
    assert event.process == pinned
    assert event.mode == "regular"


def test_local_mode_event_mode_field(tmp_path: Path) -> None:
    events = JsonlEventStore(tmp_path / "raw")
    evidence = EvidenceStore(tmp_path / "evidence", rel_base=tmp_path)
    addon = AuditAddon(events, evidence, mode="local")
    flow = tflow.tflow(resp=True)
    addon.request(flow)
    addon.response(flow)
    (event,) = addon.events.read_all()
    assert event.mode == "local"


# -------------------------------------------------------------- 阻断响应构造


def test_make_block_response_shape() -> None:
    from aaa.engine.verdict import MatchedRule

    resp = make_block_response([MatchedRule(id="r1", dim="content", action="block", weight=60)])
    assert resp.status_code == 403
    assert resp.headers["content-type"] == "application/json"
    body = json.loads(resp.content)
    assert body["aaa"] == "blocked"
    assert body["rules"] == ["r1"]


def test_event_carries_policy_version_and_classification(tmp_path: Path) -> None:
    addon = _make_addon(tmp_path)
    flow = _secret_flow()
    addon.request(flow)
    addon.response(flow)
    (event,) = addon.events.read_all()
    assert event.policy_version is not None and len(event.policy_version) == 4
    assert event.destination.classification == "known_ai_api"
