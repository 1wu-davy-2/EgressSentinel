"""多机聚合单测（06 文档 W8）。

红线：**严禁真实网络**——Forwarder 的 httpx 客户端全部注入假实现/ASGITransport
（进程内往返，不建 socket）；hub 中心用 fastapi TestClient（进程内）；
不触碰系统设置，token 比对不依赖环境（AAA_HUB_* 环境变量隔离清空）。

覆盖：summarize_event 脱敏（密钥不外发）/ 配置与环境变量覆盖 / Forwarder
批量 ≤50、重试、重试耗尽丢弃、队列溢出丢弃、close 后忽略入队 /
collector 鉴权拒绝（Bearer 头 + body token）/ 校验拒绝 / 内存缓冲→SQLite
落盘与重启存活 / 跨机器聚合统计 / Forwarder→collector 全链路往返。
"""

from __future__ import annotations

import json
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from aaa.hub.collector import HubAuthError, HubCollector, IngestEnvelope, create_hub_app
from aaa.hub.forwarder import (
    HUB_TIMEOUT_SECONDS,
    MAX_BATCH_SIZE,
    Forwarder,
    build_forwarder,
    default_hub_client_factory,
    summarize_event,
)
from aaa.hub.model import HUB_TOKEN_ENV, HUB_URL_ENV, HubConfig, apply_env_overrides
from aaa.store.events import (
    AuditEvent,
    Destination,
    EvidenceInfo,
    ProcessInfo,
    RequestInfo,
)

#: 假 AWS 密钥（形似真钥、非官方示例 allowlist，专供测试；与 test_notify 同源）
FAKE_AWS_KEY = "AKIAQ2FZV3TQPE8KX9YZ"

#: hub 共享令牌（测试专用）
TOKEN = "hub-test-token"

#: 假机器名
MACHINE_A = "machine-a"
MACHINE_B = "machine-b"


@pytest.fixture(autouse=True)
def _clean_hub_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """隔离 AAA_HUB_* 环境变量：配置类测试不受本机环境影响。"""
    monkeypatch.delenv(HUB_URL_ENV, raising=False)
    monkeypatch.delenv(HUB_TOKEN_ENV, raising=False)


def _event(**overrides: object) -> AuditEvent:
    """构造测试事件（可覆盖字段）。"""
    fields: dict[str, object] = {
        "id": "evt_test1",
        "ts": "2026-10-24T12:00:00.000+08:00",
        "mode": "regular",
        "verdict": "block",
        "risk_score": 80,
        "process": ProcessInfo(pid=1234, name="node.exe", profile="agent_cli"),
        "destination": Destination(host="api.openai.com", port=443),
        "request": RequestInfo(method="POST", path="/v1/chat", size=100),
    }
    fields.update(overrides)
    return AuditEvent(**fields)  # type: ignore[arg-type]


def _event_payload(**overrides: object) -> dict[str, Any]:
    """agent 端真实产物形态的事件摘要（summarize_event 输出）。"""
    return summarize_event(_event(**overrides))


def _envelope(
    events: list[dict[str, Any]],
    *,
    host: str = MACHINE_A,
    token: str = TOKEN,
) -> dict[str, Any]:
    """构造 ``POST /ingest`` 请求体（W8：``{token, host, events}``）。"""
    return {"token": token, "host": host, "events": events}


def _wait_until(predicate: Any, timeout: float = 5.0) -> bool:
    """轮询等待条件成立（线程时序同步用；超时返回 False 不抛出）。"""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


class FakeHubClient:
    """假 hub 客户端：记录请求；按脚本返回状态码/抛异常；可选阻塞门。"""

    def __init__(
        self,
        script: list[int | Exception] | None = None,
        *,
        gate: threading.Event | None = None,
    ) -> None:
        self.requests: list[dict[str, Any]] = []
        self.script = list(script or [])
        self.gate = gate

    def post(self, url: str, json: Any = None, headers: Any = None) -> Any:
        self.requests.append({"url": url, "json": json, "headers": headers})
        if self.gate is not None:
            self.gate.wait(timeout=10)
        item: int | Exception = self.script.pop(0) if self.script else 200
        if isinstance(item, Exception):
            raise item
        return FakeResponse(item)

    def close(self) -> None:
        self.closed = True


class FakeResponse:
    """假响应：只带 status_code（Forwarder 只看它）。"""

    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


# ==========================================================================
# summarize_event：脱敏红线
# ==========================================================================


def test_summarize_event_masks_secrets() -> None:
    """路径查询串/evidence/进程字段里的密钥必须打码后才外发（W8 红线）。"""
    event = _event(
        request=RequestInfo(method="POST", path=f"/v1/chat?key={FAKE_AWS_KEY}", size=10),
        process=ProcessInfo(pid=1, name="node.exe", exe=f"C:\\tmp\\x\\{FAKE_AWS_KEY}.exe"),
        matched_rules=[
            {"id": "aws-key", "dim": "secrets", "evidence": FAKE_AWS_KEY, "weight": 80,
             "internal_field": "should-not-leak"},
        ],
    )
    data = summarize_event(event)
    dumped = json.dumps(data, ensure_ascii=False)
    assert FAKE_AWS_KEY not in dumped
    assert "⟦" in data["request"]["path"]  # 已按同一核心打码
    # 摘要文本存在且不含明文密钥
    assert data["summary"]
    assert FAKE_AWS_KEY not in data["summary"]
    # matched_rules 白名单化：保留已知字段、evidence 已打码、内部字段被剥除
    rule = data["matched_rules"][0]
    assert rule["id"] == "aws-key" and "internal_field" not in rule
    assert FAKE_AWS_KEY not in rule["evidence"]


def test_summarize_event_drops_evidence_and_filters_judge_note() -> None:
    """evidence 文件指向 agent 本机路径不外发；judge_note 只留结构化白名单。"""
    event = _event(
        evidence=EvidenceInfo(file="evidence/local-only.bin", sha256="a" * 64, size=10),
        judge_note={
            "status": "ok",
            "is_violation": True,
            "confidence": 0.9,
            "category": "secrets",
            "reason": f"模型理由可能引用请求内容 {FAKE_AWS_KEY}",
        },
    )
    data = summarize_event(event)
    assert "evidence" not in data
    assert set(data["judge_note"]) == {"status", "is_violation", "confidence", "category"}
    assert FAKE_AWS_KEY not in json.dumps(data, ensure_ascii=False)


# ==========================================================================
# 配置模型与环境变量覆盖
# ==========================================================================


def test_hub_config_defaults_and_strictness() -> None:
    """缺省=关、batch_size 上限 50 是 schema 红线、未知字段拒绝。"""
    config = HubConfig()
    assert config.enabled is False
    assert config.url == "" and config.token == ""
    assert config.batch_size == MAX_BATCH_SIZE == 50
    assert config.timeout == HUB_TIMEOUT_SECONDS == 3.0
    with pytest.raises(ValidationError):
        HubConfig(batch_size=51)  # W8 红线：≤50 条/次
    with pytest.raises(ValidationError):
        HubConfig(batch_size=0)
    with pytest.raises(ValidationError):
        HubConfig(unknown_field=1)


def test_apply_env_overrides_priority_and_trial_intent() -> None:
    """环境变量 > 策略文件；试用意图仅在策略从未配置 url+token 时生效。"""
    # 环境变量覆盖策略值
    config = apply_env_overrides(
        HubConfig(url="http://policy:1", token="policy-t", enabled=True),
        {HUB_URL_ENV: "http://env:2", HUB_TOKEN_ENV: "env-t"},
    )
    assert config.url == "http://env:2" and config.token == "env-t" and config.enabled
    # 显式 enabled=false + 策略已配置 → 环境变量补值也不启用（显式关闭获胜）
    config = apply_env_overrides(
        HubConfig(url="http://policy:1", token="policy-t", enabled=False),
        {HUB_URL_ENV: "http://env:2", HUB_TOKEN_ENV: "env-t"},
    )
    assert config.enabled is False
    # 策略从未配置：env 补齐 url+token → 试用意图自动启用（D-33 收窄版）
    config = apply_env_overrides(
        HubConfig(), {HUB_URL_ENV: "http://env:2", HUB_TOKEN_ENV: "env-t"}
    )
    assert config.enabled is True
    # 策略从未配置但 env 只给 url → 不启用（差 token 的 forwarder 只会 401 空转）
    config = apply_env_overrides(HubConfig(), {HUB_URL_ENV: "http://env:2"})
    assert config.enabled is False
    # 空串视同未设置
    config = apply_env_overrides(
        HubConfig(url="http://policy:1", token="t"), {HUB_URL_ENV: "  ", HUB_TOKEN_ENV: ""}
    )
    assert config.url == "http://policy:1" and config.token == "t"


def test_build_forwarder_guards() -> None:
    """未启用/配置不全 → None；url/token 缺失、batch_size 越界 → ValueError。"""
    assert build_forwarder(HubConfig()) is None
    assert build_forwarder(HubConfig(enabled=True)) is None
    assert build_forwarder(HubConfig(enabled=True, url="http://hub")) is None
    forwarder = build_forwarder(HubConfig(enabled=True, url="http://hub/", token="t"))
    assert forwarder is not None
    assert forwarder.stats()["url"] == "http://hub/"
    with pytest.raises(ValueError):
        Forwarder("", "t")
    with pytest.raises(ValueError):
        Forwarder("http://hub", "")
    with pytest.raises(ValueError):
        Forwarder("http://hub", "t", batch_size=51)


def test_default_hub_client_factory() -> None:
    """生产工厂：trust_env=False 直连（防回环）+ 默认 3s 超时。"""
    client = default_hub_client_factory()
    try:
        assert client.trust_env is False  # type: ignore[attr-defined]
        assert client.timeout.connect == HUB_TIMEOUT_SECONDS
    finally:
        client.close()


# ==========================================================================
# Forwarder：批量 / 重试 / 丢弃
# ==========================================================================


def test_forwarder_batches_limited_to_50() -> None:
    """120 条事件按 ≤50 条/次分批（50/50/20），payload 形态与鉴权头正确。"""
    fake = FakeHubClient()
    forwarder = Forwarder(
        "http://hub.test",
        TOKEN,
        hostname=MACHINE_A,
        client_factory=lambda: fake,
        sleeper=lambda _s: None,
    )
    events = [_event(id=f"evt_{i}") for i in range(120)]
    # 持发送锁期间批量入队：worker 尚未消费，保证批边界确定为 50/50/20
    with forwarder._send_lock:  # noqa: SLF001 - 时序确定性需要
        for event in events:
            forwarder.enqueue(event)
    forwarder.flush(timeout=10.0)
    assert len(fake.requests) == 3
    assert [len(req["json"]["events"]) for req in fake.requests] == [50, 50, 20]
    stats = forwarder.stats()
    assert stats["sent_events"] == 120
    assert stats["sent_batches"] == 3
    assert stats["dropped"] == 0
    # wire 形态（D-2026-10-25-47）：基地址 + /ingest、Bearer 头、body 三字段
    request = fake.requests[0]
    assert request["url"] == "http://hub.test/ingest"
    assert request["headers"]["Authorization"] == f"Bearer {TOKEN}"
    assert request["json"]["token"] == TOKEN
    assert request["json"]["host"] == MACHINE_A
    assert request["json"]["events"][0]["id"].startswith("evt_")


def test_forwarder_retry_then_success() -> None:
    """网络异常与 5xx 均重试（带退避），最终成功计数正确。"""
    fake = FakeHubClient([ConnectionError("boom"), 500, 200])
    sleeps: list[float] = []
    forwarder = Forwarder(
        "http://hub.test",
        TOKEN,
        hostname=MACHINE_A,
        client_factory=lambda: fake,
        retries=2,
        retry_backoff=0.5,
        sleeper=sleeps.append,
    )
    forwarder.enqueue(_event(id="evt_1"))
    forwarder.flush(timeout=10.0)
    assert len(fake.requests) == 3
    assert sleeps == [0.5, 1.0]  # 线性退避
    stats = forwarder.stats()
    assert stats["sent_events"] == 1
    assert stats["retries_used"] == 2
    assert stats["dropped"] == 0
    assert stats["last_error"] is None


def test_forwarder_drops_batch_after_retries_exhausted() -> None:
    """重试耗尽：整批丢弃计数、记录 last_error，绝不向上抛。"""
    fake = FakeHubClient([503, 503, 503])
    forwarder = Forwarder(
        "http://hub.test",
        TOKEN,
        hostname=MACHINE_A,
        client_factory=lambda: fake,
        retries=2,
        retry_backoff=0.0,
        sleeper=lambda _s: None,
    )
    forwarder.enqueue(_event(id="evt_1"))
    forwarder.flush(timeout=10.0)  # 不抛出即通过
    assert len(fake.requests) == 3
    stats = forwarder.stats()
    assert stats["dropped"] == 1
    assert stats["send_errors"] == 1
    assert stats["sent_events"] == 0
    assert stats["last_error"] is not None and "503" in stats["last_error"]


def test_forwarder_client_factory_failure_does_not_kill_worker() -> None:
    """客户端工厂本身抛异常：按一次失败处理，重试后成功。"""
    fake = FakeHubClient([200])
    calls = {"n": 0}

    def flaky_factory() -> FakeHubClient:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("factory boom")
        return fake

    forwarder = Forwarder(
        "http://hub.test",
        TOKEN,
        hostname=MACHINE_A,
        client_factory=flaky_factory,
        retries=1,
        retry_backoff=0.0,
        sleeper=lambda _s: None,
    )
    forwarder.enqueue(_event(id="evt_1"))
    forwarder.flush(timeout=10.0)
    assert calls["n"] == 2
    assert forwarder.stats()["sent_events"] == 1


def test_forwarder_queue_full_drops_and_counts() -> None:
    """队列满：丢弃计数、永不阻塞入队方（审计主路径红线）。"""
    gate = threading.Event()
    fake = FakeHubClient(gate=gate)
    forwarder = Forwarder(
        "http://hub.test",
        TOKEN,
        hostname=MACHINE_A,
        client_factory=lambda: fake,
        max_queue=1,
        sleeper=lambda _s: None,
    )
    forwarder.enqueue(_event(id="evt_a"))  # worker 取走后阻塞在 post（gate）
    assert _wait_until(lambda: bool(fake.requests))
    forwarder.enqueue(_event(id="evt_b"))  # 占满队列（maxsize=1）
    forwarder.enqueue(_event(id="evt_c"))  # 溢出 → 丢弃计数
    gate.set()
    assert _wait_until(lambda: forwarder.stats()["sent_events"] == 2)
    forwarder.flush(timeout=5.0)
    stats = forwarder.stats()
    assert stats["dropped"] == 1
    assert stats["sent_events"] == 2
    assert stats["queue_size"] == 0
    forwarder.close()


def test_forwarder_ignores_enqueue_after_close() -> None:
    """close 后 enqueue 被忽略（关闭哨兵语义，同 notify dispatcher）。"""
    gate = threading.Event()
    fake = FakeHubClient(gate=gate)
    forwarder = Forwarder(
        "http://hub.test", TOKEN, hostname=MACHINE_A, client_factory=lambda: fake
    )
    forwarder.enqueue(_event(id="evt_a"))  # worker 取走，阻塞在 post
    assert _wait_until(lambda: bool(fake.requests))
    forwarder.close(timeout=0.3)  # worker 仍在 post 里，join 超时即返回
    forwarder.enqueue(_event(id="evt_b"))  # closing → 忽略
    gate.set()
    assert _wait_until(lambda: forwarder.stats()["sent_events"] == 1)
    assert forwarder.stats()["queue_size"] == 0
    assert forwarder.stats()["dropped"] == 0


# ==========================================================================
# HubCollector：鉴权 / 校验 / 缓冲落盘
# ==========================================================================


@pytest.fixture
def hub(tmp_path: Path):
    """临时 hub 中心：collector（阈值=2）+ TestClient（进程内，零真实网络）。"""
    collector = HubCollector(tmp_path / "hub.db", TOKEN, flush_threshold=2)
    client = TestClient(create_hub_app(collector))
    yield {"collector": collector, "client": client, "tmp_path": tmp_path}
    collector.close()


def _bearer(token: str = TOKEN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_ingest_auth_rejections(hub) -> None:
    """Bearer 头缺失/伪造/.scheme 错、body token 不匹配 → 一律 401。"""
    payload = _event_payload(id="evt_auth")
    # 无 Authorization 头
    response = hub["client"].post("/ingest", json=_envelope([payload]))
    assert response.status_code == 401
    assert "Bearer" in response.headers.get("www-authenticate", "")
    # 错误令牌
    response = hub["client"].post("/ingest", json=_envelope([payload]), headers=_bearer("wrong"))
    assert response.status_code == 401
    # 非 Bearer scheme
    response = hub["client"].post(
        "/ingest",
        json=_envelope([payload]),
        headers={"Authorization": f"Basic {TOKEN}"},
    )
    assert response.status_code == 401
    # 头正确但 body token 与 hub 配置不匹配（双重要求，D-2026-10-25-47）
    response = hub["client"].post(
        "/ingest",
        json=_envelope([payload], token="mismatch"),
        headers=_bearer(),
    )
    assert response.status_code == 401
    # collector 直连同样拒绝
    with pytest.raises(HubAuthError):
        hub["collector"].ingest(
            IngestEnvelope.model_validate(_envelope([payload], token="mismatch"))
        )
    assert hub["collector"].counters()["accepted"] == 0


def test_ingest_rejects_malformed_payloads(hub) -> None:
    """空 events / 缺 id / 未知顶层字段 / 超过单次上限 → 422。"""
    # 空 events
    response = hub["client"].post(
        "/ingest", json={"token": TOKEN, "host": MACHINE_A, "events": []}, headers=_bearer()
    )
    assert response.status_code == 422
    # 事件缺 id
    response = hub["client"].post(
        "/ingest",
        json={
            "token": TOKEN,
            "host": MACHINE_A,
            "events": [{"ts": "2026-10-25T00:00:00+08:00"}],
        },
        headers=_bearer(),
    )
    assert response.status_code == 422
    # 未知顶层字段（extra=forbid）
    response = hub["client"].post(
        "/ingest",
        json={**_envelope([_event_payload(id="x")]), "extra": 1},
        headers=_bearer(),
    )
    assert response.status_code == 422
    # 超过单次 ingest 上限（1000）
    oversized = [_event_payload(id=f"evt_{i}") for i in range(1001)]
    response = hub["client"].post(
        "/ingest", json=_envelope(oversized), headers=_bearer()
    )
    assert response.status_code == 422
    # 机器名超长
    response = hub["client"].post(
        "/ingest", json=_envelope([_event_payload(id="x")], host="m" * 256), headers=_bearer()
    )
    assert response.status_code == 422


def test_ingest_query_roundtrip_via_api(hub) -> None:
    """ingest → 自动落盘（阈值 2）→ /api/hub/events 可查；读接口同样要 Bearer。"""
    events = [
        _event_payload(id="evt_q1", verdict="block"),
        _event_payload(id="evt_q2", verdict="alert"),
    ]
    response = hub["client"].post("/ingest", json=_envelope(events), headers=_bearer())
    assert response.status_code == 200
    body = response.json()
    assert body["accepted"] == 2
    assert body["buffered"] == 0  # 达阈值（2）已自动落盘
    assert body["persisted_total"] == 2
    # 查询（带令牌）
    response = hub["client"].get("/api/hub/events", headers=_bearer())
    assert response.status_code == 200
    listing = response.json()
    assert listing["total"] == 2 and len(listing["items"]) == 2
    item = listing["items"][0]
    assert item["machine"] == MACHINE_A
    assert item["received_ts"]
    assert item["destination"]["host"] == "api.openai.com"
    assert item["verdict"] in ("block", "alert")
    # 读接口无令牌 → 401（hub 监听局域网，只读也不匿名开放）
    assert hub["client"].get("/api/hub/events").status_code == 401
    assert hub["client"].get("/api/hub/stats").status_code == 401
    assert hub["client"].get("/api/hub/machines").status_code == 401
    # 过滤参数生效
    response = hub["client"].get(
        "/api/hub/events", params={"verdict": "block"}, headers=_bearer()
    )
    assert response.json()["total"] == 1
    # 非法 since → 400
    response = hub["client"].get(
        "/api/hub/events", params={"since": "not-a-time"}, headers=_bearer()
    )
    assert response.status_code == 400


def test_collector_buffer_flushes_to_sqlite_and_survives_reopen(tmp_path: Path) -> None:
    """内存缓冲 → SQLite：未达阈值不落盘、flush 落盘、close 兜底、重启可读。"""
    db_path = tmp_path / "hub.db"
    collector = HubCollector(db_path, TOKEN, flush_threshold=100)
    envelope = _envelope([_event_payload(id=f"evt_p{i}") for i in range(3)])
    collector.ingest(IngestEnvelope.model_validate(envelope))
    assert collector.buffered() == 3
    assert collector.query_events()[1] == 0  # 未达阈值：还在内存缓冲
    assert collector.flush() == 3
    assert collector.buffered() == 0
    assert collector.counters()["persisted"] == 3
    collector.close()
    # 重开同一库：数据仍在（SQLite 持久化）
    reopened = HubCollector(db_path, TOKEN)
    try:
        events, total = reopened.query_events()
        assert total == 3 and {e["id"] for e in events} == {"evt_p0", "evt_p1", "evt_p2"}
    finally:
        reopened.close()


def test_collector_flush_threshold_auto_persists(tmp_path: Path) -> None:
    """达到阈值自动落盘；同 (machine, id) 重复上报幂等去重。"""
    collector = HubCollector(tmp_path / "hub.db", TOKEN, flush_threshold=2)
    try:
        collector.ingest(
            IngestEnvelope.model_validate(
                _envelope([_event_payload(id="evt_a"), _event_payload(id="evt_b"),
                           _event_payload(id="evt_c")])
            )
        )
        assert collector.buffered() == 0
        assert collector.counters()["persisted"] == 3
        # 幂等：同键重发不产生重复行
        collector.ingest(
            IngestEnvelope.model_validate(_envelope([_event_payload(id="evt_a")]))
        )
        collector.flush()
        assert collector.query_events()[1] == 3
        assert collector.counters()["accepted"] == 4
    finally:
        collector.close()


def test_collector_requires_token(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        HubCollector(tmp_path / "hub.db", "")


def test_collector_trim_removes_old_events(tmp_path: Path) -> None:
    collector = HubCollector(tmp_path / "hub.db", TOKEN, flush_threshold=1)
    try:
        collector.ingest(
            IngestEnvelope.model_validate(
                _envelope([_event_payload(id="evt_old", ts="2020-01-01T00:00:00+08:00")])
            )
        )
        collector.ingest(
            IngestEnvelope.model_validate(_envelope([_event_payload(id="evt_new")]))
        )
        assert collector.query_events()[1] == 2
        assert collector.trim(days=1) == 1
        assert collector.query_events()[1] == 1
    finally:
        collector.close()


# ==========================================================================
# 跨机器聚合
# ==========================================================================


def test_cross_machine_aggregation(tmp_path: Path) -> None:
    """两台机器上报：stats 按机器/判定/规则聚合；查询按机器过滤。"""
    collector = HubCollector(tmp_path / "hub.db", TOKEN, flush_threshold=1)
    try:
        collector.ingest(
            IngestEnvelope.model_validate(
                _envelope(
                    [
                        _event_payload(
                            id="evt_a1",
                            verdict="block",
                            matched_rules=[
                                {"id": "aws-key", "dim": "secrets", "weight": 80}
                            ],
                        ),
                        _event_payload(id="evt_a2", verdict="alert"),
                    ],
                    host=MACHINE_A,
                )
            )
        )
        collector.ingest(
            IngestEnvelope.model_validate(
                _envelope([_event_payload(id="evt_b1", verdict="alert")], host=MACHINE_B)
            )
        )
        stats = collector.stats()
        assert stats["total"] == 3
        assert stats["by_machine"] == {MACHINE_A: 2, MACHINE_B: 1}
        assert stats["by_verdict"] == {"alert": 2, "block": 1}
        assert {"rule_id": "aws-key", "dim": "secrets", "n": 1} in stats["by_rule"]
        assert {m["machine"] for m in stats["machines"]} == {MACHINE_A, MACHINE_B}
        assert {m["machine"]: m["events"] for m in stats["machines"]} == {
            MACHINE_A: 2,
            MACHINE_B: 1,
        }
        # 机器维度过滤
        _, total_a = collector.query_events(machine=MACHINE_A)
        _, total_b = collector.query_events(machine=MACHINE_B)
        assert (total_a, total_b) == (2, 1)
        # since/until 过滤（未来窗口 → 空）
        _, total_future = collector.query_events(
            since=datetime.now(UTC) + timedelta(hours=1)
        )
        assert total_future == 0
    finally:
        collector.close()


def test_stats_by_host_and_process(tmp_path: Path) -> None:
    collector = HubCollector(tmp_path / "hub.db", TOKEN, flush_threshold=1)
    try:
        collector.ingest(
            IngestEnvelope.model_validate(_envelope([_event_payload(id="evt_h1")]))
        )
        stats = collector.stats()
        assert {"host": "api.openai.com", "n": 1} in stats["by_host"]
        assert any(
            row["process_name"] == "node.exe" and row["pid"] == 1234
            for row in stats["by_process"]
        )
        assert stats["by_day"] and stats["by_day"][0]["n"] == 1
    finally:
        collector.close()


# ==========================================================================
# Forwarder → collector 全链路往返（ASGITransport 进程内，零真实网络）
# ==========================================================================


class _TestClientAdapter:
    """把 fastapi ``TestClient`` 适配成 Forwarder 注入点的 client 接口。

    本环境的 httpx 为补丁版：``ASGITransport`` 只有 async 方法，同步
    ``httpx.Client`` 走不了进程内 ASGI；``TestClient`` 自带进程内传输，
    适配 ``post(url, json=..., headers=...)`` / ``close()`` 即可全注入往返。
    """

    def __init__(self, client: TestClient) -> None:
        self._client = client

    def post(self, url: str, json: Any = None, headers: Any = None) -> Any:
        return self._client.post(url, json=json, headers=headers)

    def close(self) -> None:
        pass


def test_roundtrip_forwarder_to_collector(tmp_path: Path) -> None:
    """端到端：Forwarder 批量转发 → collector 鉴权落盘 → 聚合可查。"""
    collector = HubCollector(tmp_path / "hub.db", TOKEN, flush_threshold=50)
    app = create_hub_app(collector)
    test_client = TestClient(app)

    def factory() -> Any:
        # 进程内传输（TestClient）：不建 socket、不经代理（往返测试的"注入边界"）
        return _TestClientAdapter(test_client)

    forwarder = Forwarder(
        "http://hub.test/",
        TOKEN,
        hostname=MACHINE_A,
        client_factory=factory,
        batch_size=3,
        sleeper=lambda _s: None,
    )
    try:
        for i in range(7):
            forwarder.enqueue(_event(id=f"evt_rt_{i}", verdict="block" if i % 2 else "alert"))
        forwarder.flush(timeout=10.0)
        assert forwarder.stats()["sent_events"] == 7
        assert collector.buffered() == 7  # 未达阈值（50）：先落内存缓冲
        assert collector.flush() == 7  # 兜底落盘（退出路径语义）
        events, total = collector.query_events(machine=MACHINE_A)
        assert total == 7 and len(events) == 7
        assert all(item["machine"] == MACHINE_A for item in events)
        assert {item["id"] for item in events} == {f"evt_rt_{i}" for i in range(7)}
        stats = collector.stats()
        assert stats["by_machine"] == {MACHINE_A: 7}
        assert stats["total"] == 7
        # 错误令牌的 Forwarder → 401 → 整批重试后丢弃（不污染中心库）
        bad = Forwarder(
            "http://hub.test/",
            "wrong-token",
            hostname=MACHINE_B,
            client_factory=factory,
            retries=0,
            sleeper=lambda _s: None,
        )
        bad.enqueue(_event(id="evt_bad"))
        bad.flush(timeout=10.0)
        assert bad.stats()["dropped"] == 1
        _, total_after = collector.query_events(machine=MACHINE_B)
        assert total_after == 0
    finally:
        forwarder.close(timeout=0.5)
        collector.close()
