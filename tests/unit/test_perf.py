"""W4 性能单测（06 文档波次一 W4）：WAL/synchronous、批量事务、大 body 采样扫描、覆盖索引。

- 基准（1000 事件批量 vs 逐条）：硬断言是**批量事务次数=1**（逐条=1000）与
  批量正确性；耗时只做相对断言（批量 < 逐条），不断言绝对值（CI 时长不可靠）；
- 采样（06 文档 W4）：body > ``defaults.max_body_scan`` 时非豁免扫描器只扫前
  ``sampling.head_bytes`` 字节；**secrets 行为不回退**——仍整段交给 secrets
  （截断语义保持既有 ``max_body_scan``）；
- 覆盖索引：EXPLAIN QUERY PLAN 断言 dim 过滤/按规则聚合走 covering index、
  列表页 ORDER BY 免排序（本机 SQLite 3.42 验证过的计划文案）。

红线：全部为进程内 SQLite 与注入式扫描断言，无系统级操作、无网络。
"""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from aaa.engine.pipeline import AuditPipeline, EvaluationInput, SamplingConfig
from aaa.policy.loader import PolicyLoader
from aaa.scanners.base import ScanResult
from aaa.store.db import DbEventStore
from aaa.store.events import AuditEvent, Destination, ProcessInfo, RequestInfo
from aaa.store.jsonl import JsonlEventStore

# ---------------------------------------------------------------- 工具与夹具


def _mk_event(i: int, *, rules: list[dict[str, Any]] | None = None) -> AuditEvent:
    """轻量审计事件（毫秒级错开 ts 保证 ts_epoch 单调）。"""
    ts = (datetime(2026, 10, 25, 12, 0, 0, tzinfo=UTC) + timedelta(milliseconds=i)).isoformat()
    return AuditEvent(
        id=f"evt_{i:06d}",
        ts=ts,
        mode="regular",
        verdict="alert" if i % 3 == 0 else "allow",
        risk_score=20,
        process=ProcessInfo(pid=1000 + i, name="node.exe", profile="agent_cli"),
        destination=Destination(
            host=f"host{i % 7}.example.com", port=443, classification="known_ai_api"
        ),
        request=RequestInfo(
            method="POST", path=f"/v1/{i}", content_type="application/json", size=128
        ),
        matched_rules=rules or [],
    )


def _rule_dict() -> dict[str, Any]:
    return {"id": "secret-leak", "dim": "content", "action": "block", "weight": 60}


class _TxnCounter:
    """经 ``set_trace_callback`` 统计连接上的 BEGIN/COMMIT 次数。

    Python 3.12 sqlite3 的隐式事务（INSERT 前自动 BEGIN、``with conn`` 的 COMMIT）
    均可见（本仓库 Python 3.12.0 实测）；重新挂载即清零。
    """

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.begins = 0
        self.commits = 0
        conn.set_trace_callback(self._on_statement)

    def _on_statement(self, statement: str) -> None:
        head = statement.strip().split(" ", 1)[0].upper()
        if head == "BEGIN":
            self.begins += 1
        elif head == "COMMIT":
            self.commits += 1


@pytest.fixture
def store(tmp_path: Path) -> Any:
    s = DbEventStore(tmp_path / "perf.db")
    yield s
    s.close()


# ------------------------------------------------------------------ WAL/PRAGMA


def test_wal_and_synchronous_pragmas(store: DbEventStore) -> None:
    """06 文档 W4：journal_mode=WAL + synchronous=NORMAL。"""
    mode = store._conn.execute("PRAGMA journal_mode").fetchone()[0]
    sync = store._conn.execute("PRAGMA synchronous").fetchone()[0]
    assert mode == "wal"
    assert sync == 1, "synchronous=NORMAL（1）；每连接 PRAGMA 必须重设，不能只靠库文件"


def test_wal_converted_on_reopen_for_existing_db(tmp_path: Path) -> None:
    """既有库文件重开：journal 被转回 WAL、数据完好（波次二“旧库打开不炸”地基）。"""
    path = tmp_path / "audit.db"
    first = DbEventStore(path)
    first.append(_mk_event(1))
    first.close()
    # 模拟“外部把它改回非 WAL”的既有库文件
    raw = sqlite3.connect(str(path))
    raw.execute("PRAGMA journal_mode=DELETE")
    raw.close()

    reopened = DbEventStore(path)
    try:
        assert reopened._conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert reopened.count() == 1
        assert reopened.get("evt_000001") is not None
    finally:
        reopened.close()


# ------------------------------------------------------------------ 批量事务


def test_insert_events_batch_roundtrip(store: DbEventStore) -> None:
    """批量落盘正确性：行数/逐字段还原/event_rules 明细/统计/dim 过滤。"""
    events = [_mk_event(i) for i in range(1000)]
    events[7] = _mk_event(7, rules=[_rule_dict()])
    assert store.insert_events(events) == 1000
    assert store.count() == 1000
    loaded_first = store.get("evt_000000")
    loaded_last = store.get("evt_000999")
    assert loaded_first is not None and loaded_first.model_dump() == events[0].model_dump()
    assert loaded_last is not None and loaded_last.model_dump() == events[999].model_dump()
    # event_rules 明细落库且 dim 过滤可用
    matched, total = store.query(dim="content")
    assert [e.id for e in matched] == ["evt_000007"] and total == 1
    stats = store.stats()
    assert stats["total"] == 1000
    assert stats["by_rule"][0]["rule_id"] == "secret-leak"


def test_insert_events_replace_semantics_same_as_append(store: DbEventStore) -> None:
    """同 id 重放批量：INSERT OR REPLACE 覆盖、总数不变（与逐条一致）。"""
    events = [_mk_event(i) for i in range(10)]
    store.insert_events(events)
    again = [_mk_event(i) for i in range(5)]  # 前 5 条同 id
    assert store.insert_events(again) == 5
    assert store.count() == 10


def test_insert_events_batch_single_transaction(store: DbEventStore) -> None:
    """核心断言（06 文档 W4）：1000 事件批量只开 1 个事务；逐条 append 每条 1 个。"""
    batch_counter = _TxnCounter(store._conn)
    store.insert_events([_mk_event(i) for i in range(1000)])
    assert (batch_counter.begins, batch_counter.commits) == (1, 1), (
        "批量落盘必须整批单事务（BEGIN/COMMIT 各一次）"
    )

    seq_counter = _TxnCounter(store._conn)  # 重新挂载清零
    for i in range(20):
        store.append(_mk_event(2000 + i))
    assert (seq_counter.begins, seq_counter.commits) == (20, 20), (
        "逐条 append 语义保持：每条一个事务"
    )


def test_insert_events_batch_vs_sequential_benchmark(tmp_path: Path) -> None:
    """基准（06 文档 W4）：1000 事件批量 vs 逐条。

    硬断言：批量事务次数=1、逐条=1000、两边行数一致、批量耗时更低
    （机制由单事务保证；不断言绝对耗时——CI 时长不可靠）。
    """
    events = [_mk_event(i) for i in range(1000)]
    batch_store = DbEventStore(tmp_path / "batch.db")
    seq_store = DbEventStore(tmp_path / "seq.db")
    try:
        batch_counter = _TxnCounter(batch_store._conn)
        t0 = time.perf_counter()
        batch_store.insert_events(events)
        batch_elapsed = time.perf_counter() - t0
        assert batch_counter.commits == 1

        seq_counter = _TxnCounter(seq_store._conn)
        t0 = time.perf_counter()
        for event in events:
            seq_store.append(event)
        seq_elapsed = time.perf_counter() - t0
        assert seq_counter.commits == 1000

        assert batch_store.count() == 1000
        assert seq_store.count() == 1000
        assert batch_elapsed < seq_elapsed, (
            f"批量应快于逐条：batch={batch_elapsed:.3f}s seq={seq_elapsed:.3f}s"
        )
    finally:
        batch_store.close()
        seq_store.close()


def test_insert_events_mirror_fanout_in_order(store: DbEventStore, tmp_path: Path) -> None:
    """JSONL 双写：批量提交后 mirror 按序收到全部事件。"""
    mirror = JsonlEventStore(tmp_path / "raw")
    store.mirror = mirror
    events = [_mk_event(i) for i in range(50)]
    store.insert_events(events)
    assert [e.id for e in mirror.read_all()] == [e.id for e in events]


def test_insert_events_empty_list_noop(store: DbEventStore) -> None:
    assert store.insert_events([]) == 0
    assert store.count() == 0


def test_insert_events_rollback_keeps_previous_state(
    store: DbEventStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """原子性：批内 SQL 中途失败（坏行）→ 整批回滚，既有数据不受影响。"""
    store.append(_mk_event(1))
    real_rule_rows = DbEventStore._rule_rows

    def poisoned(event: AuditEvent) -> list[tuple[str, str, str, str | None, int | None]]:
        rows = real_rule_rows(event)
        if event.id == "evt_000050":  # 批中段埋一个字段数不符的坏行
            rows = [*rows, ("only-one-field",)]
        return rows

    monkeypatch.setattr(DbEventStore, "_rule_rows", staticmethod(poisoned))
    events = [_mk_event(i, rules=[_rule_dict()]) for i in range(2, 100)]
    with pytest.raises(sqlite3.ProgrammingError):
        store.insert_events(events)
    assert store.count() == 1, "失败的批次必须整体回滚"
    assert store.get("evt_000002") is None


# ------------------------------------------------------------------ 覆盖索引


def _plan(store: DbEventStore, sql: str, params: tuple[Any, ...] = ()) -> str:
    rows = store._conn.execute("EXPLAIN QUERY PLAN " + sql, params).fetchall()
    return " | ".join(str(row[-1]) for row in rows)


def test_covering_indexes_present(store: DbEventStore) -> None:
    names = {
        row[0] for row in store._conn.execute("SELECT name FROM sqlite_master WHERE type='index'")
    }
    assert {"idx_events_ts_id", "idx_event_rules_event_dim", "idx_event_rules_rule_dim"} <= names


def test_dim_filter_uses_covering_index(store: DbEventStore) -> None:
    """dim 过滤（面板筛选）的 EXISTS 子查询走 (event_id, dim) 覆盖索引。"""
    plan = _plan(
        store,
        "SELECT raw FROM events WHERE EXISTS (SELECT 1 FROM event_rules r "
        "WHERE r.event_id = events.id AND r.dim = ?) ORDER BY ts_epoch DESC, id DESC",
        ("content",),
    )
    assert "COVERING INDEX idx_event_rules_event_dim" in plan


def test_by_rule_aggregation_uses_covering_index(store: DbEventStore) -> None:
    """按规则聚合（stats.by_rule）走 (rule_id, dim) 索引（免回表取 dim）。"""
    plan = _plan(
        store,
        "SELECT r.rule_id, r.dim, COUNT(*) AS n FROM event_rules r "
        "JOIN events e ON e.id = r.event_id GROUP BY r.rule_id, r.dim",
    )
    assert "idx_event_rules_rule_dim" in plan


def test_list_query_order_by_uses_index(store: DbEventStore) -> None:
    """列表页（无过滤 + ORDER BY ts_epoch DESC, id DESC）走复合索引、免排序。"""
    plan = _plan(store, "SELECT raw FROM events ORDER BY ts_epoch DESC, id DESC LIMIT 50")
    assert "idx_events_ts_id" in plan
    assert "TEMP B-TREE FOR ORDER BY" not in plan


# ------------------------------------------------------------- 内容扫描采样

SAMPLING_YAML: dict[str, Any] = {
    "version": 1,
    "mode": "dry-run",
    "defaults": {"fail_open": True, "max_body_scan": 2048},
    "domains": {"classes": {"known_ai_api": ["api.openai.com"]}, "rules": []},
    "processes": {"profiles": {}, "rules": []},
    "content": {
        "scanners": ["secrets", "pii", "code_leak"],
        "rules": [
            {"id": "secret-leak", "scanner": "secrets", "action": "block", "weight": 60},
            {
                "id": "pii-bulk",
                "scanner": "pii",
                "match": {"hits_gt": 2},
                "action": "confirm",
                "weight": 40,
            },
        ],
    },
    "volume": [],
    "time_window": [],
}


def _write_policy(tmp_path: Path, doc: dict[str, Any] | None = None) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(
        yaml.safe_dump(doc if doc is not None else SAMPLING_YAML, allow_unicode=True),
        encoding="utf-8",
    )
    return path


def _pipeline(tmp_path: Path, doc: dict[str, Any] | None = None, **kw: Any) -> AuditPipeline:
    return AuditPipeline(PolicyLoader(_write_policy(tmp_path, doc)), **kw)


def _recorder(name: str, calls: list[tuple[int, int | None]]) -> Callable[..., ScanResult]:
    """记录每次收到的 (body 字节数, max_bytes) 的假扫描器。"""

    def scan(body: object, max_bytes: int | None = None) -> ScanResult:
        calls.append((len(body) if body else 0, max_bytes))
        return ScanResult(scanner=name)

    return scan


def _inp(**kw: Any) -> EvaluationInput:
    defaults: dict[str, Any] = {"host": "api.openai.com", "port": 443}
    defaults.update(kw)
    return EvaluationInput(**defaults)


def test_sampling_head_truncation_contract(tmp_path: Path) -> None:
    """采样契约（注入式断言，最精确）：大 body 下非豁免扫描器只见前 head_bytes
    字节；secrets 保持整段（截断仍按 max_body_scan）——行为不回退。"""
    calls: dict[str, list[tuple[int, int | None]]] = {"secrets": [], "pii": [], "code_leak": []}
    pipe = _pipeline(
        tmp_path,
        scanners={
            "secrets": _recorder("secrets", calls["secrets"]),
            "pii": _recorder("pii", calls["pii"]),
            "code_leak": _recorder("code_leak", calls["code_leak"]),
        },
        sampling={"head_bytes": 1024},
    )
    body = b"x" * 4096  # > max_body_scan(2048) → 采样生效
    pipe.evaluate(_inp(body=body, body_size=len(body)))
    assert calls["secrets"] == [(4096, 2048)], "secrets 不回退：整段 body、按 max_body_scan 截断"
    assert calls["pii"] == [(1024, 1024)], "其余扫描器：只扫前 head_bytes 字节"
    assert calls["code_leak"] == [(1024, 1024)]
    assert pipe.stats()["sampled_scans"] == 2  # pii + code_leak 被截头


def test_sampling_secrets_beyond_head_still_detected(tmp_path: Path) -> None:
    """secrets 行为不回退：位于 head_bytes 之后、max_body_scan 之内的密钥仍被检出；
    max_body_scan 之外的密钥维持既有截断语义（不被扫）。"""
    pipe = _pipeline(tmp_path, sampling={"head_bytes": 1024})
    # 密钥在 1501 ∈ (head=1024, max=2048)；前后空格保证 \b 词边界
    body = b"x" * 1500 + b" AKIAQ2FZV3TQPE8KX9YZ " + b"y" * 400
    result = pipe.evaluate(_inp(body=body, body_size=len(body)))
    assert "secret-leak" in [m.id for m in result.matched]

    body2 = b"x" * 2100 + b"AKIAQ2FZV3TQPE8KX9YZ"  # 密钥在 2100 > max_body_scan=2048
    result2 = pipe.evaluate(_inp(body=body2, body_size=len(body2)))
    assert "secret-leak" not in [m.id for m in result2.matched]


def test_sampling_disabled_keeps_legacy_scan(tmp_path: Path) -> None:
    """采样开关关：与既有行为完全一致——head 之外、max 之内的 pii 命中不被截掉。"""
    # body 总长 2123 > max_body_scan(2048)（采样只对超限 body 生效）；
    # 3 封邮件在偏移 1500 ∈ (head=1024, max=2048)
    body = b"x" * 1500 + b"a@x.com b@x.com c@x.com" + b"y" * 600

    pipe_on = _pipeline(tmp_path, sampling={"head_bytes": 1024})
    r_on = pipe_on.evaluate(_inp(body=body, body_size=len(body)))
    assert "pii-bulk" not in [m.id for m in r_on.matched], "采样开：head 之后的 pii 不参与判定"
    assert pipe_on.stats()["sampled_scans"] > 0

    pipe_off = _pipeline(tmp_path, sampling={"enabled": False, "head_bytes": 1024})
    r_off = pipe_off.evaluate(_inp(body=body, body_size=len(body)))
    assert "pii-bulk" in [m.id for m in r_off.matched], "采样关：既有全量扫描行为保持"
    assert pipe_off.stats()["sampled_scans"] == 0


def test_sampling_not_triggered_below_max_body_scan(tmp_path: Path) -> None:
    """body ≤ max_body_scan：即便超过 head_bytes 也全量扫描（采样只在超限时触发）。"""
    calls: list[tuple[int, int | None]] = []
    pipe = _pipeline(
        tmp_path, scanners={"pii": _recorder("pii", calls)}, sampling={"head_bytes": 1024}
    )
    body = b"x" * 1500  # > head(1024) 但 ≤ max_body_scan(2048)
    pipe.evaluate(_inp(body=body, body_size=len(body)))
    assert calls == [(1500, 2048)]
    assert pipe.stats()["sampled_scans"] == 0


def test_sampling_default_head_equals_legacy_truncation(tmp_path: Path) -> None:
    """出厂默认 sampling（head=256KiB ≥ 常见 max_body_scan）：非豁免扫描器的有效
    截断 = min(max, head) = max —— 与既有行为零差异（采样只会少扫、不会多扫）。"""
    calls: dict[str, list[tuple[int, int | None]]] = {"pii": []}
    pipe = _pipeline(
        tmp_path,
        scanners={"pii": _recorder("pii", calls["pii"])},  # type: ignore[dict-item]
    )  # SAMPLING_YAML max_body_scan=2048 < 出厂 head=262144
    body = b"x" * 4096
    pipe.evaluate(_inp(body=body, body_size=len(body)))
    assert calls["pii"] == [(2048, 2048)], "head ≥ max 时有效截断等于既有 max_body_scan"
    assert pipe.sampling == SamplingConfig()


def test_sampling_config_validation() -> None:
    """SamplingConfig：出厂值/extra=forbid/下界；管线接受 dict 与实例。"""
    cfg = SamplingConfig()
    assert cfg.enabled is True and cfg.head_bytes == 262144
    with pytest.raises(ValidationError):
        SamplingConfig(head_bytes=0)
    with pytest.raises(ValidationError):
        SamplingConfig(unknown_key=1)  # type: ignore[call-arg]
    validated = SamplingConfig.model_validate({"head_bytes": 4096, "enabled": False})
    assert validated.head_bytes == 4096 and validated.enabled is False


# --------------------------------------------------------------------- 观测


def test_stats_reports_sampling_config(tmp_path: Path) -> None:
    pipe = _pipeline(tmp_path, sampling={"head_bytes": 4096})
    stats = pipe.stats()
    assert stats["sampling"] == {"enabled": True, "head_bytes": 4096}
    assert stats["sampled_scans"] == 0
