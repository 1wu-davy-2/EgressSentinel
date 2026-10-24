"""AuditAddon 单测（03 文档 T1.2）：钩子 → 事件对象 → JSONL + 证据。

用 mitmproxy.test.tflow 构造 flow（不依赖真实网络/真实代理进程）。
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from mitmproxy.test import tflow

from aaa.capture.addon import AuditAddon
from aaa.store.evidence import EvidenceStore
from aaa.store.jsonl import JsonlEventStore


def _make_addon(data_dir: Path) -> AuditAddon:
    events = JsonlEventStore(data_dir / "raw")
    evidence = EvidenceStore(data_dir / "evidence", rel_base=data_dir)
    return AuditAddon(events, evidence, mode="regular")


def test_hooks_produce_event_with_evidence(data_dir: Path) -> None:
    addon = _make_addon(data_dir)
    flow = tflow.tflow(resp=True)
    addon.client_connected(flow.client_conn)
    addon.request(flow)
    addon.response(flow)

    events = addon.events.read_all()
    assert len(events) == 1
    event = events[0]
    assert event.destination.host == "address"
    assert event.destination.port == 22
    assert event.request.method == "GET"
    assert event.request.path == "/path"
    assert event.request.size == len(b"content")
    assert event.response is not None and event.response.status_code == 200
    assert event.mode == "regular"
    assert event.verdict == "unassessed"  # P1 无策略引擎（见 decisions.md D-2026-10-24-04）
    assert event.evidence is not None
    assert event.evidence.sha256 == hashlib.sha256(b"content").hexdigest()
    assert addon.connections_seen == 1
    # 证据文件存在且内容一致
    evidence_path = data_dir / event.evidence.file
    assert evidence_path.read_bytes() == b"content"


def test_request_body_truncated_to_limit(data_dir: Path) -> None:
    from aaa.config import DEFAULT_BODY_EVIDENCE_LIMIT

    addon = _make_addon(data_dir)
    flow = tflow.tflow(resp=True)
    big_body = b"B" * (DEFAULT_BODY_EVIDENCE_LIMIT + 4096)
    flow.request.content = big_body
    addon.request(flow)
    addon.response(flow)

    (event,) = addon.events.read_all()
    assert event.evidence is not None
    assert event.evidence.truncated is True
    assert event.evidence.size == DEFAULT_BODY_EVIDENCE_LIMIT
    assert event.evidence.original_size == len(big_body)
    evidence_path = data_dir / event.evidence.file
    assert evidence_path.stat().st_size == DEFAULT_BODY_EVIDENCE_LIMIT
    truncated_sha = hashlib.sha256(big_body[:DEFAULT_BODY_EVIDENCE_LIMIT]).hexdigest()
    assert event.evidence.sha256 == truncated_sha


def test_error_hook_records_flow_without_response(data_dir: Path) -> None:
    addon = _make_addon(data_dir)
    flow = tflow.tflow(err=True)
    addon.request(flow)
    addon.error(flow)

    (event,) = addon.events.read_all()
    assert event.error == str(flow.error)  # tflow 的 terr() 错误串
    assert event.error  # 非空
    assert event.response is None
    assert event.action_taken == "error"


def test_response_hook_without_pending_request_still_records(data_dir: Path) -> None:
    """仅 response（如 addon 启动前已开始的流）也要留痕。"""
    addon = _make_addon(data_dir)
    flow = tflow.tflow(resp=True)
    addon.response(flow)
    assert len(addon.events.read_all()) == 1


def test_hooks_fail_open(data_dir: Path, monkeypatch) -> None:
    """store 抛异常时钩子不传播（fail-open，不崩代理进程，03 文档 §3）。"""
    addon = _make_addon(data_dir)
    flow = tflow.tflow(resp=True)

    def boom(event):  # type: ignore[no-untyped-def]
        raise RuntimeError("store down")

    monkeypatch.setattr(addon.events, "append", boom)
    addon.request(flow)  # 证据保存正常，不写 JSONL
    addon.response(flow)  # append 抛异常 → 被吞掉
    addon.error(flow)


def test_done_clears_pending(data_dir: Path) -> None:
    addon = _make_addon(data_dir)
    flow = tflow.tflow()
    addon.request(flow)
    assert addon.pending_count == 1
    addon.done()
    assert addon.pending_count == 0
