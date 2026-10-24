"""P1 E2E：regular 模式采集留痕（03 文档 T1.x 验收的本地自动化部分）。

本地 fixture（无外网、无系统改动）：
1. 进程内起 regular 代理（CaptureEngine + AuditAddon）；
2. Python httpx 客户端经代理 GET/POST；
3. curl 客户端（Windows 自带，缺失则跳过该子断言）经代理 GET；
4. 断言 JSONL 事件齐全、证据文件与 sha256 一致。
浏览器手工验证项见返回结果 needs_manual_verification。
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import httpx

from aaa.capture.addon import AuditAddon
from aaa.capture.engine import ProxyConfig, start_in_background
from aaa.store.evidence import EvidenceStore
from aaa.store.jsonl import JsonlEventStore
from conftest import free_port, wait_until


def _env_without_proxy() -> dict[str, str]:
    """去掉 no_proxy/http_proxy 等：否则 curl 对 127.0.0.1 目标会绕过 -x 指定的代理。"""
    return {
        k: v
        for k, v in os.environ.items()
        if k.lower() not in ("no_proxy", "http_proxy", "https_proxy", "all_proxy")
    }


def test_regular_capture_end_to_end(data_dir: Path, http_fixture_server) -> None:
    fixture_port = http_fixture_server.server_address[1]
    events = JsonlEventStore(data_dir / "raw")
    evidence = EvidenceStore(data_dir / "evidence", rel_base=data_dir)
    addon = AuditAddon(events, evidence, mode="regular")
    config = ProxyConfig(
        listen_host="127.0.0.1", listen_port=free_port(), confdir=data_dir / "mitm"
    )
    handle = start_in_background(config, [addon])
    try:
        base = f"http://127.0.0.1:{fixture_port}"
        proxy_url = f"http://127.0.0.1:{config.listen_port}"

        # —— Python httpx 客户端 ——
        with httpx.Client(proxy=proxy_url, trust_env=False, timeout=10.0) as client:
            get_resp = client.get(f"{base}/e2e-get")
            assert get_resp.status_code == 200
            post_resp = client.post(f"{base}/e2e-post", content=b"P" * 5000)
            assert post_resp.status_code == 200

        # —— curl 客户端（Windows 10 自带；缺失则如实跳过）——
        curl_path = shutil.which("curl")
        curl_ran = False
        if curl_path:
            proc = subprocess.run(
                [curl_path, "-sS", "-x", proxy_url, f"{base}/e2e-curl"],
                capture_output=True,
                timeout=20,
                check=False,
                env=_env_without_proxy(),
            )
            curl_ran = proc.returncode == 0
            assert curl_ran, f"curl 经代理失败：{proc.stderr!r}"

        expected_min = 3 if curl_ran else 2
        assert wait_until(lambda: len(events.read_all()) >= expected_min, timeout=15.0), (
            f"JSONL 事件不足：{len(events.read_all())} < {expected_min}"
        )

        all_events = events.read_all()
        assert {e.destination.host for e in all_events} == {"127.0.0.1"}
        assert all(e.destination.port == fixture_port for e in all_events)
        methods = {e.request.method for e in all_events}
        assert {"GET", "POST"} <= methods

        # POST 体量与证据 sha256 可复核；无 body 的 GET 不落证据文件（设计语义）
        post_events = [e for e in all_events if e.request.method == "POST"]
        assert post_events[0].request.size == 5000
        for event in all_events:
            if event.request.size > 0:
                assert event.evidence is not None, f"{event.request.method} 应有证据"
                evidence_path = data_dir / event.evidence.file
                assert evidence_path.exists()
                file_sha = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
                assert file_sha == event.evidence.sha256
            else:
                assert event.evidence is None, "无 body 的 GET 不应有证据文件"

        # JSONL 路径形如 data/raw/YYYYMMDD.jsonl
        jsonl_files = list((data_dir / "raw").glob("*.jsonl"))
        assert len(jsonl_files) == 1
        assert len(jsonl_files[0].name) == len("20261024.jsonl")  # YYYYMMDD.jsonl
    finally:
        handle.stop()

    # 代理退出后：CA 已生成于 confdir（T1.3 复用同一 confdir）
    assert (data_dir / "mitm" / "mitmproxy-ca.pem").exists()


def test_stop_is_graceful_and_repeatable(data_dir: Path) -> None:
    """后台代理可重复停止（幂等），端口随后释放。"""
    import socket

    port = free_port()
    config = ProxyConfig(listen_port=port, confdir=data_dir / "mitm")
    handle = start_in_background(config, [])
    handle.stop()
    handle.stop()  # 二次 stop 不抛异常
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        assert probe.connect_ex(("127.0.0.1", port)) != 0, "代理退出后端口应已释放"
