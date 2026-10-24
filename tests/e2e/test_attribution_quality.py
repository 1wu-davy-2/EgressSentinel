"""P2 E2E：进程归因质量（03 文档 T2.3）。

regular 模式起本地代理（进程内嵌入），用当前 venv python 经代理发 N 个本地请求，
断言事件归因到本进程（pid/exe/name）的准确率 ≥ 90%（本地 fixture，无外网、无系统改动）。

curl 子断言可选（03 文档：curl 可选；node 缺失则跳过并在 deviations 说明）。
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

from aaa.attribution.table import ProcessAttributor
from aaa.capture.addon import AuditAddon
from aaa.capture.engine import ProxyConfig, start_in_background
from aaa.store.evidence import EvidenceStore
from aaa.store.jsonl import JsonlEventStore
from conftest import free_port, wait_until

# Linux/macOS：无特权会话里 psutil 无法把其他进程的连接映射到 PID（/proc 扫描受
# 权限限制），归因恒为 unknown；02 文档 D2 本就只对 Windows 承诺归因质量。
# 缺口登记见 docs/notes/decisions.md「CI 跨平台矩阵落地记录」。
pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Linux/macOS 无特权会话连接表无 PID 映射，归因断言仅 Windows 有效（02 文档 D2）",
)

#: T2.3 验收线
ACCURACY_THRESHOLD = 0.90
REQUEST_COUNT = 20


def _env_without_proxy() -> dict[str, str]:
    return {
        k: v
        for k, v in os.environ.items()
        if k.lower() not in ("no_proxy", "http_proxy", "https_proxy", "all_proxy")
    }


def test_attribution_accuracy_at_least_90_percent(data_dir: Path, http_fixture_server) -> None:
    fixture_port = http_fixture_server.server_address[1]
    events = JsonlEventStore(data_dir / "raw")
    evidence = EvidenceStore(data_dir / "evidence", rel_base=data_dir)
    attributor = ProcessAttributor()
    addon = AuditAddon(events, evidence, mode="regular", attributor=attributor)
    config = ProxyConfig(
        listen_host="127.0.0.1", listen_port=free_port(), confdir=data_dir / "mitm"
    )
    handle = start_in_background(config, [addon])
    try:
        base = f"http://127.0.0.1:{fixture_port}"
        proxy_url = f"http://127.0.0.1:{config.listen_port}"
        with httpx.Client(proxy=proxy_url, trust_env=False, timeout=10.0) as client:
            for i in range(REQUEST_COUNT):
                resp = client.get(f"{base}/attr-{i}")
                assert resp.status_code == 200

        assert wait_until(lambda: len(events.read_all()) >= REQUEST_COUNT, timeout=15.0), (
            f"事件数量不足：{len(events.read_all())} < {REQUEST_COUNT}"
        )

        all_events = events.read_all()
        assert len(all_events) >= REQUEST_COUNT
        my_pid = os.getpid()
        attributed = sum(1 for e in all_events if e.process and e.process.pid == my_pid)
        accuracy = attributed / len(all_events)
        assert accuracy >= ACCURACY_THRESHOLD, (
            f"归因准确率 {accuracy:.2%} < {ACCURACY_THRESHOLD:.0%}"
            f"（{attributed}/{len(all_events)}，unknown={attributor.stats.unknown}）"
        )
        # 归因字段完整性（02 文档 §6 process）
        sample = next(e for e in all_events if e.process and e.process.pid == my_pid)
        assert sample.process is not None
        assert sample.process.name, "进程名应非空"
        assert sample.process.exe and Path(sample.process.exe).exists()
        assert sample.process.profile in ("agent_cli", "other")
    finally:
        handle.stop()


def test_curl_client_attribution(data_dir: Path, http_fixture_server) -> None:
    """curl 客户端（Windows 自带，缺失则跳过）经代理请求，事件归因到 curl 进程。"""
    curl_path = shutil.which("curl")
    if not curl_path:
        pytest.skip("系统无 curl（03 文档：curl 可选）")
    fixture_port = http_fixture_server.server_address[1]
    events = JsonlEventStore(data_dir / "raw")
    evidence = EvidenceStore(data_dir / "evidence", rel_base=data_dir)
    attributor = ProcessAttributor()
    addon = AuditAddon(events, evidence, mode="regular", attributor=attributor)
    config = ProxyConfig(
        listen_host="127.0.0.1", listen_port=free_port(), confdir=data_dir / "mitm"
    )
    handle = start_in_background(config, [addon])
    try:
        base = f"http://127.0.0.1:{fixture_port}"
        proxy_url = f"http://127.0.0.1:{config.listen_port}"
        proc = subprocess.run(
            [curl_path, "-sS", "-x", proxy_url, f"{base}/curl-attr"],
            capture_output=True,
            timeout=20,
            check=False,
            env=_env_without_proxy(),
        )
        assert proc.returncode == 0, f"curl 经代理失败：{proc.stderr!r}"

        assert wait_until(lambda: len(events.read_all()) >= 1, timeout=15.0)
        (event,) = events.read_all()
        # 归因到 curl 进程（pid 命中；短连接竞态见 02 文档 D2 已知边界）
        assert event.process is not None
        if event.process.pid is not None:
            assert "curl" in (event.process.name or "").lower()
        else:
            pytest.fail("curl 请求未归因到 PID（超出 02 文档 D2 已知边界描述）")
    finally:
        handle.stop()


NODE_SCRIPT = """
const http = require('http');
const proxyPort = process.argv[1]; // node -e 下 argv[1] 起为用户参数
const target = process.argv[2]; // 绝对 URI（显式代理语义）
const req = http.request(
  { host: '127.0.0.1', port: Number(proxyPort), path: target, method: 'GET',
    headers: { Host: new URL(target).host } },
  (res) => { res.resume(); process.exitCode = res.statusCode === 200 ? 0 : 1; },
);
req.on('error', () => { process.exitCode = 1; });
req.end();
"""


def test_node_client_attribution(data_dir: Path, http_fixture_server) -> None:
    """node 客户端（03 文档 T2.3 三客户端之一；缺失则跳过）经代理请求归因到 node 进程。"""
    node_path = shutil.which("node")
    if not node_path:
        pytest.skip("系统无 node（按工作约定跳过并在 deviations 说明）")
    fixture_port = http_fixture_server.server_address[1]
    events = JsonlEventStore(data_dir / "raw")
    evidence = EvidenceStore(data_dir / "evidence", rel_base=data_dir)
    attributor = ProcessAttributor()
    addon = AuditAddon(events, evidence, mode="regular", attributor=attributor)
    config = ProxyConfig(
        listen_host="127.0.0.1", listen_port=free_port(), confdir=data_dir / "mitm"
    )
    handle = start_in_background(config, [addon])
    try:
        proxy_port = config.listen_port
        target = f"http://127.0.0.1:{fixture_port}/attr-node"
        proc = subprocess.run(
            [node_path, "-e", NODE_SCRIPT, str(proxy_port), target],
            capture_output=True,
            timeout=20,
            check=False,
            env=_env_without_proxy(),
        )
        assert proc.returncode == 0, f"node 经代理失败：{proc.stderr!r}"

        assert wait_until(lambda: len(events.read_all()) >= 1, timeout=15.0)
        (event,) = events.read_all()
        assert event.process is not None
        if event.process.pid is not None:
            assert "node" in (event.process.name or "").lower()
            assert event.process.profile == "agent_cli"  # node 命中 agent_cli 画像
        else:
            pytest.fail("node 请求未归因到 PID（超出 02 文档 D2 已知边界描述）")
    finally:
        handle.stop()
