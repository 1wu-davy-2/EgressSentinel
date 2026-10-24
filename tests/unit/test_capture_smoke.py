"""T0.2 嵌入冒烟：mitmproxy 以库方式在本进程内起 regular 代理（03 文档 T0.2）。

本进程内：CaptureEngine（DumpMaster + addon）后台线程起 regular 代理 →
httpx 经代理访问本地 fixture HTTP server → 断言 addon 的 request 钩子收到 flow。
不依赖真实外网。
"""

from __future__ import annotations

import sys
import threading
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from aaa.capture.engine import ProxyConfig, start_in_background
from conftest import free_port, wait_until  # pytest conftest 同目录模块


class FlowRecorder:
    """最小 addon：记录 request 钩子收到的 flow（T0.2 冒烟探针）。"""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.flows: list[object] = []
        self.client_connected_count = 0

    def client_connected(self, client: object) -> None:
        with self.lock:
            self.client_connected_count += 1

    def request(self, flow: object) -> None:
        with self.lock:
            self.flows.append(flow)


@pytest.fixture
def recorder() -> FlowRecorder:
    return FlowRecorder()


@pytest.fixture
def proxy_handle(data_dir: Path, recorder: FlowRecorder) -> Iterator[object]:
    """后台线程中的 regular 代理（独立端口、独立 confdir）。"""
    config = ProxyConfig(
        listen_host="127.0.0.1", listen_port=free_port(), confdir=data_dir / "mitm"
    )
    handle = start_in_background(config, [recorder])
    yield handle
    handle.stop()


def test_embedded_regular_proxy_delivers_flow_to_request_hook(
    proxy_handle: object, http_fixture_server: object, recorder: FlowRecorder
) -> None:
    """库嵌入路线可行：经代理的 HTTP 请求触发 addon.request 钩子。"""
    fixture_port = http_fixture_server.server_address[1]  # type: ignore[attr-defined]
    url = f"http://127.0.0.1:{fixture_port}/smoke"
    with httpx.Client(
        proxy=f"http://127.0.0.1:{proxy_handle.listen_port}",  # type: ignore[attr-defined]
        trust_env=False,  # 忽略环境代理设置
        timeout=10.0,
    ) as client:
        response = client.get(url)
    assert response.status_code == 200
    assert response.text == "fixture-ok"

    assert wait_until(lambda: len(recorder.flows) >= 1, timeout=10.0)
    flow = recorder.flows[0]
    assert flow.request.pretty_url == url  # type: ignore[attr-defined]
    assert flow.request.method == "GET"  # type: ignore[attr-defined]
    assert recorder.client_connected_count >= 1


@pytest.mark.skipif(
    sys.platform != "win32",
    reason="非 Windows 上 confdir 的 CA 生成时机不同（疑似首次 TLS 才懒生成），待专项验证",
)
def test_embedded_proxy_generates_ca_in_confdir(proxy_handle: object, data_dir: Path) -> None:
    """代理启动时在 confdir（data/mitm）生成 CA，供 T1.3 复用。"""
    confdir = data_dir / "mitm"
    assert (confdir / "mitmproxy-ca.pem").exists()
    assert (confdir / "mitmproxy-ca-cert.pem").exists()
