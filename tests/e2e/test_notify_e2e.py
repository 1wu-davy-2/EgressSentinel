"""通知链路 E2E（04 文档 T5）。

真实代理（regular 模式 + HTTPS fixture 端点）→ AuditAddon 入队 → Dispatcher →
**假通道**（安全红线：E2E 用假通道，绝不真实发送 toast/webhook）：

1. enforce 下假 AWS key 请求被 block → 假 toast + 假 webhook 各收到一条**脱敏**摘要
   （明文密钥绝不出现在通知正文，04 文档 §6）；
2. 连发 20 条 alert 事件 → 每通道 ≤10 条 + 1 条 digest（滑动窗口限流合并）。
"""

from __future__ import annotations

import json
import ssl
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml

from aaa.capture.addon import AuditAddon
from aaa.capture.engine import ProxyConfig, start_in_background
from aaa.engine.pipeline import AuditPipeline
from aaa.notify.dispatcher import Dispatcher
from aaa.notify.model import NotifyConfig, RateLimitConfig
from aaa.policy.loader import PolicyLoader
from aaa.setup import ca as ca_mod
from aaa.store.events import AuditEvent
from aaa.store.evidence import EvidenceStore
from aaa.store.jsonl import JsonlEventStore
from conftest import free_port, wait_until

#: 假 AWS 密钥（形似真钥、非官方示例，专供测试）
FAKE_AWS_KEY = "AKIAQ2FZV3TQPE8KX9YZ"


class FakeNotifyChannel:
    """E2E 假通道（04 文档 §6：E2E 用假通道，绝不真实发送）。"""

    def __init__(self, name: str) -> None:
        self.name = name
        self.messages: list[tuple[str, AuditEvent]] = []

    def send(self, text: str, event: AuditEvent) -> None:
        self.messages.append((text, event))


def _notify_config(max_per_minute: int = 10) -> NotifyConfig:
    return NotifyConfig(rate_limit=RateLimitConfig(max_per_minute=max_per_minute))


def _policy_doc(mode: str, *, with_notifications: bool = True) -> dict[str, Any]:
    """本地 fixture 策略：secret-leak（block）+ host_regex alert 规则 + 通知段。"""
    doc: dict[str, Any] = {
        "version": 1,
        "mode": mode,
        "defaults": {"fail_open": True, "max_body_scan": 262144},
        "domains": {
            "classes": {"known_ai_api": ["api.openai.com"]},
            "rules": [
                {
                    "id": "alert-every-request",
                    "match": {"host_regex": "^127\\.0\\.0\\.1$"},
                    "action": "alert",
                    "weight": 20,
                }
            ],
        },
        "processes": {"profiles": {}, "rules": []},
        "content": {
            "scanners": ["secrets"],
            "rules": [
                {"id": "secret-leak", "scanner": "secrets", "action": "block", "weight": 60},
            ],
        },
        "volume": [],
        "time_window": [],
    }
    if with_notifications:
        doc["notifications"] = {
            "min_action": "alert",
            "toast": {"enabled": True},
            "webhook": {"enabled": True, "provider": "generic", "url": "https://hooks.invalid/x"},
            "rate_limit": {"max_per_minute": 10},
        }
    return doc


def _write_policy(tmp_path: Path, mode: str, **kwargs: Any) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(
        yaml.safe_dump(_policy_doc(mode, **kwargs), allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    return path


def _run_proxy(
    data_dir: Path, policy_path: Path, dispatcher: Dispatcher
) -> tuple[Any, JsonlEventStore, AuditAddon, Path]:
    """起代理 + addon（挂 dispatcher）+ 管线，返回 (handle, events, addon, ca_pem)。"""
    events = JsonlEventStore(data_dir / "raw")
    evidence = EvidenceStore(data_dir / "evidence", rel_base=data_dir)
    pipeline = AuditPipeline(PolicyLoader(policy_path))
    addon = AuditAddon(
        events,
        evidence,
        mode="regular",
        attributor=None,
        pipeline=pipeline,
        dispatcher=dispatcher,
    )
    confdir = data_dir / "mitm"
    ca_info = ca_mod.ensure_ca(confdir)  # 预生成 CA，与采集引擎共用 confdir
    config = ProxyConfig(
        listen_host="127.0.0.1",
        listen_port=free_port(),
        confdir=confdir,
        ssl_insecure=True,  # 上游为自签名本地 fixture（与 test_audit_pipeline 一致）
    )
    handle = start_in_background(config, [addon])
    return handle, events, addon, ca_info.path


@pytest.fixture
def fake_channels() -> tuple[FakeNotifyChannel, FakeNotifyChannel]:
    return FakeNotifyChannel("toast"), FakeNotifyChannel("webhook")


def _client(ca_pem: Path, proxy_url: str) -> httpx.Client:
    """经代理的客户端：只信任 mitmproxy CA（进程级注入，不改系统证书存储）。"""
    return httpx.Client(
        proxy=proxy_url,
        verify=ssl.create_default_context(cafile=str(ca_pem)),
        trust_env=False,
        timeout=30.0,
    )


def test_enforce_block_notifies_masked_summary_via_fake_channels(
    data_dir: Path,
    tmp_path: Path,
    https_fixture_server,
    fake_channels: tuple[FakeNotifyChannel, FakeNotifyChannel],
) -> None:
    """enforce 假密钥 block → 假 toast+webhook 各收 1 条脱敏摘要（04 文档 T5-1）。"""
    fixture_port = https_fixture_server.server_address[1]
    base = f"https://127.0.0.1:{fixture_port}"
    policy_path = _write_policy(tmp_path, "enforce")
    toast_fake, webhook_fake = fake_channels
    dispatcher = Dispatcher([toast_fake, webhook_fake], config=_notify_config())
    handle, _events, _addon, ca_pem = _run_proxy(data_dir, policy_path, dispatcher)
    try:
        proxy_url = f"http://127.0.0.1:{handle.listen_port}"
        secret_payload = json.dumps({"model": "gpt-x", "api_key": FAKE_AWS_KEY}).encode()
        with _client(ca_pem, proxy_url) as client:
            response = client.post(f"{base}/v1/chat/completions", content=secret_payload)
        assert response.status_code == 403, "enforce 下假密钥请求应被 403"

        assert wait_until(
            lambda: len(toast_fake.messages) >= 1 and len(webhook_fake.messages) >= 1,
            timeout=10.0,
        ), (
            f"假通道未收到通知：toast={len(toast_fake.messages)} "
            f"webhook={len(webhook_fake.messages)}"
        )
        dispatcher.flush(2.0)

        # 各通道恰好 1 条（未触发限流，无 digest）
        assert len(toast_fake.messages) == 1
        assert len(webhook_fake.messages) == 1
        for name, (text, event) in [
            ("toast", toast_fake.messages[0]),
            ("webhook", webhook_fake.messages[0]),
        ]:
            assert event.verdict == "block"
            assert "动作：block" in text
            # 脱敏红线：明文密钥绝不出现在通知正文（04 文档 §6）
            assert FAKE_AWS_KEY not in text, f"{name} 通知泄露明文密钥"
            assert "secret-leak" in text, "命中规则应出现在摘要"
            # 扫描器 evidence 是打码形态（保留首 4 尾 2），摘要照实携带
            assert "AKIA****YZ" in text, f"{name} 通知应携带打码后的密钥指纹"
    finally:
        dispatcher.close()
        handle.stop()


def test_burst_alerts_rate_limited_to_digest(
    data_dir: Path,
    tmp_path: Path,
    https_fixture_server,
    fake_channels: tuple[FakeNotifyChannel, FakeNotifyChannel],
) -> None:
    """连发 20 条 alert → 假通道 ≤10 条 + 1 条 digest（04 文档 T5-2）。"""
    fixture_port = https_fixture_server.server_address[1]
    base = f"https://127.0.0.1:{fixture_port}"
    policy_path = _write_policy(tmp_path, "dry-run")
    toast_fake, webhook_fake = fake_channels
    dispatcher = Dispatcher([toast_fake, webhook_fake], config=_notify_config())
    handle, events, _addon, ca_pem = _run_proxy(data_dir, policy_path, dispatcher)
    try:
        proxy_url = f"http://127.0.0.1:{handle.listen_port}"
        # 单会话（keep-alive）连发 20 条，避免 20 次 TLS 握手拖慢测试
        with _client(ca_pem, proxy_url) as client:
            for i in range(20):
                response = client.post(f"{base}/v1/burst/{i}", content=b'{"n": 1}')
                assert response.status_code == 200

        assert wait_until(lambda: len(events.read_all()) >= 20, timeout=15.0), (
            f"事件不足：{len(events.read_all())}"
        )
        assert wait_until(
            lambda: len(toast_fake.messages) >= 10 and len(webhook_fake.messages) >= 10,
            timeout=10.0,
        )
        dispatcher.flush(5.0)

        stats = dispatcher.stats()
        for channel in (toast_fake, webhook_fake):
            texts = [text for text, _event in channel.messages]
            event_messages = [t for t in texts if "被限流" not in t]
            digests = [t for t in texts if "被限流" in t]
            assert len(event_messages) <= 10, f"{channel.name} 超过限流窗口"
            assert len(digests) == 1, f"{channel.name} 应合并出恰好 1 条 digest"
            assert "另有 10 条事件被限流" in digests[0]
        # suppressed_total 按通道累计：每通道限流 10 条 × 2 通道 = 20
        assert stats["suppressed_total"] == 20
        assert stats["dropped"] == 0
    finally:
        dispatcher.close()
        handle.stop()
