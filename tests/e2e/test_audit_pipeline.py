"""P3 E2E：审计管线全场景（03 文档 T3.5）。

本地 **HTTPS** fixture server 充当"AI 端点"（无外网、无系统改动、无管理员权限），
覆盖 mitmproxy 真实 TLS 解密路径（02 文档 G1"HTTPS 为主战场"）：客户端以
mitmproxy CA 校验服务端证书（``verify=`` 进程级注入，不改系统证书存储）——
请求体能命中内容规则，即证明流量经过了"CONNECT → TLS 拦截 → 解密 → 明文求值"全链路：

1. dry-run（出厂默认）：①含假 AWS key 请求 ②512KB 代码体 → 命中告警（放行）；
   ③正常请求 → 放行且无内容命中；事件与证据齐全；
2. enforce：①被合成 403（端点未收到），②③照常到达端点；
3. 真实 TLS 下的 SNI kill（02 文档 D5 / decisions.md D-10 手工探针的自动化回归）：
   enforce 域名 blocklist 在 ClientHello 阶段杀死握手，对照组握手正常。
"""

from __future__ import annotations

import hashlib
import json
import socket
import ssl
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml

from aaa.capture.addon import AuditAddon
from aaa.capture.engine import ProxyConfig, start_in_background
from aaa.engine.pipeline import AuditPipeline
from aaa.policy.loader import PolicyLoader
from aaa.setup import ca as ca_mod
from aaa.store.evidence import EvidenceStore
from aaa.store.jsonl import JsonlEventStore
from conftest import free_port, wait_until

#: 假 AWS 密钥（形似真钥、非官方示例，专供测试）
FAKE_AWS_KEY = "AKIAQ2FZV3TQPE8KX9YZ"
CODE_BODY_TARGET = 512 * 1024  # 512KB（03 文档 T3.5）


def _policy_doc(mode: str) -> dict[str, Any]:
    """与 policies/default.yaml 同构的最小策略（本地 fixture 域名走 unknown 类）。"""
    return {
        "version": 1,
        "mode": mode,
        "defaults": {"fail_open": True, "max_body_scan": 262144},
        "domains": {
            "classes": {"known_ai_api": ["api.openai.com"]},
            "rules": [
                {
                    "id": "domain-unknown",
                    "match": {"class": "unknown"},
                    "action": "alert",
                    "weight": 20,
                }
            ],
        },
        "processes": {"profiles": {}, "rules": []},
        "content": {
            "scanners": ["secrets", "pii", "code_leak"],
            "rules": [
                {"id": "secret-leak", "scanner": "secrets", "action": "block", "weight": 60},
                {
                    "id": "pii-bulk",
                    "scanner": "pii",
                    "match": {"hits_gt": 10},
                    "action": "confirm",
                    "weight": 40,
                },
                {
                    "id": "code-bulk-upload",
                    "match": {"body_size_gt": 512000, "code_likeness_gt": 0.6},
                    "action": "confirm",
                    "weight": 40,
                },
            ],
        },
        "volume": [],
        "time_window": [],
    }


def _write_policy(tmp_path: Path, mode: str) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(
        yaml.safe_dump(_policy_doc(mode), allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    return path


def _code_body() -> bytes:
    """高代码密度、约 512KB 的 Python 风格代码体（代码特征行占比 > 0.6）。"""
    chunk = (
        "import os\n"
        "import sys\n"
        "import json\n"
        "def transform(payload, opts):\n"
        '    data = {"items": [x for x in payload]};\n'
        "    if (data is not None):\n"
        '        return {"ok": True, "items": data};\n'
        '    raise ValueError("bad payload");\n'
    )
    reps = CODE_BODY_TARGET // len(chunk) + 1
    body = (chunk * reps).encode()
    assert len(body) >= CODE_BODY_TARGET
    return body


def _run_proxy(data_dir: Path, policy_path: Path):  # type: ignore[no-untyped-def]
    """起代理 + addon + 管线，返回 (handle, events, addon, ca_pem)。"""
    events = JsonlEventStore(data_dir / "raw")
    evidence = EvidenceStore(data_dir / "evidence", rel_base=data_dir)
    pipeline = AuditPipeline(PolicyLoader(policy_path))
    addon = AuditAddon(
        events,
        evidence,
        mode="regular",
        attributor=None,  # 归因质量见 test_attribution_quality.py；此处聚焦管线
        pipeline=pipeline,
    )
    confdir = data_dir / "mitm"
    # 预生成 CA（与采集引擎共用同一 confdir）：客户端 verify= 信任 mitmproxy 签发的证书
    ca_pem = ca_mod.ensure_ca(confdir).path
    config = ProxyConfig(
        listen_host="127.0.0.1",
        listen_port=free_port(),
        confdir=confdir,
        ssl_insecure=True,  # 上游为自签名本地 fixture（mitmproxy 12 默认校验上游证书）
    )
    handle = start_in_background(config, [addon])
    return handle, events, addon, ca_pem


def _client_ssl_context(ca_pem: Path) -> ssl.SSLContext:
    """客户端 TLS 上下文：只信任 mitmproxy CA（进程级注入，不改系统证书存储）。"""
    return ssl.create_default_context(cafile=str(ca_pem))


def _send(
    base: str, proxy_url: str, path: str, content: bytes, ca_pem: Path
) -> httpx.Response:
    with httpx.Client(
        proxy=proxy_url, trust_env=False, timeout=30.0, verify=_client_ssl_context(ca_pem)
    ) as client:
        return client.post(f"{base}{path}", content=content)


def test_dry_run_audit_pipeline_end_to_end(
    data_dir: Path, tmp_path: Path, https_fixture_server
) -> None:
    """出厂默认 dry-run：命中告警但放行，事件与证据齐全（02 文档 §0/D4/D6）。"""
    fixture_port = https_fixture_server.server_address[1]
    base = f"https://127.0.0.1:{fixture_port}"
    policy_path = _write_policy(tmp_path, "dry-run")
    handle, events, addon, ca_pem = _run_proxy(data_dir, policy_path)
    try:
        proxy_url = f"http://127.0.0.1:{handle.listen_port}"
        # 预热：让 127.0.0.1 不再触发 unknown 首连告警，后续断言更精确
        warm = _send(base, proxy_url, "/warmup", b"{}", ca_pem)
        assert warm.status_code == 200

        # ① 含假 AWS key 的请求
        secret_payload = json.dumps({"model": "gpt-x", "api_key": FAKE_AWS_KEY}).encode()
        r1 = _send(base, proxy_url, "/v1/chat/completions", secret_payload, ca_pem)
        assert r1.status_code == 200, "dry-run 下命中密钥仍应放行"

        # ② 512KB 代码体
        r2 = _send(base, proxy_url, "/upload/code", _code_body(), ca_pem)
        assert r2.status_code == 200, "dry-run 下代码体命中 confirm 仍应放行"

        # ③ 正常请求
        r3 = _send(base, proxy_url, "/v1/hello", b'{"message": "hi"}', ca_pem)
        assert r3.status_code == 200

        assert wait_until(lambda: len(events.read_all()) >= 4, timeout=15.0), (
            f"事件不足：{len(events.read_all())} < 4"
        )
        by_path = {e.request.path: e for e in events.read_all()}

        # ① secret-leak 命中（block 判定，dry-run 只告警）——TLS 解密后才能看到明文密钥
        ev1 = by_path["/v1/chat/completions"]
        assert {r["id"] for r in ev1.matched_rules} >= {"secret-leak"}
        assert ev1.verdict == "block"
        assert ev1.action_taken == "alerted"
        assert ev1.risk_score >= 60
        # 证据不携带完整密钥，事件可留痕
        assert FAKE_AWS_KEY not in json.dumps([r for r in ev1.matched_rules])

        # ② code-bulk-upload 命中（confirm）
        ev2 = by_path["/upload/code"]
        assert "code-bulk-upload" in {r["id"] for r in ev2.matched_rules}
        assert ev2.verdict == "confirm"
        assert ev2.action_taken == "alerted"
        assert ev2.request.size >= CODE_BODY_TARGET

        # ③ 正常请求：无内容规则命中
        ev3 = by_path["/v1/hello"]
        assert {r["id"] for r in ev3.matched_rules} == set()
        assert ev3.verdict == "allow"
        assert ev3.action_taken == "logged"

        # 证据齐全：body 请求有证据文件 + sha256 可复核；512KB 截断到 256KB
        for ev in (ev1, ev2, ev3):
            assert ev.evidence is not None and ev.evidence.file
            evidence_path = data_dir / ev.evidence.file
            assert evidence_path.exists()
            assert hashlib.sha256(evidence_path.read_bytes()).hexdigest() == ev.evidence.sha256
        assert ev2.evidence is not None
        assert ev2.evidence.truncated is True
        assert ev2.evidence.size == 262144  # max_body_scan/证据上限 256KB

        # 端点收到了 dry-run 的全部三个请求（未被阻断）
        received_paths = [req[1] for req in https_fixture_server.requests if len(req) > 2]
        assert "/v1/chat/completions" in received_paths
        assert "/upload/code" in received_paths

        # policy_version 落事件（02 文档 §6）
        assert all(e.policy_version for e in by_path.values())
    finally:
        handle.stop()


def test_enforce_blocks_fake_key_before_endpoint(
    data_dir: Path, tmp_path: Path, https_fixture_server
) -> None:
    """enforce：假密钥请求被 403 且端点未收到；代码体/正常请求照常到达（02 文档 D5）。"""
    fixture_port = https_fixture_server.server_address[1]
    base = f"https://127.0.0.1:{fixture_port}"
    policy_path = _write_policy(tmp_path, "enforce")
    handle, events, addon, ca_pem = _run_proxy(data_dir, policy_path)
    try:
        proxy_url = f"http://127.0.0.1:{handle.listen_port}"
        warm = _send(base, proxy_url, "/warmup2", b"{}", ca_pem)
        assert warm.status_code == 200

        before = len([r for r in https_fixture_server.requests if len(r) > 2])

        # ① 假 AWS key → 403（含规则 id），端点未收到
        secret_payload = json.dumps({"model": "gpt-x", "api_key": FAKE_AWS_KEY}).encode()
        r1 = _send(base, proxy_url, "/v1/blocked-path", secret_payload, ca_pem)
        assert r1.status_code == 403
        body = json.loads(r1.content)
        assert body["aaa"] == "blocked"
        assert "secret-leak" in body["rules"]

        # ② 512KB 代码体 → confirm 不阻断，端点收到
        r2 = _send(base, proxy_url, "/upload/code2", _code_body(), ca_pem)
        assert r2.status_code == 200

        # ③ 正常请求 → 端点收到
        r3 = _send(base, proxy_url, "/v1/ok", b'{"message": "hi"}', ca_pem)
        assert r3.status_code == 200

        assert wait_until(lambda: len(events.read_all()) >= 4, timeout=15.0)
        by_path = {e.request.path: e for e in events.read_all()}
        ev1 = by_path["/v1/blocked-path"]
        assert ev1.action_taken == "blocked-403"
        assert ev1.verdict == "block"

        # 端点收到的请求：不含被阻断的 ①
        received = [req[1] for req in https_fixture_server.requests if len(req) > 2][before:]
        assert "/v1/blocked-path" not in received, "被阻断请求不得到达端点"
        assert "/upload/code2" in received
        assert "/v1/ok" in received
    finally:
        handle.stop()


# --------------------------------------------------------------------------
# 真实 TLS 下的 SNI kill（D-10 手工探针的自动化回归防线）
# --------------------------------------------------------------------------


def _tls_handshake_via_proxy(
    proxy_port: int, connect_host: str, connect_port: int, sni: str
) -> None:
    """经代理 CONNECT 后做真实 TLS 握手（原生 socket，等价 D-10 的手工探针）。

    握手成功则正常返回（连接随后关闭）；握手被杀则抛 ``OSError``
    （``ssl.SSLError`` / ``ConnectionResetError`` 等）。CONNECT 阶段的 host 用
    ``connect_host``（不在 blocklist），SNI 单独由 ``server_hostname`` 指定。
    """
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=10) as sock:
        sock.settimeout(10)
        sock.sendall(
            f"CONNECT {connect_host}:{connect_port} HTTP/1.1\r\n"
            f"Host: {connect_host}:{connect_port}\r\n\r\n".encode()
        )
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(4096)
            if not chunk:
                raise AssertionError("代理在 CONNECT 响应前关闭了连接")
            response += chunk
        status_line = response.split(b"\r\n", 1)[0].decode("latin-1")
        assert " 200 " in status_line, f"CONNECT 未成功：{status_line}"
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # 探针只关心连接是否被杀，不校验信任链
        tls_sock = context.wrap_socket(sock, server_hostname=sni)
        try:
            tls_sock.do_handshake()
        finally:
            tls_sock.close()


def test_enforce_sni_kill_real_tls_handshake(
    data_dir: Path, tmp_path: Path, https_fixture_server
) -> None:
    """SNI 命中 enforce blocklist → 真实 TLS 握手被杀；SNI 不在名单 → 握手成功。

    CONNECT 目标（127.0.0.1）不在 blocklist，因此阻断发生在 ClientHello 解析后的
    ``tls_start_client``（decisions.md D-10/D-11）。若 mitmproxy 升级改变该钩子
    语义导致 kill 失效，本测试会以"DID NOT RAISE"失败。
    """
    doc = _policy_doc("enforce")
    doc["domains"]["rules"].append(
        {
            "id": "domain-blocklist",
            "match": {"host_regex": r"\.mal\.com$"},
            "action": "block",
            "weight": 80,
        }
    )
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        yaml.safe_dump(doc, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )
    handle, events, _addon, _ca_pem = _run_proxy(data_dir, policy_path)
    try:
        fixture_port = https_fixture_server.server_address[1]
        # 杀死组：SNI 命中 blocklist → 握手必须失败
        with pytest.raises(OSError):
            _tls_handshake_via_proxy(
                handle.listen_port, "127.0.0.1", fixture_port, "c2.evil.mal.com"
            )
        # 对照组：SNI 不在名单 → 真实 TLS 握手成功（kill 是精确命中，不是一刀切）
        _tls_handshake_via_proxy(
            handle.listen_port, "127.0.0.1", fixture_port, "api.openai.com"
        )
        # SNI kill 发生在 HTTP 语义之前：两类探针都不产生请求事件
        assert events.read_all() == []
    finally:
        handle.stop()
