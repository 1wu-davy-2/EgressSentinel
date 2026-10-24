"""整体 E2E 验收剧本（03 文档 §4）：一条测试串起全部能力。

剧本步骤（对应 03 文档 §4）：
1. ``aaa setup --yes``（fixture 模式：CurrentUser CA + 系统代理 + 用户环境变量，
   全部 journal-first 记录、可还原）；
2. 起 mitmproxy regular 模式 + 本地 **HTTPS** "AI 端点" fixture；
3. 三个模拟客户端（python/node/curl）各发：正常请求 / 假 AWS key / 512KB 代码体；
4. 断言：归因正确、①正常放行 ②密钥 ③代码体告警（dry-run）；切 enforce 后重发 ②
   得 403 且目标端点未收到；
5. ``aaa status`` 可见事件与待还原改动；``aaa teardown`` 后系统状态与初始快照一致
   （再跑一次幂等 no-op）。面板 API 全流程（过滤/脱敏/解锁/导出/决策）见
   test_web_flow.py（同一验收线的面板侧）。

安全红线（为何能"真跑 setup/teardown"而不违规）：
- ``aaa setup``/``aaa teardown`` 走**真实 CLI 代码路径**，但全部系统后端注入假实现：
  注册表/环境变量/WM_SETTINGCHANGE/InternetSetOption 经共享夹具 ``fake_backends``
  （tests/conftest.py），CA 安装/卸载经本模块的记录器假函数——验证的是应用与还原
  逻辑本身，绝不真实施改系统设置；
- HTTPS 端点的自签名证书只落 ``tmp_path``；客户端信任经进程级机制注入
  （httpx ``verify=``、curl ``--cacert``、node ``NODE_EXTRA_CA_CERTS``），不改证书存储；
- node/curl 客户端缺失时跳过对应子场景（03 文档 T2.3 同规则）。
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import ssl
import subprocess
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml
from typer.testing import CliRunner

from aaa.attribution.table import ProcessAttributor
from aaa.capture.addon import AuditAddon
from aaa.capture.engine import ProxyConfig, start_in_background
from aaa.cli import app
from aaa.engine.pipeline import AuditPipeline
from aaa.policy.loader import PolicyLoader
from aaa.setup import ca as ca_mod
from aaa.setup.state import StateFile
from aaa.store.db import DbEventStore
from aaa.store.evidence import EvidenceStore
from conftest import free_port, wait_until

# 剧本集成归因/setup 等已知的 Linux/macOS 缺口（见 docs/notes/decisions.md
# 「CI 跨平台矩阵落地记录」），随各缺口专项修复后逐项放开。
pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="集成剧本依赖 Windows 专属路径（归因/CA 时机等），缺口修复前仅在 Windows 执行",
)

runner = CliRunner()

FAKE_AWS_KEY = "AKIAQ2FZV3TQPE8KX9YZ"
CODE_BODY_TARGET = 512 * 1024
PROXY_PORT = 8080  # §4 剧本默认（aaa setup 默认 --proxy-port）

CLIENTS = ("python", "curl", "node")
PAYLOAD_PATHS = {
    "normal": "/payload/normal",
    "secret": "/payload/secret-key",
    "code": "/payload/code-bulk",
}


# --------------------------------------------------------------------------
# 剧本素材：策略 / 载荷 / 客户端
# --------------------------------------------------------------------------


def _policy_doc(mode: str) -> dict[str, Any]:
    """与 policies/default.yaml 同构的最小策略（同 test_audit_pipeline.py）。"""
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


def _write_policy(path: Path, mode: str) -> Path:
    path.write_text(
        yaml.safe_dump(_policy_doc(mode), allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    return path


def _payload(kind: str) -> bytes:
    if kind == "normal":
        return json.dumps({"message": "hi"}).encode()
    if kind == "secret":
        return json.dumps({"model": "gpt-x", "api_key": FAKE_AWS_KEY}).encode()
    if kind == "code":
        chunk = (
            "import os\n"
            "import sys\n"
            "def transform(payload, opts):\n"
            '    data = {"items": [x for x in payload]};\n'
            "    if (data is not None):\n"
            '        return {"ok": True, "items": data};\n'
        )
        reps = CODE_BODY_TARGET // len(chunk) + 1
        body = (chunk * reps).encode()
        assert len(body) >= CODE_BODY_TARGET
        return body
    raise ValueError(kind)


def _send_python(
    base: str, proxy_url: str, path: str, body: bytes, ssl_ctx: ssl.SSLContext
) -> httpx.Response:
    with httpx.Client(proxy=proxy_url, trust_env=False, timeout=30.0, verify=ssl_ctx) as client:
        return client.post(f"{base}{path}", content=body)


def _send_curl(
    curl_path: str, proxy_url: str, url: str, body: bytes, ca_pem: Path, tmp_path: Path
) -> int:
    """curl 经代理 POST（HTTPS）：先 --cacert 校验 mitmproxy CA；失败退回 -k 再试。

    退回仅影响客户端信任锚的注入方式（Windows 自带 curl 为 Schannel 时对
    ``--cacert`` 支持不全），CONNECT+TLS 拦截与解密路径两次完全相同。
    """
    body_file = tmp_path / "curl-body.bin"
    body_file.write_bytes(body)
    # 必须剔除代理类环境变量：本机若有 NO_PROXY=…127.0.0.1…，curl 会对 127.0.0.1 目标
    # 绕过 -x 指定的代理直连（同 test_regular_capture_e2e._env_without_proxy 的教训）
    env = {
        k: v
        for k, v in os.environ.items()
        if k.lower() not in ("http_proxy", "https_proxy", "no_proxy", "all_proxy")
    }
    common = [
        curl_path,
        "-sS",
        "-w",
        "\n%{http_code}",  # 状态码追加在响应体之后（fixture 响应体很小，整体捕获）
        "-x",
        proxy_url,
        "--data-binary",
        f"@{body_file}",
        "-H",
        "Content-Type: application/octet-stream",
    ]
    proc: subprocess.CompletedProcess[bytes] | None = None
    for extra in (["--cacert", str(ca_pem)], ["-k"]):
        proc = subprocess.run(
            [*common, *extra, url], capture_output=True, timeout=30, check=False, env=env
        )
        if proc.returncode == 0:
            return int(proc.stdout.decode().strip().rsplit("\n", 1)[-1].strip())
    assert proc is not None
    raise AssertionError(f"curl 经代理请求失败：{proc.stderr.decode(errors='replace')!r}")


NODE_SCRIPT = r"""
const net = require('net');
const tls = require('tls');
const fs = require('fs');
const [proxyPort, host, port, path, bodyFile] = process.argv.slice(2);
const body = fs.readFileSync(bodyFile);
const sock = net.connect(Number(proxyPort), '127.0.0.1', () => {
  sock.write(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n\r\n`);
});
let gotResponse = false;
sock.on('error', (e) => {
  if (!gotResponse) { console.error('SOCK_ERR', e.message); process.exit(1); }
});
sock.once('data', (chunk) => {
  const status = chunk.toString('latin1').split('\r\n')[0];
  if (!status.includes(' 200 ')) { console.error('CONNECT_ERR', status); process.exit(1); }
  // RFC 6066 禁止在 SNI 中放 IP 字面量（node DEP0123），故 SNI 用 localhost
  // （mitmproxy 据此签发 DNS SAN 证书），CONNECT 隧道目标仍为 127.0.0.1:port；
  // 证书链经 NODE_EXTRA_CA_CERTS 校验（进程级注入，不改系统证书存储）。
  // 不发 Connection: close（代理关闭与响应送达存在竞态，读到响应后主动 destroy）。
  const tlsSock = tls.connect(
    { socket: sock, servername: 'localhost', rejectUnauthorized: true },
    () => {
    tlsSock.write(
      `POST ${path} HTTP/1.1\r\nHost: ${host}:${port}\r\n` +
      `Content-Type: application/octet-stream\r\n` +
      `Content-Length: ${body.length}\r\n\r\n`);
    tlsSock.write(body);
  });
  tlsSock.on('error', (e) => {
    if (!gotResponse) { console.error('TLS_ERR', e.message); process.exit(1); }
  });
  tlsSock.once('data', (d) => {
    gotResponse = true;
    process.exitCode = d.toString('latin1').split('\r\n')[0].includes(' 200 ') ? 0 : 1;
    tlsSock.destroy();
  });
});
"""


def _send_node(
    node_path: str,
    proxy_port: int,
    fixture_port: int,
    path: str,
    body: bytes,
    ca_pem: Path,
    tmp_path: Path,
) -> None:
    """node 经代理 CONNECT + TLS 发 POST（信任锚经 NODE_EXTRA_CA_CERTS 进程级注入）。"""
    script = tmp_path / "node-client.js"
    body_file = tmp_path / "node-body.bin"
    script.write_text(NODE_SCRIPT, encoding="utf-8")
    body_file.write_bytes(body)
    env = {
        k: v
        for k, v in os.environ.items()
        if k.lower() not in ("http_proxy", "https_proxy", "no_proxy", "all_proxy")
    }
    env["NODE_EXTRA_CA_CERTS"] = str(ca_pem)
    proc = subprocess.run(
        [
            node_path,
            str(script),
            str(proxy_port),
            "127.0.0.1",
            str(fixture_port),
            path,
            str(body_file),
        ],
        capture_output=True,
        timeout=30,
        check=False,
        env=env,
    )
    assert proc.returncode == 0, f"node 经代理请求失败：{proc.stderr.decode(errors='replace')!r}"


# --------------------------------------------------------------------------
# §4 剧本主体
# --------------------------------------------------------------------------


def test_full_scenario_setup_capture_clients_enforce_teardown(
    data_dir: Path,
    tmp_path: Path,
    https_fixture_server,
    fake_backends: tuple[dict[str, str], dict[str, object]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """setup → 采集（HTTPS）→ 三客户端×三载荷 → enforce 阻断 → status → teardown 还原。"""
    env_registry, inet_registry = fake_backends
    env_before = dict(env_registry)
    inet_before = dict(inet_registry)

    # 客户端可用性（缺失则跳过对应子场景，03 文档 T2.3 同规则）
    curl_path = shutil.which("curl")
    node_path = shutil.which("node")
    ran = {"python": True, "curl": curl_path is not None, "node": node_path is not None}

    # 假 CA 安装/卸载记录器（红线：不碰真实证书存储；serial 用真实 CA 的以便核对）
    installed: list[str] = []
    uninstalled: list[str] = []
    monkeypatch.setattr(
        ca_mod,
        "install_cert",
        lambda store, cert_path, **_kw: installed.append(
            ca_mod.load_ca_info(Path(cert_path)).serial
        ),
    )
    monkeypatch.setattr(
        ca_mod, "uninstall_cert", lambda store, serial, **_kw: uninstalled.append(serial)
    )

    # v0.1.2：setup --yes 默认附装自启并立即启动——测试注入假实现（红线：绝不真建任务/起进程）
    from aaa.setup import autostart as autostart_fake

    autostart_offered: list[str] = []
    launched: list[Path] = []

    class _FakeProc:  # 供 CLI 打印 pid
        pid = 424242

    def _fake_enable(state, data_dir):  # noqa: ANN001
        autostart_offered.append(str(data_dir))
        return []

    def _fake_spawn(data_dir, **_kw):  # noqa: ANN001
        launched.append(data_dir)
        return _FakeProc()

    monkeypatch.setattr(autostart_fake, "enable_autostart", _fake_enable)
    monkeypatch.setattr(autostart_fake, "spawn_run_now", _fake_spawn)

    fixture_port = https_fixture_server.server_address[1]
    base = f"https://127.0.0.1:{fixture_port}"

    # ---- 第 1 步：aaa setup（CurrentUser CA + 代理 + 环境变量，真实 CLI 路径 + 假后端）----
    result = runner.invoke(app, ["setup", "--yes", "--data-dir", str(data_dir)])
    assert result.exit_code == 0, result.output
    out = " ".join(result.output.split())
    for title in ("CA 根证书", "系统代理", "用户环境变量"):
        assert title in out, f"向导缺少 {title} 步骤"
    assert "向导结束" in out and "未执行任何改动" not in out
    assert len(installed) == 1, "CA 必须恰好安装一次（假记录器）"
    assert inet_registry["ProxyEnable"] == 1, "WinINET 代理应已下发（假注册表）"
    assert env_registry["HTTP_PROXY"] == f"http://127.0.0.1:{PROXY_PORT}"
    assert env_registry["NO_PROXY"] == "localhost,127.0.0.1"
    state_entries = StateFile(data_dir / "setup-state.json").entries()
    kinds = [entry.kind for entry in state_entries]
    assert kinds.count("env_var") == 8 and kinds.count("wininet_proxy") == 1
    assert kinds.count("ca_cert_user") == 1 and kinds.count("file_created") == 1
    # v0.1.2 默认行为：安装即守护（自启任务 + 立即后台启动，均为假实现）
    assert len(autostart_offered) == 1 and autostart_offered[0] == str(data_dir)
    assert launched == [data_dir]

    # ---- 第 2 步：mitmproxy regular + 本地 HTTPS "AI 端点" fixture ----
    policy_dry = _write_policy(tmp_path / "policy-dry-run.yaml", "dry-run")
    policy_enforce = _write_policy(tmp_path / "policy-enforce.yaml", "enforce")
    ca_pem = data_dir / "mitm" / "mitmproxy-ca-cert.pem"
    assert ca_pem.exists(), "setup 应已在 confdir 生成 mitmproxy CA"

    store = DbEventStore(data_dir / "audit.db", evidence_dir=data_dir / "evidence")
    addon = AuditAddon(
        store,
        EvidenceStore(data_dir / "evidence", rel_base=data_dir),
        mode="regular",
        attributor=ProcessAttributor(),
        pipeline=AuditPipeline(PolicyLoader(policy_dry)),
    )
    handle = start_in_background(
        ProxyConfig(
            listen_host="127.0.0.1",
            listen_port=free_port(),
            confdir=data_dir / "mitm",
            ssl_insecure=True,  # 上游是自签名本地 fixture
        ),
        [addon],
    )
    try:
        proxy_url = f"http://127.0.0.1:{handle.listen_port}"
        ssl_ctx = ssl.create_default_context(cafile=str(ca_pem))

        # 预热：吸收 unknown 域首连告警（D-13），后续载荷断言更精确
        warm = _send_python(base, proxy_url, "/warmup", b"{}", ssl_ctx)
        assert warm.status_code == 200

        # ---- 第 3 步：三客户端 × 三载荷 ----
        for kind, path in PAYLOAD_PATHS.items():
            resp = _send_python(base, proxy_url, f"/python{path}", _payload(kind), ssl_ctx)
            assert resp.status_code == 200, f"dry-run 下 {kind} 应放行"
        if curl_path:
            for kind, path in PAYLOAD_PATHS.items():
                status = _send_curl(
                    curl_path, proxy_url, f"{base}/curl{path}", _payload(kind), ca_pem, tmp_path
                )
                assert status == 200, f"curl {kind} 应放行（dry-run）"
        if node_path:
            for kind, path in PAYLOAD_PATHS.items():
                _send_node(
                    node_path,
                    handle.listen_port,
                    fixture_port,
                    f"/node{path}",
                    _payload(kind),
                    ca_pem,
                    tmp_path,
                )

        expected_min = 1 + sum(3 for c in CLIENTS if ran[c])
        assert wait_until(lambda: store.count() >= expected_min, timeout=30.0), (
            f"事件数量不足：{store.count()} < {expected_min}；"
            f"已有路径：{sorted(e.request.path for e in store.iter_all())}"
        )
        by_path = {e.request.path: e for e in store.iter_all()}

        # ---- 第 4 步（dry-run 半场）：①放行 ②③告警 + 归因正确 ----
        for client in CLIENTS:
            if not ran[client]:
                continue
            for kind, path in PAYLOAD_PATHS.items():
                event = by_path[f"/{client}{path}"]
                # 归因：python 客户端 = 本进程；子进程客户端 = 对应进程名
                assert event.process is not None, f"{client}/{kind} 事件必须带归因"
                if client == "python":
                    assert event.process.pid == os.getpid()
                    assert event.process.profile == "agent_cli"
                else:
                    assert event.process.pid is not None, (
                        f"{client}/{kind} 未归因到 PID（超出 02 文档 D2 已知边界）"
                    )
                    assert client in (event.process.name or "").lower()
                    # 02 文档 §5 默认画像：node/python 属 agent_cli；curl 属 other
                    expected_profile = "agent_cli" if client == "node" else "other"
                    assert event.process.profile == expected_profile
                if kind == "normal":
                    assert event.verdict == "allow" and event.action_taken == "logged"
                    assert {r["id"] for r in event.matched_rules} == set()
                elif kind == "secret":
                    assert "secret-leak" in {r["id"] for r in event.matched_rules}
                    assert event.verdict == "block" and event.action_taken == "alerted"
                    assert event.risk_score >= 60
                    assert FAKE_AWS_KEY not in json.dumps(event.matched_rules)
                else:
                    assert "code-bulk-upload" in {r["id"] for r in event.matched_rules}
                    assert event.verdict == "confirm" and event.action_taken == "alerted"
                    assert event.request.size >= CODE_BODY_TARGET
                    assert event.evidence is not None and event.evidence.truncated
                # 证据 sha256 可复核
                if event.evidence is not None:
                    evidence_path = data_dir / event.evidence.file
                    assert evidence_path.exists()
                    assert (
                        hashlib.sha256(evidence_path.read_bytes()).hexdigest()
                        == event.evidence.sha256
                    )

        # 端点收到全部 dry-run 载荷（未被阻断）
        received = [req[1] for req in https_fixture_server.requests if len(req) > 2]
        for client in CLIENTS:
            if not ran[client]:
                continue
            for path in PAYLOAD_PATHS.values():
                assert f"/{client}{path}" in received, f"{client} 的 {path} 未到达端点"

        # ---- 第 4 步（enforce 半场）：切换策略，重发 ② 得 403 且端点未收到 ----
        # （热更新已有单测覆盖；剧本用新进程重启代理，语义等价且确定性）
    finally:
        handle.stop()

    addon_enforce = AuditAddon(
        store,
        EvidenceStore(data_dir / "evidence", rel_base=data_dir),
        mode="regular",
        attributor=ProcessAttributor(),
        pipeline=AuditPipeline(PolicyLoader(policy_enforce)),
    )
    handle2 = start_in_background(
        ProxyConfig(
            listen_host="127.0.0.1",
            listen_port=free_port(),
            confdir=data_dir / "mitm",
            ssl_insecure=True,
        ),
        [addon_enforce],
    )
    try:
        proxy_url2 = f"http://127.0.0.1:{handle2.listen_port}"
        ssl_ctx = ssl.create_default_context(cafile=str(ca_pem))
        endpoint_before = len([r for r in https_fixture_server.requests if len(r) > 2])

        blocked = _send_python(
            base, proxy_url2, "/python/enforce-secret", _payload("secret"), ssl_ctx
        )
        assert blocked.status_code == 403, "enforce 下假密钥必须被 403"
        body = json.loads(blocked.content)
        assert body["aaa"] == "blocked" and "secret-leak" in body["rules"]

        if curl_path:
            status = _send_curl(
                curl_path,
                proxy_url2,
                f"{base}/curl/enforce-secret",
                _payload("secret"),
                ca_pem,
                tmp_path,
            )
            assert status == 403, "enforce 下 curl 假密钥必须被 403"

        assert wait_until(
            lambda: any(e.action_taken == "blocked-403" for e in store.iter_all()), timeout=15.0
        ), "enforce 阻断事件未落库"

        received_after = [
            req[1] for req in https_fixture_server.requests if len(req) > 2
        ][endpoint_before:]
        assert not any("enforce-secret" in p for p in received_after), "被阻断请求不得到达端点"

        # ---- 第 5 步前半：aaa status 可见事件与待还原改动 ----
        status_out = runner.invoke(
            app, ["status", "--data-dir", str(data_dir), "--policy", str(policy_dry)]
        )
        assert status_out.exit_code == 0, status_out.output
        norm = " ".join(status_out.output.split())
        assert f"{store.count()} 条" in norm, "status 应显示事件计数"
        assert "未还原" in norm and "teardown" in norm, "status 应提示待还原改动"
    finally:
        handle2.stop()

    # ---- 第 5 步后半：aaa teardown 后系统状态与初始快照一致 ----
    result = runner.invoke(app, ["teardown", "--data-dir", str(data_dir)])
    assert result.exit_code == 0, result.output
    out = " ".join(result.output.split())
    assert f"将按状态文件逆序还原 {len(state_entries)} 项改动" in out, "计划清单必须先于执行打印"
    assert "env_var:HTTP_PROXY" in out and "ca_cert_user" in out
    assert "teardown 完成" in out

    assert env_registry == env_before, f"环境变量必须与初始快照一致：{env_registry}"
    assert inet_registry == inet_before, f"注册表必须与初始快照一致：{inet_registry}"
    assert uninstalled == installed, "CA 必须按安装时的序列号精确卸载"
    assert StateFile(data_dir / "setup-state.json").entries() == [], "还原后记录清空"
    assert not (data_dir / "ca-bundle.pem").exists(), "工具创建的合并 PEM 应被删除"

    # 幂等：再跑一次 teardown 无操作
    again = runner.invoke(app, ["teardown", "--data-dir", str(data_dir)])
    assert again.exit_code == 0
    assert "没有需要还原" in again.output

    store.close()
