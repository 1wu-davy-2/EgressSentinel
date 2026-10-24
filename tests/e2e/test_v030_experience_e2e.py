"""v0.3.0 体验与生态 E2E（06 文档波次二第 6 条）。

四条验收场景（06 文档波次二 §6）：
1. **profile 切换 → 策略热更新生效**：``aaa policy use`` 拷贝 profile → current.yaml，
   运行中的真实代理（CaptureEngine + AuditAddon + PolicyLoader）在 mtime 轮询内
   加载新策略，新请求按新规则求值（本地 fixture 服务器，无外网）；
2. **``--lang en`` 冒烟**：子进程 ``python -m aaa.cli --help`` 全英文（AAA_LANG 与
   ``--lang`` 两条路径），中文为对照组；
3. **daily report 渲染**：真实 SQLite 库种子 → ``aaa report --daily`` 落 HTML，
   聚合数字/脱敏/HTML 转义；
4. **forwarder → collector 本机往返**：真实 uvicorn 监听 127.0.0.1，Forwarder
   经真实 httpx（trust_env=False）POST /ingest，脱敏事件落 hub.db 可查询。

红线：全程本地回环/临时目录；不触网、不碰真实 policies/ 与系统设置。
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
import uvicorn
from typer.testing import CliRunner

from aaa import config as config_mod
from aaa.capture.addon import AuditAddon
from aaa.capture.engine import ProxyConfig, start_in_background
from aaa.cli import app
from aaa.hub.collector import HubCollector, create_hub_app
from aaa.hub.forwarder import Forwarder
from aaa.policy.loader import PolicyLoader
from aaa.policy.model import PolicyDocument
from aaa.store.db import DbEventStore
from aaa.store.events import AuditEvent, Destination, RequestInfo
from aaa.store.evidence import EvidenceStore
from conftest import free_port, wait_until

runner = CliRunner()

#: 测试用假密钥（形似真钥、非官方示例 allowlist；与 test_hub/test_notify 同源）
FAKE_AWS_KEY = "AKIAQ2FZV3TQPE8KX9YZ"

#: hub 共享令牌（测试专用）
HUB_TOKEN = "v030-e2e-token"

_CJK_RE = re.compile(r"[\u4e00-\u9fff]")

_PROFILE_COMMON = """\
version: 1
mode: dry-run
defaults:
  fail_open: true
  max_body_scan: 262144
domains:
  classes: {}
  rules: []
processes:
  profiles: {}
  rules: []
content:
  scanners: [secrets]
  rules:
    - id: {rule_id}
      scanner: secrets
      action: alert
      weight: {weight}
volume: []
time_window: []
notifications:
  toast:
    enabled: false
sampling:
  enabled: false
"""


def _event(**overrides: object) -> AuditEvent:
    fields: dict[str, object] = {
        "id": "evt_v030",
        "ts": datetime.now(UTC).astimezone().isoformat(timespec="milliseconds"),
        "mode": "regular",
        "verdict": "alert",
        "risk_score": 20,
        "destination": Destination(host="e2e-v030.example.com", port=443),
        "request": RequestInfo(method="GET", path="/v030", size=0),
    }
    fields.update(overrides)
    return AuditEvent(**fields)  # type: ignore[arg-type]


# ------------------------------------------------ 1. profile 切换 → 热更新生效


def test_profile_switch_hot_reload(
    tmp_path: Path, data_dir: Path, http_fixture_server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``policy use`` 切换后，运行中的代理在 mtime 轮询内按新策略求值。"""
    policies_dir = tmp_path / "policies"
    profiles_dir = policies_dir / "profiles"
    profiles_dir.mkdir(parents=True)
    (profiles_dir / "base.yaml").write_text(
        _PROFILE_COMMON.replace("{rule_id}", "base-secret").replace("{weight}", "5"),
        encoding="utf-8",
    )
    (profiles_dir / "strict.yaml").write_text(
        _PROFILE_COMMON.replace("{rule_id}", "strict-secret").replace("{weight}", "50"),
        encoding="utf-8",
    )
    monkeypatch.setattr(config_mod, "DEFAULT_POLICIES_DIR", policies_dir)

    switched = runner.invoke(app, ["policy", "use", "base"])
    assert switched.exit_code == 0, switched.output
    current = policies_dir / "current.yaml"
    assert current.exists()

    store = DbEventStore(data_dir / "audit.db", evidence_dir=data_dir / "evidence")
    evidence = EvidenceStore(data_dir / "evidence", rel_base=data_dir)
    loader = PolicyLoader(config_mod.default_policy_file())
    doc_before: PolicyDocument = loader.load()
    addon = AuditAddon(store, evidence, mode="regular", pipeline=audit_pipeline(loader))
    config = ProxyConfig(
        listen_host="127.0.0.1", listen_port=free_port(), confdir=data_dir / "mitm"
    )
    handle = start_in_background(config, [addon])
    fixture_port = http_fixture_server.server_address[1]
    base_url = f"http://127.0.0.1:{fixture_port}"
    proxy_url = f"http://127.0.0.1:{config.listen_port}"
    try:
        with httpx.Client(proxy=proxy_url, trust_env=False, timeout=10.0) as client:
            resp = client.post(f"{base_url}/v030-1", content=f"key {FAKE_AWS_KEY}".encode())
            assert resp.status_code == 200

        assert wait_until(lambda: store.count() >= 1, timeout=20.0)
        first = store.latest(1)[0]
        first_rules = {str(rule.get("id")) for rule in first.matched_rules}
        assert "base-secret" in first_rules, first.matched_rules
        assert first.policy_version == doc_before.policy_version

        # —— 切换 profile：拷贝 strict → current.yaml（2s mtime 轮询热更新）——
        switched = runner.invoke(app, ["policy", "use", "strict"])
        assert switched.exit_code == 0, switched.output
        doc_after = PolicyLoader(config_mod.default_policy_file()).load()
        assert doc_after.policy_version != doc_before.policy_version

        # 热更新靠 mtime 轮询（2s）：像真实流量一样持续发请求，直到新策略生效。
        # 切换后首个请求可能在旧策略窗口内求值（如实语义，不视为失败）。
        deadline = time.monotonic() + 25.0
        second: AuditEvent | None = None
        while time.monotonic() < deadline:
            with httpx.Client(proxy=proxy_url, trust_env=False, timeout=10.0) as client:
                client.post(f"{base_url}/v030-2", content=f"key {FAKE_AWS_KEY}".encode())
            events = store.query(limit=30)[0]
            candidates = [e for e in events if e.request.path == "/v030-2"]
            matched = [e for e in candidates if "strict-secret" in
                       {str(r.get("id")) for r in e.matched_rules}]
            if matched:
                second = matched[-1]
                break
            time.sleep(0.5)
        assert second is not None, "切换 profile 后新请求未按新策略求值（热更新未生效）"
        second_rules = {str(rule.get("id")) for rule in second.matched_rules}
        assert "strict-secret" in second_rules
        assert "base-secret" not in second_rules, "旧 profile 的规则不应残留"
        assert second.policy_version == doc_after.policy_version
    finally:
        handle.stop()
        store.close()


def audit_pipeline(loader: PolicyLoader):  # noqa: ANN201 - 测试辅助（避免顶层多余导入）
    from aaa.engine.pipeline import AuditPipeline

    return AuditPipeline(loader)


# --------------------------------------------------- 2. --lang en 冒烟（子进程）


def _run_cli_subprocess(
    args: list[str], *, env_lang: str | None
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["NO_COLOR"] = "1"
    env["TERM"] = "dumb"
    env["PYTHONIOENCODING"] = "utf-8"
    if env_lang is None:
        env.pop("AAA_LANG", None)
    else:
        env["AAA_LANG"] = env_lang
    return subprocess.run(
        [sys.executable, "-m", "aaa.cli", *args],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        env=env,
        cwd=str(Path(__file__).resolve().parents[2]),
        check=False,
    )


def test_lang_en_help_smoke_via_aaa_lang_env() -> None:
    """``AAA_LANG=en aaa --help``：帮助全英文（导入期渲染路径）。"""
    proc = _run_cli_subprocess(["--help"], env_lang="en")
    assert proc.returncode == 0, proc.stderr
    assert "Usage:" in proc.stdout
    assert not _CJK_RE.search(proc.stdout), "英文模式下帮助不得残留中文"


def test_lang_en_help_smoke_via_flag() -> None:
    """``aaa --lang en policy list --help``：启动期预扫描 → 子命令帮助全英文。"""
    proc = _run_cli_subprocess(["--lang", "en", "policy", "list", "--help"], env_lang=None)
    assert proc.returncode == 0, proc.stderr
    assert "Usage:" in proc.stdout
    assert not _CJK_RE.search(proc.stdout), "``--lang en`` 下子命令帮助不得残留中文"


def test_lang_default_zh_control() -> None:
    """对照组：默认 zh 帮助含中文（默认输出不变的红线）。"""
    proc = _run_cli_subprocess(["--help"], env_lang=None)
    assert proc.returncode == 0, proc.stderr
    assert _CJK_RE.search(proc.stdout), "默认语言应为中文"


# ------------------------------------------------------- 3. daily report 渲染


def test_daily_report_render_masking_and_escaping(tmp_path: Path) -> None:
    data = tmp_path / "data"
    store = DbEventStore(data / "audit.db", evidence_dir=data / "evidence")
    now = datetime.now(UTC).astimezone()
    events = [
        _event(
            id=f"evt_dr_{i}",
            ts=(now - timedelta(hours=i)).isoformat(timespec="milliseconds"),
            verdict="block" if i % 2 == 0 else "alert",
            risk_score=90 - i * 10,
            request=RequestInfo(
                method="POST",
                path=(
                    f"/leak?k={FAKE_AWS_KEY}&x=<script>alert(1)</script>"
                    if i == 0
                    else f"/normal/{i}"
                ),
                size=100 + i,
            ),
        )
        for i in range(4)
    ]
    assert store.insert_events(events) == 4
    store.close()

    result = runner.invoke(app, ["report", "--daily", "--data-dir", str(data)])
    assert result.exit_code == 0, result.output
    from datetime import date

    report_file = data / "reports" / f"daily-{date.today().isoformat()}.html"
    assert report_file.exists(), result.output
    html = report_file.read_text(encoding="utf-8")
    assert "block" in html and "alert" in html, "按判定聚合应出现"
    assert FAKE_AWS_KEY not in html, "明文密钥绝不出现在日报（脱敏红线）"
    assert "<script>alert(1)</script>" not in html, "HTML 必须转义"
    assert "&lt;script&gt;" in html


# -------------------------------------------- 4. forwarder → collector 本机往返


@pytest.fixture
def hub_server(tmp_path: Path):
    """真实 uvicorn 监听 127.0.0.1 的 hub 中心（本机 TCP 往返；不发外网）。"""
    collector = HubCollector(tmp_path / "hub.db", HUB_TOKEN)
    server = uvicorn.Server(
        uvicorn.Config(create_hub_app(collector), host="127.0.0.1", port=free_port(),
                       log_level="error")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    assert wait_until(lambda: server.started, timeout=15.0), "uvicorn 未在期限内启动"
    yield collector, f"http://127.0.0.1:{server.config.port}"
    server.should_exit = True
    thread.join(timeout=10)
    collector.close()


def test_forwarder_to_collector_loopback_roundtrip(hub_server) -> None:
    collector, base_url = hub_server
    forwarder = Forwarder(
        base_url, HUB_TOKEN, retries=2, retry_backoff=0.1, timeout=3.0
    )
    try:
        forwarder.enqueue(
            _event(
                id="evt_fwd_1",
                verdict="block",
                risk_score=60,
                request=RequestInfo(method="POST", path=f"/chat?k={FAKE_AWS_KEY}", size=50),
            )
        )
        forwarder.enqueue(_event(id="evt_fwd_2", verdict="alert", risk_score=20))
        forwarder.flush(10.0)
        stats = forwarder.stats()
        assert stats["sent_events"] == 2, stats
        assert stats["send_errors"] == 0, stats
        # 中心侧内存缓冲（flush_threshold=100）落盘后再查询
        collector.flush()

        with httpx.Client(trust_env=False, timeout=5.0) as client:
            ok = client.get(
                f"{base_url}/api/hub/events?limit=10",
                headers={"Authorization": f"Bearer {HUB_TOKEN}"},
            )
            assert ok.status_code == 200
            payload = ok.json()
            assert payload["total"] == 2
            hosts = {item["destination"]["host"] for item in payload["items"]}
            assert hosts == {"e2e-v030.example.com"}
            # 脱敏红线：明文密钥不出现在中心收到的任何字节里
            assert FAKE_AWS_KEY not in ok.text
            # 鉴权拒绝矩阵（真实 TCP 往返）
            no_token = client.get(f"{base_url}/api/hub/events")
            assert no_token.status_code == 401
            wrong = client.get(
                f"{base_url}/api/hub/events", headers={"Authorization": "Bearer nope"}
            )
            assert wrong.status_code == 401
    finally:
        forwarder.close(1.0)
    # 中心侧跨机聚合统计可见
    assert collector.machines(), "hub.db 应有机器维度记录"
