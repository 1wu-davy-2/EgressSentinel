"""通知模块单测（04 文档 T1-T4）。

红线：**严禁真实发送**——toast 的 PowerShell、webhook 的 httpx、email 的 smtplib
全部注入假实现；不依赖真实网络；不触碰系统设置。
"""

from __future__ import annotations

import base64
import threading
import time
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest

import aaa.notify.dispatcher as dispatcher_mod
from aaa.notify.channels import (
    CHANNEL_NAMES,
    EmailChannel,
    ToastChannel,
    WebhookChannel,
    build_channels,
    default_webhook_client_factory,
    encode_powershell_command,
    webhook_payload,
)
from aaa.notify.dispatcher import Dispatcher, build_dispatcher
from aaa.notify.model import (
    EmailConfig,
    NotifyConfig,
    RateLimitConfig,
    ToastConfig,
    WebhookConfig,
    apply_env_overrides,
    disabled_notify_config,
)
from aaa.notify.summary import (
    SUMMARY_MAX_CHARS,
    build_digest_text,
    build_summary,
    mask_event_path,
)
from aaa.policy.loader import PolicyError, PolicyLoader
from aaa.store.events import (
    AuditEvent,
    Destination,
    ProcessInfo,
    RequestInfo,
)

#: 假 AWS 密钥（形似真钥、非官方示例 allowlist，专供测试）
FAKE_AWS_KEY = "AKIAQ2FZV3TQPE8KX9YZ"


@pytest.fixture(autouse=True)
def _clean_notify_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """隔离 AAA_* 凭据环境变量：装配类测试不受本机环境影响。"""
    monkeypatch.delenv("AAA_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("AAA_SMTP_PASSWORD", raising=False)


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


class FakeChannel:
    """假通道：记录 (text, event)；可注入异常/阻塞。"""

    def __init__(
        self,
        name: str,
        *,
        error_on: Callable[[str], bool] | None = None,
        gate: threading.Event | None = None,
    ) -> None:
        self.name = name
        self.messages: list[tuple[str, AuditEvent]] = []
        self.error_on = error_on
        self.gate = gate

    def send(self, text: str, event: AuditEvent) -> None:
        if self.gate is not None:
            self.gate.wait(timeout=10)
        if self.error_on is not None and self.error_on(text):
            raise RuntimeError(f"injected failure for {self.name}")
        self.messages.append((text, event))


# ==========================================================================
# T1 model.py：缺省 / 完整 / 非法配置 + 环境变量覆盖
# ==========================================================================


def _write_policy(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_missing_notifications_section_all_disabled(tmp_path: Path) -> None:
    """老策略文件无 notifications 段：不报错且全部通道关闭（04 文档 §3 T1）。"""
    doc = PolicyLoader(_write_policy(tmp_path, "version: 1\nmode: dry-run\n")).load()
    assert doc.notifications.toast.enabled is False
    assert doc.notifications.webhook.enabled is False
    assert doc.notifications.email.enabled is False


def test_full_notifications_section_parses(tmp_path: Path) -> None:
    """完整 notifications 段（default.yaml 形态）逐字段解析。"""
    path = _write_policy(
        tmp_path,
        """
version: 1
notifications:
  min_action: confirm
  toast:
    enabled: true
  webhook:
    enabled: true
    provider: feishu
    url: "https://open.feishu.cn/open-apis/bot/v2/hook/xxx"
  email:
    enabled: true
    smtp_host: smtp.example.com
    smtp_port: 465
    use_tls: true
    username: u
    password: p
    from_addr: a@b.c
    to_addrs: [x@y.z]
  rate_limit:
    max_per_minute: 3
""",
    )
    notify = PolicyLoader(path).load().notifications
    assert notify.min_action == "confirm"
    assert notify.toast.enabled is True
    assert notify.webhook.provider == "feishu"
    assert notify.webhook.url.endswith("hook/xxx")
    assert notify.email.to_addrs == ["x@y.z"]
    assert notify.rate_limit.max_per_minute == 3
    assert notify.enabled_channel_names() == ["toast", "webhook", "email"]


def test_partial_section_uses_field_defaults(tmp_path: Path) -> None:
    """段落存在但省略字段：按字段级出厂默认（toast 开、webhook/email 关）。"""
    path = _write_policy(
        tmp_path, "version: 1\nnotifications:\n  rate_limit:\n    max_per_minute: 5\n"
    )
    notify = PolicyLoader(path).load().notifications
    assert notify.toast.enabled is True
    assert notify.webhook.enabled is False
    assert notify.rate_limit.max_per_minute == 5


@pytest.mark.parametrize(
    "snippet",
    [
        "notifications:\n  unknown_field: 1\n",  # extra=forbid：拼写错误必须被抓
        "notifications:\n  min_action: bogus\n",  # 门槛只允许 alert|confirm|block
        "notifications:\n  webhook:\n    provider: twitter\n",  # 未知 provider
        "notifications:\n  rate_limit:\n    max_per_minute: 0\n",  # 必须 ≥1
    ],
)
def test_invalid_notifications_rejected(tmp_path: Path, snippet: str) -> None:
    with pytest.raises(PolicyError):
        PolicyLoader(_write_policy(tmp_path, f"version: 1\n{snippet}")).load()


def test_env_overrides_apply(monkeypatch: pytest.MonkeyPatch) -> None:
    """AAA_WEBHOOK_URL / AAA_SMTP_PASSWORD 优先于策略文件（04 文档 §2）。"""
    base = NotifyConfig(
        webhook=WebhookConfig(enabled=True, url=""),
        rate_limit=RateLimitConfig(max_per_minute=2),
    )
    monkeypatch.setenv("AAA_WEBHOOK_URL", "https://hooks.example/t1")
    monkeypatch.setenv("AAA_SMTP_PASSWORD", "pw-from-env")
    merged = apply_env_overrides(base)
    assert merged.webhook.url == "https://hooks.example/t1"
    assert merged.webhook.enabled is True  # 原本就启用
    assert merged.email.password == "pw-from-env"
    assert merged.rate_limit.max_per_minute == 2  # 其余字段不动
    assert base.webhook.url == ""  # 入参不被修改


def test_env_webhook_url_alone_enables_trial(monkeypatch: pytest.MonkeyPatch) -> None:
    """仅设环境变量（策略 url 为空且未启用）→ 视为显式试用意图启用 webhook。

    见 decisions 日志：04 文档「便于快速试用」的解释性实现；策略已配 url 时
    enabled 开关仍以策略为准。
    """
    monkeypatch.setenv("AAA_WEBHOOK_URL", "https://hooks.example/t2")
    trial = apply_env_overrides(NotifyConfig())
    assert trial.webhook.enabled is True and trial.webhook.url.endswith("/t2")
    explicit = apply_env_overrides(NotifyConfig(webhook=WebhookConfig(enabled=False, url="x")))
    # 策略已自配 url：enabled 开关以策略为准，但 url 值仍被环境变量覆盖
    assert explicit.webhook.enabled is False and explicit.webhook.url.endswith("/t2")


def test_env_empty_string_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AAA_WEBHOOK_URL", "")
    monkeypatch.setenv("AAA_SMTP_PASSWORD", "")
    config = NotifyConfig()
    assert apply_env_overrides(config) == config


def test_disabled_notify_config_factory() -> None:
    disabled = disabled_notify_config()
    assert disabled.enabled_channel_names() == []
    assert disabled.min_action == "alert"


# ==========================================================================
# T2 summary.py：脱敏摘要
# ==========================================================================


def test_summary_masks_fake_aws_key() -> None:
    """含假 AWS key 的事件摘要必须打码（04 文档 §6 红线）。"""
    event = _event(request=RequestInfo(method="POST", path=f"/k?key={FAKE_AWS_KEY}", size=1))
    summary = build_summary(event)
    assert FAKE_AWS_KEY not in summary.text
    assert summary.masked_hits.get("aws-access-token") == 1


def test_summary_required_fields_present() -> None:
    """字段齐全：时间/动作/风险分/进程/主机/命中规则（04 文档 §3 T2）。"""
    event = _event(
        matched_rules=[
            {
                "id": "secret-leak",
                "dim": "content",
                "action": "block",
                "weight": 60,
                "evidence": "AKIA****YZ",
            }
        ]
    )
    text = build_summary(event).text
    for fragment in (
        "动作：block",
        "风险分 80",
        "主机：api.openai.com POST /v1/chat",
        "进程：node.exe(1234)",
        "规则：secret-leak(content)「AKIA****YZ」",
        "时间：2026-10-24T12:00:00.000+08:00",
    ):
        assert fragment in text, f"摘要缺少 {fragment}"


def test_summary_process_unknown_and_no_rules() -> None:
    text = build_summary(_event(process=None)).text
    assert "进程：unknown" in text
    assert "规则：-" in text


def test_summary_truncated_to_200_chars() -> None:
    summary = build_summary(_event(destination=Destination(host="h" * 500, port=1)))
    assert len(summary.text) == SUMMARY_MAX_CHARS
    assert summary.truncated is True


def test_summary_not_truncated_normally() -> None:
    assert build_summary(_event()).truncated is False


def test_mask_event_path_keeps_clean_path() -> None:
    assert mask_event_path("/v1/chat/completions") == "/v1/chat/completions"


def test_digest_text_mentions_suppressed_count() -> None:
    assert "另有 10 条事件被限流" in build_digest_text(10, max_per_minute=10)


# ==========================================================================
# T3 channels.py：三通道（全部注入假实现）
# ==========================================================================


def test_channel_names() -> None:
    assert CHANNEL_NAMES == ("toast", "webhook", "email")


def test_webhook_payload_six_providers() -> None:
    """六种 provider payload 形态（04 文档 §4）。"""
    event = _event()
    text = "摘要文本"
    assert webhook_payload("generic", text, event) == event.model_dump(mode="json")
    assert webhook_payload("wecom", text, event) == {
        "msgtype": "markdown",
        "markdown": {"content": text},
    }
    assert webhook_payload("dingtalk", text, event) == {
        "msgtype": "markdown",
        "markdown": {"title": "EgressSentinel 审计告警", "text": text},
    }
    assert webhook_payload("feishu", text, event) == {
        "msg_type": "text",
        "content": {"text": text},
    }
    assert webhook_payload("slack", text, event) == {"text": text}
    assert webhook_payload("discord", text, event) == {"content": text}


def test_generic_payload_masks_free_text_fields() -> None:
    """generic 外发前的最后防线：path/cmdline/exe/error 打码（04 文档 §6）。"""
    event = _event(
        process=ProcessInfo(
            pid=1,
            name="node.exe",
            exe="C:\\tools\\node.exe",
            cmdline=["node", f"--token={FAKE_AWS_KEY}"],
        ),
        request=RequestInfo(method="GET", path=f"/?key={FAKE_AWS_KEY}", size=0),
        error=f"upstream refused: {FAKE_AWS_KEY}",
    )
    dumped = str(webhook_payload("generic", "t", event))
    assert FAKE_AWS_KEY not in dumped
    assert "aws-access-token" in dumped


class FakeResponse:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


class FakeWebhookClient:
    """假 httpx 客户端：记录 POST；可编排「第 N 次失败/状态码」。"""

    def __init__(self, script: list[Exception | int], calls: list[dict[str, object]]) -> None:
        self._script = list(script)
        self.calls = calls
        self.closed = False

    def post(self, url: str, json: dict[str, object]) -> FakeResponse:
        self.calls.append({"url": url, "json": json})
        outcome: Exception | int = self._script.pop(0) if self._script else 200
        if isinstance(outcome, Exception):
            raise outcome
        return FakeResponse(outcome)

    def close(self) -> None:
        self.closed = True


def test_webhook_send_success_single_post() -> None:
    calls: list[dict[str, object]] = []
    client = FakeWebhookClient([], calls)
    channel = WebhookChannel("slack", "https://hooks.example/x", client_factory=lambda: client)
    channel.send("hello", _event())
    assert len(calls) == 1
    assert calls[0]["url"] == "https://hooks.example/x"
    assert calls[0]["json"] == {"text": "hello"}
    assert client.closed, "客户端用完必须关闭"


def test_webhook_retry_once_then_success() -> None:
    """失败重试 1 次：第二次成功即送达（04 文档 §4）。"""
    calls: list[dict[str, object]] = []
    attempt = {"n": 0}

    def factory() -> FakeWebhookClient:
        attempt["n"] += 1
        if attempt["n"] == 1:
            return FakeWebhookClient([httpx.ConnectError("boom")], calls)
        return FakeWebhookClient([], calls)

    channel = WebhookChannel("wecom", "https://hooks.example/x", client_factory=factory, retries=1)
    channel.send("hello", _event())
    assert len(calls) == 2, "首次失败 + 重试成功 = 2 次 POST"


def test_webhook_retries_exhausted_no_raise_but_checked_raises() -> None:
    calls: list[dict[str, object]] = []
    channel = WebhookChannel(
        "discord",
        "https://hooks.example/x",
        client_factory=lambda: FakeWebhookClient([500, 500], calls),
        retries=1,
    )
    channel.send("hello", _event())  # 不抛出（dispatcher 契约：失败记日志）
    assert len(calls) == 2, "失败重试 1 次共 2 次尝试"
    with pytest.raises(RuntimeError):
        channel.send_checked("hello", _event())


def test_webhook_empty_url_rejected() -> None:
    with pytest.raises(ValueError):
        WebhookChannel("slack", "")


def test_default_webhook_client_is_direct_connection() -> None:
    """trust_env=False（04 文档 §6：直连不经本机代理防回环）+ 3s 超时。"""
    client = default_webhook_client_factory()
    try:
        assert client._trust_env is False  # type: ignore[attr-defined]
        assert client.timeout.connect == 3.0
        assert client.timeout.read == 3.0
    finally:
        client.close()


def test_encode_powershell_command_is_utf16le_base64() -> None:
    encoded = encode_powershell_command("你好 toast")
    assert base64.b64decode(encoded).decode("utf-16-le") == "你好 toast"


def test_toast_encoded_command_contains_script() -> None:
    """-EncodedCommand 参数 = UTF-16LE Base64（04 文档 §4），含标题与正文前 3 行。"""
    captured: list[list[str]] = []
    channel = ToastChannel(run_powershell=captured.append)
    channel.send("第1行\n第2行\n第3行\n第4行\n第5行", _event())
    assert len(captured) == 1
    argv = captured[0]
    assert argv[:3] == ["powershell", "-NoProfile", "-NonInteractive"]
    encoded = argv[argv.index("-EncodedCommand") + 1]
    script = base64.b64decode(encoded).decode("utf-16-le")
    assert "EgressSentinel 审计告警" in script
    for line in ("第1行", "第2行", "第3行"):
        assert f"<text>{line}</text>" in script
    assert "第4行" not in script, "toast 正文只取摘要前 3 行"
    assert "CreateToastNotifier" in script and "Show($toast)" in script


def test_toast_escapes_xml_special_chars() -> None:
    captured: list[list[str]] = []
    channel = ToastChannel(run_powershell=captured.append)
    channel.send("a<b>&c", _event())
    script = base64.b64decode(captured[0][captured[0].index("-EncodedCommand") + 1]).decode(
        "utf-16-le"
    )
    assert "a&lt;b&gt;&amp;c" in script


def test_toast_failure_is_silent() -> None:
    def boom(argv: list[str]) -> None:
        raise FileNotFoundError("powershell not found")

    channel = ToastChannel(run_powershell=boom)
    channel.send("hello", _event())  # 失败静默（04 文档 §4），不抛出


def test_email_sender_injected() -> None:
    sent: list[tuple[str, str]] = []
    channel = EmailChannel(
        disabled_notify_config().email, sender=lambda subject, body: sent.append((subject, body))
    )
    channel.send("邮件正文", _event())
    assert sent == [("EgressSentinel 审计告警", "邮件正文")]


def test_email_failure_logged_not_raised() -> None:
    def boom(subject: str, body: str) -> None:
        raise ConnectionRefusedError("smtp down")

    channel = EmailChannel(disabled_notify_config().email, sender=boom)
    channel.send("正文", _event())  # 失败记日志不抛出（04 文档 §4）
    with pytest.raises(ConnectionRefusedError):
        channel.send_checked("正文", _event())


def test_build_channels_skips_incomplete_config() -> None:
    """webhook 无 url / email 不完整 → 告警跳过（04 文档 §3 装配约束）。"""
    config = NotifyConfig(
        toast=ToastConfig(enabled=True),
        webhook=WebhookConfig(enabled=True, url=""),
        email=EmailConfig(enabled=True, smtp_host=""),
    )
    assert [ch.name for ch in build_channels(config)] == ["toast"]


def test_build_channels_full() -> None:
    config = NotifyConfig(
        toast=ToastConfig(enabled=True),
        webhook=WebhookConfig(enabled=True, url="https://hooks.example/x"),
    )
    assert [ch.name for ch in build_channels(config)] == ["toast", "webhook"]


# ==========================================================================
# T4 dispatcher.py：永不阻塞 / 限流 digest / flush / 异常隔离
# ==========================================================================


def _notify_config(max_per_minute: int = 10, min_action: str = "alert") -> NotifyConfig:
    return NotifyConfig(
        min_action=min_action,  # type: ignore[arg-type]
        rate_limit=RateLimitConfig(max_per_minute=max_per_minute),
    )


def test_enqueue_never_blocks_when_queue_full() -> None:
    """队列满：enqueue 立即返回并丢弃计数（04 文档 §3：审计主路径永不阻塞）。"""
    gate = threading.Event()
    slow = FakeChannel("toast", gate=gate)
    dispatcher = Dispatcher([slow], config=_notify_config(), queue_maxsize=1)
    try:
        dispatcher.enqueue(_event(id="evt_first"))
        deadline = time.monotonic() + 5
        while not slow.messages and time.monotonic() < deadline:
            time.sleep(0.01)  # worker 已取走第一条并阻塞在 send（占住发送锁）
        started = time.monotonic()
        for i in range(10):
            dispatcher.enqueue(_event(id=f"evt_{i}"))
        elapsed = time.monotonic() - started
        assert elapsed < 1.0, "enqueue 在队列满时必须立即返回"
        assert dispatcher.dropped >= 1
    finally:
        gate.set()
        dispatcher.close()


def test_rate_limit_merges_into_single_digest() -> None:
    """20 条事件 + max_per_minute=10：10 条正常 + flush 补 1 条 digest（04 文档 T4/T5）。"""
    channel = FakeChannel("toast")
    dispatcher = Dispatcher([channel], config=_notify_config(max_per_minute=10))
    try:
        for i in range(20):
            dispatcher.enqueue(_event(id=f"evt_{i}"))
        dispatcher.flush(5.0)
        texts = [text for text, _ in channel.messages]
        assert len(texts) == 11, f"应恰好 10 条通知 + 1 条 digest，得到 {len(texts)}"
        digests = [t for t in texts if "被限流" in t]
        assert len(digests) == 1
        assert "另有 10 条事件被限流" in digests[0]
        stats = dispatcher.stats()
        assert stats["sent"] == 10
        assert stats["digests_sent"] == 1
        assert stats["suppressed_total"] == 10
    finally:
        dispatcher.close()


def test_flush_bounded_when_channel_blocks() -> None:
    """flush 有界：通道卡住时到点放弃，绝不阻塞退出（04 文档 §3）。"""
    gate = threading.Event()
    slow = FakeChannel("toast", gate=gate)
    dispatcher = Dispatcher([slow], config=_notify_config())
    try:
        dispatcher.enqueue(_event())
        deadline = time.monotonic() + 5
        while not slow.messages and time.monotonic() < deadline:
            time.sleep(0.01)
        dispatcher.enqueue(_event(id="evt_pending"))  # 队列里还压着一条
        started = time.monotonic()
        dispatcher.flush(0.2)
        assert time.monotonic() - started < 2.0, "flush 必须有界返回"
    finally:
        gate.set()
        dispatcher.close()


def test_channel_exception_isolated() -> None:
    """单通道异常：不影响其他通道，也不影响 worker（04 文档 §3）。"""
    bad = FakeChannel("toast", error_on=lambda _text: True)
    good = FakeChannel("webhook")
    dispatcher = Dispatcher([bad, good], config=_notify_config())
    try:
        for i in range(3):
            dispatcher.enqueue(_event(id=f"evt_{i}"))
        dispatcher.flush(5.0)
        assert len(good.messages) == 3, "好通道必须照常收到全部通知"
        stats = dispatcher.stats()
        assert stats["send_errors"] == 3
        assert stats["sent"] == 3
    finally:
        dispatcher.close()


def test_min_action_and_stats() -> None:
    dispatcher = Dispatcher([FakeChannel("toast")], config=_notify_config(min_action="block"))
    assert dispatcher.min_action == "block"
    assert dispatcher.channel_names == ["toast"]


def test_config_hot_reload_rebuilds_channels(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """策略热更新（04 文档 §1 ⑤）：provider 配置变化 → 通道自动重建（无需重启）。"""
    monkeypatch.setattr("aaa.policy.loader.RELOAD_POLL_SECONDS", 0.0)
    built: list[list[FakeChannel]] = []

    def fake_build_channels(config: NotifyConfig) -> list[FakeChannel]:
        # 红线：热更新重建必须走假通道——绝不真的发 toast/webhook
        channels = [FakeChannel(name) for name in config.enabled_channel_names()]
        built.append(channels)
        return channels

    monkeypatch.setattr(dispatcher_mod, "build_channels", fake_build_channels)
    path = _write_policy(
        tmp_path,
        "version: 1\nnotifications:\n  rate_limit:\n    max_per_minute: 2\n",
    )
    dispatcher = build_dispatcher(PolicyLoader(path))
    try:
        assert dispatcher.channel_names == ["toast"]  # 段落存在：toast 字段默认开
        assert dispatcher.min_action == "alert"
        time.sleep(0.05)
        path.write_text(
            "version: 1\nnotifications:\n  rate_limit:\n    max_per_minute: 4\n"
            "  webhook:\n    enabled: true\n    provider: slack\n"
            "    url: https://hooks.example/x\n",
            encoding="utf-8",
        )
        dispatcher.enqueue(_event())  # 事件触发热更新检查 → 重建 → 经新通道发送
        dispatcher.flush(5.0)
        assert dispatcher.channel_names == ["toast", "webhook"]
        latest = built[-1]
        assert all(len(ch.messages) == 1 for ch in latest), "重建后的两个通道各收一条"
    finally:
        dispatcher.close()


def test_worker_survives_summary_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """worker 异常隔离兜底：摘要构建抛异常也不死。"""

    def boom(*args: object, **kwargs: object) -> str:
        raise RuntimeError("boom")

    channel = FakeChannel("toast")
    dispatcher = Dispatcher([channel], config=_notify_config())
    try:
        monkeypatch.setattr(dispatcher_mod, "build_summary", boom)
        dispatcher.enqueue(_event())
        dispatcher.flush(2.0)
        monkeypatch.setattr(dispatcher_mod, "build_summary", build_summary)  # 恢复
        dispatcher.enqueue(_event(id="evt_after"))
        dispatcher.flush(2.0)
        assert len(channel.messages) == 1, "恢复后照常发送"
    finally:
        dispatcher.close()


# ==========================================================================
# T6 CLI：aaa notify test（只测参数校验与装配，04 文档 T6）+ status 通知概要行
# ==========================================================================


@pytest.fixture
def notify_env_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    """CLI 通知测试同样隔离 AAA_* 环境变量。"""
    monkeypatch.delenv("AAA_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("AAA_SMTP_PASSWORD", raising=False)


def test_notify_test_rejects_unknown_channel(notify_env_clean: None) -> None:
    from typer.testing import CliRunner

    from aaa.cli import app

    result = CliRunner().invoke(app, ["notify", "test", "--channel", "sms"])
    assert result.exit_code != 0
    assert "toast|webhook|email" in " ".join(result.output.split())


def test_notify_test_no_channels_enabled(tmp_path: Path, notify_env_clean: None) -> None:
    """全关策略：如实报错退出（不是静默假装成功）。"""
    from typer.testing import CliRunner

    from aaa.cli import app

    policy = _write_policy(tmp_path, "version: 1\n")
    result = CliRunner().invoke(app, ["notify", "test", "--policy", str(policy)])
    assert result.exit_code == 1
    assert "未启用任何通知通道" in " ".join(result.output.split())


def test_notify_test_assembly_uses_selected_channel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, notify_env_clean: None
) -> None:
    """装配验证：--channel webhook 只装配并触发 webhook 通道（假实现，零真实发送）。"""
    from typer.testing import CliRunner

    import aaa.cli as cli_mod
    from aaa.cli import app

    sent: list[tuple[str, str]] = []

    class RecordingChannel:
        def __init__(self, name: str) -> None:
            self.name = name

        def send_checked(self, text: str, event: object) -> None:
            sent.append((self.name, text))

    def fake_build_channels(config: NotifyConfig) -> list[RecordingChannel]:
        return [RecordingChannel(name) for name in config.enabled_channel_names()]

    monkeypatch.setattr(cli_mod, "build_channels", fake_build_channels)
    policy = _write_policy(
        tmp_path,
        "version: 1\nnotifications:\n"
        "  toast:\n    enabled: true\n"
        "  webhook:\n    enabled: true\n    provider: slack\n    url: https://hooks.example/x\n",
    )
    result = CliRunner().invoke(
        app, ["notify", "test", "--channel", "webhook", "--policy", str(policy)]
    )
    assert result.exit_code == 0, result.output
    assert [name for name, _text in sent] == ["webhook"], "只发选中的通道"
    assert sent and "测试通知" in sent[0][1]


def test_notify_test_channel_config_missing_fails_honestly(
    tmp_path: Path, notify_env_clean: None
) -> None:
    """--channel email 但策略未启用 email：非零退出 + 指引（不假成功）。"""
    from typer.testing import CliRunner

    from aaa.cli import app

    policy = _write_policy(tmp_path, "version: 1\n")
    result = CliRunner().invoke(
        app, ["notify", "test", "--channel", "email", "--policy", str(policy)]
    )
    assert result.exit_code == 1
    assert "email" in result.output


def test_status_shows_notification_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, notify_env_clean: None
) -> None:
    """aaa status 通知概要行（04 文档 T6）：通道/门槛/限流；凭据绝不出现。"""
    from rich.console import Console
    from typer.testing import CliRunner

    import aaa.cli as cli_mod
    from aaa.cli import app

    monkeypatch.setattr(cli_mod, "console", Console(width=300))
    policy = _write_policy(
        tmp_path,
        "version: 1\nnotifications:\n"
        "  min_action: block\n"
        "  webhook:\n    enabled: true\n    provider: feishu\n"
        "    url: https://open.feishu.cn/open-apis/bot/v2/hook/TOKEN123\n"
        "  email:\n    enabled: false\n    password: supersecret123\n",
    )
    result = CliRunner().invoke(
        app,
        ["status", "--data-dir", str(tmp_path / "data"), "--policy", str(policy)],
    )
    assert result.exit_code == 0, result.output
    out = " ".join(result.output.split())
    assert "通知" in out
    assert "webhook" in out and "min_action=block" in out and "10 条/分钟" in out
    # 安全红线：url 内嵌 token 与 SMTP 密码绝不进状态输出
    assert "TOKEN123" not in out
    assert "supersecret123" not in out
