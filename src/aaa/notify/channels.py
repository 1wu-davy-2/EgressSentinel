"""通知三通道：toast / webhook / email（04 文档 §3 T3、§4 实现要点）。

**全部依赖注入，单测零真实发送**（04 文档 §6 红线）：
- toast 注入 ``run_powershell``（默认经 subprocess 发 ``-EncodedCommand``，Base64(UTF-16LE)
  规避 cp1252 编码问题）；
- webhook 注入 httpx 客户端工厂（默认 ``httpx.Client(trust_env=False, timeout=3.0)``——
  **trust_env=False 直连**，避免被自身代理拦截形成回环）；失败重试 1 次；
- email 注入发送函数（默认 smtplib ``SMTP_SSL``/``SMTP+starttls``）。

各通道自行按 04 文档要求处理失败：toast 失败记 debug 静默、webhook 重试后 warning、
email 记 error——绝不向上抛（dispatcher 还有第二层隔离）。
"""

from __future__ import annotations

import base64
import logging
import subprocess
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Protocol

import httpx

from aaa.notify.model import EmailConfig, NotifyConfig, WebhookProvider
from aaa.notify.summary import NOTIFY_TITLE, mask_event_path
from aaa.store.events import AuditEvent

logger = logging.getLogger(__name__)

#: 通道名单（CLI ``aaa notify test --channel`` 校验用）
CHANNEL_NAMES: tuple[str, ...] = ("toast", "webhook", "email")

#: webhook 超时（04 文档 §4：timeout=3.0）
WEBHOOK_TIMEOUT_SECONDS = 3.0

#: webhook 失败重试次数（04 文档 §4：失败重试 1 次——首次 + 重试共 2 次尝试）
WEBHOOK_RETRIES = 1

#: PowerShell -EncodedCommand 的编码：UTF-16LE 再 Base64（04 文档 §4：规避 cp1252）
_POWERSHELL_ENCODING = "utf-16-le"

#: toast AppId：用 PowerShell 自己的（04 文档 §4），保证 WinRT 通知有合法来源标识
POWERSHELL_APPID = r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"

#: toast 正文最多显示前 3 行摘要（04 文档 §4：正文=摘要前 3 行）
TOAST_MAX_LINES = 3


class Channel(Protocol):
    """通知通道协议（04 文档 §3：``send(text, event) -> None``）。"""

    name: str

    def send(self, text: str, event: AuditEvent) -> None:
        """发送一条通知；实现自行吞掉异常记日志，不向 dispatcher 抛出。"""
        ...


# --------------------------------------------------------------------------
# toast：PowerShell WinRT（零第三方依赖）
# --------------------------------------------------------------------------


def _xml_escape(text: str) -> str:
    """toast 模板 XML 的文本转义（防 ``<>&`` 破坏模板结构）。"""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def toast_script(title: str, lines: Sequence[str]) -> str:
    """构造 WinRT toast 的 PowerShell 脚本（模板 XML：标题 + 正文前 3 行）。"""
    body_lines = "\n".join(f"<text>{_xml_escape(line)}</text>" for line in lines[:TOAST_MAX_LINES])
    return (
        "[Windows.UI.Notifications.ToastNotificationManager,"
        " Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null\n"
        '$template = @"\n'
        '<toast><visual><binding template="ToastGeneric">'
        f"<text>{_xml_escape(title)}</text>\n{body_lines}"
        "</binding></visual></toast>\n"
        '"@\n'
        "$xml = New-Object Windows.Data.Xml.Dom.XmlDocument\n"
        "$xml.LoadXml($template)\n"
        "$toast = New-Object Windows.UI.Notifications.ToastNotification($xml)\n"
        f"[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("
        f"'{POWERSHELL_APPID}').Show($toast)"
    )


def encode_powershell_command(script: str) -> str:
    """脚本 → ``-EncodedCommand`` 参数：UTF-16LE 编码后 Base64（规避 cp1252）。"""
    return base64.b64encode(script.encode(_POWERSHELL_ENCODING)).decode("ascii")


def _run_powershell(argv: list[str]) -> None:
    """默认 PowerShell 执行器（subprocess；失败向上抛，由调用方处理）。"""
    subprocess.run(  # noqa: S603 - argv 白名单构造，无 shell
        argv,
        check=True,
        timeout=10.0,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


#: toast 的 PowerShell 执行器注入点（单测注入假实现，04 文档 §3）
PowerShellRunner = Callable[[list[str]], None]


class ToastChannel:
    """Windows 系统通知（PowerShell WinRT）。失败记 debug 静默（04 文档 §4）。"""

    name = "toast"

    def __init__(self, *, run_powershell: PowerShellRunner | None = None) -> None:
        self._run = run_powershell or _run_powershell

    def send(self, text: str, event: AuditEvent) -> None:
        try:
            self.send_checked(text, event)
        except Exception as exc:  # noqa: BLE001 - toast 失败绝不影响代理（04 文档 §4）
            logger.debug("toast 通知失败（静默）：%s", exc)

    def send_checked(self, text: str, event: AuditEvent) -> None:
        """同 ``send``，但失败向上抛（``aaa notify test`` 需要如实的成功/失败结果）。"""
        lines = [line for line in text.splitlines() if line.strip()]
        argv = [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            encode_powershell_command(toast_script(NOTIFY_TITLE, lines)),
        ]
        self._run(argv)


# --------------------------------------------------------------------------
# webhook：httpx POST JSON，trust_env=False，timeout=3.0，失败重试 1 次
# --------------------------------------------------------------------------

#: webhook 客户端工厂注入点（单测注入假客户端，04 文档 §3）
WebhookClientFactory = Callable[[], Any]
"""返回带 ``post(url, json=...)`` / ``close()`` 的客户端（生产为 httpx.Client）。"""


def default_webhook_client_factory() -> httpx.Client:
    """生产客户端工厂：**trust_env=False 直连**（04 文档 §6：不经本机代理防回环）。"""
    return httpx.Client(trust_env=False, timeout=WEBHOOK_TIMEOUT_SECONDS)


def _sanitize_event(event: AuditEvent) -> dict[str, Any]:
    """事件 JSON 外发前的最后防线：对自由文本字段按同一脱敏核心打码。

    ``matched_rules[].evidence`` 在扫描时已打码（decisions D-18）；此处补打
    ``request.path``（查询串可能带密钥）、``process.exe/cmdline``、``error``。
    只处理字段值本身，序列化后 JSON 结构完好。
    """
    data = event.model_dump(mode="json")
    request = data.get("request")
    if isinstance(request, dict) and isinstance(request.get("path"), str):
        request["path"] = mask_event_path(request["path"])
    process = data.get("process")
    if isinstance(process, dict):
        if isinstance(process.get("exe"), str):
            process["exe"] = mask_event_path(process["exe"])
        if isinstance(process.get("name"), str):
            process["name"] = mask_event_path(process["name"])
        cmdline = process.get("cmdline")
        if isinstance(cmdline, list):
            process["cmdline"] = [
                mask_event_path(item) if isinstance(item, str) else item for item in cmdline
            ]
    if isinstance(data.get("error"), str):
        data["error"] = mask_event_path(data["error"])
    return data


def webhook_payload(provider: WebhookProvider, text: str, event: AuditEvent) -> dict[str, Any]:
    """按 provider 构造 payload（04 文档 §4 六种形态）。"""
    if provider == "generic":
        # generic = 完整脱敏事件 JSON（04 文档 §4）
        return _sanitize_event(event)
    if provider == "wecom":
        return {"msgtype": "markdown", "markdown": {"content": text}}
    if provider == "dingtalk":
        return {"msgtype": "markdown", "markdown": {"title": NOTIFY_TITLE, "text": text}}
    if provider == "feishu":
        return {"msg_type": "text", "content": {"text": text}}
    if provider == "slack":
        return {"text": text}
    if provider == "discord":
        return {"content": text}
    raise ValueError(f"未知 webhook provider：{provider!r}")


class WebhookChannel:
    """Webhook 通知（httpx POST JSON；trust_env=False；失败重试 1 次）。"""

    name = "webhook"

    def __init__(
        self,
        provider: WebhookProvider,
        url: str,
        *,
        client_factory: WebhookClientFactory | None = None,
        retries: int = WEBHOOK_RETRIES,
    ) -> None:
        if not url:
            raise ValueError("webhook url 为空（策略 webhook.url 或环境变量 AAA_WEBHOOK_URL）")
        self.provider = provider
        self.url = url
        self.retries = retries
        self._client_factory = client_factory or default_webhook_client_factory

    def send(self, text: str, event: AuditEvent) -> None:
        try:
            self.send_checked(text, event)
        except Exception as exc:  # noqa: BLE001 - 重试后仍失败：记日志，不抛出
            logger.error("webhook 通知最终失败（已重试 %d 次）：%s", self.retries, exc)

    def send_checked(self, text: str, event: AuditEvent) -> None:
        """同 ``send``，但最终失败向上抛（``aaa notify test`` 需要如实的成功/失败结果）。"""
        payload = webhook_payload(self.provider, text, event)
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            client = self._client_factory()
            try:
                response = client.post(self.url, json=payload)
                status = getattr(response, "status_code", None)
                if isinstance(status, int) and 200 <= status < 300:
                    return
                # 非 2xx 视为失败，进入重试（04 文档 §4）
                last_error = RuntimeError(f"webhook 返回 HTTP {status}")
                logger.warning(
                    "webhook 通知失败（第 %d 次）：%s → %s", attempt + 1, self.url, status
                )
            except Exception as exc:  # noqa: BLE001 - 网络异常重试，最终抛出
                last_error = exc
                logger.warning("webhook 通知异常（第 %d 次）：%s", attempt + 1, exc)
            finally:
                close = getattr(client, "close", None)
                if callable(close):
                    close()
        raise RuntimeError(f"webhook 重试 {self.retries} 次后仍失败：{last_error}")


# --------------------------------------------------------------------------
# email：smtplib 注入式
# --------------------------------------------------------------------------

#: email 发送函数注入点：(subject, body) -> None（单测注入记录器，04 文档 §3）
EmailSender = Callable[[str, str], None]

#: SMTP 连接超时（秒）
SMTP_TIMEOUT_SECONDS = 10.0


def send_email(config: EmailConfig, subject: str, body: str) -> None:
    """默认 SMTP 发送实现（``SMTP_SSL`` 或 ``SMTP+starttls``，纯文本摘要）。"""
    import smtplib
    from email.message import EmailMessage

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = config.from_addr or config.username
    message["To"] = ", ".join(config.to_addrs)
    message.set_content(body)
    if config.use_tls:
        with smtplib.SMTP_SSL(
            config.smtp_host, config.smtp_port, timeout=SMTP_TIMEOUT_SECONDS
        ) as server:
            _login_and_send(server, config, message)
    else:
        with smtplib.SMTP(
            config.smtp_host, config.smtp_port, timeout=SMTP_TIMEOUT_SECONDS
        ) as server:
            server.starttls()
            _login_and_send(server, config, message)


def _login_and_send(server: Any, config: EmailConfig, message: Any) -> None:
    if config.username:
        server.login(config.username, config.password)
    server.send_message(message)


class EmailChannel:
    """SMTP 邮件通知（纯文本摘要）。失败记 error（04 文档 §4）。"""

    name = "email"

    def __init__(self, config: EmailConfig, *, sender: EmailSender | None = None) -> None:
        self.config = config
        self._sender = (
            sender
            if sender is not None
            else (lambda subject, body: send_email(config, subject, body))
        )

    def send(self, text: str, event: AuditEvent) -> None:
        try:
            self.send_checked(text, event)
        except Exception as exc:  # noqa: BLE001 - 邮件失败绝不影响代理
            logger.error("email 通知失败：%s", exc)

    def send_checked(self, text: str, event: AuditEvent) -> None:
        """同 ``send``，但失败向上抛（``aaa notify test`` 需要如实的成功/失败结果）。"""
        self._sender(NOTIFY_TITLE, text)


# --------------------------------------------------------------------------
# 装配
# --------------------------------------------------------------------------


def build_channels(config: NotifyConfig) -> list[Channel]:
    """按（已应用环境变量覆盖的）配置装配启用通道；配置不完整时告警跳过。"""
    channels: list[Channel] = []
    if config.toast.enabled:
        channels.append(ToastChannel())
    if config.webhook.enabled:
        if config.webhook.url:
            channels.append(WebhookChannel(config.webhook.provider, config.webhook.url))
        else:
            logger.warning("webhook 已启用但 url 为空（可设 AAA_WEBHOOK_URL），跳过该通道")
    if config.email.enabled:
        if config.email.smtp_host and config.email.to_addrs:
            channels.append(EmailChannel(config.email))
        else:
            logger.warning("email 已启用但 smtp_host/to_addrs 不完整，跳过该通道")
    return channels


def channel_summary(channels: Mapping[str, bool]) -> str:
    """通道启用概况的一行文本（``aaa status``/启动概要用）。"""
    enabled = [name for name in CHANNEL_NAMES if channels.get(name)]
    return ", ".join(enabled) if enabled else "全部关闭"
