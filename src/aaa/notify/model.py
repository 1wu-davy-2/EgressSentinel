"""通知配置模型（04 文档 §2：策略 YAML ``notifications`` 段 + 环境变量覆盖）。

- 所有模型 ``extra="forbid"``（与策略 schema 一致，lint 能抓到拼写错误）；
- **缺省段落=全关**（老策略文件无 ``notifications`` 段时不报错且不启用任何通道，
  ``PolicyDocument.notifications`` 的 default_factory 给出全关副本）；
- 段落**存在但字段缺省**时按出厂默认解析（``toast.enabled: true``——本机、无外发，
  webhook/email 默认关）；
- 环境变量覆盖：``AAA_WEBHOOK_URL``、``AAA_SMTP_PASSWORD``（凭据分离，便于快速试用；
  覆盖发生在解析后、装配前，不参与 ``policy_version`` 哈希，见 :func:`apply_env_overrides`）。
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

#: webhook 地址环境变量（04 文档 §2：优先于策略文件）
WEBHOOK_URL_ENV = "AAA_WEBHOOK_URL"

#: SMTP 密码环境变量（04 文档 §2：优先于策略文件；仅存本机策略文件以外的凭据通道）
SMTP_PASSWORD_ENV = "AAA_SMTP_PASSWORD"

#: 通知门槛：action 级别 allow < alert < confirm < block，事件 action ≥ min_action 才入队
MinAction = Literal["alert", "confirm", "block"]

#: webhook 六种 provider payload 形态（04 文档 §4）
WebhookProvider = Literal["generic", "wecom", "dingtalk", "feishu", "slack", "discord"]


class _Strict(BaseModel):
    """严格模型基类：禁止未知字段（与 ``policy.model._Strict`` 同约定；此处独立定义，
    避免 notify ↔ policy 循环导入——policy 单向依赖 notify）。"""

    model_config = ConfigDict(extra="forbid")


class ToastConfig(_Strict):
    """Windows 系统 toast 通知（PowerShell WinRT，零第三方依赖）。"""

    enabled: bool = True
    """出厂默认开启：本机通知、无外发（04 文档 §2）。"""


class WebhookConfig(_Strict):
    """Webhook 通知（httpx POST JSON，trust_env=False 直连）。"""

    enabled: bool = False
    provider: WebhookProvider = "generic"
    url: str = ""
    """环境变量 ``AAA_WEBHOOK_URL`` 优先（:func:`apply_env_overrides`）。"""


class EmailConfig(_Strict):
    """SMTP 邮件通知（纯文本摘要）。"""

    enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = Field(default=465, ge=1, le=65535)
    use_tls: bool = True
    """true=SMTP_SSL(465)；false=SMTP+starttls。"""
    username: str = ""
    password: str = ""
    """仅存本机策略文件；环境变量 ``AAA_SMTP_PASSWORD`` 优先。"""
    from_addr: str = ""
    to_addrs: list[str] = Field(default_factory=list)


class RateLimitConfig(_Strict):
    """通知限流（防轰炸）。"""

    max_per_minute: int = Field(default=10, ge=1)
    """每通道滑动窗口；超出部分合并为一条 digest（04 文档 §2）。"""


class NotifyConfig(_Strict):
    """``notifications`` 段（04 文档 §2 示例的 pydantic 化）。"""

    min_action: MinAction = "alert"
    toast: ToastConfig = Field(default_factory=ToastConfig)
    webhook: WebhookConfig = Field(default_factory=WebhookConfig)
    email: EmailConfig = Field(default_factory=EmailConfig)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)

    def enabled_channel_names(self) -> list[str]:
        """当前已启用的通道名（``toast``/``webhook``/``email``，装配与状态展示用）。"""
        names: list[str] = []
        if self.toast.enabled:
            names.append("toast")
        if self.webhook.enabled:
            names.append("webhook")
        if self.email.enabled:
            names.append("email")
        return names


def disabled_notify_config() -> NotifyConfig:
    """全关副本（老策略文件无 ``notifications`` 段时的缺省，04 文档 §3 T1）。

    与 ``NotifyConfig()`` 的字段级出厂默认（toast 开）区分：段落**缺席**=全关，
    段落**存在但省略字段**=按字段默认解析。
    """
    return NotifyConfig(
        toast=ToastConfig(enabled=False),
        webhook=WebhookConfig(enabled=False),
        email=EmailConfig(enabled=False),
        rate_limit=RateLimitConfig(),
    )


def apply_env_overrides(
    config: NotifyConfig, environ: Mapping[str, str] | None = None
) -> NotifyConfig:
    """按 04 文档 §2 应用环境变量覆盖（``AAA_WEBHOOK_URL`` / ``AAA_SMTP_PASSWORD``）。

    返回新对象（pydantic ``model_copy``，不改入参）；环境变量为空串视同未设置。
    不写回策略文件，也不参与 ``policy_version``——凭据只在装配通知通道时生效。
    """
    env = os.environ if environ is None else environ
    updates: dict[str, object] = {}
    webhook_url = (env.get(WEBHOOK_URL_ENV) or "").strip()
    if webhook_url:
        webhook = config.webhook.model_copy(update={"url": webhook_url})
        if not webhook.enabled and config.webhook.url == "":
            # 仅给了环境变量而策略未启用 webhook：视为显式试用意图，启用之
            webhook = webhook.model_copy(update={"enabled": True})
        updates["webhook"] = webhook
    smtp_password = env.get(SMTP_PASSWORD_ENV) or ""
    if smtp_password:
        updates["email"] = config.email.model_copy(update={"password": smtp_password})
    if not updates:
        return config
    return config.model_copy(update=updates)  # type: ignore[arg-type]
