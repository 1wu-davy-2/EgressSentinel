"""多机聚合配置模型（06 文档 W8：``AAA_HUB_URL/TOKEN`` env 或策略 ``hub:`` 段）。

- ``HubConfig`` 是策略 ``hub:`` 段的 pydantic 形态（``extra="forbid"``，与
  notify/policy 同约定）；**缺省=关**（老策略文件无 ``hub:`` 段不报错、不外发）；
- ``policy/model.py`` 属 06 文档全局禁改清单，故模型定义在本模块，波次二集成时
  把它挂到 ``PolicyDocument``（或由集成层透传），本模块不回头改 policy；
- 环境变量覆盖：``AAA_HUB_URL`` / ``AAA_HUB_TOKEN``（优先于策略文件，凭据分离，
  与 notify 的 ``AAA_WEBHOOK_URL`` / ``AAA_SMTP_PASSWORD`` 同思路）。
"""

from __future__ import annotations

import os
from collections.abc import Mapping

from pydantic import BaseModel, ConfigDict, Field

#: hub 中心地址环境变量（06 文档 W8：优先于策略文件）
HUB_URL_ENV = "AAA_HUB_URL"

#: hub 共享令牌环境变量（06 文档 W8：优先于策略文件；agent 与中心配置同一值）
HUB_TOKEN_ENV = "AAA_HUB_TOKEN"


class HubConfig(BaseModel):
    """策略 ``hub:`` 段（agent 端 Forwarder 用；中心端复用同一 token）。"""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    """默认关：多机聚合是显式开启的外发行为（事件摘要发往另一台机器）。"""
    url: str = ""
    """hub 中心基地址（如 ``http://192.168.1.10:8788``；``/ingest`` 由 Forwarder 追加）。"""
    token: str = ""
    """共享 Bearer 令牌（环境变量 ``AAA_HUB_TOKEN`` 优先）。"""
    batch_size: int = Field(default=50, ge=1, le=50)
    """单次 POST 最大事件数（06 文档 W8 红线：≤50 条/次）。"""
    timeout: float = Field(default=3.0, gt=0)
    """HTTP 超时秒数（对齐 webhook 通道的 3.0s）。"""


def apply_env_overrides(
    config: HubConfig, environ: Mapping[str, str] | None = None
) -> HubConfig:
    """应用环境变量覆盖（``AAA_HUB_URL`` / ``AAA_HUB_TOKEN``；空串视同未设置）。

    返回新对象（pydantic ``model_copy``，不改入参）。环境变量值优先于策略文件值。
    试用意图（decisions D-33 同款、收窄版）：仅当策略**从未配置** url 与 token
    （两者皆空、即从未打算启用 hub）而环境变量把两者都补齐时，才视为显式试用、
    自动 ``enabled=True``——策略已填 url/token 的显式 ``enabled: false`` 永远获胜。
    """
    env = os.environ if environ is None else environ
    url = (env.get(HUB_URL_ENV) or "").strip() or config.url
    token = (env.get(HUB_TOKEN_ENV) or "").strip() or config.token
    updates: dict[str, object] = {}
    if url != config.url:
        updates["url"] = url
    if token != config.token:
        updates["token"] = token
    enabled = config.enabled
    if not enabled and not config.url and not config.token and url and token:
        # 环境变量凭空补齐 url+token：显式试用意图（策略侧从未配置过 hub）
        enabled = True
    if enabled != config.enabled:
        updates["enabled"] = enabled
    if not updates:
        return config
    return config.model_copy(update=updates)  # type: ignore[arg-type]
