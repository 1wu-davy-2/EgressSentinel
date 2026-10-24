"""多机聚合（06 文档 W8 波次一模块）。

- agent 端：:class:`aaa.hub.forwarder.Forwarder` —— 脱敏事件摘要、队列、
  重试、批量 ≤50 条/次，httpx trust_env=False；
- 中心端：:class:`aaa.hub.collector.HubCollector` + ``create_hub_app`` ——
  独立 FastAPI app，Bearer 鉴权，内存缓冲 → SQLite hub.db，机器名维度聚合；
- 配置：:class:`aaa.hub.model.HubConfig`（策略 ``hub:`` 段形态）+
  ``apply_env_overrides``（``AAA_HUB_URL`` / ``AAA_HUB_TOKEN``）。

红线：事件外发前必经 ``summarize_event`` 脱敏（notify.summary 同一核心）；
hub 中心所有端点要求 Bearer 令牌（含只读查询）。

导入说明（v0.3.0 波次二）：本包 ``__init__`` 改为 **惰性导出**（PEP 562）——
``aaa.policy.model`` 需要引用 ``hub.model.HubConfig``（策略 ``hub:`` 段），
而 collector/forwarder 顶层带 fastapi/httpx 依赖；若 eager 导出会让基础安装
（未装 web extra）连 ``aaa policy`` 都起不来。公开名字保持不变，逐个访问时
才加载对应子模块。
"""

from __future__ import annotations

from typing import Any

_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    # 公开名 → (子模块, 原名)
    "DEFAULT_HUB_PORT": ("aaa.hub.collector", "DEFAULT_HUB_PORT"),
    "HubAuthError": ("aaa.hub.collector", "HubAuthError"),
    "HubCollector": ("aaa.hub.collector", "HubCollector"),
    "IngestEnvelope": ("aaa.hub.collector", "IngestEnvelope"),
    "create_hub_app": ("aaa.hub.collector", "create_hub_app"),
    "run_hub": ("aaa.hub.collector", "run_hub"),
    "MAX_BATCH_SIZE": ("aaa.hub.forwarder", "MAX_BATCH_SIZE"),
    "Forwarder": ("aaa.hub.forwarder", "Forwarder"),
    "build_forwarder": ("aaa.hub.forwarder", "build_forwarder"),
    "default_hub_client_factory": ("aaa.hub.forwarder", "default_hub_client_factory"),
    "summarize_event": ("aaa.hub.forwarder", "summarize_event"),
    "HUB_TOKEN_ENV": ("aaa.hub.model", "HUB_TOKEN_ENV"),
    "HUB_URL_ENV": ("aaa.hub.model", "HUB_URL_ENV"),
    "HubConfig": ("aaa.hub.model", "HubConfig"),
    "apply_env_overrides": ("aaa.hub.model", "apply_env_overrides"),
}

__all__ = list(_LAZY_EXPORTS)


def __getattr__(name: str) -> Any:
    """PEP 562 惰性导出：首次访问公开名时才导入对应子模块。"""
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    module_name, attr = target
    return getattr(importlib.import_module(module_name), attr)


def __dir__() -> list[str]:
    return sorted(__all__)
