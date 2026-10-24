"""策略文件加载与 mtime 热更新（02 文档 D4，03 文档 T3.1）。

- ``load()``：读 YAML → pydantic 严格校验；解析/校验失败抛 ``PolicyError``（lint 报告用）；
- ``maybe_reload()``：引擎每 2 秒调用，``stat().st_mtime`` 变了才重读；热更新失败时
  保留上一份好策略并记日志（fail-open，不因坏策略文件崩代理）。
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

import yaml

from aaa.policy.model import PolicyDocument

logger = logging.getLogger(__name__)

#: 热更新轮询间隔秒数（03 文档 T3.1：引擎轮询 2s）
RELOAD_POLL_SECONDS = 2.0


class PolicyError(ValueError):
    """策略文件解析/校验失败。"""


def parse_policy(raw: str | bytes) -> PolicyDocument:
    """YAML 文本 → ``PolicyDocument``（校验失败抛 ``PolicyError``）。"""
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise PolicyError(f"YAML 解析失败：{exc}") from exc
    if data is None:
        raise PolicyError("策略文件为空")
    if not isinstance(data, dict):
        raise PolicyError(f"策略文件顶层必须是映射，得到 {type(data).__name__}")
    try:
        return PolicyDocument.model_validate(data)
    except Exception as exc:
        raise PolicyError(f"策略校验失败：{exc}") from exc


class PolicyLoader:
    """单文件策略加载器：load / maybe_reload（mtime 轮询）。

    线程安全：mitmproxy 钩子跑在事件循环线程，测试可能从其他线程读 ``current``。
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._policy: PolicyDocument | None = None
        self._mtime: float | None = None
        self._last_check = 0.0
        self._error: str | None = None

    # -------------------------------------------------------------- 加载

    def load(self) -> PolicyDocument:
        """强制（重新）加载策略文件；失败抛 ``PolicyError``。"""
        try:
            raw = self.path.read_bytes()
        except OSError as exc:
            raise PolicyError(f"策略文件读取失败 {self.path}：{exc}") from exc
        policy = parse_policy(raw)
        self._policy = policy
        self._mtime = self._current_mtime()
        self._error = None
        logger.info(
            "策略已加载：%s（mode=%s version=%s）",
            self.path,
            policy.mode,
            policy.policy_version,
        )
        return policy

    @property
    def current(self) -> PolicyDocument:
        """当前策略（首次访问时懒加载）。"""
        if self._policy is None:
            return self.load()
        return self._policy

    @property
    def last_error(self) -> str | None:
        """最近一次热更新失败的错误描述（无错误为 ``None``）。"""
        return self._error

    # ----------------------------------------------------------- 热更新

    def _current_mtime(self) -> float | None:
        try:
            return self.path.stat().st_mtime
        except OSError:
            return None

    def maybe_reload(self, *, now: float | None = None) -> bool:
        """mtime 变了才重读；最多每 ``RELOAD_POLL_SECONDS`` 秒 stat 一次。

        返回是否发生了重载。热更新失败保留旧策略、记 ``self._error``（不抛）。
        """
        stamp = time.monotonic() if now is None else now
        if self._last_check and (stamp - self._last_check) < RELOAD_POLL_SECONDS:
            return False
        self._last_check = stamp
        mtime = self._current_mtime()
        if mtime is None or mtime == self._mtime:
            return False
        try:
            self.load()
        except PolicyError as exc:
            # fail-open：保留上一份好策略，下一轮 mtime 变化再试
            self._error = str(exc)
            self._mtime = mtime  # 避免同一份坏文件每 2s 重试刷屏
            logger.error("策略热更新失败（保留旧策略）：%s", exc)
            return False
        return True
