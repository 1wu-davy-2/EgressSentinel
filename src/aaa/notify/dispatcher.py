"""通知调度器（04 文档 §3 T4：队列 + 单 worker + 限流 + flush）。

- ``enqueue(event)`` **永不阻塞**（审计主路径只调用它）：``put_nowait``，队列满直接
  丢弃并计数（绝不影响代理）；
- 单 worker 线程消费：逐通道发送脱敏摘要；**通道异常隔离**（任何通道抛异常只记日志，
  绝不影响其他通道与代理进程）；
- 滑动窗口限流：每通道 ``max_per_minute``；窗口内超限的事件**合并为一条 digest**
  （「另有 N 条事件被限流」）——digest 在同通道下一次成功发送前追加发出，
  ``flush()`` 兜底补发（窗口滚动的精确时机不依赖定时器，见 decisions 日志）；
- ``flush(timeout)``：退出前排空队列并补发未发的 digest（Ctrl+C/关机优雅退出路径）。

策略热更新（04 文档 §1 ⑤）：``config_provider`` 返回的 ``NotifyConfig`` 与上次
不相等时自动重建通道（``build_dispatcher`` 以 ``PolicyLoader.current.notifications``
为 provider，热更新即刻生效，无需重启）。
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from aaa.notify.channels import Channel, build_channels
from aaa.notify.model import NotifyConfig, apply_env_overrides
from aaa.notify.summary import build_digest_text, build_summary
from aaa.policy.loader import PolicyLoader
from aaa.store.events import AuditEvent

logger = logging.getLogger(__name__)

#: 滑动窗口宽度（04 文档 §2：max_per_minute 每分钟）
WINDOW_SECONDS = 60.0

#: 默认队列容量（超出即丢弃计数；瞬时洪峰保护）
DEFAULT_QUEUE_MAXSIZE = 1000

#: worker 空转轮询间隔（秒）
_WORKER_POLL_SECONDS = 0.2

_STOP = object()  # 关闭哨兵（经队列传递，保证排空后退出）


@dataclass
class _ChannelState:
    """单通道运行态：滑动窗口 + 未上报的被限流计数。"""

    channel: Channel
    window: deque[float] = field(default_factory=deque)
    suppressed: int = 0
    last_suppressed: AuditEvent | None = None


class Dispatcher:
    """通知调度器：审计主路径只调 ``enqueue``；发送/限流/异常全在 worker 侧。"""

    def __init__(
        self,
        channels: Sequence[Channel],
        *,
        config: NotifyConfig | None = None,
        config_provider: Callable[[], NotifyConfig] | None = None,
        max_per_minute: int | None = None,
        clock: Callable[[], float] = time.monotonic,
        queue_maxsize: int = DEFAULT_QUEUE_MAXSIZE,
    ) -> None:
        self._config = config
        self._config_provider = config_provider
        self._clock = clock
        self._queue: queue.Queue[AuditEvent | object] = queue.Queue(maxsize=max(1, queue_maxsize))
        self._send_lock = threading.Lock()
        self._counter_lock = threading.Lock()
        self._worker: threading.Thread | None = None
        self._closing = False
        # 统计（观测/状态命令用）
        self.sent = 0
        self.digests_sent = 0
        self.dropped = 0
        self.suppressed_total = 0
        self.send_errors = 0
        max_per_minute = max_per_minute or (config.rate_limit.max_per_minute if config else 10)
        self._max_per_minute = max_per_minute
        self._states: list[_ChannelState] = [_ChannelState(ch) for ch in channels]

    # ------------------------------------------------------------- 入队路径

    def enqueue(self, event: AuditEvent) -> None:
        """入队一条待通知事件；**永不阻塞**（队列满丢弃计数，04 文档 §3）。"""
        if self._closing:
            return
        self._ensure_worker()
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            with self._counter_lock:
                self.dropped += 1
            logger.debug("通知队列已满，事件 %s 通知被丢弃（计数）", event.id)

    # ------------------------------------------------------------- 发送路径

    def _ensure_worker(self) -> None:
        """懒启动 worker（无通知事件则无线程）。"""
        if self._worker is not None and self._worker.is_alive():
            return
        with self._counter_lock:
            if self._worker is not None and self._worker.is_alive():
                return
            self._worker = threading.Thread(
                target=self._worker_loop, name="aaa-notify-dispatcher", daemon=True
            )
            self._worker.start()

    def _worker_loop(self) -> None:
        while True:
            idle = False
            with self._send_lock:
                if self._closing:
                    return
                try:
                    item = self._queue.get_nowait()
                except queue.Empty:
                    idle = True
                else:
                    if item is _STOP:
                        return
                    assert isinstance(item, AuditEvent)
                    try:
                        self._process_locked(item)
                    except Exception:  # noqa: BLE001 - worker 绝不因单事件异常死亡
                        logger.exception("通知 worker 处理事件异常（已跳过）")
            if idle:
                # 锁外空转等待（get_nowait+sleep，绝不持锁阻塞——否则 flush 的有界
                # 获取会被热循环重新抢锁饿死，digest 就丢在退出路径上）
                time.sleep(_WORKER_POLL_SECONDS)

    def _process_locked(self, event: AuditEvent) -> None:
        """逐通道限流判定 + 发送（须持 ``_send_lock``；通道异常隔离在 _send 内）。"""
        self._maybe_refresh_config()
        text = build_summary(event).text
        now = self._clock()
        for state in self._states:
            self._prune_window(state, now)
            if len(state.window) < self._max_per_minute:
                if state.suppressed > 0:
                    self._send_digest(state)
                self._send(state, text, event)
                state.window.append(now)
            else:
                state.suppressed += 1
                state.last_suppressed = event
                with self._counter_lock:
                    self.suppressed_total += 1

    def _send(self, state: _ChannelState, text: str, event: AuditEvent) -> None:
        """单通道发送 + 异常隔离（04 文档 §3：绝不影响代理）。"""
        try:
            state.channel.send(text, event)
            with self._counter_lock:
                self.sent += 1
        except Exception:  # noqa: BLE001 - 通道实现应自吞异常；这里兜底
            with self._counter_lock:
                self.send_errors += 1
            logger.exception("通道 %s 发送异常（已隔离）", state.channel.name)

    def _send_digest(self, state: _ChannelState) -> None:
        """补发该通道被限流事件的合并 digest（04 文档：「另有 N 条事件被限流」）。"""
        count, state.suppressed = state.suppressed, 0
        event = state.last_suppressed
        state.last_suppressed = None
        if event is None:
            return
        text = build_digest_text(count, max_per_minute=self._max_per_minute)
        try:
            state.channel.send(text, event)
            with self._counter_lock:
                self.digests_sent += 1
        except Exception:  # noqa: BLE001 - digest 失败同样只记日志
            with self._counter_lock:
                self.send_errors += 1
            logger.exception("通道 %s digest 发送异常（已隔离）", state.channel.name)

    def _prune_window(self, state: _ChannelState, now: float) -> None:
        cutoff = now - WINDOW_SECONDS
        while state.window and state.window[0] < cutoff:
            state.window.popleft()

    # ------------------------------------------------- 配置热更新（04 §1 ⑤）

    def _maybe_refresh_config(self) -> None:
        """provider 配置变化（不相等）时重建通道；窗口状态按序保留。"""
        if self._config_provider is None:
            return
        try:
            fresh = self._config_provider()
        except Exception:  # noqa: BLE001 - 策略读取失败沿用现有通道
            logger.exception("读取通知配置失败（沿用现有通道）")
            return
        if self._config is not None and fresh == self._config:
            return
        self._config = fresh
        self._max_per_minute = fresh.rate_limit.max_per_minute
        channels = build_channels(fresh)
        old = {state.channel.name: state for state in self._states}
        states: list[_ChannelState] = []
        for channel in channels:
            state = _ChannelState(channel)
            previous = old.get(channel.name)
            if previous is not None:
                # 同名通道保留限流窗口与未上报计数（连续性），但通道对象必须换新
                # （url/provider 等配置可能已变，复用旧对象会拿陈旧配置发送）
                state.window = previous.window
                state.suppressed = previous.suppressed
                state.last_suppressed = previous.last_suppressed
            states.append(state)
        self._states = states
        logger.info("通知配置已热更新：启用通道 %s", [s.channel.name for s in states])

    # -------------------------------------------------------------- 退出路径

    def flush(self, timeout: float = 2.0) -> None:
        """排空队列并补发未发的 digest（优雅退出路径，04 文档 §5：engine 停止后调用）。

        有界等待：超时后放弃（记 debug），绝不阻塞退出；任何内部异常只记日志不向上抛
        （调用方在退出 finally 里，通知失败不得阻断 store.close 等收尾）。与 worker
        共用发送锁，持锁兜底处理等待中的事件，保证 digest 计数不丢。
        """
        try:
            deadline = time.monotonic() + max(0.0, timeout)
            while not self._queue.empty() and time.monotonic() < deadline:
                time.sleep(0.02)
            remaining = max(0.0, deadline - time.monotonic())
            if not self._send_lock.acquire(timeout=remaining):
                logger.debug("flush 未能在 %.1fs 内取得发送锁，digest 留待下次", remaining)
                return
            try:
                while True:  # 持锁兜底：排空期间新入队的事件直接处理
                    try:
                        item = self._queue.get_nowait()
                    except queue.Empty:
                        break
                    if isinstance(item, AuditEvent):
                        self._process_locked(item)
                for state in self._states:
                    if state.suppressed > 0:
                        self._send_digest(state)
            finally:
                self._send_lock.release()
        except Exception:  # noqa: BLE001 - 退出路径的通知失败绝不阻断收尾
            logger.exception("通知 flush 异常（已忽略，不影响退出收尾）")

    def close(self, timeout: float = 1.0) -> None:
        """停止 worker（测试与显式关闭用；``aaa run`` 退出仅需 flush）。"""
        self._closing = True
        worker = self._worker
        if worker is not None and worker.is_alive():
            try:
                self._queue.put_nowait(_STOP)
            except queue.Full:
                pass
            worker.join(timeout)

    # --------------------------------------------------------------- 观测

    def stats(self) -> dict[str, object]:
        """调度统计（``aaa status``/诊断用）。"""
        with self._counter_lock:
            return {
                "sent": self.sent,
                "digests_sent": self.digests_sent,
                "dropped": self.dropped,
                "suppressed_total": self.suppressed_total,
                "send_errors": self.send_errors,
                "queue_size": self._queue.qsize(),
                "channels": [state.channel.name for state in self._states],
            }

    @property
    def min_action(self) -> str:
        """通知门槛（addon 侧判定用；热更新后随配置变化）。"""
        return self._config.min_action if self._config is not None else "alert"

    @property
    def channel_names(self) -> list[str]:
        return [state.channel.name for state in self._states]

    def __repr__(self) -> str:  # pragma: no cover - 调试辅助
        return f"Dispatcher(channels={self.channel_names}, max_per_minute={self._max_per_minute})"


# --------------------------------------------------------------------------
# 装配（aaa run / aaa notify test 共用）
# --------------------------------------------------------------------------


def notify_config_from_policy(
    policy_loader: PolicyLoader, *, environ: dict[str, str] | None = None
) -> NotifyConfig:
    """策略当前通知配置 + 环境变量覆盖（04 文档 §2 优先级：环境变量 > 策略文件）。

    先做 mtime 轮询（与 ``AuditPipeline.policy`` 同机制），热更新即刻生效。
    """
    policy_loader.maybe_reload()
    return apply_env_overrides(policy_loader.current.notifications, environ)


def build_dispatcher(
    policy_loader: PolicyLoader, *, channels: Sequence[Channel] | None = None
) -> Dispatcher:
    """按策略装配 Dispatcher（``aaa run`` 用）。

    ``channels`` 为 ``None`` 时按配置装配真实通道，并挂策略热更新 provider；
    显式传入（测试/E2E 假通道）则通道静态、不挂 provider。
    """
    config = notify_config_from_policy(policy_loader)
    if channels is not None:
        return Dispatcher(list(channels), config=config)
    provider = lambda: notify_config_from_policy(policy_loader)  # noqa: E731 - 单行闭包
    return Dispatcher(list(build_channels(config)), config=config, config_provider=provider)
