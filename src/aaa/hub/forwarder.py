"""Agent 端事件转发器（06 文档 W8：队列 + 重试 + 批量 ≤50 条/次）。

红线：
- **脱敏后才外发**：事件先经 ``notify.summary`` 同一脱敏核心打码（``build_summary``
  摘要文本 / ``mask_event_path`` 自由文本字段，decisions D-18/D-34 同源防线），
  绝不能把拦截到的明文密钥发到 hub；``judge_note.reason`` 可能引用请求内容，
  只保留结构化白名单字段（status/is_violation/confidence/category）；
- httpx **trust_env=False 直连**（04 文档 §6 同款：不经本机代理防回环）；
- **永不阻塞审计主路径**：``enqueue`` 只 ``put_nowait``，队列满丢弃计数；发送在
  daemon worker 线程，任何异常只记日志不外抛；
- 批量 ≤50 条/次；失败按退避重试，重试耗尽整批丢弃并计数（绝不无限堆积拖垮队列）。

wire 形态（decisions D-2026-10-25-47）：``POST {url}/ingest``，头
``Authorization: Bearer <token>``，body ``{"token", "host", "events": [...]}``；
``url`` 为 hub 基地址（结尾的 ``/`` 容忍），``host`` 为本机机器名维度。
"""

from __future__ import annotations

import logging
import queue
import socket
import threading
import time
from collections.abc import Callable
from typing import Any

import httpx

from aaa.hub.model import HubConfig
from aaa.notify.summary import build_summary, mask_event_path
from aaa.store.events import AuditEvent

logger = logging.getLogger(__name__)

#: 默认 HTTP 超时（秒；对齐 notify webhook 通道）
HUB_TIMEOUT_SECONDS = 3.0

#: 单次 POST 事件数上限（06 文档 W8：≤50 条/次）
MAX_BATCH_SIZE = 50

#: 失败重试次数（不含首次；共 retries+1 次尝试）
DEFAULT_RETRIES = 2

#: 重试退避基数（第 n 次重试前 sleep(backoff * n) 秒）
DEFAULT_RETRY_BACKOFF = 0.5

#: 默认队列容量（超出即丢弃计数；瞬时洪峰保护，与 notify dispatcher 同策略）
DEFAULT_QUEUE_MAXSIZE = 1000

#: worker 空转轮询间隔（秒）
_WORKER_POLL_SECONDS = 0.2

#: judge_note 允许外发的白名单字段（``reason`` 可能引用请求内容，不外发）
_JUDGE_NOTE_FIELDS = ("status", "is_violation", "confidence", "category")

#: matched_rules 允许外发的字段（evidence 已在扫描时打码，此处再打一道）
_RULE_FIELDS = ("id", "dim", "action", "weight", "severity", "evidence")

#: hub 客户端工厂注入点（单测注入假客户端；生产为 httpx.Client(trust_env=False)）
HubClientFactory = Callable[[], Any]
"""返回带 ``post(url, json=..., headers=...)`` / ``close()`` 的客户端。"""


def default_hub_client_factory(timeout: float = HUB_TIMEOUT_SECONDS) -> httpx.Client:
    """生产客户端工厂：**trust_env=False 直连**（不经本机代理防回环，04 文档 §6）。"""
    return httpx.Client(trust_env=False, timeout=timeout)


def summarize_event(event: AuditEvent) -> dict[str, Any]:
    """事件 → 脱敏摘要 dict（Forwarder payload 的单条形态）。

    流程：``model_dump`` → 自由文本字段过 ``mask_event_path``（同一脱敏核心：
    request.path 查询串可能携带密钥、process.exe/cmdline、error）→ matched_rules
    白名单化并对 evidence 二次打码（扫描时已打码，防线叠加，D-18）→ 附加
    ``build_summary`` 的脱敏文本摘要 → 丢弃 ``evidence``（文件指向 agent 本机
    路径，hub 侧无意义）与 ``judge_note.reason``（可能引用请求内容）。
    """
    data = event.model_dump(mode="json")
    process = data.get("process")
    if isinstance(process, dict):
        for key in ("exe", "name"):
            if isinstance(process.get(key), str):
                process[key] = mask_event_path(process[key])
        cmdline = process.get("cmdline")
        if isinstance(cmdline, list):
            process["cmdline"] = [
                mask_event_path(item) if isinstance(item, str) else item for item in cmdline
            ]
    request = data.get("request")
    if isinstance(request, dict) and isinstance(request.get("path"), str):
        request["path"] = mask_event_path(request["path"])
    if isinstance(data.get("error"), str):
        data["error"] = mask_event_path(data["error"])
    rules: list[dict[str, Any]] = []
    for rule in data.get("matched_rules") or []:
        if not isinstance(rule, dict):
            continue
        piece = {key: rule[key] for key in _RULE_FIELDS if key in rule}
        if isinstance(piece.get("evidence"), str):
            piece["evidence"] = mask_event_path(piece["evidence"])
        rules.append(piece)
    data["matched_rules"] = rules
    data.pop("evidence", None)
    judge_note = data.get("judge_note")
    if isinstance(judge_note, dict):
        data["judge_note"] = {
            key: judge_note[key] for key in _JUDGE_NOTE_FIELDS if key in judge_note
        }
    # 脱敏 + 截断的文本摘要（notify.summary 同一核心，hub 侧一屏可读）
    data["summary"] = build_summary(event).text
    return data


class Forwarder:
    """事件转发器：审计主路径只调 ``enqueue``；批量/重试/异常全在 worker 侧。"""

    def __init__(
        self,
        url: str,
        token: str,
        *,
        hostname: str | None = None,
        client_factory: HubClientFactory | None = None,
        batch_size: int = MAX_BATCH_SIZE,
        max_queue: int = DEFAULT_QUEUE_MAXSIZE,
        retries: int = DEFAULT_RETRIES,
        retry_backoff: float = DEFAULT_RETRY_BACKOFF,
        timeout: float = HUB_TIMEOUT_SECONDS,
        sleeper: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not url:
            raise ValueError("hub url 为空（策略 hub.url 或环境变量 AAA_HUB_URL）")
        if not token:
            raise ValueError("hub token 为空（策略 hub.token 或环境变量 AAA_HUB_TOKEN）")
        if not 1 <= batch_size <= MAX_BATCH_SIZE:
            raise ValueError(f"batch_size 必须在 1..{MAX_BATCH_SIZE}（W8 红线 ≤50 条/次）")
        self._url = url
        self._token = token
        self._endpoint = url.rstrip("/") + "/ingest"
        self._hostname = hostname if hostname is not None else socket.gethostname()
        self._client_factory: HubClientFactory = client_factory or (
            lambda: default_hub_client_factory(timeout)
        )
        self._batch_size = batch_size
        self._retries = max(0, retries)
        self._retry_backoff = max(0.0, retry_backoff)
        self._sleeper = sleeper
        self._clock = clock
        self._queue: queue.Queue[AuditEvent] = queue.Queue(maxsize=max(1, max_queue))
        self._send_lock = threading.Lock()
        self._counter_lock = threading.Lock()
        self._worker: threading.Thread | None = None
        self._closing = False
        # 统计（aaa hub forward status / 诊断用）
        self.sent_events = 0
        self.sent_batches = 0
        self.dropped = 0
        self.retries_used = 0
        self.send_errors = 0
        self.last_error: str | None = None

    # ------------------------------------------------------------- 入队路径

    def enqueue(self, event: AuditEvent) -> None:
        """入队一条待转发事件；**永不阻塞**（队列满丢弃计数，同 notify dispatcher）。"""
        if self._closing:
            return
        self._ensure_worker()
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            with self._counter_lock:
                self.dropped += 1
            logger.debug("hub 转发队列已满，事件 %s 被丢弃（计数）", event.id)

    def _ensure_worker(self) -> None:
        """懒启动 worker（无事件则无线程）。"""
        if self._worker is not None and self._worker.is_alive():
            return
        with self._counter_lock:
            if self._worker is not None and self._worker.is_alive():
                return
            self._worker = threading.Thread(
                target=self._worker_loop, name="aaa-hub-forwarder", daemon=True
            )
            self._worker.start()

    # ------------------------------------------------------------- 发送路径

    def _drain_batch(self) -> list[AuditEvent]:
        """从队列取一批（≤batch_size）；非阻塞，取到多少算多少。"""
        batch: list[AuditEvent] = []
        while len(batch) < self._batch_size:
            try:
                batch.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return batch

    def _worker_loop(self) -> None:
        while True:
            idle = False
            with self._send_lock:
                if self._closing:
                    return
                batch = self._drain_batch()
                if batch:
                    try:
                        self._send_batch(batch)  # 内部吞掉一切异常，worker 绝不死亡
                    except Exception:  # noqa: BLE001 - 兜底：批次已出队，如实计丢弃
                        with self._counter_lock:
                            self.dropped += len(batch)
                            self.send_errors += 1
                        logger.exception("hub worker 发送批次异常（已隔离）")
                else:
                    idle = True
            if idle:
                time.sleep(_WORKER_POLL_SECONDS)

    def _send_batch(self, events: list[AuditEvent]) -> None:
        """一批事件按重试策略 POST；重试耗尽整批丢弃计数，绝不向上抛。"""
        payload = {
            "token": self._token,
            "host": self._hostname,
            "events": [summarize_event(event) for event in events],
        }
        headers = {"Authorization": f"Bearer {self._token}"}
        last_error: Exception | None = None
        for attempt in range(self._retries + 1):
            client: Any = None
            try:
                client = self._client_factory()
            except Exception as exc:  # noqa: BLE001 - 工厂异常按一次失败重试
                last_error = exc
                logger.warning("hub 客户端工厂异常（第 %d 次）：%s", attempt + 1, exc)
            if client is not None:
                try:
                    response = client.post(self._endpoint, json=payload, headers=headers)
                    status = getattr(response, "status_code", None)
                    if isinstance(status, int) and 200 <= status < 300:
                        with self._counter_lock:
                            self.sent_events += len(events)
                            self.sent_batches += 1
                        return
                    last_error = RuntimeError(f"hub 返回 HTTP {status}")
                    logger.warning(
                        "hub 转发失败（第 %d 次）：%s → %s", attempt + 1, self._url, status
                    )
                except Exception as exc:  # noqa: BLE001 - 网络异常重试，最终只记日志
                    last_error = exc
                    logger.warning("hub 转发异常（第 %d 次）：%s", attempt + 1, exc)
                finally:
                    close = getattr(client, "close", None)
                    if callable(close):
                        try:
                            close()
                        except Exception:  # noqa: BLE001 - 关闭失败绝不吞掉发送结果
                            logger.debug("hub 客户端关闭异常（忽略）", exc_info=True)
            if attempt < self._retries:
                with self._counter_lock:
                    self.retries_used += 1
                self._sleeper(self._retry_backoff * (attempt + 1))
        assert last_error is not None
        with self._counter_lock:
            self.dropped += len(events)
            self.send_errors += 1
            self.last_error = str(last_error)
        logger.error(
            "hub 转发重试 %d 次后仍失败，丢弃 %d 条事件：%s",
            self._retries,
            len(events),
            last_error,
        )

    # -------------------------------------------------------------- 退出路径

    def flush(self, timeout: float = 5.0) -> None:
        """排空队列并同步发送（优雅退出路径；有界等待，绝不阻塞退出收尾）。

        与 worker 共用发送锁：先等 worker 把队列发空（有界），再持锁兜底发送
        剩余事件；持锁期间 worker 不会并发发送，保证计数不重不漏。
        """
        deadline = self._clock() + max(0.0, timeout)
        while not self._queue.empty() and self._clock() < deadline:
            time.sleep(0.02)
        remaining = max(0.0, deadline - self._clock())
        if not self._send_lock.acquire(timeout=remaining):
            logger.debug("hub flush 未能在 %.1fs 内取得发送锁，剩余事件放弃", remaining)
            return
        try:
            while True:
                batch = self._drain_batch()
                if not batch:
                    break
                self._send_batch(batch)
        except Exception:  # noqa: BLE001 - 退出路径的转发失败绝不阻断收尾
            logger.exception("hub flush 异常（已忽略，不影响退出收尾）")
        finally:
            self._send_lock.release()

    def close(self, timeout: float = 1.0) -> None:
        """停止 worker（测试与显式关闭用；``aaa run`` 退出仅需 flush）。"""
        self._closing = True
        worker = self._worker
        if worker is not None and worker.is_alive():
            worker.join(timeout)

    # --------------------------------------------------------------- 观测

    def stats(self) -> dict[str, Any]:
        """转发统计（``aaa hub forward status``/诊断用）。"""
        with self._counter_lock:
            return {
                "url": self._url,
                "host": self._hostname,
                "sent_events": self.sent_events,
                "sent_batches": self.sent_batches,
                "dropped": self.dropped,
                "retries_used": self.retries_used,
                "send_errors": self.send_errors,
                "last_error": self.last_error,
                "queue_size": self._queue.qsize(),
                "batch_size": self._batch_size,
            }

    def __repr__(self) -> str:  # pragma: no cover - 调试辅助
        return f"Forwarder(url={self._url!r}, host={self._hostname!r})"


def build_forwarder(
    config: HubConfig, *, hostname: str | None = None, **kwargs: Any
) -> Forwarder | None:
    """按（已应用环境变量覆盖的）配置装配 Forwarder；未启用或配置不全返回 None。

    ``kwargs`` 透传给 :class:`Forwarder`（测试注入假 client_factory 等）。
    """
    if not config.enabled:
        return None
    if not config.url or not config.token:
        logger.warning("hub 已启用但 url/token 不完整（可设 AAA_HUB_URL/AAA_HUB_TOKEN），不转发")
        return None
    return Forwarder(
        config.url,
        config.token,
        hostname=hostname,
        batch_size=config.batch_size,
        timeout=config.timeout,
        **kwargs,
    )
