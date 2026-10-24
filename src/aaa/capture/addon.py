"""审计 addon：mitmproxy 钩子 → 事件对象 → store（03 文档 T1.2/T2.1/T3.4）。

- ``client_connected``：进程归因（ProcessAttributor，源端口反查连接表）；
- ``http_connect`` / ``tls_clienthello``：域名 blocklist 在 CONNECT/SNI 阶段阻断（02 文档 D5）；
- ``request``：构建事件 + 五维求值；enforce 且 verdict=block 时合成 403（请求不到目标），
  dry-run 只告警；引擎异常按 fail_open 放行并记 error；
- ``response`` / ``error``：补全事件并 JSONL 直写（每条流一行，见 docs/notes/decisions.md D5）。

引擎内任何异常一律捕获记日志（fail-open，不崩代理进程，03 文档 §3 错误处理）。
"""

from __future__ import annotations

import json
import logging
import weakref
from datetime import datetime
from typing import Any

from mitmproxy import connection, http, tls

from aaa.attribution.table import ProcessAttributor
from aaa.engine.pipeline import AuditPipeline, EvaluationInput
from aaa.engine.verdict import MatchedRule
from aaa.notify.dispatcher import Dispatcher
from aaa.policy.model import action_rank
from aaa.store.db import EventSink
from aaa.store.decisions import DECISION_DENY, DecisionStore, decision_key
from aaa.store.events import (
    AuditEvent,
    Destination,
    ProcessInfo,
    RequestInfo,
    ResponseInfo,
    new_event_id,
)
from aaa.store.evidence import EvidenceStore

logger = logging.getLogger(__name__)

#: 阻断响应状态码与说明（02 文档 D5：合成 403 JSON 响应）
BLOCK_STATUS_CODE = 403


def make_block_response(matched: list[MatchedRule]) -> http.Response:
    """合成 403 JSON 响应（含命中规则 id，02 文档 D5）。"""
    body = json.dumps(
        {
            "aaa": "blocked",
            "message": "request blocked by AI-AGENT-AUDIT policy (enforce mode)",
            "rules": [m.id for m in matched],
        },
        ensure_ascii=False,
    ).encode("utf-8")
    return http.Response.make(
        BLOCK_STATUS_CODE,
        body,
        {"Content-Type": "application/json"},
    )


def _request_body(flow: http.HTTPFlow) -> bytes | None:
    """取请求 body：优先解码后的 content，失败退回 raw_content。"""
    try:
        body = flow.request.content
        if body is not None:
            return body
    except ValueError:
        logger.debug("request content 解码失败，退回 raw_content: %s", flow.request.url)
    try:
        return flow.request.raw_content
    except ValueError:
        return None


def _server_ip(flow: http.HTTPFlow) -> str | None:
    peername = flow.server_conn.peername
    if peername:
        return str(peername[0])
    return None


class AuditAddon:
    """把 mitmproxy 钩子转成审计事件：归因 → 求值 → 阻断/告警 → 落盘。"""

    def __init__(
        self,
        events: EventSink,
        evidence: EvidenceStore,
        *,
        mode: str = "regular",
        attributor: ProcessAttributor | None = None,
        pipeline: AuditPipeline | None = None,
        pinned_process: ProcessInfo | None = None,
        decisions: DecisionStore | None = None,
        dispatcher: Dispatcher | None = None,
    ) -> None:
        self.events = events
        self.evidence = evidence
        self.mode = mode
        self.attributor = attributor
        self.pipeline = pipeline
        #: local 模式 ``--pid/--process`` 的原生归因（03 文档 T2.2）
        self.pinned_process = pinned_process
        #: confirm 决策缓存（T5.3：用户 deny 后同类请求升级 block，TTL 可配）
        self.decisions = decisions
        #: 告警通知调度器（04 文档 §5：可选注入，None 时完全跳过——既有测试零改动兼容）
        self.dispatcher = dispatcher
        #: client_connected 已见的连接数
        self.connections_seen = 0
        #: 归因未命中（unknown）的事件计数
        self.unknown_attribution_count = 0
        #: 已入队通知的事件计数
        self.notified_count = 0
        self._pending: dict[str, AuditEvent] = {}
        #: 连接对象 → 归因结果（client_connected 时点查，源端口时效性，02 文档 D2）
        self._conn_process: weakref.WeakKeyDictionary[connection.Client, ProcessInfo] = (
            weakref.WeakKeyDictionary()
        )

    # ------------------------------------------------------------------ hooks

    def client_connected(self, client: connection.Client) -> None:
        """连接建立：进程归因（立即查连接表，02 文档 D2）+ 记录元数据。"""
        try:
            self.connections_seen += 1
            if self.attributor is not None:
                identity = self.attributor.attribute(client.peername)
                self._conn_process[client] = identity.to_process_info()
                logger.debug(
                    "client_connected peer=%s pid=%s profile=%s",
                    client.peername,
                    identity.pid,
                    identity.profile,
                )
        except Exception:
            logger.exception("audit addon client_connected 钩子异常（fail-open）")

    def client_disconnected(self, client: connection.Client) -> None:
        """连接关闭：清理归因缓存。"""
        self._conn_process.pop(client, None)

    def http_connect(self, flow: http.HTTPFlow) -> None:
        """CONNECT 阶段：域名 blocklist 阻断（enforce，02 文档 D5）。"""
        try:
            if self.pipeline is None or flow.response is not None:
                return
            if not self._enforce_mode:
                return
            blocked = self.pipeline.is_domain_blocked(flow.request.host)
            if blocked:
                logger.warning("CONNECT 已阻断（blocklist）：%s", flow.request.host)
                event = self._build_request_event(flow)
                event.verdict = "block"
                event.risk_score = min(100, sum(m.weight for m in blocked))
                event.matched_rules = [m.to_dict() for m in blocked]
                event.action_taken = "blocked-connect"
                self.events.append(event)
                self._maybe_notify(event)
                flow.response = make_block_response(blocked)
        except Exception:
            logger.exception("audit addon http_connect 钩子异常（fail-open）")

    def tls_start_client(self, data: tls.TlsData) -> None:
        """SNI 阶段：域名 blocklist kill 连接（enforce，02 文档 D5）。

        mitmproxy 12 的 ``ClientHelloData`` 无 kill 属性；``tls_start_client`` 钩子中
        保持 ``ssl_conn=None`` 会让 TLS 层发出 ``CloseConnection``（tls.py 的已验证
        关闭路径），配合 ``connection_strategy="lazy"`` 目标在此之前不会被接触。
        """
        try:
            if self.pipeline is None or not self._enforce_mode:
                return
            sni = getattr(data.conn, "sni", None)
            if not sni:
                return
            blocked = self.pipeline.is_domain_blocked(sni)
            if blocked:
                logger.warning("TLS ClientHello 已阻断（SNI=%s）", sni)
                data.conn.error = f"AI-AGENT-AUDIT: connection killed by blocklist (SNI: {sni})"
                data.ssl_conn = None
        except Exception:
            logger.exception("audit addon tls_start_client 钩子异常（fail-open）")

    def request(self, flow: http.HTTPFlow) -> None:
        """请求阶段：构建事件 + 五维求值 + （enforce）阻断。"""
        try:
            event = self._build_request_event(flow)
            if self.pipeline is not None:
                self._evaluate_and_maybe_block(flow, event)
            self._pending[flow.id] = event
        except Exception:
            logger.exception("audit addon request 钩子异常（fail-open）")

    def response(self, flow: http.HTTPFlow) -> None:
        """响应阶段：补全响应字段后落盘；达到通知门槛的事件入队（04 文档 §5）。"""
        try:
            event = self._pending.pop(flow.id, None) or self._build_request_event(flow)
            if flow.response is not None:
                event.response = ResponseInfo(
                    status_code=flow.response.status_code,
                    size=len(flow.response.raw_content or b""),
                    content_type=flow.response.headers.get("content-type"),
                )
            self.events.append(event)
            self._maybe_notify(event)
        except Exception:
            logger.exception("audit addon response 钩子异常（fail-open）")

    def error(self, flow: http.HTTPFlow) -> None:
        """流错误（响应未到达也要留痕）。"""
        try:
            event = self._pending.pop(flow.id, None) or self._build_request_event(flow)
            if flow.error is not None:
                event.error = str(flow.error)
            event.action_taken = "error"
            self.events.append(event)
            self._maybe_notify(event)
        except Exception:
            logger.exception("audit addon error 钩子异常（fail-open）")

    def done(self) -> None:
        """引擎退出：清空 pending（事件已尽力落盘，未完成的流不阻塞退出）。"""
        self._pending.clear()

    # ------------------------------------------------------------- internals

    @property
    def _enforce_mode(self) -> bool:
        """策略 enforce 模式（默认 dry-run 只告警，03 文档 §0）。"""
        if self.pipeline is None:
            return False
        return self.pipeline.policy.mode == "enforce"

    def _process_for_flow(self, flow: http.HTTPFlow) -> ProcessInfo | None:
        """事件归因：pinned（local --pid/--process）> 连接缓存 > 现场反查。"""
        if self.pinned_process is not None:
            return self.pinned_process
        if self.attributor is None:
            return None
        identity = self._conn_process.get(flow.client_conn)
        if identity is None:
            # 兜底：addon 挂载前已建立的连接等场景（仍可按源端口反查）
            identity = self.attributor.attribute(flow.client_conn.peername).to_process_info()
            self._conn_process[flow.client_conn] = identity
        if identity.pid is None:
            self.unknown_attribution_count += 1
        return identity

    def _build_request_event(self, flow: http.HTTPFlow) -> AuditEvent:
        event_id = new_event_id()
        body = _request_body(flow)
        evidence = self.evidence.save_body(event_id, body)
        request = flow.request
        content_length = len(body) if body is not None else 0
        event = AuditEvent(
            id=event_id,
            ts=datetime.now().astimezone().isoformat(timespec="milliseconds"),
            mode=self.mode,
            destination=Destination(
                host=request.host,
                port=request.port,
                ip=_server_ip(flow),
            ),
            request=RequestInfo(
                method=request.method,
                path=request.path,
                content_type=request.headers.get("content-type"),
                size=content_length,
            ),
            process=self._process_for_flow(flow),
            evidence=evidence if evidence.sha256 else None,
        )
        return event

    def _evaluate_and_maybe_block(self, flow: http.HTTPFlow, event: AuditEvent) -> None:
        """五维求值并按模式执行阻断（02 文档 D4/D5）+ confirm 决策缓存（T5.3）。"""
        assert self.pipeline is not None
        event.destination.classification = self.pipeline.policy.classify_host(
            event.destination.host
        )
        result = self.pipeline.evaluate(
            EvaluationInput(
                host=event.destination.host,
                port=event.destination.port,
                body=_request_body(flow),
                body_size=event.request.size,
                content_type=event.request.content_type,
                process=event.process,
            )
        )
        event.verdict = result.verdict
        event.risk_score = result.risk_score
        event.matched_rules = [m.to_dict() for m in result.matched]
        event.policy_version = self.pipeline.policy.policy_version
        if result.error:
            event.error = result.error
            if self.pipeline.policy.defaults.fail_open:
                # fail-open：放行并记 error（02 文档 D5）
                event.action_taken = "fail-open"
                return
            # fail-closed：继续按求值结果（block）执行阻断
        blocked_by_decision = False
        if result.verdict == "confirm":
            blocked_by_decision = self._apply_confirm_decision(event)
        if result.should_block or blocked_by_decision:
            if self._enforce_mode:
                logger.warning(
                    "请求已阻断：%s %s（规则 %s）",
                    event.request.method,
                    event.destination.host,
                    [m.id for m in result.matched],
                )
                flow.response = make_block_response(list(result.matched))
                event.action_taken = "blocked-403"
            else:
                event.action_taken = "alerted"
        elif result.verdict in ("alert", "confirm"):
            event.action_taken = "alerted"
        else:
            event.action_taken = "logged"

    def _apply_confirm_decision(self, event: AuditEvent) -> bool:
        """confirm 判定套用用户决策缓存（03 文档 T5.3）。

        用户曾对 ``(host, 命中规则)`` 拒绝且仍在 TTL 内 ⇒ 升级为 block；
        允许是一次性放行（只落事件），不进缓存。返回是否应阻断。
        """
        if self.decisions is None:
            return False
        rule_ids = [
            str(rule.get("id", "")) for rule in event.matched_rules if isinstance(rule, dict)
        ]
        key = decision_key(event.destination.host, rule_ids)
        if self.decisions.active(key) != DECISION_DENY:
            return False
        logger.warning(
            "confirm 已按用户拒绝决策升级 block：%s（key=%s）", event.destination.host, key
        )
        event.verdict = "block"
        event.matched_rules = [
            *event.matched_rules,
            {
                "id": "decision-deny",
                "dim": "decision",
                "action": "block",
                "weight": 0,
                "evidence": "user decision: deny",
                "detail": f"cached deny decision (key={key})",
            },
        ]
        return True

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    def _maybe_notify(self, event: AuditEvent) -> None:
        """达到通知门槛的事件入队（04 文档 §5：action ≥ min_action 才通知）。

        dispatcher 为可选注入（None 跳过，既有测试零改动兼容）；min_action 读当前
        策略（热更新即刻生效），无管线时回落 dispatcher 携带的配置。
        """
        if self.dispatcher is None:
            return
        min_action = self.dispatcher.min_action
        if self.pipeline is not None:
            min_action = self.pipeline.policy.notifications.min_action
        try:
            try:
                rank = action_rank(event.verdict)
            except KeyError:
                return  # verdict=unassessed 等非四级动作（无策略管线的旧路径）不通知
            if rank < action_rank(min_action):
                return
            self.dispatcher.enqueue(event)
            self.notified_count += 1
        except Exception:  # noqa: BLE001 - 通知绝不影响审计主路径（04 文档 §3）
            logger.exception("通知入队异常（fail-open）")

    def notify_stats(self) -> dict[str, Any]:
        """通知统计（诊断/状态命令用；未启用通知时为 None 项）。"""
        if self.dispatcher is None:
            return {"enabled": False}
        return {"enabled": True, "enqueued": self.notified_count, **self.dispatcher.stats()}

    def attribution_summary(self) -> dict[str, Any]:
        """归因统计（诊断/状态命令用）。"""
        summary: dict[str, Any] = {
            "connections_seen": self.connections_seen,
            "unknown_attribution": self.unknown_attribution_count,
        }
        if self.attributor is not None:
            stats = self.attributor.stats
            summary["attributor"] = {
                "total": stats.total,
                "resolved": stats.resolved,
                "unknown": stats.unknown,
                "pid_cache_hits": stats.pid_cache_hits,
                "pid_cache_misses": stats.pid_cache_misses,
            }
        return summary

    def __repr__(self) -> str:  # pragma: no cover - 调试辅助
        return f"AuditAddon(mode={self.mode!r}, connections_seen={self.connections_seen})"
