"""事件 → 通知摘要（04 文档 §3 T2：脱敏是红线）。

- 复用 web 侧同一脱敏核心（``web.masking.mask_secret_spans`` → ``iter_secret_spans``，
  规则 + allowlist + 熵阈值同源，decisions D-18）：命中的密钥片段打码，
  绝不能把拦截到的明文密钥再发到 toast/webhook/邮件；
- 字段（04 文档 §3）：时间 / 动作 / 风险分 / 进程 / 主机 / 命中规则；
- 正文截断 200 字符（toast/邮件摘要保持短小；截断在脱敏之后，防止截半截密钥）；
- ``request.path`` 可能携带查询串密钥（如 ``?key=AKIA…``），事件 JSON 外发（generic
  webhook）前单独打码——事件其余字段结构上不含 body 明文（``matched_rules[].evidence``
  在扫描时已按同一核心打码）。
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from aaa.scanners.secrets import SecretRule
from aaa.store.events import AuditEvent
from aaa.web.masking import mask_secret_spans

#: 摘要正文上限（04 文档 §3 T2：正文截断 200 字符）
SUMMARY_MAX_CHARS = 200

#: 通知标题（toast 通道的标题行；04 文档 §4「EgressSentinel 审计告警」）
NOTIFY_TITLE = "EgressSentinel 审计告警"


@dataclass(frozen=True)
class NotifySummary:
    """脱敏摘要结果。"""

    text: str
    """脱敏 + 截断后的多行摘要文本（可直接作为通知正文）。"""
    masked_hits: dict[str, int] = field(default_factory=dict)
    """``{rule_id: 打码次数}``（与 ``MaskedBody.hits`` 同形态）。"""
    truncated: bool = False
    """是否因 200 字符上限被截断。"""


def _format_process(event: AuditEvent) -> str:
    """进程字段：``name(pid)``；未归因为 ``unknown``（decisions D-14 形态）。"""
    process = event.process
    if process is None:
        return "unknown"
    name = process.name or "unknown"
    pid = str(process.pid) if process.pid is not None else "?"
    return f"{name}({pid})"


def _format_rules(event: AuditEvent) -> str:
    """命中规则：``id(dim)「evidence」`` 逗号连接；无命中为 ``-``。

    ``evidence`` 为扫描器输出，密钥片段在扫描时已按同一核心打码（decisions D-18）；
    摘要整体还会再过一遍 ``mask_secret_spans``（防线叠加）。
    """
    parts: list[str] = []
    for rule in event.matched_rules:
        if not isinstance(rule, Mapping):
            continue
        piece = f"{rule.get('id', '?')}({rule.get('dim', '?')})"
        evidence = str(rule.get("evidence") or "")
        if evidence:
            piece = f"{piece}「{evidence}」"
        parts.append(piece)
    return ", ".join(parts) if parts else "-"


def build_summary(
    event: AuditEvent,
    *,
    max_chars: int = SUMMARY_MAX_CHARS,
    rules: tuple[SecretRule, ...] | None = None,
) -> NotifySummary:
    """构建事件的脱敏摘要（04 文档 §3 T2）。

    流程：拼字段 → ``mask_secret_spans`` 打码（同一脱敏核心）→ 截断 ``max_chars``。
    必备字段：时间/动作/风险分/进程/主机/命中规则；附加「方法 路径」一行（查询串
    可能携带密钥——正是脱敏核心发挥作用的地方）。行序按 glance 价值排列（toast
    只显示前 3 行）。``rules`` 供测试注入精简规则表，生产走内置 ``SECRET_RULES``。
    """
    lines = [
        f"动作：{event.verdict}（风险分 {event.risk_score}）",
        f"主机：{event.destination.host} {event.request.method} {event.request.path}",
        f"进程：{_format_process(event)}",
        f"规则：{_format_rules(event)}",
        f"时间：{event.ts}",
    ]
    kwargs: dict[str, tuple[SecretRule, ...]] = {}
    if rules is not None:
        kwargs["rules"] = rules
    masked = mask_secret_spans("\n".join(lines), **kwargs)
    text = masked.text
    truncated = False
    if len(text) > max_chars:
        text = text[:max_chars]
        truncated = True
    return NotifySummary(text=text, masked_hits=masked.hits, truncated=truncated)


def mask_event_path(path: str) -> str:
    """对 ``request.path``（可能含查询串密钥）打码（generic webhook 外发前的防线）。"""
    return mask_secret_spans(path).text


def build_digest_text(suppressed: int, *, max_per_minute: int) -> str:
    """限流 digest 文本（04 文档 §3：「另有 N 条事件被限流」）。"""
    return (
        f"{NOTIFY_TITLE}：另有 {suppressed} 条事件被限流"
        f"（{max_per_minute} 条/分钟，已合并为本摘要）。"
    )
