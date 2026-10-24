"""五维求值管线（02 文档 D4，03 文档 T3.2）。

维度：domain（分类 + unknown 首连）、process（画像）、content（secrets/pii/code_leak）、
volume（体量）、time_window（进程×域名滑动窗口速率）。
动作四级取最高，``risk_score = min(100, Σ weight)``；引擎异常按 ``fail_open`` 放行或阻断。
"""

from __future__ import annotations

import logging
import re
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from aaa.engine.verdict import (
    DIM_CONTENT,
    DIM_DOMAIN,
    DIM_PROCESS,
    DIM_TIME_WINDOW,
    DIM_VOLUME,
    EvaluationResult,
    MatchedRule,
)
from aaa.policy.loader import PolicyLoader
from aaa.policy.model import (
    ContentRule,
    DomainRule,
    PolicyDocument,
)
from aaa.scanners import scan_code_leak, scan_pii, scan_secrets
from aaa.scanners.base import ScanResult
from aaa.store.events import ProcessInfo

logger = logging.getLogger(__name__)

#: 扫描器函数签名：（body 文本, 截断上限 max_bytes 关键字）→ ScanResult
ScannerFn = Callable[..., ScanResult]

BUILTIN_SCANNERS: dict[str, ScannerFn] = {
    "secrets": scan_secrets,
    "pii": scan_pii,
    "code_leak": scan_code_leak,
}


@dataclass(frozen=True)
class EvaluationInput:
    """一次求值的输入快照（addon 在 request 钩子组装）。"""

    host: str
    port: int
    body: bytes | None = None
    body_size: int = 0
    content_type: str | None = None
    process: ProcessInfo | None = None


class AuditPipeline:
    """策略驱动的五维求值器（线程安全；策略经 ``PolicyLoader`` 热更新）。"""

    def __init__(
        self,
        policy_loader: PolicyLoader,
        *,
        scanners: Mapping[str, ScannerFn] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.loader = policy_loader
        self._scanners: dict[str, ScannerFn] = (
            dict(scanners) if scanners else dict(BUILTIN_SCANNERS)
        )
        self._clock = clock
        self._lock = threading.Lock()
        self._seen_hosts: set[str] = set()
        self._windows: dict[tuple[str, str], deque[float]] = {}
        self.evaluations = 0
        self._last_policy_version: str | None = None

    # ------------------------------------------------------------------ 入口

    @property
    def policy(self) -> PolicyDocument:
        """当前策略（顺带做 mtime 轮询，loader 内部限频 2s）。"""
        changed = self.loader.maybe_reload()
        doc = self.loader.current
        # 热更新生效可见：版本变化写一条日志（run 控制台/autostart.log 均可见）
        if changed and self._last_policy_version is not None:
            logger.info(
                "策略已热更新：%s → %s（无需重启，即刻生效）",
                self._last_policy_version,
                doc.policy_version,
            )
        self._last_policy_version = doc.policy_version
        return doc

    def evaluate(self, inp: EvaluationInput) -> EvaluationResult:
        """五维求值；任何维度异常按 fail_open 配置放行或阻断。"""
        policy = self.policy
        matched: list[MatchedRule] = []
        dimension_errors: list[str] = []
        for name, dimension in (
            ("domain", self._eval_domain),
            ("process", self._eval_process),
            ("content", self._eval_content),
            ("volume", self._eval_volume),
            ("time_window", self._eval_time_window),
        ):
            try:
                matched.extend(dimension(policy, inp))
            except Exception as exc:  # noqa: BLE001 - 单维异常不拖垮整个求值
                logger.exception("策略维度 %s 求值异常", name)
                dimension_errors.append(f"{name}: {exc}")
        with self._lock:
            self.evaluations += 1
        if dimension_errors:
            error = "; ".join(dimension_errors)
            if policy.defaults.fail_open:
                return EvaluationResult(verdict="allow", risk_score=0, error=error)
            return EvaluationResult(
                verdict="block", risk_score=100, matched=tuple(matched), error=error
            )
        return EvaluationResult.from_matched(matched)

    # ------------------------------------------------------- 域阻断快速通道

    def is_domain_blocked(self, host: str) -> list[MatchedRule]:
        """CONNECT/SNI 阶段的域名 blocklist 快速判定（02 文档 D5）。"""
        try:
            policy = self.policy
        except Exception:  # noqa: BLE001 - 策略不可用时按 fail_open 放行
            return []
        matched: list[MatchedRule] = []
        for rule in policy.domains.rules:
            if rule.action != "block":
                continue
            if self._domain_rule_hits(policy, rule, host, first_contact=True):
                matched.append(
                    MatchedRule(
                        id=rule.id,
                        dim=DIM_DOMAIN,
                        action=rule.action,
                        weight=rule.weight,
                        evidence=host,
                    )
                )
        return matched

    # ------------------------------------------------------------- 各维度

    def _eval_domain(self, policy: PolicyDocument, inp: EvaluationInput) -> list[MatchedRule]:
        classification = policy.classify_host(inp.host)
        first_contact = self._mark_host_seen(inp.host)
        matched: list[MatchedRule] = []
        for rule in policy.domains.rules:
            if self._domain_rule_hits(policy, rule, inp.host, first_contact=first_contact):
                matched.append(
                    MatchedRule(
                        id=rule.id,
                        dim=DIM_DOMAIN,
                        action=rule.action,
                        weight=rule.weight,
                        evidence=f"{inp.host} ({classification})",
                        detail=f"classification={classification}, first_contact={first_contact}",
                    )
                )
        return matched

    def _domain_rule_hits(
        self,
        policy: PolicyDocument,
        rule: DomainRule,
        host: str,
        *,
        first_contact: bool,
    ) -> bool:
        m = rule.match
        if m.host_regex and not re.search(m.host_regex, host):
            return False
        if m.cls:
            classification = policy.classify_host(host)
            if classification != m.cls:
                return False
            # unknown 首连告警（02 文档 D4）：unknown 类规则只在首次接触该域名时命中
            if m.cls == "unknown" and not first_contact:
                return False
        if not m.host_regex and not m.cls:
            return False
        return True

    def _eval_process(self, policy: PolicyDocument, inp: EvaluationInput) -> list[MatchedRule]:
        name = inp.process.name if inp.process else None
        exe = inp.process.exe if inp.process else None
        profile = policy.profile_of(name, exe)
        classification = policy.classify_host(inp.host)
        matched: list[MatchedRule] = []
        for rule in policy.processes.rules:
            m = rule.match
            if m.profile and profile != m.profile:
                continue
            if m.profile_not and profile == m.profile_not:
                continue
            if m.dest_class and classification != m.dest_class:
                continue
            if not (m.profile or m.profile_not or m.dest_class):
                continue
            matched.append(
                MatchedRule(
                    id=rule.id,
                    dim=DIM_PROCESS,
                    action=rule.action,
                    weight=rule.weight,
                    evidence=f"{name or 'unknown'} [{profile}] → {inp.host}",
                    detail=f"profile={profile}, dest_class={classification}",
                )
            )
        return matched

    def _eval_content(self, policy: PolicyDocument, inp: EvaluationInput) -> list[MatchedRule]:
        if inp.body is None or not inp.body or not policy.content.scanners:
            return []
        limit = policy.defaults.max_body_scan
        results: dict[str, ScanResult] = {}
        for scanner_name in policy.content.scanners:
            fn = self._scanners.get(scanner_name)
            if fn is None:
                logger.warning("策略启用了未知扫描器 %s（跳过）", scanner_name)
                continue
            try:
                results[scanner_name] = fn(inp.body, max_bytes=limit)
            except Exception as exc:  # noqa: BLE001 - 带上扫描器名再抛（fail_open 记录用）
                raise RuntimeError(f"scanner {scanner_name}: {exc}") from exc
        matched: list[MatchedRule] = []
        for rule in policy.content.rules:
            hits = self._content_rule_hits(rule, inp, results)
            if hits is None:
                continue
            evidence, detail = hits
            matched.append(
                MatchedRule(
                    id=rule.id,
                    dim=DIM_CONTENT,
                    action=rule.action,
                    weight=rule.weight,
                    evidence=evidence,
                    detail=detail,
                )
            )
        return matched

    def _content_rule_hits(
        self,
        rule: ContentRule,
        inp: EvaluationInput,
        results: Mapping[str, ScanResult],
    ) -> tuple[str, str] | None:
        """返回 (evidence, detail) 或 ``None``（未命中）。"""
        m = rule.match
        if rule.scanner is not None:
            result = results.get(rule.scanner)
            if result is None:
                return None
            if m.hits_gt is not None:
                if result.metrics.get("hits", 0) <= m.hits_gt:
                    return None
                summary = ", ".join(h.rule_id for h in result.hits[:5])
                return (
                    f"{result.hit_count} hits [{rule.scanner}]",
                    f"hits={result.hit_count} > {m.hits_gt}: {summary}",
                )
            if result.hit_count == 0:
                return None
            first = result.hits[0]
            return (
                first.evidence,
                f"{rule.scanner}:{first.rule_id}"
                + (f" (+{result.hit_count - 1} more)" if result.hit_count > 1 else ""),
            )
        # 无 scanner 的内容规则：体量 + 代码相似度（如 code-bulk-upload）
        if m.body_size_gt is not None and inp.body_size <= m.body_size_gt:
            return None
        if m.code_likeness_gt is not None:
            likeness = results.get("code_leak")
            if likeness is None or likeness.metrics.get("code_likeness", 0) <= m.code_likeness_gt:
                return None
            value = likeness.metrics["code_likeness"]
            return (
                f"code_likeness={value}",
                f"body_size={inp.body_size} > {m.body_size_gt}, "
                f"code_likeness={value} > {m.code_likeness_gt}",
            )
        if m.body_size_gt is not None:
            return (f"body_size={inp.body_size}", f"body_size={inp.body_size} > {m.body_size_gt}")
        return None

    def _eval_volume(self, policy: PolicyDocument, inp: EvaluationInput) -> list[MatchedRule]:
        matched: list[MatchedRule] = []
        for rule in policy.volume:
            if inp.body_size > rule.match.body_size_gt:
                matched.append(
                    MatchedRule(
                        id=rule.id,
                        dim=DIM_VOLUME,
                        action=rule.action,
                        weight=rule.weight,
                        evidence=f"{inp.body_size} bytes → {inp.host}",
                        detail=f"body_size={inp.body_size} > {rule.match.body_size_gt}",
                    )
                )
        return matched

    def _eval_time_window(self, policy: PolicyDocument, inp: EvaluationInput) -> list[MatchedRule]:
        if not policy.time_window:
            return []
        proc_key = (
            str(inp.process.pid)
            if inp.process and inp.process.pid is not None
            else (inp.process.name if inp.process else "unknown")
        )
        now = self._clock()
        matched: list[MatchedRule] = []
        for rule in policy.time_window:
            count = self._record_window((proc_key, inp.host), now, rule.match.window_seconds)
            if count > rule.match.requests_gt:
                matched.append(
                    MatchedRule(
                        id=rule.id,
                        dim=DIM_TIME_WINDOW,
                        action=rule.action,
                        weight=rule.weight,
                        evidence=f"{count} req/{rule.match.window_seconds}s → {inp.host}",
                        detail=(
                            f"requests={count} > {rule.match.requests_gt}"
                            f" in {rule.match.window_seconds}s"
                        ),
                    )
                )
        return matched

    def _record_window(self, key: tuple[str, str], now: float, window_seconds: int) -> int:
        """记录一次请求并返回窗口内计数（滑动窗口，惰性清理过期样本）。"""
        with self._lock:
            window = self._windows.setdefault(key, deque())
            window.append(now)
            cutoff = now - window_seconds
            while window and window[0] < cutoff:
                window.popleft()
            # 惰性回收空窗口，避免键无限增长
            if not window:
                self._windows.pop(key, None)
            return len(window)

    def _mark_host_seen(self, host: str) -> bool:
        """返回是否首次接触该域名（unknown 首连判定用）。"""
        with self._lock:
            key = (host or "").lower().rstrip(".")
            if key in self._seen_hosts:
                return False
            self._seen_hosts.add(key)
            return True

    # --------------------------------------------------------------- 观测

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "evaluations": self.evaluations,
                "tracked_hosts": len(self._seen_hosts),
                "tracked_windows": len(self._windows),
            }
