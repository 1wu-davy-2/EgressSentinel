"""五维求值管线（02 文档 D4，03 文档 T3.2；v0.2.0 安全深化扩展）。

维度：domain（分类 + unknown 首连）、process（画像）、content（secrets/pii/code_leak/
repo_fingerprint）、volume（体量）、time_window（进程×域名滑动窗口速率）。
动作四级取最高，``risk_score = min(100, Σ weight)``；引擎异常按 ``fail_open`` 放行或阻断。

v0.2.0（05 文档波次二）：新增响应侧求值 :meth:`AuditPipeline.evaluate_response`
（注入特征扫描 + response 规则，仅 alert 级标注、绝不阻断）与 ``repo_fingerprint``
内容扫描器（本地仓库指纹比对，命中清单附进事件 matched_rules 的 extra）。
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
    DIM_RESPONSE,
    DIM_TIME_WINDOW,
    DIM_VOLUME,
    EvaluationResult,
    MatchedRule,
)
from aaa.fingerprint import FingerprintIndex
from aaa.policy.loader import PolicyLoader
from aaa.policy.model import (
    ContentRule,
    DomainRule,
    PolicyDocument,
)
from aaa.scanners import scan_code_leak, scan_pii, scan_secrets
from aaa.scanners.base import ScanHit, ScanResult
from aaa.scanners.injection import InjectionHit, scan_injection, worst_severity
from aaa.store.events import ProcessInfo

logger = logging.getLogger(__name__)

#: 扫描器函数签名：（body 文本, 截断上限 max_bytes 关键字）→ ScanResult
ScannerFn = Callable[..., ScanResult]

BUILTIN_SCANNERS: dict[str, ScannerFn] = {
    "secrets": scan_secrets,
    "pii": scan_pii,
    "code_leak": scan_code_leak,
}

#: 仓库指纹扫描器注册名（policy content.scanners 引用；策略未启用指纹时不注册）
FINGERPRINT_SCANNER_NAME = "repo_fingerprint"

#: repo_fingerprint 扫描器的规则 id（事件 matched_rules[].id 中的扫描器规则名）
FINGERPRINT_RULE_ID = "repo-fingerprint-hit"


def make_fingerprint_scanner(index: FingerprintIndex) -> ScannerFn:
    """把 :class:`FingerprintIndex` 包装成管线扫描器（05 文档波次二 §2）。

    - 命中 → ``ScanHit``：``evidence`` 用指纹模块的 snippet（80 字符、空白已压缩，
      W1 红线：事件/通知外发不携带更长原文）；``extra`` 携带结构化命中位置
      （repo/file/line），供事件 evidence 附指纹命中清单；
    - ``max_bytes`` 与其他扫描器同语义：先截断再比对（build 与 scan 共用
      ``iter_slices`` 切片规范，截断只影响参与比对的尾部）；
    - 空索引/无命中 → 空 ScanResult，绝不抛异常（扫描异常由管线 fail_open 兜底）。
    """

    def scan_fingerprint(body: bytes | str | None, max_bytes: int | None = None) -> ScanResult:
        if not body:
            return ScanResult(scanner=FINGERPRINT_SCANNER_NAME)
        text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body
        if max_bytes is not None and len(text) > max_bytes:
            text = text[:max_bytes]
        try:
            hits = index.scan_body(text)
        except Exception as exc:  # noqa: BLE001 - 扫描异常交由管线 fail_open 处理
            raise RuntimeError(f"fingerprint scan: {exc}") from exc
        scan_hits = tuple(
            ScanHit(
                FINGERPRINT_SCANNER_NAME,
                FINGERPRINT_RULE_ID,
                hit.snippet,
                hit.line,
                f"{hit.repo}/{hit.file}:{hit.line}",
                {"repo": hit.repo, "file": hit.file, "line": hit.line},
            )
            for hit in hits
        )
        return ScanResult(
            scanner=FINGERPRINT_SCANNER_NAME,
            hits=scan_hits,
            metrics={"hits": float(len(scan_hits))},
        )

    return scan_fingerprint


def _fingerprint_hit_dict(hit: ScanHit) -> dict[str, Any]:
    """``ScanHit``（repo_fingerprint）→ 事件 ``extra.fingerprint_hits`` 条目。

    snippet 已由指纹模块截断 80 字符（W1 红线：事件外发不携带更长原文）。
    """
    return {
        "repo": hit.extra.get("repo"),
        "file": hit.extra.get("file"),
        "line": hit.extra.get("line"),
        "snippet": hit.evidence,
    }


@dataclass(frozen=True)
class ResponseFinding:
    """一次响应侧求值结果（05 文档波次二 §2）。

    响应侧**只有 alert 级标注**：``matched`` 里的规则 action 恒为 alert、weight 恒
    为 0——不参与阻断，也不抬高 risk_score；``hits`` 为注入特征原始命中（含严重
    度与类别，供事件/诊断展示）。
    """

    matched: tuple[MatchedRule, ...] = ()
    hits: tuple[InjectionHit, ...] = ()
    worst_severity: str | None = None
    """命中特征的最高严重度（low|medium|high）；无命中为 None。"""

    @property
    def verdict(self) -> str:
        """本次响应侧判定的动作（恒 alert 或 allow，绝不 confirm/block）。"""
        if not self.matched:
            return "allow"
        return "alert"

    @property
    def has_findings(self) -> bool:
        return bool(self.matched)


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
        fingerprint_index: FingerprintIndex | None = None,
    ) -> None:
        self.loader = policy_loader
        self._scanners: dict[str, ScannerFn] = (
            dict(scanners) if scanners else dict(BUILTIN_SCANNERS)
        )
        if fingerprint_index is not None and FINGERPRINT_SCANNER_NAME not in self._scanners:
            # 05 文档波次二 §2：策略启用指纹且拿到索引时注册 repo_fingerprint 扫描器
            # （测试显式注入的同名扫描器优先——注入面优先于自动装配）
            self._scanners[FINGERPRINT_SCANNER_NAME] = make_fingerprint_scanner(
                fingerprint_index
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

    # ------------------------------------------------------- 响应侧求值（v0.2.0）

    def evaluate_response(
        self,
        text: bytes | str | None,
        *,
        policy: PolicyDocument | None = None,
    ) -> ResponseFinding:
        """响应侧求值（05 文档波次二 §2/§3）：注入特征扫描 + response 规则标注。

        - 扫描注入特征（``scanners.injection``，纯 regex/启发式、无网络）；
        - 命中后按 ``policy.response.rules`` 生成标注规则：``patterns="all"`` 对任何
          命中标注；``"high"`` 仅当最高严重度为 high；
        - **红线**：产出的规则 action 恒为 alert、weight 恒为 0——响应侧只标注、
          绝不阻断响应（05 文档波次二 §3），本方法任何路径都不会产出 block/confirm；
        - 策略/扫描异常一律收敛为"无命中"返回（fail-open，响应侧标注绝不影响代理）；
        - ``evidence`` 取首条命中片段（W4 模块已做 80 字符截断 + 不可见字符显性化）。
        """
        try:
            doc = policy if policy is not None else self.policy
            hits = scan_injection(text, max_bytes=doc.defaults.max_body_scan)
        except Exception:  # noqa: BLE001 - 响应侧标注 fail-open（波次二 §3）
            logger.exception("响应侧注入扫描异常（fail-open）")
            return ResponseFinding()
        if not hits:
            return ResponseFinding()
        worst = worst_severity(hits)
        first_evidence = hits[0].evidence
        summary = ", ".join(dict.fromkeys(h.pattern for h in hits[:5]))
        suffix = f" (+{len(hits) - 1} more)" if len(hits) > 5 else ""
        matched: list[MatchedRule] = []
        for rule in doc.response.rules:
            if rule.patterns == "high" and worst != "high":
                continue
            matched.append(
                MatchedRule(
                    id=rule.id,
                    dim=DIM_RESPONSE,
                    action="alert",
                    weight=0,
                    evidence=first_evidence,
                    detail=(
                        f"injection hits={len(hits)}, worst={worst}, "
                        f"patterns={rule.patterns}: {summary}{suffix}"
                    ),
                    extra={
                        "worst_severity": worst,
                        "hit_count": len(hits),
                        "hits": [
                            {
                                "pattern": h.pattern,
                                "severity": h.severity,
                                "category": h.category,
                                "evidence": h.evidence,
                                "line": h.line,
                            }
                            for h in hits[:10]
                        ],
                    },
                )
            )
        return ResponseFinding(matched=tuple(matched), hits=tuple(hits), worst_severity=worst)

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
            rule_match = self._content_rule_hits(rule, inp, results)
            if rule_match is None:
                continue
            matched.append(rule_match)
        return matched

    def _content_rule_hits(
        self,
        rule: ContentRule,
        inp: EvaluationInput,
        results: Mapping[str, ScanResult],
    ) -> MatchedRule | None:
        """返回命中的 :class:`MatchedRule` 或 ``None``（未命中）。

        ``repo_fingerprint`` 扫描器命中时，把结构化指纹命中清单（repo/file/line/
        snippet，snippet 已按 W1 红线截断 80 字符）附进 ``extra.fingerprint_hits``
        ——即 05 文档波次二 §2 的"事件 evidence 附指纹命中清单"。
        """
        m = rule.match
        if rule.scanner is not None:
            result = results.get(rule.scanner)
            if result is None:
                return None
            if m.hits_gt is not None:
                if result.metrics.get("hits", 0) <= m.hits_gt:
                    return None
                summary = ", ".join(h.rule_id for h in result.hits[:5])
                evidence = f"{result.hit_count} hits [{rule.scanner}]"
                detail = f"hits={result.hit_count} > {m.hits_gt}: {summary}"
            elif result.hit_count == 0:
                return None
            else:
                first = result.hits[0]
                evidence = first.evidence
                detail = (
                    f"{rule.scanner}:{first.rule_id}"
                    + (f" (+{result.hit_count - 1} more)" if result.hit_count > 1 else "")
                )
            extra: dict[str, Any] = dict(result.hits[0].extra) if result.hits else {}
            if rule.scanner == FINGERPRINT_SCANNER_NAME and result.hits:
                # 05 文档波次二 §2：命中 → 事件附指纹命中清单（全部命中，≤20 条）
                extra["fingerprint_hits"] = [_fingerprint_hit_dict(h) for h in result.hits]
            return MatchedRule(
                id=rule.id,
                dim=DIM_CONTENT,
                action=rule.action,
                weight=rule.weight,
                evidence=evidence,
                detail=detail,
                extra=extra,
            )
        # 无 scanner 的内容规则：体量 + 代码相似度（如 code-bulk-upload）
        if m.body_size_gt is not None and inp.body_size <= m.body_size_gt:
            return None
        if m.code_likeness_gt is not None:
            likeness = results.get("code_leak")
            if likeness is None or likeness.metrics.get("code_likeness", 0) <= m.code_likeness_gt:
                return None
            value = likeness.metrics["code_likeness"]
            return MatchedRule(
                id=rule.id,
                dim=DIM_CONTENT,
                action=rule.action,
                weight=rule.weight,
                evidence=f"code_likeness={value}",
                detail=(
                    f"body_size={inp.body_size} > {m.body_size_gt}, "
                    f"code_likeness={value} > {m.code_likeness_gt}"
                ),
            )
        if m.body_size_gt is not None:
            return MatchedRule(
                id=rule.id,
                dim=DIM_CONTENT,
                action=rule.action,
                weight=rule.weight,
                evidence=f"body_size={inp.body_size}",
                detail=f"body_size={inp.body_size} > {m.body_size_gt}",
            )
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
