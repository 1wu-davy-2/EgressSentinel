"""五维求值器单测（03 文档 T3.2）：每维独立 + 组合取最高 + risk_score 合成。"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from aaa.engine.pipeline import AuditPipeline, EvaluationInput
from aaa.policy.loader import PolicyLoader
from aaa.scanners.base import ScanHit, ScanResult
from aaa.store.events import ProcessInfo

VALID_YAML: dict[str, Any] = {
    "version": 1,
    "mode": "dry-run",
    "defaults": {"fail_open": True, "max_body_scan": 1024},
    "domains": {
        "classes": {
            "known_ai_api": ["api.anthropic.com", "api.openai.com"],
            "code_hosting": ["github.com"],
        },
        "rules": [
            {
                "id": "domain-unknown",
                "match": {"class": "unknown"},
                "action": "alert",
                "weight": 20,
            },
            {
                "id": "domain-blocklist",
                "match": {"host_regex": r"\.mal\.com$"},
                "action": "block",
                "weight": 80,
            },
        ],
    },
    "processes": {
        "profiles": {
            "agent_cli": {"exe_regex": "(?i)(claude|codex|node|python)"},
            "browser": {"exe_regex": "(?i)(chrome|msedge)\\.exe$"},
        },
        "rules": [
            {
                "id": "non-agent-to-ai-api",
                "match": {"profile_not": "agent_cli", "dest_class": "known_ai_api"},
                "action": "alert",
                "weight": 30,
            }
        ],
    },
    "content": {
        "scanners": ["secrets", "pii", "code_leak"],
        "rules": [
            {"id": "secret-leak", "scanner": "secrets", "action": "block", "weight": 60},
            {
                "id": "pii-bulk",
                "scanner": "pii",
                "match": {"hits_gt": 2},
                "action": "confirm",
                "weight": 40,
            },
            {
                "id": "code-bulk-upload",
                "match": {"body_size_gt": 100, "code_likeness_gt": 0.6},
                "action": "confirm",
                "weight": 40,
            },
        ],
    },
    "volume": [
        {"id": "huge-body", "match": {"body_size_gt": 1000}, "action": "alert", "weight": 20}
    ],
    "time_window": [
        {
            "id": "burst",
            "match": {"requests_gt": 3, "window_seconds": 60},
            "action": "alert",
            "weight": 20,
        }
    ],
}


def _write_policy(tmp_path: Path, doc: dict[str, Any] | None = None) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(
        yaml.safe_dump(doc if doc is not None else VALID_YAML, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    return path


def _pipeline(tmp_path: Path, doc: dict[str, Any] | None = None, **kw: Any) -> AuditPipeline:
    return AuditPipeline(PolicyLoader(_write_policy(tmp_path, doc)), **kw)


def _inp(**kw: Any) -> EvaluationInput:
    defaults: dict[str, Any] = {"host": "example.org", "port": 443}
    defaults.update(kw)
    return EvaluationInput(**defaults)


AGENT = ProcessInfo(pid=100, name="claude.exe", exe=r"C:\bin\claude.exe")
BROWSER = ProcessInfo(pid=200, name="chrome.exe", exe=r"C:\bin\chrome.exe")


# ------------------------------------------------------------------ domain 维


def test_domain_unknown_first_connection_only(tmp_path: Path) -> None:
    pipe = _pipeline(tmp_path)
    first = pipe.evaluate(_inp(host="new.site.com"))
    assert [m.id for m in first.matched] == ["domain-unknown"]
    assert first.verdict == "alert"
    second = pipe.evaluate(_inp(host="new.site.com"))
    assert second.matched == ()
    assert second.verdict == "allow"


def test_domain_known_class_no_alert(tmp_path: Path) -> None:
    pipe = _pipeline(tmp_path)
    result = pipe.evaluate(_inp(host="api.openai.com", process=AGENT))
    assert result.matched == ()
    assert result.verdict == "allow"


def test_domain_blocklist_regex(tmp_path: Path) -> None:
    pipe = _pipeline(tmp_path)
    result = pipe.evaluate(_inp(host="evil.mal.com"))
    # evil.mal.com 同时是 unknown 首连（alert）与 blocklist 正则命中（block）
    assert sorted(m.id for m in result.matched) == ["domain-blocklist", "domain-unknown"]
    assert result.verdict == "block"
    assert result.risk_score == 100
    # is_domain_blocked 快速通道（CONNECT/SNI 用）
    assert [m.id for m in pipe.is_domain_blocked("x.evil.mal.com")] == ["domain-blocklist"]
    assert pipe.is_domain_blocked("api.openai.com") == []


def test_is_domain_blocked_only_block_actions(tmp_path: Path) -> None:
    """alert 级域名规则不进 CONNECT 快速通道。"""
    pipe = _pipeline(tmp_path)
    assert pipe.is_domain_blocked("brand-new-site.org") == []


# ----------------------------------------------------------------- process 维


def test_process_profile_not_match(tmp_path: Path) -> None:
    pipe = _pipeline(tmp_path)
    result = pipe.evaluate(_inp(host="api.anthropic.com", process=BROWSER))
    ids = [m.id for m in result.matched]
    assert ids == ["non-agent-to-ai-api"]
    assert result.verdict == "alert"


def test_process_agent_cli_not_matched(tmp_path: Path) -> None:
    pipe = _pipeline(tmp_path)
    result = pipe.evaluate(_inp(host="api.anthropic.com", process=AGENT))
    assert result.matched == ()


# ----------------------------------------------------------------- content 维


def test_content_secret_hit_blocks(tmp_path: Path) -> None:
    pipe = _pipeline(tmp_path)
    result = pipe.evaluate(_inp(host="api.openai.com", body=b"key AKIAQ2FZV3TQPE8KX9YZ"))
    assert "secret-leak" in [m.id for m in result.matched]
    assert result.verdict == "block"
    # 证据打码
    leak = next(m for m in result.matched if m.id == "secret-leak")
    assert "Q2FZV3TQPE8KX9YZ" not in leak.evidence


def test_content_pii_hits_gt(tmp_path: Path) -> None:
    pipe = _pipeline(tmp_path)
    # 2 封邮件（不超阈值 2）
    under = pipe.evaluate(_inp(host="api.openai.com", body=b"a@x.com b@x.com"))
    assert "pii-bulk" not in [m.id for m in under.matched]
    # 3 封（> 2）
    over = pipe.evaluate(_inp(host="api.openai.com", body=b"a@x.com b@x.com c@x.com"))
    assert "pii-bulk" in [m.id for m in over.matched]
    assert over.verdict == "confirm"


def test_content_code_bulk_upload(tmp_path: Path) -> None:
    pipe = _pipeline(tmp_path)
    code = ("\n".join(f"import os\ndef f{i}(x):\n    return x+{i}" for i in range(20))).encode()
    assert len(code) > 100
    result = pipe.evaluate(_inp(host="api.openai.com", body=code, body_size=len(code)))
    assert "code-bulk-upload" in [m.id for m in result.matched]
    assert result.verdict == "confirm"
    # 体量不足不命中
    small = code[:80]
    r2 = pipe.evaluate(_inp(host="api.openai.com", body=small, body_size=len(small)))
    assert "code-bulk-upload" not in [m.id for m in r2.matched]


def test_content_code_likeness_requires_code_leak_scanner_enabled(tmp_path: Path) -> None:
    """code-bulk-upload 依赖 code_leak 指标；扫描器未启用则不命中。"""
    doc = yaml.safe_load(yaml.safe_dump(VALID_YAML))
    doc["content"]["scanners"] = ["secrets"]
    pipe = _pipeline(tmp_path, doc)
    code = ("\n".join(f"import os\ndef f{i}(x):\n    return x+{i}" for i in range(20))).encode()
    result = pipe.evaluate(_inp(host="api.openai.com", body=code, body_size=len(code)))
    assert "code-bulk-upload" not in [m.id for m in result.matched]


def test_content_max_body_scan_truncates(tmp_path: Path) -> None:
    """扫描截断：密钥在截断点之后不被扫描。"""
    pipe = _pipeline(tmp_path)  # max_body_scan=1024
    padding = b"x" * 2000
    body = padding + b"AKIAQ2FZV3TQPE8KX9YZ"
    result = pipe.evaluate(_inp(host="api.openai.com", body=body, body_size=len(body)))
    assert "secret-leak" not in [m.id for m in result.matched]


def test_content_scanner_disabled_by_policy(tmp_path: Path) -> None:
    """scanners 未启用 secret-leak 规则的扫描器 → 不命中。"""
    doc = yaml.safe_load(yaml.safe_dump(VALID_YAML))
    doc["content"]["scanners"] = ["pii", "code_leak"]
    pipe = _pipeline(tmp_path, doc)
    result = pipe.evaluate(_inp(host="api.openai.com", body=b"AKIAQ2FZV3TQPE8KX9YZ"))
    assert "secret-leak" not in [m.id for m in result.matched]


def test_content_injected_scanner_fn(tmp_path: Path) -> None:
    """扫描器函数可注入（策略测试不依赖真实扫描实现）。"""

    def fake_scanner(body: object, max_bytes: int | None = None) -> ScanResult:
        return ScanResult(
            scanner="secrets",
            hits=(ScanHit("secrets", "injected-rule", "AB****", None, "injected"),),
            metrics={"hits": 1.0},
        )

    pipe = _pipeline(tmp_path, scanners={"secrets": fake_scanner})  # type: ignore[dict-item]
    result = pipe.evaluate(_inp(host="api.openai.com", body=b"anything"))
    assert "secret-leak" in [m.id for m in result.matched]


# ------------------------------------------------------------------ volume 维


def test_volume_body_size_gt(tmp_path: Path) -> None:
    pipe = _pipeline(tmp_path)
    under = pipe.evaluate(_inp(body=b"x" * 1000, body_size=1000))
    assert "huge-body" not in [m.id for m in under.matched]
    over = pipe.evaluate(_inp(body=b"x" * 1001, body_size=1001))
    assert "huge-body" in [m.id for m in over.matched]


# ------------------------------------------------------------- time_window 维


def test_time_window_sliding_burst(tmp_path: Path) -> None:
    ticks = iter(float(i) for i in range(10000))
    pipe = _pipeline(tmp_path, clock=lambda: next(ticks))
    host = "bursty.example.com"
    proc = ProcessInfo(pid=7, name="agent.exe", exe="agent.exe")
    verdicts = []
    for _ in range(4):  # requests_gt=3 → 第 4 次触发（首次另有 unknown 首连告警）
        result = pipe.evaluate(_inp(host=host, process=proc))
        verdicts.append(sorted(m.id for m in result.matched))
    assert verdicts == [
        ["domain-unknown"],
        [],
        [],
        ["burst"],
    ]
    # 滑动窗口：同进程同域名计数；不同域名独立（新域名的 unknown 首连告警不算 burst）
    fresh = pipe.evaluate(_inp(host="other.example.com", process=proc))
    assert "burst" not in [m.id for m in fresh.matched]


def test_time_window_window_expiry(tmp_path: Path) -> None:
    now = [1000.0]

    def clock() -> float:
        return now[0]

    pipe = _pipeline(tmp_path, clock=clock)
    proc = ProcessInfo(pid=7, name="agent.exe", exe="agent.exe")
    host = "w.example.com"
    for _ in range(3):
        pipe.evaluate(_inp(host=host, process=proc))
    now[0] += 61.0  # 窗口（60s）已过期
    result = pipe.evaluate(_inp(host=host, process=proc))
    assert result.matched == ()


# --------------------------------------------------------------- 组合与合成


def test_combination_takes_highest_action_and_sum_weights(tmp_path: Path) -> None:
    """02 文档 D4：多维命中取最高级，risk_score = min(100, Σ weight)。"""
    pipe = _pipeline(tmp_path)
    # known AI api（process 维 30）+ secret（content 维 60）+ huge body（volume 维 20）
    big = b"AKIAQ2FZV3TQPE8KX9YZ " + b"x" * 1100  # 空格分隔保证词边界
    result = pipe.evaluate(
        _inp(host="api.openai.com", process=BROWSER, body=big, body_size=len(big))
    )
    ids = {m.id for m in result.matched}
    assert {"non-agent-to-ai-api", "secret-leak", "huge-body"} <= ids
    assert result.verdict == "block"
    assert result.risk_score == min(100, 30 + 60 + 20)


def test_combination_with_domain_unknown(tmp_path: Path) -> None:
    """unknown 首连 + 内容命中的四维组合（20+60+20=100）。"""
    pipe = _pipeline(tmp_path)
    big = b"AKIAQ2FZV3TQPE8KX9YZ " + b"x" * 1100  # 空格分隔保证词边界
    result = pipe.evaluate(_inp(host="strange.io", body=big, body_size=len(big)))
    ids = {m.id for m in result.matched}
    assert {"domain-unknown", "secret-leak", "huge-body"} <= ids
    assert result.verdict == "block"
    assert result.risk_score == min(100, 20 + 60 + 20)


def test_no_match_is_allow_zero_risk(tmp_path: Path) -> None:
    pipe = _pipeline(tmp_path)
    result = pipe.evaluate(_inp(host="api.openai.com", process=AGENT))
    assert result.verdict == "allow"
    assert result.risk_score == 0
    assert result.matched == ()


def test_risk_score_capped_at_100(tmp_path: Path) -> None:
    doc = yaml.safe_load(yaml.safe_dump(VALID_YAML))
    doc["domains"]["rules"].append(
        {"id": "b1", "match": {"host_regex": "x"}, "action": "block", "weight": 100}
    )
    pipe = _pipeline(tmp_path, doc)
    big = b"AKIAQ2FZV3TQPE8KX9YZ " + b"x" * 1100  # 空格分隔保证词边界
    result = pipe.evaluate(_inp(host="x.com", process=BROWSER, body=big, body_size=len(big)))
    assert result.risk_score == 100


# ------------------------------------------------------------------ fail_open


def test_fail_open_on_engine_exception(tmp_path: Path) -> None:
    """维度异常 → fail_open 放行并带 error（02 文档 D5）。"""

    def boom(body: object, max_bytes: int | None = None) -> ScanResult:
        raise RuntimeError("scanner crashed")

    pipe = _pipeline(tmp_path, scanners={"secrets": boom})  # type: ignore[dict-item]
    result = pipe.evaluate(_inp(host="api.openai.com", body=b"data"))
    assert result.verdict == "allow"
    assert result.error is not None
    assert "secrets" in result.error
    assert "scanner crashed" in result.error


def test_fail_closed_on_engine_exception(tmp_path: Path) -> None:
    doc = yaml.safe_load(yaml.safe_dump(VALID_YAML))
    doc["defaults"]["fail_open"] = False

    def boom(body: object, max_bytes: int | None = None) -> ScanResult:
        raise RuntimeError("scanner crashed")

    pipe = _pipeline(tmp_path, doc, scanners={"secrets": boom})  # type: ignore[dict-item]
    result = pipe.evaluate(_inp(host="api.openai.com", body=b"data"))
    assert result.verdict == "block"
    assert result.error is not None


def test_policy_hot_reload_visible_through_pipeline(tmp_path: Path) -> None:
    """引擎轮询热更新：evaluate 间策略文件变化生效。"""
    import os

    path = _write_policy(tmp_path)
    loader = PolicyLoader(path)
    loader.load()
    pipe = AuditPipeline(loader, clock=lambda: 0.0)
    loader.path.write_text(
        yaml.safe_dump({**VALID_YAML, "mode": "enforce"}, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    stat = os.stat(path)
    os.utime(path, (stat.st_atime + 5, stat.st_mtime + 5))
    assert pipe.policy.mode == "enforce"  # policy 属性触发 maybe_reload


# --------------------------------------------------------------------- 观测


def test_pipeline_stats(tmp_path: Path) -> None:
    pipe = _pipeline(tmp_path)
    pipe.evaluate(_inp(host="a.com"))
    stats = pipe.stats()
    assert stats["evaluations"] == 1
    assert stats["tracked_hosts"] == 1


def test_scanner_fn_type_alias_contract() -> None:
    """ScannerFn 以关键字 max_bytes 调用（管线与扫描器契约）。"""
    from aaa.engine.pipeline import BUILTIN_SCANNERS

    for scanner_name, fn in BUILTIN_SCANNERS.items():
        result = fn(b"", max_bytes=10)
        assert isinstance(result, ScanResult)
        assert result.scanner == scanner_name
