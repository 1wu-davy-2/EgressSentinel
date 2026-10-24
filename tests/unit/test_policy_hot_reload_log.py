"""策略热更新生效可见：pipeline 检测版本变化并写日志（无需重启）。"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from aaa.engine.pipeline import AuditPipeline
from aaa.policy import loader as loader_mod
from aaa.policy.loader import PolicyLoader

_MINIMAL = """version: 1
mode: dry-run
domains:
  classes: {}
  rules: []
"""


def _write(path: Path, extra: str = "") -> None:
    path.write_text(_MINIMAL + extra, encoding="utf-8")


def test_policy_change_logs_hot_reload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    policy_file = tmp_path / "p.yaml"
    _write(policy_file)
    loader = PolicyLoader(policy_file)
    loader.load()
    pipeline = AuditPipeline(loader)

    clock = {"t": 1000.0, "mtime": 111.0}

    class FakeTime:
        @staticmethod
        def monotonic() -> float:
            return clock["t"]

    # 去 FS 依赖：时间与 mtime 都由测试注入（CI 磁盘时间戳粒度可能粗于写入间隔）
    monkeypatch.setattr(loader_mod, "time", FakeTime)
    monkeypatch.setattr(
        loader_mod.PolicyLoader, "_current_mtime", lambda self: clock["mtime"]
    )

    with caplog.at_level(logging.INFO, logger="aaa.engine.pipeline"):
        _ = pipeline.policy  # 初次：建立基线版本，不告警
        assert "热更新" not in caplog.text

        clock["t"] += 5  # 越过 RELOAD_POLL_SECONDS
        clock["mtime"] += 1.0  # mtime 必然变化
        _write(policy_file, "\n# touched\n")
        _ = pipeline.policy  # mtime 变化 → 重读 → 日志

    assert "热更新" in caplog.text
    hits = [r for r in caplog.records if "热更新" in r.getMessage()]
    assert len(hits) == 1
