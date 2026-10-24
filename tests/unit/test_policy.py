"""策略模型/加载器/lint 单测（03 文档 T3.1）。"""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aaa.cli import app
from aaa.policy.loader import PolicyError, PolicyLoader, parse_policy
from aaa.policy.model import PolicyDocument

runner = CliRunner()

VALID_YAML = """
version: 1
mode: dry-run
defaults: {fail_open: true, max_body_scan: 262144}
domains:
  classes:
    known_ai_api:
      - api.anthropic.com
      - api.openai.com
    code_hosting:
      - github.com
      - api.github.com
      - gitlab.com
  rules:
    - {id: domain-unknown, match: {class: unknown}, action: alert, weight: 20}
    - id: domain-blocklist
      match: {host_regex: '\\.example-mal\\.com$'}
      action: block
      weight: 80
processes:
  profiles:
    agent_cli: {exe_regex: '(?i)(claude|cursor|codex|copilot|node|python|java)'}
    browser: {exe_regex: '(?i)(chrome|msedge|firefox)\\.exe$'}
  rules:
    - id: non-agent-to-ai-api
      match: {profile_not: agent_cli, dest_class: known_ai_api}
      action: alert
      weight: 30
content:
  scanners: [secrets, pii, code_leak]
  rules:
    - {id: secret-leak, scanner: secrets, action: block, weight: 60}
    - {id: pii-bulk, scanner: pii, match: {hits_gt: 10}, action: confirm, weight: 40}
    - id: code-bulk-upload
      match: {body_size_gt: 512000, code_likeness_gt: 0.6}
      action: confirm
      weight: 40
volume:
  - {id: huge-body, match: {body_size_gt: 5242880}, action: alert, weight: 20}
time_window:
  - {id: burst, match: {requests_gt: 60, window_seconds: 60}, action: alert, weight: 20}
"""


# ------------------------------------------------------------------ 模型严格性


def test_parse_valid_document() -> None:
    doc = parse_policy(VALID_YAML)
    assert doc.mode == "dry-run"
    assert doc.defaults.fail_open is True
    assert doc.defaults.max_body_scan == 262144
    assert len(doc.domains.rules) == 2
    assert len(doc.content.rules) == 3
    assert doc.volume[0].match.body_size_gt == 5242880
    assert doc.time_window[0].match.window_seconds == 60


def test_extra_fields_forbidden() -> None:
    """未知字段直接校验失败（lint 抓拼写错误）。"""
    with pytest.raises(PolicyError, match="校验失败"):
        parse_policy("mode: dry-run\nbogus_section: 1\n")


def test_invalid_action_rejected() -> None:
    with pytest.raises(PolicyError):
        parse_policy(
            "domains:\n  rules:\n"
            "    - {id: x, match: {host_regex: 'a'}, action: nuke, weight: 10}\n"
        )


def test_invalid_mode_rejected() -> None:
    with pytest.raises(PolicyError):
        parse_policy("mode: dryrun\n")


def test_invalid_regex_rejected() -> None:
    with pytest.raises(PolicyError):
        parse_policy(
            "domains:\n  rules:\n    - {id: x, match: {host_regex: '([unclosed'}, action: alert}\n"
        )


def test_weight_out_of_range_rejected() -> None:
    with pytest.raises(PolicyError):
        parse_policy("volume:\n  - {id: x, match: {body_size_gt: 1}, action: alert, weight: 200}\n")


def test_unknown_scanner_name_rejected() -> None:
    with pytest.raises(PolicyError):
        parse_policy("content:\n  scanners: [virustotal]\n")


def test_empty_or_non_mapping_rejected() -> None:
    with pytest.raises(PolicyError):
        parse_policy("")
    with pytest.raises(PolicyError):
        parse_policy("- a\n- b\n")
    with pytest.raises(PolicyError):
        parse_policy("key: [unclosed\n")


# ---------------------------------------------------------------------- 加载器


def test_loader_load_and_current(tmp_path: Path) -> None:
    path = tmp_path / "p.yaml"
    path.write_text(VALID_YAML, encoding="utf-8")
    loader = PolicyLoader(path)
    doc = loader.current  # 懒加载
    assert doc.mode == "dry-run"
    assert loader.current is doc


def test_loader_load_error_message(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("mode: {unclosed\n", encoding="utf-8")
    loader = PolicyLoader(path)
    with pytest.raises(PolicyError):
        loader.load()
    missing = PolicyLoader(tmp_path / "nope.yaml")
    with pytest.raises(PolicyError, match="读取失败"):
        missing.load()


def test_hot_reload_on_mtime_change(tmp_path: Path) -> None:
    path = tmp_path / "p.yaml"
    path.write_text(VALID_YAML, encoding="utf-8")
    loader = PolicyLoader(path)
    loader.load()
    v1 = loader.current.policy_version

    # mtime 未变：不重载
    assert loader.maybe_reload(now=100.0) is False

    # 改内容（必须让 mtime 真的变化）
    time.sleep(0.02)
    path.write_text(VALID_YAML.replace("mode: dry-run", "mode: enforce"), encoding="utf-8")
    import os

    stat = os.stat(path)
    os.utime(path, (stat.st_atime + 5, stat.st_mtime + 5))
    assert loader.maybe_reload(now=100.0 + 5) is True
    assert loader.current.mode == "enforce"
    assert loader.current.policy_version != v1

    # 轮询限频：2 秒内不再 stat/reload
    assert loader.maybe_reload(now=100.0 + 5.5) is False


def test_hot_reload_bad_file_keeps_last_good(tmp_path: Path) -> None:
    path = tmp_path / "p.yaml"
    path.write_text(VALID_YAML, encoding="utf-8")
    loader = PolicyLoader(path)
    good = loader.load()
    time.sleep(0.02)
    path.write_text("mode: bogus\n", encoding="utf-8")
    import os

    stat = os.stat(path)
    os.utime(path, (stat.st_atime + 5, stat.st_mtime + 5))
    reloaded = loader.maybe_reload(now=1000.0)
    assert reloaded is False
    assert loader.last_error is not None
    assert loader.current is good  # 保留上一份好策略（fail-open）


# ----------------------------------------------------------------- 派生工具


def test_classify_host_exact_and_subdomain() -> None:
    doc = parse_policy(VALID_YAML)
    assert doc.classify_host("api.openai.com") == "known_ai_api"
    assert doc.classify_host("a.api.openai.com") == "known_ai_api"  # 子域
    assert doc.classify_host("notopenai.com") == "unknown"  # 非后缀
    assert doc.classify_host("API.GitHub.COM.") == "code_hosting"  # 大小写/尾点


def test_profile_of() -> None:
    doc = parse_policy(VALID_YAML)
    assert doc.profile_of("claude.exe", None) == "agent_cli"
    assert doc.profile_of("node", "/usr/bin/node") == "agent_cli"
    # profiles 顺序匹配：agent_cli 正则含 "node"，先于 browser 命中
    assert doc.profile_of("notepad.exe", None) == "other"
    assert doc.profile_of("msedge.exe", None) == "browser"
    chrome = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
    assert doc.profile_of(None, chrome) == "browser"


def test_policy_version_stable_and_sensitive() -> None:
    doc1 = parse_policy(VALID_YAML)
    doc2 = parse_policy(VALID_YAML)
    assert doc1.policy_version == doc2.policy_version
    doc3 = parse_policy(VALID_YAML.replace("mode: dry-run", "mode: enforce"))
    assert doc1.policy_version != doc3.policy_version
    assert len(doc1.policy_version) == 4


# ------------------------------------------------------------------- CLI lint


def test_cli_policy_lint_valid(tmp_path: Path) -> None:
    path = tmp_path / "p.yaml"
    path.write_text(VALID_YAML, encoding="utf-8")
    result = runner.invoke(app, ["policy", "lint", str(path)])
    assert result.exit_code == 0
    assert "策略合法" in result.output


def test_cli_policy_lint_invalid(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("mode: bogus\n", encoding="utf-8")
    result = runner.invoke(app, ["policy", "lint", str(path)])
    assert result.exit_code == 1
    assert "策略校验失败" in result.output


def test_cli_policy_lint_default_file() -> None:
    """项目默认策略合法（出厂默认 dry-run）。"""
    result = runner.invoke(app, ["policy", "lint"])
    assert result.exit_code == 0
    assert "dry-run" in result.output


def test_default_policy_is_dry_run() -> None:
    """02 文档 §0：出厂默认 dry-run。"""
    from aaa.config import DEFAULT_POLICY_FILE

    doc: PolicyDocument = parse_policy(DEFAULT_POLICY_FILE.read_text(encoding="utf-8"))
    assert doc.mode == "dry-run"
    assert doc.defaults.fail_open is True
    assert set(doc.content.scanners) == {"secrets", "pii", "code_leak"}
    assert {r.id for r in doc.domains.rules} == {"domain-unknown", "domain-blocklist"}
