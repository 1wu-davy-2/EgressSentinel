"""规则市场模块单测（06 文档波次一 W7）。

覆盖四组验收点：导入校验拒绝 / 合并语义 / gitleaks 转换样例（2 条 TOML 样本）/
pin 记录；另含规则包扫描的 allowlist 端到端行为。

红线自查：本文件**零真实网络**（URL 同步一律注入假客户端），落盘只发生在
``tmp_path``；不触碰真实策略文件与项目 data/。
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from aaa.policy.loader import parse_policy
from aaa.ruleshub import (
    DEFAULT_GITLEAKS_SOURCE,
    PackRule,
    RulesHubError,
    SecretsRulePack,
    convert_gitleaks_toml,
    export_section,
    import_section,
    load_pack,
    load_pack_file,
    scan_with_pack,
    shareable_sections,
    sync_gitleaks,
    to_secret_rules,
)
from aaa.scanners.secrets import SecretRule

# ------------------------------------------------------------------ 样本

BASE_POLICY = """\
version: 1
mode: dry-run
defaults: {fail_open: true, max_body_scan: 4096}
domains:
  classes:
    known_ai_api:
      - api.openai.com
  rules:
    - {id: domain-unknown, match: {class: unknown}, action: alert, weight: 20}
content:
  scanners: [secrets, pii]
  rules:
    - {id: secret-leak, scanner: secrets, action: block, weight: 60}
notifications:
  min_action: alert
  webhook: {enabled: true, provider: generic, url: 'https://hook.example.test/ingest'}
volume:
  - {id: huge-body, match: {body_size_gt: 5242880}, action: alert, weight: 20}
"""

DOMAINS_PACK = """\
classes:
  code_hosting:
    - gitlab.com
rules:
  - id: domain-blocklist
    match: {host_regex: '\\.evil\\.example$'}
    action: block
    weight: 90
"""

DOMAINS_UNION_OVERRIDE_PACK = """\
classes:
  known_ai_api:
    - api.anthropic.com
rules:
  - id: domain-unknown
    match: {class: unknown}
    action: confirm
    weight: 55
  - id: domain-blocklist
    match: {host_regex: '\\.evil\\.example$'}
    action: block
    weight: 90
"""

VOLUME_PACK = """\
- id: huge-body
  match: {body_size_gt: 1048576}
  action: confirm
  weight: 30
- id: giant-body
  match: {body_size_gt: 10485760}
  action: alert
  weight: 10
"""

# gitleaks TOML 样本一：2 条规则（1 条简单 + 1 条 keywords/熵/规则级 allowlist）
# + 全局 allowlist（06 文档 W7「转换样例」）
TOML_SAMPLE = """\
title = "sample gitleaks config"

[allowlist]
description = "global allowlist"
regexes = ['''(?i)EXAMPLE''', '''0000-0000''']

[[rules]]
id = "acme-token"
description = "Acme platform token"
regex = '''\\bacm_[A-Za-z0-9]{20}\\b'''
keywords = ["ACME_TOKEN", "acm_"]

[[rules]]
id = "legacy-key"
description = "High entropy assignment"
regex = '''(?i)legacy[_-]?key["']?\\s*[:=]\\s*["']?[A-Za-z0-9+/]{20,}'''
entropy = 3.5

  [[rules.allowlists]]
  description = "ignore docs"
  regexes = ['''DOC-SAMPLE''']
"""

# gitleaks TOML 样本二：跳过路径（缺 regex / secretGroup / Go 专有正则 / 重复 id）
TOML_SAMPLE_SKIPS = """\
title = "skip cases"

[[rules]]
id = "no-regex-rule"
description = "missing regex"

[[rules]]
id = "group-rule"
description = "uses secretGroup"
regex = '''(?i)aws.{0,20}([a-z0-9]{40})'''
secretGroup = 1

[[rules]]
id = "bad-regex-rule"
description = "Go-only unicode class"
regex = '''\\p{L}{5}'''

[[rules]]
id = "acme-token"
description = "first"
regex = '''acm_[a-z]{4}'''

[[rules]]
id = "acme-token"
description = "duplicate"
regex = '''acm_[a-z]{8}'''
"""

# ------------------------------------------------------------------ 段导出/导入


def test_shareable_sections_match_policy_fields() -> None:
    sections = shareable_sections()
    assert "domains" in sections and "content" in sections and "notifications" in sections
    assert "bogus" not in sections


def test_export_section_roundtrip_into_another_policy() -> None:
    doc = parse_policy(BASE_POLICY)
    exported = export_section(doc, "domains")
    merged_text = import_section("version: 1\nmode: dry-run\n", "domains", exported)
    merged = parse_policy(merged_text)
    assert merged.domains.classes == doc.domains.classes
    assert [rule.id for rule in merged.domains.rules] == ["domain-unknown"]
    assert merged.domains.rules[0].weight == 20


def test_export_section_is_bare_section_content() -> None:
    doc = parse_policy(BASE_POLICY)
    volume_yaml = export_section(doc, "volume")
    assert volume_yaml.lstrip().startswith("- id: huge-body"), "列表段导出为裸 YAML 列表"


@pytest.mark.parametrize("section", ["bogus", "rulez"])
def test_unknown_section_rejected_for_export_and_import(section: str) -> None:
    doc = parse_policy(BASE_POLICY)
    with pytest.raises(RulesHubError, match="未知策略段"):
        export_section(doc, section)
    with pytest.raises(RulesHubError, match="未知策略段"):
        import_section(BASE_POLICY, section, "a: 1\n")


def test_import_replace_replaces_whole_section() -> None:
    merged = parse_policy(import_section(BASE_POLICY, "domains", DOMAINS_PACK))
    assert merged.domains.classes == {"code_hosting": ["gitlab.com"]}
    assert [rule.id for rule in merged.domains.rules] == ["domain-blocklist"]
    assert merged.domains.rules[0].weight == 90
    # 段外一切保持不变
    assert merged.mode == "dry-run"
    assert [rule.id for rule in merged.content.rules] == ["secret-leak"]


def test_import_union_merges_rules_by_id_and_classes_by_key() -> None:
    merged = parse_policy(
        import_section(BASE_POLICY, "domains", DOMAINS_UNION_OVERRIDE_PACK, merge="union")
    )
    # 域名清单：同键并集，本方在前
    assert merged.domains.classes["known_ai_api"] == ["api.openai.com", "api.anthropic.com"]
    # 规则按 id：同 id 导入者胜（位置不变），新 id 追加
    assert [rule.id for rule in merged.domains.rules] == ["domain-unknown", "domain-blocklist"]
    unknown = merged.domains.rules[0]
    assert unknown.action == "confirm" and unknown.weight == 55
    assert merged.domains.rules[1].weight == 90


def test_import_union_keeps_local_rules_when_imported_section_omits_them() -> None:
    merged = parse_policy(
        import_section(BASE_POLICY, "domains", "classes:\n  code_hosting:\n  - gitlab.com\n",
                       merge="union")
    )
    assert [rule.id for rule in merged.domains.rules] == ["domain-unknown"]
    assert merged.domains.classes == {
        "known_ai_api": ["api.openai.com"],
        "code_hosting": ["gitlab.com"],
    }


def test_import_union_preserves_unspecified_nested_keys() -> None:
    """defaults/notifications：部分字段导入只覆盖给出的字段。"""
    merged = parse_policy(
        import_section(BASE_POLICY, "defaults", "fail_open: false\n", merge="union")
    )
    assert merged.defaults.fail_open is False
    assert merged.defaults.max_body_scan == 4096  # 本方独有键保留
    merged_notify = parse_policy(
        import_section(BASE_POLICY, "notifications", "min_action: block\n", merge="union")
    )
    assert merged_notify.notifications.min_action == "block"
    assert merged_notify.notifications.webhook.enabled is True
    assert merged_notify.notifications.webhook.url == "https://hook.example.test/ingest"


def test_import_replace_resets_omitted_fields_to_schema_defaults() -> None:
    merged = parse_policy(import_section(BASE_POLICY, "notifications", "min_action: block\n"))
    assert merged.notifications.min_action == "block"
    assert merged.notifications.webhook.enabled is False  # 整段替换=字段级出厂默认


def test_import_volume_list_section_union_by_id() -> None:
    merged = parse_policy(import_section(BASE_POLICY, "volume", VOLUME_PACK, merge="union"))
    assert [rule.id for rule in merged.volume] == ["huge-body", "giant-body"]
    assert merged.volume[0].match.body_size_gt == 1048576
    assert merged.volume[0].action == "confirm"
    assert merged.volume[1].match.body_size_gt == 10485760


BAD_IMPORTS = [
    "rules:\n- {id: x, match: {}, bogus: 1}\n",  # 未知字段（extra=forbid）
    "rules:\n- {id: x, match: {class: unknown}, action: deny}\n",  # 非法动作
    "rules:\n- {id: x, match: {host_regex: '[unclosed'}, action: alert}\n",  # 坏正则
    "rules:\n- {id: x, match: {class: unknown}, weight: 101}\n",  # weight 越界
    "- just\n- a\n- list\n",  # 映射段收到列表
    "rules: not-a-list\n",
    "{unclosed: [}\n",  # YAML 语法错误
    "",  # 空内容
    "\n---\n",  # 解析为空
]


@pytest.mark.parametrize("bad_yaml", BAD_IMPORTS)
def test_import_invalid_section_never_writes(tmp_path: Path, bad_yaml: str) -> None:
    """红线：导入不合法时抛错且既有策略文件一字不动、不留 .tmp 残片。"""
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(BASE_POLICY, encoding="utf-8")
    original = policy_file.read_text(encoding="utf-8")
    with pytest.raises(RulesHubError):
        import_section(BASE_POLICY, "domains", bad_yaml, output_path=policy_file)
    assert policy_file.read_text(encoding="utf-8") == original
    assert list(tmp_path.glob("*.tmp")) == []


def test_import_rejects_bad_current_yaml_and_bad_merge_mode(tmp_path: Path) -> None:
    out = tmp_path / "policy.yaml"
    with pytest.raises(RulesHubError, match="当前策略 YAML 不合法"):
        import_section("bogus_section: 1\n", "domains", DOMAINS_PACK, output_path=out)
    with pytest.raises(RulesHubError, match="未知合并模式"):
        import_section(BASE_POLICY, "domains", DOMAINS_PACK, merge="bogus")  # type: ignore[arg-type]
    assert not out.exists()


def test_import_success_with_output_path_writes_valid_policy(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(BASE_POLICY, encoding="utf-8")
    merged_text = import_section(
        BASE_POLICY, "domains", DOMAINS_PACK, merge="union", output_path=policy_file
    )
    assert policy_file.read_text(encoding="utf-8") == merged_text
    on_disk = parse_policy(policy_file.read_text(encoding="utf-8"))
    assert [rule.id for rule in on_disk.domains.rules] == ["domain-unknown", "domain-blocklist"]
    assert on_disk.mode == "dry-run"  # 重写后其余段完整保留


def test_import_of_scalar_section_mode() -> None:
    merged = parse_policy(import_section(BASE_POLICY, "mode", "enforce\n"))
    assert merged.mode == "enforce"
    assert [rule.id for rule in merged.domains.rules] == ["domain-unknown"]


# ------------------------------------------------------------------ gitleaks 转换


def test_convert_sample_one_maps_regex_entropy_allowlist_keywords() -> None:
    pack = convert_gitleaks_toml(TOML_SAMPLE)
    assert [rule.id for rule in pack.rules] == ["acme-token", "legacy-key"]
    assert pack.meta.skipped == []
    acme, legacy = pack.rules
    assert acme.pattern == r"\bacm_[A-Za-z0-9]{20}\b"
    assert acme.entropy == 0.0
    # 关键词统一转小写（本项目扫描器按行小写包含匹配）
    assert acme.keywords == ["acme_token", "acm_"]
    assert legacy.entropy == 3.5
    assert legacy.allowlist == ["DOC-SAMPLE"]
    # 全局 [allowlist] regexes → 包级 allowlist
    assert pack.allowlist == ["(?i)EXAMPLE", "0000-0000"]


def test_convert_sample_two_skips_unsupported_rules_with_reasons() -> None:
    pack = convert_gitleaks_toml(TOML_SAMPLE_SKIPS)
    assert [rule.id for rule in pack.rules] == ["acme-token"]
    assert pack.rules[0].description == "first"  # 重复 id 保留首条
    skipped = {item.id: item.reason for item in pack.meta.skipped}
    assert set(skipped) == {"no-regex-rule", "group-rule", "bad-regex-rule", "acme-token"}
    assert "缺少非空 regex" in skipped["no-regex-rule"]
    assert "secretGroup" in skipped["group-rule"]
    assert "无法在 Python 编译" in skipped["bad-regex-rule"]
    assert "重复 id" in skipped["acme-token"]


def test_convert_rejects_broken_toml() -> None:
    with pytest.raises(RulesHubError, match="TOML 解析失败"):
        convert_gitleaks_toml("not = [valid\n")


def test_to_secret_rules_maps_to_scanner_types() -> None:
    pack = convert_gitleaks_toml(TOML_SAMPLE)
    rules = to_secret_rules(pack)
    assert all(isinstance(rule, SecretRule) for rule in rules)
    acme = rules[0]
    assert acme.id == "acme-token"
    assert acme.keywords == ("acme_token", "acm_")
    assert acme.entropy == 0.0
    assert acme.pattern.search("token acm_ABCDEFGHIJKLMNOPQRST end") is not None
    assert rules[1].entropy == 3.5


# ------------------------------------------------------------------ pin 记录与同步


class FakeResponse:
    """假 HTTP 响应（status_code/content，与 httpx 语义对齐）。"""

    def __init__(self, status_code: int, content: bytes) -> None:
        self.status_code = status_code
        self.content = content


class FakeClient:
    """假 HTTP 客户端：记录调用、可注入响应或异常；绝不联网。"""

    def __init__(self, response: FakeResponse | Exception) -> None:
        self.response = response
        self.calls: list[str] = []
        self.closed = False

    def get(self, url: str) -> FakeResponse:
        self.calls.append(url)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response

    def close(self) -> None:
        self.closed = True


def test_sync_from_path_writes_pack_with_pin(tmp_path: Path) -> None:
    source = tmp_path / "gitleaks.toml"
    source.write_text(TOML_SAMPLE, encoding="utf-8")
    out = tmp_path / "packs" / "gitleaks-rules.yaml"

    def _fail_if_called() -> FakeClient:
        raise AssertionError("本地路径同步不得触碰网络客户端")

    result = sync_gitleaks(str(source), output_path=out, client_factory=_fail_if_called)
    assert result.kind == "path"
    assert result.source == str(source)
    assert result.sha256 == hashlib.sha256(source.read_bytes()).hexdigest()
    assert result.converted == 2
    assert result.skipped == []
    assert result.output_path == str(out)
    assert result.yaml_text == out.read_text(encoding="utf-8")
    # pin 写进包 meta，可从落盘文件读回
    pack = load_pack_file(out)
    assert pack.meta.source == str(source)
    assert pack.meta.sha256 == result.sha256
    assert pack.meta.rule_count == 2
    assert pack.meta.synced_at == result.synced_at
    assert pack.rules  # 非空


def test_sync_from_url_uses_injected_client_and_records_pin(tmp_path: Path) -> None:
    client = FakeClient(FakeResponse(200, TOML_SAMPLE.encode("utf-8")))
    url = "https://upstream.example.test/config/gitleaks.toml"
    out = tmp_path / "pack.yaml"
    result = sync_gitleaks(url, output_path=out, client_factory=lambda: client, now=None)
    assert client.calls == [url], "必须以原始 URL 调用注入客户端"
    assert client.closed is True
    assert result.kind == "url"
    assert result.sha256 == hashlib.sha256(TOML_SAMPLE.encode("utf-8")).hexdigest()
    assert result.converted == 2
    pack = load_pack(result.yaml_text)
    assert pack.meta.source == url
    assert pack.meta.sha256 == result.sha256


def test_sync_url_http_error_never_writes(tmp_path: Path) -> None:
    client = FakeClient(FakeResponse(404, b"nope"))
    out = tmp_path / "pack.yaml"
    with pytest.raises(RulesHubError, match="404"):
        sync_gitleaks("https://upstream.example.test/x.toml", output_path=out,
                      client_factory=lambda: client)
    assert client.closed is True
    assert not out.exists()
    assert list(tmp_path.glob("*.tmp")) == []


def test_sync_url_network_exception_never_writes(tmp_path: Path) -> None:
    client = FakeClient(RuntimeError("connection refused"))
    out = tmp_path / "pack.yaml"
    with pytest.raises(RulesHubError, match="connection refused"):
        sync_gitleaks("https://upstream.example.test/x.toml", output_path=out,
                      client_factory=lambda: client)
    assert not out.exists()


def test_sync_rejects_broken_toml_and_empty_conversion(tmp_path: Path) -> None:
    out = tmp_path / "pack.yaml"
    broken = tmp_path / "broken.toml"
    broken.write_text("rules = [not closed\n", encoding="utf-8")
    with pytest.raises(RulesHubError, match="TOML 解析失败"):
        sync_gitleaks(str(broken), output_path=out)
    empty = tmp_path / "empty.toml"
    empty.write_text('[[rules]]\nid = "group-rule"\nregex = "x"\nsecretGroup = 1\n',
                     encoding="utf-8")
    with pytest.raises(RulesHubError, match="空规则包"):
        sync_gitleaks(str(empty), output_path=out)
    assert not out.exists()
    assert list(tmp_path.glob("*.tmp")) == []


def test_sync_rejects_empty_source() -> None:
    with pytest.raises(RulesHubError, match="来源为空"):
        sync_gitleaks("   ")


def test_default_source_is_https_url() -> None:
    assert DEFAULT_GITLEAKS_SOURCE.startswith("https://")
    assert DEFAULT_GITLEAKS_SOURCE.endswith(".toml")


# ------------------------------------------------------------------ 规则包扫描


def _hand_pack() -> SecretsRulePack:
    """手工规则包：熵守卫 + 规则级 allowlist（避免 TOML 前缀匹配的熵边界干扰）。"""
    return SecretsRulePack(
        rules=[
            PackRule(id="hex-token", description="32 位大写十六进制令牌",
                     pattern=r"\b[A-Z0-9]{32}\b", entropy=3.0, allowlist=[r"^PREFIX"]),
        ]
    )


def test_scan_with_pack_hits_and_filters_by_entropy_and_allowlist() -> None:
    pack = _hand_pack()
    body = (
        "high = A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6\n"  # 高熵 → 命中
        "low = ABABABABABABABABABABABABABABABAB\n"  # 低熵（≈1 bit）→ 熵守卫拦下
        "ok = PREFIXA1B2C3D4E5F6G7H8I9J0K1L2M3N4\n"  # 命中白名单 ^PREFIX → 丢弃
    )
    result = scan_with_pack(body, pack)
    assert [hit.rule_id for hit in result.hits] == ["hex-token"]
    hit = result.hits[0]
    assert hit.evidence.startswith("A1B2****") and "A1B2C3D4" not in hit.evidence
    assert hit.line == 1


def test_scan_with_pack_end_to_end_from_toml_sample() -> None:
    pack = convert_gitleaks_toml(TOML_SAMPLE)
    body = (
        'ACME_TOKEN="acm_ABCDEFGHIJKLMNOPQRST"\n'  # 命中 acme-token
        'ACME_TOKEN="acm_EXAMPLEklmnopqrstuvwx"\n'  # 全局 allowlist (?i)EXAMPLE → 丢弃
    )
    result = scan_with_pack(body, pack)
    assert [hit.rule_id for hit in result.hits] == ["acme-token"]
    assert result.metrics["hits"] == 1.0


def test_scan_with_pack_empty_body_and_empty_pack() -> None:
    assert scan_with_pack("", _hand_pack()).hit_count == 0
    assert scan_with_pack(None, _hand_pack()).hit_count == 0
    assert scan_with_pack("A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6", SecretsRulePack()).hit_count == 0


def test_scan_with_pack_respects_max_bytes() -> None:
    body = "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6"
    assert scan_with_pack(body, _hand_pack(), max_bytes=8).hit_count == 0
    assert scan_with_pack(body, _hand_pack(), max_bytes=len(body)).hit_count == 1


# ------------------------------------------------------------------ 规则包读取校验


def test_load_pack_rejects_bad_pattern_and_unknown_fields() -> None:
    with pytest.raises(RulesHubError, match="规则包校验失败"):
        load_pack("rules:\n- id: x\n  pattern: '['\n")
    with pytest.raises(RulesHubError, match="规则包校验失败"):
        load_pack("rules:\n- id: x\n  pattern: 'ok'\n  bogus_field: 1\n")
    with pytest.raises(RulesHubError, match="顶层必须是映射"):
        load_pack("- just\n- a\n- list\n")
    with pytest.raises(RulesHubError, match="YAML 解析失败"):
        load_pack("{unclosed: [}\n")


def test_load_pack_file_missing(tmp_path: Path) -> None:
    with pytest.raises(RulesHubError, match="规则包读取失败"):
        load_pack_file(tmp_path / "nope.yaml")
