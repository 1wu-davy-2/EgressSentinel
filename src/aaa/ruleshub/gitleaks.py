"""gitleaks 上游规则同步（06 文档波次一 W7）。

:func:`sync_gitleaks` 下载（URL）或读取（本地路径）gitleaks 规则 TOML，转换为
本项目 secrets 扫描器的规则 YAML 包（``SecretsRulePack``：正则 + 熵 + allowlist
映射），并在包 ``meta`` 里附**来源与 sha256 pin**（锁上游版本、可校验是否被篡改）。
gitleaks 为 MIT 许可（02 文档 §7 合规），本模块只做格式转换、不改其规则语义。

红线（06 文档 W7）：
1. **网络全注入**：URL 下载走 :class:`FetchClient` 协议，默认工厂才是
   httpx（``trust_env=False`` 直连——本工具自身是系统代理，防回环采集，与
   judge/webhook 同一约定）；单测注入假客户端，绝不真实联网；
2. **不合法绝不写**：TOML 解析/转换失败、转换结果为空（全部规则被跳过）时抛
   :class:`RulesHubError`，``output_path`` 一个字节都不落盘；
3. **不支持的特性如实跳过**：``secretGroup``（本引擎按整段匹配，熵守卫语义会
   失真）、Python 无法编译的 Go 正则、缺 id/regex、重复 id（保留首条）——全部
   记入 ``meta.skipped``（id + 原因），绝不静默丢弃也绝不带病转换。

语义映射（gitleaks → 本项目）：``regex``→``pattern``；``entropy``→``entropy``
（对整段匹配生效）；``keywords``→``keywords``（统一转小写——本项目扫描器按行
小写包含匹配，见 ``scanners/secrets.py``）；``[allowlist]``/``[[rules.allowlists]]``
的 ``regexes``→包级/规则级 allowlist（``paths``/``commits`` 等文件维度条目对本
引擎无意义，忽略）。allowlist 应用形态见 :func:`scan_with_pack`。
"""

from __future__ import annotations

import hashlib
import math
import re
import tomllib
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from aaa.ruleshub.sections import RulesHubError, atomic_write_text
from aaa.scanners.base import ScanHit, ScanResult
from aaa.scanners.secrets import SCANNER_NAME, SecretRule, iter_secret_spans, mask_secret

#: gitleaks 官方规则上游（MIT 许可）；``aaa gitleaks sync`` 缺省来源，可传任意
#: URL 或本地路径覆盖（06 文档波次二第 1 条接线时使用）
DEFAULT_GITLEAKS_SOURCE = (
    "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml"
)

#: URL 下载默认超时秒数（与 webhook/judge 同量级的保守值）
DEFAULT_SYNC_TIMEOUT_SECONDS = 30.0


class _Strict(BaseModel):
    """严格模型基类：禁止未知字段（与策略 schema 同约定，规则包也能抓拼写错误）。"""

    model_config = ConfigDict(extra="forbid")


class SkippedRule(_Strict):
    """一条被跳过的上游规则（id + 原因；pin 记录的一部分，绝不静默丢）。"""

    id: str
    reason: str


class PackMeta(_Strict):
    """规则包元数据：来源 + sha256 pin + 同步时间 + 转换统计（06 文档 W7）。"""

    source: str = ""
    """来源（URL 或本地路径）；转换产物（未同步）为空串。"""
    sha256: str = ""
    """来源 TOML 原始字节的 sha256（hex 小写）——pin 记录，锁上游版本。"""
    synced_at: str = ""
    """同步时间（ISO 8601，UTC）。"""
    rule_count: int = Field(default=0, ge=0)
    """成功转换的规则数（完整性校验用，与 ``rules`` 长度一致）。"""
    skipped: list[SkippedRule] = Field(default_factory=list)
    """被跳过的上游规则清单（id + 原因）。"""


class PackRule(_Strict):
    """包内一条密钥规则（与 ``scanners.secrets.SecretRule`` 的可序列化形态对应）。"""

    id: str
    description: str = ""
    pattern: str
    """正则（Python 语法；构建即编译校验，坏正则进不了包）。"""
    entropy: float = Field(default=0.0, ge=0.0)
    """>0 时要求命中串香农熵不低于该值（bit/字符）；0=不设熵守卫。"""
    keywords: list[str] = Field(default_factory=list)
    """关键词守卫（已转小写）：所在行包含任一关键词才尝试匹配。"""
    allowlist: list[str] = Field(default_factory=list)
    """规则级白名单正则（gitleaks ``[[rules.allowlists]]`` 的 regexes 映射）。"""

    @field_validator("pattern")
    @classmethod
    def _pattern_compiles(cls, value: str) -> str:
        try:
            re.compile(value)
        except re.error as exc:  # pydantic 只包装 ValueError，re.error 须显式转译
            raise ValueError(f"正则无法编译：{exc}") from exc
        return value

    @field_validator("allowlist")
    @classmethod
    def _allowlist_compiles(cls, value: list[str]) -> list[str]:
        for pattern in value:
            try:
                re.compile(pattern)
            except re.error as exc:  # pydantic 只包装 ValueError，re.error 须显式转译
                raise ValueError(f"白名单正则无法编译：{exc}") from exc
        return value


class SecretsRulePack(_Strict):
    """gitleaks 同步规则包（YAML 序列化形态即落盘格式，见 :func:`dump_pack`）。"""

    meta: PackMeta = Field(default_factory=PackMeta)
    allowlist: list[str] = Field(default_factory=list)
    """包级白名单正则（gitleaks 全局 ``[allowlist]`` 的 regexes 映射），作用于全部规则。"""
    rules: list[PackRule] = Field(default_factory=list)


# ---------------------------------------------------------------- 网络注入


class FetchClient(Protocol):
    """HTTP GET 客户端最小协议（生产为 :class:`httpx.Client`，测试注入假客户端）。"""

    def get(self, url: str) -> Any:
        """GET 请求，返回带 ``status_code`` / ``content`` 的响应对象。"""
        ...

    def close(self) -> None:
        """释放底层连接（httpx.Client 语义）。"""
        ...


#: 客户端工厂注入点（06 文档 W7：网络全注入，测试给假客户端）
FetchClientFactory = Callable[[], FetchClient]


def default_fetch_client_factory(timeout: float = DEFAULT_SYNC_TIMEOUT_SECONDS) -> Any:
    """生产客户端工厂：**trust_env=False 直连**（红线 1：本工具自身是系统代理，防回环）。"""
    import httpx

    return httpx.Client(trust_env=False, timeout=timeout, follow_redirects=True)


def _utc_now() -> datetime:
    """默认时钟：UTC 当前时间（测试注入）。"""
    return datetime.now(UTC)


# ---------------------------------------------------------------- TOML 转换


def _is_positive_number(value: Any) -> bool:
    """gitleaks 数值字段是否为可用的正数（bool/NaN/Inf/负数都算不可用）。"""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return math.isfinite(value) and value > 0


def _compile_checked(pattern: str) -> str | None:
    """Python 可编译的正则原样返回；否则 None（Go 正则可能有 Python 不支持的语法）。"""
    try:
        re.compile(pattern)
    except re.error:
        return None
    return pattern


def _collect_regexes(blocks: Any) -> list[str]:
    """从 allowlist 条目（单表或表数组）提取 ``regexes``，丢弃编译不过的条目。

    丢弃坏 allowlist 是保守方向：allowlist 只会抑制命中，丢弃它至多多报、绝不漏报。
    """
    if isinstance(blocks, dict):
        blocks = [blocks]
    if not isinstance(blocks, list):
        return []
    result: list[str] = []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        regexes = block.get("regexes")
        if not isinstance(regexes, list):
            continue
        for pattern in regexes:
            if isinstance(pattern, str) and pattern.strip() and _compile_checked(pattern):
                result.append(pattern)
    return result


def convert_gitleaks_toml(raw_toml: str | bytes) -> SecretsRulePack:
    """gitleaks 规则 TOML → 规则包（meta 仅含 skipped/rule_count，来源 pin 由同步填）。

    映射与跳过语义见模块 docstring；TOML 解析失败抛 :class:`RulesHubError`。
    """
    if isinstance(raw_toml, bytes):
        try:
            raw_toml = raw_toml.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RulesHubError(f"gitleaks TOML 不是 UTF-8 编码：{exc}") from exc
    try:
        data = tomllib.loads(raw_toml)
    except tomllib.TOMLDecodeError as exc:
        raise RulesHubError(f"TOML 解析失败：{exc}") from exc
    if not isinstance(data, dict):  # tomllib 顶层必为表；防御式兜底
        raise RulesHubError("TOML 顶层必须是表")

    allowlist = _collect_regexes(data.get("allowlist"))
    allowlist += _collect_regexes(data.get("allowlists"))  # 兼容部分配置的复数键
    raw_rules = data.get("rules")
    entries: list[Any] = raw_rules if isinstance(raw_rules, list) else []
    skipped: list[SkippedRule] = []
    if raw_rules is not None and not isinstance(raw_rules, list):
        skipped.append(SkippedRule(id="<rules>", reason="[[rules]] 不是数组，已整体忽略"))

    rules: list[PackRule] = []
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        label = f"<rules[{index}]>"
        if not isinstance(entry, dict):
            skipped.append(SkippedRule(id=label, reason="规则条目不是映射（TOML 表）"))
            continue
        rule_id = entry.get("id")
        if not isinstance(rule_id, str) or not rule_id.strip():
            skipped.append(SkippedRule(id=label, reason="缺少非空 id"))
            continue
        rule_id = rule_id.strip()
        regex = entry.get("regex")
        if not isinstance(regex, str) or not regex.strip():
            skipped.append(SkippedRule(id=rule_id, reason="缺少非空 regex"))
            continue
        secret_group = entry.get("secretGroup")
        if (
            isinstance(secret_group, int)
            and not isinstance(secret_group, bool)
            and secret_group > 0
        ):
            skipped.append(
                SkippedRule(
                    id=rule_id,
                    reason="secretGroup 无法映射（本引擎按整段匹配，熵守卫语义会失真）",
                )
            )
            continue
        if _compile_checked(regex) is None:
            skipped.append(
                SkippedRule(id=rule_id, reason="regex 无法在 Python 编译（gitleaks 为 Go 正则）")
            )
            continue
        if rule_id in seen:
            skipped.append(SkippedRule(id=rule_id, reason="重复 id，保留首条"))
            continue
        seen.add(rule_id)
        description = entry.get("description")
        keywords = [
            keyword.lower()
            for keyword in entry.get("keywords", [])
            if isinstance(keyword, str) and keyword
        ]
        entropy = entry.get("entropy")
        rules.append(
            PackRule(
                id=rule_id,
                description=description if isinstance(description, str) else rule_id,
                pattern=regex,
                entropy=entropy if _is_positive_number(entropy) else 0.0,
                keywords=keywords,
                allowlist=_collect_regexes(entry.get("allowlists")),
            )
        )
    return SecretsRulePack(
        meta=PackMeta(rule_count=len(rules), skipped=skipped),
        allowlist=allowlist,
        rules=rules,
    )


# ---------------------------------------------------------------- 同步


class GitleaksSyncResult(BaseModel):
    """一次同步的结果（pin 记录同时写进规则包 ``meta``，此处是便捷回执）。"""

    model_config = ConfigDict(extra="forbid")

    source: str
    """来源（URL 或本地路径）。"""
    kind: Literal["url", "path"]
    """来源类型。"""
    sha256: str
    """来源 TOML 原始字节的 sha256（hex 小写）——pin。"""
    synced_at: str
    """同步时间（ISO 8601，UTC）。"""
    converted: int
    """成功转换的规则数。"""
    skipped: list[SkippedRule] = Field(default_factory=list)
    """被跳过的规则（id + 原因）。"""
    output_path: str | None = None
    """实际落盘路径（未落盘为 None）。"""
    yaml_text: str
    """规则包 YAML 全文（与落盘内容一致）。"""


def _fetch_url(url: str, factory: FetchClientFactory) -> bytes:
    """经注入客户端下载字节；HTTP 错误/异常/缺内容都收敛为 :class:`RulesHubError`。"""
    client = factory()
    try:
        try:
            response = client.get(url)
        except RulesHubError:
            raise
        except Exception as exc:  # noqa: BLE001 - 网络层任意异常都收敛为同步失败
            raise RulesHubError(f"下载 gitleaks 规则失败（{type(exc).__name__}）：{exc}") from exc
    finally:
        close = getattr(client, "close", None)
        if callable(close):
            close()
    status = getattr(response, "status_code", None)
    if not isinstance(status, int) or not (200 <= status < 300):
        raise RulesHubError(f"下载 gitleaks 规则失败：HTTP {status!r}（{url}）")
    content = getattr(response, "content", None)
    if not isinstance(content, (bytes, bytearray)):
        raise RulesHubError("下载响应缺少二进制内容（content）")
    return bytes(content)


def _read_source_path(source: str) -> bytes:
    """读取本地 TOML 文件字节；IO 失败收敛为 :class:`RulesHubError`。"""
    path = Path(source)
    try:
        return path.read_bytes()
    except OSError as exc:
        raise RulesHubError(f"读取 gitleaks 规则文件失败 {path}：{exc}") from exc


def sync_gitleaks(
    source: str,
    *,
    output_path: str | Path | None = None,
    client_factory: FetchClientFactory | None = None,
    now: Callable[[], datetime] | None = None,
) -> GitleaksSyncResult:
    """同步 gitleaks 上游规则并转换为内置 secrets 规则 YAML 包（附来源与 sha256 pin）。

    - ``source``：``http(s)://`` 开头走注入的 HTTP 客户端下载（红线 1），否则按
      本地文件路径读取；本地路径**不触碰网络**（连客户端工厂都不调用）；
    - ``output_path``：规则包 YAML 落盘路径——仅在 TOML 解析、转换成功且规则非空
      后才原子写入（红线 2）；
    - ``client_factory``/``now``：网络与时钟注入点（测试用）。

    任何失败抛 :class:`RulesHubError`，``output_path`` 一字不落。
    """
    if not source or not source.strip():
        raise RulesHubError("同步来源为空")
    source = source.strip()
    is_url = source.startswith(("http://", "https://"))
    if is_url:
        raw = _fetch_url(source, client_factory or default_fetch_client_factory)
        kind: Literal["url", "path"] = "url"
    else:
        raw = _read_source_path(source)
        kind = "path"
    digest = hashlib.sha256(raw).hexdigest()
    pack = convert_gitleaks_toml(raw)
    if not pack.rules:
        detail = "；".join(f"{item.id}: {item.reason}" for item in pack.meta.skipped) or "无规则"
        raise RulesHubError(f"未转换出任何规则，拒绝生成空规则包（{detail}）")
    synced_at = (now or _utc_now)().isoformat(timespec="seconds")
    final_pack = SecretsRulePack(
        meta=PackMeta(
            source=source,
            sha256=digest,
            synced_at=synced_at,
            rule_count=len(pack.rules),
            skipped=pack.meta.skipped,
        ),
        allowlist=pack.allowlist,
        rules=pack.rules,
    )
    yaml_text = dump_pack(final_pack)
    written: str | None = None
    if output_path is not None:
        atomic_write_text(output_path, yaml_text)
        written = str(output_path)
    return GitleaksSyncResult(
        source=source,
        kind=kind,
        sha256=digest,
        synced_at=synced_at,
        converted=len(pack.rules),
        skipped=pack.meta.skipped,
        output_path=written,
        yaml_text=yaml_text,
    )


# ---------------------------------------------------------------- 包读写与扫描


def dump_pack(pack: SecretsRulePack) -> str:
    """规则包 → YAML 文本（meta pin 在前，规则在后；注释级可读）。"""
    return yaml.safe_dump(
        pack.model_dump(mode="json"), allow_unicode=True, sort_keys=False, width=1000
    )


def load_pack(raw: str | bytes) -> SecretsRulePack:
    """规则包 YAML 文本 → ``SecretsRulePack``（结构/正则全部校验，失败抛错）。"""
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise RulesHubError(f"规则包 YAML 解析失败：{exc}") from exc
    if not isinstance(data, dict):
        raise RulesHubError("规则包顶层必须是映射（meta / allowlist / rules）")
    try:
        return SecretsRulePack.model_validate(data)
    except ValidationError as exc:
        raise RulesHubError(f"规则包校验失败：{exc}") from exc


def load_pack_file(path: str | Path) -> SecretsRulePack:
    """从文件读取规则包（IO/解析/校验失败抛 :class:`RulesHubError`）。"""
    target = Path(path)
    try:
        raw = target.read_text(encoding="utf-8")
    except OSError as exc:
        raise RulesHubError(f"规则包读取失败 {target}：{exc}") from exc
    return load_pack(raw)


def to_secret_rules(pack: SecretsRulePack) -> tuple[SecretRule, ...]:
    """规则包 → ``scanners.secrets.SecretRule`` 元组（模式编译、关键词守卫、熵映射）。"""
    return tuple(
        SecretRule(
            id=rule.id,
            description=rule.description or rule.id,
            pattern=re.compile(rule.pattern),
            entropy=rule.entropy,
            keywords=tuple(rule.keywords),
        )
        for rule in pack.rules
    )


def scan_with_pack(
    body: bytes | str | None,
    pack: SecretsRulePack,
    *,
    max_bytes: int | None = None,
) -> ScanResult:
    """用同步规则包扫描文本：内置匹配核心 + **包级/规则级 allowlist** 过滤。

    复用 ``scanners.secrets.iter_secret_spans`` 的匹配核心（关键词守卫 + 内置
    allowlist + 熵阈值），在其上追加 gitleaks 映射来的 allowlist（搜索语义匹配
    命中片段，片段被白名单正则命中即丢弃）——不改 ``scanners/secrets.py`` 即补上
    上游 allowlist 语义。输出与 ``scan_secrets`` 同构（evidence 打码）。
    """
    rules = to_secret_rules(pack)
    if not body or not rules:
        return ScanResult(scanner=SCANNER_NAME)
    text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body
    if max_bytes is not None and len(text) > max_bytes:
        text = text[:max_bytes]
    global_allow = [re.compile(pattern) for pattern in pack.allowlist]
    per_rule: dict[str, list[re.Pattern[str]]] = {
        rule.id: [re.compile(pattern) for pattern in rule.allowlist]
        for rule in pack.rules
        if rule.allowlist
    }
    hits: list[ScanHit] = []
    seen: set[tuple[str, int]] = set()
    for rule, lineno, start, end in iter_secret_spans(text, rules=rules):
        if (rule.id, lineno) in seen:
            continue
        secret = text[start:end]
        if any(pattern.search(secret) for pattern in global_allow):
            continue
        if any(pattern.search(secret) for pattern in per_rule.get(rule.id, ())):
            continue
        seen.add((rule.id, lineno))
        hits.append(
            ScanHit(
                scanner=SCANNER_NAME,
                rule_id=rule.id,
                evidence=mask_secret(secret.strip()),
                line=lineno,
                detail=rule.description,
            )
        )
    metrics: dict[str, float] = {"hits": float(len(hits))}
    return ScanResult(scanner=SCANNER_NAME, hits=tuple(hits), metrics=metrics)
