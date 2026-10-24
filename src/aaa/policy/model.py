"""策略 schema 的 pydantic 严格化（02 文档 §5，03 文档 T3.1）。

- 所有模型 ``extra="forbid"``：lint 能抓到拼写错误（如 ``dryrun``、未知字段）；
- 动作四级 ``allow < alert < confirm < block``（02 文档 D4）；
- ``policy_version``：对 canonical JSON 的 sha256 前 4 位，落事件（02 文档 §6 示例 "7f3a"）。
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aaa.hub.model import HubConfig
from aaa.judge.llm import JudgeConfig
from aaa.notify.model import NotifyConfig, disabled_notify_config

#: 四级动作（02 文档 D4：allow < alert < confirm < block）
Action = Literal["allow", "alert", "confirm", "block"]

#: 策略运行模式（03 文档 §0：默认 dry-run 只告警不阻断）
PolicyMode = Literal["dry-run", "enforce"]

#: 内置内容扫描器名单（v0.2.0 增 repo_fingerprint：仓库指纹比对，05 文档波次二 §2）
SCANNER_NAMES = ("secrets", "pii", "code_leak", "repo_fingerprint")

#: 响应侧规则的匹配档位（05 文档波次二 §1）：all=任何注入特征命中；high=仅高危命中
ResponsePatterns = Literal["all", "high"]

#: ``policy.judge`` 段直接复用 W3 的 :class:`JudgeConfig`（extra=forbid、默认全关，
#: 字段与 05 文档 W3 一一对应：enabled/api_base/model/timeout/max_events_per_day）。
JudgeSection = JudgeConfig

_ACTION_ORDER: dict[str, int] = {"allow": 0, "alert": 1, "confirm": 2, "block": 3}


def action_rank(action: str) -> int:
    """动作严重级（用于多维命中取最高级）。"""
    return _ACTION_ORDER[action]


class _Strict(BaseModel):
    """严格模型基类：禁止未知字段。"""

    model_config = ConfigDict(extra="forbid")


class Defaults(_Strict):
    """``defaults`` 段（02 文档 D5：失败模式默认 fail-open）。"""

    fail_open: bool = True
    max_body_scan: int = Field(default=262144, ge=1)


class DomainMatch(_Strict):
    """域名规则匹配条件：分类 或 host 正则。"""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    cls: str | None = Field(default=None, alias="class")
    """端点分类：known_ai_api / code_hosting / unknown / 其他自定义类。"""
    host_regex: str | None = None

    @field_validator("host_regex")
    @classmethod
    def _valid_regex(cls, value: str | None) -> str | None:
        if value is not None:
            re.compile(value)
        return value


class DomainRule(_Strict):
    id: str
    match: DomainMatch
    action: Action = "alert"
    weight: int = Field(default=0, ge=0, le=100)


class ProcessProfile(_Strict):
    """进程画像：按 exe/进程名正则分类（agent_cli / browser / ...）。"""

    exe_regex: str

    @field_validator("exe_regex")
    @classmethod
    def _valid_regex(cls, value: str) -> str:
        re.compile(value)
        return value


class ProcessMatch(_Strict):
    """进程规则匹配条件：画像（正向/反向）+ 目标分类。"""

    profile: str | None = None
    profile_not: str | None = None
    dest_class: str | None = None


class ProcessRule(_Strict):
    id: str
    match: ProcessMatch
    action: Action = "alert"
    weight: int = Field(default=0, ge=0, le=100)


class ContentMatch(_Strict):
    """内容规则匹配条件：扫描器命中数 / 体量 / 代码相似度阈值。"""

    hits_gt: int | None = Field(default=None, ge=0)
    body_size_gt: int | None = Field(default=None, ge=0)
    code_likeness_gt: float | None = Field(default=None, ge=0.0, le=1.0)


class ContentRule(_Strict):
    id: str
    scanner: Literal["secrets", "pii", "code_leak", "repo_fingerprint"] | None = None
    match: ContentMatch = Field(default_factory=ContentMatch)
    action: Action = "alert"
    weight: int = Field(default=0, ge=0, le=100)


class VolumeMatch(_Strict):
    body_size_gt: int = Field(ge=0)


class VolumeRule(_Strict):
    id: str
    match: VolumeMatch
    action: Action = "alert"
    weight: int = Field(default=0, ge=0, le=100)


class TimeWindowMatch(_Strict):
    requests_gt: int = Field(ge=0)
    window_seconds: int = Field(default=60, ge=1)


class TimeWindowRule(_Strict):
    id: str
    match: TimeWindowMatch
    action: Action = "alert"
    weight: int = Field(default=0, ge=0, le=100)


class DomainsSection(_Strict):
    classes: dict[str, list[str]] = Field(default_factory=dict)
    rules: list[DomainRule] = Field(default_factory=list)


class ProcessesSection(_Strict):
    profiles: dict[str, ProcessProfile] = Field(default_factory=dict)
    rules: list[ProcessRule] = Field(default_factory=list)


class ContentSection(_Strict):
    scanners: list[Literal["secrets", "pii", "code_leak", "repo_fingerprint"]] = Field(
        default_factory=list
    )
    rules: list[ContentRule] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# v0.2.0 安全深化新段（05 文档波次二 §1）：全部默认关/空——缺省段落行为与
# v0.1.x 完全一致（老策略文件无这些段也合法，升级零惊扰）。
# ---------------------------------------------------------------------------


class FingerprintSection(_Strict):
    """``policy.fingerprint`` 段：本地仓库指纹比对（05 文档 W1/波次二）。

    - ``enabled``：默认关闭——只有显式开启后才会把请求体与本地代码库切片比对；
    - ``repos``：仓库工作区路径清单（``aaa fingerprint build --repo PATH`` 逐个
      建库时缺省读取）；建库是显式 CLI 动作，``run`` 绝不自动扫描仓库；
    - ``min_hits``：命中多少片算一次有效命中（默认 1，05 文档"命中 ≥1 片"）。
    """

    enabled: bool = False
    repos: list[str] = Field(default_factory=list)
    min_hits: int = Field(default=1, ge=1)


class ResponseRule(_Strict):
    """一条响应侧标注规则（05 文档波次二 §1）。

    - ``patterns``：``all``（任何注入特征命中即标注）| ``high``（仅 high 严重度
      ——指令覆盖/隐藏载体——命中才标注）；
    - ``action``：恒为 ``alert``——响应侧只做 alert 级标注、绝不阻断响应
      （05 文档波次二 §3 红线，在 schema 层固化：写 block/confirm 直接校验失败）。
    """

    id: str
    patterns: ResponsePatterns = "all"
    action: Literal["alert"] = "alert"


class ResponseSection(_Strict):
    """``policy.response`` 段：响应侧注入特征标注规则清单（空 = 功能关闭）。"""

    rules: list[ResponseRule] = Field(default_factory=list)


class EncryptSection(_Strict):
    """``policy.encrypt`` 段：证据静态加密开关（05 文档 W5/波次二）。

    默认关闭（向后兼容）：关闭时写入明文，读取仍透明兼容既有密文（密钥来源
    解析见 ``store.crypto.CryptoEngine``）；开关在 ``aaa run`` 启动时生效，
    运行中热更新不改变密钥状态（decisions.md D-2026-10-24-39）。
    """

    enabled: bool = False


class SamplingSection(_Strict):
    """``policy.sampling`` 段：内容扫描采样（06 文档 W4，decisions D-2026-10-25-46）。

    - ``enabled``：**默认关**——老策略文件（无本段）升级零惊扰，保持 v0.2.x 的
      全量扫描行为；出厂 ``default.yaml`` 也显式写 ``enabled: false``（06 文档
      波次二第 5 条「sampling 段默认关」）。与管线层出厂 ``SamplingConfig``
      （enabled=True，head_bytes==max_body_scan 出厂值下零行为差异）是**两层
      独立默认**（D-46 第 3 条）；
    - ``head_bytes``：触发采样后非豁免扫描器只扫头部字节数；生效截断 =
      ``min(max_body_scan, head_bytes)``——采样只会少扫、绝不比既有行为多扫；
      secrets 扫描器豁免（``SAMPLING_EXEMPT_SCANNERS``，secrets 行为不回退）。
    """

    enabled: bool = False
    head_bytes: int = Field(default=262144, ge=1)


class PolicyDocument(_Strict):
    """策略文档根模型（02 文档 §5 + 04 文档 §2 通知段 + 05 文档安全深化段）。"""

    version: int = 1
    mode: PolicyMode = "dry-run"
    defaults: Defaults = Field(default_factory=Defaults)
    domains: DomainsSection = Field(default_factory=DomainsSection)
    processes: ProcessesSection = Field(default_factory=ProcessesSection)
    content: ContentSection = Field(default_factory=ContentSection)
    volume: list[VolumeRule] = Field(default_factory=list)
    time_window: list[TimeWindowRule] = Field(default_factory=list)
    notifications: NotifyConfig = Field(default_factory=disabled_notify_config)
    """通知配置（04 文档 §2）。缺省段落=全关（老策略文件兼容，04 文档 §3 T1）；
    段落存在但省略字段时按 ``NotifyConfig`` 字段级出厂默认（toast 开、webhook/email 关）。"""
    fingerprint: FingerprintSection = Field(default_factory=FingerprintSection)
    """仓库指纹段（05 文档波次二 §1）。缺省=关闭（不建库、不比对）。"""
    judge: JudgeSection = Field(default_factory=lambda: JudgeSection())
    """LLM 辅助判定段（05 文档 W3 ``JudgeConfig`` 直接复用）。缺省=关闭（零外发）。"""
    response: ResponseSection = Field(default_factory=ResponseSection)
    """响应侧标注段（05 文档波次二 §1）。缺省 rules=[] = 不扫描响应体。"""
    encrypt: EncryptSection = Field(default_factory=EncryptSection)
    """证据加密段（05 文档 W5）。缺省=关闭（写明文，读透明兼容密文）。"""
    sampling: SamplingSection = Field(default_factory=SamplingSection)
    """内容扫描采样段（06 文档 W4）。缺省=关闭（与 v0.2.x 全量扫描行为一致）；
    ``aaa run`` 接线为 ``AuditPipeline(sampling=...)``（decisions D-46）。"""
    hub: HubConfig = Field(default_factory=HubConfig)
    """多机聚合段（06 文档 W8，模型复用 ``hub.model.HubConfig``）。缺省=关闭
    （零外发）；env 覆盖 ``AAA_HUB_URL/AAA_HUB_TOKEN``（D-47 收窄版试用意图）。"""

    # ------------------------------------------------------------- 派生工具

    def classify_host(self, host: str) -> str:
        """域名 → 分类：按 classes 精确/后缀匹配；都不中为 ``unknown``。"""
        host = (host or "").lower().rstrip(".")
        for cls_name, hosts in self.domains.classes.items():
            for entry in hosts:
                entry = entry.lower().rstrip(".")
                if host == entry or host.endswith("." + entry):
                    return cls_name
        return "unknown"

    def profile_of(self, name: str | None, exe: str | None) -> str:
        """进程名/exe → 画像（processes.profiles 顺序匹配，先定义先命中）。"""
        for profile_name, profile in self.processes.profiles.items():
            pattern = re.compile(profile.exe_regex)
            for candidate in (exe, name):
                if candidate and pattern.search(candidate):
                    return profile_name
        return "other"

    @property
    def policy_version(self) -> str:
        """canonical JSON 的 sha256 前 4 位（事件 ``policy_version``，02 文档 §6）。"""
        canonical = json.dumps(
            self.model_dump(mode="json", by_alias=True),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:4]
