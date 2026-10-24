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

from aaa.notify.model import NotifyConfig, disabled_notify_config

#: 四级动作（02 文档 D4：allow < alert < confirm < block）
Action = Literal["allow", "alert", "confirm", "block"]

#: 策略运行模式（03 文档 §0：默认 dry-run 只告警不阻断）
PolicyMode = Literal["dry-run", "enforce"]

#: 内置内容扫描器名单
SCANNER_NAMES = ("secrets", "pii", "code_leak")

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
    scanner: Literal["secrets", "pii", "code_leak"] | None = None
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
    scanners: list[Literal["secrets", "pii", "code_leak"]] = Field(default_factory=list)
    rules: list[ContentRule] = Field(default_factory=list)


class PolicyDocument(_Strict):
    """策略文档根模型（02 文档 §5 + 04 文档 §2 通知段）。"""

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
