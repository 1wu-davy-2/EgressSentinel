"""规则市场（06 文档波次一 W7）：策略段落导出/导入 + gitleaks 上游规则同步。

模块结构：
- ``sections``：``export_section``（策略文档 → 单段 YAML 文本）/ ``import_section``
  （合并单段进当前策略，**先 pydantic 校验后落盘，不合法绝不写**）+ replace/union
  两种合并语义；
- ``gitleaks``：``sync_gitleaks``（URL/路径来源 → TOML → 内置 secrets 规则 YAML 包，
  附来源与 sha256 pin）+ 规则包读写与 ``scan_with_pack``（含 allowlist 语义的扫描）。

红线（06 文档 W7）：导入三关校验（导入段 → 合并结果 → 完整策略）全部通过才允许
落盘；gitleaks 同步网络全注入（默认工厂为 httpx ``trust_env=False`` 直连，单测注入
假客户端绝不真实联网）；转换失败/空结果不落盘，不支持的特性如实记 ``skipped``。
"""

from aaa.ruleshub.gitleaks import (
    DEFAULT_GITLEAKS_SOURCE,
    DEFAULT_SYNC_TIMEOUT_SECONDS,
    FetchClient,
    FetchClientFactory,
    GitleaksSyncResult,
    PackMeta,
    PackRule,
    SecretsRulePack,
    SkippedRule,
    convert_gitleaks_toml,
    default_fetch_client_factory,
    dump_pack,
    load_pack,
    load_pack_file,
    scan_with_pack,
    sync_gitleaks,
    to_secret_rules,
)
from aaa.ruleshub.sections import (
    MergeMode,
    RulesHubError,
    atomic_write_text,
    export_section,
    import_section,
    shareable_sections,
)

__all__ = [
    "DEFAULT_GITLEAKS_SOURCE",
    "DEFAULT_SYNC_TIMEOUT_SECONDS",
    "FetchClient",
    "FetchClientFactory",
    "GitleaksSyncResult",
    "MergeMode",
    "PackMeta",
    "PackRule",
    "RulesHubError",
    "SecretsRulePack",
    "SkippedRule",
    "atomic_write_text",
    "convert_gitleaks_toml",
    "default_fetch_client_factory",
    "dump_pack",
    "export_section",
    "import_section",
    "load_pack",
    "load_pack_file",
    "scan_with_pack",
    "shareable_sections",
    "sync_gitleaks",
    "to_secret_rules",
]
