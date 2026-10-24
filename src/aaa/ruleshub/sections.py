"""策略段落导出/导入（06 文档波次一 W7「规则市场」）。

- :func:`export_section`：策略文档 → 单段 YAML 文本（即规则包分享格式，可供
  ``aaa rules export <section>`` 落盘分发）；
- :func:`import_section`：当前策略 YAML + 单段 YAML → 合并后完整策略 YAML，
  可选 ``output_path`` 校验通过后原子落盘；
- 合并语义 ``merge``：``replace``（整段替换）| ``union``（按条目合并，详见
  :func:`_union_value`——06 文档只给了模式名，逐字段语义见 decisions.md 记录）。

红线（06 文档 W7）：**导入先 pydantic 校验、后落盘，不合法绝不写**。校验三关：
导入段校验 → 合并结果校验 → 完整策略校验，全部通过才允许写文件；任何一步失败
抛 :class:`RulesHubError`，且 ``output_path`` 的既有内容一字不动（原子写
tmp + replace，失败清理临时文件）。

边界声明：本模块不隐式触碰文件系统——``current_yaml`` 是策略 YAML **文本**，
返回值是合并后的 YAML **文本**；只有显式传 ``output_path`` 才落盘。落盘为整文
重写（YAML 注释不进 pydantic 模型，重写会丢注释），波次二 CLI 应向用户提示。
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import TypeAdapter, ValidationError

from aaa.policy.loader import PolicyError, parse_policy
from aaa.policy.model import PolicyDocument

#: 合并模式（06 文档 W7：replace=整段替换；union=按条目合并）
MergeMode = Literal["replace", "union"]


class RulesHubError(ValueError):
    """规则市场操作失败（导出/导入/校验/同步）。"""


#: 段校验可能抛出的异常：pydantic ``ValidationError``，以及策略模型正则校验器
#: 直接抛出的 ``re.error``（pydantic 只包装 ValueError/AssertionError，
#: ``policy/model.py`` 的 ``_valid_regex`` 等校验器 raising re.error 会穿透——
#: 该文件属全局禁改，故在本模块调用点统一兜住）。
_SectionValidationError = (ValidationError, re.error)


#: 各策略段的 pydantic 校验器（按 ``PolicyDocument`` 字段注解构建，模块加载期一次）。
#: 列表段（volume/time_window）注解为 ``list[...]``，其余段为对应模型类。
_SECTION_ADAPTERS: dict[str, TypeAdapter[Any]] = {
    name: TypeAdapter(field.annotation)
    for name, field in PolicyDocument.model_fields.items()
    if field.annotation is not None
}


def shareable_sections() -> tuple[str, ...]:
    """可导出/可导入的策略段名单（``PolicyDocument`` 顶层字段，含 version/mode）。"""
    return tuple(PolicyDocument.model_fields)


def atomic_write_text(path: str | Path, text: str) -> None:
    """文本原子落盘（tmp + replace；失败清理临时文件，绝不留半截内容）。

    规则市场两个落盘点（import_section / sync_gitleaks）共用；均为
    **校验全部通过后**才调用本函数。
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(target.name + ".tmp")
    try:
        tmp.write_text(text, encoding="utf-8", newline="\n")
        tmp.replace(target)
    finally:
        tmp.unlink(missing_ok=True)


def _ensure_section(section: str) -> None:
    """段名合法性门禁：不在 ``PolicyDocument`` 字段内直接拒绝。"""
    if section not in PolicyDocument.model_fields:
        raise RulesHubError(
            f"未知策略段：{section!r}；可导出/导入的段：{'、'.join(shareable_sections())}"
        )


def export_section(policy_doc: PolicyDocument, section: str) -> str:
    """导出策略文档的一个段为 YAML 文本（段内容本身，不带段名包裹）。

    导出结果可直接作为 :func:`import_section` 的 ``yaml_str`` 回灌（往返格式）。
    段名非法抛 :class:`RulesHubError`。
    """
    _ensure_section(section)
    dumped = policy_doc.model_dump(mode="json", by_alias=True, include={section})
    return yaml.safe_dump(dumped[section], allow_unicode=True, sort_keys=False, width=1000)


def _union_value(current: Any, imported: Any) -> Any:
    """union 合并的逐值语义（对原始 dict/list 生效，合并结果仍需过 pydantic 校验）。

    - 双方都是映射：递归按键合并——键冲突**导入者胜**，本方独有键保留
      （即部分字段导入只覆盖给出的字段，适合 notifications/defaults 这类嵌套段）；
    - 双方都是列表且全部元素是带字符串 ``id`` 的映射（各类 rules）：按 id 合并——
      同 id **导入者胜**（整条覆盖），新 id 追加到尾部，本方规则顺序不变；
    - 其余列表（域名清单、收件人等）：去重并集（本方在前，导入新元素追加）；
    - 标量/类型不同：导入者胜。
    """
    if isinstance(current, dict) and isinstance(imported, dict):
        merged = dict(current)
        for key, value in imported.items():
            merged[key] = _union_value(merged[key], value) if key in merged else value
        return merged
    if (
        isinstance(current, list)
        and isinstance(imported, list)
        and current
        and imported
        and all(isinstance(item, dict) and isinstance(item.get("id"), str) for item in current)
        and all(isinstance(item, dict) and isinstance(item.get("id"), str) for item in imported)
    ):
        by_id: dict[str, dict[str, Any]] = {}
        for item in current:
            by_id[item["id"]] = item
        for item in imported:  # 同 id 导入者胜（整条覆盖），新 id 保持导入顺序追加
            by_id[item["id"]] = item
        return list(by_id.values())
    if isinstance(current, list) and isinstance(imported, list):
        merged_list = list(current)
        for item in imported:
            if item not in merged_list:
                merged_list.append(item)
        return merged_list
    return imported


def _parse_current(current_yaml: str | bytes) -> PolicyDocument:
    """当前策略 YAML 文本 → ``PolicyDocument``（失败收敛为 :class:`RulesHubError`）。"""
    try:
        return parse_policy(current_yaml)
    except PolicyError as exc:
        raise RulesHubError(f"当前策略 YAML 不合法：{exc}") from exc


def _load_imported(section: str, yaml_str: str | bytes) -> Any:
    """导入段 YAML 文本 → Python 值（空/解析失败/顶层为空值直接拒绝）。"""
    if not yaml_str or not yaml_str.strip():
        raise RulesHubError(f"段 {section!r} 的导入内容为空")
    try:
        data = yaml.safe_load(yaml_str)
    except yaml.YAMLError as exc:
        raise RulesHubError(f"导入段 {section!r} YAML 解析失败：{exc}") from exc
    if data is None:
        raise RulesHubError(f"段 {section!r} 的导入内容为空")
    return data


def import_section(
    current_yaml: str | bytes,
    section: str,
    yaml_str: str,
    *,
    merge: MergeMode = "replace",
    output_path: str | Path | None = None,
) -> str:
    """把单段 YAML 导入当前策略，返回合并后的**完整策略 YAML 文本**。

    流程（红线：不合法绝不写）：
      1. 当前策略全文过 :func:`aaa.policy.loader.parse_policy`（pydantic 严格校验）；
      2. 导入段按该段的 pydantic 模型单独校验（未知字段/非法动作/坏正则等直接拒绝）；
      3. 按 ``merge`` 合并，**合并结果**再过该段模型校验；
      4. 拼回完整策略再过一次 ``PolicyDocument`` 校验（双保险）；
      5. 全部通过后才返回文本；显式传 ``output_path`` 时原子落盘。

    任何一步失败抛 :class:`RulesHubError`，``output_path`` 既有内容一字不动。
    """
    if merge not in ("replace", "union"):
        raise RulesHubError(f"未知合并模式：{merge!r}（可选 replace | union）")
    _ensure_section(section)
    current_doc = _parse_current(current_yaml)
    imported_raw = _load_imported(section, yaml_str)
    adapter = _SECTION_ADAPTERS[section]
    try:
        adapter.validate_python(imported_raw)
    except _SectionValidationError as exc:
        raise RulesHubError(f"导入段 {section!r} 校验失败：{exc}") from exc
    current_raw = current_doc.model_dump(mode="json", by_alias=True)
    if merge == "union":
        merged_raw = _union_value(current_raw.get(section), imported_raw)
        try:
            adapter.validate_python(merged_raw)
        except _SectionValidationError as exc:
            raise RulesHubError(f"合并结果校验失败（段 {section!r}）：{exc}") from exc
    else:
        merged_raw = imported_raw
    full_raw = dict(current_raw)
    full_raw[section] = merged_raw
    try:
        PolicyDocument.model_validate(full_raw)
    except _SectionValidationError as exc:  # 双保险：理论上前两关已挡住，防御合并型遗漏
        raise RulesHubError(f"合并后完整策略校验失败：{exc}") from exc
    merged_text = yaml.safe_dump(full_raw, allow_unicode=True, sort_keys=False, width=1000)
    if output_path is not None:
        atomic_write_text(output_path, merged_text)
    return merged_text
