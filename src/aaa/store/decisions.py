"""confirm 交互流的用户决策缓存（03 文档 T5.3，02 文档 G4）。

- 策略引擎对请求给出 ``verdict=confirm`` 时，事件进入面板等待用户决策；
- 用户 **拒绝**：按 ``(host, 命中规则)`` 键缓存 ``deny``，TTL 内同类请求直接升级
  block（采集进程与面板进程可能不同，故文件持久化 ``data/decisions.json``）；
- 用户 **允许**：仅记录到该事件（``events.decision``），一次性放行，不缓存——
  后续同类请求再次进入 confirm（03 文档 T5.3 "允许（记 allow 一次）"）。

TTL 单位秒，可配（``POST /api/decisions`` 的 ``ttl_seconds``、环境变量
``AAA_CONFIRM_TTL`` 的默认值）。过期条目在读写时惰性清除。
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

#: 默认决策 TTL（秒）：面板拒绝后同类请求升级 block 的缓存时长
DEFAULT_DECISION_TTL_SECONDS = 3600

#: 决策取值
DECISION_ALLOW = "allow"
DECISION_DENY = "deny"

_DECISIONS_NAME = "decisions.json"


def decision_key(host: str, rule_ids: list[str] | tuple[str, ...]) -> str:
    """confirm 决策键："同类" = 同一目标主机 + 同一组命中规则（顺序无关）。"""
    return f"{(host or '').lower().rstrip('.')}|{','.join(sorted(set(rule_ids)))}"


class DecisionStore:
    """文件持久化的 deny 决策缓存（线程安全；跨进程经 mtime 感知更新）。"""

    def __init__(self, path: Path, *, default_ttl: int = DEFAULT_DECISION_TTL_SECONDS) -> None:
        self._path = path
        self._default_ttl = default_ttl
        self._lock = threading.Lock()
        self._mtime: float | None = None
        self._cache: dict[str, dict[str, Any]] = {}

    @property
    def path(self) -> Path:
        return self._path

    @property
    def default_ttl(self) -> int:
        return self._default_ttl

    # ------------------------------------------------------------------ 读写

    def set(
        self,
        key: str,
        decision: str,
        *,
        ttl_seconds: int | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """记录一条决策（当前仅 deny 需要缓存；allow 一次性、不入缓存）。"""
        if decision != DECISION_DENY:
            raise ValueError(f"决策缓存只接受 {DECISION_DENY!r}，收到 {decision!r}（allow 落事件）")
        ttl = self._default_ttl if ttl_seconds is None else int(ttl_seconds)
        if ttl <= 0:
            raise ValueError(f"ttl_seconds 必须为正数，收到 {ttl}")
        stamp = now or datetime.now(UTC).astimezone()
        entry = {
            "key": key,
            "decision": decision,
            "ts": stamp.isoformat(timespec="milliseconds"),
            "ttl_seconds": ttl,
            "expires_epoch": stamp.timestamp() + ttl,
        }
        with self._lock:
            data = self._load()
            data["decisions"] = [d for d in data.get("decisions", []) if d.get("key") != key]
            data["decisions"].append(entry)
            self._save(data)
        return entry

    def active(self, key: str, *, now: datetime | None = None) -> str | None:
        """查决策：TTL 内返回 ``deny``，过期/不存在返回 ``None``（惰性清除过期项）。"""
        stamp = (now or datetime.now(UTC).astimezone()).timestamp()
        with self._lock:
            data = self._reload_if_changed()
            changed = False
            result: str | None = None
            kept: list[dict[str, Any]] = []
            for item in data.get("decisions", []):
                if item.get("expires_epoch", 0) <= stamp:
                    changed = True  # 过期惰性清除
                    continue
                if item.get("key") == key:
                    result = str(item.get("decision"))
                kept.append(item)
            if changed:
                data["decisions"] = kept
                self._save(data)
            return result

    def list_active(self, *, now: datetime | None = None) -> list[dict[str, Any]]:
        """当前（未过期）决策列表（面板回显）。"""
        stamp = (now or datetime.now(UTC).astimezone()).timestamp()
        with self._lock:
            data = self._reload_if_changed()
            active = [
                item for item in data.get("decisions", []) if item.get("expires_epoch", 0) > stamp
            ]
        return sorted(active, key=lambda item: str(item.get("key")))

    # -------------------------------------------------------------- 内部存储

    def _load(self) -> dict[str, Any]:
        """读文件（不存在/为空 → 空结构；损坏 → 记日志并视为空，绝不崩采集进程）。"""
        try:
            raw = self._path.read_text(encoding="utf-8")
            if not raw.strip():
                return {"version": 1, "decisions": []}
            data = json.loads(raw)
            if not isinstance(data, dict) or not isinstance(data.get("decisions"), list):
                raise ValueError("结构不符")
            return data
        except FileNotFoundError:
            return {"version": 1, "decisions": []}
        except (json.JSONDecodeError, ValueError):
            logger.exception("决策文件损坏，按空处理（不影响采集）： %s", self._path)
            return {"version": 1, "decisions": []}

    def _save(self, data: dict[str, Any]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self._path)
        self._mtime = self._path.stat().st_mtime
        self._cache = data

    def _reload_if_changed(self) -> dict[str, Any]:
        """跨进程感知：文件 mtime 变了才重读（确认高频路径的读放大可控）。"""
        try:
            mtime = self._path.stat().st_mtime
        except FileNotFoundError:
            self._cache = {}
            self._mtime = None
            return {"version": 1, "decisions": []}
        if self._mtime is None or mtime != self._mtime:
            self._cache = self._load()
            self._mtime = mtime
        return self._cache


__all__ = [
    "DECISION_ALLOW",
    "DECISION_DENY",
    "DEFAULT_DECISION_TTL_SECONDS",
    "DecisionStore",
    "decision_key",
]
