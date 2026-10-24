"""setup 改动状态日志：``data/setup-state.json``（02 文档 R7，03 文档 T1.4/T1.5）。

原则：**journal-first**——先读旧值、先记条目（含时间戳），再做实际改动；
teardown 依据记录逆序幂等还原，崩溃后仍可依据记录完整还原（03 文档 T4.3）。
"""

from __future__ import annotations

import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class SetupStateError(RuntimeError):
    """状态文件读取/写入失败（如 JSON 损坏）。绝不静默丢弃还原记录。"""


class StateEntry(BaseModel):
    """一次系统改动记录。"""

    kind: str
    key: str
    ts: str
    old: Any = None
    new: Any = None
    note: str | None = None


class SetupState(BaseModel):
    """状态文件内容。"""

    version: int = 1
    entries: list[StateEntry] = Field(default_factory=list)


class StateFile:
    """线程安全的 setup 状态文件（load-modify-save）。"""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self._path

    def load(self) -> SetupState:
        """读取状态文件；不存在返回空状态；JSON 损坏抛出 ``SetupStateError``。"""
        if not self._path.exists():
            return SetupState()
        try:
            raw = self._path.read_text(encoding="utf-8")
            if not raw.strip():
                return SetupState()
            return SetupState.model_validate_json(raw)
        except (json.JSONDecodeError, ValueError) as exc:
            raise SetupStateError(
                f"setup 状态文件损坏，无法安全还原（{self._path}）：{exc}。"
                f"请人工检查后处理；不要删除该文件，否则系统设置无法还原。"
            ) from exc

    def save(self, state: SetupState) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        tmp.write_text(state.model_dump_json(indent=2), encoding="utf-8")
        tmp.replace(self._path)

    def record(
        self,
        *,
        kind: str,
        key: str,
        old: Any = None,
        new: Any = None,
        note: str | None = None,
        now: datetime | None = None,
    ) -> StateEntry:
        """追加一条改动记录（journal-first，先记录后改系统）。"""
        entry = StateEntry(
            kind=kind,
            key=key,
            ts=(now or datetime.now()).astimezone().isoformat(timespec="milliseconds"),
            old=old,
            new=new,
            note=note,
        )
        with self._lock:
            state = self.load()
            state.entries.append(entry)
            self.save(state)
        return entry

    def drop(self, kind: str, key: str) -> int:
        """还原成功后移除对应记录，返回移除条数（teardown 幂等的关键）。"""
        with self._lock:
            state = self.load()
            before = len(state.entries)
            state.entries = [e for e in state.entries if not (e.kind == kind and e.key == key)]
            removed = before - len(state.entries)
            if removed:
                self.save(state)
            return removed

    def entries(self) -> list[StateEntry]:
        return self.load().entries
