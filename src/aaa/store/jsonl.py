"""事件 JSONL 直写：``data/raw/YYYYMMDD.jsonl``（03 文档 T1.2）。

P1 先直写 JSONL 留痕，P4/T4.1 收敛为 SQLite 双写（JSONL 保留开关）。
"""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from pathlib import Path

from aaa.store.events import AuditEvent


class JsonlEventStore:
    """线程安全的 JSONL 追加写存储。"""

    def __init__(self, raw_dir: Path) -> None:
        self._raw_dir = raw_dir
        self._lock = threading.Lock()
        raw_dir.mkdir(parents=True, exist_ok=True)

    @property
    def raw_dir(self) -> Path:
        return self._raw_dir

    def _path_for_now(self, now: datetime) -> Path:
        return self._raw_dir / f"{now.strftime('%Y%m%d')}.jsonl"

    def append(self, event: AuditEvent, *, now: datetime | None = None) -> Path:
        """追加一条事件到当天的 JSONL 文件，返回写入路径。"""
        stamp = now or datetime.now(UTC).astimezone()
        path = self._path_for_now(stamp)
        line = json.dumps(json.loads(event.model_dump_json()), ensure_ascii=False)
        with self._lock, path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        return path

    def read_all(self, day: str | None = None) -> list[AuditEvent]:
        """读取一天（默认今天）的全部事件，按文件顺序返回。"""
        pattern = f"{day}.jsonl" if day else "*.jsonl"
        events: list[AuditEvent] = []
        for path in sorted(self._raw_dir.glob(pattern)):
            with path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        events.append(AuditEvent.model_validate_json(line))
        return events
