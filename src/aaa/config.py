"""路径、常量、运行配置（设计文档 02 §4：``aaa.config``）。

配置优先级（03 文档 §3）：CLI 参数 > 环境变量（``AAA_*``） > 默认值。
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

#: 数据目录覆盖环境变量
DATA_DIR_ENV = "AAA_DATA_DIR"

#: regular 模式默认监听地址（02 文档 D1：显式本地代理 127.0.0.1）
DEFAULT_LISTEN_HOST = "127.0.0.1"
#: regular 模式默认监听端口（02 文档 D1：127.0.0.1:8080）
DEFAULT_LISTEN_PORT = 8080
#: 请求 body 证据截断上限，默认 256KB（02 文档 D6）
DEFAULT_BODY_EVIDENCE_LIMIT = 256 * 1024

#: 事件保留期环境变量与默认值（02 文档 D6：启动自动清理，``aaa trim --days N`` 手动）
RETENTION_DAYS_ENV = "AAA_RETENTION_DAYS"
DEFAULT_RETENTION_DAYS = 14

#: confirm 决策默认 TTL 环境变量（03 文档 T5.3：TTL 可配）
CONFIRM_TTL_ENV = "AAA_CONFIRM_TTL"

#: Web 面板默认端口（本地只读面板，仅 127.0.0.1）
DEFAULT_WEB_PORT = 8787

#: 项目根目录（src/aaa/config.py 向上两级）
PROJECT_ROOT = Path(__file__).resolve().parents[2]

if getattr(sys, "frozen", False):
    # PyInstaller onefile：随包资源在 _MEIPASS，可写数据放 exe 同级 data/
    _BUNDLE_DIR = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    _EXE_DIR = Path(sys.executable).resolve().parent
    DEFAULT_POLICIES_DIR: Path = (
        _BUNDLE_DIR / "policies" if (_BUNDLE_DIR / "policies").is_dir() else _EXE_DIR / "policies"
    )
    DEFAULT_DATA_DIR: Path = _EXE_DIR / "data"
else:
    #: 默认数据目录（02 文档 §4：data/ 运行时生成，git 忽略）
    DEFAULT_DATA_DIR = PROJECT_ROOT / "data"
    #: 默认策略目录
    DEFAULT_POLICIES_DIR = PROJECT_ROOT / "policies"

#: 默认策略文件（03 文档 T3.1）
DEFAULT_POLICY_FILE = DEFAULT_POLICIES_DIR / "default.yaml"


@dataclass(frozen=True)
class AppPaths:
    """运行时路径集合。``data_dir`` 可由 CLI 参数或 ``AAA_DATA_DIR`` 指定。"""

    data_dir: Path
    policies_dir: Path = DEFAULT_POLICIES_DIR

    @property
    def confdir(self) -> Path:
        """mitmproxy confdir（CA 存放处），02 文档 T1.1：指向 ``data/mitm/``。"""
        return self.data_dir / "mitm"

    @property
    def raw_dir(self) -> Path:
        """事件 JSONL 直写目录：``data/raw/YYYYMMDD.jsonl``（03 文档 T1.2）。"""
        return self.data_dir / "raw"

    @property
    def db_file(self) -> Path:
        """SQLite 事件库：``data/audit.db``（02 文档 D6，03 文档 T4.1）。"""
        return self.data_dir / "audit.db"

    @property
    def decisions_file(self) -> Path:
        """confirm 人工决策缓存：``data/decisions.json``（03 文档 T5.3）。"""
        return self.data_dir / "decisions.json"

    @property
    def evidence_dir(self) -> Path:
        """证据文件目录：``data/evidence/<event_id>.bin``（02 文档 D6）。"""
        return self.data_dir / "evidence"

    @property
    def setup_state_file(self) -> Path:
        """setup 改动状态日志：``data/setup-state.json``（02 文档 R7）。"""
        return self.data_dir / "setup-state.json"

    def ensure_runtime_dirs(self) -> None:
        """创建运行时目录（幂等）。"""
        for d in (self.data_dir, self.confdir, self.raw_dir, self.evidence_dir):
            d.mkdir(parents=True, exist_ok=True)


def resolve_paths(data_dir: str | os.PathLike[str] | None = None) -> AppPaths:
    """解析数据目录：显式参数 > ``AAA_DATA_DIR`` > ``<项目根>/data``。"""
    if data_dir is not None:
        chosen: Path = Path(data_dir)
    else:
        env_value = os.environ.get(DATA_DIR_ENV)
        chosen = Path(env_value) if env_value else DEFAULT_DATA_DIR
    return AppPaths(data_dir=chosen)


def resolve_retention_days(explicit: int | None = None) -> int:
    """保留期解析：CLI 参数 > ``AAA_RETENTION_DAYS`` > 14 天（02 文档 D6）。"""
    if explicit is not None:
        return explicit
    env_value = os.environ.get(RETENTION_DAYS_ENV)
    if env_value:
        try:
            return int(env_value)
        except ValueError:
            return DEFAULT_RETENTION_DAYS
    return DEFAULT_RETENTION_DAYS


def resolve_confirm_ttl(explicit: int | None = None) -> int:
    """confirm 决策 TTL 解析：参数 > ``AAA_CONFIRM_TTL`` > 3600 秒（03 文档 T5.3）。"""
    from aaa.store.decisions import DEFAULT_DECISION_TTL_SECONDS

    if explicit is not None:
        return explicit
    env_value = os.environ.get(CONFIRM_TTL_ENV)
    if env_value:
        try:
            return int(env_value)
        except ValueError:
            return DEFAULT_DECISION_TTL_SECONDS
    return DEFAULT_DECISION_TTL_SECONDS
