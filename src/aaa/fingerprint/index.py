"""仓库指纹索引（05 文档 W1）：本地代码仓库工作区 → 行滑窗指纹库 → 外发请求体比对。

- 切片规范（**建库与扫描共用同一函数** ``iter_slices``，保证"同文必同片"）：
  按行滑窗 n-gram（默认 win=8 行），先剔除空白行与注释行，每片逐行 strip 后
  以 ``"\\n"`` 连接，SHA1 摘要入库；
- 索引结构：``{digest: [(repo, rel_path, line_no), ...]}``，多仓库合并（同名拒绝）；
- 持久化 ``data/fingerprints.bin``：pickle 容忍损坏——读不出/版本不符/win 不符一律
  返回 ``None`` 由调用方重建，**绝不抛异常崩溃**；
- 大仓限流：单文件上限（默认 5MB，超限跳过）、总片上限（默认 200 万，防 OOM）；
- ``scan_body``：请求体按同规则切片比对，命中 ≥1 片即返回全部命中（上限 20 条）。

红线说明：
- 指纹库是**本地信任数据**：pickle 仅用于反序列化本工具自建的文件，绝不可加载
  来源不明的 ``fingerprints.bin``（pickle 反序列化等价于代码执行）；损坏文件按
  "不存在"处理并重建，不做任何恢复尝试；
- 命中证据 ``snippet`` 截断 80 字符且已压缩空白——事件/通知/webhook 外发的指纹
  命中清单不得携带更长原文；
- 全模块纯本地计算，无网络调用；文件系统访问一律经可注入 ``FileReader``，异常
  按跳过计数处理，不中断建库。
"""

from __future__ import annotations

import hashlib
import logging
import os
import pickle
import re
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import TypeAlias

from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)

#: 滑窗行数（05 文档 W1：默认 win=8 行）
DEFAULT_WINDOW = 8
#: 单文件大小上限（05 文档 W1：默认 5MB/文件，超限跳过防 OOM）
DEFAULT_MAX_FILE_BYTES = 5 * 1024 * 1024
#: 指纹库总片上限（05 文档 W1：默认 200 万片）
DEFAULT_MAX_SLICES = 2_000_000
#: scan_body 返回命中条数上限（05 文档 W1：上限 20 条）
MAX_SCAN_HITS = 20
#: snippet 截断长度（05 文档 W1：前 80 字符脱空白）
SNIPPET_MAX_CHARS = 80
#: 持久化文件默认名（调用方以 data_dir 拼接：``data/fingerprints.bin``）
FINGERPRINTS_FILE_NAME = "fingerprints.bin"
#: 二进制探测采样字节数（采样含 NUL 即视为二进制文件，与 git 行为一致）
_BINARY_SAMPLE_BYTES = 8192

#: 建库时跳过的目录名（git 工作区元数据不进指纹）
SKIP_DIRS: frozenset[str] = frozenset({".git"})

#: 持久化格式版本（结构变更时递增，旧文件视为不兼容 → 重建）
_FORMAT_VERSION = 1

#: 注释/噪音行前缀（行首 strip 后匹配）：shell/py/rb 的 #、C 系 //、块注释 /* * */、
#: SQL/Lua 的 --、HTML 的 <!--。保守集合：宁可少剔、不可误剔代码行。
_NOISE_LINE_RE = re.compile(r"^(?:#|//|/\*|\*|--|<!--)")

#: 可注入文件读取器（默认 ``Path.read_bytes``；测试注入假读取器/错误注入）
FileReader: TypeAlias = Callable[[Path], bytes]


def _is_noise_line(line: str) -> bool:
    """空白行或注释行 → 不参与切片（05 文档 W1"去空白/注释行"）。"""
    stripped = line.strip()
    if not stripped:
        return True
    return bool(_NOISE_LINE_RE.match(stripped))


def iter_slices(text: str, *, window: int = DEFAULT_WINDOW) -> Iterator[tuple[int, str]]:
    """切片规范唯一实现：按行滑窗 n-gram。

    处理顺序：剔除空白/注释行 → 保留行逐行 ``strip()``（消缩进/行尾空白）→
    win 行滑窗（步长 1）→ ``"\\n"`` 连接。产出 ``(窗口首行的原始行号, 规范化片文本)``，
    行号自 1 起按**原始文本**计。建库（``add_repo``）与扫描（``scan_body``）都必须
    经此函数切片——切片规范漂移等于指纹库整体失效。
    """
    if window <= 0:
        raise ValueError(f"window 必须为正数，收到 {window}")
    kept: list[tuple[int, str]] = []  # 滑窗缓冲：(原始行号, 规范化行)
    for lineno, line in enumerate(text.splitlines(), start=1):
        if _is_noise_line(line):
            continue
        kept.append((lineno, line.strip()))
        if len(kept) == window:
            yield kept[0][0], "\n".join(norm for _, norm in kept)
            del kept[0]


def digest_slice(slice_text: str) -> str:
    """规范化片文本的 SHA1 摘要（hexdigest）。"""
    return hashlib.sha1(slice_text.encode("utf-8")).hexdigest()


def _make_snippet(slice_text: str) -> str:
    """命中片段展示形态：空白压缩为单空格后取前 80 字符（05 文档 W1"脱空白"）。"""
    return " ".join(slice_text.split())[:SNIPPET_MAX_CHARS]


class FingerprintHit(BaseModel):
    """一次指纹命中（进事件 evidence 的指纹命中清单）。"""

    model_config = ConfigDict(frozen=True)

    repo: str
    """仓库名（默认取目录名，``add_repo`` 可显式指定）。"""
    file: str
    """仓库内相对路径（POSIX 分隔符）。"""
    line: int = Field(ge=1)
    """命中窗口首行的原始行号（1 起）。"""
    snippet: str
    """命中片段前 80 字符（空白已压缩），不得携带更长原文。"""


class BuildStats(BaseModel):
    """一次 ``add_repo`` 的建库统计（CLI 回显与大仓限流断言用）。"""

    model_config = ConfigDict(frozen=True)

    repo: str
    files_indexed: int = 0
    files_skipped_too_large: int = 0
    files_skipped_binary: int = 0
    files_errored: int = 0
    slices_added: int = 0
    slice_cap_reached: bool = False
    """本次建库触发了总片上限（部分文件未读、部分片未入）。"""
    total_slices: int = 0
    """本次建库完成后索引内总片数（跨仓库累计）。"""


class _RepoCounters:
    """单次 add_repo 的可变计数器（收口时转为 BuildStats）。"""

    __slots__ = (
        "files_errored",
        "files_indexed",
        "files_skipped_binary",
        "files_skipped_too_large",
        "slices_added",
    )

    def __init__(self) -> None:
        self.files_indexed = 0
        self.files_skipped_too_large = 0
        self.files_skipped_binary = 0
        self.files_errored = 0
        self.slices_added = 0

    def to_stats(self, repo: str, *, cap_reached: bool, total_slices: int) -> BuildStats:
        return BuildStats(
            repo=repo,
            files_indexed=self.files_indexed,
            files_skipped_too_large=self.files_skipped_too_large,
            files_skipped_binary=self.files_skipped_binary,
            files_errored=self.files_errored,
            slices_added=self.slices_added,
            slice_cap_reached=cap_reached,
            total_slices=total_slices,
        )


class FingerprintIndex:
    """仓库指纹索引：多仓库合并构建、持久化、请求体比对。

    线程安全：构建（``add_repo``/``save``）持锁；``scan_body`` 只做字典点查，
    与构建并发安全（采集线程扫描与 CLI 重建是集成阶段的现实并发场景）。
    """

    def __init__(
        self,
        *,
        window: int = DEFAULT_WINDOW,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_slices: int = DEFAULT_MAX_SLICES,
    ) -> None:
        if window <= 0:
            raise ValueError(f"window 必须为正数，收到 {window}")
        if max_file_bytes <= 0:
            raise ValueError(f"max_file_bytes 必须为正数，收到 {max_file_bytes}")
        if max_slices <= 0:
            raise ValueError(f"max_slices 必须为正数，收到 {max_slices}")
        self._window = window
        self._max_file_bytes = max_file_bytes
        self._max_slices = max_slices
        self._index: dict[str, list[tuple[str, str, int]]] = {}
        self._repos: set[str] = set()
        self._total_slices = 0
        self._lock = threading.Lock()

    # ------------------------------------------------------------ 构建索引

    def add_repo(
        self,
        repo_root: str | os.PathLike[str],
        *,
        name: str | None = None,
        reader: FileReader | None = None,
        require_git: bool = True,
    ) -> BuildStats:
        """把一个本地 git 仓库工作区并入索引（多仓库多次调用合并）。

        - 目录递归枚举（跳过 ``.git`` 与符号链接，按名字排序保证确定性）；
        - 限流：单文件超 ``max_file_bytes`` 跳过；累计片数达 ``max_slices`` 立即
          停止（后续 ``add_repo`` 短路返回），防 OOM；
        - ``reader`` 注入文件读取（默认真实读盘）；读取 OSError 按跳过计数，
          绝不中断建库；
        - ``require_git``（默认 True）：非 git 工作区（无 ``.git``）拒绝；
        - 同名仓库重复并入拒绝（位置来源不可区分），显式传 ``name`` 区分。
        """
        root = Path(repo_root)
        if not root.is_dir():
            raise NotADirectoryError(f"仓库目录不存在或不是目录：{root}")
        if require_git and not (root / ".git").exists():
            raise ValueError(
                f"{root} 不是 git 仓库工作区（缺少 .git）；索引普通目录请传 require_git=False"
            )
        repo_name = name or root.resolve().name
        read = reader if reader is not None else _default_reader
        counters = _RepoCounters()
        with self._lock:
            if repo_name in self._repos:
                raise ValueError(f"仓库 {repo_name!r} 已在索引中（同名拒绝，请显式传 name 区分）")
            cap_reached = self._total_slices >= self._max_slices
            if cap_reached:
                # 已达总片上限：短路，不再读任何文件
                return counters.to_stats(
                    repo_name, cap_reached=True, total_slices=self._total_slices
                )
            self._repos.add(repo_name)
            for path in _iter_worktree_files(root):
                if self._total_slices >= self._max_slices:
                    cap_reached = True
                    break
                self._index_file(root, path, repo_name, read, counters)
            return counters.to_stats(
                repo_name, cap_reached=cap_reached, total_slices=self._total_slices
            )

    def _index_file(
        self, root: Path, path: Path, repo: str, read: FileReader, counters: _RepoCounters
    ) -> None:
        """读单个文件并切片入库（限流/异常均按计数跳过，不抛出）。"""
        try:
            raw = read(path)
        except OSError:
            logger.debug("指纹建库读取失败，跳过：%s", path)
            counters.files_errored += 1
            return
        if len(raw) > self._max_file_bytes:
            counters.files_skipped_too_large += 1
            return
        if b"\x00" in raw[:_BINARY_SAMPLE_BYTES]:
            counters.files_skipped_binary += 1
            return
        text = raw.decode("utf-8", errors="replace")
        rel = path.relative_to(root).as_posix()
        added = 0
        for line_no, slice_text in iter_slices(text, window=self._window):
            if self._total_slices >= self._max_slices:
                break
            self._index.setdefault(digest_slice(slice_text), []).append((repo, rel, line_no))
            self._total_slices += 1
            added += 1
            counters.slices_added += 1
        if added:
            counters.files_indexed += 1  # 有片入库才算"已索引"（不足一个窗口的文件不算）

    # ------------------------------------------------------------ 请求体比对

    def scan_body(self, body: bytes | str | None) -> list[FingerprintHit]:
        """请求体指纹比对：与建库**同一切片规范**（``iter_slices``）逐片查表。

        命中 ≥1 片即返回全部命中（按 ``(repo, file, line)`` 去重，上限
        ``MAX_SCAN_HITS`` 条）；无命中/空体/空索引返回空列表，绝不抛异常。
        """
        if not body:
            return []
        text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body
        hits: list[FingerprintHit] = []
        seen: set[tuple[str, str, int]] = set()
        for _, slice_text in iter_slices(text, window=self._window):
            locations = self._index.get(digest_slice(slice_text))
            if not locations:
                continue
            snippet = _make_snippet(slice_text)
            for repo, rel, line_no in locations:
                key = (repo, rel, line_no)
                if key in seen:
                    continue
                seen.add(key)
                hits.append(FingerprintHit(repo=repo, file=rel, line=line_no, snippet=snippet))
                if len(hits) >= MAX_SCAN_HITS:
                    return hits
        return hits

    # ---------------------------------------------------------------- 持久化

    def save(self, path: str | os.PathLike[str]) -> None:
        """原子写指纹库（tmp + replace）。pickle 仅用于本工具自建的本地信任文件。"""
        target = Path(path)
        with self._lock:
            payload = {
                "version": _FORMAT_VERSION,
                "window": self._window,
                "repos": sorted(self._repos),
                "index": self._index,
            }
            target.parent.mkdir(parents=True, exist_ok=True)
            tmp = target.with_suffix(target.suffix + ".tmp")
            with tmp.open("wb") as fh:
                pickle.dump(payload, fh, protocol=4)
            tmp.replace(target)

    @classmethod
    def load(
        cls,
        path: str | os.PathLike[str],
        *,
        window: int = DEFAULT_WINDOW,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_slices: int = DEFAULT_MAX_SLICES,
    ) -> FingerprintIndex | None:
        """读指纹库；文件缺失/**损坏**/版本或 win 不符 → ``None``（调用方重建）。

        红线：pickle 损坏容忍——任何反序列化异常都吞掉并返回 ``None``，
        绝不向上抛（05 文档 W1"容忍损坏→重建"）。
        """
        try:
            raw = Path(path).read_bytes()
        except OSError:
            return None
        try:
            payload = pickle.loads(raw)
            if not isinstance(payload, dict):
                raise ValueError("指纹库结构不符（非 dict）")
            if payload.get("version") != _FORMAT_VERSION:
                logger.warning("指纹库版本不兼容，需重建：%s", path)
                return None
            if payload.get("window") != window:
                logger.warning(
                    "指纹库 win=%r 与当前 win=%r 不符，需重建", payload.get("window"), window
                )
                return None
            index = payload["index"]
            repos = payload["repos"]
            if not isinstance(index, dict) or not isinstance(repos, list):
                raise ValueError("指纹库字段类型不符")
            loaded = cls(window=window, max_file_bytes=max_file_bytes, max_slices=max_slices)
            loaded._index = {
                str(digest): [(str(r), str(f), int(n)) for r, f, n in locations]
                for digest, locations in index.items()
            }
            loaded._repos = {str(r) for r in repos}
            loaded._total_slices = sum(len(v) for v in loaded._index.values())
            return loaded
        except Exception:  # 损坏指纹库可能是任何异常形态：一律按"需重建"处理
            logger.warning("指纹库损坏，忽略并重建：%s", path, exc_info=True)
            return None

    # ------------------------------------------------------------------ 状态

    @property
    def window(self) -> int:
        return self._window

    @property
    def repos(self) -> frozenset[str]:
        """已并入索引的仓库名集合。"""
        return frozenset(self._repos)

    @property
    def total_slices(self) -> int:
        """索引内总片数（跨仓库累计，限流依据）。"""
        return self._total_slices

    @property
    def digest_count(self) -> int:
        """不同指纹（digest）数。"""
        return len(self._index)

    def locations(self, digest: str) -> list[tuple[str, str, int]]:
        """查某指纹的全部来源位置（``(repo, rel_path, line_no)``，诊断用）。"""
        return list(self._index.get(digest, ()))


def _default_reader(path: Path) -> bytes:
    """默认文件读取器（真实读盘）。"""
    return path.read_bytes()


def _iter_worktree_files(root: Path) -> Iterator[Path]:
    """深度优先枚举工作区文件：跳过 ``.git``，不跟随符号链接，按名排序（确定性）。

    单个目录枚举失败（如遍历途中被删）按跳过处理，不中断建库。
    """
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                children = sorted(entries, key=lambda entry: entry.name)
        except OSError:
            logger.debug("指纹建库目录枚举失败，跳过：%s", current)
            continue
        for entry in children:
            if entry.is_dir(follow_symlinks=False):
                if entry.name not in SKIP_DIRS:
                    stack.append(Path(entry.path))
            elif entry.is_file(follow_symlinks=False):
                yield Path(entry.path)
