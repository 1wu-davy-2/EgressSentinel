"""仓库指纹单测（05 文档 W1）：建索引/命中/持久化/上限/空仓，全部临时目录 + 注入。

红线：不依赖真实网络与真实 git 命令（临时目录手造 ``.git`` 占位即可）；
``fingerprints.bin`` 损坏场景以垃圾字节/截断文件模拟，验证"重建而非崩溃"。
"""

from __future__ import annotations

import random
from pathlib import Path

import pytest

from aaa.fingerprint import (
    DEFAULT_WINDOW,
    FINGERPRINTS_FILE_NAME,
    MAX_SCAN_HITS,
    SNIPPET_MAX_CHARS,
    BuildStats,
    FingerprintHit,
    FingerprintIndex,
    digest_slice,
    iter_slices,
)

# --------------------------------------------------------------------- 夹具材料

#: 24 行互不相同的"代码"（无注释/空行，window=8 → 17 片）
LINES_A = [f"alpha_line_{i:02d} = compute_alpha({i})" for i in range(1, 25)]
TEXT_A = "\n".join(LINES_A) + "\n"

#: 另一组 20 行（供第二个仓库/第二个文件用）
LINES_B = [f"beta_line_{i:02d} = compute_beta({i})" for i in range(1, 21)]
TEXT_B = "\n".join(LINES_B) + "\n"


def _make_repo(root: Path, files: dict[str, str | bytes], *, git: bool = True) -> Path:
    """临时目录里手造一个"git 仓库工作区"（.git 只建占位目录，不跑 git 命令）。

    文本按 ``newline="\\n"`` 写盘（避免 Windows 把 \\n 翻译成 \\r\\n 改变字节数）；
    规范化切片本就兼容 \\r\\n，这里只是让文件大小断言精确。
    """
    root.mkdir(parents=True, exist_ok=True)
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8", newline="")
    if git:
        (root / ".git").mkdir(exist_ok=True)
    return root


def _random_text(lines: int = 200, seed: int = 20261024) -> str:
    """确定性随机文本（误报边界用）：不会与仓库内容重合的乱码行。"""
    rng = random.Random(seed)
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789_=+."
    return "\n".join(
        "".join(rng.choice(alphabet) for _ in range(rng.randint(24, 60))) for _ in range(lines)
    )


# ------------------------------------------------------------------ 切片规范


def test_iter_slices_window_and_line_numbers() -> None:
    """滑窗步长 1、片数 = 保留行数 - win + 1、行号按原始文本计。"""
    slices = list(iter_slices(TEXT_A))
    assert len(slices) == len(LINES_A) - DEFAULT_WINDOW + 1 == 17
    assert slices[0][0] == 1
    assert slices[1][0] == 2  # 步长 1
    assert slices[-1][0] == len(LINES_A) - DEFAULT_WINDOW + 1
    # 片文本 = 8 行规范化后按 \n 连接
    assert slices[0][1] == "\n".join(LINES_A[:8])
    assert slices[1][1] == "\n".join(LINES_A[1:9])


def test_iter_slices_skips_blank_and_comment_lines() -> None:
    """空白行与注释行不参与切片，行号仍按原始行计。"""
    text = (
        "# 顶部注释\n"
        "\n"
        "   \n"
        "first_real()\n"
        "// c++ 注释\n"
        "/* 块注释头\n"
        " * 块注释体\n"
        "second_real()\n"
        "-- sql 注释\n"
        "<!-- html 注释 -->\n"
        "third_real()\n"
    )
    slices = list(iter_slices(text, window=3))
    assert len(slices) == 1  # 只有 3 行保留行
    line_no, slice_text = slices[0]
    assert line_no == 4  # 窗口首行 = 第一个保留行的原始行号
    assert slice_text == "first_real()\nsecond_real()\nthird_real()"


def test_iter_slices_normalizes_indentation_and_eol() -> None:
    """规范化：行首/行尾空白剔除——同文不同缩进必须同片（同一切片规范的前提）。"""
    base = "\n".join(LINES_A[:8])
    indented = "\r\n".join("    " + line + "   " for line in LINES_A[:8]) + "\r\n"
    assert digest_slice(list(iter_slices(base))[0][1]) == digest_slice(
        list(iter_slices(indented))[0][1]
    )


def test_iter_slices_short_text_yields_nothing() -> None:
    """保留行不足 win → 0 片（命中窗口下界）。"""
    assert list(iter_slices("\n".join(LINES_A[:7]))) == []
    assert list(iter_slices("")) == []


def test_iter_slices_rejects_bad_window() -> None:
    with pytest.raises(ValueError, match="window"):
        list(iter_slices(TEXT_A, window=0))


# ----------------------------------------------------------------------- 建索引


def test_add_repo_builds_index(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path / "proj", {"app.py": TEXT_A, "lib/util.py": TEXT_B})
    index = FingerprintIndex()
    stats = index.add_repo(repo)
    assert isinstance(stats, BuildStats)
    assert stats.repo == "proj"
    assert stats.files_indexed == 2
    assert stats.files_skipped_too_large == 0
    assert stats.files_skipped_binary == 0
    assert stats.files_errored == 0
    assert stats.slices_added == (len(LINES_A) - 7) + (len(LINES_B) - 7)
    assert stats.slice_cap_reached is False
    assert stats.total_slices == index.total_slices == stats.slices_added
    assert index.repos == {"proj"}
    assert index.digest_count > 0


def test_add_repo_requires_git_worktree(tmp_path: Path) -> None:
    plain = _make_repo(tmp_path / "plain", {"a.py": TEXT_A}, git=False)
    index = FingerprintIndex()
    with pytest.raises(ValueError, match="git 仓库工作区"):
        index.add_repo(plain)
    # 显式放行非 git 目录（快照式源码目录场景）
    stats = index.add_repo(plain, require_git=False)
    assert stats.files_indexed == 1


def test_add_repo_rejects_missing_dir(tmp_path: Path) -> None:
    index = FingerprintIndex()
    with pytest.raises(NotADirectoryError):
        index.add_repo(tmp_path / "nope")


def test_add_repo_rejects_duplicate_name(tmp_path: Path) -> None:
    r1 = _make_repo(tmp_path / "dup", {"a.py": TEXT_A})
    r2 = _make_repo(tmp_path / "other" / "dup", {"b.py": TEXT_B})
    index = FingerprintIndex()
    index.add_repo(r1)
    with pytest.raises(ValueError, match="已在索引中"):
        index.add_repo(r2)
    # 显式不同名即可合并
    stats = index.add_repo(r2, name="dup2")
    assert stats.repo == "dup2"
    assert index.repos == {"dup", "dup2"}


def test_add_repo_empty_worktree(tmp_path: Path) -> None:
    """空仓：只有 .git 占位 → 0 文件 0 片。"""
    repo = _make_repo(tmp_path / "empty", {})
    index = FingerprintIndex()
    stats = index.add_repo(repo)
    assert stats.files_indexed == 0
    assert stats.slices_added == 0
    assert index.total_slices == 0
    assert index.scan_body(TEXT_A) == []


# ----------------------------------------------------------------------- 命中


def test_scan_body_hits_expected_location(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path / "proj", {"app.py": TEXT_A, "lib/util.py": TEXT_B})
    index = FingerprintIndex()
    index.add_repo(repo)

    # 请求体 = app.py 第 9..16 行（恰好一个完整窗口）→ 命中 line=9
    body = "\n".join(LINES_A[8:16])
    hits = index.scan_body(body)
    assert hits == [
        FingerprintHit(
            repo="proj",
            file="app.py",
            line=9,
            snippet=" ".join(body.split())[:SNIPPET_MAX_CHARS],
        )
    ]

    # 多窗口长体：命中窗口起点连续
    long_hits = index.scan_body(TEXT_A)
    assert [h.line for h in long_hits] == list(range(1, 18))
    assert all(h.repo == "proj" and h.file == "app.py" for h in long_hits)

    # bytes 输入同样支持（addon 侧 body 常为 bytes）
    assert index.scan_body(body.encode("utf-8")) == hits

    # lib/util.py 的片段命中相对路径文件
    assert index.scan_body("\n".join(LINES_B[:8]))[0].file == "lib/util.py"


def test_scan_body_below_window_no_false_positive(tmp_path: Path) -> None:
    """误报边界：不足一个窗口（含注释挤占窗口位）→ 0 命中。"""
    repo = _make_repo(tmp_path / "proj", {"app.py": TEXT_A})
    index = FingerprintIndex()
    index.add_repo(repo)
    assert index.scan_body("\n".join(LINES_A[:7])) == []
    # 8 行里 1 行是注释 → 保留 7 行 → 不成片
    polluted = LINES_A[:7] + ["# 这行是注释"]
    assert index.scan_body("\n".join(polluted)) == []
    assert index.scan_body(_random_text()) == []


def test_scan_body_random_text_zero_hits(tmp_path: Path) -> None:
    """随机文本 0 命中（05 文档 W1 误报边界）。"""
    repo = _make_repo(tmp_path / "proj", {"app.py": TEXT_A, "lib/util.py": TEXT_B})
    index = FingerprintIndex()
    index.add_repo(repo)
    for seed in (1, 42, 20261024):
        assert index.scan_body(_random_text(lines=500, seed=seed)) == []


def test_scan_body_whitespace_only_variants(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path / "proj", {"app.py": TEXT_A})
    index = FingerprintIndex()
    index.add_repo(repo)
    assert index.scan_body("") == []
    assert index.scan_body(None) == []
    assert index.scan_body("   \n\t\n") == []


def test_scan_body_reflowed_body_still_hits(tmp_path: Path) -> None:
    """同文必同片：请求体重排缩进/插注释空行后仍命中同一条目（共享切片规范）。"""
    repo = _make_repo(tmp_path / "proj", {"app.py": TEXT_A})
    index = FingerprintIndex()
    index.add_repo(repo)
    reflowed = "\n".join(
        ["# 请求体里的注释"] + ["    " + line + "\t" for line in LINES_A[8:16]] + ["", "// tail"]
    )
    hits = index.scan_body(reflowed)
    assert len(hits) == 1
    assert (hits[0].repo, hits[0].file, hits[0].line) == ("proj", "app.py", 9)


def test_scan_body_snippet_truncated_and_whitespace_stripped(tmp_path: Path) -> None:
    long_line = "x = '" + "A" * 200 + "'"
    text = "\n".join([long_line] + [f"pad_{i} = {i}" for i in range(1, 12)]) + "\n"
    index = FingerprintIndex()
    index.add_repo(_make_repo(tmp_path / "proj", {"big.py": text}))
    hits = index.scan_body(text)
    assert hits, "应命中"
    assert len(hits[0].snippet) == SNIPPET_MAX_CHARS
    snippet = hits[0].snippet
    assert "\n" not in snippet and "\t" not in snippet and "  " not in snippet


def test_scan_body_cap_20_hits(tmp_path: Path) -> None:
    """命中上限 20：同一片在库里有 30 个来源位置，只返回前 20。"""
    block = "\n".join(LINES_A[:8])  # 8 行块整体重复 → 周期位置上的窗口同片
    text = "\n".join(block for _ in range(30)) + "\n"
    index = FingerprintIndex()
    index.add_repo(_make_repo(tmp_path / "proj", {"dup.py": text}))
    assert len(index.scan_body(block)) == MAX_SCAN_HITS == 20


def test_scan_body_dedupes_repeated_body_slice(tmp_path: Path) -> None:
    """同一片在请求体里重复出现 → 同一来源位置只返回一条（去重）。

    库内该 8 行块仅出现一次（line 11，前后为独立垫行）；请求体把它连写两遍，
    两个体窗口同片 → 不去重会得 2 条，去重后恰 1 条。
    """
    block = "\n".join(LINES_A[:8])
    pads = [f"pad_line_{i:02d} = {i}" for i in range(1, 11)]
    file_text = "\n".join([*pads, block, *pads]) + "\n"
    index = FingerprintIndex()
    index.add_repo(_make_repo(tmp_path / "proj", {"once.py": file_text}))
    hits = index.scan_body(block + "\n" + block)
    assert [(h.repo, h.file, h.line) for h in hits] == [("proj", "once.py", 11)]


def test_scan_body_on_empty_index() -> None:
    """空索引（未建任何仓库）→ 恒空。"""
    index = FingerprintIndex()
    assert index.scan_body(TEXT_A) == []
    assert index.scan_body(_random_text()) == []


def test_multi_repo_merge_hits_both(tmp_path: Path) -> None:
    """多仓库合并：同一片段同时存在于两个仓库 → 两个来源都返回。"""
    shared = "\n".join(LINES_A[:8]) + "\n"
    r1 = _make_repo(tmp_path / "repo_one", {"src/common.py": shared + "\n".join(LINES_B) + "\n"})
    r2 = _make_repo(tmp_path / "repo_two", {"other/common.py": shared})
    index = FingerprintIndex()
    index.add_repo(r1)
    index.add_repo(r2)
    assert index.repos == {"repo_one", "repo_two"}
    hits = index.scan_body("\n".join(LINES_A[:8]))
    assert {(h.repo, h.file) for h in hits} == {
        ("repo_one", "src/common.py"),
        ("repo_two", "other/common.py"),
    }
    assert {h.line for h in hits} == {1}


# ----------------------------------------------------------------------- 持久化


def test_save_load_roundtrip(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path / "proj", {"app.py": TEXT_A, "lib/util.py": TEXT_B})
    index = FingerprintIndex()
    index.add_repo(repo)
    store = tmp_path / "data" / FINGERPRINTS_FILE_NAME
    index.save(store)
    assert store.is_file()

    loaded = FingerprintIndex.load(store)
    assert loaded is not None
    assert loaded.repos == index.repos
    assert loaded.total_slices == index.total_slices
    assert loaded.digest_count == index.digest_count
    body = "\n".join(LINES_A[8:16])
    assert [h.model_dump() for h in loaded.scan_body(body)] == [
        h.model_dump() for h in index.scan_body(body)
    ]
    # 加载后的库可继续合并新仓库（多 repo 合并跨进程场景）
    stats = loaded.add_repo(_make_repo(tmp_path / "proj2", {"b.py": TEXT_B}), name="proj2")
    assert stats.slices_added > 0


def test_load_missing_returns_none(tmp_path: Path) -> None:
    assert FingerprintIndex.load(tmp_path / "absent.bin") is None


@pytest.mark.parametrize(
    "corrupt",
    [
        b"this is not a pickle \x00\xff",  # 垃圾字节
        None,  # 截断的合法 pickle
    ],
)
def test_load_corrupt_returns_none_then_rebuild(tmp_path: Path, corrupt: bytes | None) -> None:
    """pickle 损坏（垃圾/截断）→ load 返回 None 不抛异常 → 重建流程可用。"""
    repo = _make_repo(tmp_path / "proj", {"app.py": TEXT_A})
    store = tmp_path / FINGERPRINTS_FILE_NAME
    index = FingerprintIndex()
    index.add_repo(repo)
    index.save(store)
    if corrupt is None:
        raw = store.read_bytes()
        store.write_bytes(raw[: len(raw) // 2])  # 截断
    else:
        store.write_bytes(corrupt)

    loaded = FingerprintIndex.load(store)  # 绝不抛异常
    assert loaded is None

    # 集成侧标准重建流程：load 失败 → 重建 → 覆盖保存 → 恢复命中
    rebuilt = FingerprintIndex()
    rebuilt.add_repo(repo)
    rebuilt.save(store)
    assert FingerprintIndex.load(store) is not None


def test_load_window_mismatch_returns_none(tmp_path: Path) -> None:
    """切片规范（win）不符的库拒绝复用 → 重建。"""
    repo = _make_repo(tmp_path / "proj", {"app.py": TEXT_A})
    store = tmp_path / FINGERPRINTS_FILE_NAME
    index = FingerprintIndex(window=4)
    index.add_repo(repo)
    index.save(store)
    assert FingerprintIndex.load(store, window=8) is None
    ok = FingerprintIndex.load(store, window=4)
    assert ok is not None and ok.window == 4


# ----------------------------------------------------------------------- 上限


def test_max_file_bytes_skips_large_file(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path / "proj", {"big.py": TEXT_A, "small.py": TEXT_B})
    # 上限取 TEXT_B 的字节数：TEXT_A（更大）被跳过，TEXT_B（恰好等于上限）保留
    index = FingerprintIndex(max_file_bytes=len(TEXT_B.encode("utf-8")))
    stats = index.add_repo(repo)
    assert stats.files_skipped_too_large == 1
    assert stats.files_indexed == 1
    assert stats.slices_added == len(LINES_B) - 7
    assert index.scan_body("\n".join(LINES_A[:8])) == []  # 大文件内容未入库
    assert len(index.scan_body("\n".join(LINES_B[:8]))) == 1


def test_max_slices_caps_total_slices(tmp_path: Path) -> None:
    """总片上限：达上限立即停，后续文件不再读（防 OOM）。"""
    repo = _make_repo(tmp_path / "proj", {"a.py": TEXT_A, "b.py": TEXT_B})
    index = FingerprintIndex(max_slices=5)
    stats = index.add_repo(repo)
    assert stats.slice_cap_reached is True
    assert stats.slices_added == 5
    assert stats.total_slices == index.total_slices == 5
    assert stats.files_indexed == 1  # a.py 半途截止，b.py 未读
    assert index.scan_body("\n".join(LINES_A[:8])), "已入库的片仍可命中"
    assert index.scan_body("\n".join(LINES_B[:8])) == []


def test_add_repo_after_cap_short_circuits(tmp_path: Path) -> None:
    r1 = _make_repo(tmp_path / "r1", {"a.py": TEXT_A})
    r2 = _make_repo(tmp_path / "r2", {"b.py": TEXT_B})
    index = FingerprintIndex(max_slices=1)
    index.add_repo(r1)
    stats = index.add_repo(r2)  # 已达上限：短路不读文件
    assert stats.files_indexed == 0
    assert stats.slice_cap_reached is True
    assert stats.slices_added == 0
    assert "r2" not in index.repos


def test_binary_file_skipped(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path / "proj",
        {"app.py": TEXT_A, "logo.png": b"PNG\x00\x00\x01" + b"\x00" * 64},
    )
    index = FingerprintIndex()
    stats = index.add_repo(repo)
    assert stats.files_skipped_binary == 1
    assert stats.files_indexed == 1


def test_reader_error_counted_not_fatal(tmp_path: Path) -> None:
    """可注入读取器：抛 OSError 的文件按跳过计数，建库不中断。"""
    repo = _make_repo(tmp_path / "proj", {"app.py": TEXT_A, "lib/util.py": TEXT_B})

    def failing_reader(path: Path) -> bytes:
        raise PermissionError(f"注入的读取失败：{path}")

    index = FingerprintIndex()
    stats = index.add_repo(repo, reader=failing_reader)
    assert stats.files_errored == 2
    assert stats.files_indexed == 0
    assert index.total_slices == 0


def test_reader_injection_changes_content(tmp_path: Path) -> None:
    """可注入读取器：改写内容（大写化）→ 指纹随之变化且可命中。"""
    repo = _make_repo(tmp_path / "proj", {"app.py": TEXT_A})

    def upper_reader(path: Path) -> bytes:
        return path.read_bytes().upper()

    index = FingerprintIndex()
    index.add_repo(repo, reader=upper_reader)
    assert index.scan_body(TEXT_A) == []  # 原文不再命中
    hits = index.scan_body(TEXT_A.upper())
    assert hits and hits[0].file == "app.py"


# ------------------------------------------------------------------- 杂项红线


def test_git_dir_content_never_indexed(tmp_path: Path) -> None:
    """.git 目录内容（如 Objects 里的源码副本）不进指纹。"""
    git_like = "\n".join([f"gitobj_{i}" for i in range(1, 13)]) + "\n"
    repo = _make_repo(
        tmp_path / "proj",
        {"app.py": TEXT_A, ".git/objects/leak.py": git_like},
    )
    index = FingerprintIndex()
    index.add_repo(repo)
    assert index.scan_body("\n".join(git_like.splitlines()[:8])) == []
    assert index.scan_body("\n".join(LINES_A[:8]))


def test_fingerprint_hit_frozen() -> None:
    hit = FingerprintHit(repo="r", file="f", line=1, snippet="s")
    with pytest.raises(Exception, match="frozen"):
        hit.line = 2  # type: ignore[misc]
