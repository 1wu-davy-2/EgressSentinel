"""代码外泄扫描器（03 文档 T3.3）：本地绝对路径、代码密度启发、multipart 文件段、base64 大块。

- 代码密度 ``code_likeness``：代码特征行（import/def/class/函数定义/花括号等）占非空行比例，
  供策略 ``code_likeness_gt`` 条件（02 文档 §5 code-bulk-upload）；
- 全部纯函数、无网络调用。
"""

from __future__ import annotations

import re

from aaa.scanners.base import ScanHit, ScanResult

SCANNER_NAME = "code_leak"

#: Windows 盘符绝对路径（C:\Users\...、E:\tmp\...）
_WIN_PATH_RE = re.compile(r"\b[A-Za-z]:\\(?:[^\\\/:*?\"<>|\r\n]+\\)+[^\\\/:*?\"<>|\r\n]*")
#: POSIX 常见用户/项目目录绝对路径（/home/...、/Users/...、/root/...）
_POSIX_PATH_RE = re.compile(
    r"(?:/(?:home|Users|root|tmp|var|opt|mnt|srv)/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)+)"
)

#: 代码特征行（shebang / import / 定义 / 语句结尾分号 / 花括号密集）
_CODE_LINE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^\s*#!"),
    re.compile(r"^\s*(?:import|from)\s+\w+", re.MULTILINE),
    re.compile(r"^\s*(?:def|class|async\s+def|function|func|fn|const|let|var|package|using)\b"),
    re.compile(r"^\s*(?:public|private|protected|static|final|abstract)\s.*[\{;]"),
    re.compile(r"^\s*(?:#include|using\s+namespace)"),
    re.compile(r"^\s*(?:if|for|while|try|switch|elif|else)\s*[\(\{]"),
    re.compile(r"[\{\};]\s*$"),
    re.compile(r"^\s*(?:endif|endforeach|end)\b"),
    re.compile(r"^\s*//.*$"),
    re.compile(r"^\s*#.*$"),
)

#: 代码行特征：行内同时含运算符与括号（如 foo(bar(x))）
_OPERATOR_LINE_RE = re.compile(r"=|\(|\)|=>")

_MULTIPART_FILE_RE = re.compile(
    r"Content-Disposition:\s*form-data;[^\r\n]*filename\s*=\s*[\"']?([^\"'\r\n;]+)",
    re.IGNORECASE,
)

#: 超阈值 base64 块（默认 ≥ 200 连续 base64url 字符）
_BASE64_BLOCK_RE = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}|[A-Za-z0-9_-]{200,}")
#: 行内密花括号视为代码
_BRACE_LINE_RE = re.compile(r"^.*\{.*\}.*$")


def _mask(value: str, head: int = 24) -> str:
    value = value.strip()
    return value if len(value) <= head else value[:head] + "…"


def _code_likeness(text: str) -> float:
    """代码密度：代码特征行数 / 非空行数（0.0 - 1.0）。"""
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return 0.0
    code_lines = 0
    for line in lines:
        if any(p.search(line) for p in _CODE_LINE_PATTERNS):
            code_lines += 1
        elif _OPERATOR_LINE_RE.search(line) and _BRACE_LINE_RE.match(line):
            code_lines += 1
    return code_lines / len(lines)


def scan_code_leak(
    body: bytes | str | None,
    *,
    max_bytes: int | None = None,
    base64_min_length: int = 200,
) -> ScanResult:
    """扫描代码外泄特征，返回命中与 ``code_likeness`` 等指标。"""
    if not body:
        return ScanResult(
            scanner=SCANNER_NAME,
            metrics={
                "local_paths": 0.0,
                "multipart_files": 0.0,
                "base64_blocks": 0.0,
                "code_likeness": 0.0,
                "hits": 0.0,
            },
        )
    text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body
    if max_bytes is not None and len(text) > max_bytes:
        text = text[:max_bytes]

    hits: list[ScanHit] = []
    counts = {"local_paths": 0, "multipart_files": 0, "base64_blocks": 0}

    for lineno, line in enumerate(text.splitlines(), start=1):
        for match in _WIN_PATH_RE.finditer(line):
            counts["local_paths"] += 1
            hits.append(
                ScanHit(
                    SCANNER_NAME,
                    "windows-local-path",
                    _mask(match.group(0)),
                    lineno,
                    "Windows 本地路径",
                )
            )
        for match in _POSIX_PATH_RE.finditer(line):
            counts["local_paths"] += 1
            hits.append(
                ScanHit(
                    SCANNER_NAME,
                    "posix-local-path",
                    _mask(match.group(0)),
                    lineno,
                    "POSIX 本地路径",
                )
            )
        for match in _MULTIPART_FILE_RE.finditer(line):
            counts["multipart_files"] += 1
            hits.append(
                ScanHit(
                    SCANNER_NAME,
                    "multipart-file-upload",
                    _mask(match.group(1)),
                    lineno,
                    "multipart 文件上传段",
                )
            )
        for match in _BASE64_BLOCK_RE.finditer(line):
            if len(match.group(0)) < base64_min_length:
                continue
            counts["base64_blocks"] += 1
            hits.append(
                ScanHit(
                    SCANNER_NAME,
                    "base64-bulk-block",
                    _mask(match.group(0), head=12),
                    lineno,
                    "超阈值 base64 块",
                )
            )

    likeness = _code_likeness(text)
    metrics: dict[str, float] = {k: float(v) for k, v in counts.items()}
    metrics["code_likeness"] = round(likeness, 4)
    metrics["hits"] = float(len(hits))
    return ScanResult(scanner=SCANNER_NAME, hits=tuple(hits), metrics=metrics)
