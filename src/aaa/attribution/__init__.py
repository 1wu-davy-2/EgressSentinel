"""进程归因层（02 文档 §2 ``aaa.attribution``）。"""

from aaa.attribution.table import (
    ConnectionEntry,
    ConnectionTable,
    ProcessAttributor,
    ProcessIdentity,
    PsutilConnectionTable,
    PsutilProcessInfoReader,
    classify_profile,
    read_file_company,
    resolve_pinned_process,
)

__all__ = [
    "ConnectionEntry",
    "ConnectionTable",
    "ProcessAttributor",
    "ProcessIdentity",
    "PsutilConnectionTable",
    "PsutilProcessInfoReader",
    "classify_profile",
    "read_file_company",
    "resolve_pinned_process",
]
