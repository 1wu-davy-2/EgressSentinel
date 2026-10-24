"""build_exe.py 打包配置单测：hiddenimports/数据文件/入口齐全（不执行真实构建）。"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def build_exe():
    spec = importlib.util.spec_from_file_location("build_exe", PROJECT_ROOT / "build_exe.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["build_exe"] = module
    spec.loader.exec_module(module)
    return module


def test_entry_script_exists() -> None:
    entry = PROJECT_ROOT / "entry_aaa.py"
    assert entry.is_file()
    assert "aaa.cli" in entry.read_text(encoding="utf-8")


def test_hiddenimports_cover_mitmproxy_dynamic_imports(build_exe) -> None:  # type: ignore[name-defined]
    """任务卡要求：mitmproxy.addons.*、cryptography、brotli、kaitaistruct 等动态导入。"""
    hidden = build_exe.collect_hiddenimports()
    import mitmproxy.addons as addons_pkg

    addon_modules = {
        m.name
        for m in __import__("pkgutil").iter_modules(addons_pkg.__path__)
        if not m.name.startswith("_")
    }
    declared = {h.split(".")[-1] for h in hidden if h.startswith("mitmproxy.addons")}
    assert addon_modules <= declared, f"addons 隐藏导入遗漏：{addon_modules - declared}"
    for required in (
        "brotli",
        "kaitaistruct",
        "cryptography.hazmat.bindings._rust",
        "mitmproxy_rs",
        "mitmproxy.contrib.kaitaistruct.png",
        "mitmproxy.contrib.kaitaistruct.tls_client_hello",
    ):
        assert required in hidden, f"缺少 hidden-import：{required}"


def test_hiddenimports_deduplicated(build_exe) -> None:  # type: ignore[name-defined]
    hidden = build_exe.collect_hiddenimports()
    assert len(hidden) == len(set(hidden))


def test_datas_include_policy_and_static(build_exe) -> None:  # type: ignore[name-defined]
    datas = build_exe.collect_datas()
    joined = "; ".join(datas)
    assert "policies" in joined, "出厂默认策略必须随包"
    assert "static" in joined, "Web 面板静态页必须随包"


def test_build_args_shape(build_exe) -> None:  # type: ignore[name-defined]
    args = build_exe.build_args()
    text = " ".join(args)
    assert "--onefile" in text and "--name=ai-agent-audit" in text
    assert f"--distpath={build_exe.DIST_DIR}" in text
    assert "entry_aaa.py" in text
    hidden_args = [a for a in args if a.startswith("--hidden-import=")]
    assert len(hidden_args) == len(build_exe.collect_hiddenimports())
