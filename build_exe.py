"""PyInstaller 打包脚本（03 文档 T6.3 打包部分提前到本阶段交付）。

以编程方式调用 PyInstaller：onefile、name=ai-agent-audit、入口 ``entry_aaa.py``
（转发到 ``aaa.cli:main``），产物 ``dist/ai-agent-audit.exe``。

要点：
- **hiddenimports**：mitmproxy 存在动态导入面——``mitmproxy.addons.*``（42 个 addon
  模块）、``mitmproxy.contrib.kaitaistruct.*``（图片/ TLS hello 解析器，运行期按
  ``import_module`` 语义逐个取用）、cryptography 的 rust 后端、brotli 压缩、
  ``mitmproxy_rs``（WinDivert/local 模式）。本脚本用 ``pkgutil.iter_modules`` 在
  **构建期** 枚举并逐项声明，缺失的可选项自动跳过；
- **datas**：``policies/default.yaml``（出厂默认策略）与 Web 面板静态页
  （``src/aaa/web/static``）随包分发；frozen 路径解析见 ``aaa/config.py``；
- 运行方式：``python build_exe.py``（需 venv 内已装 pyinstaller）。

用法：``python build_exe.py [--no-clean]``；``--no-clean`` 保留 build/ 工作目录。
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import pkgutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
SRC_DIR = PROJECT_ROOT / "src"
DIST_DIR = PROJECT_ROOT / "dist"
BUILD_DIR = PROJECT_ROOT / "build"
ENTRY_SCRIPT = PROJECT_ROOT / "entry_aaa.py"
APP_NAME = "ai-agent-audit"

#: 确定存在的核心 hiddenimports（mitmproxy 动态导入面 + 压缩/加密后端）
_BASE_HIDDEN = [
    "brotli",
    "brotlicffi",  # brotli 缺失时的回退实现，缺失自动跳过
    "kaitaistruct",  # KaitaiStream（image/tls hello 解析依赖）
    "mitmproxy_rs",  # local 模式 WinDivert / 连接层
    "cryptography.hazmat.bindings._rust",  # cryptography 编译后端
]

#: web 面板依赖（可选 extra：未安装则跳过，exe 不含面板）
_WEB_HIDDEN = [
    "uvicorn",
    "uvicorn.logging",
    "uvicorn.loops",
    "uvicorn.loops.auto",
    "uvicorn.protocols",
    "uvicorn.protocols.http",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.protocols.websockets",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.protocols.websockets.wsproto_impl",
    "uvicorn.lifespan",
    "uvicorn.lifespan.on",
    "uvicorn.lifespan.off",
    "anyio._backends._asyncio",
]


def _installed(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError, ModuleNotFoundError):
        return False


def collect_hiddenimports() -> list[str]:
    """枚举 mitmproxy 动态导入面，返回去重后的 hiddenimports 清单。"""
    names: list[str] = list(_BASE_HIDDEN)

    def _add_pkg_modules(pkg_name: str) -> None:
        try:
            pkg = importlib.import_module(pkg_name)
        except ImportError:
            return
        names.append(pkg_name)
        for mod in pkgutil.iter_modules(pkg.__path__):  # type: ignore[attr-defined]
            if not mod.name.startswith("_"):
                names.append(f"{pkg_name}.{mod.name}")

    # mitmproxy.addons.*：mitmproxy/addons/__init__.py 静态导入全部 addon，
    # 但插件机制经 pluggy 反射注册，逐项声明保证零遗漏（任务卡要求）
    _add_pkg_modules("mitmproxy.addons")
    # mitmproxy.contentviews.*（_view_* 逐个 import）
    _add_pkg_modules("mitmproxy.contentviews")
    # 内置 kaitai 解析器（image_parser 按 contrib 子模块逐个 import）
    _add_pkg_modules("mitmproxy.contrib.kaitaistruct")

    if _installed("fastapi"):
        names.extend(_WEB_HIDDEN)
    names.append("aaa")
    # 去重保序
    deduped: list[str] = []
    seen: set[str] = set()
    for name in names:
        if name not in seen:
            seen.add(name)
            deduped.append(name)
    return deduped


def collect_datas() -> list[str]:
    """随包数据文件：出厂默认策略 + Web 面板静态页（``--add-data src<sep>dst`` 形态）。

    分隔符必须是当前平台的 ``os.pathsep``：Windows 为 ``;``，Linux/macOS 为 ``:``。
    """
    sep = os.pathsep
    datas: list[str] = []
    policies = PROJECT_ROOT / "policies"
    if policies.is_dir():
        datas.append(f"{policies}{sep}policies")
    static = SRC_DIR / "aaa" / "web" / "static"
    if static.is_dir():
        datas.append(f"{static}{sep}aaa/web/static")
    return datas


def build_args(*, no_clean: bool = False) -> list[str]:
    """组装 PyInstaller 命令行（以子进程调用，隔离内部状态、输出实时可见）。"""
    args = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--onefile",
        "--console",
        f"--name={APP_NAME}",
        f"--distpath={DIST_DIR}",
        f"--workpath={BUILD_DIR}",
        f"--specpath={PROJECT_ROOT}",
        f"--paths={SRC_DIR}",
    ]
    if not no_clean:
        # PyInstaller 无 --no-clean 选项：仅清理时传 --clean
        args.append("--clean")
    for hidden in collect_hiddenimports():
        args.append(f"--hidden-import={hidden}")
    for data in collect_datas():
        args.append(f"--add-data={data}")
    args.append(str(ENTRY_SCRIPT))
    return args


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-clean", action="store_true", help="保留 build/ 工作目录")
    options = parser.parse_args()

    if not _installed("PyInstaller"):
        print("PyInstaller 未安装：请先在 venv 内执行 pip install pyinstaller", file=sys.stderr)
        return 2
    if not ENTRY_SCRIPT.exists():
        print(f"入口脚本缺失：{ENTRY_SCRIPT}", file=sys.stderr)
        return 2
    args = build_args(no_clean=options.no_clean)
    print("PyInstaller 命令：")
    print("  " + " ".join(args))
    completed = subprocess.run(args, cwd=str(PROJECT_ROOT))
    # 非 Windows 平台 PyInstaller 产物无 .exe 后缀
    exe = DIST_DIR / (APP_NAME + (".exe" if os.name == "nt" else ""))
    if completed.returncode != 0 or not exe.exists():
        print(f"打包失败（exit={completed.returncode}），未生成 {exe}", file=sys.stderr)
        return 1
    size_mb = exe.stat().st_size / (1024 * 1024)
    print(f"打包完成：{exe}（{size_mb:.1f} MB）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
