"""T0.3 local 模式 spike 脚本。

- 检测当前是否管理员（ctypes，``aaa.setup.admin``）；
- 非管理员：**绝不**运行 ``--mode local``，只打印依赖检查与结论；
- 管理员（显式传 ``--run``）：真正启动 ``aaa run --mode local``，人工观察后 Ctrl+C。

用法：
    python scripts/local_mode_spike.py            # 只做检测，不动系统
    python scripts/local_mode_spike.py --run      # 管理员下实际运行 local 模式
"""

from __future__ import annotations

import argparse
import sys

from aaa.capture.engine import _validate_mode
from aaa.setup.admin import is_current_process_elevated


def _dependency_report() -> list[str]:
    lines: list[str] = []
    try:
        from mitmproxy import version

        lines.append(f"mitmproxy {version.VERSION}")
    except Exception as exc:  # noqa: BLE001
        lines.append(f"mitmproxy 导入失败：{exc}")
    try:
        from mitmproxy_rs import local as rs_local

        redirector = rs_local.LocalRedirector is not None
        lines.append(f"mitmproxy_rs.local 可导入（LocalRedirector={redirector}）")
    except Exception as exc:  # noqa: BLE001
        lines.append(f"mitmproxy_rs.local 导入失败（WinDivert 封装缺失？）：{exc}")
    try:
        _validate_mode("local")
        lines.append("engine 模式规格 local 可解析（ProxyConfig/_validate_mode）")
    except Exception as exc:  # noqa: BLE001
        lines.append(f"engine 模式规格解析失败：{exc}")
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description="local 模式 spike（T0.3）")
    parser.add_argument(
        "--run",
        action="store_true",
        help="实际运行 aaa run --mode local（仅管理员；非管理员直接拒绝）",
    )
    args = parser.parse_args()

    elevated = is_current_process_elevated()
    print(f"管理员（IsUserAnAdmin/TokenElevation）：{elevated}")
    for line in _dependency_report():
        print(f"  - {line}")

    if not elevated:
        print("结论：非管理员会话，按 T0.3 与安全红线【未运行 --mode local】。")
        print("代码路径已实现，需管理员环境人工验证：见 docs/notes/local-mode-spike.md。")
        return 0
    if not args.run:
        print("当前已是管理员。加 --run 实际运行 local 模式（人工观察，Ctrl+C 退出）。")
        return 0
    print("以管理员运行 aaa run --mode local ...")
    from aaa.cli import app

    # typer app 直调：等价于 `aaa run --mode local`
    try:
        app(["run", "--mode", "local"], standalone_mode=False)
    except SystemExit as exc:  # typer 退出码
        return int(exc.code or 0)
    return 0


if __name__ == "__main__":
    sys.exit(main())
