"""PyInstaller 打包入口：``dist/ai-agent-audit.exe`` 的程序入口指向 ``aaa`` CLI。

（build_exe.py 以本文件作为 onefile 分析起点；保持极薄，仅转发到 aaa.cli:main。）
"""

from aaa.cli import main

if __name__ == "__main__":
    main()
