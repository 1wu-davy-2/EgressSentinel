"""静态页服务（T5.2：原生 JS 静态页，不引入重前端框架）。"""

from __future__ import annotations

from pathlib import Path

from fastapi.responses import FileResponse, PlainTextResponse

#: 静态资源目录（随包分发；PyInstaller 打包需包含该目录）
STATIC_DIR = Path(__file__).resolve().parent / "static"


def index_page() -> FileResponse | PlainTextResponse:
    """返回面板首页；静态资源缺失时给出可诊断的错误页（不 500 崩溃）。"""
    index = STATIC_DIR / "index.html"
    if index.is_file():
        return FileResponse(index, media_type="text/html; charset=utf-8")
    return PlainTextResponse(
        "面板静态资源缺失（src/aaa/web/static/index.html）。"
        "请重新安装或检查打包配置（build_exe.py datas）。",
        status_code=500,
    )


__all__ = ["STATIC_DIR", "index_page"]
