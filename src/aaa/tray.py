"""系统托盘（06 文档 W2）：pystray 托盘图标 + 菜单，代理/面板快捷操作（v0.3.0）。

菜单项（06 文档 W2）：
- **状态**：只读展示自检结果（复用 ``setup/watchdog`` 的判定语义：idle/ok/degraded，
  读 journal + 探测代理端口；**不写 watchdog.log**，托盘状态展示零副作用）；
- **打开面板**：起 ``aaa web`` 子进程（端口已被占用则只提示面板地址，不重复拉起）；
- **启动代理**：复用 ``setup.autostart.spawn_run_now`` 后台启动 ``aaa run``；
- **重启代理**：v1 保守语义 = spawn 新进程 + 提示「旧进程需 ``aaa teardown``
  或结束进程树停止」（不自动杀进程，避免误伤）；
- **退出**：``icon.stop()``。

红线：
- **lazy import**：pystray/Pillow 只允许在函数体内导入，模块顶层绝不 import——
  未安装依赖时 ``run_tray`` 给出 pip 安装提示并以退出码 2 返回，绝不崩栈；
- **全注入式**：pystray 的 Icon/Menu/MenuItem 经 ``icon_factory``/``menu_cls``/
  ``item_cls`` 注入（缺省在依赖加载成功后才从 pystray 取），子进程经 ``_popen``/
  ``_spawn_run_now`` 注入，端口探测经 ``_port_open`` 注入；单测绝不真起托盘；
- **托盘是只读编排层**：自身绝不改系统代理/证书/环境变量等设置。
"""

from __future__ import annotations

import io
import logging
import os
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from aaa.config import DEFAULT_WEB_PORT, PROJECT_ROOT
from aaa.setup import watchdog
from aaa.setup.autostart import spawn_run_now
from aaa.setup.state import StateFile

if TYPE_CHECKING:  # 仅类型检查用：运行时 Pillow 为可选依赖（lazy 红线）
    from PIL import Image

logger = logging.getLogger(__name__)

#: 托盘标题（托盘图标 name / 通知标题）
TRAY_TITLE = "EgressSentinel"

#: 托盘图标边长（px）
ICON_SIZE = 64

#: 依赖缺失（pystray/Pillow 未安装）时的退出码
MISSING_DEPS_EXIT_CODE = 2

#: 缺省图标绘制配色（取自 website/icon.svg 渐变中点色 + 白色描边）
SHIELD_BACKGROUND = (43, 214, 195, 255)  # #2BD6C3
SHIELD_STROKE = (255, 255, 255, 255)

#: CLI 子进程引导（与 autostart_command 同策略：typer 入口经 -c 调 main()）
_CLI_BOOTSTRAP = "from aaa.cli import main; main()"

#: 网站资源目录中的位图图标候选（svg 不可栅格化时的回退，与 svg 同源）
_WEBSITE_PNG_CANDIDATES = ("icon-192.png", "icon-512.png", "icon-180.png")


class TrayDependencyError(RuntimeError):
    """pystray/Pillow 可选依赖缺失（消息含 pip 安装提示）。"""


def _deps_hint(dep: str) -> str:
    """构造缺依赖的用户提示（含 pip 安装指引）。"""
    return (
        f"{dep} 未安装，托盘功能不可用。请执行：pip install -e .[tray]"
        f"（或 pip install pystray Pillow）后重试。"
    )


def _load_tray_deps() -> tuple[Any, Any]:
    """lazy 导入 pystray 与 Pillow，返回 ``(pystray_module, PIL.Image)``。

    红线：本函数是唯一合法的 pystray/PIL 导入点；任一缺失即抛
    ``TrayDependencyError``（含 pip 提示），由 ``run_tray`` 转为退出码 2。
    """
    try:
        import pystray
    except ImportError as exc:
        raise TrayDependencyError(_deps_hint("pystray")) from exc
    try:
        from PIL import Image
    except ImportError as exc:
        raise TrayDependencyError(_deps_hint("Pillow")) from exc
    return pystray, Image


class TraySettings(BaseModel):
    """托盘运行配置（pydantic 校验；波次二由 ``aaa tray`` 命令构造）。"""

    data_dir: Path
    web_port: int = Field(default=DEFAULT_WEB_PORT, ge=1, le=65535)
    title: str = TRAY_TITLE
    website_dir: Path = Field(default_factory=lambda: resolve_website_dir())


def resolve_website_dir() -> Path:
    """定位网站资源目录（图标来源）：frozen 优先 _MEIPASS，源码为 ``<项目根>/website``。"""
    if getattr(sys, "frozen", False):
        bundle = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent)) / "website"
        if bundle.is_dir():
            return bundle
        return Path(sys.executable).resolve().parent / "website"
    return PROJECT_ROOT / "website"


def _cli_command(args: list[str]) -> tuple[str, list[str]]:
    """构造 ``aaa <args>`` 子进程命令行（与 ``autostart_command`` 相同解释器策略）。

    frozen：exe 本体即 CLI；源码：pythonw（无窗口，托盘场景无控制台），
    pythonw 不存在则退回当前解释器。
    """
    if getattr(sys, "frozen", False):
        return sys.executable, list(args)
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    launcher = str(pythonw if pythonw.exists() else Path(sys.executable))
    return launcher, ["-c", _CLI_BOOTSTRAP, *args]


def panel_command(settings: TraySettings) -> tuple[str, list[str]]:
    """「打开面板」的 ``aaa web`` 命令行（仅监听 127.0.0.1，端口取配置）。"""
    args = [
        "web",
        "--data-dir",
        str(settings.data_dir),
        "--port",
        str(settings.web_port),
    ]
    return _cli_command(args)


def _spawn_detached(
    command_line: tuple[str, list[str]],
    _popen: Callable[..., subprocess.Popen[str]],
) -> subprocess.Popen[str]:
    """脱离当前控制台启动子进程（Windows DETACHED_PROCESS，托盘退出不受影响）。"""
    command, args = command_line
    creationflags = 0
    if os.name == "nt":
        creationflags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    return _popen(
        [command, *args],
        creationflags=creationflags,
        close_fds=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


# --------------------------------------------------------------------------
# 图标：icon.svg 优先（有渲染后端时）→ website PNG → 纯色盾形绘制
# --------------------------------------------------------------------------


def _svg_to_png_default(data: bytes, size: int) -> bytes:
    """SVG 栅格化缺省实现：经 cairosvg（**非声明依赖**，环境可选安装）。

    Pillow 本身不支持 SVG 渲染；环境无 cairosvg 时抛 ImportError，
    ``load_tray_icon`` 回退到 PNG / 纯色盾形绘制（见 decisions 记录）。
    """
    import cairosvg  # lazy：可选渲染后端，缺失则走回退路径

    return cairosvg.svg2png(bytestring=data, output_width=size, output_height=size)


def draw_shield_icon(size: int = ICON_SIZE) -> Image.Image:
    """缺省图标：纯色圆角底 + 白色盾形描边 + 白色外发箭头（Pillow 原语绘制）。

    几何近似 ``website/icon.svg``（盾形曲线以直线段近似，64px 下视觉等价）。
    """
    from PIL import Image, ImageDraw

    scale = size / 64.0
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.rounded_rectangle(
        [0, 0, size - 1, size - 1],
        radius=max(2, round(14 * scale)),
        fill=SHIELD_BACKGROUND,
    )
    stroke_width = max(2, round(3.6 * scale))
    # 盾形描边：M32 11 L46 17.5 V31 C46 41.5 39.5 49 32 52.5 C24.5 49 18 41.5 18 31 V17.5 Z
    shield = [
        (32.0, 11.0),
        (46.0, 17.5),
        (46.0, 31.0),
        (41.0, 44.0),
        (32.0, 52.5),
        (23.0, 44.0),
        (18.0, 31.0),
        (18.0, 17.5),
    ]
    draw.line(
        [*shield, shield[0]],
        fill=SHIELD_STROKE,
        width=stroke_width,
        joint="curve",
    )
    # 外发箭头：M25.5 38.5 L37.5 26.5 与箭头头部 M30.5 25.5 H38 V33
    draw.line([(25.5, 38.5), (37.5, 26.5)], fill=SHIELD_STROKE, width=stroke_width)
    draw.line(
        [(30.5, 25.5), (38.0, 25.5), (38.0, 33.0)],
        fill=SHIELD_STROKE,
        width=stroke_width,
        joint="curve",
    )
    return img


def load_tray_icon(
    website_dir: Path,
    *,
    size: int = ICON_SIZE,
    _svg_to_png: Callable[[bytes, int], bytes] | None = _svg_to_png_default,
) -> Image.Image:
    """加载托盘图标：icon.svg（有渲染后端）→ website 位图 → 纯色盾形绘制。

    任何一路失败都降级到下一路（记 debug 日志），保证托盘总能拿到一张图。
    """
    from PIL import Image

    svg_path = website_dir / "icon.svg"
    if svg_path.exists() and _svg_to_png is not None:
        try:
            png_bytes = _svg_to_png(svg_path.read_bytes(), size)
            img = Image.open(io.BytesIO(png_bytes)).convert("RGBA")
            if img.size != (size, size):
                img = img.resize((size, size))
            return img
        except Exception:  # noqa: BLE001 - 渲染失败仅降级，不影响托盘启动
            logger.debug("icon.svg 渲染失败，回退位图/绘制：%s", svg_path, exc_info=True)

    for name in _WEBSITE_PNG_CANDIDATES:
        png_path = website_dir / name
        if png_path.exists():
            try:
                return Image.open(png_path).convert("RGBA")
            except Exception:  # noqa: BLE001 - 同上，降级不中断
                logger.debug("托盘位图加载失败：%s", png_path, exc_info=True)

    return draw_shield_icon(size)


# --------------------------------------------------------------------------
# 状态只读展示（复用 watchdog 判定语义，零副作用）
# --------------------------------------------------------------------------


def status_text(
    state_file: Path,
    *,
    _port_open: Callable[[str, int], bool] = watchdog.port_open,
) -> str:
    """托盘「状态」菜单文案：读 setup journal + 探测代理端口（**只读，不写日志**）。

    判定与 ``setup/watchdog`` 三态一致（idle/ok/degraded）；托盘展示不追加
    ``data/watchdog.log``（自检日志仍由 ``aaa watchdog`` 负责）。
    """
    entries = StateFile(state_file).entries()
    endpoint = watchdog.proxy_endpoint(entries)
    if endpoint is None:
        return "状态：未托管系统代理（journal 无代理记录）"
    host, port = endpoint
    if _port_open(host, port):
        return f"状态：代理运行中（{host}:{port} 可达）"
    return (
        f"状态：异常——系统代理仍指向 {host}:{port} 但不可达。"
        f"恢复：aaa watchdog --fix 或 aaa teardown proxy。"
    )


# --------------------------------------------------------------------------
# 菜单回调装配（签名与 pystray 约定一致：action(icon, item)）
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class TrayActions:
    """菜单回调集合；全部接收 pystray 传入的 ``(icon, item)``。"""

    open_panel: Callable[..., None]
    start_proxy: Callable[..., None]
    restart_proxy: Callable[..., None]
    quit_tray: Callable[..., None]


def _notify(icon: Any, message: str, title: str) -> None:
    """托盘气泡通知；通知失败只记 debug（不打断菜单动作）。"""
    try:
        icon.notify(message, title)
    except Exception:  # noqa: BLE001 - 通知失败不影响主流程
        logger.debug("托盘通知失败：%s", message, exc_info=True)


def make_actions(
    settings: TraySettings,
    *,
    _popen: Callable[..., subprocess.Popen[str]] = subprocess.Popen,
    _spawn_run_now: Callable[..., Any] = spawn_run_now,
    _port_open: Callable[[str, int], bool] = watchdog.port_open,
) -> TrayActions:
    """装配四个菜单回调（闭包持有 settings；系统级操作全走注入点）。"""
    title = settings.title

    def open_panel(icon: Any, item: Any) -> None:
        url = f"http://127.0.0.1:{settings.web_port}"
        try:
            if _port_open("127.0.0.1", settings.web_port):
                _notify(icon, f"面板已在运行：{url}", title)
                return
            _spawn_detached(panel_command(settings), _popen)
            _notify(icon, f"面板启动中：{url}", title)
        except OSError as exc:
            _notify(icon, f"面板启动失败：{exc}", title)

    def start_proxy(icon: Any, item: Any) -> None:
        try:
            _spawn_run_now(settings.data_dir)
            _notify(icon, "已后台启动代理（aaa run）；日志见 data/autostart.log", title)
        except OSError as exc:
            _notify(icon, f"代理启动失败：{exc}", title)

    def restart_proxy(icon: Any, item: Any) -> None:
        # v1 保守语义（06 文档 W2）：spawn 新进程 + 提示旧进程的停止方式，不自动杀进程
        try:
            _spawn_run_now(settings.data_dir)
            _notify(
                icon,
                "已启动新代理进程。旧进程未自动停止：请运行 aaa teardown 或"
                "结束旧进程树后再试（避免误杀）。",
                title,
            )
        except OSError as exc:
            _notify(icon, f"代理重启失败：{exc}", title)

    def quit_tray(icon: Any, item: Any) -> None:
        icon.stop()

    return TrayActions(
        open_panel=open_panel,
        start_proxy=start_proxy,
        restart_proxy=restart_proxy,
        quit_tray=quit_tray,
    )


def build_menu(
    settings: TraySettings,
    actions: TrayActions,
    *,
    menu_cls: Any,
    item_cls: Any,
) -> Any:
    """构建托盘菜单（pystray 对象经 menu_cls/item_cls 注入）。

    「状态」行只读展示：text 为 callable，pystray 每次打开菜单时实时求值
    （``status_text``），action=None 且 enabled=False（不可点击）。
    """
    state_file = settings.data_dir / "setup-state.json"
    return menu_cls(
        [
            item_cls(lambda item: status_text(state_file), None, enabled=False),
            item_cls("打开面板", actions.open_panel),
            item_cls("启动代理", actions.start_proxy),
            item_cls("重启代理", actions.restart_proxy),
            item_cls("退出", actions.quit_tray),
        ]
    )


def run_tray(
    data_dir: str | os.PathLike[str],
    *,
    web_port: int = DEFAULT_WEB_PORT,
    title: str = TRAY_TITLE,
    website_dir: Path | None = None,
    icon_factory: Callable[..., Any] | None = None,
    menu_cls: Any = None,
    item_cls: Any = None,
    _deps_loader: Callable[[], tuple[Any, Any]] = _load_tray_deps,
    _popen: Callable[..., subprocess.Popen[str]] = subprocess.Popen,
    _spawn_run_now: Callable[..., Any] = spawn_run_now,
    _port_open: Callable[[str, int], bool] = watchdog.port_open,
) -> int:
    """运行托盘主循环（阻塞至「退出」），返回进程退出码。

    - 依赖缺失：打印 pip 提示并返回 ``MISSING_DEPS_EXIT_CODE``（2），绝不崩栈；
    - 正常退出（用户点「退出」→ ``icon.stop()``）返回 0；
    - pystray Icon/Menu/MenuItem 全注入（``icon_factory``/``menu_cls``/``item_cls``，
      缺省在依赖加载成功后才从 pystray 取），单测替换为假实现，不真起托盘。
    """
    try:
        pystray_mod, _image_mod = _deps_loader()
    except TrayDependencyError as exc:
        from rich.console import Console

        Console(stderr=True).print(f"[red]{exc}[/red]")
        logger.warning("托盘依赖缺失：%s", exc)
        return MISSING_DEPS_EXIT_CODE

    settings = TraySettings(
        data_dir=Path(data_dir), web_port=web_port, title=title, website_dir=website_dir
    )
    actions = make_actions(
        settings, _popen=_popen, _spawn_run_now=_spawn_run_now, _port_open=_port_open
    )
    menu = build_menu(
        settings,
        actions,
        menu_cls=menu_cls if menu_cls is not None else pystray_mod.Menu,
        item_cls=item_cls if item_cls is not None else pystray_mod.MenuItem,
    )
    image = load_tray_icon(settings.website_dir)
    icon = (icon_factory or pystray_mod.Icon)(settings.title, image, menu)
    icon.run()  # 阻塞至回调 quit_tray 调 icon.stop()
    return 0
