"""托盘（W2）单测：pystray/子进程/端口探测全注入，绝不真起托盘、绝不真起进程。

红线覆盖：
- 模块导入零 GUI 依赖（pystray/PIL 顶层导入即违规）；
- 缺依赖 → pip 提示 + 退出码 2；
- 菜单构建/回调装配/图标降级路径；
- 状态展示只读（不写 watchdog.log）。
"""

from __future__ import annotations

import importlib.util
import io
import subprocess
import sys
import types
from pathlib import Path

import pytest
from pydantic import ValidationError

from aaa import tray as tray_mod
from aaa.setup.proxy import KIND_WININET
from aaa.setup.state import StateFile
from aaa.tray import (
    MISSING_DEPS_EXIT_CODE,
    SHIELD_BACKGROUND,
    SHIELD_STROKE,
    TrayDependencyError,
    TraySettings,
    build_menu,
    draw_shield_icon,
    load_tray_icon,
    make_actions,
    panel_command,
    run_tray,
    status_text,
)


def _pystray_installed() -> bool:
    """当前环境是否装了 pystray（真实缺依赖路径的测试仅在未装时运行）。"""
    return importlib.util.find_spec("pystray") is not None


class FakeIcon:
    """假 pystray.Icon：记录构造参数/通知/启停，绝不真起托盘。"""

    def __init__(self, name=None, image=None, menu=None) -> None:  # noqa: ANN001
        self.name = name
        self.image = image
        self.menu = menu
        self.notifications: list[tuple[str, str | None]] = []
        self.stopped = False
        self.ran = False

    def notify(self, message: str, title: str | None = None) -> None:
        self.notifications.append((message, title))

    def stop(self) -> None:
        self.stopped = True

    def run(self) -> None:
        self.ran = True


class FakeMenuItem:
    """假 pystray.MenuItem：与 build_menu 使用的实参签名一致。"""

    def __init__(self, text, action=None, enabled=True) -> None:  # noqa: ANN001
        self.text = text
        self.action = action
        self.enabled = enabled


class FakeMenu:
    """假 pystray.Menu：仅保存条目列表。"""

    def __init__(self, items) -> None:  # noqa: ANN001
        self.items = list(items)


class FakeSpawn:
    """假 spawn_run_now：记录 data_dir，绝不真起进程。"""

    def __init__(self) -> None:
        self.calls: list[Path] = []

    def __call__(self, data_dir: Path, **_kwargs: object) -> str:
        self.calls.append(Path(data_dir))
        return "fake-popen"


class FakePopen:
    """假 Popen：记录命令行与 kwargs，绝不真起进程。"""

    def __init__(self, *, raise_on_call: OSError | None = None) -> None:
        self.calls: list[tuple[list[str], dict[str, object]]] = []
        self.raise_on_call = raise_on_call

    def __call__(self, cmd: list[str], **kwargs: object) -> str:
        if self.raise_on_call is not None:
            raise self.raise_on_call
        self.calls.append((list(cmd), kwargs))
        return "fake-popen"


def _record_proxy(state: StateFile, server: str = "127.0.0.1:18080") -> None:
    state.record(
        kind=KIND_WININET,
        key="Internet Settings",
        old={"ProxyEnable": 0},
        new={"ProxyEnable": 1, "ProxyServer": server, "ProxyOverride": "<local>"},
    )


# --------------------------------------------------------------------------
# lazy import 红线
# --------------------------------------------------------------------------


def test_module_import_is_lazy() -> None:
    """红线：import aaa.tray 绝不拉起 pystray/PIL（独立子进程验证）。"""
    code = (
        "import sys; import aaa.tray; "
        "assert 'pystray' not in sys.modules, 'pystray 被顶层导入'; "
        "assert 'PIL' not in sys.modules, 'Pillow 被顶层导入'"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0, proc.stderr


def test_missing_deps_returns_exit_code_2_with_pip_hint(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """缺依赖：run_tray 返回退出码 2 并给出 pip 安装提示（不抛栈）。"""

    def _missing() -> tuple[object, object]:
        raise TrayDependencyError(tray_mod._deps_hint("pystray"))

    rc = run_tray(tmp_path, _deps_loader=_missing)
    assert rc == MISSING_DEPS_EXIT_CODE == 2
    err = capsys.readouterr().err
    assert "pip install" in err
    assert "pystray" in err


@pytest.mark.skipif(_pystray_installed(), reason="pystray 已安装，无法测真实缺依赖路径")
def test_real_env_missing_pystray_returns_2(tmp_path: Path) -> None:
    """真实环境校验（venv 未装 pystray）：走真导入路径也必须优雅返回 2。"""
    assert run_tray(tmp_path) == 2


@pytest.mark.skipif(_pystray_installed(), reason="pystray 已安装，无法测真实缺依赖路径")
def test_load_tray_deps_message_has_pip_hint() -> None:
    with pytest.raises(TrayDependencyError) as excinfo:
        tray_mod._load_tray_deps()
    assert "pystray" in str(excinfo.value)
    assert "pip install" in str(excinfo.value)


# --------------------------------------------------------------------------
# 图标：svg 优先 → 位图 → 纯色盾形绘制
# --------------------------------------------------------------------------


def test_draw_shield_icon_shape() -> None:
    """缺省盾形：尺寸/配色/圆角外透明，白描边与底色均存在。"""
    img = draw_shield_icon(64)
    assert img.size == (64, 64)
    assert img.mode == "RGBA"
    assert img.getpixel((0, 0)) == (0, 0, 0, 0)  # 圆角外透明
    assert img.getpixel((10, 32)) == SHIELD_BACKGROUND  # 底色（盾内、描边外）
    assert img.getpixel((32, 12)) == SHIELD_STROKE  # 盾顶描边
    colors = {color for _, color in img.getcolors(maxcolors=65536) or []}
    assert SHIELD_STROKE in colors
    assert SHIELD_BACKGROUND in colors


def test_png_fallback_used_without_svg(tmp_path: Path) -> None:
    """无 svg 时回退 website 位图（icon-192.png）。"""
    from PIL import Image as PILImage

    website = tmp_path / "website"
    website.mkdir()
    marker = (1, 2, 3, 255)
    PILImage.new("RGBA", (192, 192), marker).save(website / "icon-192.png")
    img = load_tray_icon(website)
    assert img.size == (192, 192)
    assert img.getpixel((0, 0)) == marker


def test_svg_preferred_when_renderer_available(tmp_path: Path) -> None:
    """有渲染后端：icon.svg 优先于位图（06 文档 W2 图标优先级）。"""
    from PIL import Image as PILImage

    website = tmp_path / "website"
    website.mkdir()
    (website / "icon.svg").write_bytes(b"<svg/>")
    PILImage.new("RGBA", (64, 64), (1, 2, 3, 255)).save(website / "icon-192.png")
    buf = io.BytesIO()
    PILImage.new("RGBA", (64, 64), (9, 9, 9, 255)).save(buf, format="PNG")
    png_bytes = buf.getvalue()

    img = load_tray_icon(website, _svg_to_png=lambda _data, _size: png_bytes)
    assert img.getpixel((0, 0)) == (9, 9, 9, 255)  # 来自 svg 渲染结果


def test_svg_renderer_failure_falls_back_to_png(tmp_path: Path) -> None:
    """渲染后端失败：降级到位图，托盘总能拿到图。"""
    from PIL import Image as PILImage

    website = tmp_path / "website"
    website.mkdir()
    (website / "icon.svg").write_bytes(b"<svg/>")
    marker = (1, 2, 3, 255)
    PILImage.new("RGBA", (64, 64), marker).save(website / "icon-192.png")

    def _boom(_data: bytes, _size: int) -> bytes:
        raise RuntimeError("renderer broken")

    img = load_tray_icon(website, _svg_to_png=_boom)
    assert img.getpixel((0, 0)) == marker


@pytest.mark.skipif(
    importlib.util.find_spec("cairosvg") is not None, reason="cairosvg 已安装，无法测无后端回退"
)
def test_svg_without_renderer_falls_back_to_png(tmp_path: Path) -> None:
    """真实缺省（无 cairosvg）：svg 存在也回退位图而非崩栈。"""
    from PIL import Image as PILImage

    website = tmp_path / "website"
    website.mkdir()
    (website / "icon.svg").write_bytes(b"<svg/>")
    marker = (1, 2, 3, 255)
    PILImage.new("RGBA", (64, 64), marker).save(website / "icon-192.png")
    img = load_tray_icon(website)
    assert img.getpixel((0, 0)) == marker


def test_icon_falls_back_to_drawing_on_empty_dir(tmp_path: Path) -> None:
    img = load_tray_icon(tmp_path)  # 空目录：无 svg 无位图
    assert img.size == (tray_mod.ICON_SIZE, tray_mod.ICON_SIZE)
    assert img.getpixel((10, 32)) == SHIELD_BACKGROUND


# --------------------------------------------------------------------------
# 状态只读展示（复用 watchdog 判定语义）
# --------------------------------------------------------------------------


def test_status_text_idle_ok_degraded(tmp_path: Path) -> None:
    state_path = tmp_path / "setup-state.json"
    assert "无代理记录" in status_text(state_path)  # idle

    state = StateFile(state_path)
    _record_proxy(state)
    assert "代理运行中" in status_text(state_path, _port_open=lambda _h, _p: True)
    degraded = status_text(state_path, _port_open=lambda _h, _p: False)
    assert "127.0.0.1:18080" in degraded
    assert "aaa watchdog --fix" in degraded


def test_status_display_writes_no_watchdog_log(tmp_path: Path) -> None:
    """红线：托盘状态展示零副作用——不追加 watchdog.log。"""
    state_path = tmp_path / "setup-state.json"
    state = StateFile(state_path)
    _record_proxy(state)
    status_text(state_path, _port_open=lambda _h, _p: False)
    assert not (tmp_path / "watchdog.log").exists()


# --------------------------------------------------------------------------
# 菜单构建与回调装配
# --------------------------------------------------------------------------


def test_build_menu_wires_items(tmp_path: Path) -> None:
    settings = TraySettings(data_dir=tmp_path)
    actions = make_actions(settings, _popen=FakePopen(), _spawn_run_now=FakeSpawn())
    menu = build_menu(settings, actions, menu_cls=FakeMenu, item_cls=FakeMenuItem)

    texts = [i.text if isinstance(i.text, str) else "<callable>" for i in menu.items]
    assert texts == ["<callable>", "打开面板", "启动代理", "重启代理", "退出"]

    status_item = menu.items[0]
    assert status_item.action is None and status_item.enabled is False
    assert callable(status_item.text)

    assert menu.items[1].action is actions.open_panel
    assert menu.items[2].action is actions.start_proxy
    assert menu.items[3].action is actions.restart_proxy
    assert menu.items[4].action is actions.quit_tray
    assert all(i.enabled for i in menu.items[1:])


def test_status_item_text_resolves_live(tmp_path: Path) -> None:
    """状态行 callable 实时求值：打开菜单时按 journal/端口现算。"""
    state_path = tmp_path / "setup-state.json"
    state = StateFile(state_path)
    _record_proxy(state)
    settings = TraySettings(data_dir=tmp_path)
    menu = build_menu(
        settings,
        make_actions(settings, _popen=FakePopen(), _spawn_run_now=FakeSpawn()),
        menu_cls=FakeMenu,
        item_cls=FakeMenuItem,
    )
    text = menu.items[0].text(None)
    assert "127.0.0.1:18080" in text
    assert "不可达" in text  # 默认 _port_open 探测：18080 无服务在听


def test_start_proxy_spawns_and_notifies(tmp_path: Path) -> None:
    spawn = FakeSpawn()
    icon = FakeIcon()
    actions = make_actions(TraySettings(data_dir=tmp_path), _spawn_run_now=spawn)
    actions.start_proxy(icon, None)
    assert spawn.calls == [tmp_path]
    assert icon.notifications and "aaa run" in icon.notifications[0][0]


def test_open_panel_spawns_web_when_port_closed(tmp_path: Path) -> None:
    popen = FakePopen()
    icon = FakeIcon()
    settings = TraySettings(data_dir=tmp_path, web_port=8123)
    actions = make_actions(settings, _popen=popen, _port_open=lambda _h, _p: False)
    actions.open_panel(icon, None)

    assert len(popen.calls) == 1
    cmd, kwargs = popen.calls[0]
    assert "web" in cmd
    assert "--port" in cmd and "8123" in cmd
    assert "--data-dir" in cmd and str(tmp_path) in cmd
    assert kwargs["creationflags"] != 0  # DETACHED_PROCESS（Windows 下）
    assert icon.notifications and "127.0.0.1:8123" in icon.notifications[0][0]


def test_open_panel_skips_spawn_when_port_open(tmp_path: Path) -> None:
    popen = FakePopen()
    icon = FakeIcon()
    actions = make_actions(
        TraySettings(data_dir=tmp_path, web_port=8787), _popen=popen, _port_open=lambda _h, _p: True
    )
    actions.open_panel(icon, None)
    assert popen.calls == []  # 面板已在运行：不重复拉起
    assert icon.notifications and "已在运行" in icon.notifications[0][0]


def test_open_panel_failure_notifies_without_raise(tmp_path: Path) -> None:
    popen = FakePopen(raise_on_call=OSError("no launcher"))
    icon = FakeIcon()
    actions = make_actions(
        TraySettings(data_dir=tmp_path), _popen=popen, _port_open=lambda _h, _p: False
    )
    actions.open_panel(icon, None)  # 不抛异常
    assert icon.notifications and "失败" in icon.notifications[0][0]


def test_restart_proxy_spawns_with_teardown_hint(tmp_path: Path) -> None:
    spawn = FakeSpawn()
    icon = FakeIcon()
    actions = make_actions(TraySettings(data_dir=tmp_path), _spawn_run_now=spawn)
    actions.restart_proxy(icon, None)
    assert spawn.calls == [tmp_path]
    hint = icon.notifications[0][0]
    assert "aaa teardown" in hint  # v1 保守语义：spawn + 提示旧进程停止方式
    assert "未自动停止" in hint


def test_quit_stops_icon() -> None:
    icon = FakeIcon()
    actions = make_actions(TraySettings(data_dir=Path(".")), _popen=FakePopen())
    actions.quit_tray(icon, None)
    assert icon.stopped is True


def test_panel_command_uses_pythonw_strategy(tmp_path: Path) -> None:
    """源码运行：面板子进程用 pythonw（无窗口）+ -c 引导 typer 入口。"""
    settings = TraySettings(data_dir=tmp_path, web_port=8787)
    command, args = panel_command(settings)
    assert Path(command).exists()
    assert Path(command).name == "pythonw.exe"
    assert args[0] == "-c" and args[1] == tray_mod._CLI_BOOTSTRAP
    assert "web" in args
    assert "--port" in args and "8787" in args


# --------------------------------------------------------------------------
# run_tray 全装配（注入假 pystray 模块，不真起托盘）
# --------------------------------------------------------------------------


def test_run_tray_full_assembly_with_fakes(tmp_path: Path) -> None:
    fake_pystray = types.SimpleNamespace(Menu=FakeMenu, MenuItem=FakeMenuItem)
    created: list[FakeIcon] = []

    def factory(name: str, image: object, menu: object) -> FakeIcon:
        icon = FakeIcon(name, image, menu)
        created.append(icon)
        return icon

    rc = run_tray(
        tmp_path,
        website_dir=tmp_path,  # 空目录 → 缺省盾形图（Pillow 已装，可真实渲染）
        icon_factory=factory,
        _deps_loader=lambda: (fake_pystray, None),
    )

    assert rc == 0
    assert len(created) == 1
    icon = created[0]
    assert icon.ran is True  # icon.run() 被调用（阻塞主循环）
    assert icon.name == "EgressSentinel"
    assert icon.image is not None and icon.image.mode == "RGBA"
    assert len(icon.menu.items) == 5
    icon.menu.items[4].action(icon, None)  # 「退出」回调 → icon.stop()
    assert icon.stopped is True


def test_tray_settings_validation(tmp_path: Path) -> None:
    settings = TraySettings(data_dir=tmp_path)
    assert settings.web_port == 8787
    assert settings.title == "EgressSentinel"

    with pytest.raises(ValidationError):
        TraySettings(data_dir=tmp_path, web_port=0)  # 端口越界
    with pytest.raises(ValidationError):
        TraySettings(data_dir=tmp_path, web_port=70000)

    coerced = TraySettings(data_dir=str(tmp_path))  # str → Path 自动转换
    assert coerced.data_dir == tmp_path
