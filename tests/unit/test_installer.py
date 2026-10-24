"""W3 安装器单测：.iss 关键段校验 + 版本注入脚本 + CI installer job 一致性（06 文档 W3）。

全部为静态文件校验与注入式脚本测试：不执行 iscc、不联网、不触碰系统设置。
对账三件事：teardown 卸载调用、版本占位、产物文件名与 build 产物名一致。
"""

from __future__ import annotations

import fnmatch
import importlib.util
import re
import sys
import tomllib
from pathlib import Path
from types import ModuleType

import pytest
import yaml

_REPO_ROOT = str(Path(__file__).resolve().parents[2])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import scripts.iss_version as iss_version  # noqa: E402

PROJECT_ROOT = Path(_REPO_ROOT)
ISS_PATH = PROJECT_ROOT / "installer" / "egress-sentinel.iss"
BUILD_YML = PROJECT_ROOT / ".github" / "workflows" / "build.yml"
#: installer job 下载的 build 产物 artifact 名（与 build job upload 模板解析结果必须一致）
EXE_ARTIFACT_NAME = "egress-sentinel-windows-amd64"
#: 安装包文件名模式（.iss OutputBaseFilename 与 build.yml upload/release 共用）
SETUP_GLOB = "dist/egress-sentinel-setup-*.exe"
#: AppId 固定 GUID（升级/卸载识别，永不改变）
APP_ID = "AppId={{7E0848AB-7AD7-47EE-AE66-9130DF75B025}"


# ---------------------------------------------------------------------------
# 夹具与小工具
# ---------------------------------------------------------------------------


@pytest.fixture
def iss_text() -> str:
    return ISS_PATH.read_text(encoding="utf-8-sig")


@pytest.fixture
def sections(iss_text: str) -> dict[str, list[str]]:
    """把 .iss 按 [Section] 标头切段（跳过空行与 ; 注释行），返回 {段名: [条目行]}。"""
    result: dict[str, list[str]] = {}
    current: list[str] = []
    for raw in iss_text.splitlines():
        line = raw.strip()
        if not line or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = result.setdefault(line[1:-1], [])
            continue
        current.append(line)
    return result


@pytest.fixture
def workflow() -> dict:
    """解析 build.yml（yaml.safe_load；注意 YAML 1.1 把 `on:` 解析成布尔 True 键）。"""
    data = yaml.safe_load(BUILD_YML.read_text(encoding="utf-8"))
    assert isinstance(data, dict), "build.yml 必须解析为映射"
    return data


@pytest.fixture
def build_exe() -> ModuleType:
    """加载 build_exe.py（只读对账 APP_NAME 等常量，不执行真实构建）。"""
    spec = importlib.util.spec_from_file_location(
        "build_exe_installer_check", PROJECT_ROOT / "build_exe.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _steps(job: dict) -> list[dict]:
    steps = job.get("steps")
    assert isinstance(steps, list), "job 必须有 steps"
    return steps


def _runs(steps: list[dict]) -> str:
    return "\n".join(str(s.get("run", "")) for s in steps if "run" in s)


# ---------------------------------------------------------------------------
# .iss：编码与基本形态
# ---------------------------------------------------------------------------


def test_iss_is_utf8_with_bom() -> None:
    """中文内容需要 BOM 才能在所有 Unicode Inno Setup 6 版本被无歧义识别为 UTF-8。"""
    raw = ISS_PATH.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf"), ".iss 必须保存为 UTF-8 with BOM"
    raw.decode("utf-8-sig")


def test_iss_no_line_continuation(iss_text: str) -> None:
    """.iss 段内条目不支持续行——行尾的反斜杠会被当字面量导致条目语义错误。"""
    for lineno, line in enumerate(iss_text.splitlines(), start=1):
        assert not line.rstrip().endswith("\\"), f"第 {lineno} 行以续行符结尾（.iss 不支持）"


def test_iss_required_sections_present(sections: dict[str, list[str]]) -> None:
    for name in ("Setup", "Files", "Icons", "Run", "UninstallRun"):
        assert name in sections, f"缺少 [{name}] 段"


# ---------------------------------------------------------------------------
# .iss：版本占位注入（scripts/iss_version.py → iscc /DMyAppVersion）
# ---------------------------------------------------------------------------


def test_version_must_be_injected(iss_text: str, sections: dict[str, list[str]]) -> None:
    """版本号不写死：必须经 /DMyAppVersion 注入，未注入直接 #error。"""
    assert "#ifndef MyAppVersion" in iss_text
    assert re.search(r"^\s*#error ", iss_text, re.MULTILINE), "缺少未注入版本的 #error 守卫"
    setup_lines = "\n".join(sections["Setup"])
    assert "AppVersion={#MyAppVersion}" in setup_lines, "AppVersion 必须用版本占位符"
    assert not re.search(r"^AppVersion=\d", setup_lines, re.MULTILINE), "版本号不得写死在脚本里"


def test_output_base_filename_pattern(sections: dict[str, list[str]]) -> None:
    match = re.search(r"^OutputBaseFilename=(.+)$", "\n".join(sections["Setup"]), re.MULTILINE)
    assert match is not None, "[Setup] 缺少 OutputBaseFilename"
    assert match.group(1) == "egress-sentinel-setup-v{#MyAppVersion}"


def test_setup_artifact_name_matches_workflow(iss_text: str) -> None:
    """模拟 tag v0.3.0 + pyproject 版本：产物文件名必须命中 build.yml 的 SETUP_GLOB 模式。"""
    assert re.search(
        r"^OutputBaseFilename=egress-sentinel-setup-v\{#MyAppVersion\}$", iss_text, re.MULTILINE
    ), "OutputBaseFilename 必须是 egress-sentinel-setup-v<占位符>（与 CI 命名对账）"
    assert fnmatch.fnmatch("dist/egress-sentinel-setup-v0.3.0.exe", SETUP_GLOB)
    current = f"dist/egress-sentinel-setup-v{iss_version.read_version()}.exe"
    assert fnmatch.fnmatch(current, SETUP_GLOB)


def test_app_id_is_stable(iss_text: str) -> None:
    assert APP_ID in iss_text, "AppId GUID 必须固定不变（升级/卸载识别）"


# ---------------------------------------------------------------------------
# .iss：安装内容与 build 产物名一致
# ---------------------------------------------------------------------------


def _iss_defines(iss_text: str) -> dict[str, str]:
    return {
        m.group(1): m.group(2)
        for m in re.finditer(r'^#define\s+(\w+)\s+"([^"]*)"$', iss_text, re.MULTILINE)
    }


def test_installs_build_exe_and_readme(
    iss_text: str, sections: dict[str, list[str]], build_exe: ModuleType
) -> None:
    """装 dist/<APP_NAME>.exe + README.md；exe 名必须与 build_exe.APP_NAME 对账一致。"""
    app_name: str = build_exe.APP_NAME
    assert _iss_defines(iss_text).get("MyAppExe") == f"{app_name}.exe", (
        "#define MyAppExe 必须等于 build_exe 产物名"
    )
    files = sections["Files"]
    assert any(
        line.startswith('Source: "..\\dist\\{#MyAppExe}"')
        and 'DestDir: "{app}"' in line
        and "ignoreversion" in line
        for line in files
    ), "[Files] 必须从 ..\\dist\\ 安装主程序 exe"
    assert any(
        "README.md" in line and 'DestDir: "{app}"' in line for line in files
    ), "[Files] 必须安装 README.md"


def test_shortcuts_created(sections: dict[str, list[str]]) -> None:
    """06 文档 W3：开始菜单/桌面快捷方式。"""
    icons = sections["Icons"]
    assert any(line.startswith('Name: "{group}\\') for line in icons), "缺少开始菜单快捷方式"
    assert any(
        line.startswith('Name: "{autodesktop}\\') and "Tasks: desktopicon" in line for line in icons
    ), "缺少桌面快捷方式（desktopicon 任务）"


# ---------------------------------------------------------------------------
# .iss：卸载红线——先 teardown 再删文件
# ---------------------------------------------------------------------------


def test_uninstall_runs_teardown_before_deleting_files(sections: dict[str, list[str]]) -> None:
    """[UninstallRun] 在 Inno 删除已安装文件之前执行（官方语义），teardown 必须在此段。

    waituntilterminated（该段默认值，显式声明自证）保证 teardown 退出后才进入删文件阶段。
    """
    unrun = sections["UninstallRun"]
    teardown_lines = [line for line in unrun if 'Parameters: "teardown"' in line]
    assert len(teardown_lines) == 1, "[UninstallRun] 必须恰好一条 teardown 调用"
    line = teardown_lines[0]
    assert line.startswith('Filename: "{app}\\{#MyAppExe}"'), "teardown 必须调用已安装的主程序"
    assert "waituntilterminated" in line, "teardown 必须等待退出（waituntilterminated）"
    kill_idx = next(i for i, entry in enumerate(unrun) if "taskkill" in entry)
    assert kill_idx < unrun.index(line), "应先结束占用进程（taskkill），再跑 teardown"


def test_teardown_only_in_uninstall_section(sections: dict[str, list[str]]) -> None:
    """teardown 只应出现在 [UninstallRun]（卸载时），不得装在 [Run]（安装即强改系统）。"""
    for name, entries in sections.items():
        if name == "UninstallRun":
            continue
        assert not any("teardown" in entry for entry in entries), f"[{name}] 不得出现 teardown"


# ---------------------------------------------------------------------------
# scripts/iss_version.py：版本注入源
# ---------------------------------------------------------------------------


def test_read_version_matches_pyproject() -> None:
    expected = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text("utf-8"))["project"][
        "version"
    ]
    assert iss_version.read_version() == expected
    assert re.fullmatch(r"\d+\.\d+\.\d+", expected), "Inno AppVersion 需要语义版本"


def test_read_version_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError):
        iss_version.read_version(tmp_path / "missing.toml")


def test_read_version_rejects_toml_without_version(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\nname = "x"\n', encoding="utf-8")
    with pytest.raises(RuntimeError):
        iss_version.read_version(pyproject)


def test_read_version_rejects_broken_toml(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("not [valid", encoding="utf-8")
    with pytest.raises(RuntimeError):
        iss_version.read_version(pyproject)


def test_main_prints_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert iss_version.main([]) == 0
    assert capsys.readouterr().out.strip() == iss_version.read_version()


def test_main_usage_error() -> None:
    """argv 约定同 release_notes.main（含程序名）：多传参数即用法错误。"""
    assert iss_version.main(["iss_version.py", "unexpected-arg"]) == 2


def test_main_missing_project_exits_1(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(iss_version, "PYPROJECT", tmp_path / "missing.toml")
    assert iss_version.main([]) == 1


# ---------------------------------------------------------------------------
# .github/workflows/build.yml：installer job 与产物名对账
# ---------------------------------------------------------------------------


def test_installer_job_exists_and_tag_only(workflow: dict) -> None:
    jobs = workflow["jobs"]
    assert "build" in jobs, "既有 build job 不得被移除"
    installer = jobs["installer"]
    assert installer["runs-on"] == "windows-latest"
    assert installer["needs"] == "build"
    assert installer["if"] == "startsWith(github.ref, 'refs/tags/')", "installer 仅 tag 触发"


def test_installer_job_uses_choco_innosetup_and_iscc(workflow: dict) -> None:
    steps = _steps(workflow["jobs"]["installer"])
    runs = _runs(steps)
    assert "choco install innosetup" in runs, "必须经 choco 安装 Inno Setup"
    assert "scripts/iss_version.py" in runs, "版本号必须来自 iss_version.py"
    assert "/DMyAppVersion" in runs, "版本必须经 /DMyAppVersion 注入"
    assert "installer/egress-sentinel.iss" in runs
    # 版本经步骤输出 → 环境变量传入编译步骤（避免引号/注入问题）
    ver_sources = [
        s
        for s in steps
        if s.get("id") == "ver" and "scripts/iss_version.py" in str(s.get("run", ""))
    ]
    assert ver_sources, "缺少 id=ver 的版本解析步骤"
    ver_steps = [s for s in steps if isinstance(s.get("env"), dict) and "AAA_VERSION" in s["env"]]
    assert ver_steps, "编译步骤必须经 AAA_VERSION 接收版本"
    assert ver_steps[0]["env"]["AAA_VERSION"] == "${{ steps.ver.outputs.version }}"


def test_installer_reuses_windows_amd64_artifact(workflow: dict) -> None:
    """installer 复用 build job 的 windows-amd64 产物：artifact 名两端必须解析一致。"""
    build = workflow["jobs"]["build"]
    legs = [
        leg
        for leg in build["strategy"]["matrix"]["include"]
        if leg.get("os") == "windows" and leg.get("arch") == "amd64"
    ]
    assert legs and legs[0]["experimental"] is False, (
        "windows-amd64 必须是稳定（非 experimental）产出"
    )
    uploads = [
        s for s in _steps(build) if str(s.get("uses", "")).startswith("actions/upload-artifact@")
    ]
    assert uploads, "build job 必须上传 artifact"
    upload_name = str(uploads[0]["with"]["name"])
    resolved = upload_name.replace("${{ matrix.os }}", "windows").replace(
        "${{ matrix.arch }}", "amd64"
    )
    assert resolved == EXE_ARTIFACT_NAME, "build 上传模板解析后应等于 installer 下载的 artifact 名"
    downloads = [
        s
        for s in _steps(workflow["jobs"]["installer"])
        if str(s.get("uses", "")).startswith("actions/download-artifact@")
    ]
    assert any(
        s.get("with", {}).get("name") == EXE_ARTIFACT_NAME for s in downloads
    ), "installer 必须按名下载 windows-amd64 artifact"
    assert "dist/ai-agent-audit.exe" in _runs(_steps(workflow["jobs"]["installer"])), (
        "exe 必须还原到 ISS 期望的 dist/ai-agent-audit.exe"
    )


def test_installer_upload_and_release_patterns(workflow: dict) -> None:
    steps = _steps(workflow["jobs"]["installer"])
    uploads = [
        s for s in steps if str(s.get("uses", "")).startswith("actions/upload-artifact@")
    ]
    assert uploads and uploads[0]["with"]["path"] == SETUP_GLOB
    assert uploads[0]["with"]["if-no-files-found"] == "error"
    releases = [
        s for s in steps if str(s.get("uses", "")).startswith("softprops/action-gh-release@")
    ]
    assert releases, "安装包必须挂 GitHub Release"
    assert releases[0]["with"]["files"] == SETUP_GLOB
    assert releases[0]["with"]["fail_on_unmatched_files"] is True


def test_tag_trigger_preserved(workflow: dict) -> None:
    on_section = workflow.get("on") or workflow.get(True)
    assert on_section is not None
    assert on_section["push"]["tags"] == ["v*"], "v* tag 触发不得被破坏"
