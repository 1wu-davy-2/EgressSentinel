"""v0.3.0 波次二集成单测（06 文档波次二任务 1-4/8）。

覆盖：新 CLI 命令（service/tray/rules/gitleaks/hub/policy use|list/report
--daily|--weekly）的装配与边界、``--lang`` 运行时切换、addon 批量落盘与
Forwarder 接线、WAL 迁移（旧库打开不炸）、``aaa --version`` 0.3.0。

红线：schtasks 全部注入假实现（绝不真创建任务）；不触网；不碰真实
``policies/``（profile 测试 monkeypatch ``DEFAULT_POLICIES_DIR``）。
"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from subprocess import CompletedProcess

import pytest
from typer.testing import CliRunner

from aaa import config as config_mod
from aaa.capture.addon import AuditAddon
from aaa.cli import app
from aaa.i18n import t
from aaa.reporting import daily as reporting_daily
from aaa.setup import service as service_mod
from aaa.setup.state import StateFile
from aaa.setup.teardown import teardown_target_kinds
from aaa.store.db import DbEventStore
from aaa.store.events import AuditEvent, Destination, RequestInfo
from aaa.store.evidence import EvidenceStore

runner = CliRunner()

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _norm(text: str) -> str:
    """去 ANSI 颜色码并压平空白（rich 80 列换行不影响子串断言，test_cli 同款）。"""
    return " ".join(_ANSI_RE.sub("", text).split())

#: 测试用假密钥（形似真钥、非官方示例 allowlist；与 test_hub/test_notify 同源）
FAKE_AWS_KEY = "AKIAQ2FZV3TQPE8KX9YZ"

_MINIMAL_POLICY = """\
version: 1
mode: dry-run
defaults:
  fail_open: true
  max_body_scan: 262144
domains:
  classes: {}
  rules: []
processes:
  profiles: {}
  rules: []
content:
  scanners: [secrets]
  rules: []
notifications:
  toast:
    enabled: false
"""


def _write_policy(path: Path, *, extra: str = "") -> Path:
    path.write_text(_MINIMAL_POLICY + extra, encoding="utf-8")
    return path


@pytest.fixture(autouse=True)
def _no_hub_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """隔离 AAA_HUB_* 环境变量（hub 配置测试不受本机环境影响）。"""
    monkeypatch.delenv("AAA_HUB_URL", raising=False)
    monkeypatch.delenv("AAA_HUB_TOKEN", raising=False)


def _event(**overrides: object) -> AuditEvent:
    fields: dict[str, object] = {
        "id": "evt_w2_1",
        "ts": datetime.now(UTC).astimezone().isoformat(timespec="milliseconds"),
        "mode": "regular",
        "verdict": "alert",
        "risk_score": 20,
        "destination": Destination(host="w2.example.com", port=443),
        "request": RequestInfo(method="GET", path="/w2", size=0),
    }
    fields.update(overrides)
    return AuditEvent(**fields)  # type: ignore[arg-type]


# ---------------------------------------------------------------- service（W1）


def _fake_schtasks(recorder: list[list[str]], create_ok: bool = True):
    """假 schtasks：/Query 一律未命中（returncode 1）；/Create 成功记账；/Delete
    仅在该会话创建过任务时成功（模拟真实 schtasks 的存在性语义）。"""
    created = {"flag": False}

    def _run(args: list[str]) -> CompletedProcess[str]:
        recorder.append(args)
        if "/Query" in args:
            return CompletedProcess(args, 1, "", "")
        if "/Create" in args:
            created["flag"] = create_ok
            return CompletedProcess(args, 0 if create_ok else 1, "", "mock")
        if "/Delete" in args:
            return CompletedProcess(args, 0 if created["flag"] else 1, "", "")
        return CompletedProcess(args, 0, "", "")

    return _run


def test_service_install_requires_admin(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """D-40 集成落位：非提权 exit 2 + UAC 指引，绝不触达 schtasks。"""
    import aaa.cli as cli_mod

    calls: list[list[str]] = []
    monkeypatch.setattr(service_mod, "_run_schtasks", _fake_schtasks(calls))
    monkeypatch.setattr(cli_mod, "is_current_process_elevated", lambda: False)
    result = runner.invoke(
        app, ["service", "install", "--yes", "--data-dir", str(tmp_path / "d")]
    )
    assert result.exit_code == 2
    assert "管理员" in _norm(result.output)
    assert calls == [], "非提权时不得执行任何 schtasks"


def test_service_install_happy_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """管理员（mock）+ --yes：journal-first 落 setup-state.json，输出确认与提示。"""
    import aaa.cli as cli_mod

    calls: list[list[str]] = []
    monkeypatch.setattr(service_mod, "_run_schtasks", _fake_schtasks(calls))
    monkeypatch.setattr(cli_mod, "is_current_process_elevated", lambda: True)
    data = tmp_path / "d"
    result = runner.invoke(app, ["service", "install", "--yes", "--data-dir", str(data)])
    assert result.exit_code == 0, result.output
    assert "服务计划任务已创建" in _norm(result.output)
    assert any("/Create" in " ".join(args) for args in calls)
    state = StateFile(data / "setup-state.json")
    kinds = [entry.kind for entry in state.entries()]
    assert kinds == [service_mod.KIND_SERVICE_TASK]


def test_service_install_conflict_warning(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """已装登录自启任务时安装服务：互斥提示打印（不阻断，D-40 第 6 条）。"""
    import aaa.cli as cli_mod

    calls: list[list[str]] = []
    monkeypatch.setattr(service_mod, "_run_schtasks", _fake_schtasks(calls))
    monkeypatch.setattr(cli_mod, "is_current_process_elevated", lambda: True)
    data = tmp_path / "d"
    data.mkdir(parents=True)
    state = StateFile(data / "setup-state.json")
    state.record(
        kind="autostart_task",
        key="EgressSentinel-AutoStart",
        old=None,
        new={"task_name": "EgressSentinel-AutoStart"},
    )
    result = runner.invoke(app, ["service", "install", "--yes", "--data-dir", str(data)])
    assert result.exit_code == 0, result.output
    assert "EgressSentinel-AutoStart" in _norm(result.output)


def test_service_uninstall_and_status(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(service_mod, "_run_schtasks", _fake_schtasks(calls))
    data = tmp_path / "d"
    # 未安装：uninstall 幂等提示
    result = runner.invoke(app, ["service", "uninstall", "--data-dir", str(data)])
    assert result.exit_code == 0
    assert "不存在" in _norm(result.output)
    # status：journal 有记录（先手工写一条）→ 已安装 + 命令行展示
    state = StateFile(data / "setup-state.json")
    state.record(
        kind=service_mod.KIND_SERVICE_TASK,
        key=service_mod.SERVICE_TASK_NAME,
        old=None,
        new={"command": "pythonw", "log_file": str(data / "service.log")},
    )
    result = runner.invoke(app, ["service", "status", "--data-dir", str(data)])
    assert result.exit_code == 0, result.output
    assert "已安装" in _norm(result.output)
    assert "pythonw" in _norm(result.output)


# -------------------------------------------------------------------- tray（W2）


def test_tray_command_propagates_exit_code(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """缺依赖退出码 2（run_tray 返回值 → 进程退出码，D-41 契约）。"""
    import aaa.tray as tray_mod

    seen: list[Path] = []

    def fake_run_tray(data_dir: str | Path) -> int:
        seen.append(Path(data_dir))
        return tray_mod.MISSING_DEPS_EXIT_CODE

    monkeypatch.setattr(tray_mod, "run_tray", fake_run_tray)
    data = tmp_path / "d"
    result = runner.invoke(app, ["tray", "--data-dir", str(data)])
    assert result.exit_code == tray_mod.MISSING_DEPS_EXIT_CODE == 2
    assert seen == [data]


def test_tray_command_normal_exit_zero(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import aaa.tray as tray_mod

    monkeypatch.setattr(tray_mod, "run_tray", lambda data_dir: 0)
    result = runner.invoke(app, ["tray", "--data-dir", str(tmp_path / "d")])
    assert result.exit_code == 0


# ------------------------------------------------------------- rules（W7 市场）


def test_rules_export_stdout(tmp_path: Path) -> None:
    policy = _write_policy(tmp_path / "p.yaml")
    result = runner.invoke(app, ["rules", "export", "content", "--policy", str(policy)])
    assert result.exit_code == 0, result.output
    assert "secrets" in result.output


def test_rules_export_to_file_and_unknown_section(tmp_path: Path) -> None:
    policy = _write_policy(tmp_path / "p.yaml")
    out = tmp_path / "domains.yaml"
    result = runner.invoke(
        app, ["rules", "export", "domains", "--out", str(out), "--policy", str(policy)]
    )
    assert result.exit_code == 0, result.output
    assert out.exists() and "classes" in out.read_text(encoding="utf-8")
    bad = runner.invoke(app, ["rules", "export", "nope", "--policy", str(policy)])
    assert bad.exit_code == 1
    assert "未知策略段" in _norm(bad.output)


def test_rules_import_roundtrip_and_reject(tmp_path: Path) -> None:
    policy = _write_policy(tmp_path / "p.yaml")
    exported = tmp_path / "content.yaml"
    assert runner.invoke(
        app, ["rules", "export", "content", "--out", str(exported), "--policy", str(policy)]
    ).exit_code == 0
    # 改一条合法变更后 union 导入 → 落盘生效
    good = tmp_path / "piece.yaml"
    good.write_text("scanners: [secrets, pii]\n", encoding="utf-8")
    result = runner.invoke(
        app,
        ["rules", "import", "content", str(good), "--merge", "union", "--policy", str(policy)],
    )
    assert result.exit_code == 0, result.output
    text = policy.read_text(encoding="utf-8")
    assert "pii" in text
    # 非法导入：整文件一字不动
    before = policy.read_text(encoding="utf-8")
    bad_piece = tmp_path / "bad.yaml"
    bad_piece.write_text(
        "scanners: [nope]\nrules:\n  - id: x\n    action: nuke\n", encoding="utf-8"
    )
    bad = runner.invoke(
        app, ["rules", "import", "content", str(bad_piece), "--policy", str(policy)]
    )
    assert bad.exit_code == 1
    assert policy.read_text(encoding="utf-8") == before


# ------------------------------------------------------------ gitleaks（W7 同步）


_GITLEAKS_TOML = """\
[[rules]]
id = "gitlab-pat"
description = "GitLab personal access token"
regex = \'\'\'glpat-[0-9a-zA-Z\\\\-]{20}\'\'\'
keywords = ["glpat"]
"""


def test_gitleaks_sync_local_path(tmp_path: Path) -> None:
    source = tmp_path / "gitleaks.toml"
    source.write_text(_GITLEAKS_TOML, encoding="utf-8")
    data = tmp_path / "d"
    result = runner.invoke(app, ["gitleaks", "sync", str(source), "--data-dir", str(data)])
    assert result.exit_code == 0, result.output
    pack_file = data / "rules" / "gitleaks.yaml"
    assert pack_file.exists()
    pack_text = pack_file.read_text(encoding="utf-8")
    assert "gitlab-pat" in pack_text
    assert "sha256" in pack_text  # pin 记录在包 meta
    assert "1 条" in _norm(result.output)


def test_gitleaks_sync_bad_source_fails(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["gitleaks", "sync", str(tmp_path / "nope.toml"), "--data-dir", str(tmp_path)]
    )
    assert result.exit_code == 1
    assert "gitleaks 同步失败" in _norm(result.output)


# ------------------------------------------------------------------ hub（W8）


def test_hub_serve_requires_token(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    result = runner.invoke(app, ["hub", "serve", "--data-dir", str(tmp_path)])
    assert result.exit_code == 2
    assert "AAA_HUB_TOKEN" in result.output


def test_hub_forward_status_disabled_and_stats(tmp_path: Path) -> None:
    policy = _write_policy(tmp_path / "p.yaml")
    data = tmp_path / "d"
    data.mkdir(parents=True, exist_ok=True)
    # 未启用：关闭提示
    result = runner.invoke(
        app, ["hub", "forward", "status", "--policy", str(policy), "--data-dir", str(data)]
    )
    assert result.exit_code == 0, result.output
    assert "关闭" in _norm(result.output)
    assert "暂无运行时统计" in _norm(result.output)
    # 有快照：统计行 + 最近错误
    snapshot = {
        "updated": "2026-10-25T12:00:00.000+08:00",
        "stats": {
            "sent_events": 7,
            "sent_batches": 1,
            "dropped": 0,
            "retries_used": 0,
            "send_errors": 1,
            "queue_size": 0,
            "last_error": "boom",
        },
    }
    (data / "hub-forward.json").write_text(json.dumps(snapshot), encoding="utf-8")
    result = runner.invoke(
        app, ["hub", "forward", "status", "--policy", str(policy), "--data-dir", str(data)]
    )
    assert result.exit_code == 0, result.output
    assert "已发送 7 条" in _norm(result.output)
    assert "boom" in _norm(result.output)


# --------------------------------------------------------- policy use / list


@pytest.fixture
def profile_policies_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    policies_dir = tmp_path / "policies"
    (policies_dir / "profiles").mkdir(parents=True)
    (policies_dir / "profiles" / "alpha.yaml").write_text(
        _MINIMAL_POLICY, encoding="utf-8"
    )
    (policies_dir / "profiles" / "beta.yaml").write_text(
        _MINIMAL_POLICY.replace("mode: dry-run", "mode: enforce"), encoding="utf-8"
    )
    monkeypatch.setattr(config_mod, "DEFAULT_POLICIES_DIR", policies_dir)
    return policies_dir


def test_policy_use_switch_and_reset(profile_policies_dir: Path) -> None:
    result = runner.invoke(app, ["policy", "use", "beta"])
    assert result.exit_code == 0, result.output
    current = profile_policies_dir / "current.yaml"
    assert current.exists()
    assert (profile_policies_dir / "profiles" / "beta.yaml").read_text(
        encoding="utf-8"
    ) == current.read_text(encoding="utf-8")
    assert config_mod.default_policy_file() == current
    # list 标注当前生效
    listing = runner.invoke(app, ["policy", "list"])
    assert listing.exit_code == 0, listing.output
    assert "← 当前生效" in _norm(listing.output)
    # 回出厂
    reset = runner.invoke(app, ["policy", "use", "--reset"])
    assert reset.exit_code == 0
    assert not current.exists()
    assert config_mod.default_policy_file() == config_mod.DEFAULT_POLICY_FILE


def test_policy_use_missing_and_invalid(profile_policies_dir: Path) -> None:
    missing = runner.invoke(app, ["policy", "use", "ghost"])
    assert missing.exit_code == 1
    assert "profile 不存在" in _norm(missing.output)
    bad = profile_policies_dir / "profiles" / "bad.yaml"
    bad.write_text("mode: bogus\n", encoding="utf-8")
    invalid = runner.invoke(app, ["policy", "use", "bad"])
    assert invalid.exit_code == 1
    assert "profile 校验失败" in _norm(invalid.output)
    assert not (profile_policies_dir / "current.yaml").exists()


# ------------------------------------------------------- report --daily/--weekly


def _seed_events(store: DbEventStore, count: int = 3) -> None:
    now = datetime.now(UTC).astimezone()
    events = [
        _event(
            id=f"evt_seed_{i}",
            ts=(now - timedelta(hours=i)).isoformat(timespec="milliseconds"),
            verdict="block" if i % 2 == 0 else "alert",
            risk_score=60 + i,
            request=RequestInfo(
                method="POST",
                path=f"/api/p{i}?k={FAKE_AWS_KEY}" if i == 0 else f"/api/p{i}",
                size=10 + i,
            ),
        )
        for i in range(count)
    ]
    assert store.insert_events(events) == count


def test_report_daily_and_weekly_html(tmp_path: Path) -> None:
    data = tmp_path / "d"
    store = DbEventStore(data / "audit.db", evidence_dir=data / "evidence")
    _seed_events(store)
    store.close()
    result = runner.invoke(app, ["report", "--daily", "--data-dir", str(data)])
    assert result.exit_code == 0, result.output
    daily_file = data / "reports" / f"daily-{date.today().isoformat()}.html"
    assert daily_file.exists()
    html = daily_file.read_text(encoding="utf-8")
    assert "block" in html and "alert" in html
    assert FAKE_AWS_KEY not in html, "明文密钥绝不出现在日报"
    weekly = runner.invoke(app, ["report", "--weekly", "--data-dir", str(data)])
    assert weekly.exit_code == 0, weekly.output
    files = list((data / "reports").glob("weekly-*.html"))
    assert len(files) == 1


def test_report_daily_rejects_conflicting_options(tmp_path: Path) -> None:
    data = tmp_path / "d"
    both = runner.invoke(app, ["report", "--daily", "--weekly", "--data-dir", str(data)])
    assert both.exit_code != 0
    assert "二选一" in _norm(both.output)
    mixed = runner.invoke(app, ["report", "--daily", "--json", "--data-dir", str(data)])
    assert mixed.exit_code != 0
    bad_day = runner.invoke(
        app, ["report", "--daily", "--day", "2026-13-99", "--data-dir", str(data)]
    )
    assert bad_day.exit_code != 0


# ------------------------------------------------------- run 接线（采样/转发/批量）


def test_run_wires_sampling_and_forwarder(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import aaa.cli as cli_mod

    monkeypatch.setattr(cli_mod, "is_current_process_elevated", lambda: True)
    policy = _write_policy(
        tmp_path / "p.yaml",
        extra=(
            "\nsampling:\n  enabled: true\n  head_bytes: 1024\n"
            "hub:\n  enabled: true\n  url: 'http://127.0.0.1:1'\n  token: 'tok'\n"
        ),
    )
    seen: dict[str, object] = {}

    class FakeEngine:
        def __init__(self, config: object, addons: list[object]) -> None:
            seen["addon"] = addons[0]

        def run_blocking(self) -> None:
            pass

    monkeypatch.setattr(cli_mod, "CaptureEngine", FakeEngine)
    data = tmp_path / "d"
    result = runner.invoke(
        app, ["run", "--policy", str(policy), "--data-dir", str(data), "--db-batch", "5"]
    )
    assert result.exit_code == 0, result.output
    addon = seen["addon"]
    assert addon.pipeline.sampling.enabled is True  # type: ignore[attr-defined]
    assert addon.pipeline.sampling.head_bytes == 1024  # type: ignore[attr-defined]
    assert addon.forwarder is not None  # type: ignore[attr-defined]
    assert addon.batch_size == 5  # type: ignore[attr-defined]
    assert "hub 转发：开启" in _norm(result.output)
    assert "扫描采样：开启" in _norm(result.output)
    # 退出路径写统计快照（空队列也落 updated）
    assert (data / "hub-forward.json").exists()
    addon.forwarder.close(0.5)  # type: ignore[attr-defined]


def test_run_default_policy_hub_off(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """默认（项目 default.yaml）：hub 关 → 零外发；采样关 → 全量扫描。"""
    import aaa.cli as cli_mod

    monkeypatch.setattr(cli_mod, "is_current_process_elevated", lambda: True)
    seen: dict[str, object] = {}

    class FakeEngine:
        def __init__(self, config: object, addons: list[object]) -> None:
            seen["addon"] = addons[0]

        def run_blocking(self) -> None:
            pass

    monkeypatch.setattr(cli_mod, "CaptureEngine", FakeEngine)
    result = runner.invoke(app, ["run", "--data-dir", str(tmp_path / "d")])
    assert result.exit_code == 0, result.output
    addon = seen["addon"]
    assert addon.forwarder is None  # type: ignore[attr-defined]
    assert addon.pipeline.sampling.enabled is False  # type: ignore[attr-defined]
    assert "hub 转发：关闭" in _norm(result.output)
    assert "扫描采样：关闭" in _norm(result.output)


class _RecordingStore:
    """区分 append / insert_events 的假 store（批量落盘接线验证）。"""

    def __init__(self) -> None:
        self.appended: list[AuditEvent] = []
        self.batches: list[list[AuditEvent]] = []

    def append(self, event: AuditEvent) -> None:
        self.appended.append(event)

    def insert_events(self, events: list[AuditEvent]) -> int:
        self.batches.append(list(events))
        return len(events)


class _FakeForwarder:
    def __init__(self) -> None:
        self.enqueued: list[AuditEvent] = []

    def enqueue(self, event: AuditEvent) -> None:
        self.enqueued.append(event)


def _evidence(tmp_path: Path) -> EvidenceStore:
    return EvidenceStore(tmp_path / "evidence", rel_base=tmp_path)


def test_addon_batch_insert_flushes_on_important(tmp_path: Path) -> None:
    """批量落盘：低危事件攒缓冲；阻断事件立即冲刷整批（insert_events 单次）。"""
    store = _RecordingStore()
    addon = AuditAddon(store, _evidence(tmp_path), batch_size=3)
    addon._save(_event(id="evt_b1", verdict="allow", risk_score=0))
    addon._save(_event(id="evt_b2", verdict="alert", risk_score=10))
    assert store.batches == [] and store.appended == []
    addon._save(_event(id="evt_b3", verdict="block", risk_score=60))
    assert len(store.batches) == 1 and len(store.batches[0]) == 3
    assert store.appended == []
    assert addon._save_buffer == []


def test_addon_batch_size_one_keeps_legacy_behavior(tmp_path: Path) -> None:
    """batch_size=1（默认）：逐条 append，与 v0.2.x 行为一致。"""
    store = _RecordingStore()
    addon = AuditAddon(store, _evidence(tmp_path))
    addon._save(_event(id="evt_s1"))
    addon._save(_event(id="evt_s2"))
    assert [e.id for e in store.appended] == ["evt_s1", "evt_s2"]
    assert store.batches == []


def test_addon_forwards_saved_events(tmp_path: Path) -> None:
    store = _RecordingStore()
    forwarder = _FakeForwarder()
    addon = AuditAddon(store, _evidence(tmp_path), forwarder=forwarder)  # type: ignore[arg-type]
    addon._save(_event(id="evt_f1"))
    assert [e.id for e in forwarder.enqueued] == ["evt_f1"]
    addon_no_fwd = AuditAddon(store, _evidence(tmp_path))  # type: ignore[arg-type]
    addon_no_fwd._save(_event(id="evt_f2"))
    assert len(forwarder.enqueued) == 1


# ---------------------------------------------------------------- --lang


def test_lang_option_switches_runtime_output(tmp_path: Path) -> None:
    """``--lang en``：运行时输出切英文（帮助文本在导入期渲染，属 AAA_LANG 职责）。"""
    from aaa import i18n

    try:
        result = runner.invoke(app, ["--lang", "en", "policy", "lint", "--help"])
        assert result.exit_code == 0
        # 运行时通道：取词函数按 set_lang 生效
        assert i18n.get_lang() == "en"
    finally:
        i18n.reset_state()


def test_aaa_lang_env_switches_runtime_output(monkeypatch: pytest.MonkeyPatch) -> None:
    from aaa import i18n

    monkeypatch.setenv("AAA_LANG", "en")
    try:
        assert i18n.get_lang() == "en"
        assert t("common.cancelled") == "Cancelled."
    finally:
        i18n.reset_state()


def test_unknown_lang_falls_back_zh(monkeypatch: pytest.MonkeyPatch) -> None:
    from aaa import i18n

    monkeypatch.setenv("AAA_LANG", "fr")
    try:
        assert i18n.get_lang() == "zh"
        assert t("common.cancelled") == "已取消。"
    finally:
        i18n.reset_state()


# ---------------------------------------------------------------- teardown 目标


def test_teardown_targets_include_service_and_daily() -> None:
    """D-40/D-45 预留的集成落位：service/daily 目标映射（还原器 import 即注册）。"""
    assert teardown_target_kinds(("service",)) == {service_mod.KIND_SERVICE_TASK}
    assert teardown_target_kinds(("daily",)) == {reporting_daily.KIND_DAILY_REPORT_TASK}
    assert teardown_target_kinds(("service", "daily")) == {
        service_mod.KIND_SERVICE_TASK,
        reporting_daily.KIND_DAILY_REPORT_TASK,
    }
    with pytest.raises(ValueError, match="未知 teardown 目标"):
        teardown_target_kinds(("bogus",))


# ------------------------------------------------------------- WAL 迁移（W4）


def test_wal_migration_from_pre_wal_database(tmp_path: Path) -> None:
    """WAL 生效迁移检查：v0.2.x 时代（journal_mode=DELETE）旧库打开不炸、可用。"""
    db_path = tmp_path / "audit.db"
    legacy = sqlite3.connect(str(db_path))
    try:
        legacy.execute("PRAGMA journal_mode=DELETE")
        legacy.execute(
            """
            CREATE TABLE events (
                id TEXT PRIMARY KEY, ts TEXT NOT NULL, ts_epoch REAL NOT NULL,
                mode TEXT NOT NULL, verdict TEXT NOT NULL, risk_score INTEGER NOT NULL DEFAULT 0,
                pid INTEGER, process_json TEXT, process_name TEXT, host TEXT NOT NULL,
                ip TEXT, port INTEGER, classification TEXT, method TEXT NOT NULL,
                path TEXT NOT NULL, content_type TEXT, request_size INTEGER NOT NULL DEFAULT 0,
                response_json TEXT, matched_rules TEXT NOT NULL DEFAULT '[]',
                action_taken TEXT NOT NULL, evidence_file TEXT, evidence_sha256 TEXT,
                evidence_truncated INTEGER NOT NULL DEFAULT 0, evidence_size INTEGER,
                evidence_original_size INTEGER, policy_version TEXT, error TEXT, raw TEXT NOT NULL
            )
            """
        )
        legacy.execute(
            "INSERT INTO events (id, ts, ts_epoch, mode, verdict, host, method, "
            "path, action_taken, raw)"
            " VALUES ('evt_old', '2026-10-01T00:00:00+00:00', 0, 'regular', 'alert',"
            " 'old.example.com', 'GET', '/', 'logged', '{}')"
        )
        legacy.commit()
    finally:
        legacy.close()
    store = DbEventStore(db_path, evidence_dir=tmp_path / "evidence")
    try:
        mode = store._conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode == "wal"
        assert store.count() == 1  # 旧事件行原样可读
        store.append(_event(id="evt_new"))  # 新写入正常
        assert store.count() == 2
    finally:
        store.close()


# ------------------------------------------------------------------ 版本（T8）


def test_cli_version_is_0_3_0() -> None:
    """06 文档波次二第 8 条：``aaa --version`` = 0.3.0。"""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "0.3.0" in result.output


def test_policy_lint_shows_sampling_and_hub(tmp_path: Path) -> None:
    policy = _write_policy(
        tmp_path / "p.yaml",
        extra="\nsampling:\n  enabled: true\n  head_bytes: 4096\n",
    )
    result = runner.invoke(app, ["policy", "lint", str(policy)])
    assert result.exit_code == 0, result.output
    assert "sampling" in result.output
    assert "head_bytes=4096" in result.output
    assert "hub" in result.output
