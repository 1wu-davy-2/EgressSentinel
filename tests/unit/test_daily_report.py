"""日报模块单测（06 文档 W6）。

红线：schtasks/smtp 全部注入假实现——绝不真实施改系统计划任务、绝不真实发邮件；
脱敏与 HTML 转义是渲染的硬性断言——日报是对外可见产物，绝不能带出明文密钥
或被事件字段注入 HTML。
"""

from __future__ import annotations

import itertools
import os
import subprocess
from datetime import date, datetime, timedelta
from email.message import EmailMessage
from pathlib import Path

import pytest

from aaa.notify.model import EmailConfig
from aaa.reporting import daily as daily_mod
from aaa.setup.state import StateFile
from aaa.setup.teardown import run_teardown
from aaa.store.db import DbEventStore
from aaa.store.events import AuditEvent, Destination, ProcessInfo, RequestInfo
from aaa.web.masking import MASK_OPEN

#: 假 AWS 密钥（形似真钥、非官方示例 allowlist，专供测试；与 test_notify 同值）
FAKE_AWS_KEY = "AKIAQ2FZV3TQPE8KX9YZ"

_seq = itertools.count()


@pytest.fixture
def store(tmp_path: Path) -> DbEventStore:
    """种子库：真实 DbEventStore（tmp_path），渲染走与生产相同的 query 路径。"""
    return DbEventStore(tmp_path / "audit.db")


def _local(day: date, hour: int, minute: int = 0) -> str:
    """``day`` 当天本地时刻的 ISO 时间戳（与渲染窗口同一时区基准）。"""
    base = datetime.combine(day, datetime.min.time()).astimezone()
    return base.replace(hour=hour, minute=minute).isoformat(timespec="milliseconds")


def _event(
    ts: str,
    *,
    host: str = "api.openai.com",
    verdict: str = "block",
    risk: int = 80,
    pid: int | None = 1234,
    name: str | None = "node.exe",
    path: str = "/v1/chat",
    method: str = "POST",
    rules: list[dict[str, object]] | None = None,
) -> AuditEvent:
    """构造测试事件（ID 自增保证唯一，避免 INSERT OR REPLACE 覆盖）。"""
    return AuditEvent(
        id=f"evt_test_{next(_seq)}",
        ts=ts,
        mode="regular",
        verdict=verdict,
        risk_score=risk,
        process=ProcessInfo(pid=pid, name=name) if pid is not None or name else None,
        destination=Destination(host=host, port=443),
        request=RequestInfo(method=method, path=path, size=100),
        matched_rules=rules or [],
    )


# ==========================================================================
# 渲染：聚合数字 / sparkline / 空窗口 / 周报
# ==========================================================================


def test_render_daily_aggregates(store: DbEventStore) -> None:
    """按判定/进程/主机聚合数字正确，趋势 sparkline 以内联 SVG 呈现。"""
    day = date.today()
    store.append(_event(_local(day, 9), verdict="block", risk=90))
    store.append(_event(_local(day, 10), verdict="block", risk=70))
    store.append(_event(_local(day, 11), verdict="allow", risk=0))
    store.append(_event(_local(day, 12), verdict="confirm", risk=50))
    store.append(
        _event(
            _local(day, 13),
            host="example.org",
            verdict="allow",
            risk=0,
            pid=555,
            name="curl.exe",
        )
    )

    html = daily_mod.render_daily(store, day)

    assert html.startswith("<!DOCTYPE html>")
    assert "<style>" in html and "<script" not in html  # 自包含：内联 CSS、无脚本
    assert "共 5 条" in html
    assert "<td>block</td><td>2</td>" in html
    assert "<td>allow</td><td>2</td>" in html
    assert "<td>confirm</td><td>1</td>" in html
    assert "api.openai.com" in html and "example.org" in html
    assert "node.exe(1234)" in html and "curl.exe(555)" in html
    # 趋势 sparkline：内联 SVG + 24 个小时桶的 polyline
    assert '<svg xmlns="http://www.w3.org/2000/svg"' in html
    assert "<polyline" in html
    assert daily_mod.sparkline_svg([]) not in html  # 有数据时不是「无数据」占位


def test_render_daily_trend_buckets_and_top_events(store: DbEventStore) -> None:
    """小时桶落位正确；Top 事件按风险分降序且截断到 TOP_EVENTS。"""
    day = date.today()
    for risk in range(1, 13):  # 12 条，风险分 1..12
        hour = 9 if risk <= 6 else 18
        store.append(_event(_local(day, hour), risk=risk, host=f"h{risk}.example"))

    since, until = daily_mod._day_window(day)
    data = daily_mod._collect(
        store, title="t", since=since, until=until, buckets=24, labels=daily_mod.HOUR_LABELS
    )

    assert data.total == 12
    assert data.trend[9] == 6 and data.trend[18] == 6
    assert sum(data.trend) == 12
    assert data.trend_peak == "09:00（6 条）" or data.trend_peak == "18:00（6 条）"
    assert len(data.top_events) == daily_mod.TOP_EVENTS
    risks = [event.risk_score for event in data.top_events]
    assert risks == sorted(risks, reverse=True)
    assert data.top_events[0].risk_score == 12
    assert data.top_events[0].destination.host == "h12.example"


def test_render_daily_empty(store: DbEventStore) -> None:
    """空窗口：有效 HTML + 总数 0 + sparkline「无数据」占位，各榜单显示无数据。"""
    html = daily_mod.render_daily(store, date.today())
    assert html.startswith("<!DOCTYPE html>")
    assert "共 0 条" in html
    assert "无数据" in html
    assert 'aria-label="趋势图"' in html


def test_render_weekly_aggregates_iso_week(store: DbEventStore) -> None:
    """周报窗口 = 含 day 的 ISO 自然周（周一为始，7 天桶）；上周事件不计入。"""
    day = date.today()
    monday = day - timedelta(days=day.weekday())
    store.append(_event(_local(monday, 9), host="mon.example"))
    store.append(_event(_local(monday + timedelta(days=3), 15), host="thu.example"))
    store.append(_event(_local(monday - timedelta(days=7), 15), host="last-week.example"))

    html = daily_mod.render_weekly(store, day)

    assert "共 2 条" in html
    assert monday.strftime("%m-%d") in html  # 7 个天桶标签
    assert "mon.example" in html and "thu.example" in html
    assert "last-week.example" not in html


# ==========================================================================
# 渲染红线：脱敏（复用 masking 核心）与 HTML 转义
# ==========================================================================


def test_render_daily_masks_secret_in_path_and_process(store: DbEventStore) -> None:
    """路径/进程名中的密钥必须打码（复用 notify/summary 同一脱敏核心），明文绝不出现。"""
    day = date.today()
    store.append(_event(_local(day, 9), path=f"/v1/chat?key={FAKE_AWS_KEY}"))
    store.append(_event(_local(day, 10), name=f"node-{FAKE_AWS_KEY}.exe", pid=None))

    html = daily_mod.render_daily(store, day)

    assert FAKE_AWS_KEY not in html
    assert html.count(MASK_OPEN) >= 3  # Top 事件表两处 + 进程聚合榜一处
    assert "aws-access-token|" in html  # 与事件 matched_rules[].evidence 同款打码约定


def test_render_daily_escapes_html(store: DbEventStore) -> None:
    """事件字段（host/进程名/路径）不得注入 HTML：统一在 _table 出口转义。"""
    day = date.today()
    store.append(
        _event(
            _local(day, 9),
            host="<script>alert(1)</script>",
            name="bad<&>.exe",
            path="/x?a=1&b=<2>",
        )
    )

    html = daily_mod.render_daily(store, day)

    assert "<script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "bad&lt;&amp;&gt;.exe" in html
    assert "1&amp;b=&lt;2&gt;" in html


# ==========================================================================
# sparkline：内联 SVG
# ==========================================================================


def test_sparkline_svg_polyline() -> None:
    """正常序列：合法 SVG，坐标对数量等于数据点数，峰值贴顶。"""
    svg = daily_mod.sparkline_svg([0, 5, 10, 5, 0])
    assert svg.startswith("<svg") and svg.endswith("</svg>")
    assert "<polyline" in svg and 'points="' in svg
    assert svg.count(",") == 5  # 每个坐标对一对 x,y 逗号
    assert "4.0" in svg and "44.0" in svg  # 基线（0 值）在底部，峰值贴顶（10 → y=pad）


def test_sparkline_svg_edge_cases() -> None:
    """空序列 / 全零 / 单点都产出合法 SVG。"""
    empty = daily_mod.sparkline_svg([])
    assert "<svg" in empty and "无数据" in empty and "<polyline" not in empty

    flat = daily_mod.sparkline_svg([0, 0, 0])
    assert "<polyline" in flat

    single = daily_mod.sparkline_svg([7])
    assert "<polyline" in single and single.count(",") == 2  # 单点复制为两点短线段


# ==========================================================================
# email_daily：注入式 SMTP
# ==========================================================================


def test_email_daily_uses_injected_sender() -> None:
    """注入 sender：原样收到 (config, subject, html)，不发真实邮件。"""
    config = EmailConfig(
        enabled=True, smtp_host="smtp.example.com", username="u", to_addrs=["a@b.c"]
    )
    calls: list[tuple[EmailConfig, str, str]] = []
    daily_mod.email_daily(
        config, "<p>hi</p>", subject="日报 2026-10-25",
        sender=lambda cfg, subj, body: calls.append((cfg, subj, body)),
    )
    assert calls == [(config, "日报 2026-10-25", "<p>hi</p>")]


def test_email_daily_rejects_incomplete_config() -> None:
    """smtp_host / to_addrs 缺失：显式报错（日报是显式动作，不许静默跳过）。"""
    html = "<p>x</p>"
    with pytest.raises(ValueError, match="smtp_host"):
        daily_mod.email_daily(EmailConfig(enabled=True), html)
    with pytest.raises(ValueError, match="to_addrs"):
        daily_mod.email_daily(EmailConfig(enabled=True, smtp_host="smtp.example.com"), html)


class FakeSMTP:
    """假 SMTP 连接：记录消息，绝不联网。"""

    sent: dict[str, object] = {}

    def __init__(self, host: str, port: int, timeout: float | None = None) -> None:
        FakeSMTP.sent["addr"] = (host, port)

    def __enter__(self) -> FakeSMTP:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def login(self, username: str, password: str) -> None:
        FakeSMTP.sent["login"] = (username, password)

    def send_message(self, message: EmailMessage) -> None:
        FakeSMTP.sent["message"] = message


def test_email_daily_default_sends_html_message(monkeypatch: pytest.MonkeyPatch) -> None:
    """默认发送走 smtplib（monkeypatch 假连接）：消息体 subtype=html、主题/收件人正确。"""
    FakeSMTP.sent = {}
    monkeypatch.setattr("smtplib.SMTP_SSL", FakeSMTP)
    config = EmailConfig(
        enabled=True,
        smtp_host="smtp.example.com",
        smtp_port=465,
        username="u",
        password="p",
        from_addr="from@x.c",
        to_addrs=["to@x.c"],
    )
    daily_mod.email_daily(config, "<p>hi</p>", subject="日报")

    assert FakeSMTP.sent["addr"] == ("smtp.example.com", 465)
    assert FakeSMTP.sent["login"] == ("u", "p")
    message = FakeSMTP.sent["message"]
    assert isinstance(message, EmailMessage)
    assert message["Subject"] == "日报"
    assert message["To"] == "to@x.c"
    assert message["From"] == "from@x.c"
    assert message.get_content_type() == "text/html"
    assert message.get_content_charset() == "utf-8"
    payload = message.get_payload(decode=True)
    assert payload is not None and "<p>hi</p>" in payload.decode("utf-8")


# ==========================================================================
# 计划任务：全 mock，绝不真实施改
# ==========================================================================


class FakeSchtasks:
    """记录调用的假 schtasks：跟踪任务存在性（/Create 建、/Delete 删，与真行为一致）。"""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.exists: set[str] = set()

    def __call__(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(args))
        if args[0] == "/Create":
            self.exists.add(args[2])
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[0] == "/Delete":
            ok = args[2] in self.exists
            self.exists.discard(args[2])
            return subprocess.CompletedProcess(args, 0 if ok else 1, "", "" if ok else "找不到")
        return subprocess.CompletedProcess(args, 0, "", "")


@pytest.fixture
def state(tmp_path: Path) -> StateFile:
    return StateFile(tmp_path / "setup-state.json")


def test_install_daily_task_creates_task_and_journals(
    monkeypatch: pytest.MonkeyPatch, state: StateFile, tmp_path: Path
) -> None:
    """journal-first：/Create 一次、任务名正确、XML 为每日触发、命令指向 report --daily --email。"""
    fake = FakeSchtasks()
    monkeypatch.setattr(daily_mod, "_run_schtasks", fake)
    data_dir = tmp_path / "data"

    entry = daily_mod.install_daily_task(state, data_dir, hour=9)

    assert entry.kind == daily_mod.KIND_DAILY_REPORT_TASK
    creates = [call for call in fake.calls if call[0] == "/Create"]
    assert len(creates) == 1
    assert creates[0][2] == daily_mod.DAILY_REPORT_TASK_NAME
    xml_file = Path(str(entry.new["xml"]))
    assert xml_file.is_file()
    xml = xml_file.read_text(encoding="utf-16")
    assert "<CalendarTrigger>" in xml
    assert "<DaysInterval>1</DaysInterval>" in xml
    assert "T09:00:00" in xml
    assert "--daily" in str(entry.new["arguments"])
    assert "--email" in str(entry.new["arguments"])
    assert f"--data-dir {data_dir}" in str(entry.new["arguments"])
    assert len(state.entries()) == 1  # journal-first：记录在案，可 teardown


def test_install_daily_task_validates_hour(
    monkeypatch: pytest.MonkeyPatch, state: StateFile, tmp_path: Path
) -> None:
    """hour 越界：ValueError 且不留任何落盘痕迹（无 XML、无 journal）。"""
    fake = FakeSchtasks()
    monkeypatch.setattr(daily_mod, "_run_schtasks", fake)
    with pytest.raises(ValueError, match="hour"):
        daily_mod.install_daily_task(state, tmp_path / "data", hour=24)
    with pytest.raises(ValueError, match="hour"):
        daily_mod.install_daily_task(state, tmp_path / "data", hour=-1)
    assert fake.calls == []
    assert state.entries() == []
    assert not (tmp_path / "data" / "tasks").exists()


def test_install_failure_keeps_journal_for_retry(
    monkeypatch: pytest.MonkeyPatch, state: StateFile, tmp_path: Path
) -> None:
    """/Create 失败：抛 DailyReportTaskError，journal 记录保留（teardown/重试可用）。"""

    def failing(args: list[str]) -> subprocess.CompletedProcess[str]:
        if args[0] == "/Create":
            return subprocess.CompletedProcess(args, 1, "", "拒绝访问")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(daily_mod, "_run_schtasks", failing)
    with pytest.raises(daily_mod.DailyReportTaskError, match="拒绝访问"):
        daily_mod.install_daily_task(state, tmp_path / "data")
    assert len(state.entries()) == 1


def test_uninstall_daily_task_is_idempotent(
    monkeypatch: pytest.MonkeyPatch, state: StateFile, tmp_path: Path
) -> None:
    """安装→卸载清记录；重复卸载为 no-op 返回 False。"""
    fake = FakeSchtasks()
    monkeypatch.setattr(daily_mod, "_run_schtasks", fake)
    daily_mod.install_daily_task(state, tmp_path / "data")

    assert daily_mod.uninstall_daily_task(state) is True
    assert state.entries() == []
    assert daily_mod.uninstall_daily_task(state) is False  # 本就不存在：幂等


def test_restore_daily_report_task_tolerates_missing(
    monkeypatch: pytest.MonkeyPatch, state: StateFile
) -> None:
    """还原容忍任务不存在（schtasks 报错也继续），并清掉 journal 记录（幂等）。"""

    def missing(args: list[str]) -> subprocess.CompletedProcess[str]:
        if args[0] == "/Delete":
            return subprocess.CompletedProcess(args, 1, "", "任务不存在")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(daily_mod, "_run_schtasks", missing)
    entry = state.record(
        kind=daily_mod.KIND_DAILY_REPORT_TASK,
        key=daily_mod.DAILY_REPORT_TASK_NAME,
        new={"task_name": daily_mod.DAILY_REPORT_TASK_NAME},
    )
    daily_mod.restore_daily_report_task(state, entry)  # 不抛异常
    assert state.entries() == []


def test_restore_registered_in_teardown_registry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """import 即注册：run_teardown 全量还原能删任务并清记录（mechanism 同 setup/service.py）。"""
    fake = FakeSchtasks()
    monkeypatch.setattr(daily_mod, "_run_schtasks", fake)
    state_path = tmp_path / "setup-state.json"
    state = StateFile(state_path)
    daily_mod.install_daily_task(state, tmp_path / "data")

    report = run_teardown(state_path)  # kinds=None = 全部

    assert report.ok, report.errors
    deletes = [call for call in fake.calls if call[0] == "/Delete"]
    assert len(deletes) == 1
    assert deletes[0][2] == daily_mod.DAILY_REPORT_TASK_NAME
    assert StateFile(state_path).entries() == []


def test_daily_report_command_interpreter_strategy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """venv：pythonw/-c 直启 CLI；frozen：cmd start /min 最小化（同 autostart_command 策略）。

    断言保持跨平台可跑（CI 含 ubuntu/macos）：非 Windows 仅要求命令非空。
    """
    command, args = daily_mod.daily_report_command(tmp_path)
    assert args[0] == "-c"
    assert args[1] == "from aaa.cli import main; main()"
    assert args[-5:] == ["report", "--daily", "--email", "--data-dir", str(tmp_path)]
    if os.name == "nt":
        assert command.endswith(".exe")  # pythonw.exe / python.exe
    else:
        assert bool(command)

    monkeypatch.setattr(daily_mod.sys, "frozen", True, raising=False)
    frozen_command, frozen_args = daily_mod.daily_report_command(tmp_path)
    assert frozen_command == "cmd.exe"
    assert frozen_args[0] == "/c"
    assert frozen_args[-5:] == ["report", "--daily", "--email", "--data-dir", str(tmp_path)]
