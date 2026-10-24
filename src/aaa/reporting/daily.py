"""日报/周报：自包含 HTML 渲染、邮件发送与每日计划任务（06 文档 W6）。

- ``render_daily(store, day) -> str``：本地自然日窗口的自包含 HTML——按判定/进程/
  主机/规则聚合 + Top 事件表 + 趋势 sparkline（**内联 SVG**，无外部资源、无脚本）；
- ``render_weekly(store, day)``：含 ``day`` 的 ISO 自然周（周一为始），按天分桶；
- ``email_daily(config, html)``：复用 notify 侧 ``EmailConfig`` 与其**注入式 SMTP**
  红线（默认实现镜像 ``notify.channels.send_email`` 的 SSL/starttls 形态，正文
  ``subtype="html"``；测试注入 ``sender``，绝不真发）。不 import ``notify.channels``
  本体——其顶层依赖 httpx（非运行时依赖），日报保持零第三方依赖；
- ``install_daily_task(state, data_dir, *, hour=9)``：schtasks 每日触发
  ``aaa report --daily --email``（journal-first + teardown 还原器注册，机制同
  ``setup/service.py``；``data_dir`` 为规格空档补位——任务命令行需显式
  ``--data-dir``，与 ``autostart_command`` 同策略，见 decisions D-40）。

脱敏红线：报告是对外可见产物——自由文本字段（请求路径/进程名）先过
``notify.summary.mask_event_path``（与通知摘要同一脱敏核心：规则 + allowlist + 熵）
再统一 HTML 转义；聚合展示一律取元数据（host/进程名/规则 id），**绝不渲染 body**
与证据原文。系统级 schtasks 只经 ``_run_schtasks`` 注入点，单测全 mock，绝不真实施改。
"""

from __future__ import annotations

import logging
import subprocess
import sys
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta
from html import escape
from pathlib import Path
from typing import Protocol
from xml.sax.saxutils import escape as _xml_escape

from aaa.notify.model import EmailConfig
from aaa.notify.summary import mask_event_path
from aaa.setup.state import StateEntry, StateFile
from aaa.setup.teardown import register_restorer
from aaa.store.events import AuditEvent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------- 常量

#: 计划任务名（与 AutoStart/Watchdog/Service 任务同一前缀约定）
DAILY_REPORT_TASK_NAME = "EgressSentinel-DailyReport"

#: journal 记录类型（teardown 据此路由到 :func:`restore_daily_report_task`）
KIND_DAILY_REPORT_TASK = "daily_report_task"

#: 默认每日触发时刻（06 文档 W6：``hour=9``）
DEFAULT_REPORT_HOUR = 9

#: 报告标题
DAILY_TITLE = "EgressSentinel 安全日报"
WEEKLY_TITLE = "EgressSentinel 安全周报"

#: 单次聚合最多读取的事件数（防御性上限，超出如实标记截断）
MAX_EVENTS = 50_000

#: 分页读取页大小（``store.query`` 每页）
PAGE_SIZE = 500

#: Top 榜单行数 / Top 事件表行数
TOP_ROWS = 10
TOP_EVENTS = 10

#: SMTP 连接超时（秒；与 notify.channels 同值）
SMTP_TIMEOUT_SECONDS = 10.0

#: 日报趋势：24 个小时桶标签
HOUR_LABELS: tuple[str, ...] = tuple(f"{hour:02d}:00" for hour in range(24))

#: 默认 SMTP 发送实现（镜像 ``notify.channels.send_email``：SSL 或 starttls）
DailyEmailSender = Callable[[EmailConfig, str, str], None]
"""注入点：``(config, subject, html) -> None``；单测注入记录器，绝不真发。"""


class ReportStore(Protocol):
    """渲染所需的事件窄接口（``DbEventStore`` 结构化兼容；单测可注入假实现）。"""

    def query(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[AuditEvent], int]:
        """分页查询时间窗口内事件（``(events, total)``）。"""
        ...


class DailyReportTaskError(RuntimeError):
    """日报计划任务创建失败（journal 记录保留，teardown/重试可用）。"""


# ---------------------------------------------------------------- 聚合


@dataclass
class ReportData:
    """一次聚合的结果（渲染的唯一数据源；单遍遍历保证口径一致）。"""

    title: str
    """报告标题（含窗口日期）。"""
    window_start: datetime
    """统计窗口起点（本地时区，含）。"""
    window_end: datetime
    """统计窗口终点（本地时区，不含）。"""
    total: int
    """窗口内事件总数。"""
    by_verdict: list[tuple[str, int]] = field(default_factory=list)
    """``[(verdict, n), …]`` 按条数降序。"""
    by_process: list[tuple[str, int]] = field(default_factory=list)
    """``[("name(pid)" | "unknown", n), …]`` 按条数降序取 Top。"""
    by_host: list[tuple[str, int]] = field(default_factory=list)
    """``[(host, n), …]`` 按条数降序取 Top。"""
    by_rule: list[tuple[str, int]] = field(default_factory=list)
    """``[("id(dim)", n), …]`` 按条数降序取 Top。"""
    trend: list[int] = field(default_factory=list)
    """趋势桶计数（日报 24 小时桶 / 周报 7 天桶）。"""
    trend_peak: str = "—"
    """峰值桶的人读描述（``"12:00（N 条）"``；无数据为 ``"—"``）。"""
    top_events: list[AuditEvent] = field(default_factory=list)
    """Top 事件（风险分降序、同分取新），截断 ``TOP_EVENTS``。"""
    truncated: bool = False
    """是否触及 ``MAX_EVENTS`` 上限（渲染时会如实标注）。"""


def _event_dt(ts: str) -> datetime | None:
    """事件 ISO 时间戳 → aware datetime（naive 按本地时区解释；解析失败返回 None）。"""
    try:
        parsed = datetime.fromisoformat(ts)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.astimezone()
    return parsed


def _epoch(ts: str) -> float:
    """Top 事件排序用的 epoch（解析失败按 0，保证确定性）。"""
    parsed = _event_dt(ts)
    return parsed.timestamp() if parsed else 0.0


def _process_label(event: AuditEvent) -> str:
    """进程展示名：``name(pid)``；未归因为 ``unknown``（与 notify.summary 同形态）。"""
    process = event.process
    if process is None:
        return "unknown"
    name = process.name or "unknown"
    pid = str(process.pid) if process.pid is not None else "?"
    return f"{name}({pid})"


def _rules_label(event: AuditEvent) -> str:
    """命中规则展示名：``id(dim)`` 逗号连接（只取规则元数据，不展示 evidence）。"""
    parts = [
        f"{rule.get('id', '?')}({rule.get('dim', '?')})"
        for rule in event.matched_rules
        if isinstance(rule, dict)
    ]
    return ", ".join(parts) if parts else "-"


def _iter_window(store: ReportStore, since: datetime, until: datetime) -> list[AuditEvent]:
    """分页拉取 ``[since, until]`` 窗口事件（store 的 until 为闭区间，调用方再过滤）。"""
    events: list[AuditEvent] = []
    offset = 0
    while True:
        page, _total = store.query(since=since, until=until, limit=PAGE_SIZE, offset=offset)
        if not page:
            return events
        events.extend(page)
        offset += len(page)
        if offset >= MAX_EVENTS:
            return events


def _collect(
    store: ReportStore,
    *,
    title: str,
    since: datetime,
    until: datetime,
    buckets: int,
    labels: Sequence[str],
) -> ReportData:
    """单遍聚合窗口事件：判定/进程/主机/规则计数 + 趋势桶 + Top 事件。

    口径说明：``DbEventStore.query`` 的 ``until`` 是闭区间，这里在 Python 侧再按
    ``since <= ts < until`` 过滤，保证报告总数与窗口语义（左闭右开）一致。
    """
    bucket_seconds = (until - since).total_seconds() / buckets
    trend = [0] * buckets
    verdicts: Counter[str] = Counter()
    hosts: Counter[str] = Counter()
    processes: Counter[tuple[int | None, str]] = Counter()
    rules: Counter[tuple[str, str]] = Counter()
    window_events: list[AuditEvent] = []
    for event in _iter_window(store, since, until):
        when = _event_dt(event.ts)
        if when is None or not (since <= when < until):
            continue
        verdicts[event.verdict] += 1
        hosts[event.destination.host] += 1
        process = event.process
        processes[(process.pid if process else None, _process_label(event))] += 1
        for rule in event.matched_rules:
            if isinstance(rule, dict):
                rules[(str(rule.get("id", "?")), str(rule.get("dim", "?")))] += 1
        index = int((when - since).total_seconds() // bucket_seconds)
        trend[min(index, buckets - 1)] += 1  # 防御浮点误差钳制到最后一桶
        window_events.append(event)
        if len(window_events) >= MAX_EVENTS:
            break
    by_process = sorted(
        # 脱敏红线：进程名可能含密钥片段（如被复制的 token），聚合榜与事件表同一防线
        ((mask_event_path(label), n) for (_pid, label), n in processes.items()),
        key=lambda kv: (-kv[1], kv[0]),
    )[:TOP_ROWS]
    peak = max(trend) if trend else 0
    return ReportData(
        title=title,
        window_start=since,
        window_end=until,
        total=len(window_events),
        by_verdict=sorted(verdicts.items(), key=lambda kv: (-kv[1], kv[0])),
        by_process=by_process,
        by_host=sorted(hosts.items(), key=lambda kv: (-kv[1], kv[0]))[:TOP_ROWS],
        by_rule=[
            (f"{rule_id}({dim})", n)
            for (rule_id, dim), n in sorted(
                rules.items(), key=lambda kv: (-kv[1], kv[0])
            )[:TOP_ROWS]
        ],
        trend=trend,
        trend_peak=f"{labels[trend.index(peak)]}（{peak} 条）" if peak > 0 else "—",
        top_events=sorted(
            window_events, key=lambda e: (-e.risk_score, -_epoch(e.ts))
        )[:TOP_EVENTS],
        truncated=len(window_events) >= MAX_EVENTS,
    )


def _day_window(day: date) -> tuple[datetime, datetime]:
    """本地自然日窗口 ``[00:00, 次日 00:00)``。"""
    start = datetime.combine(day, time.min).astimezone()
    return start, start + timedelta(days=1)


def render_daily(store: ReportStore, day: date) -> str:
    """渲染 ``day``（本地自然日）的自包含 HTML 日报。"""
    since, until = _day_window(day)
    data = _collect(
        store,
        title=f"{DAILY_TITLE}（{day.isoformat()}）",
        since=since,
        until=until,
        buckets=24,
        labels=HOUR_LABELS,
    )
    return _render_html(data)


def render_weekly(store: ReportStore, day: date) -> str:
    """渲染含 ``day`` 的 ISO 自然周（周一为始）的自包含 HTML 周报。"""
    monday = day - timedelta(days=day.weekday())
    sunday = monday + timedelta(days=6)
    start = datetime.combine(monday, time.min).astimezone()
    data = _collect(
        store,
        title=f"{WEEKLY_TITLE}（{monday.isoformat()} ~ {sunday.isoformat()}）",
        since=start,
        until=start + timedelta(days=7),
        buckets=7,
        labels=tuple((monday + timedelta(days=i)).strftime("%m-%d") for i in range(7)),
    )
    return _render_html(data)


# ---------------------------------------------------------------- sparkline


def sparkline_svg(
    values: Sequence[int], *, width: int = 280, height: int = 48, color: str = "#2563eb"
) -> str:
    """序列 → 内联 SVG 折线（自包含：无脚本/无外部引用；坐标仅数值，天然免注入）。

    空序列渲染「无数据」占位；全零渲染基线平线；单点复制为短线段保证 ``polyline``
    合法。峰值对齐顶端，基线在底部。
    """
    pad = 4.0
    span = height - 2 * pad
    if not values:
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
            f'role="img" aria-label="趋势图"><text x="{pad:.0f}" y="{height / 2:.1f}" '
            f'font-size="12" fill="#6b7280">无数据</text></svg>'
        )
    peak = max(values)

    def _y(value: int) -> float:
        if peak <= 0:
            return height - pad
        return pad + span * (1 - value / peak)

    count = len(values)
    if count == 1:
        xs = [width / 2.0, width / 2.0]
        ys = [_y(values[0]), _y(values[0])]
    else:
        step = (width - 2 * pad) / (count - 1)
        xs = [pad + i * step for i in range(count)]
        ys = [_y(value) for value in values]
    points = " ".join(f"{x:.1f},{y:.1f}" for x, y in zip(xs, ys, strict=True))
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-label="趋势图">'
        f'<polyline fill="none" stroke="{escape(color)}" stroke-width="2" '
        f'points="{points}"/></svg>'
    )


# ---------------------------------------------------------------- HTML 渲染


_CSS = """
    body { font-family: "Segoe UI", "Microsoft YaHei", sans-serif; margin: 24px auto;
           max-width: 960px; color: #1f2937; }
    h1 { font-size: 20px; }
    h2 { font-size: 15px; margin: 20px 0 6px; }
    table { border-collapse: collapse; margin: 6px 0 14px; }
    th, td { border: 1px solid #e5e7eb; padding: 3px 10px; font-size: 13px; text-align: left; }
    th { background: #f3f4f6; }
    .muted { color: #6b7280; font-size: 12px; }
    .warn { color: #b45309; font-size: 12px; }
"""


def _table(headers: Sequence[str], rows: Sequence[Sequence[object]]) -> str:
    """渲染数据表：**统一转义出口**——所有单元格在此过 ``html.escape``（防线单点）。"""
    if not rows:
        return '<p class="muted">无数据</p>'
    head = "".join(f"<th>{escape(str(header))}</th>" for header in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{escape(str(cell))}</td>" for cell in row) + "</tr>" for row in rows
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _section(title: str, body: str) -> str:
    return f"<h2>{escape(title)}</h2>{body}"


def _render_html(data: ReportData) -> str:
    """组装自包含 HTML（内联 CSS + 内联 SVG，无脚本/无外链）。"""
    verdict_note = " · ".join(f"{name} {count}" for name, count in data.by_verdict) or "无数据"
    parts = [
        "<!DOCTYPE html>",
        '<html lang="zh-CN"><head><meta charset="utf-8">',
        f"<title>{escape(data.title)}</title>",
        f"<style>{_CSS}</style></head><body>",
        f"<h1>{escape(data.title)}</h1>",
        f'<p class="muted">窗口：{data.window_start:%Y-%m-%d %H:%M} ~ '
        f"{data.window_end:%Y-%m-%d %H:%M}（本地时间，左闭右开）"
        f" · 共 {data.total} 条 · {escape(verdict_note)} · 峰值 {escape(data.trend_peak)}</p>",
        _section("趋势", sparkline_svg(data.trend)),
    ]
    if data.truncated:
        parts.append(
            f'<p class="warn">数据量超过聚合上限 {MAX_EVENTS} 条，'
            f"以下统计只覆盖窗口内前 {MAX_EVENTS} 条。</p>"
        )
    parts.append(_section("按判定", _table(("判定", "条数"), data.by_verdict)))
    parts.append(_section("Top 进程", _table(("进程", "条数"), data.by_process)))
    parts.append(_section("Top 主机", _table(("主机", "条数"), data.by_host)))
    parts.append(_section("Top 规则", _table(("规则", "条数"), data.by_rule)))
    parts.append(
        _section(
            "Top 事件（风险分降序）",
            _table(
                ("时间", "判定", "风险分", "进程", "主机", "请求", "命中规则"),
                [
                    (
                        event.ts,
                        event.verdict,
                        event.risk_score,
                        # 脱敏红线：路径/进程名过同一脱敏核心（逃过扫描器打码的
                        # 查询串密钥在这里兜底），随后由 _table 统一 HTML 转义
                        mask_event_path(_process_label(event)),
                        event.destination.host,
                        f"{event.request.method} {mask_event_path(event.request.path)}",
                        _rules_label(event),
                    )
                    for event in data.top_events
                ],
            ),
        )
    )
    parts.append(
        '<p class="muted">脱敏说明：路径/进程名等自由文本经密钥打码（与通知摘要'
        "同一核心），全部字段 HTML 转义；本报告不含请求体与证据原文。</p>"
    )
    parts.append("</body></html>")
    return "".join(parts)


# ---------------------------------------------------------------- 邮件


def _send_html_email(config: EmailConfig, subject: str, html: str) -> None:
    """默认 SMTP 发送实现（镜像 ``notify.channels.send_email``，正文 ``text/html``）。"""
    import smtplib
    from email.message import EmailMessage

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = config.from_addr or config.username
    message["To"] = ", ".join(config.to_addrs)
    message.set_content(html, subtype="html", charset="utf-8")
    if config.use_tls:
        with smtplib.SMTP_SSL(
            config.smtp_host, config.smtp_port, timeout=SMTP_TIMEOUT_SECONDS
        ) as server:
            _login_and_send(server, config, message)
    else:
        with smtplib.SMTP(
            config.smtp_host, config.smtp_port, timeout=SMTP_TIMEOUT_SECONDS
        ) as server:
            server.starttls()
            _login_and_send(server, config, message)


def _login_and_send(server: object, config: EmailConfig, message: object) -> None:
    if config.username:
        server.login(config.username, config.password)  # type: ignore[attr-defined]
    server.send_message(message)  # type: ignore[attr-defined]


def email_daily(
    config: EmailConfig,
    html: str,
    *,
    subject: str = DAILY_TITLE,
    sender: DailyEmailSender | None = None,
) -> None:
    """把渲染好的 HTML 日报经邮件通道发出（注入式；测试注入 ``sender`` 绝不真发）。

    配置不完整（缺 ``smtp_host`` 或 ``to_addrs``）直接 ``ValueError``——与
    ``notify.channels.build_channels`` 的跳过条件同口径，但日报是显式动作，
    静默跳过会让人误以为已发送，故如实报错。
    """
    if not config.smtp_host or not config.to_addrs:
        raise ValueError(
            "email 配置不完整：smtp_host 与 to_addrs 必填（策略 notifications.email 段）"
        )
    (sender or _send_html_email)(config, subject, html)


# ---------------------------------------------------------------- 计划任务


def _run_schtasks(args: list[str]) -> subprocess.CompletedProcess[str]:
    """执行 schtasks（测试注入点：monkeypatch 本函数，绝不真实施改）。"""
    return subprocess.run(
        ["schtasks", *args], capture_output=True, text=True, encoding="oem", errors="replace"
    )


def _quote(value: str) -> str:
    return f'"{value}"' if (" " in value or not value) else value


def daily_report_command(data_dir: Path) -> tuple[str, list[str]]:
    """每日触发 ``aaa report --daily --email`` 的命令行（解释器策略同 autostart_command）。

    venv 用 pythonw（无窗口；缺 pythonw 回退 python），frozen exe 经
    ``cmd start /min`` 最小化。``--data-dir`` 显式传入，保证任务与安装布局一致。
    """
    args = ["report", "--daily", "--email", "--data-dir", str(data_dir)]
    if getattr(sys, "frozen", False):  # PyInstaller exe：控制台程序，最小化启动
        return "cmd.exe", ["/c", "start", "", "/min", sys.executable, *args]
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    launcher = str(pythonw if pythonw.exists() else Path(sys.executable))
    return launcher, ["-c", "from aaa.cli import main; main()", *args]


def build_daily_task_xml(
    command: str, arguments: list[str], *, hour: int = DEFAULT_REPORT_HOUR
) -> str:
    """每日触发计划任务 XML（``CalendarTrigger``/``ScheduleByDay``，本地 ``hour:00``）。

    ``hour`` 非法（<0 或 >23）抛 ``ValueError``；``StartBoundary`` 取今天该时刻，
    已过点则由计划程序自然顺延到次日。
    """
    if not 0 <= hour <= 23:
        raise ValueError(f"hour 必须在 0-23：{hour}")
    start = datetime.now().astimezone().replace(hour=hour, minute=0, second=0, microsecond=0)
    arg_line = " ".join(_quote(argument) for argument in arguments)
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>{start.isoformat(timespec="seconds")}</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{_xml_escape(command)}</Command>
      <Arguments>{_xml_escape(arg_line)}</Arguments>
    </Exec>
  </Actions>
</Task>
"""


def install_daily_task(
    state: StateFile, data_dir: Path, *, hour: int = DEFAULT_REPORT_HOUR
) -> StateEntry:
    """journal-first 安装每日日报计划任务：先记录，再 ``schtasks /Create``。

    创建失败抛 ``DailyReportTaskError``（记录保留，teardown/重试可用）。
    """
    command, arguments = daily_report_command(data_dir)
    xml = build_daily_task_xml(command, arguments, hour=hour)  # hour 校验先于任何落盘
    xml_dir = data_dir / "tasks"
    xml_dir.mkdir(parents=True, exist_ok=True)
    xml_path = xml_dir / f"{DAILY_REPORT_TASK_NAME}.xml"
    xml_path.write_text(xml, encoding="utf-16")
    entry = state.record(
        kind=KIND_DAILY_REPORT_TASK,
        key=DAILY_REPORT_TASK_NAME,
        old=None,
        new={
            "task_name": DAILY_REPORT_TASK_NAME,
            "xml": str(xml_path),
            "command": command,
            "arguments": " ".join(_quote(argument) for argument in arguments),
            "hour": hour,
        },
        note=f"每日 {hour:02d}:00 触发 aaa report --daily --email",
    )
    result = _run_schtasks(["/Create", "/TN", DAILY_REPORT_TASK_NAME, "/XML", str(xml_path)])
    if result.returncode != 0:
        raise DailyReportTaskError(
            f"创建日报计划任务失败 {DAILY_REPORT_TASK_NAME}（记录保留，teardown 可重试）："
            f"{(result.stderr or result.stdout).strip()}"
        )
    logger.info("日报计划任务已创建：%s（每日 %02d:00）", DAILY_REPORT_TASK_NAME, hour)
    return entry


def _delete_task(task_name: str) -> bool:
    """删除计划任务；任务不存在视为已删除（幂等）。"""
    result = _run_schtasks(["/Delete", "/TN", task_name, "/F"])
    if result.returncode == 0:
        return True
    logger.debug("删除日报计划任务 %s 未执行（可能不存在）：%s", task_name, result.stderr)
    return False


def uninstall_daily_task(state: StateFile) -> bool:
    """删除日报计划任务并清 journal 记录（幂等）；返回是否有实际动作。"""
    removed_task = _delete_task(DAILY_REPORT_TASK_NAME)
    dropped = state.drop(KIND_DAILY_REPORT_TASK, DAILY_REPORT_TASK_NAME)
    return removed_task or dropped > 0


def restore_daily_report_task(state: StateFile, entry: StateEntry) -> None:
    """teardown 还原函数：删除 entry 对应任务（容忍不存在）并移除记录。"""
    meta = entry.new if isinstance(entry.new, dict) else {}
    task_name = str(meta.get("task_name") or entry.key)
    _delete_task(task_name)
    state.drop(entry.kind, entry.key)


#: 注册 teardown 还原器（``setup/service.py`` 同款机制；import 本模块即生效——
#: 集成层 CLI 需 import ``aaa.reporting.daily``）
register_restorer(KIND_DAILY_REPORT_TASK, restore_daily_report_task)


__all__ = [
    "DAILY_REPORT_TASK_NAME",
    "DAILY_TITLE",
    "DEFAULT_REPORT_HOUR",
    "DailyEmailSender",
    "DailyReportTaskError",
    "HOUR_LABELS",
    "KIND_DAILY_REPORT_TASK",
    "MAX_EVENTS",
    "ReportData",
    "ReportStore",
    "SMTP_TIMEOUT_SECONDS",
    "TOP_EVENTS",
    "TOP_ROWS",
    "WEEKLY_TITLE",
    "build_daily_task_xml",
    "daily_report_command",
    "email_daily",
    "install_daily_task",
    "render_daily",
    "render_weekly",
    "restore_daily_report_task",
    "sparkline_svg",
    "uninstall_daily_task",
]
