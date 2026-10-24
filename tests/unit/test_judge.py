"""LLM 辅助判定单测（05 文档波次一 W3）：全部注入式假客户端，零真实网络。

覆盖合同用例：正常解析 / 非法 JSON 容错 / 超时容错 / 预算封顶后跳过 / 默认关闭；
以及红线补充：任何异常收敛 unavailable、API key 不落盘不进 verdict、按日预算滚动。
"""

from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from aaa.config import resolve_paths
from aaa.judge import (
    DEFAULT_JUDGE_USAGE_FILENAME,
    JUDGE_API_KEY_ENV,
    REASON_MAX_CHARS,
    SYSTEM_PROMPT,
    JudgeConfig,
    JudgeUsageStore,
    JudgeVerdict,
    LLMJudge,
    default_judge_client_factory,
)

DAY1 = _dt.date(2026, 10, 24)
DAY2 = _dt.date(2026, 10, 25)
KEY = "sk-test-key-abcdef123456"
SUMMARY = "进程 git.exe 外发 512KB 代码到 https://api.example.com；命中规则 aws-access-token"


# ---------------------------------------------------------------------- 测试假件


class FakeResponse:
    """假 ``/chat/completions`` 响应：带 status_code / text / json()。"""

    def __init__(
        self,
        *,
        status_code: int = 200,
        payload: Any = None,
        text: str = "",
        json_error: Exception | None = None,
    ) -> None:
        self.status_code = status_code
        self._payload = payload
        self._text = text
        self._json_error = json_error

    @property
    def text(self) -> str:
        return self._text

    def json(self) -> Any:
        if self._json_error is not None:
            raise self._json_error
        return self._payload


class FakeClient:
    """假 HTTP 客户端：记录调用，可注入固定响应或异常。"""

    def __init__(
        self, *, response: FakeResponse | None = None, error: Exception | None = None
    ) -> None:
        self.calls: list[dict[str, Any]] = []
        self.closed = False
        self._response = response
        self._error = error

    def post(self, url: str, *, json: Any = None, headers: Any = None) -> FakeResponse:
        self.calls.append({"url": url, "json": json, "headers": headers})
        if self._error is not None:
            raise self._error
        assert self._response is not None, "假客户端未配置响应"
        return self._response

    def close(self) -> None:
        self.closed = True


class RecordingFactory:
    """记录构造次数的客户端工厂（所有调用共享同一个假客户端以便断言累计）。"""

    def __init__(self, client: FakeClient | None = None) -> None:
        self.client = client if client is not None else FakeClient()
        self.count = 0

    def __call__(self) -> FakeClient:
        self.count += 1
        return self.client


# ------------------------------------------------------------------------ 夹具


def _stepping_clock(start: _dt.date) -> tuple[Any, Any]:
    """可推进的假时钟：返回 (clock, advance)，advance 跳到下一天。"""
    state = {"day": start}

    def clock() -> _dt.date:
        return state["day"]

    def advance() -> None:
        state["day"] = state["day"] + _dt.timedelta(days=1)

    return clock, advance


def _config(**overrides: Any) -> JudgeConfig:
    """测试用配置基座：enabled=True + 完整 api_base/model，按需覆盖。"""
    fields: dict[str, Any] = {
        "enabled": True,
        "api_base": "https://llm.example.com/v1",
        "model": "audit-model",
        "timeout": 8.0,
        "max_events_per_day": 5,
    }
    fields.update(overrides)
    return JudgeConfig(**fields)


def _verdict_content(**overrides: Any) -> str:
    """构造一次"规范 LLM 输出"的 content 字符串。"""
    payload: dict[str, Any] = {
        "is_violation": True,
        "confidence": 0.9,
        "reason": "包含 AWS 密钥",
        "category": "secrets",
    }
    payload.update(overrides)
    return json.dumps(payload, ensure_ascii=False)


def _ok_response(content: str | None = None, **kwargs: Any) -> FakeResponse:
    """choices[0].message.content = 规范 JSON 判定 的 200 响应。"""
    body = _verdict_content() if content is None else content
    return FakeResponse(
        payload={"choices": [{"message": {"role": "assistant", "content": body}}]},
        **kwargs,
    )


def _make_judge(
    factory: RecordingFactory,
    tmp_path: Path,
    *,
    config: JudgeConfig | None = None,
    clock: Any = None,
    environ: dict[str, str] | None = None,
) -> LLMJudge:
    """装配被测对象：独立预算文件 + 固定日期时钟 + 注入环境映射。"""
    if clock is None:
        clock, _ = _stepping_clock(DAY1)
    return LLMJudge(
        config if config is not None else _config(),
        client_factory=factory,
        usage_path=tmp_path / DEFAULT_JUDGE_USAGE_FILENAME,
        environ={JUDGE_API_KEY_ENV: KEY} if environ is None else environ,
        clock=clock,
    )


# ------------------------------------------------------------------- 正常解析


def test_ok_verdict_parsed(tmp_path: Path) -> None:
    """正常路径：JSON 判定被解析为 ok 结论，请求形态与预算落盘正确。"""
    factory = RecordingFactory(FakeClient(response=_ok_response()))
    judge = _make_judge(factory, tmp_path)

    verdict = judge.judge(SUMMARY)

    assert verdict.is_ok and verdict.status == "ok"
    assert verdict.is_violation is True
    assert verdict.confidence == pytest.approx(0.9)
    assert verdict.reason == "包含 AWS 密钥"
    assert verdict.category == "secrets"
    assert factory.count == 1
    client = factory.client
    assert client.closed, "每次判定后客户端必须被关闭"
    assert len(client.calls) == 1
    call = client.calls[0]
    assert call["url"] == "https://llm.example.com/v1/chat/completions"
    assert call["headers"] == {"Authorization": f"Bearer {KEY}"}
    payload = call["json"]
    assert payload["model"] == "audit-model"
    assert payload["temperature"] == 0
    assert payload["stream"] is False
    assert payload["messages"][0] == {"role": "system", "content": SYSTEM_PROMPT}
    assert payload["messages"][1] == {"role": "user", "content": SUMMARY}
    usage = json.loads((tmp_path / DEFAULT_JUDGE_USAGE_FILENAME).read_text(encoding="utf-8"))
    assert usage == {"date": "2026-10-24", "count": 1}
    assert judge.today_usage() == 1


def test_api_base_trailing_slash_joined_once(tmp_path: Path) -> None:
    factory = RecordingFactory(FakeClient(response=_ok_response()))
    judge = _make_judge(factory, tmp_path, config=_config(api_base="https://llm.example.com/v1/"))
    judge.judge(SUMMARY)
    assert factory.client.calls[0]["url"] == "https://llm.example.com/v1/chat/completions"


def test_markdown_fenced_output_accepted(tmp_path: Path) -> None:
    """模型把 JSON 包进 Markdown 围栏：仍可解析（宽容但确定）。"""
    fenced = "```json\n" + _verdict_content() + "\n```"
    factory = RecordingFactory(FakeClient(response=_ok_response(content=fenced)))
    verdict = _make_judge(factory, tmp_path).judge(SUMMARY)
    assert verdict.is_ok and verdict.is_violation is True


def test_prose_around_json_accepted(tmp_path: Path) -> None:
    """模型在 JSON 前后加了说明文字：截取大括号片段仍可解析。"""
    noisy = "判定如下：\n" + _verdict_content() + "\n以上。"
    factory = RecordingFactory(FakeClient(response=_ok_response(content=noisy)))
    verdict = _make_judge(factory, tmp_path).judge(SUMMARY)
    assert verdict.is_ok and verdict.category == "secrets"


def test_system_prompt_demands_json_only() -> None:
    """红线契约：system 提示要求只输出 JSON 且给出固定字段。"""
    assert "只输出" in SYSTEM_PROMPT and "JSON" in SYSTEM_PROMPT
    for field in ("is_violation", "confidence", "reason", "category"):
        assert field in SYSTEM_PROMPT


def test_model_reason_truncated(tmp_path: Path) -> None:
    """模型超长理由被截断到上限，不进事件流刷屏。"""
    content = _verdict_content(reason="长" * 600)
    factory = RecordingFactory(FakeClient(response=_ok_response(content=content)))
    verdict = _make_judge(factory, tmp_path).judge(SUMMARY)
    assert verdict.is_ok
    assert len(verdict.reason) == REASON_MAX_CHARS


# --------------------------------------------------------------- 非法 JSON 容错


def test_plain_text_output_converges_unavailable(tmp_path: Path) -> None:
    """非法 JSON（纯文本输出）→ unavailable；且不消耗预算。"""
    factory = RecordingFactory(FakeClient(response=_ok_response(content="我认为这次外发有问题。")))
    verdict = _make_judge(factory, tmp_path).judge(SUMMARY)
    assert verdict.status == "unavailable" and not verdict.is_ok
    assert verdict.is_violation is False
    assert verdict.confidence == 0.0
    assert verdict.category == ""
    assert not (tmp_path / DEFAULT_JUDGE_USAGE_FILENAME).exists()


def test_broken_json_with_braces_converges_unavailable(tmp_path: Path) -> None:
    factory = RecordingFactory(FakeClient(response=_ok_response(content='{"is_violation": true,')))
    verdict = _make_judge(factory, tmp_path).judge(SUMMARY)
    assert verdict.status == "unavailable"
    assert factory.count == 1 and judge_usage_count(tmp_path) == 0


def test_non_dict_json_output_converges_unavailable(tmp_path: Path) -> None:
    factory = RecordingFactory(FakeClient(response=_ok_response(content='["is_violation", true]')))
    verdict = _make_judge(factory, tmp_path).judge(SUMMARY)
    assert verdict.status == "unavailable"


def test_non_json_body_converges_unavailable(tmp_path: Path) -> None:
    """响应体不是 JSON（如 HTML 错误页）→ unavailable，不抛异常。"""
    response = FakeResponse(json_error=json.JSONDecodeError("Expecting value", "<html>", 0))
    factory = RecordingFactory(FakeClient(response=response))
    verdict = _make_judge(factory, tmp_path).judge(SUMMARY)
    assert verdict.status == "unavailable"
    assert "JSON" in verdict.reason


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"choices": []},
        {"choices": ["oops"]},
        {"choices": [{}]},
        {"choices": [{"message": {}}]},
        {"choices": [{"message": {"content": None}}]},
    ],
    ids=["empty", "no-choices", "bad-choice", "no-message", "no-content", "null-content"],
)
def test_malformed_response_structure_converges_unavailable(payload: Any, tmp_path: Path) -> None:
    factory = RecordingFactory(FakeClient(response=FakeResponse(payload=payload)))
    verdict = _make_judge(factory, tmp_path).judge(SUMMARY)
    assert verdict.status == "unavailable"
    assert "choices" in verdict.reason or "JSON" in verdict.reason


@pytest.mark.parametrize(
    "content",
    [
        _verdict_content(is_violation="yes"),  # 布尔字段非法
        _verdict_content(confidence="abc"),  # 置信度不是数字
        _verdict_content(confidence="nan"),  # NaN 视为非法
        _verdict_content(confidence=None),  # 缺失置信度（None）
        json.dumps({"is_violation": True}),  # 缺失置信度（键不存在）
    ],
)
def test_illegal_verdict_fields_converge_unavailable(content: str, tmp_path: Path) -> None:
    factory = RecordingFactory(FakeClient(response=_ok_response(content=content)))
    verdict = _make_judge(factory, tmp_path).judge(SUMMARY)
    assert verdict.status == "unavailable"


def test_field_coercion_and_clamping(tmp_path: Path) -> None:
    """宽容面：字符串布尔/数字字符串可解析；越界置信度收敛到 [0,1]。"""
    tolerant = _verdict_content(is_violation="true", confidence="0.85")
    factory = RecordingFactory(FakeClient(response=_ok_response(content=tolerant)))
    verdict = _make_judge(factory, tmp_path).judge(SUMMARY)
    assert verdict.is_ok and verdict.is_violation is True
    assert verdict.confidence == pytest.approx(0.85)

    over = _verdict_content(confidence=95)
    factory2 = RecordingFactory(FakeClient(response=_ok_response(content=over)))
    assert _make_judge(factory2, tmp_path).judge(SUMMARY).confidence == 1.0

    under = _verdict_content(confidence=-2)
    factory3 = RecordingFactory(FakeClient(response=_ok_response(content=under)))
    assert _make_judge(factory3, tmp_path).judge(SUMMARY).confidence == 0.0


# ------------------------------------------------------------------ 超时/网络容错


def test_timeout_converges_unavailable_and_no_budget_used(tmp_path: Path) -> None:
    """超时（httpx.ReadTimeout）→ unavailable；预算不计数（失败调用没有产出）。"""
    factory = RecordingFactory(FakeClient(error=httpx.ReadTimeout("timed out")))
    verdict = _make_judge(factory, tmp_path).judge(SUMMARY)
    assert verdict.status == "unavailable"
    assert factory.count == 1
    assert judge_usage_count(tmp_path) == 0
    assert factory.client.closed, "即使 post 抛异常客户端也要被关闭"


def test_any_exception_converges_unavailable(tmp_path: Path) -> None:
    """任意异常（连接拒绝/编码错误/假对象行为异常）都收敛为 unavailable。"""
    factory = RecordingFactory(FakeClient(error=ConnectionError("connection refused")))
    assert _make_judge(factory, tmp_path).judge(SUMMARY).status == "unavailable"

    factory2 = RecordingFactory(FakeClient(response=FakeResponse(status_code="200")))  # 类型异常
    verdict = _make_judge(factory2, tmp_path).judge(SUMMARY)
    assert verdict.status == "unavailable"
    assert "HTTP" in verdict.reason


def test_non_2xx_converges_unavailable_and_scrubs_key(tmp_path: Path) -> None:
    """非 2xx → unavailable；失败原因里引用的响应体必须把 key 替换为 ***。"""
    response = FakeResponse(status_code=502, text=f"bad gateway, auth={KEY}, retry later")
    factory = RecordingFactory(FakeClient(response=response))
    verdict = _make_judge(factory, tmp_path).judge(SUMMARY)
    assert verdict.status == "unavailable"
    assert "502" in verdict.reason
    assert KEY not in verdict.reason
    assert "***" in verdict.reason


# ------------------------------------------------------------- 预算封顶/按日落盘


def judge_usage_count(tmp_path: Path) -> int:
    """读预算文件里的 count 字段（按文件内容断言，不依赖真实时钟）。

    此前经 ``JudgeUsageStore.today_count()`` 读取——它按**真实本地日期**判定"今天"，
    而被测 judge 用注入的假时钟（DAY1）落盘：跨日运行套件（真实日期 ≠ DAY1）时
    文件日期会被判为"不是今天"恒返回 0，test_budget_capped_skips_call 因此在
    2026-10-25 零点后偶发红（已实测复现）。按日滚动的语义本身由
    test_usage_store_rolls_over_by_day（注入时钟）覆盖，此处只需核对文件内容。
    """
    path = tmp_path / DEFAULT_JUDGE_USAGE_FILENAME
    if not path.exists():
        return 0
    import json

    data = json.loads(path.read_text(encoding="utf-8"))
    return int(data.get("count", 0))


def test_budget_capped_skips_call(tmp_path: Path) -> None:
    """预算封顶后跳过：不再发请求、返回 budget_exceeded、计数不变。"""
    factory = RecordingFactory(FakeClient(response=_ok_response()))
    judge = _make_judge(factory, tmp_path, config=_config(max_events_per_day=2))

    assert judge.judge(SUMMARY).is_ok
    assert judge.judge(SUMMARY).is_ok
    assert factory.count == 2

    verdict = judge.judge(SUMMARY)
    assert verdict.status == "budget_exceeded" and not verdict.is_ok
    assert "2/2" in verdict.reason
    assert factory.count == 2, "封顶后不得再发起 HTTP 调用"
    assert judge_usage_count(tmp_path) == 2
    assert judge.today_usage() == 2


def test_budget_zero_never_calls(tmp_path: Path) -> None:
    factory = RecordingFactory(FakeClient(response=_ok_response()))
    verdict = _make_judge(factory, tmp_path, config=_config(max_events_per_day=0)).judge(SUMMARY)
    assert verdict.status == "budget_exceeded"
    assert factory.count == 0


def test_budget_counts_only_disk_state(tmp_path: Path) -> None:
    """预算以落盘计数为准：手改文件为今天、超限 → 直接跳过。"""
    usage_path = tmp_path / DEFAULT_JUDGE_USAGE_FILENAME
    usage_path.write_text(json.dumps({"date": "2026-10-24", "count": 999999}), encoding="utf-8")
    factory = RecordingFactory(FakeClient(response=_ok_response()))
    verdict = _make_judge(factory, tmp_path).judge(SUMMARY)
    assert verdict.status == "budget_exceeded"
    assert factory.count == 0


def test_budget_resets_next_day(tmp_path: Path) -> None:
    """按日滚动：文件日期不是今天即归零；新一天的判定重新计数落盘。"""
    clock, advance = _stepping_clock(DAY1)
    factory = RecordingFactory(FakeClient(response=_ok_response()))
    judge = _make_judge(factory, tmp_path, config=_config(max_events_per_day=2), clock=clock)

    assert judge.judge(SUMMARY).is_ok
    assert judge.judge(SUMMARY).is_ok
    assert judge.judge(SUMMARY).status == "budget_exceeded"

    advance()
    verdict = judge.judge(SUMMARY)
    assert verdict.is_ok, "跨日后预算归零，恢复判定"
    assert factory.count == 3
    usage = json.loads((tmp_path / DEFAULT_JUDGE_USAGE_FILENAME).read_text(encoding="utf-8"))
    assert usage == {"date": "2026-10-25", "count": 1}


def test_stale_usage_file_rolls_over(tmp_path: Path) -> None:
    """历史遗留（旧日期、超limit计数）不阻塞新一天：读作 0，写回新计数。"""
    usage_path = tmp_path / DEFAULT_JUDGE_USAGE_FILENAME
    usage_path.write_text(json.dumps({"date": "2020-01-01", "count": 999999}), encoding="utf-8")
    factory = RecordingFactory(FakeClient(response=_ok_response()))
    verdict = _make_judge(factory, tmp_path, config=_config(max_events_per_day=5)).judge(SUMMARY)
    assert verdict.is_ok
    usage = json.loads(usage_path.read_text(encoding="utf-8"))
    assert usage == {"date": "2026-10-24", "count": 1}


def test_corrupt_usage_file_treated_as_zero(tmp_path: Path) -> None:
    """预算文件损坏：按 0 重新开始（成本护栏不阻断判定），不抛异常。"""
    usage_path = tmp_path / DEFAULT_JUDGE_USAGE_FILENAME
    usage_path.write_text("not-json{{{", encoding="utf-8")
    factory = RecordingFactory(FakeClient(response=_ok_response()))
    verdict = _make_judge(factory, tmp_path).judge(SUMMARY)
    assert verdict.is_ok
    assert json.loads(usage_path.read_text(encoding="utf-8"))["count"] == 1


def test_usage_persist_failure_converges_unavailable(tmp_path: Path) -> None:
    """红线 1 全覆盖：预算落盘失败（路径是目录）→ 结论收敛为 unavailable，绝不抛出。"""
    usage_dir = tmp_path / "usage-dir"
    usage_dir.mkdir()
    factory = RecordingFactory(FakeClient(response=_ok_response()))
    judge = LLMJudge(
        _config(),
        client_factory=factory,
        usage_path=usage_dir,
        environ={JUDGE_API_KEY_ENV: KEY},
    )
    verdict = judge.judge(SUMMARY)
    assert verdict.status == "unavailable"
    assert "异常" in verdict.reason


def test_default_usage_path_contract() -> None:
    """默认落点 = <data_dir>/judge-usage.json（05 文档 W3）。"""
    store = JudgeUsageStore()
    assert store.path == resolve_paths().data_dir / DEFAULT_JUDGE_USAGE_FILENAME


# -------------------------------------------------------------------- 门禁与关闭


def test_disabled_by_default_no_http(tmp_path: Path) -> None:
    """默认关闭：JudgeConfig() 出厂 enabled=False，不发起任何请求。"""
    factory = RecordingFactory()
    judge = LLMJudge(
        JudgeConfig(),
        client_factory=factory,
        usage_path=tmp_path / DEFAULT_JUDGE_USAGE_FILENAME,
        environ={JUDGE_API_KEY_ENV: KEY},
    )
    verdict = judge.judge(SUMMARY)
    assert verdict.status == "unavailable"
    assert "未启用" in verdict.reason
    assert factory.count == 0
    assert not (tmp_path / DEFAULT_JUDGE_USAGE_FILENAME).exists()


def test_missing_api_key_no_http(tmp_path: Path) -> None:
    """未设置 AAA_JUDGE_API_KEY → unavailable，不发起请求（key 不落盘不进配置）。"""
    factory = RecordingFactory()
    verdict = _make_judge(factory, tmp_path, environ={}).judge(SUMMARY)
    assert verdict.status == "unavailable"
    assert JUDGE_API_KEY_ENV in verdict.reason
    assert factory.count == 0


def test_only_named_env_var_is_consulted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """key **只**认 AAA_JUDGE_API_KEY：注入映射为空时，真实环境里的同名变量不参与。"""
    monkeypatch.setenv(JUDGE_API_KEY_ENV, KEY)
    factory = RecordingFactory()
    verdict = _make_judge(factory, tmp_path, environ={}).judge(SUMMARY)
    assert verdict.status == "unavailable"
    assert factory.count == 0


def test_real_env_var_used_when_no_mapping_injected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """默认路径（os.environ）：设置 AAA_JUDGE_API_KEY 即可用。"""
    monkeypatch.setenv(JUDGE_API_KEY_ENV, KEY)
    factory = RecordingFactory(FakeClient(response=_ok_response()))
    judge = LLMJudge(
        _config(),
        client_factory=factory,
        usage_path=tmp_path / DEFAULT_JUDGE_USAGE_FILENAME,
        environ=None,
    )
    assert judge.judge(SUMMARY).is_ok


def test_incomplete_config_no_http(tmp_path: Path) -> None:
    """api_base/model 缺失 → unavailable，不发请求。"""
    factory = RecordingFactory()
    assert _make_judge(factory, tmp_path, config=_config(api_base="")).judge(SUMMARY).status == (
        "unavailable"
    )
    assert _make_judge(factory, tmp_path, config=_config(model="")).judge(SUMMARY).status == (
        "unavailable"
    )
    assert factory.count == 0


def test_empty_summary_no_http(tmp_path: Path) -> None:
    factory = RecordingFactory()
    judge = _make_judge(factory, tmp_path)
    assert judge.judge("").status == "unavailable"
    assert judge.judge("   \n  ").status == "unavailable"
    assert factory.count == 0


# ------------------------------------------------------------------ key 不落盘


def test_api_key_never_persisted(tmp_path: Path) -> None:
    """红线 2：成功判定后，预算文件与 verdict 里都不出现 key。"""
    factory = RecordingFactory(FakeClient(response=_ok_response()))
    judge = _make_judge(factory, tmp_path)
    verdict = judge.judge(SUMMARY)
    usage_text = (tmp_path / DEFAULT_JUDGE_USAGE_FILENAME).read_text(encoding="utf-8")
    assert KEY not in usage_text
    assert KEY not in verdict.model_dump_json()
    # key 只出现在请求头里（发送给配置的端点是预期行为）
    assert factory.client.calls[0]["headers"] == {"Authorization": f"Bearer {KEY}"}


# ------------------------------------------------------------------- 模型与工厂


def test_unavailable_and_budget_verdict_shapes() -> None:
    u = JudgeVerdict.unavailable("原因")
    assert u.status == "unavailable" and not u.is_ok
    assert u.is_violation is False and u.confidence == 0.0 and u.category == ""

    b = JudgeVerdict.budget_exceeded(3, 3)
    assert b.status == "budget_exceeded" and not b.is_ok
    assert b.is_violation is False and "3/3" in b.reason


def test_unavailable_reason_truncated() -> None:
    assert len(JudgeVerdict.unavailable("长" * 600).reason) == REASON_MAX_CHARS


def test_verdict_confidence_bounds_enforced() -> None:
    with pytest.raises(ValidationError):
        JudgeVerdict(status="ok", is_violation=True, confidence=1.5)
    with pytest.raises(ValidationError):
        JudgeVerdict(status="ok", confidence=-0.1)


def test_default_config_values() -> None:
    """05 文档 W3 出厂值：默认关闭 + timeout=8s。"""
    config = JudgeConfig()
    assert config.enabled is False
    assert config.timeout == 8.0
    assert config.api_base == "" and config.model == ""


def test_default_factory_builds_direct_httpx_client() -> None:
    """生产工厂：httpx.Client、trust_env=False（防自代理回环）、注入的 timeout 生效。"""
    client = default_judge_client_factory(8.0)
    try:
        assert isinstance(client, httpx.Client)
        assert client.trust_env is False
        assert client.timeout == httpx.Timeout(8.0)
    finally:
        client.close()
