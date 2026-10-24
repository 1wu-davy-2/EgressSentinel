"""响应侧注入检测（05 文档 W4）：扫描响应/网页正文中的提示词注入特征。

规则来源：promptfoo / garak 公开语料**反推**的高频特征（人工归纳为常量规则表，
不搬运语料本身）。全部纯 regex / 启发式、无网络调用。覆盖五类：

- ``override``   指令覆盖（高危）：ignore previous instructions / 无视之前的指令 /
  忽略以上全部指令 / do not follow your initial instructions 等；
- ``role``       角色伪造：``<system>``、``## system``（整行标题）、"你现在是 DAN"、
  "没有任何限制的 AI"人设、聊天模板标记 ``<|im_start|>system`` / ``<<SYS>>``；
- ``jailbreak``  越狱模板标记：developer mode（需第二/第一人称或 reactivate 上下文）、
  DAN Mode、Do Anything Now、"越狱"（需 AI 词上下文，避免误伤 iOS 越狱文章）；
- ``hidden``     隐藏指令载体：零宽字符 U+200B-U+200D（阈值 + emoji ZWJ 白名单）、
  base64 大块 + "解码并执行"指示语（两者同现才报，"decode the JWT"类文档不报）；
- ``extraction`` 套取系统提示词（中危）：repeat/reveal your system prompt 等。

红线说明：

- 本模块**只检测与标注**（severity low|medium|high 供策略分级），不做阻断决策；
  响应侧集成一律 alert 级标注、不阻断（05 文档波次二 §3）；
- 正常技术文本零误报是验收线（tests/unit/test_injection.py 的正常语料全 0 命中）：
  歧义词（developer mode / 越狱 / system 标题）必须携带 AI/第二人称/整行标题等
  上下文才命中；
- 已知代价（docs/notes/decisions.md D-2026-10-24-35）：讲解聊天模板的文档会命中
  ``role-tag-template`` / ``role-tag-angle`` 等角色标记（中危、仅标注）；单个零宽
  字符视为复制残留不报（emoji ZWJ 序列已白名单）；
- 规则以模块常量 ``INJECTION_RULES`` 维护、逐条可测（test_injection.py 的
  ``_RULE_SAMPLES``）；零宽字符与 base64+解码两条为启发式（独立函数）。
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

from aaa.scanners.base import ScanHit, ScanResult

SCANNER_NAME = "injection"

Severity = Literal["low", "medium", "high"]
Category = Literal["override", "role", "jailbreak", "hidden", "extraction"]

#: 严重度排序（worst_severity / 集成分级用）
SEVERITY_ORDER: dict[str, int] = {"low": 0, "medium": 1, "high": 2}


@dataclass(frozen=True)
class InjectionRule:
    """一条注入特征规则（regex 型；零宽字符/base64 两条启发式不在此表）。"""

    rule_id: str
    category: Category
    description: str
    pattern: re.Pattern[str]
    severity: Severity


@dataclass(frozen=True)
class InjectionHit:
    """一次注入特征命中（05 文档 W4：pattern / 命中片段 / 严重度）。"""

    pattern: str
    """命中的规则 id（regex 源可对照 ``INJECTION_RULES``）。"""
    evidence: str
    """命中片段（±24 字符上下文、≤80 字符、不可见字符已显性化）。"""
    severity: Severity
    """严重度：low（弱信号）| medium（模板/人设/越狱标记）| high（直接劫持指令）。"""
    category: Category
    """特征类别：override / role / jailbreak / hidden / extraction。"""
    line: int | None = None
    """命中所在行号（1 起）。"""
    detail: str = ""
    """人类可读说明。"""


# ------------------------------------------------------------------ 隐藏载体常量

#: 零宽字符集（05 文档 W4：U+200B-U+200D；U+2060/U+FEFF 不计——BOM/词连接符误报面大）
ZW_CHARS: frozenset[str] = frozenset("\u200b\u200c\u200d")
#: 证据片段中零宽字符的可见替换（面板/日志不携带不可见字符）
ZW_VISIBLE = "⟨zw⟩"
#: 全文可疑零宽字符达到该数量才报（1 个可能是复制残留；合法 emoji ZWJ 序列已排除）
ZW_MIN_SUSPICIOUS = 2
#: 可疑零宽字符总数 → 严重度分档（升序，取最后一个满足档）
ZW_SEVERITY_BREAKS: tuple[tuple[int, Severity], ...] = (
    (2, "low"),
    (6, "medium"),
    (20, "high"),
)


def _is_emoji_ish(cp: int) -> bool:
    """宽判 emoji/符号码位（用于判定 ZWJ 是否为合法 emoji 序列连接符）。"""
    return (
        0x1F000 <= cp <= 0x1FAFF
        or 0x2190 <= cp <= 0x21FF
        or 0x2600 <= cp <= 0x27BF
        or 0x2B00 <= cp <= 0x2BFF
        or 0x2900 <= cp <= 0x297F
        or cp
        in (0x203C, 0x2049, 0x2122, 0x2139, 0x3030, 0x303D, 0x3297, 0x3299, 0xFE0F, 0x20E3)
    )


# ---------------------------------------------------------------------- 规则清单

_R = re.compile

INJECTION_RULES: tuple[InjectionRule, ...] = (
    # --- 指令覆盖（override，高危） ---
    InjectionRule(
        "override-en-ignore-previous",
        "override",
        "英文指令覆盖（ignore/disregard/forget/override + previous/above + instructions）",
        _R(
            r"(?i)\b(?:ignore|disregard|forget|override)\b[^.\n]{0,30}?"
            r"\b(?:previous|prior|above|earlier|preceding|initial|original)\b"
            r"[^.\n]{0,15}?\b(?:instructions?|prompts?|directions?|messages?|rules?"
            r"|guidance|constraints?)\b"
        ),
        "high",
    ),
    InjectionRule(
        "override-en-ignore-above",
        "override",
        "英文“忽略以上内容”（ignore the above + instructions/text/content 等名词）",
        _R(
            r"(?i)\b(?:ignore|disregard)\s+(?:all\s+|any\s+)?(?:of\s+)?(?:the\s+)?"
            r"(?:above|preceding|foregoing)\s+"
            r"(?:instructions?|prompts?|messages?|text|content|request|directives?)\b"
        ),
        "high",
    ),
    InjectionRule(
        "override-en-do-not-follow",
        "override",
        "英文否定式指令覆盖（do not follow the previous instructions）",
        _R(
            r"(?i)\b(?:do\s*not|don'?t|never)\s+follow\b[^.\n]{0,25}?"
            r"\b(?:the\s+|your\s+|any\s+)?(?:previous|prior|above|earlier|initial|original"
            r"|system)\b[^.\n]{0,15}?\b(?:instructions?|prompts?|rules?|directives?"
            r"|commands?)\b"
        ),
        "high",
    ),
    InjectionRule(
        "override-en-new-instructions",
        "override",
        "英文“新指令”替换式（your new instructions are …）",
        _R(
            r"(?i)\b(?:your\s+new\s+instructions?"
            r"|the\s+following\s+are\s+your\s+(?:new\s+)?instructions?)\b"
        ),
        "high",
    ),
    InjectionRule(
        "override-cn-ignore",
        "override",
        "中文指令覆盖（无视/忽略/忘记 + 之前/以上/上述 + 指令/提示词/规则）",
        _R(
            r"(?i)(?:无视|忽视|忽略|不理会|忘记|忘掉|不再遵守|不要遵守|无需遵守)"
            r"(?:之前的?|先前的?|以上|上述|上面的?|前面的?|此前|刚刚|以前|所有|全部)*的?\s*"
            r"(?:指令|提示词|系统提示词|system\s*prompt|规则|约束|设定)"
        ),
        "high",
    ),
    InjectionRule(
        "override-cn-invalidate",
        "override",
        "中文指令作废式（以上指令全部作废/失效）",
        _R(
            r"(?:以上|上述|之前|先前|前面)(?:的)?(?:所有|全部)?(?:指令|提示词|规则|约束)"
            r"(?:全部|都)?(?:作废|失效|不再有效|不再适用|不生效|统统取消|一律无效)"
        ),
        "high",
    ),
    # --- 套取系统提示词（extraction，中危） ---
    InjectionRule(
        "extract-en-system-prompt",
        "extraction",
        "英文套取系统提示词（reveal the system prompt / repeat your initial instructions）",
        _R(
            r"(?i)\b(?:reveal|leak|expose)\s+(?:the\s+|your\s+|its\s+|their\s+)?"
            r"(?:initial\s+|original\s+|full\s+|secret\s+|hidden\s+)?"
            r"(?:system\s+prompt|instructions?)\b"
            r"|\b(?:repeat|print|output|display|show|recite|spell\s+out)\s+(?:me\s+)?your\s+"
            r"(?:initial\s+|original\s+|full\s+|secret\s+|hidden\s+)?"
            r"(?:system\s+prompt|initial\s+instructions?|original\s+instructions?"
            r"|instructions?)\b"
        ),
        "medium",
    ),
    InjectionRule(
        "extract-cn-system-prompt",
        "extraction",
        "中文套取系统提示词（输出/泄露你的系统提示词）",
        _R(
            r"(?i)(?:输出|透露|泄露|打印|复述|原样输出)\s*(?:一下)?\s*(?:你的)?"
            r"(?:系统提示词|system\s*prompt|初始指令|原始指令|初始提示词)"
            r"|(?:系统提示词|system\s*prompt|初始指令|原始指令|初始提示词)[^。\n]{0,8}"
            r"(?:原样输出|输出|透露|泄露|打印|复述)"
        ),
        "medium",
    ),
    # --- 角色伪造（role） ---
    InjectionRule(
        "role-tag-angle",
        "role",
        "裸角色标签（<system>/<assistant>/<developer>，高危）",
        _R(r"(?i)<\s*/?\s*(?:system|assistant|developer)\s*>"),
        "high",
    ),
    InjectionRule(
        "role-tag-template",
        "role",
        "聊天模板角色标记（<|im_start|>system / <|system|> / <<SYS>>）",
        _R(
            r"(?i)<\|im_start\|>\s*(?:system|developer)"
            r"|<\|(?:system|assistant)\|>"
            r"|<<\s*SYS\s*>>"
        ),
        "medium",
    ),
    InjectionRule(
        "role-heading-md",
        "role",
        "Markdown 整行角色标题（## system / # SYSTEM:，“## System Requirements”不命中）",
        _R(r"^ {0,3}#{1,6}\s*(?:system|assistant|developer)\s*[:：]?\s*$", re.IGNORECASE),
        "medium",
    ),
    InjectionRule(
        "persona-dan-en",
        "role",
        "英文 DAN 角色注入（you are DAN / act as DAN）",
        _R(
            r"(?i)\b(?:you\s+(?:are|'re|will\s+be|have\s+become|are\s+now|will\s+act\s+as"
            r"|must\s+act\s+as)|act\s+as|pretend\s+to\s+be)\s+(?:an?\s+|AI\s+|named\s+)*DAN\b"
        ),
        "medium",
    ),
    InjectionRule(
        "persona-dan-cn",
        "role",
        "中文 DAN 角色注入（你现在是DAN / 你将扮演 DAN）",
        _R(
            r"(?i)你现在是\s*DAN"
            r"|从现在开始(?:你是|你将扮演)\s*DAN"
            r"|你(?:现在)?(?:要|将)?扮演\s*DAN"
        ),
        "medium",
    ),
    InjectionRule(
        "persona-unrestricted-en",
        "role",
        "英文“解除限制”人设（freed from the typical confines of AI）",
        _R(
            r"(?i)\b(?:freed|free|released|liberated)\s+from\s+(?:the\s+|all\s+|any\s+)?"
            r"(?:typical|usual|normal|standard)\s+(?:confines|limitations|restrictions"
            r"|constraints)\b"
            r"|\b(?:as\s+an?\s+AI|as\s+a\s+language\s+model)[^.\n]{0,40}?"
            r"\bwith\s+no\s+restrictions\b"
        ),
        "medium",
    ),
    InjectionRule(
        "persona-unrestricted-cn",
        "role",
        "中文“无限制”人设（你现在是没有任何限制的AI）",
        _R(
            r"(?:你现在是|你现在扮演|从现在开始(?:你是|你将扮演)|你将扮演)[^\n。；，]{0,30}?"
            r"(?:不受(?:任何)?(?:限制|约束|规则|道德|伦理|法律)"
            r"|没有(?:任何)?(?:限制|约束|规则)"
            r"|解除(?:了)?(?:所有)?(?:限制|约束|封印)"
            r"|无视(?:所有)?(?:道德|法律|规则))"
        ),
        "medium",
    ),
    # --- 越狱模板标记（jailbreak） ---
    InjectionRule(
        "jailbreak-developer-mode",
        "jailbreak",
        "Developer Mode 越狱（需 you are/I am in/reactivate 上下文，“启用开发者模式”不命中）",
        _R(
            r"(?i)\b(?:you\s+(?:are|'re|will\s+be|have\s+been|must\s+stay|must\s+remain"
            r"|are\s+now|'ll\s+be)\s+(?:now\s+)?(?:in|inside|entering)\s+(?:the\s+)?"
            r"developer\s+mode"
            r"|i\s+(?:'m|am)\s+(?:now\s+)?in\s+(?:the\s+)?developer\s+mode"
            r"|reactivat\w+\s+(?:the\s+)?developer\s+mode)\b"
        ),
        "medium",
    ),
    InjectionRule(
        "jailbreak-dan-mode",
        "jailbreak",
        "越狱模板标记：DAN Mode",
        _R(r"(?i)\bdan\s+mode\b"),
        "medium",
    ),
    InjectionRule(
        "jailbreak-do-anything-now",
        "jailbreak",
        "越狱模板标记：DAN 与 Do Anything Now 同现",
        _R(
            r"(?i)\bDAN\b[^.\n]{0,60}?\bdo(?:ing)?\s+anything\s+now\b"
            r"|\bdo(?:ing)?\s+anything\s+now\b[^.\n]{0,60}?\bDAN\b"
        ),
        "medium",
    ),
    InjectionRule(
        "jailbreak-cn-yueyu",
        "jailbreak",
        "中文越狱标记（AI 词 + 越狱 / 越狱 + 提示词/模板；iOS 越狱文章不命中）",
        _R(
            r"(?<![A-Za-z])(?:chatgpt|gpt\s*-?\s*\d(?:\.\d)?|gpt|claude|gemini|deepseek"
            r"|kimi|llm|AI)(?![A-Za-z])[^\n。]{0,20}越狱"
            r"|(?:大模型|大语言模型|人工智能|聊天机器人|AI\s*(?:助手|助理|模型))[^\n。]{0,20}越狱"
            r"|越狱[^\n。]{0,20}(?:提示词|prompt|模板|指令|咒语|话术|GPT|ChatGPT|大模型"
            r"|人工智能)",
            re.IGNORECASE,
        ),
        "medium",
    ),
    InjectionRule(
        "jailbreak-en",
        "jailbreak",
        "英文越狱标记（jailbreak 与 ChatGPT/GPT/Claude 等同现）",
        _R(
            r"(?i)(?<![A-Za-z])(?:chatgpt|gpt-?\d?|claude|gemini|llm|bard)(?![A-Za-z])"
            r"[^.\n]{0,30}?\bjail\s?-?break\w*"
            r"|\bjail\s?-?break\w*[^.\n]{0,30}?"
            r"(?<![A-Za-z])(?:chatgpt|gpt-?\d?|claude|gemini|llm|bard)(?![A-Za-z])"
        ),
        "medium",
    ),
)

assert len({rule.rule_id for rule in INJECTION_RULES}) == len(INJECTION_RULES), (
    "注入规则 id 不得重复"
)

# ------------------------------------------------------- base64+解码指示（启发式）

#: base64 运行块（≥32 连续字符，标准或 urlsafe 字母表）
_B64_RUN_RE = _R(r"[A-Za-z0-9+/]{32,}={0,2}|[A-Za-z0-9_-]{32,}")

#: “解码并执行”指示语（EN/CN）。与 blob 同现才报——"decode the following JSON"等
#: 无执行对象的正常文档不命中（正常技术文本零误报的验收线）。
_DECODE_EXECUTE_RE = _R(
    r"(?i)\bdecod(?:e|es|ed|ing)\s+(?:this|that|it|them|what\s+follows"
    r"|the\s+(?:following|above|next|attached|base\s?64))\b[^.\n]{0,80}?"
    r"\b(?:follow|execute|run|obey|perform|carry\s+out)\b[^.\n]{0,50}?"
    r"\b(?:the\s+|these\s+|those\s+|its\s+|their\s+|your\s+)?"
    r"(?:instructions?|commands?|orders?|directives?|steps?|tasks?|payload|it|them)\b"
    r"|(?:follow|execute|run|obey)\s+(?:the\s+|these\s+)?"
    r"(?:hidden\s+|secret\s+|embedded\s+)?(?:instructions?|commands?|directives?|steps?)"
    r"\s+(?:in|inside|within|encoded\s+in)\s+(?:the\s+|this\s+|that\s+)?base\s?64\b"
    r"|(?:解码|解密|解开)\s*(?:以下|下面的?|这段|此)[^。\n]{0,30}?"
    r"(?:并|然后|再|接着|，|,)\s*(?:执行|遵守|遵循|照做|运行|完成)"
    r"|(?:执行|遵守|遵循|照做)[^。\n]{0,15}(?:base\s?64|Base64|BASE64)[^。\n]{0,20}"
    r"(?:中的?|内的?|里的?|的)?(?:指令|命令|要求)"
)


# ---------------------------------------------------------------------- 工具函数

_INVISIBLE_RE = _R(r"[\u200b-\u200d\u2060\ufeff\u00ad]")


def _visible(text: str) -> str:
    """把零宽/软连字符替换为可见标记（evidence 不携带不可见字符）。"""
    return _INVISIBLE_RE.sub(ZW_VISIBLE, text)


def _snippet(line: str, start: int, end: int, *, context: int = 24, max_len: int = 80) -> str:
    """命中片段：±context 字符上下文、去首尾空白、不可见字符显性化、超长中段省略。"""
    lo = max(0, start - context)
    hi = min(len(line), end + context)
    seg = _visible(line[lo:hi].strip())
    if len(seg) > max_len:
        seg = seg[:50] + "…" + seg[-29:]
    return seg


def _zw_severity(total: int) -> Severity:
    """按全文可疑零宽字符总数取分档（ZW_SEVERITY_BREAKS 升序，取最后满足档）。"""
    severity: Severity = "low"
    for threshold, sev in ZW_SEVERITY_BREAKS:
        if total >= threshold:
            severity = sev
    return severity


# ------------------------------------------------------------------ 启发式检测器


def _zero_width_hits(text: str) -> list[InjectionHit]:
    """零宽字符载体检测：全文可疑数 ≥ ``ZW_MIN_SUSPICIOUS`` 才报（emoji ZWJ 白名单）。"""
    rows: list[tuple[int, int, str]] = []
    total = 0
    for lineno, line in enumerate(text.splitlines(), start=1):
        count = 0
        chars = list(line)
        for i, ch in enumerate(chars):
            if ch not in ZW_CHARS:
                continue
            if (
                ch == "\u200d"
                and 0 < i < len(chars) - 1
                and _is_emoji_ish(ord(chars[i - 1]))
                and _is_emoji_ish(ord(chars[i + 1]))
            ):
                continue  # 合法 emoji ZWJ 连接（家庭/职业/符号类 emoji 序列）
            count += 1
        if count:
            total += count
            rows.append((lineno, count, line))
    if total < ZW_MIN_SUSPICIOUS:
        return []
    severity = _zw_severity(total)
    return [
        InjectionHit(
            pattern="hidden-zero-width",
            evidence=_snippet(line, 0, len(line), context=0),
            severity=severity,
            category="hidden",
            line=lineno,
            detail=(
                f"零宽字符 U+200B-U+200D 共 {count} 个"
                f"（全文可疑 {total} 个，阈值 {ZW_MIN_SUSPICIOUS}）"
            ),
        )
        for lineno, count, line in rows
    ]


def _base64_decode_hits(text: str) -> list[InjectionHit]:
    """base64 大块 + “解码并执行”指示语同现检测（指示语或 blob 单独出现均不报）。"""
    hits: list[InjectionHit] = []
    seen: set[int] = set()
    for m in _DECODE_EXECUTE_RE.finditer(text):
        window = text[max(0, m.start() - 200) : m.end() + 400]
        if not _B64_RUN_RE.search(window):
            continue
        line_no = text.count("\n", 0, m.start()) + 1
        if line_no in seen:
            continue
        seen.add(line_no)
        line_start = text.rfind("\n", 0, m.start()) + 1
        line_end = text.find("\n", m.start())
        if line_end < 0:
            line_end = len(text)
        line_text = text[line_start:line_end]
        hits.append(
            InjectionHit(
                pattern="hidden-base64-decode",
                evidence=_snippet(line_text, m.start() - line_start, m.end() - line_start),
                severity="high",
                category="hidden",
                line=line_no,
                detail="base64 大块 + 解码并执行指示语同现（隐藏指令载体）",
            )
        )
    return hits


# ------------------------------------------------------------------------ 主入口


def scan_injection(
    text: str | bytes | None,
    *,
    max_bytes: int | None = None,
    rules: tuple[InjectionRule, ...] = INJECTION_RULES,
) -> list[InjectionHit]:
    """扫描注入特征，返回命中列表（05 文档 W4 签名：pattern / 命中片段 / 严重度）。

    - ``text`` 为 None/空 → 空列表；bytes 按 UTF-8 解码（errors=replace）；
    - regex 规则逐行匹配，同一规则同一行只记首条命中（与 secrets 扫描器口径一致）；
    - 纯 regex / 启发式、无网络调用、无 IO。
    """
    if not text:
        return []
    body = text.decode("utf-8", errors="replace") if isinstance(text, bytes) else text
    if max_bytes is not None and len(body) > max_bytes:
        body = body[:max_bytes]

    hits: list[InjectionHit] = []
    seen: set[tuple[str, int]] = set()
    for lineno, line in enumerate(body.splitlines(), start=1):
        for rule in rules:
            m = rule.pattern.search(line)
            if m is None:
                continue
            key = (rule.rule_id, lineno)
            if key in seen:
                continue
            seen.add(key)
            hits.append(
                InjectionHit(
                    pattern=rule.rule_id,
                    evidence=_snippet(line, m.start(), m.end()),
                    severity=rule.severity,
                    category=rule.category,
                    line=lineno,
                    detail=rule.description,
                )
            )
    hits.extend(_zero_width_hits(body))
    hits.extend(_base64_decode_hits(body))
    return hits


def rule_ids() -> tuple[str, ...]:
    """内置 regex 规则 id（逐条测试/自检用；两条隐藏载体启发式不含在内）。"""
    return tuple(rule.rule_id for rule in INJECTION_RULES)


def worst_severity(hits: Iterable[InjectionHit]) -> Severity | None:
    """命中的最高严重度（无命中 → None；集成层据此定 alert 级别）。"""
    worst: Severity | None = None
    for hit in hits:
        if worst is None or SEVERITY_ORDER[hit.severity] > SEVERITY_ORDER[worst]:
            worst = hit.severity
    return worst


def scan_injection_result(
    body: bytes | str | None,
    *,
    max_bytes: int | None = None,
) -> ScanResult:
    """``scan_injection`` 的 ScanResult 包装（engine/pipeline 的 ScannerFn 签名兼容）。"""
    hits = scan_injection(body, max_bytes=max_bytes)
    scan_hits = tuple(
        ScanHit(
            SCANNER_NAME,
            hit.pattern,
            hit.evidence,
            hit.line,
            f"[{hit.severity}] {hit.detail}",
            {"severity": hit.severity, "category": hit.category},
        )
        for hit in hits
    )
    metrics: dict[str, float] = {"hits": float(len(hits))}
    for hit in hits:
        metrics[f"sev_{hit.severity}"] = metrics.get(f"sev_{hit.severity}", 0.0) + 1.0
        metrics[f"cat_{hit.category}"] = metrics.get(f"cat_{hit.category}", 0.0) + 1.0
    return ScanResult(scanner=SCANNER_NAME, hits=scan_hits, metrics=metrics)


__all__ = [
    "Category",
    "INJECTION_RULES",
    "InjectionHit",
    "InjectionRule",
    "SCANNER_NAME",
    "SEVERITY_ORDER",
    "Severity",
    "ZW_CHARS",
    "ZW_MIN_SUSPICIOUS",
    "ZW_SEVERITY_BREAKS",
    "ZW_VISIBLE",
    "rule_ids",
    "scan_injection",
    "scan_injection_result",
    "worst_severity",
]
