# 04 · 告警通知渠道实施计划（v0.1.3，洞察清单 ①-1）

> 实施者：GLM-5.3-Flash。规划：GLM-5.3（2026-10-24）。
> 目标：block / alert / confirm 事件发生时**即时通知用户**，无需打开面板——审计工具的「最后一公里」。
> 设计权威：本文档；冲突时记 `docs/notes/decisions.md` 并在返回中说明。开发规范沿用 `03-execution-plan.md` §0（类型注解、ruff、pytest、安全红线）。

## 1. 范围与不做

做：① Windows 系统 toast 通知（默认通道，零第三方依赖）② Webhook 通知（generic / wecom / dingtalk / feishu / slack / discord 六种 payload 形态）③ SMTP 邮件 ④ 通知限流与聚合（防轰炸）⑤ 配置随策略热更新 ⑥ `aaa notify test` 测试命令。

不做（v1）：通知历史入库、桌面交互按钮、多收件人组、富媒体附件。

## 2. 配置（策略 YAML 新段 + 环境变量覆盖）

`policies/default.yaml` 新增（默认全关，`toast.enabled: true` 为出厂默认——本机、无外发）：

```yaml
notifications:
  min_action: alert        # 通知门槛：alert | confirm | block（block 为最高）
  toast:
    enabled: true          # Windows 系统通知（PowerShell WinRT，零依赖）
  webhook:
    enabled: false
    provider: generic      # generic | wecom | dingtalk | feishu | slack | discord
    url: ""                # 环境变量 AAA_WEBHOOK_URL 优先
  email:
    enabled: false
    smtp_host: ""
    smtp_port: 465
    use_tls: true
    username: ""
    password: ""           # 仅存本机策略文件；环境变量 AAA_SMTP_PASSWORD 优先
    from_addr: ""
    to_addrs: []           # 列表
  rate_limit:
    max_per_minute: 10     # 每通道滑动窗口；超出部分合并为一条 digest
```

- `pydantic` 严格化（`extra=forbid`），随 PolicyLoader 热更新（已有机制，无需重启）。
- 门槛判定：action 级别 `allow < alert < confirm < block`，事件 action ≥ `min_action` 才入队。
- 环境变量覆盖：`AAA_WEBHOOK_URL`、`AAA_SMTP_PASSWORD`（便于快速试用与凭据分离）。

## 3. 模块结构（src/aaa/notify/）

| 文件 | 职责 | 关键约束 |
|---|---|---|
| `model.py` | `NotifyConfig`（pydantic）+ 解析默认值 | 缺省段落=全关（老策略文件兼容） |
| `summary.py` | 事件 → 通知摘要（**脱敏**） | 复用 web 侧同一脱敏核心（`iter_secret_spans` 同源逻辑）：命中的密钥打码；正文截断 200 字符；字段：时间/动作/风险分/进程/主机/命中规则 |
| `channels.py` | `Channel` 协议 `send(text: str, event) -> None`；`ToastChannel` / `WebhookChannel` / `EmailChannel` | 全部依赖注入：toast 注入 `_run_powershell`，webhook 注入 httpx 客户端工厂，email 注入 smtplib 发送函数——**单测零真实发送** |
| `dispatcher.py` | `Dispatcher`：`queue.Queue` + 单 worker 线程；`enqueue(event)` 永不阻塞（队列满直接丢弃计数）；滑动窗口限流（超限合并 digest：「另有 N 条事件被限流」）；`flush(timeout)` 退出排空 | 审计主路径只调用 enqueue；通道异常仅记日志**绝不影响代理** |

## 4. 通道实现要点

- **Toast**：PowerShell WinRT（无第三方包）。要点：AppId 用 PowerShell 的（`[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('...')`，模板 XML：标题=「EgressSentinel 审计告警」，正文=摘要前 3 行）；中文编码用 Base64 传参规避 cp1252（`-EncodedCommand`）；非 Windows 或调用失败→记 debug 日志静默。
- **Webhook**：httpx POST JSON，`timeout=3.0`，失败重试 1 次。payload 按 provider：generic=完整脱敏事件 JSON；wecom=`{"msgtype":"markdown","markdown":{"content":...}}`；dingtalk=`{"msgtype":"markdown","markdown":{"title":..,"text":..}}`；feishu=`{"msg_type":"text","content":{"text":...}}`；slack=`{"text":...}`；discord=`{"content":...}`。**必须 `trust_env=False` 直连**（避免被自身代理拦截形成回环）。
- **Email**：`smtplib.SMTP_SSL/SMTP+starttls`，纯文本摘要；失败记日志。

## 5. 集成点

1. `capture/addon.py`：事件构建落库处，若 `action ≥ min_action` → `dispatcher.enqueue(event)`（dispatcher 为可选注入，None 时跳过——保持既有测试零改动兼容）。
2. `cli.py run`：按策略构造 Dispatcher 挂给 addon；启动打印通知通道概要；Ctrl+C/关机优雅退出时 `dispatcher.flush(2.0)`（在 engine 停止后、store.close 前）。
3. `cli.py` 新命令 `aaa notify test [--channel toast|webhook|email]`：发一条测试通知（走真实通道，用户显式触发）；`aaa status` 增加一行通知配置概要。

## 6. 安全红线（必须遵守）

- 通知正文**必须脱敏**（密钥打码，与面板同源逻辑），绝不能把拦截到的明文密钥再发到 webhook/邮件。
- 单测严禁真实发送：powershell/httpx/smtp 全部注入假实现；E2E 用假通道。
- webhook 直连不经本机代理（trust_env=False + 显式不走代理环境变量）。

## 7. 任务卡与验收

- T1 `model.py` + loader 兼容（老策略无该段不报错）+ 环境变量覆盖 —— 单测：缺省/完整/非法配置。
- T2 `summary.py` 脱敏摘要 —— 单测：含 `AKIA…` 的事件摘要被打码；截断生效。
- T3 `channels.py` 三通道 —— 单测：六种 provider payload 形态、toast 的 EncodedCommand 参数、重试与失败日志、trust_env=False。
- T4 `dispatcher.py` —— 单测：enqueue 不阻塞、限流合并 digest、flush 排空、worker 异常隔离。
- T5 addon/run 集成 + 关机 flush —— E2E：enforce 下假 AWS key 请求被 block → 假 toast+webhook 各收到**一条脱敏**摘要；连发 20 条 alert → 假通道收到 ≤10 条 + 1 条 digest。
- T6 CLI：`aaa notify test`（真实通道需用户显式执行；测试里只测参数校验与装配）+ `status` 概要行。
- T7 文档：README「告警通知」小节 + FAQ（怎么配飞书/钉钉）+ `CHANGELOG.md` 增加 `[v0.1.3]` 段（沿用现有格式）。

总验收：`venv python -m pytest` 全绿；`ruff check src tests` 通过；E2E 场景（T5）通过。

## 8. 明确的完成定义（给实施者的返回格式）

按 PhaseResult 结构返回：summary / files / self_test / deviations / needs_manual_verification（真实 toast、真实 webhook/SMTP 的实际送达属于人工验证项）。
