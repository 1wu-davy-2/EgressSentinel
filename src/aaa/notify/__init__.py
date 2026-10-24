"""告警通知渠道（04 文档：block / alert / confirm 事件即时通知用户）。

模块结构：
- ``model``：``NotifyConfig``（策略 YAML ``notifications`` 段的 pydantic 严格化）
  + 环境变量覆盖（``AAA_WEBHOOK_URL`` / ``AAA_SMTP_PASSWORD``）；
- ``summary``：事件 → 脱敏摘要文本（与面板同一脱敏核心，正文截断 200 字符）；
- ``channels``：toast / webhook / email 三通道（全部依赖注入，单测零真实发送）；
- ``dispatcher``：队列 + 单 worker、永不阻塞 enqueue、滑动窗口限流 + digest 合并、flush。

安全红线（04 文档 §6）：通知正文必须脱敏（密钥打码，绝不能把拦截到的明文密钥再外发）；
webhook 直连不经本机代理（``trust_env=False``）；单测严禁真实发送。
"""
