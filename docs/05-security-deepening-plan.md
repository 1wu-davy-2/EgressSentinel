# 05 · 安全能力深化实施计划（v0.2.0，洞察清单 ②）

> 实施者：GLM-5.3-Flash（波次一 5 个并行构建 + 波次二集成）。规划与集成把关：GLM-5.3。
> 开发规范沿用 docs/03 §0；安全红线：涉及系统的代码全注入式测试。

## 波次一：五个独立模块（并行，互不触碰共享文件）

**共同约束**：只新建 `src/aaa/<模块>/` 与 `tests/unit/test_<模块>*.py`；**禁止修改** cli.py / policy/model.py / capture/addon.py / engine/pipeline.py / policies/default.yaml（集成阶段统一做）；导出清晰 API 供集成；每个模块自测 `pytest tests/unit/test_<模块> -q` 全绿。

### W1 仓库指纹（fingerprint）

- `src/aaa/fingerprint/index.py`：`FingerprintIndex`——从本地 git 仓库工作区构建指纹索引：
  - 切片：按行滑窗 n-gram（默认 win=8 行、去空白/注释行），每片规范化后 SHA1 入库；
  - 索引：`{digest: [(repo, rel_path, line_no)]}`，多 repo 合并；持久化 `data/fingerprints.bin`（pickle 容忍损坏→重建）；
  - 大仓限流：文件上限（默认 5MB/文件）、总片上限（默认 200 万）防 OOM；
  - `scan_body(text) -> list[FingerprintHit]`（repo/file/line/snippet 前 80 字符脱空白）——请求体按同规则切片比对，命中 ≥1 片即返回全部命中（上限 20 条）；
  - 纯函数式可注入文件读取（测试用临时目录造 3 文件小仓验证命中与误报边界：随机文本 0 命中）。
- `src/aaa/fingerprint/__init__.py` 导出 API；测试 `test_fingerprint.py`（建索引/命中/持久化/上限/空仓）。

### W2 防火墙加固（harden）

- `src/aaa/setup/firewall.py`：
  - `plan_harden(proxy_exe)` → 列出将创建的规则清单（先 dry-run 概念）；规则集：
    ①允许出站 TCP 443：`%PROGRAMEXE%`；②阻止出站 TCP 443：任何程序（`any`）；③阻止出站 UDP 443（QUIC）；白名单 svchost/Windows Update；
  - `apply_harden(state, proxy_exe)`：netsh advfirewall 逐条创建（规则名前缀 `EgressSentinel-`），journal-first（kind=`firewall_rule`，每条规则一条记录）；
  - `restore_harden(state, entry)`：按规则名精确 `netsh advfirewall firewall delete rule name=...`（幂等容忍不存在）；
  - 管理员检测复用 `is_current_process_elevated`，非管理员直接拒绝；
  - 所有 netsh 调用走可注入 `_run_netsh(args)`；测试 `test_firewall.py` 全 mock：规则清单/创建调用序列/journal/还原幂等/非管理员拒绝。
- 导出 `plan_harden/apply_harden/restore_harden/KIND_FIREWALL_RULE`。

### W3 LLM 辅助判定（judge）

- `src/aaa/judge/llm.py`：
  - `JudgeConfig`（api_base/model/timeout=8s/max_events_per_day 预算/enable 开关）+ `JudgeVerdict`（is_violation/confidence 0-1/reason/category）；
  - `LLMJudge.judge(summary_text) -> JudgeVerdict`：OpenAI 兼容 `/chat/completions`，system 提示要求**只输出 JSON**，解析失败/超时→返回 `verdict(status="unavailable")`，绝不抛异常影响审计；
  - httpx 客户端工厂注入（测试假客户端）；预算计数器（按日，JSON 落 data/judge-usage.json，可注入时钟）；API key 只从环境变量 `AAA_JUDGE_API_KEY` 读，不落盘。
- 测试 `test_judge.py`：正常解析/非法 JSON 容错/超时容错/预算封顶后跳过/默认关闭。

### W4 响应侧注入检测（injection）

- `src/aaa/scanners/injection.py`：
  - `scan_injection(text) -> list[InjectionHit]`（pattern/命中片段/严重度 low|medium|high）：覆盖 promptfoo/garak 语料反推的高频特征——中英文指令覆盖（ignore previous/无视之前的指令/忽略以上）、角色伪造（<system>、## system、你现在是 DAN）、越狱模板标记（developer mode/越狱）、隐藏指令载体（zero-width 字符 U+200B-U+200D、base64 大块+“decode”指示）；
  - 纯 regex/启发式，无网络；规则以模块常量列表维护（可测试逐条）；
- 测试 `test_injection.py`：每类特征至少 2 例命中 + 正常技术文本 0 误报。

### W5 证据静态加密（encrypt）

- `src/aaa/store/crypto.py`：
  - `derive_key(password, salt)`：PBKDF2-HMAC-SHA256 200k 迭代（cryptography）；
  - `encrypt_bytes/decrypt_bytes(key, data)`：AES-256-GCM（nonce+ct+tag，前缀魔数 `ES01`）；
  - `CryptoEngine`：`keyfile data/.crypto-key`（32B 随机，权限尽力收紧）或 `AAA_MASTER_PASSWORD` 派生（二选一，keyfile 优先）；`enabled` 由配置控制，**默认关闭**（向后兼容旧明文证据：读取时无魔数则按明文返回，写入按当前配置）；
  - EvidenceStore 集成点以最小侵入提供 `EncryptedFileStore` 包装或 store/evidence.py 留好的注入位——本波次**不改 evidence.py**，导出 `decrypt_file(path, key)` 供集成用；
- 测试 `test_crypto.py`：往返加解密/错误密码失败/魔数识别明文兼容/keyfile 派生一致性。

## 波次二：集成（单代理串行）

1. `policy/model.py` 新段（全部默认关/空）：`fingerprint: {enabled, repos: [], min_hits: 1}`、`judge: {...W3 配置}`、`response: {rules: [{id, patterns: all|high, action: alert}]}`；`encrypt: {enabled: false}`；
2. `engine/pipeline.py`：注册 `repo_fingerprint` 内容扫描器（命中→事件 evidence 附 fingerprint 命中清单）+ `evaluate_response(text) -> ResponseFinding`；
3. `capture/addon.py`：response 钩子调 evaluate_response（action 仅 alert 级标注，不阻断响应）；verdict≥alert 且 judge.enabled 时调 LLMJudge（异常吞掉记 judge_note）；
4. `store/evidence.py`：接入 CryptoEngine（写入加密/读取透明兼容明文）；
5. `cli.py`：`aaa fingerprint build [--repo PATH]`、`aaa harden on|off`（替换占位，含管理员门禁与 dry-run 概念）、run 启动概要含 judge/fingerprint/加密状态；
6. `policies/default.yaml` 增对应段（默认关）；`teardown` 增 firewall 目标；
7. E2E 补三类：指纹命中（临时小仓+外发其片段→命中标注）、注入特征响应→标注、加密开启后证据文件魔数验证+旧明文可读；
8. 文档：README「安全深化」小节、CHANGELOG `[v0.2.0]` 段、decisions.md 记录取舍（含 audit.db 元数据暂不整库加密的边界）；
9. 版本 0.1.3→0.2.0（含 test_cli 版本断言）。

总验收：全量 pytest 绿 + ruff 通过；E2E 三场景通过。
