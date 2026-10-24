# 06 · v0.3.0 体验与生态实施计划（洞察清单 ③+④）

> 实施者：GLM-5.3-Flash（波次一 8 个并行模块 + 波次二集成）。规划与把关：GLM-5.3。
> 规范沿用 docs/03 §0；红线：系统级操作全注入式测试，绝不真实施改。

## 并行文件所有权（关键约定）

**全局禁改**（集成阶段专属）：`cli.py`、`setup/wizard.py`、`policy/model.py`、`policy/loader.py`、`capture/*`、`web/app.py`、`policies/default.yaml`、`pyproject.toml`、`README.md`、`CHANGELOG.md`、`website/*`。

各模块额外**独占**的文件（只有该模块可改，其他并行模块同样不得碰）：

| 模块 | 独占文件 |
|---|---|
| W1 服务化 | `src/aaa/setup/service.py`（新）、`tests/unit/test_service.py`（新） |
| W2 托盘 | `src/aaa/tray.py`（新）、`tests/unit/test_tray.py`（新） |
| W3 安装器 | `installer/`（新目录）、`.github/workflows/build.yml`（唯一可改 workflow 的模块） |
| W4 性能 | `src/aaa/store/db.py`、`src/aaa/engine/pipeline.py`（改）、`tests/unit/test_perf*.py`（新） |
| W5 CLI i18n | `src/aaa/i18n.py`、`src/aaa/locales/__init__.py`、`locales/zh.py`、`locales/en.py`（新）+ `test_i18n.py` |
| W6 日报 | `src/aaa/reporting/daily.py`（新）、`tests/unit/test_daily_report.py`（新） |
| W7 规则市场 | `src/aaa/ruleshub/`（新）、`tests/unit/test_ruleshub.py`（新） |
| W8 多机聚合 | `src/aaa/hub/`（新）、`tests/unit/test_hub.py`（新） |

可读任意文件；冲突/规格空档记 `docs/notes/decisions.md`（先 grep 现有最大编号 D-xxx 再取号，避免并行撞号）。

## 波次一模块规格

### W1 服务化 `setup/service.py`
- `install_service(state, data_dir)`：schtasks 创建 `EgressSentinel-Service`——`ONSTART` 触发、`RL HIGHEST` 可选参数、隐藏运行 `aaa run --log-file data/service.log`（复用 autostart_command 的解释器策略）；与既有 AutoStart/Watchdog 任务**互斥提示**（装服务则建议关登录任务）；
- journal-first（kind=`service_task`）+ `restore_service`（幂等删任务）；`service_status()`；
- netsh/schtasks 全走可注入 `_run_schtasks`；测试全 mock：创建/互斥提示/journal/还原幂等/状态。

### W2 托盘 `tray.py`
- `run_tray(data_dir)`：**lazy import pystray/Pillow**（未装给出 pip 提示并退出码 2）；
- 菜单：状态（调 watchdog/自检结果只读展示）/ 打开面板（起 `aaa web` 子进程）/ 启动代理（spawn_run_now）/ 停止代理（按端口探测 pid？保守：提示用 `aaa teardown`/结束进程树——v1 菜单项「重启代理」=spawn + 提示）/ 退出；
- 图标：优先 `website/icon.svg`→Pillow 渲染，缺省纯色盾形绘制；
- pystray Icon 全部注入式（`_icon_factory`），单测验证菜单构建/回调装配/缺依赖退出码，不真起托盘。

### W3 安装器 `installer/` + CI
- `installer/egress-sentinel.iss`（Inno Setup）：装 `dist/ai-agent-audit.exe` + README + 开始菜单/桌面快捷方式；卸载时**先执行 `ai-agent-audit.exe teardown`**（幂等）再删文件；版本号从 `scripts/iss_version.py` 注入（读 pyproject）；
- `.github/workflows/build.yml` 新增 `installer` job（仅 windows-amd64，tag 触发）：choco install innosetup → iscc → artifact `egress-sentinel-setup-<tag>.exe` 挂 Release；
- `tests/unit/test_installer.py`：校验 .iss 关键段（teardown 调用/版本占位/文件名）存在且与 build 产物名一致。

### W4 性能（db.py + pipeline.py）
- db.py：`PRAGMA journal_mode=WAL` + `synchronous=NORMAL`；`insert_events(list)` 批量事务（addon 侧由集成接线）；stats/list 查询加 covering index 复核；
- pipeline.py：内容扫描采样——body > `defaults.max_body_scan` 时除 secrets 首段全扫外，其余扫描器仅扫描前 256KB（可配 `sampling: {head_bytes: 262144}`），保证大上传低延迟；
- 基准单测：1000 事件批量插入 vs 逐条（断言批量事务次数=1）；采样开关下大 body 扫描截断正确、secrets 行为不回退。

### W5 CLI i18n `i18n.py` + `locales/{zh,en}.py`
- `t(key, **fmt)` 取词；`AAA_LANG` env / 运行时 `--lang`（集成接线）；缺 key 回落 zh 并计数告警；
- **词条目录**：通读 `cli.py` 与 `setup/wizard.py` 的全部用户可见文案（console.print/err_console.print/BadParameter/help/docstring 首行），为每条建 key 并给出 en 译文（zh 目录直接取原文）；
- 输出 `catalogue_coverage()`：key 数与未翻译数；单测：回退/格式化/覆盖统计。**不改 cli.py**（集成阶段用目录做机械包裹）。

### W6 日报 `reporting/daily.py`
- `render_daily(store, day) -> str`（自包含 HTML：按判定/进程/主机/规则聚合 + top 事件表 + 趋势 sparkline（内联 SVG））；`render_weekly`；
- `email_daily(notify_email_config, html)` 复用 notify/channels 的注入式 SMTP；
- 计划任务辅助 `install_daily_task(state, hour=9)`（schtasks 每日触发 `aaa report --daily --email`，journal + restorer）；
- 测试：种子 db→渲染断言聚合数字/脱敏（复用 masking）/HTML 转义、任务安装 mock。

### W7 规则市场 `ruleshub/`
- 导出：`export_section(policy_doc, section) -> yaml str`；导入：`import_section(current_yaml, section, yaml_str, *, merge=replace|union)`（pydantic 校验后再落，**不合法绝不写**）；
- gitleaks 上游同步：`sync_gitleaks(source=url|path)` 下载/读 rules TOML→转换为内置 secrets 规则 YAML（正则+熵+allowlist 映射），附来源与 sha256 pin；网络全注入；
- 测试：导入校验拒绝/合并语义/转换样例（造 2 条 TOML 样本）/pin 记录。

### W8 多机聚合 `hub/`
- agent 端 `Forwarder`：脱敏事件摘要（复用 notify/summary）POST `{token, host, events:[...]}`，队列+重试+批量（≤50 条/次），`AAA_HUB_URL/TOKEN` env 或策略 `hub:` 段（集成接配置）；httpx trust_env=False；
- 中心端 `HubCollector`（独立 FastAPI app，`aaa hub serve` 由集成接 CLI）：`POST /ingest`（Bearer token 校验，内存缓冲→SQLite hub.db，机器名维度）、`GET /api/hub/events|stats`（跨机器聚合）；
- 全注入 httpx/TestClient 测试：往返/鉴权拒绝/批量/重试。

## 波次二（集成，单代理）

1. CLI 新命令：`aaa service install|uninstall|status`、`aaa tray`、`aaa report --daily|--weekly [--email]`、`aaa rules export|import <section>`（+`--merge`）、`aaa gitleaks sync`、`aaa hub serve|forward status`、`aaa policy use <name>`（多 profile：`policies/profiles/*.yaml` + current 软链/拷贝语义，`aaa policy list`）；
2. **i18n 包裹**：cli.py + wizard.py 全部用户可见文案改 `t("key")`，接 `--lang/AAA_LANG`（默认 zh，输出不变）；帮助文本双语；
3. addon 接批量落盘 + Forwarder（policy `hub:` 段，默认关）；pipeline 接采样配置；db.py WAL 生效迁移检查（旧库打开不炸）；
4. pyproject：version 0.3.0、extras `tray=[pystray,Pillow]`、`report`/`hub` 无新依赖（fastapi/httpx 已有）；
5. default.yaml：`sampling/hub/` 段（默认关）+ profiles/ 示例（work/dev/strict 三份）；
6. E2E：profile 切换→策略热更新生效；`--lang en` 冒烟（--help 全英文）；daily report 渲染；forwarder→collector 本机往返；
7. 文档：README（服务/托盘/安装器/日报/规则市场/多机/双语）+ CHANGELOG `[v0.3.0]` + decisions；
8. `aaa --version` 0.3.0（含 test_cli 断言）。**官网不归你改**（发布负责人维护）。

总验收：全量 pytest 绿 + ruff 通过 + 上述 E2E 通过。
