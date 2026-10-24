# 更新日志 Changelog

## [v0.1.2] - 2026-10-24

### 新增

- **安装即守护**：`aaa setup` 完成后默认**立即后台启动审计代理**——五维规则与三大扫描器
  开箱全量监控，无需手动 `aaa run`，也无需等待重启触发自启。
- **策略热更新生效可见**：策略文件保存后约 2 秒自动生效（本就无需重启），现在版本变化
  会写入运行日志（控制台与 `data/autostart.log` 可见「策略已热更新：xxxx → yyyy」）。
- **Release 自动附更新说明**：打包 tag 的 GitHub Release 现在自动携带本文件对应版本段落
  （`scripts/release_notes.py` 提取）。

### 变更

- 官网补全 v0.1.1/v0.1.2 能力：常驻与自愈、开机即守护、策略热更新、断网自愈 FAQ（中英双语）。

## [v0.1.1] - 2026-10-24

### 新增

- **关机/注销优雅退出**：接管 Windows 关机、注销、控制台关闭事件，代理在 4 秒内限时收尾
  （低于系统 5 秒上限，绝不阻塞关机）；事件库每事件事务落盘，强退不丢已入库数据。
- **开机自启**：登录计划任务自动拉起 `aaa run`（`aaa setup` 末步默认询问安装；
  `aaa autostart on / off / status` 独立管理；日志 `data/autostart.log`）。
- **自检自愈 watchdog**：登录 30 秒后检测「系统代理已启用但代理端口不可达」的断网态，
  `--fix` 自动还原代理设置与代理环境变量（CA 保留），网络立刻恢复；`aaa status` 内置
  预警与自启状态；日志 `data/watchdog.log`。

### 变更

- `aaa teardown` 新增 `autostart` 目标（连计划任务一并还原）；`aaa run` 新增 `--log-file`。

## [v0.1.0] - 2026-10-24

首个版本。

- 双模式采集：regular（显式本地代理，无需管理员）/ local（WinDivert 透明抓取，需管理员）；
- HTTPS 明文级审计（mitmproxy，MIT 许可）+ 每请求归因到进程（PID/exe/命令行/签名者）；
- 五维规则引擎（域名/进程/内容/体量/时间窗）+ 43 条 gitleaks 移植密钥规则 + PII + 代码外泄检测；
- 四级动作 allow/alert/confirm/block，enforce 事中 403 阻断；出厂默认 dry-run 只告警；
- SQLite 事件库 + 截断证据文件（sha256）+ 面板脱敏展示（`?reveal=1` 显式解锁并记审计）；
- journal-first 全量系统改动记录与幂等 teardown（崩溃后仍完整还原）；
- 本地 Web 面板（FastAPI，仅 127.0.0.1）；CI 矩阵（Python 3.11-3.13 × amd64/arm64 ×
  Linux/Windows/macOS）；五平台单文件可执行；GitHub Pages 官网。
