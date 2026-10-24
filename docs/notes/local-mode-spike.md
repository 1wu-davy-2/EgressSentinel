# T0.3 · local 模式 spike 报告

- 日期：2026-10-24
- 执行者：glm5.3-flash（实现子代理）
- 环境：Windows 10.0.19045 x64（win32），Python 3.12.0（项目 .venv），mitmproxy 12.3.0，
  mitmproxy-windows 0.12.15 / mitmproxy_rs 0.12.15

## 结论（一句话）

**代码路径已实现、静态依赖齐备；本环境为非管理员会话，按安全红线未实际运行
`--mode local`，需管理员环境人工验证**（见下方 needs-manual 清单）。

## 已在本环境完成的验证

| 检查 | 命令/方式 | 结果 |
|---|---|---|
| 管理员检测 | `.venv/Scripts/python.exe -c "import ctypes; print(bool(ctypes.windll.shell32.IsUserAnAdmin()))"` | `False`（非管理员会话） |
| local 模式依赖存在 | `python -c "from mitmproxy_rs import local; print(local.LocalRedirector)"` | `mitmproxy_rs.local.LocalRedirector` 可导入（WinDivert 封装随包分发，`mitmproxy-windows` 0.12.15 已安装） |
| 模式规格可解析 | `mitmproxy/proxy/mode_specs.py:297` `LocalMode`（`--mode local[:spec]`，`describe_spec` 校验） | 存在，与 mitmproxy ≥10.2 行为一致 |
| 未实际运行 local 模式 | —（红线：非管理员必失败；且 T0.3 要求"非管理员则不实际运行"） | 跳过，列入 needs-manual |

## 代码路径（已实现，待管理员环境验证）

- `src/aaa/setup/admin.py`：`is_current_process_elevated()`——ctypes
  `IsUserAnAdmin`，失败回退 `GetTokenInformation(TokenElevation)`；
- `src/aaa/capture/engine.py:79`：`_validate_mode` 透传 `local[:spec]` 给
  mitmproxy `Options(mode=[...])`；
- `src/aaa/cli.py`：`aaa run --mode local` 在非管理员下直接拒绝（exit code 2）并
  给出 UAC 提升指引（管理员下正常运行）；
- spike 脚本：`scripts/local_mode_spike.py`（打印环境、管理员状态、依赖检查；
  非管理员绝不自动运行 `--mode local`）。

## needs-manual（管理员环境人工验证清单）

1. 以**管理员** PowerShell 进入项目目录，运行
   `.venv\Scripts\python.exe scripts\local_mode_spike.py --run`（脚本在检测到管理员后才会
   真正启动 `--mode local`），确认能否抓取本机进程流量；
2. 对照 mitmproxy 版本 ≥10.2 的行为（本机为 12.3.0）；
3. 观察杀软/EDR 对 WinDivert 驱动加载的告警（02 文档 R2）；
4. 验证 `aaa run --mode local` 管理员下可启动、事件带原生 PID（P2/T2.2 接入点）。

若验证失败 → 触发 03 文档 R1 回退：v1 仅 regular 模式，T2.2 改为降级说明 + 引导文档。
