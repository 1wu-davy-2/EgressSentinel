; ============================================================================
; EgressSentinel（出口哨兵）Windows 安装器脚本（Inno Setup 6，仅 windows-amd64）
;
; 红线：卸载必须**先执行 teardown 再删文件**（06 文档 W3）。teardown 幂等还原
; 系统级改动（WinINET/WinHTTP 代理、AAA_* 环境变量、CA 证书、自启/看门狗计划
; 任务、防火墙规则）；若先删文件，残留的自启任务会指向不存在的 exe，系统代理
; 也可能仍指向已被删除的本地端口，用户直接断网。Inno Setup 保证 [UninstallRun]
; 各条目在删除已安装文件之前执行、且默认逐条等待退出（waituntilterminated 是
; 默认值，此处显式声明以自证），故本节写法即满足红线。
;
; 版本号注入（CI 唯一入口，.github/workflows/build.yml 的 installer job）：
;   python scripts/iss_version.py                     → 0.2.0
;   iscc /DMyAppVersion=0.2.0 installer/egress-sentinel.iss
; 未注入 /DMyAppVersion 直接编译会 #error，杜绝产出错误版本号的安装包。
;
; 产物：dist/egress-sentinel-setup-v<版本>.exe（与 build.yml installer job 的
; upload/release 模式 dist/egress-sentinel-setup-*.exe 一致，tests/unit/test_installer.py 校验）。
;
; 文件来源（Source 路径相对本 .iss 所在目录）：
;   ..\dist\ai-agent-audit.exe —— build_exe.py 的 onefile 产物（APP_NAME=ai-agent-audit），
;     CI 中由 build job 的 windows-amd64 artifact 还原到该位置；
;   ..\README.md —— 项目说明随包分发。
; 产物名与源名的一致性由 tests/unit/test_installer.py 与 build_exe.APP_NAME 对账。
; ============================================================================

#ifndef MyAppVersion
  #error 版本号未注入：请以 iscc /DMyAppVersion=<版本> 编译（python scripts/iss_version.py 输出该值）
#endif

#define MyAppName "EgressSentinel"
#define MyAppNameZh "EgressSentinel（出口哨兵）"
#define MyAppExe "ai-agent-audit.exe"

[Setup]
; AppId 固定 GUID：升级/卸载按此识别本程序，永不改变
AppId={{7E0848AB-7AD7-47EE-AE66-9130DF75B025}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher=EgressSentinel contributors
AppPublisherURL=https://github.com/1wu-davy-2/EgressSentinel
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
UninstallDisplayName={#MyAppNameZh}
UninstallDisplayIcon={app}\{#MyAppExe}
; 产物落 repo 根的 dist/（相对 .iss 所在目录），与 build.yml 的 upload 路径一致
OutputDir=..\dist
OutputBaseFilename=egress-sentinel-setup-v{#MyAppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
DisableProgramGroupPage=yes
; 仅 64 位 Windows（CI 只出 windows-amd64 安装包）
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; {autopf} 需要管理员权限；卸载 teardown 也需要（删计划任务/防火墙规则/证书）
PrivilegesRequired=admin
; 覆盖安装前若 exe 被占用（常驻代理），提示用户关闭；卸载侧由 [UninstallRun] taskkill 兜底
CloseApplications=yes
RestartApplications=no

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
; 主程序：PyInstaller onefile 产物（名字必须与 build_exe.APP_NAME 一致，测试对账）
Source: "..\dist\{#MyAppExe}"; DestDir: "{app}"; Flags: ignoreversion
; 项目说明
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
; 开始菜单快捷方式 + 卸载入口（06 文档 W3：开始菜单/桌面快捷方式）
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
; 桌面快捷方式（任务页可取消勾选）
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"; Tasks: desktopicon

[Run]
; 安装完成后可勾选查看 README（不自动启动代理/不做任何系统改动——setup 交由用户显式执行）
Filename: "{app}\README.md"; Description: "查看 README（项目说明）"; Flags: postinstall shellexec skipifsilent nowait

[UninstallRun]
; 红线条目（顺序即执行顺序，两条都先于文件删除）：
; 1) 先结束可能仍在运行的常驻代理/watchdog 进程树，避免 exe 被占用导致后续删除失败；
;    进程不存在时 taskkill 返回非零，Inno 不校验退出码，无副作用。
Filename: "{sys}\taskkill.exe"; Parameters: "/F /T /IM {#MyAppExe}"; Flags: runhidden waituntilterminated
; 2) teardown 幂等还原系统改动：状态文件为空时是 no-op（exit 0）；个别条目还原
;    失败时 exit 1，同样不阻塞卸载（记录保留在 data/setup-state.json 供重跑）。
;    数据目录 data/（事件库/证据）属用户数据，卸载刻意保留、不静默删除。
Filename: "{app}\{#MyAppExe}"; Parameters: "teardown"; Flags: runhidden waituntilterminated
