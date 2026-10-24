"""en 词条目录（06 文档波次一 W5）：``zh.py`` 原文目录的英文译文。

约束（tests/unit/test_i18n.py 校验）：
- key 集合与 zh 目录一致（``catalogue_coverage().untranslated == 0``）；
- 每条的 ``{placeholder}`` 占位符集合与 zh 同名条目一致；
- rich markup（``[red]`` 等）与命令名（``aaa teardown`` 等）原样保留。

红线：本文件只承载词条数据，不含任何逻辑、不做任何系统级操作。
"""

from __future__ import annotations

#: en 词条目录：key → 译文（占位符与 zh 目录同名条目一致）
CATALOGUE: dict[str, str] = {
    # ---- 共享 ----
    "common.dry_run_noop": "[yellow](dry-run)[/yellow] Not applied.",
    "common.cancelled": "Cancelled.",
    "common.task_created": "[green]Scheduled task created[/green] {item_key}",
    "common.err_plain": "[red]{exc}[/red]",
    "common.read_failed": "Failed to read: {exc}",
    "common.notify_none": "all disabled",
    "common.policy_load_failed": "[red]Failed to load policy: {exc}[/red]",
    "common.state_installed": "installed",
    "common.state_not_installed": "not installed",
    # ---- 表格列标题 ----
    "cli.col_id": "ID",
    "cli.col_time": "Time",
    "cli.col_verdict": "Verdict",
    "cli.col_risk": "Risk",
    "cli.col_method": "Method",
    "cli.col_path": "Path",
    "cli.col_host": "Host",
    "cli.col_process": "Process",
    "cli.col_item": "Item",
    "cli.col_value": "Value",
    # ---- 根命令与通用参数 ----
    "cli.app.help": "AI-AGENT-AUDIT: local audit of AI-agent outbound traffic (Windows)",
    "cli.setup.group_help": ("Apply system setup (every change is recorded to setup-state.json)"),
    "cli.policy.group_help": "Policy file management and validation",
    "cli.autostart.group_help": (
        "Boot-autostart scheduled tasks (aaa run + logon watchdog self-check)"
    ),
    "cli.notify.group_help": "Alert notifications (toast/webhook/email, doc 04)",
    "cli.fingerprint.group_help": (
        "Repository fingerprint index (doc 05 W1: local code-exfiltration matching)"
    ),
    "cli.root.doc": "AI-AGENT-AUDIT command-line entry point.",
    "opt.data_dir.help": "Data directory (default <project>/data; also settable via AAA_DATA_DIR)",
    "opt.dry_run.help": "Only show actions that would run; apply no system changes",
    "opt.version.help": "Show version",
    "opt.policy.help": "Policy YAML file (default policies/default.yaml)",
    "opt.yes.help": "Skip confirmation (for automation)",
    # ---- run ----
    "opt.run_mode.help": (
        "Capture mode: regular (default, system proxy) | "
        "local[:spec] (admin required, see docs/notes/local-mode-spike.md)"
    ),
    "opt.host.help": "Listen address",
    "opt.port.help": "Listen port",
    "opt.run_pid.help": "local mode only: restrict to target process PID (passes local:pid=…)",
    "opt.run_process.help": (
        "local mode only: restrict to target process name (passes local:process=…)"
    ),
    "opt.run_jsonl.help": (
        "Also mirror-write JSONL (data/raw/YYYYMMDD.jsonl; SQLite-only by default)"
    ),
    "opt.retention_days.help": (
        "Event retention days (auto-cleaned at startup; default 14 or AAA_RETENTION_DAYS)"
    ),
    "opt.run_log_file.help": (
        "Mirror startup/shutdown messages into this file (troubleshooting headless runs, "
        "e.g. boot autostart)"
    ),
    "cli.run.doc": (
        "Start the capture proxy (blocking; Ctrl+C exits gracefully; bounded finalization "
        "on shutdown/logoff)."
    ),
    "cli.run.err_pid_not_local": "--pid/--process require --mode local",
    "cli.run.err_pid_mutex": "--pid and --process are mutually exclusive; pick one",
    "cli.run.err_local_admin": (
        "[red]--mode local requires administrator privileges (WinDivert transparent "
        "redirect).[/red]\n"
        "Re-run from an elevated PowerShell / terminal:\n"
        "  Right-click Start → Terminal (Admin) or PowerShell (Admin)\n"
        "  Then run: aaa run --mode local"
    ),
    "cli.run.banner": "[green]aaa {version}[/green] mode={mode} listening on {host}:{port}",
    "cli.run.policy_line": (
        "Policy: {path} (mode={mode} version={version}, mtime hot-reload poll 2s)"
    ),
    "cli.run.pinned_line": "local target process: pid={pid} name={name}",
    "cli.run.store_line": "Event store: {db_file}",
    "cli.run.jsonl_mirror": "  +JSONL mirror data/raw/",
    "cli.run.evidence_dir": "  Evidence: {evidence_dir}",
    "cli.run.trim_line": (
        "Startup auto-clean: deleted {events} expired events "
        "(retention {days} days, {evidence} evidence files removed)"
    ),
    "cli.run.notify_line": (
        "Notifications: {enabled}{extra}; threshold min_action={min_action}; "
        "rate limit {max_per_minute}/min (excess merged into digests)"
    ),
    "cli.run.notify_provider": " (provider={provider})",
    "cli.run.fp_missing": (
        "[yellow]Fingerprint matching: enabled but the index is missing/corrupt — run "
        "aaa fingerprint build, then restart to take effect[/yellow]"
    ),
    "cli.run.fp_on": "Fingerprint matching: on ({repos} repos {slices} slices → data/{file_name})",
    "cli.run.fp_off": "Fingerprint matching: off (policy.fingerprint.enabled)",
    "cli.run.judge_on": (
        "LLM judging: on (model={model}, used today {used}/{max_per_day}; "
        "key read from env only, never persisted)"
    ),
    "cli.run.judge_off": "LLM judging: off (policy.judge.enabled)",
    "cli.run.crypto_on": (
        "Evidence encryption: on ({algorithm}, keyfile={keyfile}; key generated on first write)"
    ),
    "cli.run.crypto_off": (
        "Evidence encryption: off (policy.encrypt.enabled; historical ciphertext still readable)"
    ),
    "cli.run.hint_exit": (
        "Press Ctrl+C to exit gracefully; shutdown/logoff triggers a bounded finalization "
        "(never blocks system shutdown)."
    ),
    "cli.run.log_start": (
        "aaa {version} started mode={mode} listen={host}:{port} policy={path}({policy_mode})"
    ),
    "cli.run.log_stop": "aaa stopped (clean exit or shutdown signal)",
    # ---- setup（一键引导入口） ----
    "opt.setup_yes.help": "Skip step-by-step confirmation (for automation)",
    "opt.machine_ca.help": "Install the CA into LocalMachine (admin required; CurrentUser by defaul"
    "t)",
    "cli.setup.doc": (
        "Interactive one-shot guide: CA root certificate → system proxy → user environment "
        "variables (each step is shown before confirmation)."
    ),
    "cli.setup.ask_autostart": (
        "Install the boot-autostart and watchdog scheduled tasks ({task_name} et al., 2 items)?"
    ),
    "cli.setup.hint_autostart_retry": "You can retry later with aaa autostart on",
    "cli.setup.err_autostart": "[red]Failed to create autostart tasks: {exc}[/red] ({hint})",
    "cli.setup.ask_spawn": (
        "Start the audit proxy now (background; see aaa status / stop with aaa teardown)?"
    ),
    "cli.setup.err_spawn": (
        "[red]Failed to start in background: {exc}[/red] (run {hint} in the foreground manually)"
    ),
    "cli.setup.spawned": (
        "[green]Audit proxy started in background[/green] pid={pid} "
        "(all five rule dimensions monitored; log: data/autostart.log)"
    ),
    # ---- setup ca ----
    "opt.ca_store.help": (
        "Certificate store: user (CurrentUser, no admin) | machine (LocalMachine, admin required)"
    ),
    "cli.setup_ca.doc": "Generate (if missing) and install the mitmproxy CA into a certificate stor"
    "e.",
    "cli.setup_ca.err_store": "--store accepts only user|machine",
    "cli.setup_ca.ca_info": (
        "CA: {path}\nSerial: {serial}  Fingerprint (SHA1): {thumbprint}\nSubject: {subject_cn}"
    ),
    "cli.setup_ca.will_do": (
        "Will do: install this CA into the {store} certificate store and record it in "
        "setup-state.json."
    ),
    "cli.setup_ca.dry_run": (
        "[yellow](dry-run)[/yellow] Would install into the {store} certificate store; not applied."
    ),
    "cli.setup_ca.err_machine_admin": (
        "[red]--store machine requires administrator privileges.[/red] "
        "Run the terminal as administrator and retry, or use --store user "
        "(CurrentUser, no admin needed)."
    ),
    "cli.setup_ca.installed": (
        "[green]Installed into the {store} certificate store[/green] "
        "(teardown can remove it precisely by serial number)."
    ),
    # ---- setup proxy ----
    "opt.winhttp.help": "Also set the WinHTTP machine proxy (admin required)",
    "cli.setup_proxy.doc": "Set the WinINET user proxy (optionally WinHTTP).",
    "cli.setup_proxy.will_do": (
        "Will set the WinINET user proxy {host}:{port} (override=<local>;localhost;127.0.0.1)"
    ),
    "cli.setup_proxy.will_do_winhttp": (
        "Will set the WinHTTP machine proxy {host}:{port} (admin required)"
    ),
    "cli.setup_proxy.done": (
        "[green]Proxy setup complete[/green]; restart browsers for it to take effect."
    ),
    # ---- setup env ----
    "cli.setup_env.doc": (
        "Deploy user environment variables (HTTP_PROXY/NODE_*/REQUESTS_CA_BUNDLE etc., "
        "doc 02 D1 list)."
    ),
    "cli.setup_env.table_title": "User environment variables to deploy",
    "cli.setup_env.col_name": "Variable",
    "cli.setup_env.done": (
        "[green]Environment variables deployed[/green]; new terminals/apps will pick them up."
    ),
    # ---- teardown ----
    "opt.teardown_targets.help": (
        "Limit scope: ca | proxy | env | autostart | firewall | service | daily "
        "(repeatable); default = all"
    ),
    "cli.teardown.doc": (
        "Restore all (or selected kinds of) changes idempotently in reverse state-file order "
        "(complete restore even after a crash)."
    ),
    "cli.teardown.empty": "State file is empty: nothing to restore.",
    "cli.teardown.will_restore": "Will restore {count} changes in reverse state-file order:",
    "cli.teardown.entry_line": "  - {kind}:{item_key} ({ts})",
    "cli.teardown.restored": "[green]Restored[/green] {item}",
    "cli.teardown.done": "[green]teardown complete: all changes restored.[/green]",
    "cli.teardown.failed": (
        "[red]teardown had failures; records kept — rerun aaa teardown to retry.[/red]"
    ),
    # ---- autostart ----
    "cli.autostart_on.doc": (
        "Create two logon scheduled tasks: persistent aaa run + watchdog self-check "
        "(--fix restores networking when broken)."
    ),
    "cli.autostart_on.will_create": (
        "Will create 2 current-user scheduled tasks (logon trigger; recorded to setup-state.json):"
    ),
    "cli.autostart_on.task1": "  1) {name}: {cmd} {args}",
    "cli.autostart_on.task2": "  2) {name} (delayed {delay}s): {cmd} {args}",
    "cli.autostart_on.confirm": "Create them?",
    "cli.autostart_on.effect": (
        "Effect: the proxy starts at boot; if autostart fails or the process is killed, "
        'the watchdog restores proxy settings 30s after logon to avoid "offline at boot".'
    ),
    "cli.autostart_off.doc": (
        "Delete the autostart and watchdog scheduled tasks (idempotent; other setup changes "
        "untouched)."
    ),
    "cli.autostart_off.removed": "[green]Scheduled tasks deleted and records cleaned[/green]: {labe"
    "l}",
    "cli.autostart_off.label_none": "(did not exist)",
    "cli.autostart_status.doc": "Check whether the autostart/watchdog scheduled tasks are installed"
    ".",
    "cli.autostart_status.line": "{name}: {state}",
    # ---- watchdog ----
    "opt.watchdog_fix.help": (
        "Automatically restore proxy settings and proxy env vars when offline (CA kept, harmless)"
    ),
    "opt.watchdog_wait.help": "Bounded wait seconds for the port (logon race protection)",
    "opt.watchdog_log.help": "Self-check log file (default data/watchdog.log)",
    "cli.watchdog.doc": (
        'Boot self-check: detect "system proxy enabled but the local proxy port is '
        'unreachable" (--fix restores automatically).'
    ),
    "cli.watchdog.status_line": "[{style}]Self-check: {status}[/{style}]  {detail}",
    # ---- notify test ----
    "opt.notify_channel.help": "toast | webhook | email (default = all channels enabled in policy)",
    "cli.notify_test.doc": (
        "Send a test notification (real channels, explicitly user-triggered; doc 04 §5 T6)."
    ),
    "cli.notify_test.summary": (
        "This is a test notification (aaa notify test).\n"
        "Channel {channel} works; summaries of block/alert hits will be delivered through it.\n"
        "Sent at: {ts}"
    ),
    "cli.notify_test.err_channel": "--channel accepts only {names}, got {channel!r}",
    "cli.notify_test.err_no_channels": (
        "[yellow]No notification channel is enabled in the current policy.[/yellow]\n"
        "Enable one in the policy YAML notifications section (toast/webhook/email), "
        "or set AAA_WEBHOOK_URL to try webhook quickly."
    ),
    "cli.notify_test.err_channel_config": (
        "[red]Channel {name} is disabled or incompletely configured.[/red]webhook needs "
        "notifications.webhook.enabled: true and a non-empty url (or AAA_WEBHOOK_URL); "
        "email needs smtp_host and to_addrs."
    ),
    "cli.notify_test.err_send": "[red]{name} send failed: {exc}[/red]",
    "cli.notify_test.sent": "[green]{name} test notification sent[/green]",
    # ---- status ----
    "cli.status.doc": (
        "Current status: proxy / CA / firewall / policy version / 5 latest events / "
        "pending restores."
    ),
    "cli.status.table_title": "aaa {version} status (data dir {data_dir})",
    "cli.status.proxy_on": "enabled {server}",
    "cli.status.proxy_off": "disabled (server={server!r})",
    "cli.status.winhttp_direct": "direct",
    "cli.status.winhttp_server": "server={server}",
    "cli.status.row_proxy_wininet": "Proxy WinINET (user)",
    "cli.status.row_proxy_winhttp": "Proxy WinHTTP (machine)",
    "cli.status.ca_desc": "{subject_cn} serial={serial} ({pem})",
    "cli.status.ca_missing": "not generated yet (aaa setup ca)",
    "cli.status.row_ca": "CA (confdir)",
    "cli.status.harden_on": (
        "hardened, {count} rules on record (aaa harden off / teardown firewall to restore)"
    ),
    "cli.status.harden_off": "not enabled (aaa harden on, admin required)",
    "cli.status.row_harden": "Firewall hardening (harden)",
    "cli.status.policy_desc": "mode={mode} version={version}",
    "cli.status.notify_desc": (
        "{enabled}; threshold min_action={min_action}; rate limit {max_per_minute}/min"
    ),
    "cli.status.notify_webhook": "; webhook provider={provider}",
    "cli.status.fp_on": "fingerprint=on",
    "cli.status.fp_off": "fingerprint=off",
    "cli.status.judge_on": "judge=on",
    "cli.status.judge_off": "judge=off",
    "cli.status.response_on": "response tagging=on",
    "cli.status.response_off": "response tagging=off",
    "cli.status.crypto_on": "evidence encryption=on",
    "cli.status.crypto_off": "evidence encryption=off",
    "cli.status.row_policy": "Policy",
    "cli.status.row_notify": "Notifications",
    "cli.status.row_deepening": "Security deepening",
    "cli.status.row_events": "Event store",
    "cli.status.events_desc": (
        "{count} events ({pending_confirm} confirm awaiting decision; db {db_file})"
    ),
    "cli.status.open_failed": "failed to open: {exc}",
    "cli.status.recent_title": "5 latest events",
    "cli.status.no_events": "(no events yet)",
    "cli.status.pending_restore": (
        "[yellow]Note: the state file has {count} unrestored changes (crash leftovers or "
        "teardown not yet run) — run aaa teardown to restore.[/yellow]"
    ),
    "cli.status.degraded": (
        "[bold red]Self-check problem: the system proxy is still enabled but the proxy port "
        'is unreachable (apps will "lose network").\n'
        "Recover: aaa watchdog --fix / aaa teardown proxy / restart aaa run[/bold red]"
    ),
    "cli.status.selfcheck_skip": "(self-check skipped: {exc})",
    "cli.status.hint_autostart_off": "aaa autostart off to disable",
    "cli.status.hint_autostart_on": "aaa autostart on to enable",
    "cli.status.autostart_line": "Boot autostart: {state} ({hint})",
    "cli.status.autostart_read_failed": "(failed to read autostart status: {exc})",
    # ---- tail ----
    "opt.tail_verdict.help": "Only show the given verdict",
    "opt.tail_interval.help": "Polling interval in seconds",
    "opt.tail_from_start.help": "Start from the earliest events (by default only new events)",
    "opt.tail_once.help": "Poll once and exit (for tests/scripts)",
    "cli.tail.doc": "Live-scroll new events (rich Live; Ctrl+C to exit).",
    "cli.tail.listen_line": (
        "tail: watching for new events (verdict={verdict} pid={pid} host={host}); Ctrl+C to exit."
    ),
    "cli.tail.filter_all": "all",
    "cli.tail.table_title": "Event stream (new → old)",
    "cli.tail.new_event": "[green]+[/green] {id} {ts} {verdict} {method} {host}{path}",
    "cli.tail.exited": "tail exited.",
    # ---- report ----
    "opt.report_since.help": "Start: 24h/30m/7d or ISO time",
    "opt.report_until.help": "End: ISO time",
    "opt.report_json.help": "Output as JSON",
    "opt.report_csv.help": "Output as CSV",
    "opt.report_verify.help": "Verify sha256 of all evidence files (slow on large stores)",
    "cli.report.doc": "Aggregate report: statistics by verdict/process/host/rule (doc 03 T4.2).",
    "cli.report.err_json_csv": "--json and --csv are mutually exclusive",
    "cli.report.table_title": "Report ({since} ~ {until}, {total} events total)",
    "cli.report.window_all": "all",
    "cli.report.window_now": "now",
    "cli.report.col_dim": "Dimension",
    "cli.report.col_count": "Count",
    "cli.report.row_verdict": "Verdict",
    "cli.report.row_process": "Process",
    "cli.report.row_host": "Host",
    "cli.report.row_rule": "Rule",
    "cli.report.integrity": (
        "Evidence check: {checked} inspected, {missing} missing, {corrupted} corrupted"
    ),
    # ---- trim ----
    "opt.trim_days.help": "Keep the latest N days; delete older events and evidence",
    "cli.trim.doc": (
        "Clean up expired events and evidence files (doc 02 D6 retention; ``run`` also "
        "auto-cleans at startup)."
    ),
    "cli.trim.done": (
        "[green]trim complete[/green]: deleted {events} events and {evidence} evidence files "
        "(retention {days} days)."
    ),
    # ---- harden ----
    "opt.harden_action.help": "on | off",
    "opt.harden_proxy_exe.help": (
        "for `on`: the proxy executable to allow (default = current interpreter/executable)"
    ),
    "cli.harden.doc": (
        "Firewall hardening switch (doc 05 wave-1 W2 / wave-2 §5): funnel outbound 443 "
        "through this proxy."
    ),
    "cli.harden.err_action": "harden accepts only on | off",
    "cli.harden.err_admin": (
        "[red]harden requires administrator privileges (netsh advfirewall needs an elevated "
        "token).[/red]\n"
        "Re-run from an elevated PowerShell / terminal:\n"
        "  Right-click Start → Terminal (Admin) or PowerShell (Admin)\n"
        "  Then run: aaa harden on"
    ),
    "cli.harden.err_proxy_missing": "[red]Proxy program not found: {exe}[/red]",
    "cli.harden.will_create": (
        "Will create {count} outbound firewall rules (name prefix EgressSentinel-):"
    ),
    "cli.harden.rule_line": "  - {name}: {action} {protocol} {port} ← {program}",
    "cli.harden.program_any": "(any program)",
    "cli.harden.boundary": (
        "[yellow]Known limitation: Windows Filtering Platform gives Block precedence over "
        "Allow, so the any-Block rule also matches the proxy and svchost allowlist — after "
        "hardening, outbound 443 may be fully cut (including this tool's proxy). "
        "If the network breaks, run aaa harden off to restore immediately.[/yellow]"
    ),
    "cli.harden.dry_run": (
        "[yellow](dry-run)[/yellow] Not applied (firewall untouched, state file not written)."
    ),
    "cli.harden.confirm": "Create the firewall rules above?",
    "cli.harden.cancelled_nochange": "Cancelled. No changes were made to the system.",
    "cli.harden.err_apply": "[red]Firewall hardening failed: {exc}[/red]",
    "cli.harden.rule_created": "[green]Firewall rule created[/green] {item_key}",
    "cli.harden.done": (
        "Hardening done: {count} rules on record (setup-state.json); "
        "restore with aaa harden off or aaa teardown firewall."
    ),
    "cli.harden.off_no_records": (
        "The state file has no hardening records (never hardened; nothing to restore)."
    ),
    "cli.harden.will_delete": "Will delete {count} firewall rules:",
    "cli.harden.err_delete": "[red]{kind}:{item_key} deletion failed: {exc}[/red]",
    "cli.harden.rule_deleted": "[green]Firewall rule deleted[/green] {item_key}",
    "cli.harden.err_delete_failed": (
        "[red]{count} rules failed to delete (records kept; rerun aaa harden off to retry).[/red]"
    ),
    "cli.harden.off_done": "[green]Firewall hardening fully restored.[/green]",
    # ---- fingerprint build ----
    "opt.fp_repo.help": (
        "Repository working-tree paths (repeatable; defaults to policy fingerprint.repos)"
    ),
    "opt.fp_rebuild.help": (
        "Discard the existing fingerprint index and rebuild from scratch (default: merge "
        "incrementally)"
    ),
    "cli.fp_build.doc": (
        "Build / incrementally merge the repository fingerprint index (data/fingerprints.bin): "
        "purely local, no outbound traffic."
    ),
    "cli.fp_build.err_no_repos": (
        "[red]No repository given.[/red] Use --repo PATH (repeatable) or configure "
        "fingerprint.repos in the policy."
    ),
    "cli.fp_build.msg_rebuild": (
        "[yellow]--rebuild: discarding the existing fingerprint index and rebuilding "
        "from scratch.[/yellow]"
    ),
    "cli.fp_build.msg_corrupt": (
        "[yellow]The existing fingerprint index is missing/corrupt; it will be rebuilt.[/yellow]"
    ),
    "cli.fp_build.skip_exists": "{name}: already in the index (--rebuild rebuilds from scratch)",
    "cli.fp_build.merged": "[green]Merged[/green] {repo}: indexed {files} files / {slices} slices",
    "cli.fp_build.skipped_suffix": (
        " (skipped: too large {too_large}, binary {binary}, read errors {errored})"
    ),
    "cli.fp_build.slice_cap": (
        "[yellow]Repository {repo} reached the total slice cap ({total} slices); "
        "later files were not indexed.[/yellow]"
    ),
    "cli.fp_build.skip_line": "[yellow]Skipped[/yellow] {note}",
    "cli.fp_build.fail_line": "[red]Failed[/red] {error}",
    "cli.fp_build.err_all_failed": (
        "[red]No repository was merged; the fingerprint index is unchanged.[/red]"
    ),
    "cli.fp_build.no_new": (
        "No new repositories (all requested repos are already in the index); "
        "the fingerprint index is unchanged."
    ),
    "cli.fp_build.saved": (
        "[green]Fingerprint index saved[/green] {path}: {repos} repos / {slices} slices / "
        "{digests} fingerprints."
    ),
    "cli.fp_build.restart_hint": " (takes effect after restarting aaa run)",
    # ---- web ----
    "opt.web_host.help": "Listen address (local loopback only)",
    "cli.web.doc": (
        "Start the local web panel (read-only + confirm decisions; listens on 127.0.0.1 only)."
    ),
    "cli.web.err_not_loopback": (
        "The web panel allows local-loopback listening only ({hosts}); got {host!r}"
    ),
    "cli.web.err_missing_dep": (
        "[red]Web panel dependency missing: {exc}[/red]\n"
        "Install the web extra: pip install -e .[web] (fastapi + uvicorn)"
    ),
    "cli.web.err_policy_soft": (
        "[yellow]Failed to load policy (the panel can still browse events): {exc}[/yellow]"
    ),
    "cli.web.listening": (
        "[green]Web panel[/green] http://{host}:{port} (local access only; Ctrl+C to exit)"
    ),
    # ---- policy lint ----
    "cli.policy_lint.doc": (
        "Validate a policy file (strict pydantic schema, doc 03 T3.1): prints a summary when "
        "valid, exits 1 when invalid."
    ),
    "cli.policy_lint.err_invalid": "[red]Policy validation failed: {path}[/red]\n{exc}",
    "cli.policy_lint.table_title": "Policy valid: {path}",
    "cli.policy_lint.row_version": "version",
    "cli.policy_lint.row_mode": "mode",
    "cli.policy_lint.row_policy_version": "policy_version",
    "cli.policy_lint.row_fail_open": "fail_open",
    "cli.policy_lint.row_max_body_scan": "max_body_scan",
    "cli.policy_lint.row_domain_classes": "domain classes",
    "cli.policy_lint.row_domain_rules": "domain rules",
    "cli.policy_lint.row_process_profiles": "process profiles",
    "cli.policy_lint.row_process_rules": "process rules",
    "cli.policy_lint.row_scanners": "scanners",
    "cli.policy_lint.row_content_rules": "content rules",
    "cli.policy_lint.row_volume_rules": "volume rules",
    "cli.policy_lint.row_time_window_rules": "time_window rules",
    "cli.policy_lint.row_fingerprint": "fingerprint",
    "cli.policy_lint.row_judge": "judge",
    "cli.policy_lint.row_response": "response",
    "cli.policy_lint.row_encrypt": "encrypt",
    "cli.policy_lint.fp_desc": "enabled={enabled}, repos={repos}, min_hits={min_hits}",
    "cli.policy_lint.judge_desc": "enabled={enabled}, model={model}, budget/day={budget}",
    "cli.policy_lint.response_ids": "({ids})",
    "cli.policy_lint.encrypt_desc": "enabled={enabled}",
    # ---- 交互向导（setup/wizard.py） ----
    "wizard.ca.title": "① CA root certificate",
    "wizard.ca.store_machine": "LocalMachine\\Root (admin required)",
    "wizard.ca.store_user": "CurrentUser\\Root",
    "wizard.ca.header": "Will install the certificate into the {store_label} certificate store:",
    "wizard.ca.file": "  CA file: {path}",
    "wizard.ca.serial": (
        "  Serial: {serial} (teardown removes it precisely by serial number, never touching "
        "other certificates)"
    ),
    "wizard.ca.thumbprint": "  Fingerprint (SHA1): {thumbprint}",
    "wizard.ca.record_to": "  Recorded to: {state_file}",
    "wizard.ca.machine_warning": (
        "  ⚠ The machine-level store affects all users and requires administrator privileges."
    ),
    "wizard.proxy.title": "② System proxy (WinINET user level)",
    "wizard.proxy.header": "Will set the WinINET user proxy: {host}:{port}",
    "wizard.proxy.registry": "  Registry: HKCU\\{reg_key}",
    "wizard.proxy.values": (
        "  Values: ProxyEnable=1, ProxyServer={host}:{port}, "
        "ProxyOverride=<local>;localhost;127.0.0.1"
    ),
    "wizard.proxy.refresh": (
        "  InternetSetOption notifies WinINET to refresh after writing "
        "(restart browsers recommended)"
    ),
    "wizard.proxy.record_to": "  Old values recorded first to: {state_file} (restored by teardown)",
    "wizard.env.title": "③ User environment variables",
    "wizard.env.merged_pem": (
        "Will create the merged PEM: {path} (mitmproxy CA + system CAs, for REQUESTS_CA_BUNDLE "
        "etc.)"
    ),
    "wizard.env.header": (
        "Will write the following user environment variables (HKCU\\Environment; "
        "effective in new terminals):"
    ),
    "wizard.env.line": "  {name} = {value}",
    "wizard.env.broadcast": (
        "  and broadcast WM_SETTINGCHANGE; all recorded to the state file for restore"
    ),
    "wizard.welcome": (
        "AI-AGENT-AUDIT one-shot guide: the steps below modify system settings and are "
        "confirmed one by one."
    ),
    "wizard.dry_run_banner": (
        "[yellow](dry-run)[/yellow] Showing the plan only; no changes applied."
    ),
    "wizard.confirm_step": "{title}: apply this step?",
    "wizard.skipped": "  [dim]Skipped.[/dim]",
    "wizard.dry_run_step": "  [yellow](dry-run)[/yellow] Not applied.",
    "wizard.step_failed": (
        "  [red]Failed: {exc}[/red] (record kept; restore via teardown and retry)"
    ),
    "wizard.step_done": "  [green]Done.[/green]",
    "wizard.summary_applied": (
        "Guide finished: {applied}. Run aaa teardown to restore all changes in one go."
    ),
    "wizard.summary_none": "Guide finished: nothing was applied.",
    # ------------------------------------------------------------------
    # v0.3.0 wave-two additions (docs 06 wave 2): new commands and --lang.
    # ------------------------------------------------------------------
    # ---- --lang (root option) ----
    "opt.lang.help": (
        "UI language: zh | en (or environment variable AAA_LANG; help text is rendered "
        "in the language set at startup)"
    ),
    # ---- service (W1) ----
    "cli.service.group_help": (
        "Windows service mode: ONSTART scheduled task EgressSentinel-Service (docs 06 W1)"
    ),
    "opt.service_highest.help": "Run with highest privileges (RunLevel=HIGHEST; default on)",
    "cli.service_install.doc": (
        "Install the boot service scheduled task (ONSTART+SYSTEM; requires admin, "
        "recorded journal-first to setup-state.json)."
    ),
    "cli.service_install.will_do": (
        "Will create ONSTART service task {task_name} (SYSTEM account; runs aaa run hidden, "
        "log {log_file}):"
    ),
    "cli.service_install.err_admin": (
        "[red]service install requires administrator privileges (ONSTART+SYSTEM tasks need "
        "an elevated token).[/red]\n"
        "Please run PowerShell / Terminal as administrator and retry:\n"
        "  Right-click Start menu → Terminal (Admin) or PowerShell (Admin)\n"
        "  Then run: aaa service install"
    ),
    "cli.service_install.done": (
        "[green]Service scheduled task created[/green] {task_name} "
        "(change recorded; aaa service status to inspect)"
    ),
    "cli.service_install.err": "[red]Failed to create service scheduled task: {exc}[/red]",
    "cli.service_uninstall.doc": (
        "Delete the service scheduled task and clear its record (idempotent)."
    ),
    "cli.service_uninstall.removed": (
        "[green]Service scheduled task deleted and record cleared[/green] {task_name}"
    ),
    "cli.service_uninstall.absent": (
        "Service scheduled task does not exist (not installed; nothing to delete)."
    ),
    "cli.service_status.doc": "Show service scheduled task status and conflict hints (read-only).",
    "cli.service_status.line": "{task_name}: {state} (command {command}, log {log_file})",
    "cli.service_status.line_no_journal": "{task_name}: {state}",
    "cli.service_status.conflict": "[yellow]{warning}[/yellow]",
    "cli.service_install.confirm": "Create the service scheduled task?",
    # ---- tray (W2) ----
    "cli.tray.doc": (
        "Start the system tray (needs pystray/Pillow: pip install -e .[tray]; "
        "exits with code 2 when dependencies are missing)."
    ),
    # ---- report --daily/--weekly/--email (W6) ----
    "opt.report_daily.help": (
        "Render the day's HTML daily report (saved under data/reports/ by default)"
    ),
    "opt.report_weekly.help": "Render the HTML weekly report for that day's ISO week (Monday first)",
    "opt.report_email.help": (
        "Send the report via the policy notifications.email channel (complete SMTP config required)"
    ),
    "opt.report_day.help": "Date YYYY-MM-DD (default today; --weekly uses that day's ISO week)",
    "opt.report_out.help": (
        "HTML output path (default data/reports/daily-<date>.html / weekly-<date>.html)"
    ),
    "cli.report.err_daily_json": "--daily/--weekly cannot be combined with --json/--csv",
    "cli.report.err_daily_both": "--daily and --weekly are mutually exclusive",
    "cli.report.err_day": "Invalid date: {value!r} (expected YYYY-MM-DD)",
    "cli.report.daily_saved": "[green]Daily report generated[/green] {path}",
    "cli.report.weekly_saved": "[green]Weekly report generated[/green] {path}",
    "cli.report.email_sent": "[green]Report email sent[/green] → {to}",
    "cli.report.email_failed": "[red]Failed to send report email: {exc}[/red]",
    "cli.report.render_failed": "[red]Failed to render report: {exc}[/red]",
    # ---- rules export/import (W7) ----
    "cli.rules.group_help": (
        "Rules hub: policy section export/import (docs 06 W7; invalid input is never written)"
    ),
    "cli.rules_export.doc": "Export a policy section as YAML text (--out to save; stdout by default).",
    "opt.rules_out.help": "Export output path (stdout by default)",
    "cli.rules_export.err": "[red]Export failed: {exc}[/red]",
    "cli.rules_export.done": "[green]Section {section} exported[/green] → {path}",
    "cli.rules_import.doc": (
        "Import a YAML file (``-`` reads stdin) into a policy section: atomic write only after "
        "all three validation passes."
    ),
    "opt.rules_merge.help": (
        "Merge mode: replace (whole section, default) | union (merge by id/key, importer wins)"
    ),
    "opt.rules_policy.help": (
        "Target policy file (default: the active policy; the file is rewritten whole, YAML "
        "comments are lost)"
    ),
    "cli.rules_import.note_comments": (
        "[yellow]Note: import rewrites the whole file; existing YAML comments are lost "
        "(back up with aaa rules export first).[/yellow]"
    ),
    "cli.rules_import.done": "[green]Section {section} imported[/green] (merge={merge}) → {path}",
    "cli.rules_import.err": "[red]Import failed: {exc}[/red]",
    # ---- gitleaks (W7) ----
    "cli.gitleaks.group_help": (
        "gitleaks upstream rule sync: TOML → native secrets rule pack (sha256 pin)"
    ),
    "cli.gitleaks_sync.doc": (
        "Sync gitleaks rules from a URL or local TOML and convert to a rule pack YAML."
    ),
    "opt.gitleaks_out.help": "Rule pack output path (default data/rules/gitleaks.yaml)",
    "cli.gitleaks_sync.done": (
        "[green]gitleaks rules synced[/green]: {converted} rules ({skipped} skipped)"
        " sha256={sha256} → {path}"
    ),
    "cli.gitleaks_sync.err": "[red]gitleaks sync failed: {exc}[/red]",
    # ---- hub (W8) ----
    "cli.hub.group_help": (
        "Multi-machine aggregation: hub collector (serve) and agent forward status (docs 06 W8)"
    ),
    "cli.hub_serve.doc": "Start the hub collector service (0.0.0.0 by default, Bearer token auth).",
    "opt.hub_host.help": "Listen address (default 0.0.0.0; accepts multi-machine reports)",
    "opt.hub_port.help": "Listen port (default 8788)",
    "opt.hub_token.help": "Shared token (default env AAA_HUB_TOKEN; required)",
    "cli.hub_serve.err_token": (
        "[red]The hub collector requires a shared token: use --token or environment variable "
        "AAA_HUB_TOKEN.[/red]"
    ),
    "cli.hub_serve.err_dep": (
        "[red]Hub dependencies missing: {exc}[/red]\n"
        "Install the web extra: pip install -e .[web] (fastapi + uvicorn)"
    ),
    "cli.hub_serve.db_line": "Event DB: {db_file} (per-machine dimension; history survives restarts)",
    "cli.hub_serve.listening": (
        "[green]Hub collector[/green] http://{host}:{port} (Bearer auth; Ctrl+C to exit)"
    ),
    "cli.hub_forward.doc": (
        "Show agent-side forward config and latest stats (a running aaa run writes "
        "data/hub-forward.json)."
    ),
    "cli.hub_forward.disabled": (
        "hub forward: disabled (policy hub.enabled or AAA_HUB_URL+AAA_HUB_TOKEN)"
    ),
    "cli.hub_forward.enabled": (
        "hub forward: enabled → {url} (batch_size={batch_size}; token via policy/env, not shown)"
    ),
    "cli.hub_forward.no_stats": "(no runtime stats yet: aaa run not running or nothing forwarded)",
    "cli.hub_forward.stats_line": (
        "sent {sent_events} events / {sent_batches} batches; dropped {dropped}; "
        "retries {retries_used}; errors {send_errors}; queue {queue_size} (updated {updated})"
    ),
    "cli.hub_forward.last_error": "Last error: {error}",
    # ---- policy use/list (multi-profile) ----
    "cli.policy_use.doc": (
        "Switch the active policy profile (copies profiles/<name>.yaml → current.yaml; "
        "running agents hot-reload within 2s)."
    ),
    "opt.policy_name.help": "Profile name (YAML file name under policies/profiles/, without extension)",
    "opt.policy_reset.help": "Remove current.yaml and fall back to the factory policies/default.yaml",
    "cli.policy_use.err_missing": (
        "[red]Profile not found: {path}[/red] (aaa policy list to view available)"
    ),
    "cli.policy_use.err_invalid": "[red]Profile validation failed: {exc}[/red]",
    "cli.policy_use.done": "[green]Active policy switched[/green] → {name} ({path})",
    "cli.policy_use.reset_done": (
        "[green]current.yaml removed[/green]: active policy is back to factory "
        "policies/default.yaml"
    ),
    "cli.policy_use.no_current": "current.yaml does not exist (already on the factory default policy).",
    "cli.policy_list.doc": "List available policy profiles and the active policy.",
    "cli.policy_list.title": "Policy profiles ({policies_dir})",
    "cli.policy_list.col_name": "profile",
    "cli.policy_list.col_status": "status",
    "cli.policy_list.current": "← active",
    "cli.policy_list.base_default": "factory default (current.yaml not in effect)",
    "cli.policy_list.none": (
        "(no profiles under policies/profiles/ yet; add YAML files then aaa policy use <name>)"
    ),
    # ---- policy lint new section rows (sampling/hub) ----
    "cli.policy_lint.row_sampling": "sampling",
    "cli.policy_lint.sampling_desc": "enabled={enabled}, head_bytes={head_bytes}",
    "cli.policy_lint.row_hub": "hub",
    "cli.policy_lint.hub_desc": "enabled={enabled}, url={url}",
    # ---- run wiring (W4 sampling / W8 forward / batch insert) ----
    "opt.run_db_batch.help": "Event batch-insert threshold (events; 1=insert immediately, default 20)",
    "cli.run.sampling_on": "scan sampling: on (head_bytes={head_bytes}, policy.sampling)",
    "cli.run.sampling_off": "scan sampling: off (policy.sampling.enabled)",
    "cli.run.hub_on": "hub forward: on → {url} (batch {batch_size}/post; token via policy/env)",
    "cli.run.hub_off": "hub forward: off (policy.hub.enabled or AAA_HUB_URL+AAA_HUB_TOKEN)",
    # ---- extra: argument help and hub forward group ----
    "opt.rules_section.help": (
        "Policy section name (domains/content/notifications/sampling/hub etc.; an invalid "
        "name lists all available sections)"
    ),
    "opt.rules_source.help": "YAML file to import, or - (read stdin)",
    "opt.gitleaks_source.help": "Source: URL (http/https) or local gitleaks TOML file path",
    "cli.hub_forward.group_help": "Agent-side event forwarding (Forwarder)",
    "cli.hub_forward_status.doc": (
        "Show agent-side forward config and latest stats (a running aaa run writes "
        "data/hub-forward.json)."
    ),
    "cli.watchdog.restored": "  - Restored {action}",
    "common.deepening_join": "; ",
    # ---- extra paragraphs of multi-line docstrings (joined into typer help=) ----
    "cli.run.detail": "Events are stored in SQLite (docs 02 D6).",
    "cli.report.detail": (
        "``--daily``/``--weekly`` (docs 06 wave 2 W6): render a self-contained HTML daily/weekly "
        "report into ``data/reports/``; ``--email`` sends it via the policy notifications.email "
        "channel."
    ),
    "cli.notify_test.detail": (
        "Actual delivery of webhook/email depends on external services; failures are reported "
        "honestly with a non-zero exit code."
    ),
    "cli.harden.detail": (
        "on: create 4 ``EgressSentinel-``-prefixed rules (journal-first into setup-state.json; "
        "restorable via ``harden off``/``aaa teardown``); off: precise deletion per records "
        "(idempotent). Requires administrator.\n\n"
        "Known boundary (registered by the firewall module): Windows WFP applies Block before "
        "Allow, so the any-Block rules also hit the proxy and svchost allowlist — after ``on``, "
        "outbound 443 may be fully blocked (including this tool's own proxy). Rehearse in a "
        "restorable environment before touching a real machine (``off`` restores), and confirm "
        "connectivity."
    ),
    "cli.fp_build.detail": (
        "Merging a repo that is already indexed is rejected (--rebuild rebuilds from scratch); "
        "a non-git workspace must contain ``.git`` (indexing only reads workspace files; no git "
        "commands are executed and no network is touched)."
    ),
}
