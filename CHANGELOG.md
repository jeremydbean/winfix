# Changelog

## 2026-11-25 - nothing required before submitting a ticket
- Submit ticket no longer waits on manual checks, notes, client name or technician. Unanswered checks are sent as Not checked; an empty client name falls back to the NinjaOne organization, Entra tenant, domain or server name, and an empty technician to the Windows user name. Only missing email settings stop a ticket. The status next to Submit shows how many optional items are empty.

## 2026-11-25 - shared SMTP2GO and NinjaOne API settings from NinjaOne fields
- The app reads the NinjaOne text fields smtp2goUsername, smtp2goPassword, smtp2goFromAddress, ninjaApiClientId and ninjaApiClientSecret through ninjarmm-cli (checked on FLF-SERVER from a non-NinjaOne process). Values there override Settings. With an API key in the fields, NinjaOne data is pulled without a sign-in. SMTP defaults are now mail.smtp2go.com:2525 with TLS.

## 2026-11-25 - remember the NinjaOne sign-in (opt-in, 30 days)
- The NinjaOne sign-in prompt has a 'Remember my sign-in on this server for 30 days' checkbox (off by default). The refresh token is DPAPI-encrypted for the machine; later audits and scheduled runs pull NinjaOne data without a sign-in. Settings > NinjaOne shows it and has Forget. The NinjaOne client app now allows the Refresh token grant.

## 2026-11-25 - NinjaOne integration
- NinjaOne button: technician signs in through the browser (Native client app, Monitoring scope, PKCE; token in memory only). The app matches this server by name and serial number and adds the NinjaOne organization as client name, open alerts, failed and pending OS patches, antivirus status and threats, online status, policy and warranty. Answers the RMM check and, without Defender, the antivirus check. Data is saved as <report>.ninja.json.

## 2026-11-25 - Polarnite branding
- Polarnite logo on the app header and PDF cover, the round badge on PDF page headers and as the exe icon. The PDF writer now supports images with transparency. Assets and the script that makes them are in app/assets.

## 2026-11-25 - override any finding
- Findings tab: a RATING dropdown on every finding (Critical, Warning, Best practice, Pass, Accepted). Overrides are saved per server (state\overrides.json), apply to future audits, and appear in the PDF and email with who changed the rating, the original rating and the reason. Accepted findings are not counted.

## 2026-11-25 — collector 1.16, in-app updates and client name from Entra
- App: **Check for updates** downloads the newest `PolarniteServerAuditTool.exe` from GitHub (`app/dist/latest.json` gives the build time, size and SHA-256), verifies it, swaps it in and restarts; `--update` does the same unattended for RMM scripts. `build.ps1` stamps each build and writes `latest.json`.
- Client name: taken from the Entra tenant (dsregcmd, or the new `TenantIdentity` check reading `HKLM\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo`, which also works where dsregcmd is missing), then from the Microsoft 365 tenant users are signed in to (OneDrive work accounts). A technician-typed name is kept.
- Synology Active Backup (checked on a second live server, agent 3.2 on Server 2025): errors that repeat inside every successful run (for example VSS `BackupComplete` failures) are a warning, and NAS outages are reported by day.

## 2026-11-25 — collector 1.15: checked against real Veeam and Synology servers
- Synology Active Backup for Business: the agent rotates `log.txt_0 … log.txt_N` and writes `Nov 21 03:59:27 -0500` timestamps without a year; most lines are once-a-minute status calls. The collector now reads backup runs from `backup-job.cpp` lines (start, `in backup routine, has_fail_volume 'N'`), backup ERROR lines and NAS connection errors (`ConvertFrom-AuditAbbLogLine`), across the newest 40 log files. The app learns the usual interval from past runs (weekly schedules are not flagged) and auto-answers the backup checks.
- Veeam Backup & Replication 12.2: confirmed `Get-VBRJob`, restore points, repositories and licence on a live server. Jobs set to run manually are no longer flagged as stale; backup copy jobs with no new copy in 7 days are a warning; licence expiry warns 60 days ahead.
- Findings are rated **Critical** (needs a fix ticket), **Warning** (noted, no ticket) or **Best practice** (no ticket). The report cover and email list everything that needs a ticket first. Hygiene items such as krbtgt age, lockout policy, NTLM level, BitLocker and Print Spooler on a DC are now Best practice.
- Removed the "Test restore performed" manual check.

## 2026-11-25 — collector 1.14 and app renamed to Polarnite Server Audit Tool
- The app is now `app/dist/PolarniteServerAuditTool.exe` ("Polarnite Server Audit Tool"). On first run it moves `C:\ProgramData\WinFixAudit` to `C:\ProgramData\PolarniteServerAudit` and replaces the `\WinFix\Monthly Server Audit` task with `\Polarnite\Monthly Server Audit`. The test override variable is now `POLARNITE_AUDIT_DATA`.
- Windows 10/11 used as a server: new `ClientPlatform` check (sleep/hibernate on AC, fast startup, automatic sign-in with the stored-password flag read by value name only, UAC, paused/deferred updates, TPM spec version). `ServerRoles` uses optional features on client Windows. The app adds LTSC support dates, Extended Security Updates licence detection (auto-answers the OS entitlement check), Home edition and Windows 11 readiness.
- Backups: new `SynologyActiveBackup` (agent service, NAS port 5510 connection, outcome lines from the newest agent logs), `VeeamServerJobs` (only on Backup & Replication servers: jobs, schedule, last result, restore points, copy jobs, repository space, licence) and `OneDriveActivity` (per-user log-folder times and client version, no log content). The app now reports the existing Synology Drive and OneDrive evidence too.
- Installed software past or near end of support (Office, Exchange, SQL Server, SharePoint, Acrobat, Java, Python 2, QuickBooks).
- Fix: a new month's draft no longer carries last month's automatic notes forward.

## 2026-11-25 — collector 1.13 and app: standard monthly checks
- Collector adds Defender detection history, Veeam job results (event 190), RMM/EDR agent log activity, certificates expiring within 60 days, Windows activation, LAPS policy, protocol/credential hardening (TLS/SSL, LLMNR, NetBIOS, WDigest, NTLM level, LSA protection, update source), key services, Dell OpenManage / HPE Smart Storage hardware health and hardware error events.
- On domain controllers it also collects AD hygiene (stale users/computers, never-expiring passwords, unsupported OS, krbtgt age, Recycle Bin), `dcdiag /q` and `repadmin /replsummary`.
- New opt-in `-ExternalExposureCheck` looks up the site's public IP in Shodan InternetDB. It is the only check that contacts a third party, and the app leaves it off unless enabled in Settings.
- App answers manual checks from evidence where it can (antivirus detections, last backup and failures, hardware health, internet exposure), marked "Auto-verified" and always overridable. It also adds local agent evidence as hints for the NinjaOne and Huntress checks.
- App compares each audit with the last submitted one: new and resolved findings, disk-full forecasts, new administrators, newly installed software (remote-access tools flagged) and new listening ports. Findings new since last month are marked NEW in the app, PDF and email.
- Fixes `app/build.ps1` and the sample generator under `powershell -File` (empty `$PSScriptRoot` in parameter defaults). The compiler now reads source as UTF-8.

## 2026-11-25 — Server Audit app
- Adds `app/`: WinFixAuditApp.exe, a standalone Windows app that runs the embedded collector, turns evidence into scored findings, records technician-verified manual checks (backup console, RMM, EDR, AV, hardware, MFA, exposure), builds a branded PDF report and emails a summary ticket with the PDF attached. Monthly scheduled runs save drafts only; nothing is sent until a technician submits.
- Settings and drafts live in `C:\ProgramData\WinFixAudit` (Administrators/SYSTEM only); the SMTP password is DPAPI-encrypted.
- Repository cleanup: removes `download_direct.ps1` and `Run_Direct.bat` (pinned to an old commit as a CDN-cache workaround), `download_and_run.ps1` (unreferenced), `OFFLINE_INSTALL.md` (inaccurate: its "offline" option downloads from GitHub) and `encrypt_creds.ps1` (contained hard-coded API credentials from the removed NinjaOne integration; rotate that secret, since it remains in git history).
- README rewritten as an overview of the tools; the detailed collector/diagnostic reference moved to `docs/Collector.md`. `agents.md` updated to the current layout.

## 2026-10-27 — collector 1.11
- Adds optional `-DeepAudit` for domain/forest/FSMO and password policies, privileged groups/account candidates, local replication/SYSVOL events, CA/IIS settings, certificate metadata, identity-sync status, DNS and DHCP configuration.
- Adds bounded storage metadata and child ACL samples plus CBS package metadata; guest UUID/BIOS evidence helps match agentless backup objects without asserting coverage.
- Fixes DC Administrators lookup and printer pseudo-path ACL errors. Adds targeted time/ID/level/provider queries with explicit coverage and deadlines.
- Bounds the VSS console reader independently and closes only that reader on timeout; preserves partial evidence and per-check checkpoints.
- Keeps PowerShell 4 compatibility, adds launcher support and fixture coverage. Live Windows/DC validation remains necessary.

## 2026-09-28 — disk diagnostic 1.1
- Fixes mounted virtual-disk discovery when Windows exposes BusType as text (such as SATA or RAID), with a regression covering the production block.

## 2026-09-28 — targeted disk diagnostic
- Adds a separate read-only ISE diagnostic for disk identity, kernel-device mappings, retained PnP entries, storage drivers/health and backup activity.
- Captures bounded Event 51 XML/binary details and optional incident-window events, with worker timeouts, per-section checkpoints and pasteable Notepad/clipboard output.

## 2026-09-28 — collector 1.10
- Adds OneDrive account/known-folder and policy evidence across loaded user profiles without opening cloud content, mounting user hives, or claiming sync health.
- Adds bounded generic text-log probes for additional backup products plus up to eight custom local log directories; broadens software/service/event/task detection.
- Adds scheduled-script SHA256 fingerprints, scoped ACL evidence, fixed command-risk indicators, task result/missed-run review flags, and allowlisted Task Scheduler failure event fields.
- Fixes rsync substring false positives and avoids resolving task-user variables in the audit administrator's environment. Inspects literal relative script references only with an explicit working directory.
- Adds disk reliability counters, storage error details, application VSS errors and unexpected shutdown evidence. Preserves PowerShell 4 and per-check timeout behavior.
- Expands regression coverage for privacy, registry expansion, profile/scan limits, actual worker boundaries, scheduler states and script fingerprints. Live Windows/vendor validation remains required.

## 2026-09-28
- Collector 1.9 adds bounded per-user Synology Drive Client log and allowlisted task-setting evidence, with explicit database/manual-evidence limits.
- Expands scheduled backup discovery to script and copy/export wrappers, including read-only local script clues, schedules, run accounts and per-task errors.
- Preserves ISE/PowerShell 4 compatibility and adds regression fixtures for privacy, discovery bounds and candidate classification.

## 2026-04-29
- Fixed `WinFixTool_v2.ps1` v5.2 → v5.3: glob mismatch (report never auto-opened), nav button crash for stub pages, locale-dependent Administrators group lookup (now uses SID S-1-5-32-544), caption-regex EOS detection replaced with build→date table, `Out-File -Encoding UTF8` BOM replaced with `WriteAllText`, `Get-HotFix` replaced with `QueryHistory(0,50)` + HotFix fallback, RDP failure count now filters LogonType=10, `copyForFreshdesk` rewritten with data-key snapshot + modern `navigator.clipboard.write()` + fallback, Defender signature age grading, elevation check + in-app warning, DC detection before local user enumeration, broader VM fingerprint, `$ErrorActionPreference` corrected to `Continue`.


## 2026-04-29
- Expanded `WinFixTool_v2.ps1` into the Max Audit engine for HIPAA-oriented MSP monthly audits.
- Added registry/service/process/path detection for NinjaRMM, Huntress, GoToAssist, remote access tools, and backup products.
- Added report sections for BitLocker, drive usage, Windows Update status/history, support lifecycle, event-log indicators, network shares, printers, RDP posture, custom scheduled tasks, system specs, and PowerShell version.
- Improved the HTML report styling and the formatted copy workflow for Freshdesk/Ninja ticket notes.
- Kept PowerShell 5.1-safe syntax and fallbacks for Windows Server 2012-era systems.

## 2025-12-16
- Removed the RMM integration from WinFixTool (GUI) and WinFixTool_v2 (GUI).
- Updated docs to reflect local-only operation.

## 2025-12-15
- Added WinFixConsole (menu-driven, no WinForms/EXE) with task window launching and unified logging.
- Fixed task windows closing immediately on errors; tasks now pause reliably even when exceptions occur.
- Fixed Security Audit on Windows Server where `Get-MpComputerStatus` is unavailable.
- Forced TLS 1.2 for web requests to avoid "Could not create SSL/TLS secure channel" on older PowerShell.
- Fixed port-scan helper crash caused by using `$Host` as a function parameter (also conflicts with `$Host`).
- Menu now accepts `QUIT`/`EXIT` (in addition to `Q`).
- Added Diagnostics/Triage utilities: quick triage export, pending reboot check, recent System events, BitLocker status, firewall profile status.
- Added Network printer scan for TCP port 9100.
- Added log tail (live) and export bundle ZIP (log + latest audit).
- Added Maintenance Bundle (SFC + DISM + Windows Update reset) with typed confirmation.
- Added typed confirmations for destructive actions (delete local user/share).
- Continued hardening and feature parity work in WinFixTool (GUI).
