# Changelog

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
