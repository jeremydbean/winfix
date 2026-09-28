# Changelog

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
