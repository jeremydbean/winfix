# Changelog

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
