# Agent Notes - WinFix

## Current Status
**Date:** December 16, 2025
**Objective:** Keep WinFix scripts stable for Windows PowerShell 5.1 (Windows Server-friendly) while maintaining the Security Audit report.

## Recent Changes
* Removed the RMM integration from both GUI scripts.
* Kept audit generation and local-only checks intact.
* Hardened `Invoke-SecurityAudit` (WinFixTool.ps1, WinFixConsole.ps1):
  HTML encoding on all interpolations, locale-independent Administrators
  lookup via SID, Domain Controller detection, build-based EOS table,
  Update Session history (replacing Get-HotFix), background job + 90s
  timeout for Windows Update search, elevation guard, DB error provider
  whitelist, broadened backup vendor list, Get-WinEvent -ListLog for
  Security log retention, UTF-8 (no BOM) output with TEMP fallback,
  modern `navigator.clipboard.write` with execCommand fallback,
  data-key based copy snapshot, broader VM detection, and built-in
  Administrator enabled-state annotation.

## Operational Notes
* Debug log path: `%TEMP%\WinFix_Debug.log`
* One-line install entrypoint: `install.ps1` (downloads + launches)

## Future Improvements (Optional)
* Add additional local-only patch/backup signal sources (Windows Update history, Windows Server Backup events) to strengthen the audit without any external integrations.
