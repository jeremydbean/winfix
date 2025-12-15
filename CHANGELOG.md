# Changelog

## 2025-12-15
- Added WinFixConsole (menu-driven, no WinForms/EXE) with task window launching and unified logging.
- Fixed task windows closing immediately on errors; tasks now pause reliably even when exceptions occur.
- Fixed Security Audit on Windows Server where `Get-MpComputerStatus` is unavailable.
- Forced TLS 1.2 for web requests to avoid "Could not create SSL/TLS secure channel" (NinjaOne/GitHub) on older PowerShell.
- NinjaOne auth now retries the token endpoint with both derived API host and the original instance host, and probes which host supports `/v2`.
- Fixed NinjaOne connect crash caused by using `$host` (conflicts with PowerShell read-only `$Host`).
- Fixed port-scan helper crash caused by using `$Host` as a function parameter (also conflicts with `$Host`).
- NinjaOne OAuth now uses `monitoring management` scope and emits a clearer error when the Client ID isn't recognized ("Client app not exist").
- Menu now accepts `QUIT`/`EXIT` (in addition to `Q`).
- Added Diagnostics/Triage utilities: quick triage export, pending reboot check, recent System events, BitLocker status, firewall profile status.
- Added Network printer scan for TCP port 9100.
- Added log tail (live) and export bundle ZIP (log + latest audit).
- Added Maintenance Bundle (SFC + DISM + Windows Update reset) with typed confirmation.
- Added typed confirmations for destructive actions (delete local user/share).
- Continued hardening and feature parity work in WinFixTool (GUI).
