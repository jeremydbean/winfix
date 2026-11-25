# Agent notes — WinFix

Updated 2026-11-25.

## Layout

| Path | Notes |
| --- | --- |
| `Export-WinFixAudit.ps1` | Read-only evidence collector. Must stay compatible with Windows PowerShell 4.0 (Server 2012 R2): no PS 5+ syntax, compact JSON only, every check inside `Invoke-AuditCheck` with a timeout. |
| `Start-WinFixAudit.ps1` | TLS 1.2 launcher for the collector. |
| `Export-WinFixDiskDiagnostic.ps1`, `Export-WinFixBackupDiagnostic.ps1` | Targeted read-only diagnostics. |
| `app/` | Server Audit app (C# 5 / .NET Framework 4.5, WinForms). Built with Framework `csc.exe` by `app/build.ps1`, which embeds the root collector. Keep the source C# 5: no string interpolation, `?.`, `nameof` or expression-bodied members. |
| `WinFixTool.ps1`, `WinFixConsole.ps1` | Repair/maintenance tool (GUI and menu). `SpaceMonger.exe` is downloaded from this repo by these scripts. |
| `WinFixTool_v2.ps1`, `install.ps1` | Earlier HTML "Max Audit" GUI and its one-line installer. |
| `tests/` | Regression scripts for the collector and diagnostics; run with `pwsh -NoProfile -File`. |
| `docs/Collector.md` | Full collector/diagnostic reference (moved out of README). |

## Rules

- Collectors never change configuration, upload data, run backups or read credentials. Missing evidence is reported as Unavailable/TimedOut, never as a pass.
- When the collector changes: bump its version string (`WinFix audit x.y`), update `CHANGELOG.md` and `docs/Collector.md`, then rebuild `app/dist/WinFixAuditApp.exe` (`app/build.ps1`) and commit the exe.
- No secrets in the repo. Integrations (SMTP, future RMM/EDR APIs) store credentials on the server with DPAPI.
- Debug log for the older GUIs: `%TEMP%\WinFix_Debug.log`. The app logs to `C:\ProgramData\WinFixAudit\logs`.
