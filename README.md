# WinFix

Windows maintenance, audit and diagnostic tools for MSP monthly server work.

| Tool | What it's for |
| --- | --- |
| [**Server Audit app**](app/README.md) — `app/dist/WinFixAuditApp.exe` | Monthly audit tickets: runs the collector, scores findings, records manual console checks, builds a PDF report and emails the ticket. Can run on a monthly schedule. |
| [`Export-WinFixAudit.ps1`](docs/Collector.md) (+ `Start-WinFixAudit.ps1` launcher) | Read-only audit evidence collector (PowerShell 4+). Used by the app; can also run on its own and produce pasteable JSON. |
| [`Export-WinFixDiskDiagnostic.ps1`](docs/Collector.md#targeted-disk-diagnostic-ise) | Read-only diagnostic for disk warnings such as Event 51. |
| [`Export-WinFixBackupDiagnostic.ps1`](docs/Collector.md#stalled-windows-backup--nas-diagnostic-ise) | Read-only diagnostic for stalled Windows Backup / NAS / Active Backup jobs. |
| `WinFixTool.ps1` / `WinFixConsole.ps1` | Repair and maintenance tool (GUI / text menu): disk cleanup, network reset, SFC, DISM, Windows Update reset, print spooler, time sync, SpaceMonger. |
| `WinFixTool_v2.ps1` (via `install.ps1`) | Earlier "Max Audit" GUI that produces an HTML report for pasting into Freshdesk/Ninja notes. The Server Audit app is its successor. |

## Monthly server audit (recommended)

1. Download [`app/dist/WinFixAuditApp.exe`](app/dist/WinFixAuditApp.exe) to the server and run it as administrator.
2. First run: **Settings & schedule** to set SMTP (and optionally a monthly schedule).
3. **Run audit**, review **Findings**, complete **Manual checks**, then **Submit ticket**.

Details, data locations and build instructions: [app/README.md](app/README.md).

## Audit collector on its own

In **64-bit Windows PowerShell (ISE) as Administrator**:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Export-WinFixAudit.ps1 -CopyToClipboard
```

On Server 2012 R2, or anywhere TLS 1.2 isn't the default, use the launcher block in
[docs/Collector.md](docs/Collector.md#windows-server-2012-r2--tls-download-errors).
Options such as `-DeepAudit`, `-SkipOnlineUpdateScan`, `-EvidenceFile` and the Veeam/Synology settings are documented there too.

## Repair tool and the earlier audit GUI

Repair tool from a local copy of the repo: double-click `Launch_WinFix.bat` (GUI), or run `WinFixConsole.ps1` for the text-menu version.

The earlier Max Audit GUI (`WinFixTool_v2.ps1`) has a one-line launcher. It requests admin, downloads to `%TEMP%` and cleans up on close:

```powershell
irm https://raw.githubusercontent.com/jeremydbean/winfix/main/install.ps1 | iex
```

`Build_and_Run.bat` compiles `WinFixTool.ps1` into `WinFixTool.exe` with PS2EXE (needs internet the first time to install the module).
Debug log: `%TEMP%\WinFix_Debug.log`.

## Requirements

- Windows Server 2012 R2 or later, or Windows 10/11.
- Windows PowerShell 4.0+ (5.1 preferred); .NET Framework 4.5+ for the Server Audit app.
- Administrator rights for audits and most fixes.

## Development

- Collector and diagnostic tests (run on PowerShell 7 too): `pwsh -NoProfile -File tests/Test-AuditExport.ps1`, plus the other scripts in `tests/`.
- App: `app/build.ps1`, with sample data from `app/tests/New-SampleAudit.ps1`. See [app/README.md](app/README.md#building).
- Changes are recorded in [CHANGELOG.md](CHANGELOG.md).

Everything here collects evidence locally. Nothing is uploaded except the ticket email the app sends when you press Submit. Review reports before sharing: they contain machine names, accounts, IP addresses and paths.
