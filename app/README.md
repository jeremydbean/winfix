# WinFix Server Audit (Windows app)

`dist/WinFixAuditApp.exe` is a single file for monthly server maintenance tickets. It:

1. Runs the repository's read-only collector, [`Export-WinFixAudit.ps1`](../Export-WinFixAudit.ps1), which is embedded in the exe.
2. Turns the evidence into **findings** (critical / warning / info / pass).
3. Lets the technician fill in what a script can't check: backup console, restore test, NinjaOne, Huntress, antivirus, hardware, MFA and exposure.
4. Builds a branded **PDF report** and emails a **summary ticket** with the PDF attached to `support@polarnite.com`:
   `Monthly Server Audit - <tenant> - <server> - <month>`

It needs nothing installed on the server beyond .NET Framework 4.5+ and Windows PowerShell 4+, which come with Windows Server 2012 R2 and later.

| Manual checks | Sample report |
| --- | --- |
| ![Manual checks tab](docs/app-manual-checks.png) | [Sample-Report-DC01.pdf](docs/Sample-Report-DC01.pdf) (fictional server) and the [ticket email](docs/ticket-email.png) |

## Using it on a server

1. Copy `dist\WinFixAuditApp.exe` to the server and run it. It asks for administrator rights.
2. First time only: **Settings & schedule…**
   - SMTP server, port (587 + STARTTLS, or 25 for a relay), username/password, From address.
     **Send test email** checks the settings.
   - Optional: **Create / update schedule** sets up a monthly run (day 1–28, time).
3. **Run audit** (3–10 minutes). Progress shows in *Collection log*.
4. Review **Findings**. You can add a technician note to any finding; notes appear in the PDF and the email.
5. Complete **Manual checks**. Required items must be answered, and *Issue found* needs a note.
6. Check **Overview**: tenant/client name (pre-filled from Entra tenant or AD domain), technician, server role and summary notes.
7. **Preview PDF** if you like, then **Submit ticket**. The button shows how many items are left until the ticket is complete.

### Scheduled runs

The scheduled task runs as SYSTEM and **only collects**. It saves the result as a draft and sends nothing.
The next time a technician opens the app, the draft loads with a yellow banner. Complete the manual
checks and press **Submit ticket**. Last month's notes are pre-filled; statuses reset to *Not checked*.

## Where things are kept

`C:\ProgramData\WinFixAudit` (access limited to Administrators and SYSTEM):

| Path | Contents |
| --- | --- |
| `settings.json` | SMTP and ticket settings. The SMTP password is encrypted with machine-scoped DPAPI. |
| `state\current.json` | The current month's draft: answers, notes and status. |
| `state\last-answers.json`, `state\history\` | Last submission (used for next month's pre-fill) and a copy of every submission. |
| `runs\<timestamp>\` | Collector JSON plus the PDF sent. Runs older than 6 months are pruned. |
| `logs\app-YYYY-MM.log` | App and scheduled-run log. |
| `bin\WinFixAuditApp.exe` | Copy used by the scheduled task. |

## Building

```powershell
cd app
.\build.ps1
```

This uses the C# compiler included in .NET Framework 4.x (`csc.exe`). No Visual Studio or NuGet is needed. It embeds
`..\Export-WinFixAudit.ps1` and writes `dist\WinFixAuditApp.exe`.
**Rebuild and commit the exe whenever the collector changes**, so the binary in `dist` matches the script.

### Testing without a server

```powershell
cd app
.\tests\New-SampleAudit.ps1                       # synthetic DC01 report with planted issues
.\build.ps1 -AsInvoker -Output .\test-build\app.exe
$env:WINFIXAUDIT_DATA = "$env:TEMP\wfa-test"      # keep test state out of ProgramData
.\test-build\app.exe --render (Get-ChildItem .\tests\sample\*.json)[0].FullName $env:TEMP\wfa-out
```

`--render` builds the PDF, the email bodies and an `.eml` file (in `mail\`) instead of sending anything.
`--screenshot <report.json> <dir>` saves PNGs of the main window.
Keep test folders short: .NET Framework rejects paths over 260 characters.

## Customising

- **Required agents** (Settings): comma-separated service names, default `Ninja, Huntress`. A missing or stopped agent is a critical finding.
- **Manual check list**: `ManualCatalog.Items` in `src\Model.cs` (title, guidance, required, and when it applies).
- **Rules and thresholds**: `src\Analyzer.cs`. Examples: drive space below 20% is a warning and below 10% is critical. A restart is due after 35 days. Defender signatures older than 3 days are a warning and older than 7 days are critical. Updates not installed for 35 days are a warning and 60 days is critical.
- **OS lifecycle dates**: `Lifecycle()` in `src\Analyzer.cs`. Check them against Microsoft's lifecycle pages from time to time.

## Notes and limits

- Missing data is never counted as a pass. Checks that fail or time out are listed under *Collection coverage* at the end of the PDF.
- SMTP port 465 (implicit TLS) is not supported by .NET's mail client. Use 587/STARTTLS or a port-25 relay.
- The exe is unsigned, and it starts `powershell.exe -ExecutionPolicy Bypass` to run the embedded collector. EDR tools (including Huntress) may flag this. Sign the exe, or allow-list its hash, before a wide rollout.
- The PDF uses the built-in Helvetica fonts (Western European characters). Other characters print as `?`.
