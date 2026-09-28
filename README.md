# WinFix Tool & Security Audit

Windows system maintenance and security audit tool.

## 🚀 Quick Start - One Line Install

**Copy and paste this into PowerShell:**

```powershell
irm https://raw.githubusercontent.com/jeremydbean/winfix/main/install.ps1 | iex
```

✅ Automatically requests admin privileges  
✅ No installation required  
✅ No prerequisites needed  
✅ Works on any Windows 10/11 or Server 2016+

---

## Features

*   **Common Fixes**:
    *   Free up disk space (cleans Temp folders and Recycle Bin).
    *   Disable Sleep & Hibernate (optimizes power settings for servers/always-on PCs).
    *   Fix Network (Resets TCP/IP stack, Winsock, and flushes DNS).
    *   Run System File Checker (SFC).
    *   **DISM Repair Image** (Restores Windows image health).
    *   **Reset Windows Update** (Clears cache and restarts services).
    *   **Clear Print Spooler** (Fixes stuck print jobs).
    *   **Restart Explorer** (Quickly restarts the shell).
    *   **Sync System Time** (Forces time synchronization).
    *   **Run Microsoft Activation Scripts (MAS)** (Launches the MAS activator).
    *   **Download & Run SpaceMonger** (Downloads and runs the classic disk usage visualization tool).
*   **System Info**:
    *   Get System Specs (OS, RAM, Model, etc.).
    *   List Printers.
    *   List Installed Software.
*   **Network Tools**:
    *   Show IP Configuration.
    *   Quick Network Scan (ARP table).
    *   Test Internet Connection (Ping).
*   **Security Audit / Max Audit**:
    *   Generates a professional HIPAA-oriented HTML report for monthly MSP auditing.
    *   Detects NinjaRMM, Huntress, GoToAssist, common remote access tools, backup products, BitLocker, drive usage, Windows Update status, event-log issues, shares, printers, RDP posture, scheduled tasks, Windows/PowerShell versions, and support lifecycle risk.
    *   Includes a formatted copy button designed for pasting report content into Freshdesk or Ninja ticket notes over a remote session.

## Troubleshooting

If you encounter issues (e.g., API connection failures), the tool now generates a debug log.
*   **Log Location**: `%TEMP%\WinFix_Debug.log`
*   **View Log**: Click the **"Open Log"** button in the bottom-right corner of the tool to view the log file instantly.

## Quick Start (One-Line Install)

**Paste this into PowerShell (automatically requests admin):**

```powershell
irm https://raw.githubusercontent.com/jeremydbean/winfix/main/install.ps1 | iex
```

This will:
1. Request Administrator privileges automatically
2. Download `WinFixTool.ps1` to a temp directory
3. Launch the GUI immediately
4. Clean up temporary files when closed

**That's it!** No installation, no prerequisites, just paste and run.

## Manual Build & Run

1.  Clone or download this repository.
2.  Double-click **`Build_and_Run.bat`**.
3.  Accept the Administrator prompt (required to install the compiler module).
4.  Wait for the process to finish.
5.  The tool will launch automatically, and you will find `WinFixTool.exe` in the folder, ready to be uploaded to Google Drive.

## How to Run (PowerShell)

**Method 1: Right-Click (Easiest)**
1.  Right-click `WinFixTool.ps1`.
2.  Select **Run with PowerShell**.
3.  If prompted for Administrator privileges, click **Yes**.

**Method 2: Terminal**
Open PowerShell as Administrator, navigate to the folder, and run:
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
.\WinFixTool.ps1
```

**Note on SpaceMonger**:
The "Download & Run SpaceMonger" feature requires an active internet connection to fetch the executable from GitHub if it is not already present in your Temp folder.

## How to Create a Standalone EXE

To distribute this tool as a single `.exe` file (e.g., via Google Drive), you can compile the PowerShell script using the popular `PS2EXE` module.

### Step 1: Install PS2EXE
Open PowerShell as Administrator and run:
```powershell
Install-Module -Name ps2exe -Scope CurrentUser
```

### Step 2: Compile the Script
Run the following command to create the EXE:

```powershell
Invoke-PS2EXE -InputFile ".\WinFixTool.ps1" -OutputFile ".\WinFixTool.exe" -Icon "" -Title "WinFix Tool" -Version "1.0" -noConsole
```

*   `-noConsole`: Hides the background console window so only the GUI appears.
*   You can add a custom icon by providing a path to an `.ico` file with the `-Icon` parameter.

### Step 3: Distribute
You can now upload `WinFixTool.exe` to Google Drive or a USB drive. It will run on any modern Windows machine without needing to install scripts or modules.

## Requirements
*   Windows 10, Windows 11, or Windows Server 2012+.
*   Windows PowerShell 5.1 preferred; the audit engine keeps compatibility fallbacks for older Server builds.
*   **Administrator Privileges** are required for most fixes.

## Collect audit evidence for a polished report

Run the standalone `Export-WinFixAudit.ps1` on the Windows computer in
**64-bit Windows PowerShell 4.0 or later as Administrator** (5.1 preferred). It does not launch the WinFix GUI.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Export-WinFixAudit.ps1 -CopyToClipboard
```

Optional labels and output location:

```powershell
.\Export-WinFixAudit.ps1 -ClientName "Example Clinic" -Location "Main office" -OutputDirectory C:\Temp\WinFixAudit
```

Results go into `Desktop\WinFixAudit` by default. The complete `*-PASTE.txt` file
opens automatically in Notepad when collection finishes. Press Ctrl+A, Ctrl+C to
copy it. Use `-NoOpen` for unattended runs. Paste the `*-PASTE.txt`
contents into your conversation. For a large audit, send the numbered `*-PART-*.txt`
files in order. The JSON file contains the same evidence in compact format for PowerShell 4 compatibility.
Ask for an executive summary, prioritized findings, remediation plan and a polished
HTML or PDF report. The collector includes this request in its paste output.

Collection covers hardware/OS, installed software, management/security/backup
services, Defender/antivirus, firewall, BitLocker, TPM, Secure Boot, accounts,
password/audit policy, disks, RDP, networking, SMB shares and permissions,
printers, non-Microsoft scheduled tasks, update history, cached missing updates,
reboot indicators, time service and recent event metadata. Cached update checks
have a 60-second timeout. A separate live scan contacts the configured Windows
Update service with a 90-second timeout; use `-SkipOnlineUpdateScan` to stay offline.
Neither scan installs updates. Every other check runs
in its own background job with a default 25-second timeout. The ISE progress display
shows the active check. Timed-out checks are marked `TimedOut`; failures with some
returned evidence are marked `Partial`; unsupported or denied checks are marked
`Unavailable`. Collection continues, and completed checks are saved after every
step in a `*-PARTIAL.json` checkpoint. The checkpoint is removed after final output
is written successfully. It remains usable if you stop the script early.

For ISE: open a new script tab, paste the entire script into the upper pane, and
press F5. No saved script path is required. Use 64-bit ISE as Administrator.
If the Desktop path is absent, output defaults to the temporary folder.

Expanded backup evidence includes installed products and services, backup scheduled
tasks (including Microsoft tasks) with last/next run and result codes, Windows
Server Backup summary/policy/schedule/targets/inclusions, the latest 20 local catalog
versions, a `wbadmin get versions` fallback, VSS writer output, shadow copies and
shadow storage. Registered backup event channels are discovered locally; up to 12
are queried separately, with any omitted channels listed in the report. The
Application log is also sampled for backup providers. VSS/storage warnings,
database errors, volume capacity, and PSChiro directory presence add local evidence.
No vendor console authentication or remote repository browsing is attempted.

Event queries first read up to 1,000 newest records per log, then apply lookback,
provider and severity filters. Each result records the scan limit, oldest scanned
time and output truncation. This trades exhaustive history for bounded work on
large logs; zero matches never establishes a clean 30-day history. Change the
`$EventScanLimit` and `$CheckTimeoutSeconds` defaults at the top when pasting into
ISE, or pass `-EventScanLimit 5000 -CheckTimeoutSeconds 45` when running a saved file.

Windows backup implementation references: [Get-WBSummary](https://learn.microsoft.com/en-us/powershell/module/windowsserverbackup/get-wbsummary),
[Get-WBPolicy](https://learn.microsoft.com/en-us/powershell/module/windowsserverbackup/get-wbpolicy),
and [Get-WBBackupSet](https://learn.microsoft.com/en-us/powershell/module/windowsserverbackup/get-wbbackupset).

This is local evidence collection, not a compliance certification. Backup restore
success, vendor-console health, MFA, public exposure and OS lifecycle entitlements
need separate verification. Samples and coverage limits are recorded in the JSON.
No configuration repairs or uploads are performed. A temporary security policy
export is normally removed after collection (forced cancellation may leave its temporary file). Review machine/domain names, account names,
network addresses and paths before sharing. Passwords, BitLocker recovery keys,
task action arguments are not intentionally collected. Backup/VSS warning and error
messages are included (at most 2,000 characters each) with best-effort labelled-secret
scrubbing; review these for filenames, account names and other sensitive text.

Developer check (also runs on non-Windows PowerShell):
`pwsh -NoProfile -File tests/Test-AuditExport.ps1`. Live collection requires Windows;
tests cover syntax, real background-job timeout/continuation, partial/scalar results, checkpoint persistence, job cleanup, event sampling and paste reassembly. They do not validate Windows providers or permissions.


### Fill the remaining report evidence gaps (collector 1.3)

The collector now reads custom share-root NTFS permissions (including inheritance
and per-share access errors), selected Entra device-registration fields, candidate
remote-access firewall allow rules from ActiveStore, local NAT mappings, default
routes, time-service settings, event-forwarding policy and current missing updates.
Backup and VSS error-message excerpts are included for troubleshooting. Share-root
ACLs do not evaluate child-folder overrides or effective access; local firewall and
NAT data do not establish internet reachability. Device registration does not prove
MFA enforcement. The default live update scan may refresh the local update cache.

Backup console results, retention, destination encryption, independent copies,
restore-test outcomes, MFA policy coverage, perimeter exposure, RMM/EDR console
health, central retention and support entitlement cannot be confirmed solely by a
local Windows script. No credentials or vendor API access were supplied, and the
collector does not guess these controls from agent presence. Each run writes an
`*-EVIDENCE-TEMPLATE.json` with the exact remaining fields and instructions. Fill it
from the relevant console or performed test, preserving the computer name; leave
anything unknown as `Unknown`. A `Reported` or `NotApplicable` entry requires its
source, observation timestamp (ISO 8601 with timezone), observer and details.

Import the completed template on the next run:

```powershell
.\Export-WinFixAudit.ps1 -EvidenceFile 'C:\Temp\Completed-Evidence.json'
```

When pasting into ISE, set the `$EvidenceFile` parameter default at the top instead.
Supplied evidence appears in the paste output as `UserSuppliedNotIndependentlyVerified`;
unknown fields stay unknown. The script does not run a restore, authenticate to
vendor consoles, scrape private agent databases or scan external networks.

References: [Entra device-state fields](https://learn.microsoft.com/en-us/entra/identity/devices/troubleshoot-device-dsregcmd),
[Windows firewall policy](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule).


### Windows Server 2012 R2 / TLS download errors

Collector 1.4 targets the PowerShell 4.0 included with Server 2012 R2 as well as
newer Windows PowerShell. Local user and built-in Administrators membership queries
fall back to CIM when the LocalAccounts module is absent. The fallback leaves
unavailable account timestamps null and uses a separate boolean for password
expiration policy. Clipboard copying falls back to Windows Forms in an STA session
such as ISE; Notepad and the saved files remain available if clipboard copying fails.
A RuntimeCapabilities check records missing optional commands. Unsupported OS
features are recorded as Unavailable, not as a passing or failed security control.

Open **64-bit PowerShell ISE as Administrator**, paste this entire block into the
script pane, and press F5. Use the plain URL exactly as shown, without Markdown
`[url](url)` syntax. TLS selection applies only to this process and is restored.

```powershell
& {
    $previousTls = [Net.ServicePointManager]::SecurityProtocol
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $auditUrl = 'https://raw.githubusercontent.com/jeremydbean/winfix/main/Export-WinFixAudit.ps1'
        $auditScript = Invoke-RestMethod -Uri $auditUrl -TimeoutSec 60 -ErrorAction Stop
        & ([scriptblock]::Create([string]$auditScript)) -CopyToClipboard
    } finally {
        [Net.ServicePointManager]::SecurityProtocol = $previousTls
    }
}
```

`Start-WinFixAudit.ps1` is a reusable launcher with the same TLS handling plus
error guidance and optional `-SkipOnlineUpdateScan` / `-EvidenceFile` parameters.
If TLS still fails, download `Export-WinFixAudit.ps1` on a working computer and
transfer it to the server, then paste its contents into ISE or run the saved file.
Investigate the server's cipher/TLS settings, certificate trust, clock and proxy;
the launcher does not weaken certificate checks, alter the registry, or install WMF.

Validation includes mocked legacy-provider and clipboard branches plus launcher
TLS selection, option forwarding and failed-download behavior. A real Server 2012
R2 / PowerShell 4.0 run has not yet been verified in this development environment.

References: [Microsoft WMF/OS version table](https://learn.microsoft.com/en-us/powershell/scripting/windows-powershell/wmf-overview),
[Microsoft TLS 1.2 session configuration](https://devblogs.microsoft.com/powershell/powershell-gallery-tls-support/),
[Win32_UserAccount fields](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-useraccount).


### PowerShell 4 JSON export fix (collector 1.5)

PowerShell 4 can report `JsonStringInBadFormat` when its JSON formatter encounters
strings ending in a backslash, such as a share path of `C:\`. All exports now use
one compact JSON serializer, including checkpoints, evidence templates and final
reports. No trailing slashes or other evidence values are stripped to avoid the
error. Compact JSON changes whitespace, not the data.

A failed checkpoint now logs a warning and leaves collection running with the
results in memory. The previous successful checkpoint is retained and export
warnings appear in the final report. Final output still requires a writable output
folder. Regression tests cover trailing-slash/quoted paths, Unicode, JSON parse-back,
paste-part reassembly, simulated legacy formatter failure and checkpoint recovery.
The exact native PowerShell 4 behavior still needs confirmation on the server.

Reference: [PowerShell 4 compact JSON workaround reported by env-exporter](https://github.com/ForNeVeR/env-exporter/issues/3).

### Hyper-V backup evidence (collector 1.6)

The collector inventories local registered VMs, including stopped VMs, and records
VM IDs, configuration paths, checkpoint settings, attached disk paths, available
local VHD metadata (including the immediate parent), integration-service status,
and up to 50 checkpoints per VM. Each VM's disk, integration and checkpoint query
has its own timeout; a blocked query does not stop the other VMs. By default the
first 50 VMs are inspected; `-MaxHyperVVMs` raises that limit up to 500, and omitted
VM names/IDs are listed. Large hosts can take longer because each VM adds checks.
Non-local VHD paths are recorded without opening a network repository; VHD metadata
errors preserve the disk attachment. Parent chains are not traversed.

Hyper-V replication state and three Admin event channels (VMMS, Worker and
Integration) add bounded local evidence and scrubbed message excerpts. Empty or
unavailable results, checkpoint presence, healthy integration services and replica
health never establish vendor backup success. Older Hyper-V versions may lack
newer properties; those remain null. Server 2012 R2 / PowerShell 4 remains targeted.

The external evidence template now also requests `HyperVBackupCoverage` and
`HyperVRestoreTest`: map every VM to a Synology/vendor task and usable recovery
point, confirm disks and application consistency, and record an isolated restore
and application test. Existing 12-control evidence files remain accepted; omitted
new controls stay Unknown. This is local-host collection only: it does not query
guest operating systems, other cluster nodes, or authenticate to the Synology NAS.

### Redirected Desktop export fix (collector 1.7)

Output folders now resolve to native filesystem paths before .NET file writes.
This fixes checkpoint and final-export failures when a redirected Desktop resolves
to `Microsoft.PowerShell.Core\FileSystem::\\server\share\...`. A temporary write
probe checks the destination before inventory starts, so an inaccessible output
folder fails early with an actionable error. Local folders, UNC shares and
filesystem PSDrives remain supported; other providers are rejected.

If a redirected Desktop is unavailable, select a writable local folder explicitly:

```powershell
.\Export-WinFixAudit.ps1 -OutputDirectory "$env:TEMP\WinFixAudit" -CopyToClipboard
```

The regression suite exercises provider-qualified paths, filesystem PSDrives,
literal bracket characters, real checkpoint/final writes and early failure. A
live Windows redirected UNC share still requires verification on that host.

### Veeam log evidence (collector 1.8)

Detected Veeam installations now add local text-log excerpts alongside Windows
event evidence. Queried Veeam event channels include rendered messages and up to
24 EventData fields (500 characters each), so useful job names and error details
can survive missing message-rendering resources. A separate warning/error sample
keeps informational events from consuming the result limit. Veeam providers in
the Application log also include messages and EventData. Event reads retain the
existing scan, output and timeout limits; an empty sample is not proof of success.

The collector reads the configured `LogDirectory` from the Veeam Backup &
Replication registry key, falling back to `C:\ProgramData\Veeam\Backup`.
See [Veeam's log-location documentation](https://www.veeam.com/kb1832).
For another local folder, pass `-VeeamLogDirectory 'D:\VeeamLogs'`; this also
enables collection when installed-product detection misses Veeam.

Discovery inspects at most 2,000 filesystem entries in the root and two directory
levels beneath it, then selects the 10 most recently modified `.log` files found
within the audit lookback. `-MaxVeeamLogFiles 20` raises the file count (maximum 30).
Each file contributes at most a 128 KiB tail and the last 40 keyword-matching lines,
capped at 1,000 characters per line. UTF-8 and BOM-marked UTF-16 are supported.
Files may remain open by Veeam; read failures are recorded per file. Discovery has
the normal check timeout, and the file-reading check has a 60-second timeout that
preserves already returned file results. Network folders, reparse points and
compressed archives are excluded.

`VeeamLogDiscovery` records discovery limits, omissions and access errors;
`VeeamFileLogDetails` records byte/line truncation and raw warning, error and
completion excerpts. Individual line timestamps are not parsed, so excerpts may
predate the lookback even when the file was recently modified. Excerpts are not
verified job results, complete history, per-VM protection or restore-test evidence.
Labelled secrets, bearer tokens and URL credentials are scrubbed best-effort;
review the paste output before sharing. Collection does not run backup jobs or
connect to Veeam servers or repositories.

Regression checks cover sparse errors, missing messages, XML failures, redaction,
bounded discovery, large UTF-8 logs, UTF-16 logs, missing files and background-worker
serialization. Server 2012 R2 / PowerShell 4 remains targeted; live Veeam validation
must be performed on a Windows host.

### Synology Drive Client and scheduled backups (collector 1.9)

**Synology Drive Client file backups, Drive sync tasks, and Active Backup for
Business are separate evidence sources.** Drive Client is now included in backup
software detection. Its data may belong to a different Windows user from the
administrator running ISE, so `SynologyDriveInventory` checks the current user's
`%LOCALAPPDATA%\SynologyDrive` and up to 20 non-system local profiles. It also
records Drive process names/paths without command lines. Profile inventory errors,
inaccessible roots and limits are explicit; no offline user hives are loaded.

`SynologyDriveDiscovery` scans at most 2,000 entries across those roots, to three
levels below each root. It skips reparse points, network paths, application files,
cache folders and the `SystemFolders` payload. It locates text logs (including
`.log.1` rotations), small JSON/INI/config files and database metadata. Discovery
keeps at most the configured file count per kind per root and reports omissions.
`SynologyDriveDetails` then reads, globally:

- The 10 newest discovered logs modified within the lookback: up to 128 KiB and
  30 matching lines each, 1,000 characters per line. Increase with
  `-MaxSynologyDriveLogFiles 20` (maximum 30). UTF-8 and BOM-marked UTF-16 work.
  Backup/sync outcomes, errors, conflicts, schedule and destination clues are
  preserved as raw evidence; sensitive labelled lines are omitted.
- Up to six settings files, 256 KiB each: only allowlisted connection/task fields
  such as server, local sources, destination, mode, schedule, SSL and status/time
  fields when present. Passwords, tokens, usernames, proxy credentials, arbitrary
  nested data and raw configuration are not exported. Arrays/depth/field counts
  are capped. Unknown formats and read failures remain explicit.
- Metadata for up to eight database files. SQLite/proprietary database contents
  are **not decoded**, and no drivers are installed. The Drive UI may hold task
  details that text files cannot expose. Deployment settings may also be stale.

For a different local data folder, use
`-SynologyDriveDirectory 'D:\DriveClientData'` on `Export-WinFixAudit.ps1`.
Discovery uses the standard per-check timeout; detail reads have a 60-second
limit. Each returned file result survives a later timeout. No NAS connection,
backup execution, file restoration or client configuration changes are performed.
Synology documents the log location in its
[Drive troubleshooting guide](https://kb.synology.com/en-global/DSM/tutorial/Why_are_files_not_synced_between_Synology_Drive_and_Drive_desktop_application)
and task configuration fields in its
[deployment guide](https://global.download.synology.com/download/Document/Software/UserGuide/Package/SynologyDrive/All/enu/Synology_Drive_Client_Mass_Deployment_Guide_enu.pdf).

`BackupTasks` streams candidate records (`RecordType=Task`) as they complete,
followed by a `RecordType=Coverage` summary with explicit scan/output limits.
Completed candidates survive a later worker timeout. It examines up to 500
scheduled tasks, including Microsoft and disabled tasks, and returns up to 100
candidates. Matching includes task names/paths, executables and arguments:
backup vendors, copy/archive/database-export tools, and generic PowerShell,
batch, scripting or command wrappers that need review. It records run identity,
last/next run, task result, missed runs, selected task settings and up to eight
actions/triggers per task. Trigger types, start boundaries, daily/weekly intervals
and repetition values are preserved where available.

For literal local script references, it reads at most 20 scripts in total, two
references per action, and 64 KiB per script. Only fixed backup-related keyword
indicators are exported: **scripts never run, and neither script content nor
command-line arguments are exported**. Network/reparse paths are skipped. Task
info failures are recorded per candidate. Nested scripts, COM executors, encoded
commands and unfamiliar tools can still require manual review. A keyword in a
comment is only a clue; task result 0, a file copy, sync completion or a disabled
historical task does not establish successful protection.

Use `BackupLastSuccess` and `BackupProtectedScope` in the generated evidence
template to record the Drive **Backup Task** screen's last completion (with
timezone), next run, server, mode, schedule, destination and selected sources.
Verify restore usability, retention, encryption, independent copies and a separate
machine-recovery plan. The collector never upgrades a generic sync/file success
into a whole-backup success. Review all output before sharing: paths and log
excerpts can contain business information, and text redaction is best-effort.

Regression fixtures exercise Drive discovery/rotation, secret omission, settings
allowlists/read limits, worker serialization, task wrappers, script inspection,
disabled tasks, trigger/run-account evidence and provider errors. Windows ISE and
Server 2012 R2 / PowerShell 4 remain targeted; live vendor validation still needs a
Windows host and real client/task data.
