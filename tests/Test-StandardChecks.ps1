# Regression checks for collector 1.13/1.14 parsers (hardware vendor tools, Veeam job messages,
# powercfg values, backup-agent log lines)
# and the presence of the new monthly-maintenance checks. Runs without Windows providers.
$ErrorActionPreference = 'Stop'
$path = Join-Path (Split-Path $PSScriptRoot) 'Export-WinFixAudit.ps1'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors -join "`n") }
$ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst]}, $false) |
    ForEach-Object { . ([scriptblock]::Create($_.Extent.Text)) }

$chassis = @"
Health

Main System Chassis

SEVERITY : COMPONENT
Ok       : Fans
Critical : Intrusion
Non-Critical : Power Supplies
Ok       : Temperatures

For further help, type the command followed by -?
"@
$items = @(ConvertFrom-AuditOmReport $chassis)
if ($items.Count -ne 4) { throw "omreport chassis: expected 4 components, got $($items.Count)." }
if (($items | Where-Object Component -eq 'Power Supplies').Status -ne 'Non-Critical') { throw 'omreport chassis: Non-Critical status lost.' }
if ($items | Where-Object Component -eq 'COMPONENT') { throw 'omreport chassis: header parsed as a component.' }

$vdisk = @"
List of Virtual Disks in the System

Controller PERC H730P Mini (Embedded)
ID                                : 0
Status                            : Ok
Name                              : OS
State                             : Ready
Hot Spare Policy violated         : Not Assigned
Layout                            : RAID-1
Size                              : 278.88 GB (299439751168 bytes)

ID                                : 1
Status                            : Non-Critical
Name                              : Data
State                             : Degraded
Layout                            : RAID-5
Size                              : 5,587.00 GB (5998999999999 bytes)
"@
$disks = @(ConvertFrom-AuditOmVdisk $vdisk)
if ($disks.Count -ne 2 -or $disks[1].State -ne 'Degraded' -or $disks[1].Layout -ne 'RAID-5' -or $disks[0].Status -ne 'Ok') { throw 'omreport vdisk blocks parsed incorrectly.' }

$ssa = @"
Smart Array P440ar in Slot 0 (Embedded)   (sn: PDNLH0BRH8B0YA)
   Controller Status: OK
   Cache Status: OK
   Battery/Capacitor Status: Failed

   Array A (SAS, Unused Space: 0  MB)
      logicaldrive 1 (558.88 GB, RAID 1, OK)
      physicaldrive 1I:1:1 (port 1I:box 1:bay 1, SAS HDD, 600 GB, OK)
      physicaldrive 1I:1:2 (port 1I:box 1:bay 2, SAS HDD, 600 GB, Predictive Failure)
"@
$rows = @(ConvertFrom-AuditSsacli $ssa)
if ($rows.Count -ne 6) { throw "ssacli: expected 6 rows, got $($rows.Count)." }
if (($rows | Where-Object Component -eq 'Battery/Capacitor Status').Status -ne 'Failed') { throw 'ssacli: battery status lost.' }
$bad = @($rows | Where-Object { $_.Component -like 'physicaldrive 1I:1:2*' })
if ($bad.Count -ne 1 -or $bad[0].Status -ne 'Predictive Failure' -or $bad[0].Controller -notlike 'Smart Array P440ar*') { throw 'ssacli: drive status or controller name lost.' }

$cases = @(
    @{ Text="Veeam Agent 'Backup Job DC01' finished with Success."; Job='Backup Job DC01'; Result='Success' },
    @{ Text="Backup job 'SQL01 nightly' finished with Warning. Job details: 1 warning"; Job='SQL01 nightly'; Result='Warning' },
    @{ Text="Job 'File server' finished with Failed."; Job='File server'; Result='Failed' }
)
foreach ($case in $cases) {
    $parsed = ConvertFrom-AuditVeeamJobMessage -Message $case.Text
    if (-not $parsed -or $parsed.Job -ne $case.Job -or $parsed.Result -ne $case.Result) { throw "Veeam message not parsed: $($case.Text)" }
}
if (ConvertFrom-AuditVeeamJobMessage -Message 'Job session started.') { throw 'Non-finish Veeam message produced a result.' }

$powercfg = @"
Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced)
  GUID Alias: SCHEME_BALANCED
  Subgroup GUID: 238c9fa8-0aad-41ed-83f4-97be242c8f20  (Sleep)
    GUID Alias: SUB_SLEEP
    Power Setting GUID: 29f6c1db-86da-48c5-9fdb-f2b67b1f44da  (Sleep after)
      GUID Alias: STANDBYIDLE
      Minimum Possible Setting: 0x00000000
      Maximum Possible Setting: 0xffffffff
      Possible Settings increment: 0x00000001
      Possible Settings units: Seconds
    Current AC Power Setting Index: 0x00000708
    Current DC Power Setting Index: 0x00000384
"@
$power = ConvertFrom-AuditPowerSetting $powercfg
if ($power.Ac -ne 1800 -or $power.Dc -ne 900) { throw "powercfg: expected AC 1800 / DC 900, got $($power.Ac) / $($power.Dc)." }
# Localized labels (German) must parse by position.
$power = ConvertFrom-AuditPowerSetting ($powercfg -replace 'Current AC Power Setting Index', 'Aktueller Wechselstrom-Energieeinstellungsindex' -replace 'Current DC Power Setting Index', 'Aktueller Gleichstrom-Energieeinstellungsindex')
if ($power.Ac -ne 1800) { throw 'powercfg: localized output not parsed by position.' }
$noBattery = ($powercfg -split "`n" | Where-Object { $_ -notmatch 'DC Power' }) -join "`n"
$power = ConvertFrom-AuditPowerSetting $noBattery
if ($power.Ac -ne 1800 -or $null -ne $power.Dc) { throw 'powercfg: AC value wrong when no DC value is listed.' }

$lineCases = @(
    @{ Text='2026-11-24 23:00:12 [INFO] Backup task [PC-FRONTDESK] completed successfully.'; Outcome='Success'; Day=24 },
    @{ Text='2026/11/25 01:10:00 [ERROR] Backup task failed: unable to connect to the server'; Outcome='Failure'; Day=25 },
    @{ Text='2026-11-23T08:00:00 Backup finished with 0 errors'; Outcome='Success'; Day=23 },
    @{ Text='Backup partially completed'; Outcome='Failure'; Day=0 },
    @{ Text='2026-11-22 10:00 Connecting to NAS'; Outcome='Other'; Day=22 }
)
foreach ($case in $lineCases) {
    $r = ConvertFrom-AuditBackupLogLine $case.Text
    if ($r.Outcome -ne $case.Outcome) { throw "Log line outcome: expected $($case.Outcome), got $($r.Outcome): $($case.Text)" }
    if ($case.Day -and (-not $r.Time -or $r.Time.Day -ne $case.Day)) { throw "Log line time not parsed: $($case.Text)" }
    if (-not $case.Day -and $r.Time) { throw "Log line without a date produced a time: $($case.Text)" }
}

# Real Synology Active Backup for Business agent lines (agent 3.1.2, Windows Server 2012 R2, PowerShell 4).
$fileTime = [datetime]'2026-11-25 15:30'
$abbCases = @(
    @{ Text="Nov 21 03:59:27 -0500 [INFO] backup-job.cpp (1418): in backup routine, has_fail_volume '0', miss_custome_volume '0', system_volume_excluded '0'"; Kind='Success'; Day=21 },
    @{ Text="Nov 21 03:00:09 -0500 [INFO] backup-job.cpp (995): Prepare snapshot job"; Kind='Start'; Day=21 },
    @{ Text="Nov 14 03:48:47 -0500 [INFO] backup-job.cpp (1418): in backup routine, has_fail_volume '1', miss_custome_volume '0', system_volume_excluded '0'"; Kind='FailedVolumes'; Day=14 },
    @{ Text="Nov 20 15:17:53 -0500 [ERROR] protocol-client.cpp (195): Failed to receive message header. (code: -2)"; Kind='ConnectionError'; Day=20 },
    @{ Text="Dec 30 23:00:00 -0500 [INFO] backup-job.cpp (1418): in backup routine, has_fail_volume '0'"; Kind='Success'; Day=30; Year=2025 }
)
foreach ($case in $abbCases) {
    $r = ConvertFrom-AuditAbbLogLine -Text $case.Text -FileTime $fileTime
    if (-not $r -or $r.Kind -ne $case.Kind -or $r.Time.Day -ne $case.Day) { throw "ABB line not parsed as $($case.Kind): $($case.Text)" }
    if ($case.Year -and $r.Time.Year -ne $case.Year) { throw 'ABB line from last December must get the previous year.' }
}
$noise = 'Nov 23 17:03:13 -0500 [INFO] auth-handler.cpp (550): send request ''{"_agent": {"version": {"build": "5059", "major": 3, "mini": 1, "minor": 2}}, "action": "success"}'''
if (ConvertFrom-AuditAbbLogLine -Text $noise -FileTime $fileTime) { throw 'Status-ping lines must not count as backup results.' }

foreach ($name in @('DefenderThreats', 'BackupJobResults', 'AgentActivity', 'CertificateExpiry', 'Activation', 'LAPS', 'SecurityHardening',
        'KeyServices', 'HardwareVendorHealth', 'HardwareEvents', 'ADHygiene', 'DCDiag', 'ReplicationSummary', 'ExternalExposure',
        'ClientPlatform', 'SynologyActiveBackup', 'VeeamServerJobs', 'OneDriveActivity', 'ServerRoles')) {
    $assignment = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq ('$checks.' + $name) }, $true)
    if (-not $assignment) { throw "Check $name is missing." }
    if ($assignment.Right.Extent.Text -notmatch '^Invoke-AuditCheck') { throw "Check $name must run through Invoke-AuditCheck." }
}
$exposure = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.IfStatementAst] -and $n.Clauses[0].Item1.Extent.Text -eq '$ExternalExposureCheck' }, $true)
if (-not $exposure) { throw 'ExternalExposure must stay behind the opt-in -ExternalExposureCheck switch.' }
$veeam = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.IfStatementAst] -and $n.Clauses[0].Item1.Extent.Text -match 'Veeam Backup and Replication' }, $true)
if (-not $veeam -or $veeam.Clauses[0].Item2.Extent.Text -notmatch 'VeeamServerJobs') { throw 'VeeamServerJobs must only run when Backup & Replication is installed.' }
$client = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$checks.ClientPlatform' }, $true)
if ($client.Extent.Text -match "Get-ItemProperty[^
]*'DefaultPassword'") { throw 'ClientPlatform must not read the auto sign-in password value.' }
Write-Host 'PASS: OpenManage/ssacli/Veeam/powercfg/log-line/Active Backup parsers and collector 1.13-1.15 check registration.'
