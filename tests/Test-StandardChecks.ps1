# Regression checks for collector 1.13 parsers (hardware vendor tools, Veeam job messages)
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

foreach ($name in @('DefenderThreats', 'BackupJobResults', 'AgentActivity', 'CertificateExpiry', 'Activation', 'LAPS', 'SecurityHardening',
        'KeyServices', 'HardwareVendorHealth', 'HardwareEvents', 'ADHygiene', 'DCDiag', 'ReplicationSummary', 'ExternalExposure')) {
    $assignment = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq ('$checks.' + $name) }, $true)
    if (-not $assignment) { throw "Check $name is missing." }
    if ($assignment.Right.Extent.Text -notmatch '^Invoke-AuditCheck') { throw "Check $name must run through Invoke-AuditCheck." }
}
$exposure = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.IfStatementAst] -and $n.Clauses[0].Item1.Extent.Text -eq '$ExternalExposureCheck' }, $true)
if (-not $exposure) { throw 'ExternalExposure must stay behind the opt-in -ExternalExposureCheck switch.' }
Write-Host 'PASS: OpenManage/ssacli/Veeam parsers and collector 1.13 check registration.'
