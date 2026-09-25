$ErrorActionPreference = 'Stop'
$path = Join-Path (Split-Path $PSScriptRoot) 'Export-WinFixAudit.ps1'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors -join "`n") }
# Load pure helpers without running Windows inventory on the test host.
$ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst]}, $false) |
    ForEach-Object { . ([scriptblock]::Create($_.Extent.Text)) }
$failed = Invoke-AuditCheck 'Denied' { throw 'Access denied' }
if ($failed.Status -ne 'Unavailable' -or $failed.Count -ne 0 -or $failed.Error -ne 'Access denied') { throw 'Failure was not preserved.' }
$empty = Invoke-AuditCheck 'Empty' { @() }
if ($empty.Status -ne 'Collected' -or $empty.Count -ne 0) { throw 'Empty results were confused with failure.' }
$single = Invoke-AuditCheck 'Single' { [pscustomobject]@{Enabled=$false} }
if ($single.Count -ne 1 -or $single.Data[0].Enabled -ne $false) { throw 'False evidence was lost.' }
$json = @{Name='Test'; Content=('Example "text" with newlines' + "`n") * 1000} | ConvertTo-Json -Compress
$blocks = @(New-PasteBlocks -Json $json -Size 4000 -Id 'test')
$reassembled = ($blocks | ForEach-Object { ($_ -split "`r`n")[1] }) -join ''
if ($reassembled -cne $json) { throw 'Paste parts did not round-trip exactly.' }
$parsed = $reassembled | ConvertFrom-Json
if ($parsed.Name -ne 'Test') { throw 'Reassembled JSON is invalid.' }
Write-Host "PASS: syntax, failure/empty/false evidence handling, and $($blocks.Count)-part JSON round-trip."

$script:checks = [ordered]@{}
$script:auditId = 'regression-test'
$script:checkpointPath = Join-Path ([IO.Path]::GetTempPath()) ("WinFix-test-" + [guid]::NewGuid().ToString('N') + '.json')
$beforeJobs = @(Get-Job).Count
try {
    $scalar = Invoke-AuditCheck 'Scalar' { 'native command text'; 42; $false }
    if ($scalar.Data[0] -cne 'native command text' -or $scalar.Data[1] -ne 42 -or $scalar.Data[2] -ne $false) { throw 'Scalar evidence changed during job serialization.' }
    $partial = Invoke-AuditCheck 'Partial' { [pscustomobject]@{Name='first'}; throw 'Later provider failure' }
    if ($partial.Status -ne 'Partial' -or $partial.Count -ne 1 -or $partial.Error -notlike '*Later provider failure*') { throw 'Partial evidence lost or misclassified.' }
    $slow = Invoke-AuditCheck 'SlowBackup' -TimeoutSeconds 2 -Collect { Start-Sleep -Seconds 30 }
    if ($slow.Status -ne 'TimedOut' -or $slow.DurationSeconds -gt 15) { throw 'Slow provider was not stopped promptly.' }
    $after = Invoke-AuditCheck 'AfterTimeout' -Context @{Example='continued'} -Collect { [pscustomobject]@{Value=$Example} }
    if ($after.Status -ne 'Collected' -or $after.Data[0].Value -ne 'continued') { throw 'Collection did not continue with explicit context.' }
    $saved = Get-Content -LiteralPath $script:checkpointPath -Raw | ConvertFrom-Json
    if (-not $saved.Incomplete -or $saved.Checks.SlowBackup.Status -ne 'TimedOut' -or $saved.Checks.AfterTimeout.Status -ne 'Collected') { throw 'Checkpoint missing completed checks.' }
    if (@(Get-Job).Count -ne $beforeJobs) { throw 'Worker jobs were leaked.' }
} finally {
    Remove-Item -LiteralPath $script:checkpointPath -ErrorAction SilentlyContinue
    $script:checkpointPath = $null
}
# Exercise sampling without Windows APIs; enforce that the collector bounds the
# initial read, then applies lookback/provider/severity filters and output caps.
$EventScanLimit = 4; $MaxEvents = 1; $since = (Get-Date).AddDays(-30)
function Get-WinEvent {
    [CmdletBinding()]param([string]$ListLog, [string]$LogName, [int]$MaxEvents)
    if ($ListLog -eq 'Denied') { throw 'Access denied' }
    if ($ListLog) { [pscustomobject]@{IsEnabled=($ListLog -ne 'Disabled'); RecordCount=10000}; return }
    if ($MaxEvents -ne 4) { throw 'Initial event scan was not bounded.' }
    foreach ($i in 1..4) {
        [pscustomobject]@{ TimeCreated=(Get-Date).AddDays(-$i); Id=$i; RecordId=(10000-$i)
            ProviderName='Veeam'; Level=2; LevelDisplayName='Error'; LogName=$LogName }
    }
}
$events = Get-AuditEvents -LogName Application -Levels 2 -ProviderPattern Veeam
if ($events.RecordsScanned -ne 4 -or -not $events.ScanLimitReached -or -not $events.OutputTruncated -or $events.Events.Count -ne 1 -or $events.MatchedInSample -ne 4) { throw 'Event sampling limits are incorrect.' }
$empty = Get-AuditEvents -LogName Application -ProviderPattern 'Unmatched'
if ($empty.Events.Count -ne 0 -or -not $empty.ScanLimitReached) { throw 'Empty sample lost coverage limits.' }
$disabled = Get-AuditEvents -LogName Disabled
if ($disabled.Enabled -or $disabled.RecordsScanned -ne 0) { throw 'Disabled log was queried.' }
try { $null = Get-AuditEvents -LogName Denied; throw 'Denied log incorrectly succeeded' }
catch { if ($_.Exception.Message -ne 'Access denied') { throw } }
Remove-Item Function:Get-WinEvent
Write-Host 'PASS: real worker timeout, continuation, scalar/partial evidence, checkpoint persistence, job cleanup and bounded event sampling.'

# Regression: the vendor name Cove must not match Discovery or Recovery.
$patternAssignment = $ast.Find({param($n)
    $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$BackupPattern'
}, $true)
$pattern = $patternAssignment.Right.Find({param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst]}, $true).Value
foreach ($name in @('Discovery Provider Host','SSDP Discovery','Dell Recovery Plugin','OobeDiscovery')) {
    if ($name -match $pattern) { throw "False backup vendor match: $name" }
}
foreach ($name in @('Cove Data Protection','Synology Active Backup for Business','Veeam Agent','Acronis','Macrium Reflect')) {
    if ($name -notmatch $pattern) { throw "Missed backup vendor: $name" }
}
# Run the actual shadow-storage collector with a fake nested CIM reference.
$shadowAssignment = $ast.Find({param($n)
    $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$checks.ShadowStorage'
}, $true)
$shadowBlock = $shadowAssignment.Find({param($n) $n -is [System.Management.Automation.Language.ScriptBlockExpressionAst]}, $true)
function Get-CimInstance {
    param($ClassName)
    [pscustomobject]@{ Volume=[pscustomobject]@{DeviceID='volume-one';Metadata=('noise'*1000)}
        DiffVolume=[pscustomobject]@{DeviceID='volume-two';Metadata=('noise'*1000)}
        UsedSpace=123; AllocatedSpace=456; MaxSpace=789 }
}
$shadow = & ([scriptblock]::Create($shadowBlock.ScriptBlock.Extent.Text.Trim('{}')))
$shadowJson = $shadow | ConvertTo-Json -Depth 12
if ($shadow.Volume -ne 'volume-one' -or $shadow.DiffVolume -ne 'volume-two' -or $shadowJson.Length -gt 300 -or $shadow.UsedSpace -ne 123) { throw 'Shadow storage lost facts or exported nested metadata.' }
Remove-Item Function:Get-CimInstance
Write-Host 'PASS: backup vendor boundaries and compact shadow-storage evidence.'

$template = New-ExternalEvidenceTemplate -ComputerName 'TESTHOST'
$unknown = @(Read-ExternalEvidence -Path '' -Template $template)
if ($unknown.Count -ne 12 -or @($unknown | Where-Object Status -ne 'Unknown').Count) { throw 'Missing external evidence was not kept unknown.' }
$evidenceTestPath = Join-Path ([IO.Path]::GetTempPath()) ('WinFix-evidence-' + [guid]::NewGuid().ToString('N') + '.json')
try {
    $template.Controls[0].Status='Reported'
    $template.Controls[0].Source='Synology task history'
    $template.Controls[0].ObservedAt='2026-09-25T15:00:00-04:00'
    $template.Controls[0].ObservedBy='Test operator'
    $template.Controls[0].Details='Last successful job and protected volumes reviewed.'
    $template | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $evidenceTestPath
    $supplied = @(Read-ExternalEvidence -Path $evidenceTestPath -Template $template)
    if ($supplied[0].Status -ne 'Reported' -or $supplied[0].Origin -ne 'UserSuppliedNotIndependentlyVerified') { throw 'Supplied evidence was incorrectly promoted to verified.' }
    # Also exercise deserialization and helper injection in the real worker.
    $check = Invoke-AuditCheck 'ExternalEvidenceTest' -Context @{
        EvidencePath=$evidenceTestPath; Template=$template; ReaderCode=${function:Read-ExternalEvidence}.ToString()
    } -Collect {
        Set-Item Function:Read-ExternalEvidence ([scriptblock]::Create($ReaderCode))
        Read-ExternalEvidence -Path $EvidencePath -Template $Template
    }
    if ($check.Status -ne 'Collected' -or $check.Count -ne 12) { throw 'External evidence did not survive the worker boundary.' }
    $template.ComputerName='WRONGHOST'
    $template | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $evidenceTestPath
    $expectedTemplate=New-ExternalEvidenceTemplate -ComputerName 'TESTHOST'
    try { $null=Read-ExternalEvidence -Path $evidenceTestPath -Template $expectedTemplate; throw 'Wrong host accepted' }
    catch { if ($_.Exception.Message -notlike '*does not match this host*') { throw } }
    $template.ComputerName='TESTHOST'; $template.Controls[0].Source=''
    $template | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $evidenceTestPath
    try { $null=Read-ExternalEvidence -Path $evidenceTestPath -Template $expectedTemplate; throw 'Missing provenance accepted' }
    catch { if ($_.Exception.Message -notlike '*requires Source*') { throw } }
} finally { Remove-Item -LiteralPath $evidenceTestPath -ErrorAction SilentlyContinue }

function Get-WinEvent {
    [CmdletBinding()]param([string]$ListLog,[string]$LogName,[int]$MaxEvents)
    if ($ListLog) { [pscustomobject]@{IsEnabled=$true;RecordCount=1}; return }
    [pscustomobject]@{TimeCreated=Get-Date;Id=4103;RecordId=77;ProviderName='Windows Backup';Level=2;LogName=$LogName
        Message='password="do not share" token=secretvalue https://user:pass@example.com '+('x'*2500)}
}
$details = Get-AuditEvents -LogName Application -IncludeMessage
if ($details.Events[0].Message.Length -gt 2000 -or -not $details.Events[0].MessageTruncated -or $details.Events[0].Message -match 'do not share|secretvalue|user:pass') { throw 'Event detail limit or labelled-secret scrub failed.' }
Remove-Item Function:Get-WinEvent

$aclAssignment=$ast.Find({param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$checks.ShareNTFSPermissions'},$true)
$aclBlock=$aclAssignment.Find({param($n) $n -is [System.Management.Automation.Language.ScriptBlockExpressionAst]},$true)
function Get-SmbShare { [pscustomobject]@{Name='Allowed';Path='C:\Data';Special=$false}; [pscustomobject]@{Name='Denied';Path='C:\Denied';Special=$false} }
function Get-Acl {
    [CmdletBinding()]param($LiteralPath)
    if ($LiteralPath -eq 'C:\Denied') { throw 'Access denied' }
    [pscustomobject]@{Owner='Administrators';AreAccessRulesProtected=$false;Access=@([pscustomobject]@{
        IdentityReference='Users';FileSystemRights='ReadAndExecute';AccessControlType='Allow';IsInherited=$true;InheritanceFlags='ContainerInherit';PropagationFlags='None'
    })}
}
$aclRows=@(& ([scriptblock]::Create($aclBlock.ScriptBlock.Extent.Text.Trim('{}'))))
if ($aclRows.Count -ne 2 -or $aclRows[0].Rules[0].Identity -ne 'Users' -or $aclRows[1].Status -ne 'Unavailable') { throw 'Share ACL evidence or per-share failure handling was lost.' }
Remove-Item Function:Get-SmbShare; Remove-Item Function:Get-Acl
Write-Host 'PASS: external-evidence provenance/host validation, worker import, bounded scrubbed event details and per-share NTFS evidence.'
