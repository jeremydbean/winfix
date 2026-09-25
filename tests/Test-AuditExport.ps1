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
