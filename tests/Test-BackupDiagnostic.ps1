$ErrorActionPreference='Stop'
$path=Join-Path (Split-Path $PSScriptRoot) 'Export-WinFixBackupDiagnostic.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw ($errors -join '; ') }
if ($ast.ScriptRequirements.RequiredPSVersion -ne [version]'4.0') { throw 'PS4 minimum declaration missing.' }
$ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$false) | ForEach-Object { . ([scriptblock]::Create($_.Extent.Text)) }
$before=[pscustomobject]@{Name='wbengine';ProcessId=42;CreationDate='2026-09-28T10:00:00';ReadTransferCount=100;WriteTransferCount=200;OtherTransferCount=$null}
$after=[pscustomobject]@{Name='wbengine';ProcessId=42;CreationDate='2026-09-28T10:00:00';ReadTransferCount=1124;WriteTransferCount=100;OtherTransferCount=4}
$d=Get-BackupCounterDelta -Before $before -After $after -Keys Name,ProcessId,CreationDate -Counters ReadTransferCount,WriteTransferCount,OtherTransferCount
if ($d.ReadTransferCountDelta -ne 1024 -or $null -ne $d.WriteTransferCountDelta -or $null -ne $d.OtherTransferCountDelta -or $d.UnavailableOrResetCounters.Count -ne 2) { throw 'Reset/missing counters misrepresented.' }
$after.CreationDate='2026-09-28T12:00:00'
$d=Get-BackupCounterDelta -Before $before -After $after -Keys Name,ProcessId,CreationDate -Counters ReadTransferCount
if ($d.MatchedEarlierSample -or $null -ne $d.ReadTransferCountDelta) { throw 'PID reuse was treated as the same process.' }
if (@(Get-BackupCounterDelta -Before @() -After @() -Keys Name -Counters SentBytes).Count) { throw 'Empty samples generated data.' }
$jobs=@(Get-Job).Count
$partial=Invoke-BackupDiagnosticSection -Name Partial -Collect { 'first result'; throw 'fixture denied' }
if ($partial -notmatch 'Partial' -or $partial -notmatch 'first result' -or $partial -notmatch 'fixture denied') { throw 'Partial output lost.' }
$timed=Invoke-BackupDiagnosticSection -Name Slow -TimeoutSeconds 2 -Collect { 'before timeout'; Start-Sleep 30 }
if ($timed -notmatch 'TimedOut' -or $timed -notmatch 'before timeout' -or @(Get-Job).Count -ne $jobs) { throw 'Worker timeout/cleanup failed.' }
# Actual subprocesses: normal/nonzero exits, continuous status output, independent stderr,
# output cap, and cleanup. No Windows backup commands run on the test host.
$exe=(Get-Process -Id $PID).Path
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('winfix-reader-'+[guid]::NewGuid().ToString('N')+'.ps1')
try {
    [IO.File]::WriteAllText($fixture,'[Console]::Out.WriteLine("progress 97%"); [Console]::Error.WriteLine("fixture stderr"); Start-Sleep 30')
    $timer=[Diagnostics.Stopwatch]::StartNew()
    $r=Invoke-BackupStatusReader -FilePath $exe -Arguments ('-NoLogo -NoProfile -File "'+$fixture+'"') -Seconds 2
    if (-not $r.ReaderTimeLimitReached -or -not $r.ReaderExited -or $r.StandardOutput -notmatch 'progress 97%' -or $r.StandardError -notmatch 'fixture stderr' -or $timer.Elapsed.TotalSeconds -gt 10) { throw 'Continuous reader timed capture failed.' }
    if (Get-Process -Id $r.ReaderProcessId -ErrorAction SilentlyContinue) { throw 'Reader process leaked.' }
    [IO.File]::WriteAllText($fixture,'[Console]::Out.WriteLine(("x"*18000)); exit 7')
    $r=Invoke-BackupStatusReader -FilePath $exe -Arguments ('-NoLogo -NoProfile -File "'+$fixture+'"') -Seconds 5
    if ($r.ReaderTimeLimitReached -or $r.ExitCode -ne 7 -or -not $r.OutputTruncated -or $r.StandardOutput.Length -ne 16000) { throw 'Native exit/cap failed.' }
    [IO.File]::WriteAllText($fixture,'[Console]::Out.WriteLine("running in worker"); Start-Sleep 30')
    $r=Invoke-BackupDiagnosticSection -Name NativeWorker -Context @{ReaderCode=${function:Invoke-BackupStatusReader}.ToString();Exe=$exe;Fixture=$fixture} -Collect {
        Set-Item Function:Invoke-BackupStatusReader ([scriptblock]::Create($ReaderCode))
        Invoke-BackupStatusReader -FilePath $Exe -Arguments ('-NoLogo -NoProfile -File "'+$Fixture+'"') -Seconds 2
    }
    if ($r -notmatch 'Collected' -or $r -notmatch 'running in worker' -or $r -notmatch '"ReaderTimeLimitReached":true') { throw 'Native collector serialization failed.' }
} finally { Remove-Item $fixture -ErrorAction SilentlyContinue }
function Get-WinEvent {
    [CmdletBinding()]param($ListLog,$FilterHashtable,$MaxEvents)
    if ($ListLog) { return [pscustomobject]@{IsEnabled=($ListLog -ne 'Disabled');RecordCount=3} }
    if ($MaxEvents -ne 3000 -or -not $FilterHashtable.StartTime -or [math]::Abs(((Get-Date)-$FilterHashtable.StartTime).TotalHours-12) -gt 0.1) { throw 'Event query not bounded by time/count.' }
    foreach ($id in 51,153,1) {
        $e=[pscustomobject]@{TimeCreated=Get-Date;Id=$id;RecordId=$id;ProviderName='disk';Level=3;LevelDisplayName='Warning';Message=('password=fixture-secret '+('x'*3200))}
        $e | Add-Member ScriptMethod ToXml { '<Event><EventData><Binary>A1B2</Binary></EventData></Event>' }
        $e
    }
}
try {
    $e=@(Get-BackupDiagnosticEvents -LogName System -ProviderPattern 'disk' -Limit 2)
    if ($e.Count -ne 3 -or -not $e[0].OutputTruncated -or $e[1].Event51Xml -notmatch 'A1B2' -or -not $e[1].MessageTruncated -or $e[1].Message -match 'fixture-secret') { throw 'Bounded events/redaction/XML failed.' }
    $e=@(Get-BackupDiagnosticEvents -LogName Disabled -ProviderPattern '.')
    if ($e.Count -ne 1 -or $e[0].Enabled) { throw 'Disabled event log misrepresented.' }
} finally { Remove-Item Function:Get-WinEvent }
$definition=$ast.Find({param($n) $n -is [Management.Automation.Language.StringConstantExpressionAst] -and $n.Value -like '*public static class WinFixBackupSpace*'},$true)
Add-Type -TypeDefinition $definition.Value
if (-not ('WinFixBackupSpace' -as [type])) { throw 'Capacity interop failed to compile.' }
# Exercise production sampling and delta logic through a serialized worker, including a
# provider failure. Avoid real waiting in this fixture; the parent verifies actual waits above.
$assignment=$ast.Find({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$sections.ActivitySamples'},$true)
$block=$assignment.Find({param($n) $n -is [Management.Automation.Language.ScriptBlockExpressionAst]},$true)
$sampleResult=Invoke-BackupDiagnosticSection -Name SampleFixture -Context @{SampleCode=${function:Get-BackupActivitySample}.ToString();DeltaCode=${function:Get-BackupCounterDelta}.ToString();SectionCode=$block.ScriptBlock.Extent.Text;NasHost='192.0.2.10';Interval=0} -Collect {
    Set-Item Function:Get-BackupActivitySample ([scriptblock]::Create($SampleCode))
    Set-Item Function:Get-BackupCounterDelta ([scriptblock]::Create($DeltaCode))
    $script:reads=100
    function Get-CimInstance {
        param($ClassName,$OperationTimeoutSec)
        switch ($ClassName) {
            Win32_Service { [pscustomobject]@{Name='wbengine';ProcessId=42;State='Running';StartName='LocalSystem'} }
            Win32_Process { $script:reads+=1024; [pscustomobject]@{Name='wbengine.exe';ProcessId=42;CreationDate=[datetime]'2026-09-28T10:00:00';ReadTransferCount=$script:reads;WriteTransferCount=0;KernelModeTime=100;UserModeTime=100} }
            default { throw 'disk performance unavailable fixture' }
        }
    }
    function Get-NetAdapterStatistics { [CmdletBinding()]param(); [pscustomobject]@{Name='Ethernet';InterfaceDescription='Fixture';SentBytes=$script:reads;ReceivedBytes=0} }
    function Get-NetTCPConnection { [CmdletBinding()]param($RemotePort); [pscustomobject]@{RemoteAddress='192.0.2.10';RemotePort=445;State='Established';OwningProcess=4} }
    # SectionCode includes braces when extracted via AST.
    & ([scriptblock]::Create($SectionCode.Trim().Substring(1,$SectionCode.Trim().Length-2)))
}
if ($sampleResult -notmatch 'Collected' -or $sampleResult -notmatch '"ReadTransferCountDelta":1024' -or $sampleResult -notmatch 'disk performance unavailable fixture' -or $sampleResult -notmatch '"Sample":2') { throw 'Production activity sampling failed.' }
Write-Host 'PASS: parser, counter resets/missing values/PID reuse, worker partial output and cleanup, native timeout/dual-pipe capture/exit/caps, event bounds/XML/redaction, interop compilation and production sampling fixture. Live Windows/NAS behavior requires a host run.'
# Bounded file metadata and log tail handling, including hidden evidence limits.
$fixtureRoot=Join-Path ([IO.Path]::GetTempPath()) ('winfix-files-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory((Join-Path $fixtureRoot 'nested'))
try {
    1..10 | ForEach-Object {[IO.File]::WriteAllText((Join-Path $fixtureRoot ("file$_.bak")),'fixture')}
    [IO.File]::WriteAllText((Join-Path $fixtureRoot 'nested/deep.bak'),'fixture')
    $found=@(Find-BackupEvidenceFiles -Root $fixtureRoot -EntryLimit 3)
    $coverage=$found | Where-Object {$_.Kind -eq 'Coverage'}
    if ($coverage.EntriesExamined -gt 3 -or -not $coverage.LimitReached) {throw 'File enumeration cap failed.'}
    $found=@(Find-BackupEvidenceFiles -Root $fixtureRoot -Depth 1)
    if (@($found | Where-Object {$_.Kind -eq 'File'}).Count -ne 11) {throw 'Nested file metadata missing.'}
    $log=Join-Path $fixtureRoot 'agent.log'
    [IO.File]::WriteAllText($log,((1..40 | ForEach-Object {"backup completed $_"}) -join "`n")+"`nbackup token=DO-NOT-EXPORT`n",[Text.Encoding]::Unicode)
    $tail=Read-BackupTextTail -Path $log
    if ($tail.Encoding -ne 'utf-16' -or $tail.Lines.Count -ne 12 -or -not $tail.OutputTruncated -or $tail.SensitiveLinesOmitted -ne 1 -or ($tail.Lines -join ' ') -match 'DO-NOT-EXPORT') {throw 'Log encoding/redaction/output cap failed.'}
    $tail=Read-BackupTextTail -Path $log -ByteLimit 100
    if ($tail.BytesRead -gt 100 -or -not $tail.TailTruncated -or ($tail.Lines -join ' ') -match 'DO-NOT-EXPORT') {throw 'Tail byte cap/redaction failed.'}
    $result=Invoke-BackupDiagnosticSection -Name FileHelpersWorker -Context @{FinderCode=${function:Find-BackupEvidenceFiles}.ToString();TailCode=${function:Read-BackupTextTail}.ToString();Root=$fixtureRoot;Log=$log} -Collect {
        Set-Item Function:Find-BackupEvidenceFiles ([scriptblock]::Create($FinderCode))
        Set-Item Function:Read-BackupTextTail ([scriptblock]::Create($TailCode))
        Find-BackupEvidenceFiles -Root $Root -EntryLimit 2
        Read-BackupTextTail -Path $Log
    }
    if ($result -notmatch 'Collected' -or $result -notmatch 'backup completed 40' -or $result -match 'DO-NOT-EXPORT') {throw 'Evidence helpers failed in worker.'}
} finally {Remove-Item $fixtureRoot -Recurse -Force}
Write-Host 'PASS: new evidence helpers bound filesystem enumeration, preserve metadata, decode UTF16 tails, omit labelled-secret lines and work in a serialized worker.'
