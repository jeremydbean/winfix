$ErrorActionPreference='Stop'
$path=Join-Path (Split-Path $PSScriptRoot) 'Export-WinFixAudit.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw ($errors -join "`n") }
if ($ast.ScriptRequirements.RequiredPSVersion -ne [version]'4.0') { throw 'PowerShell 4 target changed.' }
$ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$false) | ForEach-Object { . ([scriptblock]::Create($_.Extent.Text)) }
$temp=[IO.Path]::GetTempPath(); if (Test-Path /private/tmp) { $temp='/private/tmp' }
$root=Join-Path $temp ('winfix-veeam-evidence-'+[guid]::NewGuid().ToString('N'))
try {
    foreach ($folder in @('busy','jobA','jobB')) { $null=[IO.Directory]::CreateDirectory((Join-Path $root $folder)) }
    $service=Join-Path $root 'Svc.VeeamBackup.log'
    [IO.File]::WriteAllText($service,'service activity')
    foreach ($n in 1..260) { [IO.File]::WriteAllText((Join-Path $root "busy/Svc.$n.log"),'service activity') }
    foreach ($folder in @('jobA','jobB')) {
        foreach ($n in 1..2) {
            $file=Join-Path $root "$folder/Task.workload$n.log"
            [IO.File]::WriteAllText($file,'activity')
            [IO.File]::SetLastWriteTime($file,(Get-Date).AddHours(-3))
        }
    }
    $found=Find-AuditVeeamLogs -Root $root -Since (Get-Date).AddDays(-1) -FileLimit 3 -EntryLimit 1000 -PrioritizeJobLogs
    if ($found.Files.Count -ne 3 -or $found.Files[0].Path -ne $service -or $found.SelectedJobLogs -ne 2 -or $found.DirectoriesCapped -ne 1) { throw 'Core service/job selection or folder quota failed.' }
    $folders=@($found.Files | Where-Object { $_.Path -ne $service } | ForEach-Object { Split-Path $_.Path -Parent } | Sort-Object -Unique)
    if ($folders.Count -ne 2 -or $found.EntriesScanned -gt 1000 -or -not $found.OutputTruncated) { throw 'Job rotation/coverage limits failed.' }
    $capped=Find-AuditVeeamLogs -Root $root -Since (Get-Date).AddDays(-1) -FileLimit 3 -EntryLimit 1 -PrioritizeJobLogs
    if ($capped.EntriesScanned -ne 1 -or -not $capped.ScanLimitReached) { throw 'Enhanced discovery exceeded global cap.' }
    $text="[27.10.2026 11:58:40.000] Repository: example-repository password=DO_NOT_EXPORT`n[27.10.2026 11:58:41.000] Gateway: example-gateway`n[27.10.2026 11:58:42.000] Error: The network path was not found.`n"
    foreach ($n in 1..30) { $text+="[27.10.2026 12:17:00.000] == Name: [ExampleJob$n], Result: [Success], State: [Stopped]`nLatest run time: 07/21/2026 09:26:20`n" }
    $text+="Session result: Success, job type: `"InfraStatistic`"`nReading block 123 token=ACTIVITY_SECRET`n"
    [IO.File]::WriteAllText($service,$text)
    $detail=Read-AuditVeeamLog -Path $service -MaxBytes 1024 -MaxLines 80 -ContextLines 2 -IncludeActivity
    # Use a larger tail for context assertions; separately ensure the smaller tail is bounded.
    if ($detail.BytesRead -gt 1024 -or -not $detail.TailTruncated) { throw 'Byte bound failed.' }
    $detail=Read-AuditVeeamLog -Path $service -MaxBytes 262144 -MaxLines 80 -ContextLines 2 -IncludeActivity
    $serialized=ConvertTo-AuditJson -InputObject $detail
    if ($detail.Lines.Count -gt 80 -or $serialized -match 'DO_NOT_EXPORT|ACTIVITY_SECRET') { throw 'Context/activity bounds or secret scrubbing failed.' }
    if (-not @($detail.Lines | Where-Object { $_.Text -match 'Repository: example-repository' }).Count -or -not @($detail.Lines | Where-Object { $_.EvidenceKind -eq 'RepositoryConnectivity' }).Count) { throw 'Cached success crowded out repository error/context.' }
    if (-not @($detail.Lines | Where-Object { $_.EvidenceKind -eq 'ConfigurationSnapshot' }).Count -or -not @($detail.Lines | Where-Object { $_.EvidenceKind -eq 'InfrastructureActivity' }).Count) { throw 'Non-backup Success was not distinguished.' }
    if ($detail.BackupOutcome -ne 'Unverified' -or $detail.VerificationNeeded.Count -lt 4 -or -not $detail.OutputTruncated -or $detail.RecentActivity.Count -ne 5) { throw 'Verification or omission metadata missing.' }
    if ($detail.Lines[0].TimestampText -ne '27.10.2026 11:58:40.000') { throw 'Raw timestamp changed or lost.' }
    $tiny=Read-AuditVeeamLog -Path $service -MaxLines 1 -ContextLines 2
    if ($tiny.Lines.Count -ne 1 -or -not $tiny.Lines[0].KeywordMatch) { throw 'Small line budget discarded its anchor.' }
    foreach ($bigEndian in @($false,$true)) {
        $encoding=New-Object Text.UnicodeEncoding($bigEndian,$false)
        $activityFile=Join-Path $root 'activity.log'
        [IO.File]::WriteAllText($activityFile,"Reading block 1`nReading block 2 password=HIDDEN`n",$encoding)
        $activity=Read-AuditVeeamLog -Path $activityFile -IncludeActivity
        $expected=if ($bigEndian) {'utf-16BE'} else {'utf-16'}
        if ($activity.Encoding -ine $expected -or $activity.MatchedLines -ne 0 -or $activity.Lines.Count -ne 0 -or $activity.RecentActivity.Count -ne 2 -or ($activity | ConvertTo-Json -Depth 8) -match 'HIDDEN') { throw 'BOM-less UTF16 activity-only evidence failed.' }
    }
    $worker=Invoke-AuditCheck VeeamContextWorker -Context @{Path=$service;ReaderCode=${function:Read-AuditVeeamLog}.ToString()} -Collect {
        Set-Item Function:Read-AuditVeeamLog ([scriptblock]::Create($ReaderCode))
        Read-AuditVeeamLog -Path $Path -MaxBytes 262144 -MaxLines 80 -ContextLines 2 -IncludeActivity
    }
    if ($worker.Status -ne 'Collected' -or $worker.Data[0].BackupOutcome -ne 'Unverified' -or $worker.Data[0].RecentActivity.Count -ne 5) { throw 'Enhanced worker context/serialization failed.' }
    $roundtrip=(ConvertTo-AuditJson -InputObject $worker) | ConvertFrom-Json
    if ($roundtrip.Data[0].Lines.Count -ne $detail.Lines.Count) { throw 'Export lost context rows.' }
} finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
Write-Host 'PASS: fair Veeam discovery, quotas, repository error context, cached status labels, activity-only logs, BOM-less UTF16, redaction, bounded reads and worker/export serialization.'
