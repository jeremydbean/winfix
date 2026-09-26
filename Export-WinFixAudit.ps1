#requires -Version 4.0
<#
.SYNOPSIS
Collect local Windows audit evidence for a report, without changing configuration.
.DESCRIPTION
Writes full JSON and numbered paste blocks. No upload is performed. Inventory can
contain machine/domain names, usernames, IPs and paths. Review before sharing.
Some backup, identity and perimeter controls require supplied console or test evidence.
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory = '',
    [string]$ClientName = '',
    [string]$Location = '',
    [ValidateRange(1,90)][int]$LookbackDays = 30,
    [ValidateRange(10,500)][int]$MaxEvents = 50,
    [ValidateRange(4000,24000)][int]$PasteBlockCharacters = 12000,
    [ValidateRange(5,300)][int]$CheckTimeoutSeconds = 25,
    [ValidateRange(100,10000)][int]$EventScanLimit = 1000,
    [ValidateRange(1,500)][int]$MaxHyperVVMs = 50,
    [string]$EvidenceFile = '',
    [string]$VeeamLogDirectory = '',
    [ValidateRange(1,30)][int]$MaxVeeamLogFiles = 10,
    [switch]$SkipOnlineUpdateScan,
    [switch]$NoOpen,
    [switch]$CopyToClipboard
)

function Protect-AuditText {
    param([AllowNull()][string]$Text)
    $Text = $Text -replace '(?i)(Bearer\s+)[A-Za-z0-9._~+/=-]+', '$1[REDACTED]'
    $Text = $Text -replace '(?i)((?:password|passwd|pwd|token|secret|authorization|api[_-]?key)\s*["'']?\s*[:=]\s*)("[^"]*"|''[^'']*''|[^\s;,]+)', '$1[REDACTED]'
    $Text = $Text -replace '(?i)(https?://)[^\s/@]+:[^\s/@]+@', '$1[REDACTED]@'
    return $Text
}
function Find-AuditVeeamLogs {
    param([string]$Root, [datetime]$Since, [int]$FileLimit=10, [int]$EntryLimit=2000)
    $provider=$null; $drive=$null
    $native=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Root,[ref]$provider,[ref]$drive)
    if ($provider.Name -ne 'FileSystem' -or $native.StartsWith('\\')) { throw 'Veeam log collection requires a local filesystem folder.' }
    if ((New-Object IO.DriveInfo([IO.Path]::GetPathRoot($native))).DriveType -eq [IO.DriveType]::Network) { throw 'Mapped network log folders are not read.' }
    # Check every ancestor so a local path cannot traverse a junction to a share.
    $ancestor=New-Object IO.DirectoryInfo($native)
    while ($null -ne $ancestor) {
        if ($ancestor.Exists -and ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Veeam log folders cannot traverse reparse points.' }
        $ancestor=$ancestor.Parent
    }
    if (-not [IO.Directory]::Exists($native)) { throw "Veeam log folder not found: $native" }
    $queue=New-Object System.Collections.Queue
    $queue.Enqueue([pscustomobject]@{Path=$native;Depth=0})
    $entries=0; $depthSkipped=0; $linksSkipped=0; $failures=@(); $files=@()
    while ($queue.Count -and $entries -lt $EntryLimit) {
        $folder=$queue.Dequeue()
        try {
            foreach ($path in [IO.Directory]::EnumerateFileSystemEntries($folder.Path)) {
                if ($entries -ge $EntryLimit) { break }
                $entries++
                try {
                    $attributes=[IO.File]::GetAttributes($path)
                    if ($attributes -band [IO.FileAttributes]::ReparsePoint) { $linksSkipped++; continue }
                    if ($attributes -band [IO.FileAttributes]::Directory) {
                        if ($folder.Depth -lt 2) { $queue.Enqueue([pscustomobject]@{Path=$path;Depth=$folder.Depth+1}) }
                        else { $depthSkipped++ }
                    } elseif ([IO.Path]::GetExtension($path) -eq '.log') {
                        $file=New-Object IO.FileInfo($path)
                        if ($file.LastWriteTime -ge $Since) { $files += [pscustomobject]@{Path=$file.FullName;Length=$file.Length;LastWriteTime=$file.LastWriteTime} }
                    }
                } catch { $failures += [pscustomobject]@{Path=$path;Error=$_.Exception.Message} }
                if ($entries -ge $EntryLimit) { break }
            }
        } catch { $failures += [pscustomobject]@{Path=$folder.Path;Error=$_.Exception.Message} }
    }
    [pscustomobject]@{Root=$native;EntriesScanned=$entries;EntryLimit=$EntryLimit;ScanLimitReached=($entries -ge $EntryLimit)
        DepthLimit=2;DeeperFoldersSkipped=$depthSkipped;ReparsePointsSkipped=$linksSkipped;Errors=@($failures | Select-Object -First 20)
        RecentLogCandidates=$files.Count;FileLimit=$FileLimit;OutputTruncated=($files.Count -gt $FileLimit)
        Files=@($files | Sort-Object LastWriteTime -Descending | Select-Object -First $FileLimit)
        Coverage='Local .log files only, root plus two directory levels; newest within bounded discovery. File modification time is not an event timestamp. No archives, remote shares or reparse points are read.'}
}
function Read-AuditVeeamLog {
    param([string]$Path, [int]$MaxBytes=131072, [int]$MaxLines=40)
    $stream=$null
    try {
        if ([IO.File]::GetAttributes($Path) -band [IO.FileAttributes]::ReparsePoint) { throw 'Log file became a reparse point.' }
        $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        $length=$stream.Length; $header=New-Object byte[] 3; $null=$stream.Read($header,0,3)
        $encoding=New-Object Text.UTF8Encoding($false); $unit=1; $bom=0
        if ($header[0] -eq 255 -and $header[1] -eq 254) { $encoding=[Text.Encoding]::Unicode; $unit=2; $bom=2 }
        elseif ($header[0] -eq 254 -and $header[1] -eq 255) { $encoding=[Text.Encoding]::BigEndianUnicode; $unit=2; $bom=2 }
        elseif ($header[0] -eq 239 -and $header[1] -eq 187 -and $header[2] -eq 191) { $bom=3 }
        $offset=[math]::Max($bom,$length-$MaxBytes)
        if ($unit -eq 2 -and ($offset % 2)) { $offset++ }
        $null=$stream.Seek($offset,[IO.SeekOrigin]::Begin)
        $count=[int][math]::Max(0,$length-$offset); $bytes=New-Object byte[] $count; $read=0
        while ($read -lt $count) { $n=$stream.Read($bytes,$read,$count-$read); if (-not $n) { break }; $read+=$n }
        $raw=$encoding.GetString($bytes,0,$read)
        if ($offset -gt $bom) {
            $newline=$raw.IndexOf("`n")
            if ($newline -ge 0) { $raw=$raw.Substring($newline+1) } else { $raw='' }
        }
        $lines=@($raw -split '\r?\n'); $matchedLines=@()
        for ($i=0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match '(?i)\b(error|failed|failure|warning|success|succeeded)\b|\b(job|session|task|backup|restore)\b.*\b(finished|completed|result|status)\b') {
                $safe=Protect-AuditText $lines[$i]
                $matchedLines += [pscustomobject]@{TailLine=($i+1);Text=$safe.Substring(0,[math]::Min(1000,$safe.Length));Truncated=($safe.Length -gt 1000)}
            }
        }
        [pscustomobject]@{Path=$Path;Status='Collected';FileLength=$length;Encoding=$encoding.WebName;BytesRead=$read;ByteLimit=$MaxBytes
            TailTruncated=($offset -gt $bom);MatchedLines=$matchedLines.Count;OutputTruncated=($matchedLines.Count -gt $MaxLines)
            Lines=@($matchedLines | Select-Object -Last $MaxLines);Error=$null
            Coverage='Keyword excerpts from a bounded file tail, in file order; TailLine is relative to the retained tail. Raw text is not a verified job outcome or restore result. Individual line timestamps are not parsed; older lines may remain. Secrets are scrubbed best-effort.'}
    } catch { [pscustomobject]@{Path=$Path;Status='Unavailable';Error=$_.Exception.Message;Lines=@()} }
    finally { if ($stream) { $stream.Dispose() } }
}

function ConvertTo-AuditJson {
    param([Parameter(Mandatory=$true)][AllowNull()]$InputObject, [ValidateRange(1,100)][int]$Depth = 14)
    # PowerShell 4's pretty formatter can reject valid strings ending in a
    # backslash (for example C:\). Compact JSON avoids that formatting bug.
    # Keep the evidence unchanged; use this for every JSON export.
    ConvertTo-Json -InputObject $InputObject -Depth $Depth -Compress -ErrorAction Stop
}
function Initialize-AuditOutputDirectory {
    param([Parameter(Mandatory=$true)][string]$Path)
    # Resolve PowerShell paths/PSDrives to native paths before any .NET I/O.
    # PathInfo.Path can include FileSystem:: for a redirected UNC Desktop.
    $provider = $null; $drive = $null
    $nativePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
        $Path, [ref]$provider, [ref]$drive)
    if ($provider.Name -ne 'FileSystem') { throw 'Audit output must use a FileSystem directory.' }
    $probePath = $null
    try {
        [IO.Directory]::CreateDirectory($nativePath) | Out-Null
        $probePath = [IO.Path]::Combine($nativePath, ('.winfix-write-test-' + [guid]::NewGuid().ToString('N')))
        [IO.File]::WriteAllText($probePath, 'WinFix output write test', (New-Object Text.UTF8Encoding($false)))
        [IO.File]::Delete($probePath)
    } catch {
        throw "Cannot write audit output to '$nativePath': $($_.Exception.Message) Use -OutputDirectory with a writable local folder."
    } finally {
        if ($probePath -and [IO.File]::Exists($probePath)) {
            Remove-Item -LiteralPath $probePath -Force -ErrorAction SilentlyContinue
        }
    }
    return $nativePath
}
function Save-AuditCheckpoint {
    if ($script:checkpointPath) {
        $tempPath = $script:checkpointPath + '.tmp'
        try {
            $snapshot = [ordered]@{ SchemaVersion='1.8'; AuditId=$script:auditId; Incomplete=$true
                SavedAt=(Get-Date).ToString('o'); ClientName=$ClientName; Location=$Location; Elevated=$elevated
                Checks=$script:checks; ExportWarnings=@($script:checkpointWarnings) }
            $checkpointJson = ConvertTo-AuditJson -InputObject $snapshot
            [IO.File]::WriteAllText($tempPath, $checkpointJson, (New-Object Text.UTF8Encoding($false)))
            Move-Item -LiteralPath $tempPath -Destination $script:checkpointPath -Force -ErrorAction Stop
        } catch {
            $script:checkpointWarnings += [pscustomobject]@{
                Stage='Checkpoint'; Time=(Get-Date).ToString('o'); Path=$script:checkpointPath; Error=$_.Exception.Message
            }
            # Preserve the previous good checkpoint and all in-memory results.
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
            Write-Warning -Message 'Checkpoint could not be saved; continuing with results in memory. The final report will include the export warning.' -WarningAction Continue
        }
    }
}
function Invoke-AuditCheck {
    param([string]$Name, [scriptblock]$Collect, [int]$TimeoutSeconds = $CheckTimeoutSeconds,
        [hashtable]$Context = @{})
    if ($TimeoutSeconds -lt 1) { $TimeoutSeconds = 25 }
    Write-Host "Collecting $Name (limit ${TimeoutSeconds}s)..."
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $job = $null; $data = @(); $status = 'Unavailable'; $failure = $null
    # Jobs isolate blocking Windows/COM/native calls from the ISE UI thread.
    $Context.MaxEvents = $MaxEvents; $Context.EventScanLimit = $EventScanLimit
    $Context.since = $since
    $Context.SystemEvidence = $script:checks.System
    $Context.BackupPattern = $BackupPattern
    try {
        $job = Start-Job -ArgumentList $Collect.ToString(), $Context, ${function:Get-AuditEvents}.ToString(), ${function:Protect-AuditText}.ToString() -ScriptBlock {
            param($Code, $Variables, $EventHelper, $TextHelper)
            $ErrorActionPreference = 'Stop'
            $ProgressPreference = 'SilentlyContinue'
            foreach ($key in $Variables.Keys) { Set-Variable -Name $key -Value $Variables[$key] }
            Set-Item Function:Protect-AuditText ([scriptblock]::Create($TextHelper))
            Set-Item Function:Get-AuditEvents ([scriptblock]::Create($EventHelper))
            & ([scriptblock]::Create($Code))
        }
        while ($job.State -in @('NotStarted','Running') -and $timer.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
            $null = Wait-Job $job -Timeout 1
            Write-Progress -Activity 'WinFix audit' -Status "$Name - $([int]$timer.Elapsed.TotalSeconds)s / ${TimeoutSeconds}s"
        }
        $timedOut = $job.State -in @('NotStarted','Running')
        if ($timedOut) { Stop-Job $job -ErrorAction SilentlyContinue }
        $workerErrors = @()
        $data = @(Receive-Job $job -ErrorAction SilentlyContinue -ErrorVariable workerErrors | ForEach-Object {
            # Preserve strings and scalar values (Select-Object * turns them into property bags).
            foreach ($property in @('PSComputerName','RunspaceId','PSShowComputerName')) {
                $_.PSObject.Properties.Remove($property)
            }
            $_
        })
        if ($timedOut) {
            $status = 'TimedOut'; $failure = "Exceeded ${TimeoutSeconds}s; continuing. Any returned data is incomplete."
        } elseif ($workerErrors.Count -or $job.State -ne 'Completed') {
            $status = if ($data.Count) { 'Partial' } else { 'Unavailable' }
            $failure = ($workerErrors | ForEach-Object { $_.ToString() }) -join '; '
            if (-not $failure) { $failure = "Worker ended in state $($job.State)." }
        } else { $status = 'Collected' }
    } catch { $failure = $_.Exception.Message }
    finally {
        if ($job) { Remove-Job $job -Force -ErrorAction SilentlyContinue }
        Write-Progress -Activity 'WinFix audit' -Completed
    }
    $result = [pscustomobject][ordered]@{ Status=$status; Count=$data.Count; Data=$data; Error=$failure
        DurationSeconds=[math]::Round($timer.Elapsed.TotalSeconds,2); TimeoutSeconds=$TimeoutSeconds }
    if ($null -ne $script:checks) { $script:checks[$Name] = $result }
    Save-AuditCheckpoint
    Write-Host "  $Name : $status ($($result.DurationSeconds)s)"
    return $result
}
function Get-AuditEvents {
    param([string]$LogName, [int[]]$Levels = @(), [int[]]$Ids = @(), [string]$ProviderPattern = '', [switch]$IncludeMessage, [switch]$IncludeEventData)
    # Bound records read BEFORE filtering; MaxEvents on a sparse filtered query
    # alone can still walk a huge log. The outer job also limits elapsed time.
    $info = Get-WinEvent -ListLog $LogName -ErrorAction Stop
    $records = @()
    if ($info.IsEnabled -and $info.RecordCount -ne 0) {
        try { $records = @(Get-WinEvent -LogName $LogName -MaxEvents $EventScanLimit -ErrorAction Stop) }
        catch { if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw } }
    }
    $matched = @($records | Where-Object {
        $_.TimeCreated -ge $since -and (-not $Levels.Count -or $_.Level -in $Levels) -and
        (-not $Ids.Count -or $_.Id -in $Ids) -and (-not $ProviderPattern -or $_.ProviderName -match $ProviderPattern)
    })
    $events = @($matched | Select-Object -First $MaxEvents | ForEach-Object {
        $entry = $_ | Select-Object TimeCreated, Id, RecordId, ProviderName, Level, LevelDisplayName, LogName
        if ($IncludeMessage) {
            $message = $null; $messageError = $null; $messageTruncated = $false
            try {
                $message = [string]$_.Message
                if ([string]::IsNullOrWhiteSpace($message)) { $messageError='Event message was empty or could not be rendered; inspect EventData when available.' }
                $message = Protect-AuditText $message
                if ($message.Length -gt 2000) { $message=$message.Substring(0,2000); $messageTruncated=$true }
            } catch { $messageError=$_.Exception.Message }
            $entry | Add-Member NoteProperty Message $message
            $entry | Add-Member NoteProperty MessageTruncated $messageTruncated
            $entry | Add-Member NoteProperty MessageError $messageError
        }
        if ($IncludeEventData) {
            $fields=@(); $xmlError=$null; $fieldCount=0
            try {
                [xml]$xml=$_.ToXml()
                $nodes=@($xml.SelectNodes('/*[local-name()="Event"]/*[local-name()="EventData"]/*'))
                $fieldCount=$nodes.Count
                foreach ($node in ($nodes | Select-Object -First 24)) {
                    $fieldName=[string]$node.GetAttribute('Name')
                    $value=if ($fieldName -match '(?i)password|passwd|pwd|token|secret|authorization|key') { '[REDACTED]' } else { Protect-AuditText ([string]$node.InnerText) }
                    $fields += [pscustomobject]@{Name=$fieldName;Value=$value.Substring(0,[math]::Min(500,$value.Length));Truncated=($value.Length -gt 500)}
                }
            } catch { $xmlError=$_.Exception.Message }
            $entry | Add-Member NoteProperty EventData $fields
            $entry | Add-Member NoteProperty EventDataTruncated ($fieldCount -gt 24)
            $entry | Add-Member NoteProperty EventDataError $xmlError
        }
        $entry
    })
    [pscustomobject]@{
        LogName=$LogName; Enabled=$info.IsEnabled; RecordsInLog=$info.RecordCount
        RecordsScanned=$records.Count; ScanLimit=$EventScanLimit; Since=$since
        OldestScannedTime=if ($records.Count) { $records[-1].TimeCreated } else { $null }
        ScanLimitReached=($records.Count -ge $EventScanLimit)
        MatchedInSample=$matched.Count; OutputTruncated=($matched.Count -gt $MaxEvents)
        Coverage='Recent-record sample only; zero matches is not proof of no incidents or no backups.'
        Events=$events
    }
}
function Get-AuditHyperVDetail {
    param([string]$VMId, [ValidateSet('Disks','Integration','Checkpoints')][string]$Kind)
    Import-Module Hyper-V -ErrorAction Stop
    $vm = Get-VM -Id ([guid]$VMId) -ErrorAction Stop
    if ($Kind -eq 'Disks') {
        # Stream each attachment so a later blocked VHD preserves earlier evidence.
        foreach ($disk in @(Get-VMHardDiskDrive -VM $vm -ErrorAction Stop)) {
            $metadata=$null; $metadataStatus='Unavailable'; $metadataError=$null
            if ([string]::IsNullOrWhiteSpace([string]$disk.Path)) {
                $metadataError='No VHD path; inspect DiskNumber for pass-through storage.'
            } elseif ([string]$disk.Path -notmatch '^[A-Za-z]:\\') {
                $metadataError='Non-local path recorded only; no network repository or VHD was opened.'
            } else {
                try {
                    $metadata = Get-VHD -Path $disk.Path -ErrorAction Stop |
                        Select-Object Path,@{n='VhdFormat';e={[string]$_.VhdFormat}},@{n='VhdType';e={[string]$_.VhdType}},
                            FileSize,Size,ParentPath,Attached
                    $metadataStatus='Collected'
                } catch { $metadataError=$_.Exception.Message }
            }
            [pscustomobject]@{ VMId=[string]$vm.Id; VMName=$vm.Name; Path=$disk.Path
                ControllerType=[string]$disk.ControllerType; ControllerNumber=$disk.ControllerNumber
                ControllerLocation=$disk.ControllerLocation; DiskNumber=$disk.DiskNumber
                VHDStatus=$metadataStatus; VHD=$metadata; VHDError=$metadataError
                Coverage='Attachment path and immediate parent only; no parent-chain traversal, guest disks or vendor backup mapping. VHD errors do not erase attachment evidence.' }
        }
    } elseif ($Kind -eq 'Integration') {
        # Keep all names/IDs: the backup (VSS) component name is localized.
        Get-VMIntegrationService -VM $vm -ErrorAction Stop |
            Select-Object @{n='VMId';e={[string]$vm.Id}},@{n='VMName';e={$vm.Name}},Name,
                @{n='Id';e={[string]$_.Id}},Enabled,
                @{n='PrimaryStatusDescription';e={[string]$_.PrimaryStatusDescription}},
                @{n='SecondaryStatusDescription';e={[string]$_.SecondaryStatusDescription}}
    } else {
        $snapshots=@(Get-VMSnapshot -VM $vm -ErrorAction Stop | Sort-Object CreationTime -Descending)
        [pscustomobject]@{ VMId=[string]$vm.Id; VMName=$vm.Name; TotalCount=$snapshots.Count
            OutputTruncated=($snapshots.Count -gt 50)
            Checkpoints=@($snapshots | Select-Object -First 50 | Select-Object Name,
                @{n='Id';e={[string]$_.Id}},CreationTime,@{n='SnapshotType';e={[string]$_.SnapshotType}},
                @{n='ParentSnapshotId';e={[string]$_.ParentSnapshotId}})
            Coverage='Checkpoints are local state, not independent backups or proof of a successful vendor job. Missing newer properties remain null in older Hyper-V versions.' }
    }
}
function New-ExternalEvidenceTemplate {
    param([string]$ComputerName)
    $questions = @{
        BackupLastSuccess='Product, task/device, last successful completion, latest failure and console status.'
        BackupProtectedScope='Protected volumes/folders, exclusions, schedule and destination capacity.'
        HyperVBackupCoverage='For each VM ID/name: vendor task, included/excluded disks, host-volume versus VM-aware protection, application consistency, schedule, latest usable restore point and recent failures.'
        HyperVRestoreTest='For each critical VM: isolated restore/boot and application test, restore point, result, elapsed time, date and tester. Checkpoint/replication health is not a restore test.'
        BackupRetention='Retention policy, oldest/newest available restore points and recovery point objective.'
        BackupEncryption='Encryption at rest and in transit, confirmed configuration; no keys or credentials.'
        BackupOffsiteProtection='Independent/offsite copy, immutability or isolation and last replication result.'
        BackupRestoreTest='Test date, restore point, alternate destination, files/workload checked, outcome, elapsed time and tester.'
        MFAEnforcement='Identity/remote-support system, effective policy scope, exceptions and sign-in evidence.'
        PublicExposure='Perimeter/cloud firewall or NAT rules, reviewed public endpoints, authorized external test scope/time/result.'
        RMMEDRConsoleHealth='Ninja/Huntress/antivirus console last check-in, alerts, signatures and applied policy.'
        CentralLogRetention='Logging destination, successful receipt, retention period and monitored event types.'
        OSSupportEntitlement='Confirmed Windows edition/build/channel and support or ESU entitlement, if applicable.'
        ApprovedSecurityPolicy='Approved password/access baseline, system owner and recovery time/point objectives.'
    }
    [pscustomobject]@{ SchemaVersion='1.0'; ComputerName=$ComputerName
        Instructions='Complete only from an identified console, policy, or performed test. Use Reported or NotApplicable with Source, ObservedAt (ISO 8601 with offset), ObservedBy and Details. Leave unknown items Unknown. Never enter credentials or recovery keys. Import using -EvidenceFile.'
        Controls=@(
            foreach ($name in @('BackupLastSuccess','BackupProtectedScope','BackupRetention','BackupEncryption',
                'BackupOffsiteProtection','BackupRestoreTest','MFAEnforcement','PublicExposure',
                'RMMEDRConsoleHealth','CentralLogRetention','OSSupportEntitlement','ApprovedSecurityPolicy','HyperVBackupCoverage','HyperVRestoreTest')) {
                [pscustomobject]@{ Name=$name; Status='Unknown'; Source=''; ObservedAt=''; ObservedBy=''; Details=''; RequestedEvidence=$questions[$name] }
            }
        ) }
}
function Read-ExternalEvidence {
    param([string]$Path, $Template)
    if ([string]::IsNullOrWhiteSpace($Path)) {
        foreach ($row in $Template.Controls) {
            [pscustomobject]@{ Name=$row.Name; Status='Unknown'; Origin='ExternalEvidenceRequired'; Source=''; ObservedAt=''; ObservedBy=''; Details='' }
        }
        return
    }
    $file = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($file.Length -gt 262144) { throw 'Evidence file exceeds the 256 KiB limit.' }
    $inputData = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($inputData.SchemaVersion -ne '1.0' -or $inputData.ComputerName -ne $Template.ComputerName) { throw 'Evidence schema or computer name does not match this host.' }
    $allowed = @($Template.Controls | ForEach-Object { $_.Name })
    $seen = @{}
    foreach ($row in @($inputData.Controls)) {
        if ($row.Name -notin $allowed -or $seen.ContainsKey([string]$row.Name)) { throw 'Unknown or duplicate evidence control name.' }
        $seen[$row.Name] = $row
        if ($row.Status -notin @('Unknown','Reported','NotApplicable')) { throw 'Evidence status must be Unknown, Reported or NotApplicable.' }
        if ($row.Status -ne 'Unknown') {
            foreach ($key in @('Source','ObservedAt','ObservedBy','Details')) {
                if ([string]::IsNullOrWhiteSpace([string]$row.$key)) { throw "Evidence $($row.Name) requires $key." }
            }
            if ($row.ObservedAt -is [datetime] -or $row.ObservedAt -is [datetimeoffset]) { $row.ObservedAt=$row.ObservedAt.ToString('o') }
            if ([string]$row.ObservedAt -notmatch '^\d{4}-\d{2}-\d{2}T.*(Z|[+-]\d{2}:\d{2})$') { throw 'ObservedAt must be an ISO 8601 timestamp with timezone.' }
            $null = [datetimeoffset]::Parse([string]$row.ObservedAt)
        }
    }
    foreach ($name in $allowed) {
        $row=$seen[$name]
        if ($null -eq $row) { $row=[pscustomobject]@{Status='Unknown'} }
        [pscustomobject]@{ Name=$name; Status=[string]$row.Status; Origin='UserSuppliedNotIndependentlyVerified'
            Source=[string]$row.Source; ObservedAt=[string]$row.ObservedAt; ObservedBy=[string]$row.ObservedBy; Details=[string]$row.Details }
    }
}
function Set-LegacyAuditClipboard {
    param([string]$Text)
    # Server 2012 R2 / PowerShell 4 has no Set-Clipboard. ISE runs in STA.
    if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
        throw 'Legacy clipboard requires an STA session such as PowerShell ISE. Use the saved text file instead.'
    }
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
    [System.Windows.Forms.Clipboard]::SetText($Text)
}
function Copy-AuditText {
    param([string]$Text)
    if (Get-Command Set-Clipboard -ErrorAction SilentlyContinue) { Set-Clipboard -Value $Text -ErrorAction Stop }
    else { Set-LegacyAuditClipboard -Text $Text }
}
function New-PasteBlocks {
    param([string]$Json, [int]$Size, [string]$Id)
    $total = [int][math]::Ceiling($Json.Length / $Size)
    for ($i = 0; $i -lt $total; $i++) {
        $part = $Json.Substring($i * $Size, [math]::Min($Size, $Json.Length - $i * $Size))
        "===== BEGIN WINFIX AUDIT $Id PART $($i + 1)/$total =====`r`n$part`r`n===== END WINFIX AUDIT $Id PART $($i + 1)/$total ====="
    }
}

if ($PSVersionTable.PSVersion.Major -lt 4) { throw 'Windows PowerShell 4.0 or later is required.' }
if ($env:OS -ne 'Windows_NT') { throw 'Run this collector on the Windows computer being audited.' }
$ErrorActionPreference = 'Stop'
$started = Get-Date
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$since = (Get-Date).AddDays(-$LookbackDays)
$script:checks = [ordered]@{}
$script:checkpointWarnings = @()
$script:auditId = [guid]::NewGuid().ToString('N')
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $desktop = [Environment]::GetFolderPath('Desktop')
    if ([string]::IsNullOrWhiteSpace($desktop)) { $desktop = $env:TEMP }
    $OutputDirectory = Join-Path $desktop 'WinFixAudit'
}
$OutputDirectory = Initialize-AuditOutputDirectory -Path $OutputDirectory
$prefix = 'WinFixAudit-' + $env:COMPUTERNAME + '-' + $started.ToString('yyyyMMdd-HHmmss')
$script:checkpointPath = Join-Path $OutputDirectory "$prefix-PARTIAL.json"
$BackupPattern = 'Veeam|Acronis|Macrium|Datto|Carbonite|Veritas|CrashPlan|\bCove\b|Axcient|Rubrik|Backup|StorageCraft|ShadowProtect|Arcserve|MSP360|CloudBerry|Druva|Commvault|NAKIVO|Retrospect|UrBackup'
Write-Host "WinFix audit 1.8. Completed checks are saved to $script:checkpointPath"
if (-not $elevated) { Write-Warning 'Run ISE as Administrator for the fullest audit.' }
Save-AuditCheckpoint
$checks.System = Invoke-AuditCheck System {
    $cs = Get-CimInstance Win32_ComputerSystem
    $os = Get-CimInstance Win32_OperatingSystem
    [pscustomobject]@{
        ComputerName = $cs.Name; Manufacturer = $cs.Manufacturer; Model = $cs.Model
        Domain = $cs.Domain; PartOfDomain = $cs.PartOfDomain; DomainRole = $cs.DomainRole
        MemoryGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
        OS = $os.Caption; Version = $os.Version; Build = $os.BuildNumber
        Architecture = $os.OSArchitecture; InstallDate = $os.InstallDate
        LastBoot = $os.LastBootUpTime; UptimeDays = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 2)
    }
}
$checks.RuntimeCapabilities = Invoke-AuditCheck RuntimeCapabilities {
    [pscustomobject]@{ PowerShellVersion=$PSVersionTable.PSVersion.ToString()
        Is64BitProcess=[Environment]::Is64BitProcess
        OptionalCommands=@(foreach ($name in @('Get-LocalUser','Get-LocalGroupMember','Get-MpComputerStatus',
            'Get-BitLockerVolume','Get-Tpm','Confirm-SecureBootUEFI','Get-NetNatStaticMapping','dsregcmd.exe','Set-Clipboard')) {
            [pscustomobject]@{ Name=$name; Available=[bool](Get-Command $name -ErrorAction SilentlyContinue) }
        })
        Coverage='Missing OS features remain Unavailable in their checks; absence is not proof of a failed security control.' }
}
$checks.OSRelease = Invoke-AuditCheck OSRelease {
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' |
        Select-Object ProductName, EditionID, DisplayVersion, ReleaseId, CurrentVersion, CurrentBuild, UBR, InstallationType
}
$checks.Hardware = Invoke-AuditCheck Hardware {
    Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors
    Get-CimInstance Win32_BIOS | Select-Object Manufacturer, SMBIOSBIOSVersion, ReleaseDate
}
$checks.ServerRoles = Invoke-AuditCheck ServerRoles {
    Get-WindowsFeature | Where-Object Installed | Select-Object Name, DisplayName
}
$checks.Software = Invoke-AuditCheck Software {
    # Do not use Win32_Product: querying it can trigger MSI repairs.
    $paths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    foreach ($path in $paths) {
        if (Test-Path $path) {
            Get-ItemProperty "$path\*" | Where-Object DisplayName |
                Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
        }
    }
}
$checks.AgentServices = Invoke-AuditCheck AgentServices {
    Get-CimInstance Win32_Service |
        Where-Object { "$($_.Name) $($_.DisplayName)" -match 'Ninja|Huntress|GoTo|LogMeIn|ScreenConnect|ConnectWise|TeamViewer|AnyDesk|Splashtop|RustDesk|VNC|BeyondTrust|Veeam|Acronis|Macrium|Datto|Carbonite|Veritas|CrashPlan|\bCove\b|Axcient|Rubrik|Backup|Sentinel|Sophos|CrowdStrike|Webroot|ESET|Bitdefender' } |
        Select-Object Name, DisplayName, State, StartMode
}
$checks.Antivirus = Invoke-AuditCheck Antivirus {
    Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct |
        Select-Object displayName, productState, timestamp
}
$checks.Defender = Invoke-AuditCheck Defender {
    Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, AntispywareEnabled,
        RealTimeProtectionEnabled, BehaviorMonitorEnabled, NISEnabled, IsTamperProtected,
        AntivirusSignatureVersion, AntivirusSignatureLastUpdated, QuickScanEndTime, FullScanEndTime
}
$checks.Firewall = Invoke-AuditCheck Firewall {
    Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogBlocked, LogAllowed
}
$checks.BitLocker = Invoke-AuditCheck BitLocker {
    # Explicit allowlist excludes recovery passwords/key protectors.
    Get-BitLockerVolume | Select-Object MountPoint, VolumeType, VolumeStatus, ProtectionStatus, EncryptionPercentage, EncryptionMethod, LockStatus
}
$checks.TPM = Invoke-AuditCheck TPM { Get-Tpm | Select-Object TpmPresent, TpmReady, TpmEnabled, TpmActivated, ManufacturerIdTxt, ManufacturerVersion }
$checks.SecureBoot = Invoke-AuditCheck SecureBoot { [pscustomobject]@{ Enabled = Confirm-SecureBootUEFI } }
$checks.Disks = Invoke-AuditCheck Disks {
    Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | Select-Object DeviceID, VolumeName, FileSystem,
        @{n='SizeGB';e={[math]::Round($_.Size / 1GB, 2)}}, @{n='FreeGB';e={[math]::Round($_.FreeSpace / 1GB, 2)}},
        @{n='FreePercent';e={if ($_.Size) {[math]::Round(100 * $_.FreeSpace / $_.Size, 1)}}}
}
$checks.Volumes = Invoke-AuditCheck Volumes {
    Get-Volume | Select-Object DriveLetter, FileSystemLabel, FileSystem, DriveType, HealthStatus, OperationalStatus, Size, SizeRemaining
}
$checks.PhysicalDisks = Invoke-AuditCheck PhysicalDisks { Get-PhysicalDisk | Select-Object FriendlyName, MediaType, HealthStatus, OperationalStatus, Size }
$checks.LocalUsers = Invoke-AuditCheck LocalUsers {
    if ($SystemEvidence.Status -ne 'Collected') { throw 'System role unavailable; local account scope cannot be determined.' }
    if ($SystemEvidence.Data[0].DomainRole -ge 4) { throw 'Domain controller: local SAM accounts are not applicable; domain account review required.' }
    if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
        Get-LocalUser | Select-Object Name, Enabled, SID, LastLogon, PasswordLastSet, PasswordExpires, PasswordRequired, UserMayChangePassword
    } else {
        # Win32_UserAccount is available on Server 2012 R2 without LocalAccounts.
        # PasswordExpires here is a boolean, not a timestamp; keep it separate.
        Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' | ForEach-Object {
            [pscustomobject]@{ Name=$_.Name; Enabled=(-not $_.Disabled); SID=$_.SID
                LastLogon=$null; PasswordLastSet=$null; PasswordExpires=$null
                PasswordRequired=$_.PasswordRequired; UserMayChangePassword=$_.PasswordChangeable
                PasswordExpirationEnabled=$_.PasswordExpires; Lockout=$_.Lockout
                Source='Win32_UserAccount fallback'
                Coverage='Local accounts only. Last-logon, password-set and expiration timestamps are unavailable from this provider.' }
        }
    }
}
$checks.Administrators = Invoke-AuditCheck Administrators {
    if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
        Get-LocalGroupMember -SID 'S-1-5-32-544' | Select-Object Name, SID, ObjectClass, PrincipalSource
    } else {
        # Use the well-known SID rather than an English group name.
        $group = Get-CimInstance Win32_Group -Filter "SID='S-1-5-32-544'"
        if ($null -eq $group) { throw 'The built-in Administrators group could not be resolved.' }
        $group | Get-CimAssociatedInstance -Association Win32_GroupUser | ForEach-Object {
            [pscustomobject]@{ Name=($_.Domain + '\' + $_.Name); SID=$_.SID
                ObjectClass=$_.CimClass.CimClassName; PrincipalSource=$null
                Source='Win32_GroupUser fallback'; Coverage='Direct members only; nested groups and unresolved identities need separate review.' }
        }
    }
}
$checks.PasswordPolicy = Invoke-AuditCheck PasswordPolicy {
    $result = & net.exe accounts 2>&1
    if ($LASTEXITCODE -ne 0) { throw ($result -join "`n") }
    $result -join "`n"
}
$checks.SecurityPolicy = Invoke-AuditCheck SecurityPolicy {
    $tempFile = Join-Path $env:TEMP ("WinFixPolicy-" + [guid]::NewGuid().ToString('N') + '.inf')
    try {
        $result = & secedit.exe /export /cfg $tempFile /areas SECURITYPOLICY /quiet 2>&1
        if ($LASTEXITCODE -ne 0) { throw ($result -join "`n") }
        Get-Content $tempFile | Where-Object { $_ -match '^(MinimumPasswordAge|MaximumPasswordAge|MinimumPasswordLength|PasswordComplexity|PasswordHistorySize|LockoutBadCount|ResetLockoutCount|LockoutDuration|ClearTextPassword)\s*=' } |
            ForEach-Object {
                $pair = ([string]$_) -split '=', 2
                [pscustomobject]@{ Name=$pair[0].Trim(); Value=$pair[1].Trim() }
            }
    } finally { if (Test-Path $tempFile) { Remove-Item $tempFile -Force } }
}
$checks.AuditPolicy = Invoke-AuditCheck AuditPolicy {
    $result = & auditpol.exe /get /category:* /r 2>&1
    if ($LASTEXITCODE -ne 0) { throw ($result -join "`n") }
    $result -join "`n"
}
$checks.RDP = Invoke-AuditCheck RDP {
    $ts = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $rdp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    [pscustomobject]@{ DenyConnections = $ts.fDenyTSConnections; RequireNLA = $rdp.UserAuthentication; SecurityLayer = $rdp.SecurityLayer; Port = $rdp.PortNumber }
}
$checks.Network = Invoke-AuditCheck Network {
    Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' |
        Select-Object Description, DHCPEnabled, IPAddress, IPSubnet, DefaultIPGateway, DNSServerSearchOrder
}
$checks.NetworkProfiles = Invoke-AuditCheck NetworkProfiles { Get-NetConnectionProfile | Select-Object Name, InterfaceAlias, NetworkCategory, IPv4Connectivity, IPv6Connectivity }
$checks.ListeningPorts = Invoke-AuditCheck ListeningPorts { Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess | Sort-Object LocalAddress, LocalPort, OwningProcess -Unique }
$checks.Shares = Invoke-AuditCheck Shares { Get-SmbShare | Select-Object Name, Path, Description, EncryptData, Special }
$checks.SharePermissions = Invoke-AuditCheck SharePermissions {
    Get-SmbShare | ForEach-Object { Get-SmbShareAccess -Name $_.Name | Select-Object Name, AccountName, AccessControlType, AccessRight }
}
$checks.SMB = Invoke-AuditCheck SMB { Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, EncryptData, RequireSecuritySignature, EnableSecuritySignature }
$checks.Printers = Invoke-AuditCheck Printers { Get-CimInstance Win32_Printer | Select-Object Name, DriverName, PortName, Shared, ShareName, Network, Default }
$checks.ScheduledTasks = Invoke-AuditCheck ScheduledTasks {
    # Omit action arguments: they may contain embedded credentials.
    Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
        Select-Object TaskPath, TaskName, State, @{n='RunAs';e={$_.Principal.UserId}}, @{n='RunLevel';e={[string]$_.Principal.RunLevel}}
}
$checks.Hotfixes = Invoke-AuditCheck Hotfixes { Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object HotFixID, Description, InstalledOn }
$checks.UpdateHistory = Invoke-AuditCheck UpdateHistory {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $count = $searcher.GetTotalHistoryCount()
    if ($count -gt 0) { $searcher.QueryHistory(0, [math]::Min(100, $count)) | Select-Object Date, Title, Operation, ResultCode, HResult }
}
$checks.CachedMissingUpdates = Invoke-AuditCheck CachedMissingUpdates -TimeoutSeconds 60 -Collect {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $searcher.Online = $false
    $result = $searcher.Search('IsInstalled=0 and IsHidden=0')
    [pscustomobject]@{ ResultCode = [int]$result.ResultCode; Source = 'Local Windows Update cache; may be stale'
        Updates = @($result.Updates | Select-Object Title, MsrcSeverity, @{n='KBArticleIDs';e={@($_.KBArticleIDs | ForEach-Object { [string]$_ })}}, RebootRequired) }
}
$checks.TimeService = Invoke-AuditCheck TimeService {
    $result = & w32tm.exe /query /status 2>&1
    if ($LASTEXITCODE -ne 0) { throw ($result -join "`n") }
    $result -join "`n"
}
$checks.PendingReboot = Invoke-AuditCheck PendingReboot {
    $sm = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    [pscustomobject]@{
        ComponentServicing = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        WindowsUpdate = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        PendingFileRename = [bool]$sm.PendingFileRenameOperations
    }
}
$checks.SecurityLog = Invoke-AuditCheck SecurityLog { Get-WinEvent -ListLog Security | Select-Object LogName, IsEnabled, LogMode, MaximumSizeInBytes, RecordCount, LastWriteTime }
foreach ($log in @('System', 'Application')) {
    $checks["${log}Events"] = Invoke-AuditCheck "${log}Events" -Context @{ Log=$log } -Collect { Get-AuditEvents -LogName $Log -Levels 1,2 }
}
$checks.FailedLogons = Invoke-AuditCheck FailedLogons { Get-AuditEvents -LogName Security -Ids 4625 }
$checks.BackupSoftware = Invoke-AuditCheck BackupSoftware {
    foreach ($path in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
        if (Test-Path $path) {
            Get-ItemProperty "$path\*" | Where-Object { $_.DisplayName -match $BackupPattern } |
                Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
        }
    }
}
$checks.BackupServices = Invoke-AuditCheck BackupServices {
    Get-CimInstance Win32_Service | Where-Object { "$($_.Name) $($_.DisplayName)" -match $BackupPattern -or $_.Name -in @('VSS','swprv','wbengine','SDRSVC') } |
        Select-Object Name, DisplayName, State, StartMode, ExitCode
}
$checks.BackupTasks = Invoke-AuditCheck BackupTasks {
    Get-ScheduledTask | Where-Object { "$($_.TaskPath) $($_.TaskName) $($_.Actions.Execute)" -match $BackupPattern } | ForEach-Object {
        $task = $_
        try {
            $info = $task | Get-ScheduledTaskInfo
            [pscustomobject]@{ TaskName=$task.TaskName; TaskPath=$task.TaskPath; State=[string]$task.State
                LastRunTime=$info.LastRunTime; NextRunTime=$info.NextRunTime; LastTaskResult=$info.LastTaskResult
                NumberOfMissedRuns=$info.NumberOfMissedRuns; Error=$null }
        } catch { [pscustomobject]@{ TaskName=$task.TaskName; TaskPath=$task.TaskPath; Error=$_.Exception.Message } }
    }
}
$checks.HyperVInventory = Invoke-AuditCheck HyperVInventory -Context @{ VMLimit=$MaxHyperVVMs } -Collect {
    Import-Module Hyper-V -ErrorAction Stop
    $vms=@(Get-VM -ErrorAction Stop | Sort-Object Name,Id)
    [pscustomobject]@{ RegisteredVMCount=$vms.Count; VMLimit=$VMLimit; OutputTruncated=($vms.Count -gt $VMLimit)
        VMs=@($vms | Select-Object -First $VMLimit | Select-Object Name,@{n='Id';e={[string]$_.Id}},
            @{n='State';e={[string]$_.State}},Status,Generation,Version,Path,ConfigurationLocation,
            SnapshotFileLocation,SmartPagingFilePath,ProcessorCount,MemoryAssigned,MemoryStartup,
            @{n='UptimeSeconds';e={$_.Uptime.TotalSeconds}},CheckpointType,AutomaticCheckpointsEnabled,
            AutomaticStartAction,AutomaticStopAction)
        OmittedVMs=@($vms | Select-Object -Skip $VMLimit | Select-Object Name,@{n='Id';e={[string]$_.Id}})
        Coverage='Local registered VMs only, including stopped VMs. Not a cluster-wide or guest-OS audit. VM inventory and checkpoints do not establish backup coverage. Missing newer properties remain null.' }
}
# Three separate bounded checks per VM: a blocked disk provider does not prevent
# integration/checkpoint checks or collection from other VMs. IDs avoid wildcards.
foreach ($vm in @($checks.HyperVInventory.Data | ForEach-Object { $_.VMs })) {
    if (-not $vm.Id) { continue }
    foreach ($kind in @('Disks','Integration','Checkpoints')) {
        $checkName="HyperV${kind}:$($vm.Id)"
        $checks[$checkName] = Invoke-AuditCheck $checkName -Context @{
            VMId=$vm.Id; DetailKind=$kind; DetailCode=${function:Get-AuditHyperVDetail}.ToString()
        } -Collect {
            Set-Item Function:Get-AuditHyperVDetail ([scriptblock]::Create($DetailCode))
            Get-AuditHyperVDetail -VMId $VMId -Kind $DetailKind
        }
    }
}
if ($checks.HyperVInventory.Status -eq 'Collected') {
    $checks.HyperVReplication = Invoke-AuditCheck HyperVReplication {
        Import-Module Hyper-V -ErrorAction Stop
        Get-VMReplication -ErrorAction Stop | Select-Object VMName,@{n='VMId';e={[string]$_.VMId}},
            State,Health,Mode,PrimaryServer,ReplicaServer,LastReplicationTime,LastApplyTime,
            @{n='Coverage';e={'Replication health is not backup success, retention or a restore test.'}}
    }
    foreach ($log in @('Microsoft-Windows-Hyper-V-VMMS-Admin','Microsoft-Windows-Hyper-V-Worker-Admin','Microsoft-Windows-Hyper-V-Integration-Admin')) {
        $checkName="HyperVLog:$log"
        $checks[$checkName] = Invoke-AuditCheck $checkName -Context @{ Log=$log } -Collect {
            Get-AuditEvents -LogName $Log -IncludeMessage
        }
    }
}
$checks.WindowsBackupSummary = Invoke-AuditCheck WindowsBackupSummary {
    Import-Module WindowsServerBackup -ErrorAction Stop
    Get-WBSummary | Select-Object LastBackupTime, LastBackupResultHR, LastSuccessfulBackupTime, NextBackupTime,
        NumberOfVersions, LastBackupTarget, LastSuccessfulBackupTarget
}
$checks.WindowsBackupPolicy = Invoke-AuditCheck WindowsBackupPolicy {
    Import-Module WindowsServerBackup -ErrorAction Stop
    $policy = Get-WBPolicy
    if ($null -eq $policy) { [pscustomobject]@{ PolicyConfigured=$false }; return }
    [pscustomobject]@{ PolicyConfigured=$true
        Schedule=@(Get-WBSchedule -Policy $policy | ForEach-Object { $_.ToString() })
        Targets=@(Get-WBBackupTarget -Policy $policy | Select-Object TargetType, Label, DiskIdentifier, VolumePath, NetworkPath)
        Volumes=@(Get-WBVolume -Policy $policy | Select-Object VolumeName, MountPath)
        Files=@(Get-WBFileSpec -Policy $policy | Select-Object FilePath, Recursive, Exclude)
        SystemState=Get-WBSystemState -Policy $policy
        BareMetalRecovery=Get-WBBareMetalRecovery -Policy $policy
        VssOptions=[string](Get-WBVssBackupOptions -Policy $policy) }
}
$checks.WindowsBackupCatalog = Invoke-AuditCheck WindowsBackupCatalog {
    Import-Module WindowsServerBackup -ErrorAction Stop
    $sets = @(Get-WBBackupSet | Sort-Object BackupTime -Descending)
    [pscustomobject]@{ TotalVersions=$sets.Count; OutputTruncated=($sets.Count -gt 20)
        Versions=@($sets | Select-Object -First 20 | Select-Object BackupTime, VersionId, BackupTarget, BackupType) }
}
$checks.WbadminVersions = Invoke-AuditCheck WbadminVersions {
    # Read the local catalog only; no -backupTarget, remote mount or backup action.
    $result = & wbadmin.exe get versions 2>&1
    if ($LASTEXITCODE -ne 0) { throw ($result -join "`n") }
    $result -join "`n"
}
$checks.VSSWriters = Invoke-AuditCheck VSSWriters {
    $result = & vssadmin.exe list writers 2>&1
    if ($LASTEXITCODE -ne 0) { throw ($result -join "`n") }
    $result -join "`n"
}
$checks.ShadowCopies = Invoke-AuditCheck ShadowCopies {
    Get-CimInstance Win32_ShadowCopy | Select-Object ID, InstallDate, VolumeName, State, Persistent, ClientAccessible, NoAutoRelease
}
$checks.ShadowStorage = Invoke-AuditCheck ShadowStorage {
    # Export only reference IDs, not the recursive CIM class/property metadata.
    Get-CimInstance Win32_ShadowStorage | Select-Object @{n='Volume';e={[string]$_.Volume.DeviceID}},
        @{n='DiffVolume';e={[string]$_.DiffVolume.DeviceID}}, UsedSpace, AllocatedSpace, MaxSpace
}
$checks.BackupLogDiscovery = Invoke-AuditCheck BackupLogDiscovery {
    # Discover registered names without opening every event log on the machine.
    $names = @(
        foreach ($path in @('SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels', 'SYSTEM\CurrentControlSet\Services\EventLog')) {
            $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($path)
            if ($null -eq $key) { continue }
            try { $key.GetSubKeyNames() | Where-Object { $_ -match $BackupPattern } }
            finally { $key.Dispose() }
        }
    )
    $names | Sort-Object -Unique | ForEach-Object { [pscustomobject]@{LogName=$_} }
}
# Query Windows Backup explicitly even when discovery is unavailable; then each
# discovered vendor channel separately so one slow channel cannot block the rest.
$backupLogs = @('Microsoft-Windows-Backup') + @($checks.BackupLogDiscovery.Data | ForEach-Object { $_.LogName } | Where-Object { $_ -and $_ -ne 'Microsoft-Windows-Backup' } | Sort-Object -Unique)
foreach ($log in ($backupLogs | Select-Object -First 12)) {
    $name = "BackupLog:$log"
    $checks[$name] = Invoke-AuditCheck $name -Context @{ Log=$log } -Collect {
        Get-AuditEvents -LogName $Log -IncludeMessage:($Log -match 'Veeam') -IncludeEventData:($Log -match 'Veeam')
    }
    if ($log -match 'Veeam') {
        $errorName="VeeamEventErrors:$log"
        $checks[$errorName] = Invoke-AuditCheck $errorName -Context @{Log=$log} -Collect {
            Get-AuditEvents -LogName $Log -Levels 1,2,3 -IncludeMessage -IncludeEventData
        }
    }
}
# Local Veeam text logs supplement rendered event messages; never connect to a
# backup server, read credentials, start jobs, or load the Veeam configuration DB.
$veeamDetected = @($checks.Software.Data | Where-Object { $_.DisplayName -match 'Veeam' }).Count -gt 0 -or
    @($checks.AgentServices.Data | Where-Object { $_.Name -match 'Veeam' }).Count -gt 0 -or
    @($backupLogs | Where-Object { $_ -match 'Veeam' }).Count -gt 0
if ($veeamDetected -or $VeeamLogDirectory) {
    $checks.VeeamApplicationDetails = Invoke-AuditCheck VeeamApplicationDetails {
        Get-AuditEvents -LogName Application -ProviderPattern 'Veeam' -IncludeMessage -IncludeEventData
    }
    $checks.VeeamLogDiscovery = Invoke-AuditCheck VeeamLogDiscovery -Context @{
        RequestedRoot=$VeeamLogDirectory;FileLimit=$MaxVeeamLogFiles;FinderCode=${function:Find-AuditVeeamLogs}.ToString()
    } -Collect {
        Set-Item Function:Find-AuditVeeamLogs ([scriptblock]::Create($FinderCode))
        $root=$RequestedRoot
        if (-not $root) {
            $config=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Veeam\Veeam Backup and Replication' -Name LogDirectory -ErrorAction SilentlyContinue
            $root=$config.LogDirectory
            if (-not $root) { $root=Join-Path $env:ProgramData 'Veeam\Backup' }
        }
        Find-AuditVeeamLogs -Root $root -Since $since -FileLimit $FileLimit
    }
    $selectedLogs=@($checks.VeeamLogDiscovery.Data | ForEach-Object { $_.Files } | ForEach-Object { $_.Path })
    if ($selectedLogs.Count) {
        $checks.VeeamFileLogDetails = Invoke-AuditCheck VeeamFileLogDetails -TimeoutSeconds 60 -Context @{
            Paths=$selectedLogs;ReaderCode=${function:Read-AuditVeeamLog}.ToString()
        } -Collect {
            Set-Item Function:Read-AuditVeeamLog ([scriptblock]::Create($ReaderCode))
            foreach ($path in $Paths) { Read-AuditVeeamLog -Path $path }
        }
    }
}
$checks.BackupApplicationEvents = Invoke-AuditCheck BackupApplicationEvents { Get-AuditEvents -LogName Application -ProviderPattern $BackupPattern }
$checks.DatabaseEvents = Invoke-AuditCheck DatabaseEvents {
    Get-AuditEvents -LogName Application -Levels 1,2 -ProviderPattern '^(MSSQLSERVER|MSSQL\$|SQLAgent|SQLBrowser|MySQL|MariaDB|OracleService|OracleOraDb|PostgreSQL)'
}
$checks.ClinicalApplication = Invoke-AuditCheck ClinicalApplication {
    [pscustomobject]@{ PSChiroDirectoryPresent=(Test-Path 'C:\Program Files\PSChiro')
        Note='Directory presence only; does not establish application encryption or configuration.' }
}
$checks.VSSSystemEvents = Invoke-AuditCheck VSSSystemEvents { Get-AuditEvents -LogName System -ProviderPattern 'VSS|VolSnap|SPP|disk|Ntfs' -Levels 1,2,3 }
$checks.ShareNTFSPermissions = Invoke-AuditCheck ShareNTFSPermissions {
    Get-SmbShare | Where-Object { -not $_.Special -and $_.Path } | ForEach-Object {
        $share = $_
        try {
            $acl = Get-Acl -LiteralPath $share.Path -ErrorAction Stop
            [pscustomobject]@{ ShareName=$share.Name; Path=$share.Path; Status='Collected'; Owner=$acl.Owner
                InheritanceDisabled=$acl.AreAccessRulesProtected
                Rules=@($acl.Access | ForEach-Object { [pscustomobject]@{
                    Identity=[string]$_.IdentityReference; Rights=[string]$_.FileSystemRights
                    Type=[string]$_.AccessControlType; Inherited=$_.IsInherited
                    Inheritance=[string]$_.InheritanceFlags; Propagation=[string]$_.PropagationFlags } })
                Coverage='Share root only; child ACLs and effective user access are not evaluated.'; Error=$null }
        } catch { [pscustomobject]@{ ShareName=$share.Name; Path=$share.Path; Status='Unavailable'; Error=$_.Exception.Message } }
    }
}
$checks.DeviceRegistration = Invoke-AuditCheck DeviceRegistration {
    $output = & dsregcmd.exe /status 2>&1
    if ($LASTEXITCODE -ne 0) { throw ($output -join "`n") }
    $fields = [ordered]@{}
    foreach ($line in $output) {
        if ([string]$line -match '^\s*(AzureAdJoined|EnterpriseJoined|DomainJoined|DomainName|DeviceAuthStatus|WorkplaceJoined|TenantName|TenantId|AzureAdPrt|EnterprisePrt)\s*:\s*(.*?)\s*$') {
            $fields[$matches[1]]=$matches[2]
        }
    }
    if (-not $fields.Count) { throw 'No recognized device-registration fields returned.' }
    [pscustomobject]@{ Fields=[pscustomobject]$fields; Coverage='Current elevated user context only. Registration and PRT presence do not prove MFA enforcement.' }
}
$checks.RemoteAccessFirewall = Invoke-AuditCheck RemoteAccessFirewall {
    # ActiveStore merges local and applied policy. Include Any and numeric port
    # ranges covering SMB, RDP, WinRM or SSH; dynamic port tokens stay visible.
    $ports = @(22,445,3389,5985,5986)
    $rdp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue
    if ($rdp.PortNumber) { $ports += [int]$rdp.PortNumber }
    Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound -Action Allow | ForEach-Object {
        $rule = $_
        $filters = @($rule | Get-NetFirewallPortFilter)
        $relevant = $false
        foreach ($filter in $filters) {
            foreach ($token in @($filter.LocalPort)) {
                if ($token -eq 'Any') { $relevant=$true }
                elseif ($token -match '^(\d+)-(\d+)$') {
                    $lo=[int]$matches[1]; $hi=[int]$matches[2]
                    if (@($ports | Where-Object { $_ -ge $lo -and $_ -le $hi }).Count) { $relevant=$true }
                } elseif ($token -match '^\d+$') { if ([int]$token -in $ports) { $relevant=$true } }
                else { $relevant=$true }
            }
        }
        if ($relevant) {
            [pscustomobject]@{ Name=$rule.Name; DisplayName=$rule.DisplayName; Profile=[string]$rule.Profile
                Ports=@($filters | Select-Object @{n='Protocol';e={[string]$_.Protocol}},LocalPort,RemotePort)
                Addresses=@($rule | Get-NetFirewallAddressFilter | Select-Object LocalAddress,RemoteAddress)
                Applications=@($rule | Get-NetFirewallApplicationFilter | Select-Object Program,Package)
                Coverage='Enabled inbound allow rules only. Blocking rules, application/service restrictions and upstream firewalls affect reachability.' }
        }
    }
}
$checks.LocalNATMappings = Invoke-AuditCheck LocalNATMappings {
    Get-NetNatStaticMapping | Select-Object NatName, Protocol, ExternalIPAddress, ExternalPort, InternalIPAddress, InternalPort
}
$checks.DefaultRoutes = Invoke-AuditCheck DefaultRoutes {
    Get-NetRoute | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','::/0') } |
        Select-Object InterfaceAlias,DestinationPrefix,NextHop,RouteMetric,InterfaceMetric,State
}
$checks.TimeConfiguration = Invoke-AuditCheck TimeConfiguration {
    $service = Get-CimInstance Win32_Service -Filter "Name='W32Time'"
    $config = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
    [pscustomobject]@{ ServiceStatus=[string]$service.State; StartupType=[string]$service.StartMode
        ConfiguredType=$config.Type; ConfiguredNtpServer=$config.NtpServer
        Coverage='Configuration only. TimeService check reports measured synchronization status when available.' }
}
$checks.EventForwarding = Invoke-AuditCheck EventForwarding {
    $path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'
    $values=@()
    if (Test-Path $path) {
        $item=Get-ItemProperty $path
        $values=@($item.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { [string]$_.Value })
    }
    [pscustomobject]@{ SubscriptionManagers=$values
        Coverage='Local policy only; third-party forwarding, receipt at the collector and central retention need console evidence.' }
}
if (-not $SkipOnlineUpdateScan) {
    $checks.LiveMissingUpdates = Invoke-AuditCheck LiveMissingUpdates -TimeoutSeconds 90 -Collect {
        $session=New-Object -ComObject Microsoft.Update.Session
        $searcher=$session.CreateUpdateSearcher(); $searcher.Online=$true
        $result=$searcher.Search('IsInstalled=0 and IsHidden=0')
        [pscustomobject]@{ ResultCode=[int]$result.ResultCode; Source='Current scan against the configured Windows Update service'
            CheckedAt=(Get-Date).ToString('o'); ServerSelection=[string]$searcher.ServerSelection
            Updates=@($result.Updates | Select-Object Title,MsrcSeverity,@{n='KBArticleIDs';e={@($_.KBArticleIDs | ForEach-Object { [string]$_ })}},RebootRequired) }
    }
}
$checks.BackupErrorDetails = Invoke-AuditCheck BackupErrorDetails {
    Get-AuditEvents -LogName Application -Levels 1,2,3 -ProviderPattern $BackupPattern -IncludeMessage
}
$checks.VSSErrorDetails = Invoke-AuditCheck VSSErrorDetails {
    Get-AuditEvents -LogName System -Levels 1,2,3 -ProviderPattern 'VSS|VolSnap' -IncludeMessage
}
$evidenceTemplate = New-ExternalEvidenceTemplate -ComputerName $env:COMPUTERNAME
$evidenceTemplatePath = Join-Path $OutputDirectory "$prefix-EVIDENCE-TEMPLATE.json"
[IO.File]::WriteAllText($evidenceTemplatePath, (ConvertTo-AuditJson -InputObject $evidenceTemplate -Depth 6), (New-Object Text.UTF8Encoding($false)))
$checks.ExternalEvidence = Invoke-AuditCheck ExternalEvidence -Context @{
    EvidencePath=$EvidenceFile; Template=$evidenceTemplate; ReaderCode=${function:Read-ExternalEvidence}.ToString()
} -Collect {
    Set-Item Function:Read-ExternalEvidence ([scriptblock]::Create($ReaderCode))
    Read-ExternalEvidence -Path $EvidencePath -Template $Template
}
$report = [ordered]@{
    SchemaVersion = '1.8'; AuditId = $script:auditId; Incomplete = $false; ClientName = $ClientName; Location = $Location
    StartedAt = $started.ToString('o'); CompletedAt = (Get-Date).ToString('o'); Elevated = $elevated
    PowerShellVersion = $PSVersionTable.PSVersion.ToString(); Checks = $checks
    ExportWarnings = @($script:checkpointWarnings)
    OnlineUpdateScanRequested = (-not $SkipOnlineUpdateScan)
    ExternalEvidenceTemplate = $evidenceTemplatePath
    BackupLogsNotQueried = @($backupLogs | Select-Object -Skip 12)
    InterpretationNotes = @(
        'Windows PowerShell 4.0 and later are targeted. On Server 2012 R2, local-account and administrator membership queries use CIM fallbacks when LocalAccounts is absent. Missing provider timestamps remain unknown.'
        'Collected means the query completed, not that the control passed. Unavailable, TimedOut, Partial and null values require follow-up; returned partial evidence is incomplete.'
        'Event queries inspect only the newest EventScanLimit records per log, then filter by time/provider/severity. Scan limits, oldest record time and output truncation are recorded. Event metadata is exported; BackupErrorDetails and VSSErrorDetails also include bounded message text with best-effort labelled-secret scrubbing. Failed logons include all logon types, not just RDP.'
        'Veeam event channels include bounded messages and EventData plus a separate warning/error sample. Veeam text-log discovery and tail reads are capped and local-only. Keyword lines are raw evidence, not inferred job success. Missing logs and truncated samples leave recovery and coverage unknown.'
        'Software inventory covers machine-wide uninstall registrations; the general scheduled task list excludes Microsoft tasks, but backup task discovery includes them.'
        'Update history is capped at 100. Missing updates use a potentially stale local cache only; ResultCode 2 means success, 3 means success with errors. LiveMissingUpdates performs a current scan unless explicitly skipped; its status and result code must be checked. Hotfix inventory is not proof of patch compliance.'
        'HyperVInventory covers local registered VMs up to MaxHyperVVMs (default 50); omitted IDs/names are explicit. Per-VM disk/integration/checkpoint checks have independent timeouts. Only local VHD metadata and immediate parent paths are read. Hyper-V event messages are bounded and scrubbed like backup messages. Checkpoints, integration status and replication are not vendor job success or tested recovery.'
        'Windows backup catalogs and shadow copies are local evidence, not proof of offsite copies or a successful restore. Task exit codes need vendor interpretation.'
        'Service or software detection does not establish agent health, backup success, encryption, or restore readiness.'
        'Listening ports and RDP settings do not establish internet exposure.'
        'ShareNTFSPermissions covers custom share roots only; inherited/child exceptions and effective user access need validation. Password policy is local evidence and may be overridden by domain policy.'
        'No passwords, recovery keys or scheduled task action arguments are intentionally collected. Backup/VSS event messages may include filenames, accounts or other sensitive details; review before sharing.'
        'ExternalEvidence is user-supplied and not independently verified. Unknown controls remain unknown; device registration, local firewall rules and service presence do not prove MFA, public exposure or backup success.'
    )
    ManualEvidenceRequired = @('Backup last success and failures from vendor console', 'Backup encryption, offsite retention and restore test',
        'Per-VM vendor backup mapping, application consistency and isolated VM restore test',
        'RMM and EDR console health', 'MFA and VPN enforcement', 'External firewall/NAT exposure',
        'OS support lifecycle including edition, servicing channel and ESU entitlement', 'Organizational policies and compliance review')
}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$compact = ConvertTo-AuditJson -InputObject $report -Depth 14
$json = $compact
$encoding = New-Object System.Text.UTF8Encoding($false)
$jsonPath = Join-Path $OutputDirectory "$prefix.json"
[IO.File]::WriteAllText($jsonPath, $json, $encoding)
$blocks = @(New-PasteBlocks -Json $compact -Size $PasteBlockCharacters -Id $report.AuditId)
$intro = "Please turn this Windows audit evidence into a polished report with an executive summary, evidence-based findings, priorities and remediation steps. Keep unavailable checks and manual verification separate from confirmed findings. Wait for all $($blocks.Count) parts before analyzing."
$paste = $intro + "`r`n`r`n" + ($blocks -join "`r`n`r`n")
$textPath = Join-Path $OutputDirectory "$prefix-PASTE.txt"
[IO.File]::WriteAllText($textPath, $paste, $encoding)
for ($i = 0; $i -lt $blocks.Count; $i++) {
    $partPath = Join-Path $OutputDirectory ("$prefix-PART-{0:D2}.txt" -f ($i + 1))
    [IO.File]::WriteAllText($partPath, ($intro + "`r`n`r`n" + $blocks[$i]), $encoding)
}
if ($CopyToClipboard) {
    try { Copy-AuditText -Text $paste; Write-Host 'Paste text copied to clipboard.' }
    catch { Write-Warning "Clipboard unavailable. Open $textPath instead." }
}
Remove-Item -LiteralPath $script:checkpointPath -ErrorAction SilentlyContinue
Write-Host "Audit saved: $jsonPath"
Write-Host "External evidence template: $evidenceTemplatePath (fill from consoles/tests, then rerun with -EvidenceFile)."
Write-Host "Paste report: $textPath ($($blocks.Count) numbered parts)"
Write-Host 'Review identifying information before sharing. Paste all parts here to generate your report.'
if (-not $elevated) { Write-Warning 'Not elevated: rerun as Administrator for the fullest audit.' }

if (-not $NoOpen) {
    try {
        # Quote paths containing spaces, including redirected OneDrive desktops.
        Start-Process -FilePath 'notepad.exe' -ArgumentList ('"' + $textPath + '"') -ErrorAction Stop | Out-Null
    } catch { Write-Warning "Could not open Notepad automatically. Open this file manually: $textPath" }
}
