#requires -Version 4.0
<#
.SYNOPSIS
Read-only evidence for a Windows Backup that appears stuck, including NAS targets.
.DESCRIPTION
Does not stop backups, change services, repair disks, create snapshots, or write
files to the backup destination. Native status readers and worker queries are bounded.
The wbadmin status reader is closed after sampling; the backup engine is left running.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^\\\\[^\\]+\\[^\\]+')][string]$BackupTarget,
    [ValidateRange(10,60)][int]$SampleSeconds = 30,
    [ValidateRange(1,168)][int]$LookbackHours = 12,
    [string]$ABBServer = '',
    [string]$TaskNamePattern = 'backup|tracs|synology',
    [switch]$IncludeSqlBackupHistory,
    [string]$OutputDirectory = '',
    [switch]$NoOpen
)
function Invoke-BackupDiagnosticSection {
    param([string]$Name, [scriptblock]$Collect, [hashtable]$Context=@{}, [int]$TimeoutSeconds=25)
    Write-Host "Collecting $Name (limit ${TimeoutSeconds}s)..."
    $job=$null; $rows=@(); $status='Unavailable'; $detail=''; $timer=[Diagnostics.Stopwatch]::StartNew()
    try {
        $job=Start-Job -ArgumentList $Collect.ToString(),$Context -ScriptBlock {
            param($Code,$Variables)
            $ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'
            foreach ($key in $Variables.Keys) { Set-Variable -Name $key -Value $Variables[$key] }
            & ([scriptblock]::Create($Code)) | ForEach-Object {
                if ($_ -is [string]) { $_ } else { ConvertTo-Json -InputObject $_ -Depth 7 -Compress }
            }
        }
        while ($job.State -in @('NotStarted','Running') -and $timer.Elapsed.TotalSeconds -lt $TimeoutSeconds) { $null=Wait-Job $job -Timeout 1 }
        $timedOut=$job.State -in @('NotStarted','Running')
        if ($timedOut) { Stop-Job $job -ErrorAction SilentlyContinue }
        $workerErrors=@()
        $rows=@(Receive-Job $job -ErrorAction SilentlyContinue -ErrorVariable workerErrors)
        if ($timedOut) { $status='TimedOut'; $detail='Partial data only; later sections will continue.' }
        elseif ($workerErrors.Count -or $job.State -ne 'Completed') { $status=if ($rows.Count) {'Partial'} else {'Unavailable'}; $detail=($workerErrors | ForEach-Object {$_.ToString()}) -join '; ' }
        else { $status='Collected' }
    } catch { $detail=$_.Exception.Message }
    finally { if ($job) { Remove-Job $job -Force -ErrorAction SilentlyContinue } }
    $body=($rows | ForEach-Object {[string]$_}) -join "`r`n"
    if ($body.Length -gt 250000) { $body=$body.Substring(0,250000)+"`r`n[Section output truncated at 250000 characters]" }
    "`r`n===== $Name | $status | $([math]::Round($timer.Elapsed.TotalSeconds,1)) seconds =====`r`n$detail`r`n$body`r`n"
}
function Get-BackupDiagnosticEvents {
    param([string]$LogName, [string]$ProviderPattern, [int[]]$Levels=@(), [string]$Incident='', [int]$Limit=30, [int]$LookbackHours=12)
    $info=Get-WinEvent -ListLog $LogName -ErrorAction Stop
    if (-not $info.IsEnabled -or $info.RecordCount -eq 0) { [pscustomobject]@{Log=$LogName;Enabled=$info.IsEnabled;RecordsInLog=$info.RecordCount}; return }
    $records=@(); $scanLimit=3000
    try {
        if ($Incident) {
            $time=[datetime]::ParseExact($Incident,'yyyy-MM-ddTHH:mm:ss',[Globalization.CultureInfo]::InvariantCulture)
            $records=@(Get-WinEvent -FilterHashtable @{LogName=$LogName;StartTime=$time.AddMinutes(-10);EndTime=$time.AddMinutes(10)} -MaxEvents $scanLimit -ErrorAction Stop)
        } else { $records=@(Get-WinEvent -FilterHashtable @{LogName=$LogName;StartTime=(Get-Date).AddHours(-$LookbackHours)} -MaxEvents $scanLimit -ErrorAction Stop) }
    } catch { if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw } }
    $matches=@($records | Where-Object { $_.ProviderName -match $ProviderPattern -and (-not $Levels.Count -or $_.Level -in $Levels) -and ($Incident -or $_.TimeCreated -ge (Get-Date).AddHours(-$LookbackHours)) })
    [pscustomobject]@{Log=$LogName;IncidentWindowLocal=$Incident;LookbackHours=$LookbackHours;NewestRecordLimit=$scanLimit;RecordsRead=$records.Count;ReadLimitReached=($records.Count -ge $scanLimit)
        OldestRead=if ($records.Count) {$records[-1].TimeCreated.ToString('o')} else {$null};Matched=$matches.Count;ReturnedLimit=$Limit;OutputTruncated=($matches.Count -gt $Limit)
        Coverage='Recent-record sample or +/-10 minute incident window in this computer local time. Missing matches do not establish absence of incidents.'}
    foreach ($event in ($matches | Select-Object -First $Limit)) {
        $message=$null; $xml=$null; $messageError=$null; $xmlError=$null; $messageTruncated=$false; $xmlTruncated=$false
        try {
            $message=[string]$event.Message
            # Labels only, best effort; paths/device identifiers remain useful diagnostic evidence.
            $message=$message -replace '(?i)((?:password|pwd|token|secret)\s*[:=]\s*)\S+','$1[REDACTED]'
            if ($message.Length -gt 3000) { $message=$message.Substring(0,3000); $messageTruncated=$true }
        } catch { $messageError=$_.Exception.Message }
        # Event 51 XML includes binary status/SCSI details needed for diagnosis.
        if ($event.Id -eq 51 -and $event.ProviderName -match '(^|-)disk$') {
            try { $xml=$event.ToXml(); if ($xml.Length -gt 16000) { $xml=$xml.Substring(0,16000); $xmlTruncated=$true } }
            catch { $xmlError=$_.Exception.Message }
        }
        [pscustomobject]@{TimeLocal=$event.TimeCreated.ToString('o');TimeUTC=$event.TimeCreated.ToUniversalTime().ToString('o');Id=$event.Id;RecordId=$event.RecordId
            Provider=$event.ProviderName;Level=$event.LevelDisplayName;Message=$message;MessageError=$messageError;MessageTruncated=$messageTruncated
            Event51Xml=$xml;XmlError=$xmlError;XmlTruncated=$xmlTruncated}
    }
}
function Invoke-BackupStatusReader {
    param([string]$FilePath,[string]$Arguments,[int]$Seconds=10,[int]$TextLimit=16000)
    $process=New-Object Diagnostics.Process
    $started=$false; $timedOut=$false; $exitCode=$null; $stdout=''; $stderr=''; $captureError=$null
    $start=Get-Date
    try {
        $process.StartInfo.FileName=$FilePath
        $process.StartInfo.Arguments=$Arguments
        $process.StartInfo.UseShellExecute=$false
        $process.StartInfo.CreateNoWindow=$true
        $process.StartInfo.RedirectStandardOutput=$true
        $process.StartInfo.RedirectStandardError=$true
        $started=$process.Start()
        $readerId=$process.Id
        # Drain BOTH pipes asynchronously so a verbose command cannot deadlock.
        $outTask=$process.StandardOutput.ReadToEndAsync()
        $errTask=$process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($Seconds*1000)) {
            $timedOut=$true
            # Only this newly-created read-only console client, never wbengine or a service.
            if (-not $process.HasExited) { $process.Kill() }
        }
        $exited=$process.WaitForExit(2000)
        if ($exited) { $exitCode=$process.ExitCode }
        if ($outTask.Wait(2000)) { $stdout=$outTask.Result } else { $captureError='Standard output drain timed out.' }
        if ($errTask.Wait(2000)) { $stderr=$errTask.Result } else { $captureError+=' Standard error drain timed out.' }
        $truncated=($stdout.Length -gt $TextLimit -or $stderr.Length -gt $TextLimit)
        if ($stdout.Length -gt $TextLimit) { $stdout=$stdout.Substring(0,$TextLimit) }
        if ($stderr.Length -gt $TextLimit) { $stderr=$stderr.Substring(0,$TextLimit) }
        [pscustomobject]@{Command=([IO.Path]::GetFileName($FilePath)+' '+$Arguments);StartedLocal=$start.ToString('o');EndedLocal=(Get-Date).ToString('o')
            ReaderProcessId=$readerId;ReaderTimeLimitReached=$timedOut;ReaderExited=$exited;ExitCode=$exitCode;OutputTruncated=$truncated
            StandardOutput=$stdout;StandardError=$stderr;CaptureError=$captureError
            Meaning='A reader time limit is not a backup failure. wbadmin get status can keep reporting until the backup completes. Only the diagnostic reader is closed.'}
    } finally {
        if ($started -and -not $process.HasExited) { $process.Kill(); $null=$process.WaitForExit(2000) }
        $process.Dispose()
    }
}
function Get-BackupActivitySample {
    $sample=[ordered]@{StartedLocal=(Get-Date).ToString('o');Processes=@();Services=@();Network=@();DiskPerformance=@();NasTcp=@();Errors=@()}
    try {
        $services=@(Get-CimInstance Win32_Service -OperationTimeoutSec 8 | Where-Object {$_.Name -match '^(wbengine|SDRSVC|VSS|swprv)$|Synology|Veeam'} |
            Select-Object -First 64 Name,State,ProcessId,StartName)
        $sample.Services=$services
        $serviceIds=@($services | Where-Object {$_.ProcessId -gt 0} | ForEach-Object {$_.ProcessId})
        $sample.Processes=@(Get-CimInstance Win32_Process -OperationTimeoutSec 8 | Where-Object {
            $_.ProcessId -in $serviceIds -or $_.Name -match 'wbengine|sdclt|synology|cloud-drive|cloudstation|vss-service|veeam'
        } | Select-Object -First 64 Name,ProcessId,CreationDate,ReadTransferCount,WriteTransferCount,OtherTransferCount,KernelModeTime,UserModeTime,WorkingSetSize,ThreadCount,HandleCount)
    } catch { $sample.Errors+=('Processes/services: '+$_.Exception.Message) }
    try { $sample.Network=@(Get-NetAdapterStatistics -ErrorAction Stop | Select-Object -First 32 Name,InterfaceDescription,ReceivedBytes,SentBytes,ReceivedPacketErrors,OutboundPacketErrors,ReceivedDiscardedPackets,OutboundDiscardedPackets) }
    catch { $sample.Errors+=('Adapter counters: '+$_.Exception.Message) }
    try { $sample.DiskPerformance=@(Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk -OperationTimeoutSec 8 | Select-Object -First 32 Name,CurrentDiskQueueLength,DiskReadBytesPersec,DiskWriteBytesPersec,DiskReadsPersec,DiskWritesPersec,PercentIdleTime) }
    catch { $sample.Errors+=('Disk performance: '+$_.Exception.Message) }
    try { $sample.NasTcp=@(Get-NetTCPConnection -RemotePort 445 -ErrorAction Stop | Where-Object {$_.RemoteAddress -eq $NasHost -or $_.RemoteAddress -in $NasAddresses} | Select-Object -First 32 LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess) }
    catch { $sample.Errors+=('NAS TCP (no connections or unavailable): '+$_.Exception.Message) }
    $sample.EndedLocal=(Get-Date).ToString('o')
    [pscustomobject]$sample
}
function Get-BackupCounterDelta {
    param($Before,$After,[string[]]$Keys,[string[]]$Counters)
    foreach ($current in @($After)) {
        $previous=$null
        foreach ($candidate in @($Before)) {
            $same=$true
            foreach ($key in $Keys) {
                # No delta when the identity is missing (including process creation time).
                if ($null -eq $candidate.$key -or $null -eq $current.$key -or [string]$candidate.$key -ne [string]$current.$key) { $same=$false; break }
            }
            if ($same) { $previous=$candidate; break }
        }
        $row=[ordered]@{}
        foreach ($key in $Keys) { $row[$key]=$current.$key }
        $row.MatchedEarlierSample=($null -ne $previous)
        $row.UnavailableOrResetCounters=@()
        foreach ($counter in $Counters) {
            $row[$counter+'Delta']=$null
            if ($null -ne $previous -and $null -ne $previous.$counter -and $null -ne $current.$counter -and [decimal]$current.$counter -ge [decimal]$previous.$counter) {
                $row[$counter+'Delta']=[decimal]$current.$counter-[decimal]$previous.$counter
            } else { $row.UnavailableOrResetCounters+=$counter }
        }
        [pscustomobject]$row
    }
}
function Find-BackupEvidenceFiles {
    param([string]$Root,[int]$Depth=2,[int]$EntryLimit=1000,[int]$DirectoryLimit=40)
    $queue=New-Object Collections.Queue
    $queue.Enqueue(@($Root,0));$entries=0;$directories=0;$skipped=0
    while ($queue.Count -and $entries -lt $EntryLimit -and $directories -lt $DirectoryLimit) {
        $item=$queue.Dequeue();$directories++
        try {
            # Lazy enumeration avoids materializing a large NAS directory before applying limits.
            foreach ($path in [IO.Directory]::EnumerateFileSystemEntries([string]$item[0])) {
                if ($entries -ge $EntryLimit) { break };$entries++
                try {
                    $attributes=[IO.File]::GetAttributes($path)
                    if ($attributes -band [IO.FileAttributes]::ReparsePoint) { $skipped++;continue }
                    if ($attributes -band [IO.FileAttributes]::Directory) {
                        if ([int]$item[1] -lt $Depth -and $queue.Count -lt $DirectoryLimit) { $queue.Enqueue(@($path,([int]$item[1]+1))) } else { $skipped++ }
                    } else {
                        $file=New-Object IO.FileInfo($path)
                        [pscustomobject]@{Kind='File';Path=$path;Length=$file.Length;ModifiedUTC=$file.LastWriteTimeUtc.ToString('o');Extension=$file.Extension}
                    }
                } catch { [pscustomobject]@{Kind='Error';Path=$path;Error=$_.Exception.Message} }
            }
        } catch { [pscustomobject]@{Kind='Error';Path=$item[0];Error=$_.Exception.Message} }
    }
    [pscustomobject]@{Kind='Coverage';Root=$Root;EntriesExamined=$entries;DirectoriesExamined=$directories;EntryLimit=$EntryLimit;DirectoryLimit=$DirectoryLimit;DepthLimit=$Depth;Skipped=$skipped;LimitReached=($queue.Count -gt 0 -or $entries -ge $EntryLimit);Meaning='Bounded metadata sample, not a complete inventory. Reparse points skipped. Missing files do not establish missing backups.'}
}
function Read-BackupTextTail {
    param([string]$Path,[int]$ByteLimit=65536)
    $stream=$null
    try {
        $stream=New-Object IO.FileStream($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        $bom=New-Object byte[] 3;$n=$stream.Read($bom,0,3)
        $encoding=[Text.Encoding]::UTF8
        if ($n -ge 2 -and $bom[0] -eq 255 -and $bom[1] -eq 254) {$encoding=[Text.Encoding]::Unicode}
        if ($n -ge 2 -and $bom[0] -eq 254 -and $bom[1] -eq 255) {$encoding=[Text.Encoding]::BigEndianUnicode}
        $offset=[math]::Max(0,$stream.Length-$ByteLimit)
        if ($encoding.CodePage -in @(1200,1201) -and $offset%2) {$offset++}
        $null=$stream.Seek($offset,[IO.SeekOrigin]::Begin)
        $bytes=New-Object byte[] $ByteLimit;$count=$stream.Read($bytes,0,$bytes.Length)
        $raw=$encoding.GetString($bytes,0,$count)
        if ($offset -gt 0) {$raw=$raw -replace '^[^\n]*\n',''}
        $lines=@();$omitted=0;$matched=0
        foreach ($line in ($raw -split '\r?\n')) {
            if ($line -match '(?i)password|passwd|\bpwd\b|secret|token|authorization|credential|private.key|connectionstring') {$omitted++;continue}
            if ($line -notmatch '(?i)backup|success|complet|fail|error|warn|connect|progress|upload|transfer|snapshot|\bVSS\b') {continue}
            $matched++;$lines+=($line.Substring(0,[math]::Min(700,$line.Length)))
        }
        [pscustomobject]@{Path=$Path;BytesRead=$count;Encoding=$encoding.WebName;TailTruncated=($offset -gt 0);MatchingLines=$matched;Lines=@($lines | Select-Object -Last 12);OutputTruncated=($matched -gt 12);SensitiveLinesOmitted=$omitted;Meaning='Local text hints only. Timestamps are not normalized. No matched text does not prove success; product console is authoritative.'}
    } finally {if ($stream) {$stream.Dispose()}}
}

function New-BackupSqlConnectionString {
    param([string]$Instance)
    $builder=New-Object Data.SqlClient.SqlConnectionStringBuilder
    # PowerShell adapts this type as a dictionary: use canonical SQL keywords,
    # not CLR property names such as DataSource or InitialCatalog.
    $builder['Data Source']=if ($Instance -eq 'MSSQLSERVER') {'.'} else {'.\'+$Instance}
    $builder['Initial Catalog']='msdb'
    $builder['Integrated Security']=$true
    $builder['Connect Timeout']=4
    $builder['Application Name']='WinFix read-only backup diagnostic'
    $builder['Pooling']=$false
    $builder.ConnectionString
}
function Test-BackupOperationalLog {
    param([string]$Path)
    $leaf=($Path -split '[\\/]')[-1]
    if ($leaf -match '(?i)license|licence|readme|notice|eula|changelog|copyright') {return $false}
    if ($leaf -match '(?i)\.log(?:\.\d+)?$') {return $true}
    if ($leaf -notmatch '(?i)\.txt(?:\.\d+)?$') {return $false}
    return ($leaf -match '(?i)log|backup|agent|service|error|history|event|job|session' -or $Path -match '(?i)[\\/]logs?[\\/]')
}

if ($env:OS -ne 'Windows_NT') { throw 'Run this on the affected Windows computer.' }
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Open PowerShell ISE as Administrator, then run again.' }
$nasHostName=($BackupTarget -split '\\')[2]
if (-not $OutputDirectory) { $OutputDirectory=Join-Path $env:TEMP 'WinFixBackupDiagnostic' }
$null=[IO.Directory]::CreateDirectory($OutputDirectory)
$output=Join-Path $OutputDirectory ('WinFixBackup-'+$env:COMPUTERNAME+'-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'.txt')
$encoding=New-Object Text.UTF8Encoding($false)
$header="WINFIX BACKUP DIAGNOSTIC 1.2`r`nComputer: $env:COMPUTERNAME`r`nCollected: $((Get-Date).ToString('o'))`r`nTimezone: $([TimeZoneInfo]::Local.Id)`r`nPowerShell: $($PSVersionTable.PSVersion)`r`nTarget supplied for investigation: $BackupTarget`r`nRunning as: $($identity.Name)`r`nRead-only. Backup engines and services remain running. Results saved after every section.`r`nNAS queries use this elevated user's credentials, which may differ from the backup account.`r`nCounters show activity, not proof that backup data is advancing. No activity over a short sample does not prove a hang.`r`nPaths, account names, device identifiers and event messages may appear. No stored passwords or recovery keys are queried.`r`n"
[IO.File]::WriteAllText($output,$header,$encoding)
Write-Host "WinFix backup diagnostic 1.2. Partial results: $output"
$sections=[ordered]@{}
$sections.WindowsBackupStatusBefore={ Invoke-BackupStatusReader -FilePath (Join-Path $env:SystemRoot 'System32\wbadmin.exe') -Arguments 'get status' -Seconds 10 }
$sections.ActivitySamples={
    $NasAddresses=@()
    # Hostname resolution has its own section; do not block sampling on DNS.
    $first=Get-BackupActivitySample
    [pscustomobject]@{Sample=1;Data=$first}
    Start-Sleep -Seconds $Interval
    $second=Get-BackupActivitySample
    [pscustomobject]@{Sample=2;Data=$second}
    [pscustomobject]@{Kind='ActivityDeltas';SecondsBetweenSampleStarts=([datetime]$second.StartedLocal-[datetime]$first.StartedLocal).TotalSeconds
        ProcessDeltas=@(Get-BackupCounterDelta -Before $first.Processes -After $second.Processes -Keys Name,ProcessId,CreationDate -Counters ReadTransferCount,WriteTransferCount,OtherTransferCount,KernelModeTime,UserModeTime)
        AdapterDeltas=@(Get-BackupCounterDelta -Before $first.Network -After $second.Network -Keys Name,InterfaceDescription -Counters ReceivedBytes,SentBytes,ReceivedPacketErrors,OutboundPacketErrors,ReceivedDiscardedPackets,OutboundDiscardedPackets)
        Caveats='Process I/O includes non-backup activity; svchost can host unrelated services. CPU time deltas use 100-nanosecond units. Adapter counters include all traffic. Missing/reset counters have null deltas. Ended processes remain visible in sample 1. TCP address matching is exact: a hostname target may not match numeric TCP addresses.'}
}
$sections.WindowsBackupStatusAfter={ Invoke-BackupStatusReader -FilePath (Join-Path $env:SystemRoot 'System32\wbadmin.exe') -Arguments 'get status' -Seconds 10 }
$sections.NasConnectivity={
    $client=New-Object Net.Sockets.TcpClient
    $watch=[Diagnostics.Stopwatch]::StartNew()
    $pending=$null
    try {
        $pending=$client.BeginConnect($NasHost,445,$null,$null)
        if (-not $pending.AsyncWaitHandle.WaitOne(5000)) { throw 'TCP connection to NAS port 445 timed out after 5 seconds.' }
        $client.EndConnect($pending)
        [pscustomobject]@{Server=$NasHost;Port=445;TcpConnected=$client.Connected;RemoteEndpoint=[string]$client.Client.RemoteEndPoint;ElapsedMs=$watch.ElapsedMilliseconds;Meaning='TCP reachability only; does not prove SMB authentication, write permission, backup progress or NAS disk health.'}
    } finally { $client.Close(); if ($pending) { $pending.AsyncWaitHandle.Close() } }
}
$sections.NasCapacity={
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class WinFixBackupSpace {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetDiskFreeSpaceEx(string path, out ulong available, out ulong total, out ulong free);
}
'@
    [uint64]$available=0; [uint64]$total=0; [uint64]$free=0
    $ok=[WinFixBackupSpace]::GetDiskFreeSpaceEx(($Target.TrimEnd('\')+'\'),[ref]$available,[ref]$total,[ref]$free)
    if (-not $ok) { throw (New-Object ComponentModel.Win32Exception([Runtime.InteropServices.Marshal]::GetLastWin32Error())) }
    [pscustomobject]@{Path=$Target;AvailableBytesToCurrentUser=$available;TotalBytesReported=$total;FreeBytesReported=$free
        AvailableGiB=[math]::Round($available/1GB,2);AvailablePercent=if ($total -gt 0) {[math]::Round(100.0*$available/$total,2)} else {$null}
        Caveat='Read-only capacity query using the elevated current user. Quotas may affect the numbers. This does not test backup-account access, capacity required to finish, NAS physical disks or write performance.'}
}
$sections.SmbConnections={
    [pscustomobject]@{Scope='SMB connections visible to this logon session. Backup services may use a different session; empty output is not proof of disconnection.'}
    Get-SmbConnection -ErrorAction Stop | Select-Object -First 32 ServerName,ShareName,UserName,Dialect,NumOpens,Encrypted,ContinuouslyAvailable
}
$sections.VssWriters={ Invoke-BackupStatusReader -FilePath (Join-Path $env:SystemRoot 'System32\vssadmin.exe') -Arguments 'list writers' -Seconds 12 }
$sections.VssShadowStorage={ Invoke-BackupStatusReader -FilePath (Join-Path $env:SystemRoot 'System32\vssadmin.exe') -Arguments 'list shadowstorage' -Seconds 10 }
$sections.Shadows={ Get-CimInstance Win32_ShadowCopy -OperationTimeoutSec 10 | Select-Object -First 24 ID,InstallDate,VolumeName,DeviceObject,State,ProviderID,OriginatingMachine,ClientAccessible,Persistent,NoAutoRelease }
$sections.LocalStorage={
    Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -OperationTimeoutSec 10 | Select-Object DeviceID,VolumeName,FileSystem,Size,FreeSpace,VolumeDirty
    Get-Disk -ErrorAction Stop | Select-Object -First 32 Number,FriendlyName,BusType,Size,OperationalStatus,HealthStatus,IsOffline,IsReadOnly
}
$sections.BackupTasks={
    foreach ($task in @(Get-ScheduledTask -ErrorAction Stop | Where-Object {$_.TaskName -match 'backup|synology|veeam' -or $_.TaskPath -match 'backup|synology|veeam'} | Select-Object -First 24)) {
        try {
            $info=$task | Get-ScheduledTaskInfo -ErrorAction Stop
            [pscustomobject]@{Name=$task.TaskName;Path=$task.TaskPath;State=[string]$task.State;LastRun=$info.LastRunTime;NextRun=$info.NextRunTime;LastResult=$info.LastTaskResult;LastResultHex=('0x{0:X8}' -f [uint32]$info.LastTaskResult);RunAs=$task.Principal.UserId}
        } catch { [pscustomobject]@{Name=$task.TaskName;Error=$_.Exception.Message} }
    }
    'At most 24 tasks matched by backup/vendor name or folder. Actions/arguments are excluded to avoid exporting embedded credentials. A running task is not proof of advancing backup data.'
}
$sections.BackupEvents={ Get-BackupDiagnosticEvents -LogName 'Microsoft-Windows-Backup' -ProviderPattern '.' -Limit 30 -LookbackHours $Hours }
$sections.ApplicationBackupVssEvents={ Get-BackupDiagnosticEvents -LogName Application -ProviderPattern 'Windows Backup|VSS|SQLWRITER|Synology|Veeam' -Limit 35 -LookbackHours $Hours }
$sections.StorageWarnings={ Get-BackupDiagnosticEvents -LogName System -ProviderPattern 'disk|ntfs|refs|storport|storahci|stornvme|iastor|volmgr|volsnap|vhdmp|spaceport' -Levels 1,2,3 -Limit 35 -LookbackHours $Hours }
$sections.SmbConnectivityEvents={ Get-BackupDiagnosticEvents -LogName 'Microsoft-Windows-SMBClient/Connectivity' -ProviderPattern '.' -Limit 20 -LookbackHours $Hours }
$sections.SmbSecurityEvents={ Get-BackupDiagnosticEvents -LogName 'Microsoft-Windows-SMBClient/Security' -ProviderPattern '.' -Levels 1,2,3 -Limit 12 -LookbackHours $Hours }
$sections.BackupTargetFiles={
    $found=@(Find-BackupEvidenceFiles -Root $Target -Depth 2)
    $found | Where-Object {$_.Kind -ne 'File'}
    $files=@($found | Where-Object {$_.Kind -eq 'File'})
    [pscustomobject]@{FilesInSample=$files.Count;ReturnedLimit=40;OutputTruncated=($files.Count -gt 40);Meaning='Newest files within the bounded sample, not necessarily newest across the whole share. Metadata only: no hashes, database reads or restore verification. Timestamps and size do not prove a usable backup.'}
    $files | Sort-Object ModifiedUTC -Descending | Select-Object -First 40
}
$sections.SynologyConnections={
    $processes=@(Get-CimInstance Win32_Process -OperationTimeoutSec 8 | Where-Object {$_.Name -match 'Synology.*Active.*Backup'})
    $processes | Select-Object Name,ProcessId,ExecutablePath
    $ids=@($processes | ForEach-Object {$_.ProcessId})
    Get-NetTCPConnection -ErrorAction Stop | Where-Object {$_.OwningProcess -in $ids -or $_.RemotePort -eq 5510} |
        Select-Object -First 40 LocalAddress,LocalPort,RemoteAddress,RemotePort,@{Name='State';Expression={[string]$_.State}},OwningProcess
    'ABB process endpoints are observations, not proof of successful backup. The supplied ABB probe host, if any, is not automatically confirmed as the configured destination.'
}
if ($ABBServer) {
    $sections.AbbPortProbe={
        $client=New-Object Net.Sockets.TcpClient;$pending=$null
        try {
            $pending=$client.BeginConnect($AbbHost,5510,$null,$null)
            if (-not $pending.AsyncWaitHandle.WaitOne(5000)) {throw 'ABB TCP 5510 connection timed out after 5 seconds.'}
            $client.EndConnect($pending)
            [pscustomobject]@{HostSuppliedForProbe=$AbbHost;Port=5510;Connected=$client.Connected;Endpoint=[string]$client.Client.RemoteEndPoint;Meaning='Connectivity only. ABB account authorization, configured destination and job outcome are not tested.'}
        } finally {$client.Close();if ($pending) {$pending.AsyncWaitHandle.Close()}}
    }
}
$sections.SynologyAgentLogs={
    $roots=@()
    if ($env:ProgramData) {$roots+=Join-Path $env:ProgramData 'ActiveBackupforBusinessAgent'}
    foreach ($base in @($env:ProgramData,$env:ProgramFiles,${env:ProgramFiles(x86)})) {
        if ($base) {
            foreach ($suffix in @('Synology\ActiveBackupforBusinessAgent','Synology\Active Backup for Business Agent')) {$roots+=Join-Path $base $suffix}
        }
    }
    foreach ($process in @(Get-CimInstance Win32_Process -OperationTimeoutSec 8 | Where-Object {$_.Name -match 'Synology.*Active.*Backup'} | Select-Object -First 4)) {
        if ($process.ExecutablePath) {$roots+=Split-Path $process.ExecutablePath -Parent}
    }
    $candidates=@()
    foreach ($root in @($roots | Select-Object -Unique)) {
        $found=@(Find-BackupEvidenceFiles -Root $root -Depth 3 -EntryLimit 600 -DirectoryLimit 24)
        $found | Where-Object {$_.Kind -ne 'File'}
        $candidates+=@($found | Where-Object {$_.Kind -eq 'File' -and (Test-BackupOperationalLog -Path $_.Path)})
    }
    $selected=@($candidates | Sort-Object Path -Unique | Sort-Object ModifiedUTC -Descending | Select-Object -First 8)
    [pscustomobject]@{SelectedLogFiles=$selected.Count;FileLimit=8;Meaning='ProgramData, conventional install and service directories only; license/readme documentation excluded; absent or inaccessible logs do not establish absence/failure of ABB. Binary, archive, database and configuration files are not read.'}
    foreach ($file in $selected) {
        try {Read-BackupTextTail -Path $file.Path} catch {[pscustomobject]@{Path=$file.Path;Error=$_.Exception.Message}}
    }
}
$sections.BackupTaskActions={
    foreach ($task in @(Get-ScheduledTask -ErrorAction Stop | Where-Object {$_.TaskName -match $TaskPattern} | Select-Object -First 20)) {
        $actions=@()
        foreach ($action in @($task.Actions)) {
            $argsText=[string]$action.Arguments
            $scripts=@([regex]::Matches($argsText,'(?i)[A-Z]:\\[^"\r\n]*?\.(?:ps1|cmd|bat|sql)') | ForEach-Object {$_.Value} | Select-Object -Unique -First 4)
            $actions+=[pscustomobject]@{Execute=$action.Execute;WorkingDirectory=$action.WorkingDirectory;ScriptPaths=$scripts;ArgumentsOmitted=$true
                UsesRobocopy=([string]$action.Execute -match 'robocopy' -or $argsText -match '\brobocopy\b');UsesSqlcmd=([string]$action.Execute -match 'sqlcmd' -or $argsText -match '\bsqlcmd\b')}
        }
        [pscustomobject]@{Task=$task.TaskName;Path=$task.TaskPath;RunAs=$task.Principal.UserId;LogonType=[string]$task.Principal.LogonType;State=[string]$task.State;Actions=$actions;Meaning='Arguments withheld because tasks can embed credentials. Script paths are hints; scripts are not executed or exported. Result zero can hide errors if a wrapper does not propagate them.'}
    }
}
if ($IncludeSqlBackupHistory) {
    $sections.SqlBackupHistory={
        $instances=@()
        foreach ($key in @('HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL')) {
            if (Test-Path $key) {$instances+=@((Get-ItemProperty $key).PSObject.Properties | Where-Object {$_.Name -notmatch '^PS'} | ForEach-Object {$_.Name})}
        }
        $instances=@($instances | Select-Object -Unique -First 4)
        [pscustomobject]@{LocalInstances=$instances;InstanceLimit=4;Meaning='Read-only msdb history, Windows authentication as the current user. SQL local timestamps are reported as stored. No restore or VERIFYONLY is performed. History is not a destination integrity test.'}
        foreach ($instance in $instances) {
            $connection=New-Object Data.SqlClient.SqlConnection
            try {
                $connection.ConnectionString=New-BackupSqlConnectionString -Instance $instance
                $connection.Open()
                $cmd=$connection.CreateCommand();$cmd.CommandTimeout=8
                $cmd.CommandText='SELECT TOP (20) database_name, backup_start_date, backup_finish_date, type, backup_size, is_copy_only, has_backup_checksums FROM msdb.dbo.backupset ORDER BY backup_finish_date DESC;'
                $reader=$cmd.ExecuteReader();$rows=0
                try {
                    while ($reader.Read()) {
                        $row=[ordered]@{Instance=$instance}
                        for ($i=0;$i -lt $reader.FieldCount;$i++) {
                            $value=$reader.GetValue($i)
                            if ($value -is [DBNull]) {$value=$null} elseif ($value -is [datetime]) {$value=$value.ToString('yyyy-MM-ddTHH:mm:ss')}
                            $row[$reader.GetName($i)]=$value
                        }
                        [pscustomobject]$row;$rows++
                    }
                } finally {$reader.Close();$cmd.Dispose()}
                [pscustomobject]@{Instance=$instance;HistoryRows=$rows;RowLimit=20}
            } catch {[pscustomobject]@{Instance=$instance;Error=$_.Exception.Message;Meaning='Missing access/history is not proof that database backups do not exist.'}}
            finally {$connection.Dispose()}
        }
    }
}
$sections.TaskHistory={Get-BackupDiagnosticEvents -LogName 'Microsoft-Windows-TaskScheduler/Operational' -ProviderPattern '.' -Levels 1,2,3 -Limit 25 -LookbackHours $Hours}

foreach ($name in $sections.Keys) {
    $context=@{SqlStringCode=${function:New-BackupSqlConnectionString}.ToString();LogFilterCode=${function:Test-BackupOperationalLog}.ToString();AbbHost=$ABBServer;TaskPattern=$TaskNamePattern;FinderCode=${function:Find-BackupEvidenceFiles}.ToString();TailCode=${function:Read-BackupTextTail}.ToString();NasHost=$nasHostName;Target=$BackupTarget;Interval=$SampleSeconds;Hours=$LookbackHours
        EventCode=${function:Get-BackupDiagnosticEvents}.ToString();ReaderCode=${function:Invoke-BackupStatusReader}.ToString()
        SampleCode=${function:Get-BackupActivitySample}.ToString();DeltaCode=${function:Get-BackupCounterDelta}.ToString();SectionCode=$sections[$name].ToString()}
    $timeout=30
    if ($name -eq 'ActivitySamples') { $timeout=$SampleSeconds+60 }
    $result=Invoke-BackupDiagnosticSection -Name $name -TimeoutSeconds $timeout -Context $context -Collect {
        Set-Item Function:New-BackupSqlConnectionString ([scriptblock]::Create($SqlStringCode))
        Set-Item Function:Test-BackupOperationalLog ([scriptblock]::Create($LogFilterCode))
        Set-Item Function:Find-BackupEvidenceFiles ([scriptblock]::Create($FinderCode))
        Set-Item Function:Read-BackupTextTail ([scriptblock]::Create($TailCode))
        Set-Item Function:Get-BackupDiagnosticEvents ([scriptblock]::Create($EventCode))
        Set-Item Function:Invoke-BackupStatusReader ([scriptblock]::Create($ReaderCode))
        Set-Item Function:Get-BackupActivitySample ([scriptblock]::Create($SampleCode))
        Set-Item Function:Get-BackupCounterDelta ([scriptblock]::Create($DeltaCode))
        & ([scriptblock]::Create($SectionCode))
    }
    [IO.File]::AppendAllText($output,$result,$encoding)
}
[IO.File]::AppendAllText($output,"`r`nEND WINFIX BACKUP DIAGNOSTIC | $((Get-Date).ToString('o'))`r`n",$encoding)
Write-Host "Saved: $output"
try {
    if (Get-Command Set-Clipboard -ErrorAction SilentlyContinue) { Set-Clipboard -Value ([IO.File]::ReadAllText($output)); Write-Host 'Results copied to clipboard.' }
    else { Write-Host 'In Notepad, press Ctrl+A then Ctrl+C to copy all results.' }
} catch { Write-Warning 'Clipboard unavailable. Copy the saved text from Notepad.' }
if (-not $NoOpen) { Start-Process notepad.exe -ArgumentList ('"'+$output+'"') }
