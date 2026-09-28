#requires -Version 4.0
<#
.SYNOPSIS
Read-only disk identity, storage-event and backup-activity evidence for ISE.
.DESCRIPTION
No disk scans, repairs, mounts, service changes or backup control commands.
Each section runs in a bounded worker. Results are saved after every section.
#>
[CmdletBinding()]
param(
    [string]$IncidentLocalTime = '',
    [ValidateRange(5,120)][int]$CheckTimeoutSeconds = 25,
    [string]$OutputDirectory = '',
    [switch]$NoOpen
)
function Invoke-DiskDiagnosticSection {
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
function Get-DiskDiagnosticEvents {
    param([string]$LogName, [string]$ProviderPattern, [int[]]$Levels=@(), [string]$Incident='', [int]$Limit=30)
    $info=Get-WinEvent -ListLog $LogName -ErrorAction Stop
    if (-not $info.IsEnabled -or $info.RecordCount -eq 0) { [pscustomobject]@{Log=$LogName;Enabled=$info.IsEnabled;RecordsInLog=$info.RecordCount}; return }
    $records=@(); $scanLimit=3000
    try {
        if ($Incident) {
            $time=[datetime]::ParseExact($Incident,'yyyy-MM-ddTHH:mm:ss',[Globalization.CultureInfo]::InvariantCulture)
            $records=@(Get-WinEvent -FilterHashtable @{LogName=$LogName;StartTime=$time.AddMinutes(-10);EndTime=$time.AddMinutes(10)} -MaxEvents $scanLimit -ErrorAction Stop)
        } else { $records=@(Get-WinEvent -LogName $LogName -MaxEvents $scanLimit -ErrorAction Stop) }
    } catch { if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw } }
    $matches=@($records | Where-Object { $_.ProviderName -match $ProviderPattern -and (-not $Levels.Count -or $_.Level -in $Levels) -and ($Incident -or $_.TimeCreated -ge (Get-Date).AddDays(-7)) })
    [pscustomobject]@{Log=$LogName;IncidentWindowLocal=$Incident;NewestRecordLimit=$scanLimit;RecordsRead=$records.Count;ReadLimitReached=($records.Count -ge $scanLimit)
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
if ($env:OS -ne 'Windows_NT') { throw 'Run this on the affected Windows computer.' }
if ($IncidentLocalTime) { $null=[datetime]::ParseExact($IncidentLocalTime,'yyyy-MM-ddTHH:mm:ss',[Globalization.CultureInfo]::InvariantCulture) }
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Open PowerShell ISE as Administrator, then run again.' }
if (-not $OutputDirectory) { $OutputDirectory=Join-Path $env:TEMP 'WinFixDiskDiagnostic' }
$null=[IO.Directory]::CreateDirectory($OutputDirectory)
$output=Join-Path $OutputDirectory ('WinFixDisk-'+$env:COMPUTERNAME+'-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'.txt')
$encoding=New-Object Text.UTF8Encoding($false)
$header="WINFIX DISK DIAGNOSTIC 1.0`r`nComputer: $env:COMPUTERNAME`r`nCollected: $((Get-Date).ToString('o'))`r`nTimezone: $([TimeZoneInfo]::Local.Id)`r`nPowerShell: $($PSVersionTable.PSVersion)`r`nIncident local time: $IncidentLocalTime`r`nRead-only collection. No disk repairs, scans, mounts or backup interruption.`r`nDevice numbers/mappings describe NOW and can differ from the incident. Current health is not proof of historical health.`r`nResults can contain hardware identifiers, local/backup paths and event messages. No passwords or recovery keys intentionally queried.`r`n"
[IO.File]::WriteAllText($output,$header,$encoding)
$sections=[ordered]@{}
$sections.DiskIdentity={
    $items=@(Get-CimInstance Win32_DiskDrive | Select-Object -First 33)
    $items | Select-Object -First 32 Index,DeviceID,Model,SerialNumber,FirmwareRevision,InterfaceType,MediaType,Size,Partitions,Status,PNPDeviceID,SCSIPort,SCSIBus,SCSITargetId,SCSILogicalUnit
    [pscustomobject]@{DiskLimit=32;Truncated=($items.Count -gt 32);DiskIndex2Present=(@($items | Where-Object {$_.Index -eq 2}).Count -gt 0)}
}
$sections.DeviceMappings={
    Add-Type -TypeDefinition @'
using System; using System.Text; using System.Runtime.InteropServices;
public static class WinFixDiskNative {
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
 public static extern uint QueryDosDevice(string name, StringBuilder buffer, int length);
}
'@
    $names=@('PhysicalDrive2')+@(Get-CimInstance Win32_DiskDrive | Select-Object -First 32 | ForEach-Object { 'PhysicalDrive'+$_.Index })
    foreach ($name in ($names | Select-Object -Unique)) {
        $buffer=New-Object Text.StringBuilder(4096)
        $result=[WinFixDiskNative]::QueryDosDevice($name,$buffer,$buffer.Capacity)
        [pscustomobject]@{DosDevice=$name;CurrentKernelDevice=if ($result) {$buffer.ToString()} else {$null};Win32Error=if ($result) {0} else {[Runtime.InteropServices.Marshal]::GetLastWin32Error()}}
    }
}
$sections.StorageDisks={ Get-Disk | Select-Object -First 32 Number,FriendlyName,SerialNumber,UniqueId,Path,Location,BusType,Size,PartitionStyle,OperationalStatus,HealthStatus,IsBoot,IsSystem,IsOffline,IsReadOnly }
$sections.Partitions={ Get-Partition | Select-Object -First 100 DiskNumber,PartitionNumber,DriveLetter,AccessPaths,Offset,Size,Type,IsBoot,IsSystem,IsHidden }
$sections.Volumes={ Get-Volume | Select-Object -First 100 DriveLetter,Path,UniqueId,FileSystemLabel,FileSystemType,DriveType,HealthStatus,OperationalStatus,Size,SizeRemaining }
$sections.LegacyPartitions={ Get-CimInstance Win32_DiskPartition | Select-Object -First 100 DiskIndex,Index,DeviceID,Name,Type,Size,StartingOffset,BootPartition }
$sections.PhysicalDiskHealth={ Get-PhysicalDisk | Select-Object -First 32 DeviceId,FriendlyName,SerialNumber,BusType,MediaType,Size,HealthStatus,OperationalStatus,PhysicalLocation }
$sections.ReliabilityCounters={
    foreach ($disk in @(Get-PhysicalDisk | Select-Object -First 32)) {
        try { [pscustomobject]@{Disk=$disk.FriendlyName;DeviceId=$disk.DeviceId;Counters=@($disk | Get-StorageReliabilityCounter -ErrorAction Stop | Select-Object Temperature,TemperatureMax,Wear,PowerOnHours,ReadErrorsTotal,ReadErrorsUncorrected,WriteErrorsTotal,WriteErrorsUncorrected,ReadLatencyMax,WriteLatencyMax)} }
        catch { [pscustomobject]@{Disk=$disk.FriendlyName;Error=$_.Exception.Message} }
    }
    'Null/zero telemetry may reflect unsupported RAID/virtual-device reporting, not healthy physical disks.'
}
$sections.SmartStatus={ Get-CimInstance -Namespace root/wmi -ClassName MSStorageDriver_FailurePredictStatus | Select-Object -First 32 InstanceName,Active,PredictFailure,Reason }
$sections.PresentAndRetainedDiskDevices={
    $devices=@(Get-PnpDevice -Class DiskDrive | Select-Object -First 65)
    foreach ($device in ($devices | Select-Object -First 64)) {
        $properties=@(); $errorText=$null
        try { $properties=@(Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName DEVPKEY_Device_IsPresent,DEVPKEY_Device_Parent,DEVPKEY_Device_LocationInfo,DEVPKEY_Device_LastArrivalDate,DEVPKEY_Device_LastRemovalDate -ErrorAction Stop | Select-Object KeyName,Type,Data) }
        catch { $errorText=$_.Exception.Message }
        [pscustomobject]@{Name=$device.FriendlyName;InstanceId=$device.InstanceId;Status=$device.Status;Problem=$device.Problem;Properties=$properties;PropertyError=$errorText}
    }
    [pscustomobject]@{DeviceLimit=64;Truncated=($devices.Count -gt 64);Coverage='Includes retained device entries when available; absence is not historical proof.'}
}
$sections.StorageControllers={ Get-CimInstance Win32_SCSIController | Select-Object -First 32 Name,Manufacturer,DeviceID,PNPDeviceID,DriverName,Status }
$sections.StorageDrivers={ Get-CimInstance Win32_PnPSignedDriver | Where-Object {$_.DeviceClass -in @('SCSIADAPTER','HDC','DISKDRIVE')} | Select-Object -First 64 DeviceName,DeviceID,Manufacturer,DriverProviderName,DriverVersion,DriverDate,InfName,IsSigned }
$sections.MountedVirtualDisks={
    foreach ($disk in @(Get-Disk | Where-Object { [string]$_.BusType -eq 'File Backed Virtual' -or [int]$_.BusType -eq 15 } | Select-Object -First 16)) {
        try { Get-DiskImage -DevicePath ('\\.\PhysicalDrive'+$disk.Number) -ErrorAction Stop | Select-Object DevicePath,ImagePath,Attached,Size,StorageType }
        catch { [pscustomobject]@{DiskNumber=$disk.Number;Error=$_.Exception.Message} }
    }
    'Only currently reported file-backed virtual disks; no image files are mounted or opened by this script.'
}
$sections.BackupActivity={
    Get-CimInstance Win32_Service | Where-Object {$_.Name -match 'VSS|swprv|wbengine|SDRSVC|Synology'} | Select-Object Name,DisplayName,State,StartMode,ExitCode
    foreach ($task in @(Get-ScheduledTask | Where-Object {$_.TaskPath -like '*WindowsBackup*'} | Select-Object -First 10)) {
        try { $info=$task | Get-ScheduledTaskInfo -ErrorAction Stop; [pscustomobject]@{Task=$task.TaskName;Path=$task.TaskPath;State=[string]$task.State;LastRun=$info.LastRunTime;LastResult=$info.LastTaskResult;NextRun=$info.NextRunTime} }
        catch { [pscustomobject]@{Task=$task.TaskName;Error=$_.Exception.Message} }
    }
}
$sections.RecentStorageEvents={ Get-DiskDiagnosticEvents -LogName System -ProviderPattern 'disk|ntfs|refs|storport|storahci|stornvme|iastor|volmgr|volsnap|vhdmp|spaceport' -Levels 1,2,3 -Limit 30 }
if ($IncidentLocalTime) { $sections.IncidentStorageEvents={ Get-DiskDiagnosticEvents -LogName System -ProviderPattern 'disk|ntfs|refs|storport|storahci|stornvme|iastor|volmgr|volsnap|vhdmp|spaceport|Kernel-PnP' -Incident $Incident -Limit 40 } }
$sections.RecentBackupVssEvents={ Get-DiskDiagnosticEvents -LogName Application -ProviderPattern 'Windows Backup|VSS|SQLWRITER|Synology' -Limit 24 }
$sections.WindowsBackupChannel={ Get-DiskDiagnosticEvents -LogName 'Microsoft-Windows-Backup' -ProviderPattern '.' -Limit 15 }
foreach ($name in $sections.Keys) {
    $context=@{Incident=$IncidentLocalTime;EventCode=${function:Get-DiskDiagnosticEvents}.ToString();SectionCode=$sections[$name].ToString()}
    $result=Invoke-DiskDiagnosticSection -Name $name -TimeoutSeconds $CheckTimeoutSeconds -Context $context -Collect {
        Set-Item Function:Get-DiskDiagnosticEvents ([scriptblock]::Create($EventCode))
        & ([scriptblock]::Create($SectionCode))
    }
    [IO.File]::AppendAllText($output,$result,$encoding)
}
[IO.File]::AppendAllText($output,"`r`nEND WINFIX DISK DIAGNOSTIC | $((Get-Date).ToString('o'))`r`n",$encoding)
Write-Host "Saved: $output"
try {
    if (Get-Command Set-Clipboard -ErrorAction SilentlyContinue) { Set-Clipboard -Value ([IO.File]::ReadAllText($output)); Write-Host 'Results copied to clipboard.' }
    else { Write-Host 'In Notepad, press Ctrl+A then Ctrl+C to copy all results.' }
} catch { Write-Warning 'Clipboard unavailable. Copy the saved text from Notepad.' }
if (-not $NoOpen) { Start-Process notepad.exe -ArgumentList ('"'+$output+'"') }
