<#
.SYNOPSIS
Writes a synthetic WinFix collector report for testing the app's rules, PDF and email.
Run in Windows PowerShell 5.1 so dates/enums serialize exactly as the real collector's do.
The server is fictional (DC01 at "Contoso Dental") and deliberately has a mix of problems.
-PreviousMonth writes the same server 30 days earlier (for testing the month-over-month comparison).
#>
param([string]$OutputDirectory = '', [switch]$PreviousMonth)
$ErrorActionPreference = 'Stop'
if (-not $OutputDirectory) { $OutputDirectory = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'sample' }
$prev = [bool]$PreviousMonth
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$now = if ($prev) { [datetime]::Now.AddDays(-30) } else { [datetime]::Now }
function Ago([double]$days) { [datetime]$now.AddDays(-$days) }
function Ok($data) { [pscustomobject][ordered]@{ Status='Collected'; Count=@($data).Count; Data=@($data); Error=$null; DurationSeconds=1.2; TimeoutSeconds=25 } }
function Fail($status, $err) { [pscustomobject][ordered]@{ Status=$status; Count=0; Data=@(); Error=$err; DurationSeconds=25; TimeoutSeconds=25 } }
function Ev($id, $provider, $level, $daysAgo, $message) {
    [pscustomobject]@{ TimeCreated=(Ago $daysAgo); Id=$id; RecordId=1000+$id; ProviderName=$provider; Level=$level; LevelDisplayName=@('','Critical','Error','Warning')[$level]; LogName='System'; Message=$message }
}
function EvSet($events, [switch]$Targeted, [switch]$Truncated) {
    [pscustomobject]@{ LogName='System'; Enabled=$true; RecordsInLog=48211; RecordsScanned=1000; RecordsReturnedByQuery=@($events).Count
        QueryMode=if ($Targeted) {'TimeAndIdOrLevelFilter'} else {'RecentRecordSample'}; ScanLimit=1000; Since=(Ago 30)
        OldestScannedTime=(Ago 12); ScanLimitReached=$true; QueryLimitReached=[bool]$Truncated; MatchedInSample=@($events).Count
        OutputTruncated=[bool]$Truncated; Coverage='sample'; Events=@($events) }
}

$checks = [ordered]@{}
$checks.System = Ok ([pscustomobject]@{ ComputerName='DC01'; Manufacturer='Dell Inc.'; Model='PowerEdge R640'; Domain='contoso.local'; PartOfDomain=$true; DomainRole=5
    MemoryGB=127.86; OS='Microsoft Windows Server 2016 Standard'; Version='10.0.14393'; Build='14393'; Architecture='64-bit'
    InstallDate=[datetime]'2019-03-14 10:12'; LastBoot=(Ago 38.4); UptimeDays=38.4 })
$checks.OSRelease = Ok ([pscustomobject]@{ ProductName='Windows Server 2016 Standard'; EditionID='ServerStandard'; DisplayVersion=$null; ReleaseId='1607'; CurrentVersion='6.3'; CurrentBuild='14393'; UBR=7515; InstallationType='Server' })
$checks.Hardware = Ok @(
    [pscustomobject]@{ Name='Intel(R) Xeon(R) Silver 4214 CPU @ 2.20GHz'; NumberOfCores=12; NumberOfLogicalProcessors=24 },
    [pscustomobject]@{ Manufacturer='Dell Inc.'; SMBIOSBIOSVersion='2.19.1'; ReleaseDate=[datetime]'2023-08-02' })
$checks.ServerRoles = Ok @('AD-Domain-Services','DNS','FS-FileServer','Hyper-V','Windows-Server-Backup','RSAT' | ForEach-Object { [pscustomobject]@{ Name=$_; DisplayName=$_ } })
$checks.AgentServices = Ok @(
    [pscustomobject]@{ Name='NinjaRMMAgent'; DisplayName='NinjaRMMAgent'; State='Running'; StartMode='Auto' },
    [pscustomobject]@{ Name='HuntressAgent'; DisplayName='Huntress Agent'; State=$(if ($prev) { 'Running' } else { 'Stopped' }); StartMode='Auto' },
    [pscustomobject]@{ Name='HuntressUpdater'; DisplayName='Huntress Updater'; State='Running'; StartMode='Auto' },
    [pscustomobject]@{ Name='TeamViewer'; DisplayName='TeamViewer'; State='Running'; StartMode='Auto' },
    [pscustomobject]@{ Name='VeeamEndpointBackupSvc'; DisplayName='Veeam Agent for Microsoft Windows'; State='Running'; StartMode='Auto' })
$checks.Antivirus = Fail 'Unavailable' 'Invalid namespace'
$checks.Defender = Ok ([pscustomobject]@{ AMServiceEnabled=$true; AntivirusEnabled=$true; AntispywareEnabled=$true; RealTimeProtectionEnabled=$true; BehaviorMonitorEnabled=$true
    NISEnabled=$true; IsTamperProtected=$false; AntivirusSignatureVersion='1.421.112.0'; AntivirusSignatureLastUpdated=(Ago 5.2); QuickScanEndTime=(Ago 1); FullScanEndTime=$null })
$checks.Firewall = Ok @(
    [pscustomobject]@{ Name='Domain'; Enabled=1; DefaultInboundAction=4; DefaultOutboundAction=2; LogBlocked=0; LogAllowed=0 },
    [pscustomobject]@{ Name='Private'; Enabled=1; DefaultInboundAction=4; DefaultOutboundAction=2; LogBlocked=0; LogAllowed=0 },
    [pscustomobject]@{ Name='Public'; Enabled=0; DefaultInboundAction=4; DefaultOutboundAction=2; LogBlocked=0; LogAllowed=0 })
$checks.BitLocker = Ok @([pscustomobject]@{ MountPoint='C:'; VolumeType=0; VolumeStatus=0; ProtectionStatus=0; EncryptionPercentage=0; EncryptionMethod=0; LockStatus=0 })
$checks.TPM = Ok ([pscustomobject]@{ TpmPresent=$true; TpmReady=$true; TpmEnabled=$true; TpmActivated=$true; ManufacturerIdTxt='NTC'; ManufacturerVersion='7.2.2.0' })
$checks.SecureBoot = Ok ([pscustomobject]@{ Enabled=$true })
$checks.Disks = Ok @(
    [pscustomobject]@{ DeviceID='C:'; VolumeName='System'; FileSystem='NTFS'; SizeGB=279.4; FreeGB=50.3; FreePercent=18 },
    [pscustomobject]@{ DeviceID='D:'; VolumeName='Data'; FileSystem='NTFS'; SizeGB=1862.9; FreeGB=$(if ($prev) { 214.6 } else { 130.4 }); FreePercent=$(if ($prev) { 11.5 } else { 7 }) },
    [pscustomobject]@{ DeviceID='E:'; VolumeName='VMs'; FileSystem='ReFS'; SizeGB=3725.9; FreeGB=1620.8; FreePercent=43.5 })
$checks.Volumes = Ok @([pscustomobject]@{ DriveLetter='C'; FileSystemLabel='System'; FileSystem='NTFS'; DriveType='Fixed'; HealthStatus='Healthy'; OperationalStatus='OK'; Size=300000000000; SizeRemaining=54000000000 })
$checks.PhysicalDisks = Ok @(
    [pscustomobject]@{ FriendlyName='DELL PERC H730P Mini (C:)'; MediaType=4; HealthStatus=0; OperationalStatus='OK'; Size=299439751168 },
    [pscustomobject]@{ FriendlyName='DELL PERC H730P Mini (Data)'; MediaType=3; HealthStatus='Warning'; OperationalStatus='Degraded'; Size=5999999999999 })
$checks.LocalUsers = Fail 'Unavailable' 'Domain controller: local SAM accounts are not applicable; domain account review required.'
$checks.Administrators = Ok ([pscustomobject]@{ Source='ActiveDirectory'; GroupSID='S-1-5-32-544'; OutputTruncated=$false
    Members=@([pscustomobject]@{ Name='Administrator'; SamAccountName='Administrator'; ObjectClass='user'; SID='S-1-5-21-1-500' },
              [pscustomobject]@{ Name='Domain Admins'; SamAccountName='Domain Admins'; ObjectClass='group'; SID='S-1-5-21-1-512' },
              [pscustomobject]@{ Name='Enterprise Admins'; SamAccountName='Enterprise Admins'; ObjectClass='group'; SID='S-1-5-21-1-519' },
              [pscustomobject]@{ Name='MSP Admin'; SamAccountName='msp.admin'; ObjectClass='user'; SID='S-1-5-21-1-1104' }) +
              @(if (-not $prev) { [pscustomobject]@{ Name='Temp Vendor'; SamAccountName='temp.vendor'; ObjectClass='user'; SID='S-1-5-21-1-1188' } }) })
$checks.SecurityPolicy = Ok @(
    [pscustomobject]@{ Name='MinimumPasswordLength'; Value='7' }, [pscustomobject]@{ Name='PasswordComplexity'; Value='1' },
    [pscustomobject]@{ Name='LockoutBadCount'; Value='0' }, [pscustomobject]@{ Name='MaximumPasswordAge'; Value='42' })
$checks.RDP = Ok ([pscustomobject]@{ DenyConnections=0; RequireNLA=1; SecurityLayer=2; Port=3389 })
$checks.Network = Ok @([pscustomobject]@{ Description='Broadcom NetXtreme Gigabit Ethernet'; DHCPEnabled=$false; IPAddress=@('10.20.0.10','fe80::1c2d:3e4f'); IPSubnet=@('255.255.255.0','64'); DefaultIPGateway=@('10.20.0.1'); DNSServerSearchOrder=@('127.0.0.1','10.20.0.11') })
$checks.Shares = Ok @(
    [pscustomobject]@{ Name='ADMIN$'; Path='C:\Windows'; Description='Remote Admin'; EncryptData=$false; Special=$true },
    [pscustomobject]@{ Name='Shared'; Path='D:\Shared'; Description=''; EncryptData=$false; Special=$false },
    [pscustomobject]@{ Name='Scans'; Path='D:\Scans'; Description=''; EncryptData=$false; Special=$false },
    [pscustomobject]@{ Name='SYSVOL'; Path='C:\Windows\SYSVOL\sysvol'; Description='Logon server share'; EncryptData=$false; Special=$false })
$checks.SharePermissions = Ok @(
    [pscustomobject]@{ Name='Shared'; AccountName='CONTOSO\Staff'; AccessControlType=0; AccessRight=1 },
    [pscustomobject]@{ Name='Scans'; AccountName='Everyone'; AccessControlType=0; AccessRight=0 },
    [pscustomobject]@{ Name='SYSVOL'; AccountName='Everyone'; AccessControlType=0; AccessRight=2 })
$checks.SMB = Ok ([pscustomobject]@{ EnableSMB1Protocol=$prev; EnableSMB2Protocol=$true; EncryptData=$false; RequireSecuritySignature=$true; EnableSecuritySignature=$true })
$checks.StorageReliability = Fail 'Unavailable' 'The requested operation is not supported (RAID controller).'
$checks.StorageErrorDetails = Ok (EvSet @((Ev 153 'disk' 3 2 'The IO operation at logical block address 0x1a2b was retried.'), (Ev 7 'disk' 2 4 'The device, \Device\Harddisk1\DR1, has a bad block.'), (Ev 7 'disk' 2 9 'The device, \Device\Harddisk1\DR1, has a bad block.')))
$checks.UnexpectedShutdowns = Ok (EvSet @((Ev 41 'Microsoft-Windows-Kernel-Power' 1 38.5 'The system has rebooted without cleanly shutting down first.')))
$checks.Hotfixes = Ok @([pscustomobject]@{ HotFixID='KB5066836'; Description='Security Update'; InstalledOn=(Ago 20) })
$checks.UpdateHistory = Ok @(
    [pscustomobject]@{ Date=(Ago 20); Title='2026-10 Cumulative Update for Windows Server 2016 for x64-based Systems (KB5066836)'; Operation=1; ResultCode=2; HResult=0 },
    [pscustomobject]@{ Date=(Ago 20); Title='Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.421.112.0)'; Operation=1; ResultCode=2; HResult=0 },
    [pscustomobject]@{ Date=(Ago 12); Title='2026-11 Servicing Stack Update for Windows Server 2016 (KB5068011)'; Operation=1; ResultCode=4; HResult=-2145124329 },
    [pscustomobject]@{ Date=(Ago 51); Title='2026-09 Cumulative Update for Windows Server 2016 for x64-based Systems (KB5065427)'; Operation=1; ResultCode=2; HResult=0 })
$checks.CachedMissingUpdates = Ok ([pscustomobject]@{ ResultCode=2; Source='Local Windows Update cache; may be stale'; Updates=@(
    [pscustomobject]@{ Title='2026-11 Cumulative Update for Windows Server 2016 for x64-based Systems (KB5068864)'; MsrcSeverity='Critical'; KBArticleIDs=@('5068864'); RebootRequired=$false },
    [pscustomobject]@{ Title='2026-11 Servicing Stack Update for Windows Server 2016 (KB5068011)'; MsrcSeverity='Important'; KBArticleIDs=@('5068011'); RebootRequired=$false }) })
$checks.TimeService = Ok @("Leap Indicator: 0(no warning)`r`nStratum: 1 (primary reference - syncd by radio clock)`r`nSource: Local CMOS Clock`r`nLast Successful Sync Time: $($now.ToString('g'))")
$checks.PendingReboot = Ok ([pscustomobject]@{ ComponentServicing=$false; WindowsUpdate=(-not $prev); PendingFileRename=(-not $prev) })
$checks.SystemEvents = Ok (EvSet @((Ev 41 'Microsoft-Windows-Kernel-Power' 1 38.5 'x'), (Ev 7 'disk' 2 4 'x'), (Ev 7 'disk' 2 9 'x'), (Ev 1129 'Microsoft-Windows-GroupPolicy' 2 3 'x'), (Ev 36887 'Schannel' 2 1 'x'), (Ev 36887 'Schannel' 2 2 'x')))
$checks.ApplicationEvents = Ok (EvSet @((Ev 1000 'Application Error' 2 6 'x'), (Ev 8193 'VSS' 2 4 'x')))
$checks.FailedLogons = Ok (EvSet -Targeted -Truncated @(1..20 | ForEach-Object {
    [pscustomobject]@{ TimeCreated=(Ago ($_ / 2)); Id=4625; ProviderName='Microsoft-Windows-Security-Auditing'; Level=0
        EventData=@([pscustomobject]@{ Name='TargetUserName'; Value=@('administrator','scanner','admin')[$_ % 3] }, [pscustomobject]@{ Name='IpAddress'; Value=@('10.20.0.55','185.220.101.4')[$_ % 2] }) } }))
$checks.BackupSoftware = Ok @([pscustomobject]@{ DisplayName='Veeam Agent for Microsoft Windows'; DisplayVersion='6.1.2.134'; Publisher='Veeam Software Group GmbH'; InstallDate='20240611' })
$checks.BackupServices = Ok @(
    [pscustomobject]@{ Name='VeeamEndpointBackupSvc'; DisplayName='Veeam Agent for Microsoft Windows'; State='Running'; StartMode='Auto'; ExitCode=0 },
    [pscustomobject]@{ Name='VSS'; DisplayName='Volume Shadow Copy'; State='Stopped'; StartMode='Manual'; ExitCode=0 })
$checks.BackupTasks = Ok @(
    [pscustomobject]@{ RecordType='Task'; TaskName='Nightly Robocopy to NAS'; TaskPath='\'; State='Ready'; CandidateReasons=@('TaskNameOrPath','ActionExecutable'); LastRunTime=(Ago 0.4); NextRunTime=(Ago -0.6); LastTaskResult=16; NumberOfMissedRuns=0; Enabled=$true
        Actions=@([pscustomobject]@{ Execute='C:\Windows\System32\robocopy.exe'; ArgumentsOmitted=$true }); Triggers=@([pscustomobject]@{ Type='MSFT_TaskDailyTrigger'; Enabled=$true }) },
    [pscustomobject]@{ RecordType='Task'; TaskName='OneDrive Standalone Update Task-S-1-5-21'; TaskPath='\'; State='Ready'; CandidateReasons=@('TaskNameOrPath'); LastRunTime=(Ago 1); LastTaskResult=0; Enabled=$true; Actions=@(); Triggers=@() },
    [pscustomobject]@{ RecordType='Coverage'; TasksScanned=212; Candidates=2 })
$checks.HyperVInventory = Ok ([pscustomobject]@{ RegisteredVMCount=2; VMLimit=50; OutputTruncated=$false; VMs=@(
    [pscustomobject]@{ Name='APP01'; Id='3f1c0a52-8d1e-4a7b-9b0e-1c2d3e4f5a6b'; State='Running'; Status='Operating normally'; Generation=2 },
    [pscustomobject]@{ Name='SQL01'; Id='7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c0d'; State='Running'; Status='Operating normally'; Generation=2 }) })
$checks['HyperVCheckpoints:3f1c0a52-8d1e-4a7b-9b0e-1c2d3e4f5a6b'] = Ok ([pscustomobject]@{ VMName='APP01'; TotalCount=1; Checkpoints=@([pscustomobject]@{ Name='Before upgrade'; CreationTime=(Ago 31) }) })
$checks['HyperVCheckpoints:7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c0d'] = Ok ([pscustomobject]@{ VMName='SQL01'; TotalCount=0; Checkpoints=@() })
$checks.HyperVReplication = Ok @()
$checks.WindowsBackupSummary = Ok ([pscustomobject]@{ LastBackupTime=(Ago 1); LastBackupResultHR=-2147024784; LastSuccessfulBackupTime=(Ago 4.3); NextBackupTime=(Ago -0.2); NumberOfVersions=14 })
$checks.WindowsBackupPolicy = Ok ([pscustomobject]@{ PolicyConfigured=$true; Schedule=@('21:00'); Targets=@([pscustomobject]@{ TargetType='Network'; Label=''; NetworkPath='\\nas01\wsb' }) })
$checks.VSSWriters = Ok ([pscustomobject]@{ Command='vssadmin.exe list writers'; ExitCode=0; StandardOutput=@"
Writer name: 'Task Scheduler Writer'
   Writer Id: {d61d61c8-d73a-4eee-8cdd-f6f9786b7124}
   State: [1] Stable
   Last error: No error

Writer name: 'Microsoft Hyper-V VSS Writer'
   Writer Id: {66841cd4-6ded-4f4b-8f17-fd23f8ddc3de}
   State: [8] Failed
   Last error: Retryable error

Writer name: 'NTDS'
   Writer Id: {b2014c9e-8711-4c5c-a5a9-3cf384484757}
   State: [1] Stable
   Last error: No error
"@ })
$checks.ShadowCopies = Ok @([pscustomobject]@{ ID='{1}'; InstallDate=(Ago 1); VolumeName='\\?\Volume{1}\'; State=12 })
$checks.BackupErrorDetails = Ok (EvSet @((Ev 190 'Veeam Agent' 2 3 'Job DC01 Nightly finished with Failed. Error: Not enough space on repository \\nas01\veeam.')))
$checks.VSSErrorDetails = Ok (EvSet @())
$checks.DeviceRegistration = Ok ([pscustomobject]@{ Fields=[pscustomobject]@{ AzureAdJoined='NO'; DomainJoined='YES'; DomainName='CONTOSO'; TenantName='Contoso Dental Group' } })
$checks.MachineIdentity = Ok @([pscustomobject]@{ Vendor='Dell Inc.'; Name='PowerEdge R640'; UUID='4C4C4544-0044' }, [pscustomobject]@{ Manufacturer='Dell Inc.'; SMBIOSBIOSVersion='2.19.1'; SerialNumber='7XK2Q93' })
$checks.LiveMissingUpdates = Fail 'TimedOut' 'Exceeded 90s; continuing. Any returned data is incomplete.'
$checks.CertificateAuthority = Fail 'Unavailable' 'The term ''certutil'' returned no CA configuration.'

# --- collector 1.13 checks -------------------------------------------------------
$software = @('Veeam Agent for Microsoft Windows', 'NinjaRMMAgent', 'Huntress Agent', 'Microsoft Edge', '7-Zip 23.01 (x64)', 'Dell OpenManage Server Administrator')
if (-not $prev) { $software += 'AnyDesk' }
$checks.Software = Ok @($software | ForEach-Object { [pscustomobject]@{ DisplayName=$_; DisplayVersion='1.0'; Publisher='Sample'; InstallDate='20240101' } })
$ports = @(53, 88, 135, 389, 445, 464, 636, 3268, 3389, 5985)
if (-not $prev) { $ports += 8443 }
$checks.ListeningPorts = Ok @($ports | ForEach-Object { [pscustomobject]@{ LocalAddress='0.0.0.0'; LocalPort=$_; OwningProcess=4 } })
$checks.DefenderThreats = Ok @(
    [pscustomobject]@{ RecordType='Detection'; ThreatID='2147735505'; ThreatName='Trojan:Win32/Wacatac.B!ml'; SeverityID=5; InitialDetectionTime=(Ago 6); LastThreatStatusChangeTime=(Ago 6); ThreatStatusID=3; ActionSuccess=$true; ResourceCount=1 },
    [pscustomobject]@{ RecordType='Detection'; ThreatID='2147812345'; ThreatName='HackTool:Win32/Mimikatz'; SeverityID=5; InitialDetectionTime=(Ago 2); LastThreatStatusChangeTime=(Ago 2); ThreatStatusID=$(if ($prev) { 3 } else { 1 }); ActionSuccess=$false; ResourceCount=1 },
    [pscustomobject]@{ RecordType='Coverage'; Since=(Ago 30); OutputTruncated=$false })
$checks.BackupJobResults = Ok (@(1..12 | ForEach-Object { [pscustomobject]@{ RecordType='Session'; Product='Veeam Agent'; Job='DC01 Nightly'; Result=$(if (-not $prev -and $_ -le 2) { 'Failed' } else { 'Success' }); EndTime=(Ago ($_ - 0.5)) } }) +
    @(1..12 | ForEach-Object { [pscustomobject]@{ RecordType='Session'; Product='Veeam Agent'; Job='SQL01 VM'; Result=$(if ($_ -eq 5) { 'Warning' } else { 'Success' }); EndTime=(Ago ($_ - 0.6)) } }) +
    @([pscustomobject]@{ RecordType='Coverage'; Product='Veeam Agent'; EventsRead=24; QueryLimitReached=$false }))
$checks.AgentActivity = Ok @(
    [pscustomobject]@{ Agent='NinjaRMM'; Root='C:\ProgramData\NinjaRMMAgent\logs'; NewestLog='ninjarmm.log'; LastWriteTime=(Ago 0.003) },
    [pscustomobject]@{ Agent='Huntress'; Root='C:\Program Files\Huntress'; NewestLog='HuntressAgent.log'; LastWriteTime=(Ago 3.2) })
$checks.CertificateExpiry = Ok @(
    [pscustomobject]@{ Store='My'; Subject='CN=remote.contosodental.com'; Issuer='CN=R11, O=Let''s Encrypt, C=US'; NotAfter=(Ago -12); Thumbprint='A1B2C3'; HasPrivateKey=$true; SelfSigned=$false; UsedForRdp=$false },
    [pscustomobject]@{ Store='Remote Desktop'; Subject='CN=DC01.contoso.local'; Issuer='CN=DC01.contoso.local'; NotAfter=(Ago -40); Thumbprint='D4E5F6'; HasPrivateKey=$true; SelfSigned=$true; UsedForRdp=$true })
$checks.Activation = Ok @([pscustomobject]@{ Name='Windows(R), ServerStandard edition'; Description='Windows(R) Operating System, VOLUME_KMSCLIENT channel'; LicenseStatus=1; GracePeriodRemaining=0 })
$checks.LAPS = Ok ([pscustomobject]@{ LegacyCseInstalled=$false; LegacyPolicyEnabled=$false; WindowsLapsBackupDirectory=$null })
$checks.SecurityHardening = Ok ([pscustomobject]@{
    SchannelServer=@('SSL 3.0', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2' | ForEach-Object { [pscustomobject]@{ Protocol=$_; Enabled=$null; DisabledByDefault=$null } })
    LLMNREnableMulticast=$null; NetbiosOptions=@([pscustomobject]@{ Description='Broadcom NetXtreme'; TcpipNetbiosOptions=0 })
    WDigestUseLogonCredential=$null; LmCompatibilityLevel=1; NoLMHash=1; RunAsPPL=$null; RestrictAnonymous=0
    AutoUpdatePolicy=[pscustomobject]@{ WUServer=$null; NoAutoUpdate=1; AUOptions=$null } })
$checks.KeyServices = Ok @(
    [pscustomobject]@{ Name='Spooler'; DisplayName='Print Spooler'; State='Running'; StartMode='Auto' },
    [pscustomobject]@{ Name='MpsSvc'; DisplayName='Windows Defender Firewall'; State='Running'; StartMode='Auto' },
    [pscustomobject]@{ Name='wuauserv'; DisplayName='Windows Update'; State='Stopped'; StartMode='Manual' },
    [pscustomobject]@{ Name='W32Time'; DisplayName='Windows Time'; State='Running'; StartMode='Auto' })
$checks.HardwareVendorHealth = Ok @(
    [pscustomobject]@{ RecordType='Section'; Tool='Dell OpenManage'; Section='Chassis'; ExitCode=0; Items=@(
        [pscustomobject]@{ Component='Fans'; Status='Ok' }, [pscustomobject]@{ Component='Memory'; Status='Ok' },
        [pscustomobject]@{ Component='Power Supplies'; Status=$(if ($prev) { 'Ok' } else { 'Non-Critical' }) }, [pscustomobject]@{ Component='Temperatures'; Status='Ok' }) },
    [pscustomobject]@{ RecordType='Section'; Tool='Dell OpenManage'; Section='Virtual disks'; ExitCode=0; Items=@(
        [pscustomobject]@{ ID='0'; Status='Ok'; Name='OS'; State='Ready'; Layout='RAID-1'; Size='278.88 GB' },
        [pscustomobject]@{ ID='1'; Status='Non-Critical'; Name='Data'; State='Degraded'; Layout='RAID-5'; Size='5,587.00 GB' }) },
    [pscustomobject]@{ RecordType='Coverage'; ToolsFound=@('omreport.exe') })
$checks.HardwareEvents = Ok (EvSet @((Ev 2048 'Server Administrator' 2 3 'Device failed: Physical Disk 0:1:3 Controller 0, Connector 0')))
$checks.ADHygiene = Ok ([pscustomobject]@{ EnabledUsers=58; StaleUsers=7; StaleUserSample=@('jsmith','old.frontdesk','temp2019','scanner.svc','rlopez','kpatel','intern' | ForEach-Object { [pscustomobject]@{ SamAccountName=$_; LastLogonDate=(Ago 140) } })
    EnabledComputers=41; StaleComputers=12; StaleComputerSample=@('WS-OLD01','WS-OLD02','LAPTOP-3' | ForEach-Object { [pscustomobject]@{ Name=$_; LastLogonDate=(Ago 200); OperatingSystem='Windows 10 Pro' } })
    PasswordNeverExpires=4; PasswordNeverExpiresSample=@('svc.veeam','svc.scan','administrator','jsmith')
    UnsupportedOsComputers=2; UnsupportedOsSample=@([pscustomobject]@{ Name='XRAY-PC'; OperatingSystem='Windows 7 Professional' }, [pscustomobject]@{ Name='FRONT-02'; OperatingSystem='Windows 10 Pro' })
    KrbtgtPasswordLastSet=[datetime]'2019-03-14 11:02'; RecycleBinEnabled=$false })
$checks.DCDiag = Ok ([pscustomobject]@{ Command='dcdiag.exe /q'; ExitCode=0; ReaderTimeLimitReached=$false; StandardOutput=@"
         There are warning or error events within the last 24 hours after the
         SYSVOL has been shared.
         ......................... DC01 failed test DFSREvent
"@ })
$checks.ReplicationSummary = Ok ([pscustomobject]@{ Command='repadmin.exe /replsummary'; ExitCode=0; ReaderTimeLimitReached=$false; StandardOutput=@"
Replication Summary Start Time: 2026-11-25 08:00:00

Source DSA          largest delta    fails/total %%   error
 DC01                      12m:04s    0 /   5    0
 DC02                      11m:52s    0 /   5    0

Destination DSA     largest delta    fails/total %%   error
 DC01                      11m:52s    0 /   5    0
 DC02                      12m:04s    0 /   5    0
"@ })
$checks.ExternalExposure = Ok ([pscustomobject]@{ PublicIP='203.0.113.25'; NotIndexed=$false; Ports=@(443, 3389); Vulns=@('CVE-2019-0708'); Hostnames=@('remote.contosodental.com'); Tags=@()
    Source='Shodan InternetDB (passive internet scan data; may be days or weeks old)' })

$report = [ordered]@{ SchemaVersion='1.13'; AuditId=[guid]::NewGuid().ToString('N'); Incomplete=$false; ClientName=''; Location=''
    StartedAt=$now.AddMinutes(-7).ToString('o'); CompletedAt=$now.ToString('o'); Elevated=$true; PowerShellVersion='5.1'; Checks=$checks; DeepAuditRequested=$false }
$path = Join-Path $OutputDirectory ('WinFixAudit-DC01-' + $now.ToString('yyyyMMdd-HHmmss') + '.json')
[IO.File]::WriteAllText($path, (ConvertTo-Json -InputObject $report -Depth 14 -Compress), (New-Object Text.UTF8Encoding($false)))
$path
