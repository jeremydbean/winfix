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
if ($unknown.Count -ne 14 -or @($unknown | Where-Object Status -ne 'Unknown').Count) { throw 'Missing external evidence was not kept unknown.' }
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
    if ($check.Status -ne 'Collected' -or $check.Count -ne 14) { throw 'External evidence did not survive the worker boundary.' }
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

# Simulate an older Windows host with no LocalAccounts module.
if ($ast.ScriptRequirements.RequiredPSVersion -ne [version]'4.0') { throw 'The collector still requires a newer PowerShell.' }
$userAssignment=$ast.Find({param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$checks.LocalUsers'},$true)
$userBlock=$userAssignment.Find({param($n) $n -is [System.Management.Automation.Language.ScriptBlockExpressionAst]},$true)
$adminAssignment=$ast.Find({param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$checks.Administrators'},$true)
$adminBlock=$adminAssignment.Find({param($n) $n -is [System.Management.Automation.Language.ScriptBlockExpressionAst]},$true)
function Get-Command { [CmdletBinding()]param($Name) return $null }
function Get-CimInstance {
    [CmdletBinding()]param($ClassName,$Filter)
    switch ($ClassName) {
        Win32_UserAccount {
            if ($Filter -ne 'LocalAccount=True') { throw 'Unbounded domain account enumeration.' }
            [pscustomobject]@{Name='test-admin';Disabled=$false;SID='S-1-5-21-1-1001';PasswordRequired=$true;PasswordChangeable=$false;PasswordExpires=$true;Lockout=$false}
            [pscustomobject]@{Name='Guest';Disabled=$true;SID='S-1-5-21-1-501';PasswordRequired=$false;PasswordChangeable=$false;PasswordExpires=$false;Lockout=$false}
        }
        Win32_Group {
            if ($Filter -ne "SID='S-1-5-32-544'") { throw 'Administrators lookup is not locale independent.' }
            [pscustomobject]@{Name='Administrateurs';SID='S-1-5-32-544'}
        }
        default { throw 'Unexpected CIM query.' }
    }
}
function Get-CimAssociatedInstance {
    [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject,$Association)
    process {
        if ($Association -ne 'Win32_GroupUser' -or $InputObject.SID -ne 'S-1-5-32-544') { throw 'Wrong group membership association.' }
        [pscustomobject]@{Domain='HOST';Name='test-admin';SID='S-1-5-21-1-1001';CimClass=[pscustomobject]@{CimClassName='Win32_UserAccount'}}
    }
}
$SystemEvidence=[pscustomobject]@{Status='Collected';Data=@([pscustomobject]@{DomainRole=2})}
$legacyUsers=@(& ([scriptblock]::Create($userBlock.ScriptBlock.Extent.Text.Trim('{}'))))
if ($legacyUsers.Count -ne 2 -or -not $legacyUsers[0].Enabled -or $legacyUsers[1].Enabled -or $null -ne $legacyUsers[0].PasswordExpires -or -not $legacyUsers[0].PasswordExpirationEnabled) { throw 'Legacy user evidence or unavailable timestamps were misrepresented.' }
$legacyAdmins=@(& ([scriptblock]::Create($adminBlock.ScriptBlock.Extent.Text.Trim('{}'))))
if ($legacyAdmins[0].Name -ne 'HOST\test-admin' -or $legacyAdmins[0].Source -ne 'Win32_GroupUser fallback') { throw 'Legacy Administrators membership failed.' }
$SystemEvidence.Data[0].DomainRole=5
try { $null=& ([scriptblock]::Create($userBlock.ScriptBlock.Extent.Text.Trim('{}'))); throw 'DC queried for local SAM' }
catch { if ($_.Exception.Message -notlike 'Domain controller:*') { throw } }
$script:clipboardTestText=$null
function Set-LegacyAuditClipboard { param([string]$Text) $script:clipboardTestText=$Text }
Copy-AuditText -Text 'Legacy clipboard text'
if ($script:clipboardTestText -ne 'Legacy clipboard text') { throw 'Legacy clipboard fallback was not used.' }
Remove-Item Function:Get-Command; Remove-Item Function:Get-CimInstance; Remove-Item Function:Get-CimAssociatedInstance
Remove-Item Function:Set-LegacyAuditClipboard

# Execute the actual launcher with mocked HTTP: verify TLS before download,
# propagation of options, restoration, and no stale execution after failure.
$launcherPath=Join-Path (Split-Path $PSScriptRoot) 'Start-WinFixAudit.ps1'
$launcherTokens=$null; $launcherErrors=$null
$launcherAst=[System.Management.Automation.Language.Parser]::ParseFile($launcherPath,[ref]$launcherTokens,[ref]$launcherErrors)
if ($launcherErrors.Count -or $launcherAst.ScriptRequirements.RequiredPSVersion -ne [version]'4.0') { throw 'Launcher syntax or version requirement failed.' }
$originalProtocol=[Net.ServicePointManager]::SecurityProtocol
$global:winfixLauncherTestRan=$false
function Invoke-RestMethod {
    [CmdletBinding()]param($Uri,$TimeoutSec)
    if ([Net.ServicePointManager]::SecurityProtocol -ne [Net.SecurityProtocolType]::Tls12) { throw 'TLS 1.2 not selected before download.' }
    if ($Uri -ne 'https://raw.githubusercontent.com/jeremydbean/winfix/main/Export-WinFixAudit.ps1') { throw 'Download URL is not plain or expected.' }
    'param([switch]$CopyToClipboard,[switch]$SkipOnlineUpdateScan,[string]$EvidenceFile) $global:winfixLauncherTestRan=($CopyToClipboard -and $SkipOnlineUpdateScan -and $EvidenceFile -eq "test.json")'
}
& $launcherPath -SkipOnlineUpdateScan -EvidenceFile 'test.json'
if (-not $global:winfixLauncherTestRan -or [Net.ServicePointManager]::SecurityProtocol -ne $originalProtocol) { throw 'Launcher options or TLS restoration failed.' }
$global:winfixLauncherTestRan=$false
function Invoke-RestMethod { [CmdletBinding()]param($Uri,$TimeoutSec) throw 'Simulated TLS failure' }
& $launcherPath -ErrorAction SilentlyContinue
if ($global:winfixLauncherTestRan -or [Net.ServicePointManager]::SecurityProtocol -ne $originalProtocol) { throw 'A failed download ran stale code or leaked TLS settings.' }
Remove-Item Function:Invoke-RestMethod
Remove-Variable -Name winfixLauncherTestRan -Scope Global
Write-Host 'PASS: PowerShell 4 requirements, legacy local accounts/admins/clipboard, DC guard, TLS launcher success/failure and protocol restoration.'

# Reproduce the legacy formatter failure at the serializer boundary. Every
# production export must bypass formatting without altering the source strings.
function ConvertTo-Json {
    [CmdletBinding()]param([Parameter(Mandatory=$true)][AllowNull()]$InputObject,[int]$Depth,[switch]$Compress)
    if (-not $Compress) { throw 'The converted JSON string is in bad format.' }
    Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $InputObject -Depth $Depth -Compress
}
$fixture = [ordered]@{ Checks=[ordered]@{Shares=[pscustomobject]@{Status='Collected';Data=@(
    [pscustomobject]@{Name='C$';Path='C:\';Description='Root "share"';EncryptData=$false},
    [pscustomobject]@{Name='Backup';Path='\\nas\backups\';Description=('Unicode ' + [char]0x00e9);EncryptData=$null}
)}}; Empty=@(); Single=@('one'); Text="Tab`tNewline`nTrailing slash\\" }
$roundTripJson=ConvertTo-AuditJson -InputObject $fixture
$roundTrip=$roundTripJson | ConvertFrom-Json
if ($roundTrip.Checks.Shares.Data[0].Path -cne 'C:\' -or $roundTrip.Checks.Shares.Data[1].Path -cne '\\nas\backups\' -or $roundTrip.Checks.Shares.Data[0].Description -cne 'Root "share"' -or $roundTrip.Text -cne $fixture.Text -or $roundTrip.Empty.Count -ne 0 -or $roundTrip.Single.Count -ne 1 -or $roundTrip.Checks.Shares.Data[0].EncryptData -ne $false -or $null -ne $roundTrip.Checks.Shares.Data[1].EncryptData) { throw 'Compact JSON changed audit evidence.' }
$fixtureBlocks=@(New-PasteBlocks -Json $roundTripJson -Size 50 -Id 'json-regression')
$rebuilt=($fixtureBlocks | ForEach-Object { ($_ -split "`r`n")[1] }) -join ''
if ($rebuilt -cne $roundTripJson) { throw 'JSON paste blocks changed escaped path data.' }
$templateRoundTrip=ConvertTo-AuditJson -InputObject (New-ExternalEvidenceTemplate -ComputerName 'SERVER') -Depth 6 | ConvertFrom-Json
if ($templateRoundTrip.Controls.Count -ne 14) { throw 'The template was not serialized through the compatible path.' }
$script:checks=$fixture.Checks
$script:checkpointWarnings=@()
$script:checkpointPath=Join-Path ([IO.Path]::GetTempPath()) ('WinFix-json-' + [guid]::NewGuid().ToString('N') + '.json')
try {
    Save-AuditCheckpoint
    $saved=Get-Content -LiteralPath $script:checkpointPath -Raw
    if (($saved | ConvertFrom-Json).Checks.Shares.Data[0].Path -cne 'C:\') { throw 'Share path did not survive checkpoint export.' }
    # Simulate a separate export failure with a prior good checkpoint on disk.
    function ConvertTo-Json { [CmdletBinding()]param($InputObject,[int]$Depth,[switch]$Compress) throw 'Simulated checkpoint serialization failure' }
    $continued=Invoke-AuditCheck 'AfterCheckpointFailure' { [pscustomobject]@{Value='still collected'} }
    if ($continued.Status -ne 'Collected' -or $script:checkpointWarnings.Count -ne 1 -or $script:checkpointWarnings[0].Error -notlike '*Simulated*') { throw 'Checkpoint failure stopped collection or was hidden.' }
    if ((Get-Content -LiteralPath $script:checkpointPath -Raw) -cne $saved) { throw 'The previous good checkpoint was lost.' }
    Remove-Item Function:ConvertTo-Json
    Save-AuditCheckpoint
    $recovered=Get-Content -LiteralPath $script:checkpointPath -Raw | ConvertFrom-Json
    if ($recovered.Checks.AfterCheckpointFailure.Status -ne 'Collected' -or $recovered.ExportWarnings.Count -ne 1) { throw 'Checkpoint recovery lost results or warnings.' }
    $final=ConvertTo-AuditJson -InputObject @{Incomplete=$false;Checks=$script:checks;ExportWarnings=@($script:checkpointWarnings)} | ConvertFrom-Json
    if ($final.Incomplete -or $final.Checks.Shares.Data[0].Path -cne 'C:\' -or $final.ExportWarnings.Count -ne 1) { throw 'Final export lost retained evidence.' }
} finally {
    Remove-Item Function:ConvertTo-Json -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $script:checkpointPath -ErrorAction SilentlyContinue
    $script:checkpointPath=$null
}
Write-Host 'PASS: legacy formatter bypass, exact path/data preservation, paste reassembly and checkpoint failure/recovery.'

# Hyper-V fixtures execute the production inventory and detail code. No Hyper-V
# module is needed on this test machine; jobs/serialization are still real below.
$hyperMocks = @'
function Import-Module { [CmdletBinding()]param($Name) if ($Name -ne 'Hyper-V') { throw 'Unexpected module' } }
function Get-VM {
    [CmdletBinding()]param([guid]$Id)
    if ($Id -eq [guid]'22222222-2222-2222-2222-222222222222') { throw 'VM removed during collection' }
    $first=[pscustomobject]@{Name='VM [one]';Id=[guid]'11111111-1111-1111-1111-111111111111';State='Off';Path='D:\VMs\one';Uptime=[timespan]::Zero}
    if ($PSBoundParameters.ContainsKey('Id')) { $first; return }
    $first
    [pscustomobject]@{Name='VM two';Id=[guid]'22222222-2222-2222-2222-222222222222';State='Running';Uptime=[timespan]::FromDays(1)}
}
function Get-VMHardDiskDrive {
    [CmdletBinding()]param($VM)
    [pscustomobject]@{Path='D:\VMs\one\disk.avhdx';ControllerType='SCSI';ControllerNumber=0;ControllerLocation=0}
    [pscustomobject]@{Path='D:\VMs\denied.vhdx';ControllerType='SCSI';ControllerLocation=1}
    [pscustomobject]@{Path='\\nas\VMs\remote.vhdx';ControllerType='SCSI';ControllerLocation=2}
    [pscustomobject]@{Path=$null;DiskNumber=4;ControllerType='SCSI';ControllerLocation=3}
}
function Get-VHD {
    [CmdletBinding()]param($Path)
    if ($Path -like '\\*') { throw 'Network path should never be opened' }
    if ($Path -like '*denied*') { throw 'VHD access denied' }
    [pscustomobject]@{Path=$Path;VhdFormat='VHDX';VhdType='Differencing';FileSize=1024;Size=4096;ParentPath='D:\VMs\base.vhdx';Attached=$true;ExtraMetadata=('noise'*10000)}
}
function Get-VMIntegrationService {
    [CmdletBinding()]param($VM)
    [pscustomobject]@{Name='Sicherung (Volumesnapshot)';Id='backup-id';Enabled=$false;PrimaryStatusDescription='OK'}
}
function Get-VMSnapshot {
    [CmdletBinding()]param($VM)
    1..52 | ForEach-Object { [pscustomobject]@{Name="checkpoint $_";Id="id$_";CreationTime=(Get-Date).AddDays(-$_);SnapshotType='Recovery'} }
}
'@
. ([scriptblock]::Create($hyperMocks))
$inventoryAssignment=$ast.Find({param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$checks.HyperVInventory'},$true)
$inventoryBlock=@($inventoryAssignment.FindAll({param($n) $n -is [System.Management.Automation.Language.ScriptBlockExpressionAst]},$true))[0]
$inventoryCode=$inventoryBlock.ScriptBlock.Extent.Text.Trim('{}')
$VMLimit=1
$inventory=& ([scriptblock]::Create($inventoryCode))
if ($inventory.RegisteredVMCount -ne 2 -or $inventory.VMs.Count -ne 1 -or -not $inventory.OutputTruncated -or $inventory.OmittedVMs[0].Name -ne 'VM two' -or $inventory.VMs[0].State -ne 'Off' -or $null -ne $inventory.VMs[0].CheckpointType) { throw 'Hyper-V inventory cap, stopped VM or legacy null evidence failed.' }
$id='11111111-1111-1111-1111-111111111111'
$disks=@(Get-AuditHyperVDetail -VMId $id -Kind Disks)
if ($disks.Count -ne 4 -or $disks[0].VHD.ParentPath -ne 'D:\VMs\base.vhdx' -or $disks[1].VHDError -ne 'VHD access denied' -or $disks[2].VHDError -notlike 'Non-local*' -or $disks[3].DiskNumber -ne 4) { throw 'Disk attachment/parent or failed/remote/pass-through evidence lost.' }
if ((ConvertTo-AuditJson -InputObject $disks).Length -gt 5000) { throw 'VHD object metadata leaked into export.' }
$integration=@(Get-AuditHyperVDetail -VMId $id -Kind Integration)
if ($integration.Count -ne 1 -or $integration[0].Enabled -ne $false -or $integration[0].Name -ne 'Sicherung (Volumesnapshot)') { throw 'Localized/disabled backup integration was lost.' }
$snap=Get-AuditHyperVDetail -VMId $id -Kind Checkpoints
if ($snap.TotalCount -ne 52 -or -not $snap.OutputTruncated -or $snap.Checkpoints.Count -ne 50 -or $snap.Checkpoints[0].Name -ne 'checkpoint 1') { throw 'Checkpoint ordering or coverage limits lost.' }
try { $null=Get-AuditHyperVDetail -VMId '22222222-2222-2222-2222-222222222222' -Kind Disks; throw 'Missing VM accepted' }
catch { if ($_.Exception.Message -ne 'VM removed during collection') { throw } }
function Get-VM { [CmdletBinding()]param([guid]$Id) @() }
$inventory=& ([scriptblock]::Create($inventoryCode))
if ($inventory.RegisteredVMCount -ne 0 -or $inventory.VMs.Count -ne 0 -or $inventory.OutputTruncated) { throw 'Empty Hyper-V host is not distinct from unavailable.' }
function Import-Module { [CmdletBinding()]param($Name) throw 'Hyper-V module unavailable' }
try { $null=& ([scriptblock]::Create($inventoryCode)); throw 'Unsupported Hyper-V host accepted' }
catch { if ($_.Exception.Message -ne 'Hyper-V module unavailable') { throw } }
foreach ($name in @('Import-Module','Get-VM','Get-VMHardDiskDrive','Get-VHD','Get-VMIntegrationService','Get-VMSnapshot')) { Remove-Item "Function:$name" }
$hyperJob=Invoke-AuditCheck HyperVWorkerTest -Context @{
    MockCode=$hyperMocks; DetailCode=${function:Get-AuditHyperVDetail}.ToString(); VMId=$id
} -Collect {
    . ([scriptblock]::Create($MockCode))
    Set-Item Function:Get-AuditHyperVDetail ([scriptblock]::Create($DetailCode))
    Get-AuditHyperVDetail -VMId $VMId -Kind Disks
}
$hyperRoundTrip=ConvertTo-AuditJson -InputObject $hyperJob | ConvertFrom-Json
if ($hyperJob.Status -ne 'Collected' -or $hyperRoundTrip.Count -ne 4 -or $hyperRoundTrip.Data[0].VMName -ne 'VM [one]' -or $hyperRoundTrip.Data[0].VHD.Path -ne 'D:\VMs\one\disk.avhdx') { throw 'Hyper-V helper/job/JSON boundary failed.' }
# Older evidence templates stay importable: new VM controls must remain Unknown.
$oldTemplate=New-ExternalEvidenceTemplate -ComputerName TESTHOST
$oldTemplate.Controls=@($oldTemplate.Controls | Select-Object -First 12)
$oldPath=Join-Path ([IO.Path]::GetTempPath()) ('WinFix-old-' + [guid]::NewGuid().ToString('N') + '.json')
try {
    [IO.File]::WriteAllText($oldPath,(ConvertTo-AuditJson -InputObject $oldTemplate))
    $imported=@(Read-ExternalEvidence -Path $oldPath -Template (New-ExternalEvidenceTemplate -ComputerName TESTHOST))
    if ($imported.Count -ne 14 -or @($imported | Where-Object { $_.Name -like 'HyperV*' -and $_.Status -eq 'Unknown' }).Count -ne 2) { throw 'Legacy evidence template compatibility failed.' }
} finally { Remove-Item -LiteralPath $oldPath }
Write-Host 'PASS: Hyper-V inventory/limits/legacy properties, per-VM evidence, VHD failures and non-local paths, localized integration, checkpoints, worker JSON and legacy template compatibility.'

# Redirected Desktop regression: provider-qualified paths must become native
# paths usable by .NET. Exercise real exports, including PSDrive resolution.
$pathTestRoot = Join-Path ([IO.Path]::GetTempPath()) ('WinFix-path-' + [guid]::NewGuid().ToString('N'))
try {
    $qualified = 'Microsoft.PowerShell.Core\FileSystem::' + (Join-Path $pathTestRoot 'audit [literal]')
    $native = Initialize-AuditOutputDirectory -Path $qualified
    if ($native -match '::' -or -not [IO.Directory]::Exists($native)) { throw 'Provider-qualified output was not normalized.' }
    New-PSDrive -Name WinFixPathTest -PSProvider FileSystem -Root $pathTestRoot | Out-Null
    $mapped = Initialize-AuditOutputDirectory -Path 'WinFixPathTest:/mapped'
    if ($mapped -like 'WinFixPathTest:*' -or -not [IO.Directory]::Exists($mapped)) { throw 'PSDrive output was not normalized.' }
    $script:checkpointPath = Join-Path $native 'PARTIAL.json'
    $script:checkpointWarnings = @()
    Save-AuditCheckpoint
    if (-not [IO.File]::Exists($script:checkpointPath) -or $script:checkpointWarnings.Count) { throw 'Native-path checkpoint export failed.' }
    foreach ($name in @('audit.json','audit-PASTE.txt','audit-PART-01.txt','audit-EVIDENCE-TEMPLATE.json')) {
        $file = Join-Path $native $name
        [IO.File]::WriteAllText($file, 'evidence')
        if ([IO.File]::ReadAllText($file) -cne 'evidence') { throw 'Native-path final export failed.' }
    }
    if (@(Get-ChildItem -LiteralPath $native -Force -Filter '.winfix-write-test-*').Count) { throw 'Output preflight left temporary files.' }
    [IO.File]::WriteAllText((Join-Path $pathTestRoot 'blocked'), 'existing file')
    try { $null = Initialize-AuditOutputDirectory -Path (Join-Path $pathTestRoot 'blocked/child'); throw 'Unwritable output accepted' }
    catch { if ($_.Exception.Message -notlike '*Cannot write audit output*') { throw } }
    try { $null = Initialize-AuditOutputDirectory -Path 'Env:/WinFixTest'; throw 'Non-filesystem output accepted' }
    catch { if ($_.Exception.Message -notlike '*FileSystem directory*') { throw } }
} finally {
    $script:checkpointPath = $null
    Remove-PSDrive WinFixPathTest -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $pathTestRoot -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host 'PASS: provider-qualified and PSDrive output, real checkpoint/final writes, literal paths and early output failure.'
