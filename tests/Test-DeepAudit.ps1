$ErrorActionPreference='Stop'
$path=Join-Path (Split-Path $PSScriptRoot) 'Export-WinFixAudit.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw ($errors -join "`n") }
if ($ast.ScriptRequirements.RequiredPSVersion -ne [version]'4.0') { throw 'Server 2012 R2 compatibility requirement changed.' }
$ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$false) | ForEach-Object { . ([scriptblock]::Create($_.Extent.Text)) }
function Get-CheckBlock {
    param($Name)
    $assignment=$ast.Find({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq ('$checks.'+$Name)},$true)
    if (-not $assignment) { throw "Missing check $Name" }
    $block=$assignment.Find({param($n) $n -is [Management.Automation.Language.ScriptBlockExpressionAst]},$true)
    [scriptblock]::Create($block.ScriptBlock.Extent.Text.Trim('{}'))
}
$MaxEvents=2; $EventScanLimit=1000; $since=(Get-Date).AddDays(-30)
function Get-WinEvent {
    [CmdletBinding()]param($ListLog,$FilterHashtable,$MaxEvents)
    if ($ListLog) { return [pscustomobject]@{IsEnabled=$true;RecordCount=4000000;ProviderNames=@('ADSync','Other')} }
    if ($MaxEvents -ne 3 -or $FilterHashtable.StartTime -ne $since -or $FilterHashtable.Id -ne 4625) { throw 'Targeted filter/cap was lost.' }
    foreach ($n in 1..3) { [pscustomobject]@{Id=4625;ProviderName='ADSync';TimeCreated=(Get-Date).AddDays(-$n);LogName='Security';Level=2} }
    $script:lastFilter=$FilterHashtable
}
$events=Get-AuditEvents -Targeted -LogName Security -Ids 4625 -ProviderPattern '^ADSync$'
if ($events.Events.Count -ne 2 -or -not $events.QueryLimitReached -or -not $events.OutputTruncated -or $null -ne $events.RecordsScanned -or $script:lastFilter.ProviderName -ne 'ADSync') { throw 'Targeted coverage/provider semantics incorrect.' }
try { $null=Get-AuditEvents -Targeted -LogName Security -Ids 4625 -ProviderPattern '^Absent$'; throw 'Missing provider claimed success.' }
catch { if ($_.Exception.Message -notlike 'No matching registered provider*') { throw } }
Remove-Item Function:Get-WinEvent
Write-Host 'PASS: targeted event query uses server-side time/ID/provider filters, lookahead cap and truthful scan semantics.'

function Import-Module { [CmdletBinding()]param($Name) }
function Get-ADGroupMember {
    [CmdletBinding()]param($Identity,$Server)
    if ($Identity -ne 'S-1-5-32-544' -or $Server -ne 'localhost') { throw 'DC admin scope/SID incorrect.' }
    1..105 | ForEach-Object { [pscustomobject]@{Name="Admin$_";SamAccountName="a$_";SID="sid-$_";ObjectClass='user'} }
}
$SystemEvidence=[pscustomobject]@{Status='Collected';Data=@([pscustomobject]@{DomainRole=5})}
$admin=& (Get-CheckBlock Administrators)
if ($admin.Source -ne 'ActiveDirectory' -or $admin.Members.Count -ne 100 -or -not $admin.OutputTruncated) { throw 'DC administrators are unavailable or unbounded.' }
Remove-Item Function:Get-ADGroupMember
function Get-ADReplicationPartnerMetadata {
    [CmdletBinding()]param($Target,$Scope)
    if ($Target -ne $env:COMPUTERNAME -or $Scope -ne 'Server') { throw 'Replication query widened beyond local DC.' }
    [pscustomobject]@{Server='this-dc';Partner='peer';LastReplicationResult=1722;ConsecutiveReplicationFailures=4;LastReplicationSuccess=(Get-Date).AddDays(-3)}
}
$rep=& (Get-CheckBlock ADReplication)
if ($rep.Partners[0].LastReplicationResult -ne 1722 -or $rep.Partners[0].ConsecutiveReplicationFailures -ne 4) { throw 'Replication failures were erased.' }
Remove-Item Function:Get-ADReplicationPartnerMetadata
Remove-Item Function:Import-Module
Write-Host 'PASS: DC Administrators uses AD and a locale-independent SID; replication failures and local scope are preserved.'

$testTemp=[IO.Path]::GetTempPath(); if (Test-Path /private/tmp) { $testTemp='/private/tmp' }
$dir=Join-Path $testTemp ('winfix-deep-'+[guid]::NewGuid().ToString('N'))
try {
    $null=[IO.Directory]::CreateDirectory($dir)
    [IO.File]::WriteAllText((Join-Path $dir 'one.log'),'1234567890')
    $null=[IO.Directory]::CreateDirectory((Join-Path $dir 'child'))
    [IO.File]::WriteAllText((Join-Path $dir 'child/two.log'),'12345')
    $sample=Measure-AuditDirectorySample -Path $dir -EntryLimit 20 -DepthLimit 3
    if ($sample.SampleLogicalBytes -ne 15 -or $sample.FilesMeasured -ne 2 -or $sample.LargestFilesInSample.Count -ne 2) { throw 'Sample byte accounting failed.' }
    $limited=Measure-AuditDirectorySample -Path $dir -EntryLimit 1
    if (-not $limited.EntryLimitReached -or $limited.EntriesInspected -ne 1) { throw 'Metadata traversal exceeded entry cap.' }
    $depth=Measure-AuditDirectorySample -Path $dir -DepthLimit 0
    if ($depth.SampleLogicalBytes -ne 10 -or $depth.DeeperDirectoriesSkipped -ne 1) { throw 'Depth cap failed.' }
    if ($env:OS -ne 'Windows_NT') {
        $link=Join-Path $dir 'linked'
        $null=New-Item -ItemType SymbolicLink -Path $link -Target (Join-Path $dir 'child')
        $linked=Measure-AuditDirectorySample -Path $dir
        if ($linked.SpecialPathsSkipped -ne 1 -or $linked.SampleLogicalBytes -ne 15) { throw 'Reparse path was followed.' }
        try { $null=Assert-AuditLocalMetadataPath $link; throw 'Symlink root accepted.' }
        catch { if ($_.Exception.Message -notlike 'Reparse*') { throw } }
    }
} finally { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
Write-Host 'PASS: metadata sampling counts bytes without reading contents and respects entry/depth/reparse limits.'

function Get-SmbShare { [pscustomobject]@{Name='Printer';Path='Office,LocalsplOnly';Special=$false} }
function Get-Acl { throw 'Printer pseudo-path was queried as a directory.' }
$printer=& (Get-CheckBlock ShareNTFSPermissions)
if ($printer.Status -ne 'NotApplicable') { throw 'Printer incorrectly marked failed NTFS evidence.' }
Remove-Item Function:Get-SmbShare; Remove-Item Function:Get-Acl

$exe=Join-Path $PSHOME 'pwsh'; if ($env:OS -eq 'Windows_NT') { $exe=Join-Path $PSHOME 'powershell.exe'; if (Test-Path (Join-Path $PSHOME 'pwsh.exe')) {$exe=Join-Path $PSHOME 'pwsh.exe'} }
$native=Invoke-AuditNativeReader -FilePath $exe -Arguments '-NoProfile -Command "[Console]::Out.Write((''a''*100000)); [Console]::Error.Write((''b''*100000)); exit 3"' -Seconds 10 -TextLimit 200
if ($native.StandardOutput.Length -ne 200 -or $native.StandardError.Length -ne 200 -or -not $native.OutputTruncated -or $native.ExitCode -ne 3) { throw 'Native dual-pipe capture/caps failed.' }
$slow=Invoke-AuditNativeReader -FilePath $exe -Arguments '-NoProfile -Command "Start-Sleep -Seconds 30"' -Seconds 1
if (-not $slow.ReaderTimeLimitReached -or -not $slow.ReaderExited -or (Get-Process -Id $slow.ReaderProcessId -ErrorAction SilentlyContinue)) { throw 'Native reader leaked or failed to time out.' }
Write-Host 'PASS: printer handling, native output/error capture, bounded reader timeout and process cleanup.'

# Exercise actual CA collector with secrets present in mocked registry values.
function Test-Path { param($Path) return $true }
function Join-Path { param($Path,$ChildPath) return ($Path+'\'+$ChildPath) }
function Get-ItemProperty {
    [CmdletBinding()]param($LiteralPath,$Path)
    if ($LiteralPath -like '*\TestCA') { return [pscustomobject]@{CAType=0;AuditFilter=127;CACertHash=@('thumb');PrivateKey='never-export';Password='never-export'} }
    [pscustomobject]@{Active='TestCA';DBDirectory='C:\CA';DBLogDirectory='C:\CALogs';Secret='never-export'}
}
$ca=& (Get-CheckBlock CertificateAuthority)
$caJson=ConvertTo-AuditJson -InputObject $ca
if ($ca.DBDirectory -ne 'C:\CA' -or $ca.AuditFilter -ne 127 -or $caJson -match 'never-export|PrivateKey|Password|Secret') { throw 'CA paths or allowlist incorrect.' }
Remove-Item Function:Get-ItemProperty; Remove-Item Function:Test-Path; Remove-Item Function:Join-Path

function Import-Module { [CmdletBinding()]param($Name) }
function Get-Website { [pscustomobject]@{Name='Test Site';Bindings=[pscustomobject]@{Collection=@([pscustomobject]@{protocol='https';bindingInformation='*:443:'})}} }
function Get-WebApplication { param($Site) [pscustomobject]@{Path='/CertSrv'} }
function Get-WebConfiguration {
    [CmdletBinding()]param($PSPath,$Location,$Filter)
    if ($Filter -notlike '*windowsAuthentication') { throw 'Unexpected IIS section.' }
    [pscustomobject]@{enabled=$true;extendedProtection=[pscustomobject]@{tokenChecking='Require'};Password='never-export'}
}
function Get-WebConfigurationProperty { [CmdletBinding()]param($PSPath,$Location,$Filter,$Name) [pscustomobject]@{Value='Ssl'} }
function Test-Path { param($Path) return ($Path -eq 'IIS:\Sites\Test Site') }
$web=@(& (Get-CheckBlock CAWebEnrollment))
$enrollment=@($web | Where-Object Location -eq 'Test Site/CertSrv')
if ($enrollment.Count -ne 1 -or $enrollment[0].EnrollmentPathExists -or $enrollment[0].ExtendedProtection -ne 'Require' -or $enrollment[0].SSLFlags -ne 'Ssl') { throw 'IIS inherited/nonexistent endpoint evidence confused.' }
if ((ConvertTo-AuditJson -InputObject $web) -match 'never-export') { throw 'Unrequested IIS fields exported.' }
foreach ($fn in @('Get-Website','Get-WebApplication','Get-WebConfiguration','Get-WebConfigurationProperty','Test-Path','Import-Module')) { Remove-Item ('Function:'+ $fn) }
Write-Host 'PASS: actual CA/IIS collectors preserve allowlists, CA paths, EPA/SSL values and nonexistent endpoint distinction.'
