$ErrorActionPreference='Stop'
$path=Join-Path (Split-Path $PSScriptRoot) 'Export-WinFixDiskDiagnostic.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if ($errors.Count -or $ast.ScriptRequirements.RequiredPSVersion -ne [version]'4.0') { throw 'Disk diagnostic parse/version failure.' }
$ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$false) | ForEach-Object { . ([scriptblock]::Create($_.Extent.Text)) }
$before=@(Get-Job).Count
$single=Invoke-DiskDiagnosticSection -Name Good -Collect { [pscustomobject]@{Device='\Device\Harddisk2\DR5';Healthy=$false} }
if ($single -notmatch 'Collected' -or $single -notmatch '"Healthy":false') { throw 'Diagnostic values lost.' }
$partial=Invoke-DiskDiagnosticSection -Name Partial -Collect { 'first disk'; throw 'provider denied' }
if ($partial -notmatch 'Partial' -or $partial -notmatch 'first disk' -or $partial -notmatch 'provider denied') { throw 'Partial evidence lost.' }
$timeout=Invoke-DiskDiagnosticSection -Name Slow -TimeoutSeconds 2 -Collect { 'before timeout'; Start-Sleep 30 }
if ($timeout -notmatch 'TimedOut' -or $timeout -notmatch 'before timeout' -or @(Get-Job).Count -ne $before) { throw 'Timeout preservation/cleanup failed.' }
$cap=Invoke-DiskDiagnosticSection -Name Long -Collect { 'x'*260000 }
if ($cap -notmatch 'truncated at 250000' -or $cap.Length -gt 251000) { throw 'Diagnostic section output cap failed.' }
$mockEventCode={
    [CmdletBinding()]param($ListLog,$LogName,$FilterHashtable,$MaxEvents)
    if ($ListLog) { return [pscustomobject]@{IsEnabled=($ListLog -ne 'Disabled');RecordCount=2} }
    if ($MaxEvents -ne 3000) { throw 'Event scan not bounded.' }
    if ($FilterHashtable -and ($FilterHashtable.EndTime-$FilterHashtable.StartTime).TotalMinutes -ne 20) { throw 'Incident bounds wrong.' }
    foreach ($id in 51,153) {
        $e=[pscustomobject]@{TimeCreated=Get-Date;Id=$id;RecordId=$id;ProviderName='disk';Level=3;LevelDisplayName='Warning';Message=('error '+('x'*3100))}
        $e | Add-Member ScriptMethod ToXml { '<Event><EventData><Binary>A1B2C3D4</Binary></EventData></Event>' }
        $e
    }
}.ToString()
Set-Item Function:Get-WinEvent ([scriptblock]::Create($mockEventCode))
$events=@(Get-DiskDiagnosticEvents -LogName System -ProviderPattern '^disk$' -Limit 1)
if ($events.Count -ne 2 -or -not $events[0].OutputTruncated -or $events[1].Event51Xml -notmatch 'A1B2C3D4' -or -not $events[1].MessageTruncated) { throw 'Event51 binary evidence/message caps failed.' }
$events=@(Get-DiskDiagnosticEvents -LogName System -ProviderPattern '^disk$' -Incident '2026-09-28T11:31:13')
if ($events[0].IncidentWindowLocal -ne '2026-09-28T11:31:13' -or $events.Count -ne 3 -or $events[2].Event51Xml) { throw 'Incident selection or XML scope failed.' }
$disabled=@(Get-DiskDiagnosticEvents -LogName Disabled -ProviderPattern '.')
if ($disabled.Count -ne 1 -or $disabled[0].Enabled) { throw 'Disabled event log falsely reported.' }
$worker=Invoke-DiskDiagnosticSection -Name Events -Context @{EventCode=${function:Get-DiskDiagnosticEvents}.ToString();Mock=$mockEventCode} -Collect {
    Set-Item Function:Get-WinEvent ([scriptblock]::Create($Mock))
    Set-Item Function:Get-DiskDiagnosticEvents ([scriptblock]::Create($EventCode))
    Get-DiskDiagnosticEvents -LogName System -ProviderPattern '^disk$'
}
if ($worker -notmatch 'Collected' -or $worker -notmatch 'A1B2C3D4') { throw 'XML lost at worker serialization boundary.' }
Remove-Item Function:Get-WinEvent
# Compile the actual interop definition without invoking a Windows DLL on the test host.
$definition=$ast.Find({param($n) $n -is [Management.Automation.Language.StringConstantExpressionAst] -and $n.Value -like '*public static class WinFixDiskNative*'},$true)
if (-not $definition) { throw 'Missing device mapping interop definition.' }
Add-Type -TypeDefinition $definition.Value
if (-not ('WinFixDiskNative' -as [type])) { throw 'Device mapping interop did not compile.' }
Write-Host 'PASS: PS4 syntax requirement, worker errors/partial/timeout/cleanup, output caps, Event51 XML, incident bounds, disabled logs, serialization and native definition compilation. Windows APIs still require a live Windows run.'
