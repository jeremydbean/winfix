#requires -Version 4.0
<#
.SYNOPSIS
Download and run the WinFix audit using TLS 1.2, including Server 2012 R2.
.DESCRIPTION
Copy this entire script into an elevated 64-bit PowerShell ISE script pane and
press F5. Only this process's TLS selection is changed, then restored. Certificate
validation remains enabled. No registry settings or OS components are changed.
#>
[CmdletBinding()]
param(
    [switch]$SkipOnlineUpdateScan,
    [string]$EvidenceFile = ''
)

$previousProtocol = [Net.ServicePointManager]::SecurityProtocol
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    # Use the plain URL, never [url](url) Markdown formatting.
    $auditUrl = 'https://raw.githubusercontent.com/jeremydbean/winfix/main/Export-WinFixAudit.ps1'
    $auditScript = Invoke-RestMethod -Uri $auditUrl -TimeoutSec 60 -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace([string]$auditScript)) { throw 'The download returned an empty script.' }
    $collector = [scriptblock]::Create([string]$auditScript)
    & $collector -CopyToClipboard -SkipOnlineUpdateScan:$SkipOnlineUpdateScan -EvidenceFile $EvidenceFile
} catch {
    Write-Error -Message ("WinFix could not complete: " + $_.Exception.Message +
        " If HTTPS still fails with TLS 1.2, download Export-WinFixAudit.ps1 on a working computer and transfer it to this server, then run locally. Check the server's TLS/cipher, certificate, clock and proxy configuration; do not bypass certificate validation.")
} finally {
    [Net.ServicePointManager]::SecurityProtocol = $previousProtocol
}
