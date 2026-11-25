<#
.SYNOPSIS
Builds WinFixAuditApp.exe with the C# compiler that ships with .NET Framework 4.x.
No Visual Studio, SDK or NuGet packages are needed.

.PARAMETER Collector
Path to Export-WinFixAudit.ps1 to embed. Defaults to the collector in the repository root,
so rebuilding after a collector change ships the new version.

.PARAMETER AsInvoker
Build without the administrator prompt. For local testing only.
#>
[CmdletBinding()]
param(
    [string]$Collector = (Join-Path (Split-Path $PSScriptRoot -Parent) 'Export-WinFixAudit.ps1'),
    [string]$Output = (Join-Path $PSScriptRoot 'dist\WinFixAuditApp.exe'),
    [switch]$AsInvoker
)
$ErrorActionPreference = 'Stop'

$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
if (-not (Test-Path $csc)) { throw 'csc.exe from .NET Framework 4.x was not found.' }
if (-not (Test-Path $Collector)) { throw "Collector script not found: $Collector" }

$manifest = Join-Path $PSScriptRoot 'app.manifest'
$tempManifest = $null
if ($AsInvoker) {
    $tempManifest = Join-Path $env:TEMP ('WinFixAudit-asInvoker-' + [guid]::NewGuid().ToString('N') + '.manifest')
    (Get-Content $manifest -Raw) -replace 'requireAdministrator', 'asInvoker' | Set-Content -Path $tempManifest -Encoding UTF8
    $manifest = $tempManifest
}

New-Item -ItemType Directory -Force -Path (Split-Path $Output) | Out-Null
$sources = Get-ChildItem (Join-Path $PSScriptRoot 'src') -Filter *.cs | ForEach-Object { $_.FullName }
$references = 'System.dll', 'System.Core.dll', 'System.Drawing.dll', 'System.Windows.Forms.dll', 'System.Web.Extensions.dll', 'System.Security.dll'
$arguments = @('/nologo', '/target:winexe', '/platform:anycpu', '/optimize+', '/warn:4',
    "/out:$Output", "/win32manifest:$manifest", "/resource:$Collector,Export-WinFixAudit.ps1") +
    ($references | ForEach-Object { "/reference:$_" }) + $sources

try {
    & $csc @arguments
    if ($LASTEXITCODE -ne 0) { throw "Compilation failed (exit $LASTEXITCODE)." }
} finally {
    if ($tempManifest) { Remove-Item $tempManifest -ErrorAction SilentlyContinue }
}

$hash = (Get-FileHash $Output -Algorithm SHA256).Hash
$version = if ((Get-Content $Collector -Raw) -match 'WinFix audit (\d+(\.\d+)*)') { $Matches[1] } else { 'unknown' }
Write-Host "Built $Output"
Write-Host "  Collector version: $version"
Write-Host "  SHA256: $hash"
