<#
.SYNOPSIS
Builds PolarniteServerAuditTool.exe with the C# compiler that ships with .NET Framework 4.x.
No Visual Studio, SDK or NuGet packages are needed.

.PARAMETER Collector
Path to Export-WinFixAudit.ps1 to embed. Defaults to the collector in the repository root,
so rebuilding after a collector change ships the new version.

.PARAMETER AsInvoker
Build without the administrator prompt. For local testing only.
#>
[CmdletBinding()]
param(
    [string]$Collector = '',
    [string]$Output = '',
    [switch]$AsInvoker
)
$ErrorActionPreference = 'Stop'
# Defaults are resolved here: Windows PowerShell leaves $PSScriptRoot empty in param() defaults under -File.
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $Collector) { $Collector = Join-Path (Split-Path $here -Parent) 'Export-WinFixAudit.ps1' }
if (-not $Output) { $Output = Join-Path $here 'dist\PolarniteServerAuditTool.exe' }

$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
if (-not (Test-Path $csc)) { throw 'csc.exe from .NET Framework 4.x was not found.' }
if (-not (Test-Path $Collector)) { throw "Collector script not found: $Collector" }

$manifest = Join-Path $here 'app.manifest'
$tempManifest = $null
if ($AsInvoker) {
    $tempManifest = Join-Path $env:TEMP ('PolarniteAudit-asInvoker-' + [guid]::NewGuid().ToString('N') + '.manifest')
    (Get-Content $manifest -Raw) -replace 'requireAdministrator', 'asInvoker' | Set-Content -Path $tempManifest -Encoding UTF8
    $manifest = $tempManifest
}

New-Item -ItemType Directory -Force -Path (Split-Path $Output) | Out-Null
$version = if ((Get-Content $Collector -Raw) -match 'WinFix audit (\d+(\.\d+)*)') { $Matches[1] } else { 'unknown' }
$built = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
# Build stamp used by the in-app updater to tell whether the build on GitHub is newer.
$buildInfo = Join-Path $env:TEMP ('PolarniteAudit-BuildInfo-' + [guid]::NewGuid().ToString('N') + '.cs')
[IO.File]::WriteAllText($buildInfo, "namespace PolarniteAudit { internal static class BuildInfo { public const string BuiltUtc = `"$built`"; public const string Collector = `"$version`"; } }")
$sources = @(Get-ChildItem (Join-Path $here 'src') -Filter *.cs | ForEach-Object { $_.FullName }) + $buildInfo
$references = 'System.dll', 'System.Core.dll', 'System.Drawing.dll', 'System.Windows.Forms.dll', 'System.Web.Extensions.dll', 'System.Security.dll'
$arguments = @('/nologo', '/codepage:65001', '/target:winexe', '/platform:anycpu', '/optimize+', '/warn:4',
    "/out:$Output", "/win32manifest:$manifest", "/resource:$Collector,Export-WinFixAudit.ps1") +
    ($references | ForEach-Object { "/reference:$_" }) + $sources

try {
    & $csc @arguments
    if ($LASTEXITCODE -ne 0) { throw "Compilation failed (exit $LASTEXITCODE)." }
} finally {
    if ($tempManifest) { Remove-Item $tempManifest -ErrorAction SilentlyContinue }
    Remove-Item $buildInfo -ErrorAction SilentlyContinue
}

$hash = (Get-FileHash $Output -Algorithm SHA256).Hash
# latest.json next to the exe: what the app's "Check for updates" reads from GitHub. Commit it with the exe.
$latest = [ordered]@{ File=(Split-Path $Output -Leaf); BuiltUtc=$built; Collector=$version; Sha256=$hash; Size=(Get-Item $Output).Length }
[IO.File]::WriteAllText((Join-Path (Split-Path $Output) 'latest.json'), ($latest | ConvertTo-Json), (New-Object Text.UTF8Encoding($false)))
Write-Host "Built $Output"
Write-Host "  Collector version: $version"
Write-Host "  Built (UTC): $built"
Write-Host "  SHA256: $hash"
