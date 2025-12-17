# WinFix Tool - One-Line Installer
# Downloads and launches WinFixTool from GitHub

$ErrorActionPreference = "Stop"

# Force TLS 1.2 for GitHub connections
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "  WinFix Tool - Remote Installer" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] Requesting Administrator privileges..." -ForegroundColor Yellow
    $scriptPath = $MyInvocation.MyCommand.Path
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -NoProfile -Command `"irm https://raw.githubusercontent.com/jeremydbean/winfix/main/install.ps1 | iex`""
    exit
}

Write-Host "[+] Running as Administrator" -ForegroundColor Green

# Create temp directory
$tempDir = "$env:TEMP\WinFixTool_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
Write-Host "[+] Created temp directory: $tempDir" -ForegroundColor Green

# Download main script
Write-Host "[*] Downloading WinFixTool_v2.ps1..." -ForegroundColor Cyan
try {
    $scriptUrl = "https://raw.githubusercontent.com/jeremydbean/winfix/main/WinFixTool_v2.ps1"
    $scriptPath = "$tempDir\WinFixTool_v2.ps1"
    Invoke-WebRequest -Uri $scriptUrl -OutFile $scriptPath -UseBasicParsing
    Write-Host "[+] Downloaded successfully" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Failed to download script: $_" -ForegroundColor Red
    pause
    exit 1
}

# Launch the tool
Write-Host ""
Write-Host "[*] Launching WinFixTool v2..." -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host ""

Start-Process powershell.exe -WorkingDirectory $tempDir -Wait -ArgumentList @(
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-STA',
    '-File', $scriptPath
)

# Cleanup on exit
Write-Host ""
Write-Host "[*] Cleaning up temporary files..." -ForegroundColor Cyan
Set-Location $env:TEMP
Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "[+] Done" -ForegroundColor Green
