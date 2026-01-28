# Direct download bypass for WinFix - Gets fixed version from specific commit
# Run this on Windows server to bypass GitHub CDN cache

Write-Host "WinFix Direct Download (Commit c7048f3)" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# Clean up old downloads
Write-Host "`nCleaning old temp files..." -ForegroundColor Yellow
Remove-Item "$env:TEMP\WinFixTool_*" -Recurse -Force -ErrorAction SilentlyContinue

# Set TLS
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Download from specific commit (no cache)
Write-Host "Downloading from commit c7048f3..." -ForegroundColor Yellow
$url = "https://raw.githubusercontent.com/jeremydbean/winfix/c7048f3/WinFixTool_v2.ps1"

try {
    $content = Invoke-RestMethod $url -ErrorAction Stop
    
    # Verify it has the fix
    if ($content -match 'if \(Get-Command Get-MpComputerStatus') {
        Write-Host "[OK] Downloaded version contains Server 2012 R2 fix" -ForegroundColor Green
    } else {
        Write-Host "[WARNING] Downloaded version may not have the fix!" -ForegroundColor Red
        Write-Host "This might still be cached. Press Ctrl+C to abort." -ForegroundColor Red
        Start-Sleep -Seconds 3
    }
    
    # Save to temp
    $tempScript = "$env:TEMP\WinFixTool_Direct.ps1"
    $content | Out-File $tempScript -Encoding UTF8
    Write-Host "Saved to: $tempScript" -ForegroundColor Green
    
    # Launch
    Write-Host "`nLaunching WinFix Tool..." -ForegroundColor Cyan
    powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File $tempScript
    
} catch {
    Write-Host "[ERROR] Download failed: $_" -ForegroundColor Red
    Write-Host "`nPress any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}
