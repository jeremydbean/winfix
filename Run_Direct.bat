@echo off
TITLE WinFix Tool - Direct Download (Fixed Version)

echo ========================================
echo WinFix Tool - Direct Launch
echo ========================================
echo.
echo Downloading FIXED version for Server 2012 R2...
echo.

REM Clean temp
if exist "%TEMP%\WinFixTool_Direct*" del /q "%TEMP%\WinFixTool_Direct*" 2>nul

REM Download and run from specific commit with fix
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $url = 'https://raw.githubusercontent.com/jeremydbean/winfix/c7048f3/WinFixTool_v2.ps1'; Write-Host 'Downloading from commit c7048f3...' -ForegroundColor Cyan; try { $content = Invoke-RestMethod $url -ErrorAction Stop; if ($content -match 'if \(Get-Command Get-MpComputerStatus') { Write-Host '[OK] Downloaded version has Server 2012 R2 fix' -ForegroundColor Green } else { Write-Host '[WARNING] Downloaded version may not have fix' -ForegroundColor Yellow }; $temp = \"$env:TEMP\WinFixTool_Direct.ps1\"; $content | Out-File $temp -Encoding UTF8; Write-Host 'Launching...' -ForegroundColor Cyan; Start-Sleep 1; Start-Process powershell.exe -ArgumentList \"-NoProfile -ExecutionPolicy Bypass -STA -File `\"$temp`\"\" } catch { Write-Host '[ERROR] Download failed. Check internet connection.' -ForegroundColor Red; Read-Host 'Press Enter to exit' }"

echo.
if %errorlevel% EQU 0 (
    echo WinFix launched successfully in new window.
) else (
    echo Download or launch failed. Press any key to exit.
    pause >nul
)
