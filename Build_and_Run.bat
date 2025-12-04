@echo off
TITLE WinFix Tool Builder

:: Check for permissions
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

:: If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    if exist "%temp%\getadmin.vbs" ( del "%temp%\getadmin.vbs" )
    pushd "%CD%"
    CD /D "%~dp0"

echo.
echo ========================================================
echo   WinFix Tool - Builder & Launcher
echo ========================================================
echo.

echo [1/3] Checking for PS2EXE module...
powershell -NoProfile -Command "if (-not (Get-Module -ListAvailable -Name ps2exe)) { Write-Host 'Installing PS2EXE module...'; Install-Module -Name ps2exe -Scope CurrentUser -Force -SkipPublisherCheck } else { Write-Host 'PS2EXE is already installed.' }"

echo.
echo [2/3] Compiling WinFixTool.ps1 to WinFixTool.exe...

:: Kill existing process if running
taskkill /F /IM WinFixTool.exe >nul 2>&1
:: Small delay to release file locks
timeout /t 2 /nobreak >nul

if exist "WinFixTool.exe" del "WinFixTool.exe"

:: Verify deletion
if exist "WinFixTool.exe" (
    echo.
    echo [ERROR] Could not delete existing WinFixTool.exe. 
    echo Please close the application manually and try again.
    pause
    exit /b
)

powershell -NoProfile -Command "Import-Module ps2exe; Invoke-PS2EXE -InputFile '.\WinFixTool.ps1' -OutputFile '.\WinFixTool.exe' -Title 'WinFix Tool' -Version '1.0' -noConsole"

if exist "WinFixTool.exe" (
    echo.
    echo [3/3] Build Successful! WinFixTool.exe created.
    echo.
    echo Launching WinFixTool.exe...
    start "" "WinFixTool.exe"
) else (
    echo.
    echo [ERROR] Build failed. Please check the output above.
    pause
)

pause
