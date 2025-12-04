@echo off
TITLE WinFix Tool - Direct Launch

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
echo   WinFix Tool - Direct PowerShell Launch
echo ========================================================
echo.
echo   Running WinFixTool.ps1 directly without compilation
echo   This method works without internet access
echo.
echo ========================================================
echo.

powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0WinFixTool.ps1"

if %errorlevel% NEQ 0 (
    echo.
    echo [ERROR] Script execution failed.
    pause
)
