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
echo   WinFix Tool - Builder ^& Launcher
echo ========================================================
echo.

echo [1/4] Checking for PS2EXE module...
powershell -NoProfile -ExecutionPolicy Bypass -Command "if (-not (Get-Module -ListAvailable -Name ps2exe)) { Write-Host 'PS2EXE not found. Attempting to install...'; try { Install-Module -Name ps2exe -Scope CurrentUser -Force -SkipPublisherCheck -ErrorAction Stop; Write-Host 'PS2EXE installed successfully.' } catch { Write-Host 'WARNING: Could not install PS2EXE (no internet?). Will try fallback method.'; exit 1 } } else { Write-Host 'PS2EXE is already installed.' }"

set PS2EXE_INSTALLED=%errorlevel%

echo.
echo [2/4] Killing any running instances...
taskkill /F /IM WinFixTool.exe >nul 2>&1
timeout /t 1 /nobreak >nul

if exist "WinFixTool.exe" del "WinFixTool.exe"

:: Verify deletion
if exist "WinFixTool.exe" (
    echo.
    echo [ERROR] Could not delete existing WinFixTool.exe. 
    echo Please close the application manually and try again.
    pause
    exit /b
)

echo.
echo [3/4] Compiling WinFixTool.ps1 to WinFixTool.exe...

if %PS2EXE_INSTALLED% EQU 0 (
    echo Using PS2EXE module...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Import-Module ps2exe; Invoke-PS2EXE -InputFile '.\WinFixTool.ps1' -OutputFile '.\WinFixTool.exe' -Title 'WinFix Tool' -Version '1.0' -noConsole -requireAdmin"
) else (
    echo PS2EXE not available. Using fallback: Direct PowerShell execution wrapper...
    echo Creating WinFixTool_Wrapper.vbs...
    (
        echo Set objShell = CreateObject^("WScript.Shell"^)
        echo strPath = objShell.CurrentDirectory
        echo objShell.Run "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File """ ^& strPath ^& "\WinFixTool.ps1""", 0, False
    ) > WinFixTool_Wrapper.vbs
    echo.
    echo [FALLBACK MODE] Created VBS wrapper instead of EXE.
    echo To run the tool, double-click 'WinFixTool_Wrapper.vbs' or run the PS1 directly.
    set BUILD_SUCCESS=1
)

echo.
echo [4/4] Verifying build...

if exist "WinFixTool.exe" (
    echo.
    echo ========================================================
    echo   BUILD SUCCESSFUL!
    echo ========================================================
    echo   File: WinFixTool.exe
    echo   Launching...
    echo ========================================================
    echo.
    start "" "WinFixTool.exe"
    timeout /t 2 /nobreak >nul
    exit
) else if defined BUILD_SUCCESS (
    echo.
    echo ========================================================
    echo   FALLBACK BUILD CREATED
    echo ========================================================
    echo   PS2EXE unavailable ^(no internet connection^)
    echo   
    echo   Run one of these instead:
    echo   1. WinFixTool_Wrapper.vbs  ^(double-click^)
    echo   2. powershell.exe -ExecutionPolicy Bypass -File WinFixTool.ps1
    echo ========================================================
    pause
) else (
    echo.
    echo ========================================================
    echo   BUILD FAILED
    echo ========================================================
    echo   Unable to compile. Check errors above.
    echo   
    echo   Manual run: powershell.exe -ExecutionPolicy Bypass -File WinFixTool.ps1
    echo ========================================================
    pause
)

pause
