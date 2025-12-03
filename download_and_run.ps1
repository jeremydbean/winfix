$installDir = "$env:USERPROFILE\Desktop\WinFix_Build"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
Set-Location $installDir

Write-Host "Downloading WinFixTool files..." -ForegroundColor Cyan
try {
    Invoke-WebRequest "https://raw.githubusercontent.com/jeremydbean/winfix/main/WinFixTool.ps1" -OutFile "WinFixTool.ps1" -ErrorAction Stop
    Invoke-WebRequest "https://raw.githubusercontent.com/jeremydbean/winfix/main/Build_and_Run.bat" -OutFile "Build_and_Run.bat" -ErrorAction Stop
}
catch {
    Write-Error "Failed to download files. Please check your internet connection."
    Exit
}

Write-Host "Files downloaded to $installDir" -ForegroundColor Green
Write-Host "Starting Builder..." -ForegroundColor Green

# Start the batch file (which handles Admin elevation)
Start-Process ".\Build_and_Run.bat"