<#
.SYNOPSIS
    WinFix Tool v2.1 - Lightweight Windows Maintenance & Diagnostics
.DESCRIPTION
    Fast, snappy GUI tool for Windows maintenance. No auto-loading - refresh on demand.
.NOTES
    Requires Administrator Privileges.
    Author: Jeremy Bean IT
    Version: 2.1
#>

# --- Request Admin Privileges ---
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    $newProcess = New-Object System.Diagnostics.ProcessStartInfo "PowerShell"
    $newProcess.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    $newProcess.Verb = "runas"
    [System.Diagnostics.Process]::Start($newProcess)
    Exit
}

# --- Load Assemblies ---
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# --- Global Settings ---
[System.Windows.Forms.Application]::EnableVisualStyles()
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# --- Theme ---
$script:Theme = @{
    Bg       = [System.Drawing.Color]::FromArgb(22, 22, 26)
    Surface  = [System.Drawing.Color]::FromArgb(32, 32, 38)
    Card     = [System.Drawing.Color]::FromArgb(42, 42, 50)
    Text     = [System.Drawing.Color]::White
    Dim      = [System.Drawing.Color]::FromArgb(140, 140, 150)
    Accent   = [System.Drawing.Color]::FromArgb(66, 135, 245)
    Green    = [System.Drawing.Color]::FromArgb(46, 204, 113)
    Yellow   = [System.Drawing.Color]::FromArgb(241, 196, 15)
    Red      = [System.Drawing.Color]::FromArgb(231, 76, 60)
}

$global:LogPath = "$env:TEMP\WinFix_Debug.log"

# --- Status Indicator Characters ---
$script:StatusOK = "[OK]"
$script:StatusWarn = "[!!]"
$script:StatusBad = "[XX]"
$script:StatusPending = "[..]"

# --- Logging ---
function Log {
    param([string]$Msg)
    $ts = Get-Date -Format "HH:mm:ss"
    $line = "[$ts] $Msg"
    Add-Content -Path $global:LogPath -Value $line -ErrorAction SilentlyContinue
    if ($script:txtLog) {
        $script:txtLog.AppendText("$line`r`n")
        $script:txtLog.ScrollToCaret()
    }
}

# --- NinjaOne Settings ---
function Get-NinjaSettings {
    $regPath = "HKCU:\Software\WinFixTool"
    try {
        if (Test-Path $regPath) {
            return @{
                Url = (Get-ItemProperty -Path $regPath -Name "NinjaUrl" -ErrorAction SilentlyContinue).NinjaUrl
                ClientId = (Get-ItemProperty -Path $regPath -Name "NinjaClientId" -ErrorAction SilentlyContinue).NinjaClientId
                ClientSecret = (Get-ItemProperty -Path $regPath -Name "NinjaClientSecret" -ErrorAction SilentlyContinue).NinjaClientSecret
            }
        }
    } catch { }
    return @{ Url = ""; ClientId = ""; ClientSecret = "" }
}

function Save-NinjaSettings {
    param($Url, $Id, $Secret)
    $regPath = "HKCU:\Software\WinFixTool"
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    Set-ItemProperty -Path $regPath -Name "NinjaUrl" -Value $Url
    Set-ItemProperty -Path $regPath -Name "NinjaClientId" -Value $Id
    Set-ItemProperty -Path $regPath -Name "NinjaClientSecret" -Value $Secret
}

function Connect-NinjaOne {
    param($ClientId, $ClientSecret, $InstanceUrl)
    Log "Connecting to NinjaOne..."
    $InstanceUrl = $InstanceUrl -replace "^https?://", "" -replace "/$", "" -replace "/apidocs.*", "" -replace "/ws/.*", ""
    $global:NinjaInstance = $InstanceUrl
    
    try {
        $authUrl = "https://$InstanceUrl/ws/oauth/token"
        $body = @{ grant_type = "client_credentials"; client_id = $ClientId; client_secret = $ClientSecret; scope = "monitoring management" }
        $response = Invoke-RestMethod -Uri $authUrl -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
        $global:NinjaToken = $response.access_token
        Log "NinjaOne connected!"
        return $true
    } catch {
        Log "NinjaOne connection failed: $_"
        return $false
    }
}

# --- Create Main Form ---
$form = New-Object System.Windows.Forms.Form
$form.Text = "WinFix Tool v2.1"
$form.Size = New-Object System.Drawing.Size(950, 650)
$form.MinimumSize = New-Object System.Drawing.Size(800, 500)
$form.StartPosition = "CenterScreen"
$form.BackColor = $script:Theme.Bg
$form.ForeColor = $script:Theme.Text
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$form.FormBorderStyle = "Sizable"

# --- Header ---
$panelHeader = New-Object System.Windows.Forms.Panel
$panelHeader.Dock = "Top"
$panelHeader.Height = 50
$panelHeader.BackColor = $script:Theme.Surface

$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = "WinFix Tool"
$lblTitle.Location = New-Object System.Drawing.Point(15, 12)
$lblTitle.AutoSize = $true
$lblTitle.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
$lblTitle.ForeColor = $script:Theme.Accent

$lblPC = New-Object System.Windows.Forms.Label
$lblPC.Text = "$env:COMPUTERNAME"
$lblPC.Location = New-Object System.Drawing.Point(750, 15)
$lblPC.AutoSize = $true
$lblPC.Anchor = "Top, Right"
$lblPC.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)

$panelHeader.Controls.AddRange(@($lblTitle, $lblPC))

# --- Nav Panel ---
$panelNav = New-Object System.Windows.Forms.Panel
$panelNav.Dock = "Left"
$panelNav.Width = 140
$panelNav.BackColor = $script:Theme.Surface

$navItems = @("Dashboard", "Quick Fix", "Diagnostics", "Network", "NinjaOne", "Audit")
$navButtons = @()
$navY = 10

foreach ($nav in $navItems) {
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $nav
    $btn.Location = New-Object System.Drawing.Point(5, $navY)
    $btn.Size = New-Object System.Drawing.Size(130, 35)
    $btn.FlatStyle = "Flat"
    $btn.BackColor = $script:Theme.Card
    $btn.ForeColor = $script:Theme.Text
    $btn.FlatAppearance.BorderSize = 0
    $btn.Tag = $nav
    $btn.Add_Click({ Show-Page $this.Tag })
    $panelNav.Controls.Add($btn)
    $navButtons += $btn
    $navY += 40
}

# --- Log Panel (collapsible) ---
$panelLog = New-Object System.Windows.Forms.Panel
$panelLog.Dock = "Bottom"
$panelLog.Height = 80
$panelLog.BackColor = $script:Theme.Surface

$lblLog = New-Object System.Windows.Forms.Label
$lblLog.Text = "Log"
$lblLog.Dock = "Top"
$lblLog.Height = 18
$lblLog.ForeColor = $script:Theme.Dim
$lblLog.Font = New-Object System.Drawing.Font("Segoe UI", 8)

$script:txtLog = New-Object System.Windows.Forms.TextBox
$script:txtLog.Multiline = $true
$script:txtLog.ScrollBars = "Vertical"
$script:txtLog.ReadOnly = $true
$script:txtLog.Dock = "Fill"
$script:txtLog.BackColor = [System.Drawing.Color]::FromArgb(18, 18, 20)
$script:txtLog.ForeColor = [System.Drawing.Color]::FromArgb(0, 200, 0)
$script:txtLog.Font = New-Object System.Drawing.Font("Consolas", 8)
$script:txtLog.BorderStyle = "None"

$panelLog.Controls.AddRange(@($lblLog, $script:txtLog))

# --- Content Panel ---
$panelContent = New-Object System.Windows.Forms.Panel
$panelContent.Dock = "Fill"
$panelContent.BackColor = $script:Theme.Bg

$pages = @{}

# === DASHBOARD PAGE ===
$pageDash = New-Object System.Windows.Forms.Panel
$pageDash.Dock = "Fill"
$pageDash.BackColor = $script:Theme.Bg

# Status Grid - Left column
$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Text = "SYSTEM STATUS"
$lblStatus.Location = New-Object System.Drawing.Point(20, 15)
$lblStatus.AutoSize = $true
$lblStatus.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$lblStatus.ForeColor = $script:Theme.Dim

$script:lblCPU = New-Object System.Windows.Forms.Label
$script:lblCPU.Text = "$($script:StatusPending) CPU: --"
$script:lblCPU.Location = New-Object System.Drawing.Point(20, 50)
$script:lblCPU.Size = New-Object System.Drawing.Size(300, 22)
$script:lblCPU.Font = New-Object System.Drawing.Font("Consolas", 10)

$script:lblRAM = New-Object System.Windows.Forms.Label
$script:lblRAM.Text = "$($script:StatusPending) Memory: --"
$script:lblRAM.Location = New-Object System.Drawing.Point(20, 75)
$script:lblRAM.Size = New-Object System.Drawing.Size(300, 22)
$script:lblRAM.Font = New-Object System.Drawing.Font("Consolas", 10)

$script:lblDisk = New-Object System.Windows.Forms.Label
$script:lblDisk.Text = "$($script:StatusPending) Disk C: --"
$script:lblDisk.Location = New-Object System.Drawing.Point(20, 100)
$script:lblDisk.Size = New-Object System.Drawing.Size(300, 22)
$script:lblDisk.Font = New-Object System.Drawing.Font("Consolas", 10)

$script:lblUptime = New-Object System.Windows.Forms.Label
$script:lblUptime.Text = "$($script:StatusPending) Uptime: --"
$script:lblUptime.Location = New-Object System.Drawing.Point(20, 125)
$script:lblUptime.Size = New-Object System.Drawing.Size(300, 22)
$script:lblUptime.Font = New-Object System.Drawing.Font("Consolas", 10)

$script:lblUpdates = New-Object System.Windows.Forms.Label
$script:lblUpdates.Text = "$($script:StatusPending) Updates: --"
$script:lblUpdates.Location = New-Object System.Drawing.Point(20, 150)
$script:lblUpdates.Size = New-Object System.Drawing.Size(300, 22)
$script:lblUpdates.Font = New-Object System.Drawing.Font("Consolas", 10)

$script:lblServices = New-Object System.Windows.Forms.Label
$script:lblServices.Text = "$($script:StatusPending) Services: --"
$script:lblServices.Location = New-Object System.Drawing.Point(20, 175)
$script:lblServices.Size = New-Object System.Drawing.Size(300, 22)
$script:lblServices.Font = New-Object System.Drawing.Font("Consolas", 10)

$script:lblNinjaStatus = New-Object System.Windows.Forms.Label
$script:lblNinjaStatus.Text = "$($script:StatusPending) NinjaOne: --"
$script:lblNinjaStatus.Location = New-Object System.Drawing.Point(20, 200)
$script:lblNinjaStatus.Size = New-Object System.Drawing.Size(300, 22)
$script:lblNinjaStatus.Font = New-Object System.Drawing.Font("Consolas", 10)

# Right side - System Info
$lblInfoTitle = New-Object System.Windows.Forms.Label
$lblInfoTitle.Text = "SYSTEM INFO"
$lblInfoTitle.Location = New-Object System.Drawing.Point(350, 15)
$lblInfoTitle.AutoSize = $true
$lblInfoTitle.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$lblInfoTitle.ForeColor = $script:Theme.Dim

$script:lblSysInfo = New-Object System.Windows.Forms.Label
$script:lblSysInfo.Text = "Click Refresh to load system info..."
$script:lblSysInfo.Location = New-Object System.Drawing.Point(350, 50)
$script:lblSysInfo.Size = New-Object System.Drawing.Size(380, 180)
$script:lblSysInfo.Font = New-Object System.Drawing.Font("Consolas", 9)
$script:lblSysInfo.Anchor = "Top, Left, Right"

# Refresh Button
$btnRefresh = New-Object System.Windows.Forms.Button
$btnRefresh.Text = "Refresh Status"
$btnRefresh.Location = New-Object System.Drawing.Point(20, 240)
$btnRefresh.Size = New-Object System.Drawing.Size(150, 35)
$btnRefresh.FlatStyle = "Flat"
$btnRefresh.BackColor = $script:Theme.Accent
$btnRefresh.ForeColor = "White"
$btnRefresh.FlatAppearance.BorderSize = 0
$btnRefresh.Add_Click({
    Log "Refreshing status..."
    $this.Enabled = $false
    $this.Text = "Loading..."
    [System.Windows.Forms.Application]::DoEvents()
    
    # CPU
    try {
        $cpu = (Get-CimInstance Win32_Processor).LoadPercentage
        if ($cpu -lt 80) {
            $script:lblCPU.Text = "$($script:StatusOK) CPU: ${cpu}%"
            $script:lblCPU.ForeColor = $script:Theme.Green
        } elseif ($cpu -lt 95) {
            $script:lblCPU.Text = "$($script:StatusWarn) CPU: ${cpu}%"
            $script:lblCPU.ForeColor = $script:Theme.Yellow
        } else {
            $script:lblCPU.Text = "$($script:StatusBad) CPU: ${cpu}%"
            $script:lblCPU.ForeColor = $script:Theme.Red
        }
    } catch { $script:lblCPU.Text = "$($script:StatusBad) CPU: Error"; $script:lblCPU.ForeColor = $script:Theme.Red }
    [System.Windows.Forms.Application]::DoEvents()
    
    # RAM
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $ramPct = [math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize * 100)
        $ramGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
        if ($ramPct -lt 80) {
            $script:lblRAM.Text = "$($script:StatusOK) Memory: ${ramPct}% of ${ramGB}GB"
            $script:lblRAM.ForeColor = $script:Theme.Green
        } elseif ($ramPct -lt 95) {
            $script:lblRAM.Text = "$($script:StatusWarn) Memory: ${ramPct}% of ${ramGB}GB"
            $script:lblRAM.ForeColor = $script:Theme.Yellow
        } else {
            $script:lblRAM.Text = "$($script:StatusBad) Memory: ${ramPct}% of ${ramGB}GB"
            $script:lblRAM.ForeColor = $script:Theme.Red
        }
    } catch { $script:lblRAM.Text = "$($script:StatusBad) Memory: Error"; $script:lblRAM.ForeColor = $script:Theme.Red }
    [System.Windows.Forms.Application]::DoEvents()
    
    # Disk
    try {
        $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
        $diskPct = [math]::Round(($disk.Size - $disk.FreeSpace) / $disk.Size * 100)
        $diskFree = [math]::Round($disk.FreeSpace / 1GB)
        if ($diskPct -lt 85) {
            $script:lblDisk.Text = "$($script:StatusOK) Disk C: ${diskPct}% (${diskFree}GB free)"
            $script:lblDisk.ForeColor = $script:Theme.Green
        } elseif ($diskPct -lt 95) {
            $script:lblDisk.Text = "$($script:StatusWarn) Disk C: ${diskPct}% (${diskFree}GB free)"
            $script:lblDisk.ForeColor = $script:Theme.Yellow
        } else {
            $script:lblDisk.Text = "$($script:StatusBad) Disk C: ${diskPct}% (${diskFree}GB free)"
            $script:lblDisk.ForeColor = $script:Theme.Red
        }
    } catch { $script:lblDisk.Text = "$($script:StatusBad) Disk: Error"; $script:lblDisk.ForeColor = $script:Theme.Red }
    [System.Windows.Forms.Application]::DoEvents()
    
    # Uptime
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $uptime = (Get-Date) - $os.LastBootUpTime
        if ($uptime.Days -lt 14) {
            $script:lblUptime.Text = "$($script:StatusOK) Uptime: $($uptime.Days)d $($uptime.Hours)h"
            $script:lblUptime.ForeColor = $script:Theme.Green
        } elseif ($uptime.Days -lt 30) {
            $script:lblUptime.Text = "$($script:StatusWarn) Uptime: $($uptime.Days)d $($uptime.Hours)h"
            $script:lblUptime.ForeColor = $script:Theme.Yellow
        } else {
            $script:lblUptime.Text = "$($script:StatusBad) Uptime: $($uptime.Days)d (reboot needed)"
            $script:lblUptime.ForeColor = $script:Theme.Red
        }
    } catch { $script:lblUptime.Text = "$($script:StatusBad) Uptime: Error"; $script:lblUptime.ForeColor = $script:Theme.Red }
    [System.Windows.Forms.Application]::DoEvents()
    
    # Windows Updates (slow - do last)
    try {
        $updates = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
        $pending = $updates.Search("IsInstalled=0 and IsHidden=0").Updates.Count
        if ($pending -eq 0) {
            $script:lblUpdates.Text = "$($script:StatusOK) Updates: All current"
            $script:lblUpdates.ForeColor = $script:Theme.Green
        } elseif ($pending -lt 5) {
            $script:lblUpdates.Text = "$($script:StatusWarn) Updates: $pending pending"
            $script:lblUpdates.ForeColor = $script:Theme.Yellow
        } else {
            $script:lblUpdates.Text = "$($script:StatusBad) Updates: $pending pending"
            $script:lblUpdates.ForeColor = $script:Theme.Red
        }
    } catch { 
        $script:lblUpdates.Text = "$($script:StatusPending) Updates: Unable to check"
        $script:lblUpdates.ForeColor = $script:Theme.Dim
    }
    [System.Windows.Forms.Application]::DoEvents()
    
    # Critical Services
    try {
        $stopped = @()
        foreach ($svc in @("wuauserv", "Spooler", "BITS", "EventLog", "Dnscache")) {
            $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
            if ($s -and $s.Status -ne "Running") { $stopped += $svc }
        }
        if ($stopped.Count -eq 0) {
            $script:lblServices.Text = "$($script:StatusOK) Services: All running"
            $script:lblServices.ForeColor = $script:Theme.Green
        } else {
            $script:lblServices.Text = "$($script:StatusWarn) Services: $($stopped.Count) stopped"
            $script:lblServices.ForeColor = $script:Theme.Yellow
        }
    } catch { $script:lblServices.Text = "$($script:StatusBad) Services: Error"; $script:lblServices.ForeColor = $script:Theme.Red }
    [System.Windows.Forms.Application]::DoEvents()
    
    # NinjaOne
    if ($global:NinjaToken) {
        $script:lblNinjaStatus.Text = "$($script:StatusOK) NinjaOne: Connected"
        $script:lblNinjaStatus.ForeColor = $script:Theme.Green
    } else {
        $script:lblNinjaStatus.Text = "$($script:StatusPending) NinjaOne: Not connected"
        $script:lblNinjaStatus.ForeColor = $script:Theme.Dim
    }
    
    # System Info
    try {
        $cs = Get-CimInstance Win32_ComputerSystem
        $os = Get-CimInstance Win32_OperatingSystem
        $bios = Get-CimInstance Win32_Bios
        $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
        
        $script:lblSysInfo.Text = @"
$($cs.Manufacturer) $($cs.Model)
Serial: $($bios.SerialNumber)

$($os.Caption)
Build: $($os.BuildNumber)

$($cpu.Name)
Cores: $($cpu.NumberOfCores) / Threads: $($cpu.NumberOfLogicalProcessors)
"@
    } catch { $script:lblSysInfo.Text = "Error loading system info" }
    
    $this.Text = "Refresh Status"
    $this.Enabled = $true
    Log "Status refresh complete"
})

$pageDash.Controls.AddRange(@($lblStatus, $script:lblCPU, $script:lblRAM, $script:lblDisk, $script:lblUptime, $script:lblUpdates, $script:lblServices, $script:lblNinjaStatus, $lblInfoTitle, $script:lblSysInfo, $btnRefresh))
$pages["Dashboard"] = $pageDash

# === QUICK FIX PAGE ===
$pageQuick = New-Object System.Windows.Forms.Panel
$pageQuick.Dock = "Fill"
$pageQuick.BackColor = $script:Theme.Bg
$pageQuick.AutoScroll = $true

$lblQuickTitle = New-Object System.Windows.Forms.Label
$lblQuickTitle.Text = "QUICK FIXES"
$lblQuickTitle.Location = New-Object System.Drawing.Point(20, 15)
$lblQuickTitle.AutoSize = $true
$lblQuickTitle.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$lblQuickTitle.ForeColor = $script:Theme.Dim

$pageQuick.Controls.Add($lblQuickTitle)

$fixes = @(
    @{Name = "Clear Temp Files"; Cmd = { Remove-Item "$env:TEMP\*","C:\Windows\Temp\*" -Recurse -Force -EA 0; Clear-RecycleBin -Force -EA 0; "Done!" }}
    @{Name = "Flush DNS"; Cmd = { ipconfig /flushdns }}
    @{Name = "Reset Network"; Cmd = { netsh winsock reset; netsh int ip reset; ipconfig /release; ipconfig /renew; "Done! Restart recommended." }}
    @{Name = "Fix Windows Update"; Cmd = { Stop-Service wuauserv,cryptSvc,bits,msiserver -Force -EA 0; Remove-Item "C:\Windows\SoftwareDistribution\*","C:\Windows\System32\catroot2\*" -Recurse -Force -EA 0; Start-Service wuauserv,cryptSvc,bits,msiserver -EA 0; "Done!" }}
    @{Name = "Clear Print Spooler"; Cmd = { Stop-Service Spooler -Force; Remove-Item "C:\Windows\System32\spool\PRINTERS\*" -Force -EA 0; Start-Service Spooler; "Done!" }}
    @{Name = "SFC Scan"; Cmd = { sfc /scannow }}
    @{Name = "DISM Repair"; Cmd = { DISM /Online /Cleanup-Image /RestoreHealth }}
    @{Name = "Sync Time"; Cmd = { w32tm /resync /force }}
    @{Name = "Restart Explorer"; Cmd = { Stop-Process -Name explorer -Force; Start-Process explorer; "Done!" }}
)

$fixY = 50; $fixX = 20; $fixCol = 0
foreach ($fix in $fixes) {
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $fix.Name
    $btn.Location = New-Object System.Drawing.Point($fixX, $fixY)
    $btn.Size = New-Object System.Drawing.Size(160, 40)
    $btn.FlatStyle = "Flat"
    $btn.BackColor = $script:Theme.Card
    $btn.ForeColor = $script:Theme.Text
    $btn.FlatAppearance.BorderSize = 0
    $btn.Tag = $fix.Cmd
    $btn.Add_Click({
        Log "Running: $($this.Text)..."
        try {
            $result = & $this.Tag
            if ($result) { Log $result }
            [System.Windows.Forms.MessageBox]::Show("$($this.Text) complete!", "WinFix", "OK", "Information")
        } catch { Log "Error: $_"; [System.Windows.Forms.MessageBox]::Show("Error: $_", "WinFix", "OK", "Error") }
    })
    $pageQuick.Controls.Add($btn)
    
    $fixCol++
    if ($fixCol -ge 4) { $fixCol = 0; $fixX = 20; $fixY += 50 }
    else { $fixX += 170 }
}

$pages["Quick Fix"] = $pageQuick

# === DIAGNOSTICS PAGE ===
$pageDiag = New-Object System.Windows.Forms.Panel
$pageDiag.Dock = "Fill"
$pageDiag.BackColor = $script:Theme.Bg

$lblDiagTitle = New-Object System.Windows.Forms.Label
$lblDiagTitle.Text = "DIAGNOSTICS"
$lblDiagTitle.Location = New-Object System.Drawing.Point(20, 15)
$lblDiagTitle.AutoSize = $true
$lblDiagTitle.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$lblDiagTitle.ForeColor = $script:Theme.Dim

$txtDiag = New-Object System.Windows.Forms.TextBox
$txtDiag.Multiline = $true
$txtDiag.ScrollBars = "Both"
$txtDiag.ReadOnly = $true
$txtDiag.Location = New-Object System.Drawing.Point(20, 50)
$txtDiag.Size = New-Object System.Drawing.Size(500, 350)
$txtDiag.BackColor = $script:Theme.Surface
$txtDiag.ForeColor = $script:Theme.Text
$txtDiag.Font = New-Object System.Drawing.Font("Consolas", 9)
$txtDiag.Anchor = "Top, Left, Right, Bottom"

$diagBtns = @(
    @{Name = "System Specs"; Cmd = {
        $cs = Get-CimInstance Win32_ComputerSystem
        $os = Get-CimInstance Win32_OperatingSystem
        $cpu = Get-CimInstance Win32_Processor
        $bios = Get-CimInstance Win32_Bios
        $disk = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3"
        $info = "=== SYSTEM ===`r`n$($cs.Manufacturer) $($cs.Model)`r`nSerial: $($bios.SerialNumber)`r`n`r`n"
        $info += "=== OS ===`r`n$($os.Caption) ($($os.OSArchitecture))`r`nBuild: $($os.BuildNumber)`r`n`r`n"
        $info += "=== CPU ===`r`n$($cpu.Name)`r`nCores: $($cpu.NumberOfCores)`r`n`r`n"
        $info += "=== RAM ===`r`n$([math]::Round($cs.TotalPhysicalMemory/1GB,1)) GB`r`n`r`n"
        $info += "=== DISKS ===`r`n"
        foreach ($d in $disk) { $info += "$($d.DeviceID) $([math]::Round($d.Size/1GB))GB (Free: $([math]::Round($d.FreeSpace/1GB))GB)`r`n" }
        $info
    }}
    @{Name = "Printers"; Cmd = { Get-Printer | Format-Table Name, DriverName, PortName -AutoSize | Out-String }}
    @{Name = "Software"; Cmd = { Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -EA 0 | Where-Object DisplayName | Sort-Object DisplayName | Select-Object DisplayName, DisplayVersion | Format-Table -AutoSize | Out-String }}
    @{Name = "Event Errors"; Cmd = { Get-WinEvent -FilterHashtable @{LogName='System','Application';Level=1,2;StartTime=(Get-Date).AddDays(-7)} -MaxEvents 20 -EA 0 | Format-Table TimeCreated, ProviderName, Message -Wrap | Out-String }}
    @{Name = "Services"; Cmd = { Get-Service | Where-Object Status -eq Running | Sort-Object DisplayName | Format-Table DisplayName, Name -AutoSize | Out-String }}
    @{Name = "Startup"; Cmd = { Get-CimInstance Win32_StartupCommand | Format-Table Name, Command, Location -Wrap | Out-String }}
)

$btnY = 50
foreach ($diag in $diagBtns) {
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $diag.Name
    $btn.Location = New-Object System.Drawing.Point(540, $btnY)
    $btn.Size = New-Object System.Drawing.Size(120, 32)
    $btn.FlatStyle = "Flat"
    $btn.BackColor = $script:Theme.Card
    $btn.ForeColor = $script:Theme.Text
    $btn.FlatAppearance.BorderSize = 0
    $btn.Anchor = "Top, Right"
    $btn.Tag = $diag.Cmd
    $btn.Add_Click({ Log "Running: $($this.Text)..."; $txtDiag.Text = & $this.Tag; Log "Done." })
    $pageDiag.Controls.Add($btn)
    $btnY += 40
}

$pageDiag.Controls.AddRange(@($lblDiagTitle, $txtDiag))
$pages["Diagnostics"] = $pageDiag

# === NETWORK PAGE ===
$pageNet = New-Object System.Windows.Forms.Panel
$pageNet.Dock = "Fill"
$pageNet.BackColor = $script:Theme.Bg

$lblNetTitle = New-Object System.Windows.Forms.Label
$lblNetTitle.Text = "NETWORK TOOLS"
$lblNetTitle.Location = New-Object System.Drawing.Point(20, 15)
$lblNetTitle.AutoSize = $true
$lblNetTitle.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$lblNetTitle.ForeColor = $script:Theme.Dim

$txtNet = New-Object System.Windows.Forms.TextBox
$txtNet.Multiline = $true
$txtNet.ScrollBars = "Both"
$txtNet.ReadOnly = $true
$txtNet.Location = New-Object System.Drawing.Point(20, 50)
$txtNet.Size = New-Object System.Drawing.Size(500, 350)
$txtNet.BackColor = $script:Theme.Surface
$txtNet.ForeColor = $script:Theme.Text
$txtNet.Font = New-Object System.Drawing.Font("Consolas", 9)
$txtNet.Anchor = "Top, Left, Right, Bottom"

$netBtns = @(
    @{Name = "IP Config"; Cmd = { ipconfig /all | Out-String }}
    @{Name = "ARP Table"; Cmd = { arp -a | Out-String }}
    @{Name = "Test Internet"; Cmd = { Test-Connection 8.8.8.8 -Count 4 | Format-Table Address, ResponseTime, Status | Out-String }}
    @{Name = "Connections"; Cmd = { netstat -an | Out-String }}
    @{Name = "DNS Servers"; Cmd = { Get-DnsClientServerAddress | Format-Table InterfaceAlias, ServerAddresses | Out-String }}
    @{Name = "Routes"; Cmd = { route print | Out-String }}
)

$btnY = 50
foreach ($net in $netBtns) {
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $net.Name
    $btn.Location = New-Object System.Drawing.Point(540, $btnY)
    $btn.Size = New-Object System.Drawing.Size(120, 32)
    $btn.FlatStyle = "Flat"
    $btn.BackColor = $script:Theme.Card
    $btn.ForeColor = $script:Theme.Text
    $btn.FlatAppearance.BorderSize = 0
    $btn.Anchor = "Top, Right"
    $btn.Tag = $net.Cmd
    $btn.Add_Click({ Log "Running: $($this.Text)..."; $txtNet.Text = & $this.Tag; Log "Done." })
    $pageNet.Controls.Add($btn)
    $btnY += 40
}

$pageNet.Controls.AddRange(@($lblNetTitle, $txtNet))
$pages["Network"] = $pageNet

# === NINJAONE PAGE ===
$pageNinja = New-Object System.Windows.Forms.Panel
$pageNinja.Dock = "Fill"
$pageNinja.BackColor = $script:Theme.Bg

$lblNinjaTitle = New-Object System.Windows.Forms.Label
$lblNinjaTitle.Text = "NINJAONE RMM"
$lblNinjaTitle.Location = New-Object System.Drawing.Point(20, 15)
$lblNinjaTitle.AutoSize = $true
$lblNinjaTitle.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$lblNinjaTitle.ForeColor = $script:Theme.Dim

$savedSettings = Get-NinjaSettings

$lblUrl = New-Object System.Windows.Forms.Label
$lblUrl.Text = "Instance URL:"
$lblUrl.Location = New-Object System.Drawing.Point(20, 50)
$lblUrl.AutoSize = $true

$txtUrl = New-Object System.Windows.Forms.TextBox
$txtUrl.Location = New-Object System.Drawing.Point(20, 70)
$txtUrl.Size = New-Object System.Drawing.Size(300, 25)
$txtUrl.Text = if ($savedSettings.Url) { $savedSettings.Url } else { "app.ninjarmm.com" }

$lblCid = New-Object System.Windows.Forms.Label
$lblCid.Text = "Client ID:"
$lblCid.Location = New-Object System.Drawing.Point(20, 100)
$lblCid.AutoSize = $true

$txtCid = New-Object System.Windows.Forms.TextBox
$txtCid.Location = New-Object System.Drawing.Point(20, 120)
$txtCid.Size = New-Object System.Drawing.Size(300, 25)
$txtCid.Text = $savedSettings.ClientId

$lblSec = New-Object System.Windows.Forms.Label
$lblSec.Text = "Client Secret:"
$lblSec.Location = New-Object System.Drawing.Point(20, 150)
$lblSec.AutoSize = $true

$txtSec = New-Object System.Windows.Forms.TextBox
$txtSec.Location = New-Object System.Drawing.Point(20, 170)
$txtSec.Size = New-Object System.Drawing.Size(300, 25)
$txtSec.UseSystemPasswordChar = $true
$txtSec.Text = $savedSettings.ClientSecret

$lblNinjaConn = New-Object System.Windows.Forms.Label
$lblNinjaConn.Text = "$($script:StatusPending) Not connected"
$lblNinjaConn.Location = New-Object System.Drawing.Point(140, 210)
$lblNinjaConn.AutoSize = $true
$lblNinjaConn.Font = New-Object System.Drawing.Font("Consolas", 10)
$lblNinjaConn.ForeColor = $script:Theme.Dim

$btnConnect = New-Object System.Windows.Forms.Button
$btnConnect.Text = "Connect"
$btnConnect.Location = New-Object System.Drawing.Point(20, 205)
$btnConnect.Size = New-Object System.Drawing.Size(100, 30)
$btnConnect.FlatStyle = "Flat"
$btnConnect.BackColor = $script:Theme.Accent
$btnConnect.ForeColor = "White"
$btnConnect.FlatAppearance.BorderSize = 0
$btnConnect.Add_Click({
    Save-NinjaSettings -Url $txtUrl.Text -Id $txtCid.Text -Secret $txtSec.Text
    $lblNinjaConn.Text = "$($script:StatusPending) Connecting..."
    $lblNinjaConn.ForeColor = $script:Theme.Dim
    [System.Windows.Forms.Application]::DoEvents()
    
    if (Connect-NinjaOne -ClientId $txtCid.Text -ClientSecret $txtSec.Text -InstanceUrl $txtUrl.Text) {
        $lblNinjaConn.Text = "$($script:StatusOK) Connected!"
        $lblNinjaConn.ForeColor = $script:Theme.Green
    } else {
        $lblNinjaConn.Text = "$($script:StatusBad) Failed"
        $lblNinjaConn.ForeColor = $script:Theme.Red
    }
})

$pageNinja.Controls.AddRange(@($lblNinjaTitle, $lblUrl, $txtUrl, $lblCid, $txtCid, $lblSec, $txtSec, $btnConnect, $lblNinjaConn))
$pages["NinjaOne"] = $pageNinja

# === AUDIT PAGE ===
$pageAudit = New-Object System.Windows.Forms.Panel
$pageAudit.Dock = "Fill"
$pageAudit.BackColor = $script:Theme.Bg

$lblAuditTitle = New-Object System.Windows.Forms.Label
$lblAuditTitle.Text = "SECURITY AUDIT"
$lblAuditTitle.Location = New-Object System.Drawing.Point(20, 15)
$lblAuditTitle.AutoSize = $true
$lblAuditTitle.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$lblAuditTitle.ForeColor = $script:Theme.Dim

$lblAuditDesc = New-Object System.Windows.Forms.Label
$lblAuditDesc.Text = "Generate a comprehensive security audit report for this system."
$lblAuditDesc.Location = New-Object System.Drawing.Point(20, 50)
$lblAuditDesc.AutoSize = $true

$btnAudit = New-Object System.Windows.Forms.Button
$btnAudit.Text = "Generate Audit Report"
$btnAudit.Location = New-Object System.Drawing.Point(20, 90)
$btnAudit.Size = New-Object System.Drawing.Size(200, 40)
$btnAudit.FlatStyle = "Flat"
$btnAudit.BackColor = $script:Theme.Accent
$btnAudit.ForeColor = "White"
$btnAudit.FlatAppearance.BorderSize = 0
$btnAudit.Add_Click({
    Log "Generating audit report..."
    [System.Windows.Forms.MessageBox]::Show("Audit report generation would run here.", "Security Audit", "OK", "Information")
})

$pageAudit.Controls.AddRange(@($lblAuditTitle, $lblAuditDesc, $btnAudit))
$pages["Audit"] = $pageAudit

# --- Navigation ---
function Show-Page {
    param($PageName)
    $panelContent.Controls.Clear()
    if ($pages.ContainsKey($PageName)) {
        $panelContent.Controls.Add($pages[$PageName])
        foreach ($btn in $navButtons) {
            $btn.BackColor = if ($btn.Tag -eq $PageName) { $script:Theme.Accent } else { $script:Theme.Card }
        }
        Log "View: $PageName"
    }
}

# --- Assemble Form ---
$form.Controls.Add($panelContent)
$form.Controls.Add($panelLog)
$form.Controls.Add($panelNav)
$form.Controls.Add($panelHeader)

# --- Initialize ---
$form.Add_Shown({
    Show-Page "Dashboard"
    Log "WinFix Tool v2.1 ready - click Refresh to scan"
})

[void]$form.ShowDialog()
