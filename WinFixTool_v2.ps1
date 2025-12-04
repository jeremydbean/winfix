<#
.SYNOPSIS
    WinFix Tool v2.0 - All-in-One Windows Maintenance & Diagnostics
.DESCRIPTION
    A modern GUI tool to diagnose, fix, and maintain Windows systems.
    Integrates with NinjaOne RMM for enhanced monitoring.
    Features: Health Score, One-Click Fixes, Network Tools, Security Audit
.NOTES
    Requires Administrator Privileges.
    Author: Jeremy Bean IT
    Version: 2.0
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

# --- Modern Theme Colors ---
$Theme = @{
    Background    = [System.Drawing.Color]::FromArgb(18, 18, 18)
    Surface       = [System.Drawing.Color]::FromArgb(30, 30, 30)
    Card          = [System.Drawing.Color]::FromArgb(40, 40, 40)
    CardHover     = [System.Drawing.Color]::FromArgb(50, 50, 50)
    Text          = [System.Drawing.Color]::FromArgb(255, 255, 255)
    TextSecondary = [System.Drawing.Color]::FromArgb(180, 180, 180)
    Accent        = [System.Drawing.Color]::FromArgb(0, 150, 255)
    Success       = [System.Drawing.Color]::FromArgb(76, 175, 80)
    Warning       = [System.Drawing.Color]::FromArgb(255, 193, 7)
    Error         = [System.Drawing.Color]::FromArgb(244, 67, 54)
    Purple        = [System.Drawing.Color]::FromArgb(156, 39, 176)
}

# --- Global Variables ---
$global:NinjaToken = $null
$global:NinjaInstance = $null
$global:NinjaDeviceData = $null
$global:HealthScore = 100
$global:Issues = @()
$global:LogPath = "$env:TEMP\WinFix_Debug.log"

# --- Logging Function ---
function Log-Output {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logLine = "[$timestamp] $Message"
    
    # Write to log file
    Add-Content -Path $global:LogPath -Value $logLine -ErrorAction SilentlyContinue
    
    # Update GUI if available
    if ($script:txtLog) {
        $script:txtLog.AppendText("$logLine`r`n")
        $script:txtLog.ScrollToCaret()
    }
}

# --- NinjaOne Functions ---
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
    
    Log-Output "Connecting to NinjaOne..."
    
    # Clean URL
    $InstanceUrl = $InstanceUrl -replace "^https?://", "" -replace "/$", "" -replace "/apidocs.*", "" -replace "/ws/.*", ""
    
    # Transform app URL to API URL
    $apiHost = $InstanceUrl
    if ($InstanceUrl -match "^app\.") { $apiHost = $InstanceUrl -replace "^app\.", "api." }
    elseif ($InstanceUrl -match "^eu\.") { $apiHost = $InstanceUrl -replace "^eu\.", "eu-api." }
    elseif ($InstanceUrl -match "^oc\.") { $apiHost = $InstanceUrl -replace "^oc\.", "oc-api." }
    elseif ($InstanceUrl -match "^ca\.") { $apiHost = $InstanceUrl -replace "^ca\.", "ca-api." }
    elseif ($InstanceUrl -notmatch "api\.") { $apiHost = "api." + $InstanceUrl }
    
    $global:NinjaInstance = $apiHost
    $authUrl = "https://$apiHost/ws/oauth/token"
    
    Log-Output "Auth URL: $authUrl"
    
    try {
        $body = @{
            grant_type = "client_credentials"
            client_id = $ClientId
            client_secret = $ClientSecret
            scope = "monitoring management"
        }
        
        $response = Invoke-RestMethod -Uri $authUrl -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
        $global:NinjaToken = $response.access_token
        Log-Output "Connected to NinjaOne successfully!"
        
        # Auto-detect device
        Get-NinjaDeviceData
        return $true
    } catch {
        Log-Output "NinjaOne connection failed: $($_.Exception.Message)"
        return $false
    }
}

function Get-LocalNinjaNodeId {
    $regPaths = @(
        "HKLM:\SOFTWARE\NinjaRMM LLC\NinjaRMMAgent",
        "HKLM:\SOFTWARE\NinjaRMM\Agent",
        "HKLM:\SOFTWARE\WOW6432Node\NinjaRMM LLC\NinjaRMMAgent"
    )
    
    foreach ($path in $regPaths) {
        if (Test-Path $path) {
            $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            foreach ($name in @("NodeID", "DeviceID", "id", "agent_id")) {
                if ($props.$name) { return $props.$name }
            }
        }
    }
    return $null
}

function Get-NinjaDeviceData {
    if (-not $global:NinjaToken) { return }
    
    $headers = @{ Authorization = "Bearer $global:NinjaToken" }
    
    # Try local Node ID first
    $localId = Get-LocalNinjaNodeId
    if ($localId) {
        try {
            $device = Invoke-RestMethod -Uri "https://$($global:NinjaInstance)/v2/devices/$localId" -Headers $headers
            if ($device) {
                $global:NinjaDeviceData = $device
                Log-Output "Device found: $($device.systemName) (ID: $($device.id))"
                Get-NinjaExtendedData
                return
            }
        } catch { Log-Output "Node ID lookup failed: $_" }
    }
    
    # Search by hostname/serial
    $serial = (Get-CimInstance Win32_Bios).SerialNumber
    $hostname = $env:COMPUTERNAME
    
    try {
        $devices = Invoke-RestMethod -Uri "https://$($global:NinjaInstance)/v2/devices?pageSize=1000" -Headers $headers
        
        $match = $devices | Where-Object { $_.serialNumber -eq $serial -or $_.systemName -eq $hostname }
        if ($match) {
            $global:NinjaDeviceData = $match | Select-Object -First 1
            Log-Output "Device matched: $($global:NinjaDeviceData.systemName)"
            Get-NinjaExtendedData
        }
    } catch { Log-Output "Device search failed: $_" }
}

function Get-NinjaExtendedData {
    if (-not $global:NinjaDeviceData -or -not $global:NinjaToken) { return }
    
    $headers = @{ Authorization = "Bearer $global:NinjaToken" }
    $devId = $global:NinjaDeviceData.id
    
    # Get additional data from various endpoints
    $endpoints = @{
        "disks" = "/v2/device/$devId/disks"
        "software" = "/v2/device/$devId/software"
        "osPatches" = "/v2/device/$devId/os-patches"
        "activities" = "/v2/device/$devId/activities?pageSize=20"
        "alerts" = "/v2/device/$devId/alerts"
        "customFields" = "/v2/device/$devId/custom-fields"
    }
    
    foreach ($key in $endpoints.Keys) {
        try {
            $url = "https://$($global:NinjaInstance)$($endpoints[$key])"
            $data = Invoke-RestMethod -Uri $url -Headers $headers -ErrorAction Stop
            $global:NinjaDeviceData | Add-Member -NotePropertyName $key -NotePropertyValue $data -Force
            Log-Output "Fetched $key data"
        } catch {
            Log-Output "Could not fetch $key`: $_"
        }
    }
    
    # Get organization name
    if ($global:NinjaDeviceData.organizationId) {
        try {
            $org = Invoke-RestMethod -Uri "https://$($global:NinjaInstance)/v2/organizations/$($global:NinjaDeviceData.organizationId)" -Headers $headers
            $global:NinjaDeviceData | Add-Member -NotePropertyName "organizationName" -NotePropertyValue $org.name -Force
        } catch { }
    }
}

# --- System Health Functions ---
function Get-SystemHealth {
    $health = @{
        Score = 100
        Issues = @()
        Warnings = @()
        Good = @()
    }
    
    # CPU Usage
    $cpu = (Get-CimInstance Win32_Processor).LoadPercentage
    if ($cpu -gt 90) { $health.Issues += "CPU usage critical: ${cpu}%"; $health.Score -= 15 }
    elseif ($cpu -gt 70) { $health.Warnings += "CPU usage high: ${cpu}%"; $health.Score -= 5 }
    else { $health.Good += "CPU: ${cpu}%" }
    
    # Memory Usage
    $os = Get-CimInstance Win32_OperatingSystem
    $memUsed = [math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize * 100)
    if ($memUsed -gt 90) { $health.Issues += "Memory critical: ${memUsed}%"; $health.Score -= 15 }
    elseif ($memUsed -gt 80) { $health.Warnings += "Memory high: ${memUsed}%"; $health.Score -= 5 }
    else { $health.Good += "Memory: ${memUsed}%" }
    
    # Disk Space
    $disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3"
    foreach ($d in $disks) {
        $pct = [math]::Round(($d.Size - $d.FreeSpace) / $d.Size * 100)
        if ($pct -gt 95) { $health.Issues += "Disk $($d.DeviceID) critical: ${pct}%"; $health.Score -= 20 }
        elseif ($pct -gt 85) { $health.Warnings += "Disk $($d.DeviceID) low: ${pct}%"; $health.Score -= 10 }
        else { $health.Good += "Disk $($d.DeviceID): ${pct}%" }
    }
    
    # Uptime
    $uptime = (Get-Date) - $os.LastBootUpTime
    if ($uptime.Days -gt 30) { $health.Warnings += "System uptime: $($uptime.Days) days (consider reboot)"; $health.Score -= 5 }
    
    # Windows Updates
    try {
        $updates = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
        $pending = $updates.Search("IsInstalled=0 and IsHidden=0").Updates.Count
        if ($pending -gt 10) { $health.Issues += "$pending pending Windows updates"; $health.Score -= 10 }
        elseif ($pending -gt 0) { $health.Warnings += "$pending pending Windows updates"; $health.Score -= 5 }
    } catch { }
    
    # Services Check
    $criticalServices = @("wuauserv", "Spooler", "BITS", "EventLog")
    foreach ($svc in $criticalServices) {
        $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($service -and $service.Status -ne "Running") {
            $health.Warnings += "Service stopped: $($service.DisplayName)"
            $health.Score -= 3
        }
    }
    
    # Event Log Errors (last 24h)
    try {
        $errors = Get-WinEvent -FilterHashtable @{LogName='System'; Level=2; StartTime=(Get-Date).AddDays(-1)} -MaxEvents 50 -ErrorAction SilentlyContinue
        if ($errors.Count -gt 20) { $health.Issues += "$($errors.Count) system errors in 24h"; $health.Score -= 10 }
        elseif ($errors.Count -gt 5) { $health.Warnings += "$($errors.Count) system errors in 24h"; $health.Score -= 5 }
    } catch { }
    
    $health.Score = [Math]::Max(0, $health.Score)
    return $health
}

# --- Quick Fix Functions ---
$QuickFixes = @{
    "Clear Temp Files" = {
        Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
        Clear-RecycleBin -Force -ErrorAction SilentlyContinue
        "Temporary files cleared!"
    }
    
    "Flush DNS Cache" = {
        ipconfig /flushdns
        "DNS cache flushed!"
    }
    
    "Reset Network Stack" = {
        netsh winsock reset
        netsh int ip reset
        ipconfig /release
        ipconfig /renew
        ipconfig /flushdns
        "Network stack reset! Restart recommended."
    }
    
    "Fix Windows Update" = {
        Stop-Service -Name wuauserv, cryptSvc, bits, msiserver -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "C:\Windows\SoftwareDistribution\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "C:\Windows\System32\catroot2\*" -Recurse -Force -ErrorAction SilentlyContinue
        Start-Service -Name wuauserv, cryptSvc, bits, msiserver -ErrorAction SilentlyContinue
        "Windows Update components reset!"
    }
    
    "Clear Print Spooler" = {
        Stop-Service -Name Spooler -Force
        Remove-Item -Path "C:\Windows\System32\spool\PRINTERS\*" -Force -ErrorAction SilentlyContinue
        Start-Service -Name Spooler
        "Print spooler cleared!"
    }
    
    "Run SFC Scan" = {
        sfc /scannow
        "System File Checker complete!"
    }
    
    "Run DISM Repair" = {
        DISM /Online /Cleanup-Image /RestoreHealth
        "DISM repair complete!"
    }
    
    "Sync System Time" = {
        w32tm /resync /force
        "Time synchronized!"
    }
    
    "Restart Explorer" = {
        Stop-Process -Name explorer -Force
        Start-Process explorer
        "Explorer restarted!"
    }
    
    "Check Disk (Schedule)" = {
        $drive = "C:"
        chkdsk $drive /F /R
        "Check Disk scheduled for next restart."
    }
}

# --- Create Main Form ---
$form = New-Object System.Windows.Forms.Form
$form.Text = "WinFix Tool v2.0"
$form.Size = New-Object System.Drawing.Size(1100, 750)
$form.StartPosition = "CenterScreen"
$form.BackColor = $Theme.Background
$form.ForeColor = $Theme.Text
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$form.FormBorderStyle = "FixedSingle"
$form.MaximizeBox = $false

# --- Header Panel ---
$panelHeader = New-Object System.Windows.Forms.Panel
$panelHeader.Dock = "Top"
$panelHeader.Height = 60
$panelHeader.BackColor = $Theme.Surface

$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = "WinFix Tool"
$lblTitle.Location = New-Object System.Drawing.Point(20, 15)
$lblTitle.AutoSize = $true
$lblTitle.Font = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Bold)
$lblTitle.ForeColor = $Theme.Accent

$lblVersion = New-Object System.Windows.Forms.Label
$lblVersion.Text = "v2.0 - Windows Maintenance and Diagnostics"
$lblVersion.Location = New-Object System.Drawing.Point(170, 25)
$lblVersion.AutoSize = $true
$lblVersion.ForeColor = $Theme.TextSecondary

$lblComputer = New-Object System.Windows.Forms.Label
$lblComputer.Text = "$env:COMPUTERNAME"
$lblComputer.Location = New-Object System.Drawing.Point(850, 20)
$lblComputer.AutoSize = $true
$lblComputer.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$lblComputer.ForeColor = $Theme.Text

$panelHeader.Controls.AddRange(@($lblTitle, $lblVersion, $lblComputer))

# --- Side Navigation ---
$panelNav = New-Object System.Windows.Forms.Panel
$panelNav.Dock = "Left"
$panelNav.Width = 180
$panelNav.BackColor = $Theme.Surface

$navButtons = @()
$navItems = @(
    @{Text = "Dashboard"; Icon = "D"}
    @{Text = "Quick Fixes"; Icon = "F"}
    @{Text = "Diagnostics"; Icon = "I"}
    @{Text = "Network"; Icon = "N"}
    @{Text = "NinjaOne"; Icon = "R"}
    @{Text = "Security Audit"; Icon = "A"}
)

$navY = 20
foreach ($item in $navItems) {
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $item.Text
    $btn.Location = New-Object System.Drawing.Point(10, $navY)
    $btn.Size = New-Object System.Drawing.Size(160, 45)
    $btn.FlatStyle = "Flat"
    $btn.FlatAppearance.BorderSize = 0
    $btn.BackColor = $Theme.Card
    $btn.ForeColor = $Theme.Text
    $btn.TextAlign = "MiddleLeft"
    $btn.Padding = New-Object System.Windows.Forms.Padding(15, 0, 0, 0)
    $btn.Tag = $item.Text
    $btn.Cursor = "Hand"
    
    $btn.Add_MouseEnter({ $this.BackColor = $Theme.CardHover })
    $btn.Add_MouseLeave({ 
        if ($this.Tag -ne $script:ActiveTab) { $this.BackColor = $Theme.Card }
    })
    
    $panelNav.Controls.Add($btn)
    $navButtons += $btn
    $navY += 55
}

# --- Main Content Area ---
$panelContent = New-Object System.Windows.Forms.Panel
$panelContent.Dock = "Fill"
$panelContent.BackColor = $Theme.Background
$panelContent.Padding = New-Object System.Windows.Forms.Padding(20)

# --- Log Panel (Bottom) ---
$panelLog = New-Object System.Windows.Forms.Panel
$panelLog.Dock = "Bottom"
$panelLog.Height = 150
$panelLog.BackColor = $Theme.Surface
$panelLog.Padding = New-Object System.Windows.Forms.Padding(10)

$lblLog = New-Object System.Windows.Forms.Label
$lblLog.Text = "Activity Log"
$lblLog.Dock = "Top"
$lblLog.Height = 25
$lblLog.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)

$script:txtLog = New-Object System.Windows.Forms.TextBox
$script:txtLog.Multiline = $true
$script:txtLog.ScrollBars = "Vertical"
$script:txtLog.ReadOnly = $true
$script:txtLog.Dock = "Fill"
$script:txtLog.BackColor = [System.Drawing.Color]::FromArgb(20, 20, 20)
$script:txtLog.ForeColor = [System.Drawing.Color]::FromArgb(0, 255, 0)
$script:txtLog.Font = New-Object System.Drawing.Font("Consolas", 9)
$script:txtLog.BorderStyle = "None"

$panelLog.Controls.AddRange(@($lblLog, $script:txtLog))

# --- Content Pages ---
$pages = @{}

# === DASHBOARD PAGE ===
$pageDashboard = New-Object System.Windows.Forms.Panel
$pageDashboard.Dock = "Fill"
$pageDashboard.BackColor = $Theme.Background
$pageDashboard.AutoScroll = $true

# Health Score Card
$cardHealth = New-Object System.Windows.Forms.Panel
$cardHealth.Location = New-Object System.Drawing.Point(20, 20)
$cardHealth.Size = New-Object System.Drawing.Size(250, 150)
$cardHealth.BackColor = $Theme.Card

$lblHealthTitle = New-Object System.Windows.Forms.Label
$lblHealthTitle.Text = "System Health"
$lblHealthTitle.Location = New-Object System.Drawing.Point(15, 10)
$lblHealthTitle.AutoSize = $true
$lblHealthTitle.ForeColor = $Theme.TextSecondary

$lblHealthScore = New-Object System.Windows.Forms.Label
$lblHealthScore.Text = "..."
$lblHealthScore.Location = New-Object System.Drawing.Point(15, 40)
$lblHealthScore.AutoSize = $true
$lblHealthScore.Font = New-Object System.Drawing.Font("Segoe UI", 48, [System.Drawing.FontStyle]::Bold)

$lblHealthStatus = New-Object System.Windows.Forms.Label
$lblHealthStatus.Text = "Analyzing..."
$lblHealthStatus.Location = New-Object System.Drawing.Point(15, 115)
$lblHealthStatus.AutoSize = $true

$cardHealth.Controls.AddRange(@($lblHealthTitle, $lblHealthScore, $lblHealthStatus))

# System Info Card
$cardSystem = New-Object System.Windows.Forms.Panel
$cardSystem.Location = New-Object System.Drawing.Point(290, 20)
$cardSystem.Size = New-Object System.Drawing.Size(400, 150)
$cardSystem.BackColor = $Theme.Card

$lblSystemTitle = New-Object System.Windows.Forms.Label
$lblSystemTitle.Text = "System Information"
$lblSystemTitle.Location = New-Object System.Drawing.Point(15, 10)
$lblSystemTitle.AutoSize = $true
$lblSystemTitle.ForeColor = $Theme.TextSecondary

$lblSystemInfo = New-Object System.Windows.Forms.Label
$lblSystemInfo.Text = "Loading..."
$lblSystemInfo.Location = New-Object System.Drawing.Point(15, 35)
$lblSystemInfo.Size = New-Object System.Drawing.Size(370, 105)

$cardSystem.Controls.AddRange(@($lblSystemTitle, $lblSystemInfo))

# Issues Card
$cardIssues = New-Object System.Windows.Forms.Panel
$cardIssues.Location = New-Object System.Drawing.Point(20, 190)
$cardIssues.Size = New-Object System.Drawing.Size(670, 200)
$cardIssues.BackColor = $Theme.Card

$lblIssuesTitle = New-Object System.Windows.Forms.Label
$lblIssuesTitle.Text = "Issues and Warnings"
$lblIssuesTitle.Location = New-Object System.Drawing.Point(15, 10)
$lblIssuesTitle.AutoSize = $true
$lblIssuesTitle.ForeColor = $Theme.TextSecondary

$txtIssues = New-Object System.Windows.Forms.TextBox
$txtIssues.Multiline = $true
$txtIssues.ScrollBars = "Vertical"
$txtIssues.ReadOnly = $true
$txtIssues.Location = New-Object System.Drawing.Point(15, 35)
$txtIssues.Size = New-Object System.Drawing.Size(640, 150)
$txtIssues.BackColor = $Theme.Surface
$txtIssues.ForeColor = $Theme.Text
$txtIssues.BorderStyle = "None"
$txtIssues.Font = New-Object System.Drawing.Font("Consolas", 9)

$cardIssues.Controls.AddRange(@($lblIssuesTitle, $txtIssues))

# Refresh Button
$btnRefreshDash = New-Object System.Windows.Forms.Button
$btnRefreshDash.Text = "Refresh Dashboard"
$btnRefreshDash.Location = New-Object System.Drawing.Point(20, 410)
$btnRefreshDash.Size = New-Object System.Drawing.Size(200, 40)
$btnRefreshDash.FlatStyle = "Flat"
$btnRefreshDash.BackColor = $Theme.Accent
$btnRefreshDash.ForeColor = "White"
$btnRefreshDash.FlatAppearance.BorderSize = 0
$btnRefreshDash.Add_Click({
    Log-Output "Refreshing dashboard..."
    
    # Get health data
    $health = Get-SystemHealth
    
    # Update health score
    $lblHealthScore.Text = "$($health.Score)"
    if ($health.Score -ge 80) {
        $lblHealthScore.ForeColor = $Theme.Success
        $lblHealthStatus.Text = "System Healthy"
        $lblHealthStatus.ForeColor = $Theme.Success
    } elseif ($health.Score -ge 50) {
        $lblHealthScore.ForeColor = $Theme.Warning
        $lblHealthStatus.Text = "Needs Attention"
        $lblHealthStatus.ForeColor = $Theme.Warning
    } else {
        $lblHealthScore.ForeColor = $Theme.Error
        $lblHealthStatus.Text = "Critical Issues"
        $lblHealthStatus.ForeColor = $Theme.Error
    }
    
    # Update system info
    $cs = Get-CimInstance Win32_ComputerSystem
    $os = Get-CimInstance Win32_OperatingSystem
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $uptime = (Get-Date) - $os.LastBootUpTime
    
    $sysInfo = @"
Computer: $($cs.Name)
OS: $($os.Caption)
CPU: $($cpu.Name)
RAM: $([math]::Round($cs.TotalPhysicalMemory / 1GB, 1)) GB
Uptime: $($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m
"@
    
    if ($global:NinjaDeviceData) {
        $sysInfo += "`nNinja Org: $($global:NinjaDeviceData.organizationName)"
    }
    
    $lblSystemInfo.Text = $sysInfo
    
    # Update issues
    $issueText = ""
    foreach ($issue in $health.Issues) {
        $issueText += "[ERROR] $issue`r`n"
    }
    foreach ($warn in $health.Warnings) {
        $issueText += "[WARN] $warn`r`n"
    }
    if (-not $issueText) {
        $issueText = "No issues detected. System is healthy!"
    }
    $txtIssues.Text = $issueText
    
    Log-Output "Dashboard refreshed. Health Score: $($health.Score)"
})

$pageDashboard.Controls.AddRange(@($cardHealth, $cardSystem, $cardIssues, $btnRefreshDash))
$pages["Dashboard"] = $pageDashboard

# === QUICK FIXES PAGE ===
$pageQuickFixes = New-Object System.Windows.Forms.Panel
$pageQuickFixes.Dock = "Fill"
$pageQuickFixes.BackColor = $Theme.Background
$pageQuickFixes.AutoScroll = $true

$lblFixesTitle = New-Object System.Windows.Forms.Label
$lblFixesTitle.Text = "One-Click Quick Fixes"
$lblFixesTitle.Location = New-Object System.Drawing.Point(20, 20)
$lblFixesTitle.AutoSize = $true
$lblFixesTitle.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)

$pageQuickFixes.Controls.Add($lblFixesTitle)

$fixY = 60
$fixX = 20
$fixCol = 0

foreach ($fixName in $QuickFixes.Keys) {
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $fixName
    $btn.Location = New-Object System.Drawing.Point($fixX, $fixY)
    $btn.Size = New-Object System.Drawing.Size(200, 50)
    $btn.FlatStyle = "Flat"
    $btn.BackColor = $Theme.Card
    $btn.ForeColor = $Theme.Text
    $btn.FlatAppearance.BorderSize = 0
    $btn.Tag = $QuickFixes[$fixName]
    
    $btn.Add_Click({
        $action = $this.Tag
        Log-Output "Running: $($this.Text)..."
        try {
            $result = & $action
            if ($result) { Log-Output $result }
            Log-Output "Completed: $($this.Text)"
            [System.Windows.Forms.MessageBox]::Show("Completed: $($this.Text)", "WinFix", "OK", "Information")
        } catch {
            Log-Output "Error: $_"
            [System.Windows.Forms.MessageBox]::Show("Error: $_", "WinFix", "OK", "Error")
        }
    })
    
    $btn.Add_MouseEnter({ $this.BackColor = $Theme.CardHover })
    $btn.Add_MouseLeave({ $this.BackColor = $Theme.Card })
    
    $pageQuickFixes.Controls.Add($btn)
    
    $fixCol++
    if ($fixCol -ge 3) {
        $fixCol = 0
        $fixX = 20
        $fixY += 60
    } else {
        $fixX += 220
    }
}

$pages["Quick Fixes"] = $pageQuickFixes

# === DIAGNOSTICS PAGE ===
$pageDiagnostics = New-Object System.Windows.Forms.Panel
$pageDiagnostics.Dock = "Fill"
$pageDiagnostics.BackColor = $Theme.Background
$pageDiagnostics.AutoScroll = $true

$lblDiagTitle = New-Object System.Windows.Forms.Label
$lblDiagTitle.Text = "System Diagnostics"
$lblDiagTitle.Location = New-Object System.Drawing.Point(20, 20)
$lblDiagTitle.AutoSize = $true
$lblDiagTitle.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)

$txtDiag = New-Object System.Windows.Forms.TextBox
$txtDiag.Multiline = $true
$txtDiag.ScrollBars = "Both"
$txtDiag.ReadOnly = $true
$txtDiag.Location = New-Object System.Drawing.Point(20, 60)
$txtDiag.Size = New-Object System.Drawing.Size(650, 300)
$txtDiag.BackColor = $Theme.Surface
$txtDiag.ForeColor = $Theme.Text
$txtDiag.Font = New-Object System.Drawing.Font("Consolas", 9)

$diagButtons = @(
    @{Text = "System Specs"; Action = {
        $cs = Get-CimInstance Win32_ComputerSystem
        $os = Get-CimInstance Win32_OperatingSystem
        $cpu = Get-CimInstance Win32_Processor
        $disk = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3"
        $bios = Get-CimInstance Win32_Bios
        
        $info = "=== SYSTEM SPECIFICATIONS ===`r`n`r`n"
        $info += "Computer: $($cs.Name)`r`n"
        $info += "Manufacturer: $($cs.Manufacturer)`r`n"
        $info += "Model: $($cs.Model)`r`n"
        $info += "Serial: $($bios.SerialNumber)`r`n`r`n"
        $info += "OS: $($os.Caption) ($($os.OSArchitecture))`r`n"
        $info += "Build: $($os.BuildNumber)`r`n`r`n"
        $info += "CPU: $($cpu.Name)`r`n"
        $info += "Cores: $($cpu.NumberOfCores) / Threads: $($cpu.NumberOfLogicalProcessors)`r`n`r`n"
        $info += "RAM: $([math]::Round($cs.TotalPhysicalMemory / 1GB, 2)) GB`r`n`r`n"
        $info += "=== DISKS ===`r`n"
        foreach ($d in $disk) {
            $info += "$($d.DeviceID) $([math]::Round($d.Size/1GB))GB (Free: $([math]::Round($d.FreeSpace/1GB))GB)`r`n"
        }
        return $info
    }}
    @{Text = "List Printers"; Action = {
        $printers = Get-Printer
        $ports = Get-PrinterPort
        $info = "=== INSTALLED PRINTERS ===`r`n`r`n"
        foreach ($p in $printers) {
            $port = $ports | Where-Object { $_.Name -eq $p.PortName }
            $ip = if ($port.PrinterHostAddress) { $port.PrinterHostAddress } else { "Local" }
            $info += "$($p.Name)`r`n  Driver: $($p.DriverName)`r`n  IP: $ip`r`n`r`n"
        }
        return $info
    }}
    @{Text = "List Software"; Action = {
        $keys = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
                "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        $software = Get-ItemProperty $keys -ErrorAction SilentlyContinue | 
            Where-Object { $_.DisplayName } | 
            Sort-Object DisplayName |
            Select-Object DisplayName, DisplayVersion
        
        $info = "=== INSTALLED SOFTWARE ===`r`n`r`n"
        foreach ($s in $software) {
            $info += "$($s.DisplayName) - $($s.DisplayVersion)`r`n"
        }
        return $info
    }}
    @{Text = "Event Log Errors"; Action = {
        $info = "=== RECENT SYSTEM ERRORS (7 Days) ===`r`n`r`n"
        $events = Get-WinEvent -FilterHashtable @{LogName='System','Application'; Level=1,2; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 30 -ErrorAction SilentlyContinue
        if ($events) {
            foreach ($e in $events) {
                $info += "[$($e.TimeCreated.ToString('MM-dd HH:mm'))] $($e.ProviderName)`r`n"
                $info += "  $($e.Message.Substring(0, [Math]::Min(150, $e.Message.Length)))...`r`n`r`n"
            }
        } else {
            $info += "No critical errors found!"
        }
        return $info
    }}
    @{Text = "Running Services"; Action = {
        $services = Get-Service | Where-Object { $_.Status -eq "Running" } | Sort-Object DisplayName
        $info = "=== RUNNING SERVICES ===`r`n`r`n"
        foreach ($s in $services) {
            $info += "$($s.DisplayName) [$($s.Name)]`r`n"
        }
        return $info
    }}
    @{Text = "Startup Programs"; Action = {
        $info = "=== STARTUP PROGRAMS ===`r`n`r`n"
        $startup = Get-CimInstance Win32_StartupCommand
        foreach ($s in $startup) {
            $info += "$($s.Name)`r`n  Command: $($s.Command)`r`n  Location: $($s.Location)`r`n`r`n"
        }
        return $info
    }}
)

$btnY = 60
foreach ($diag in $diagButtons) {
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $diag.Text
    $btn.Location = New-Object System.Drawing.Point(690, $btnY)
    $btn.Size = New-Object System.Drawing.Size(150, 40)
    $btn.FlatStyle = "Flat"
    $btn.BackColor = $Theme.Card
    $btn.ForeColor = $Theme.Text
    $btn.FlatAppearance.BorderSize = 0
    $btn.Tag = $diag.Action
    
    $btn.Add_Click({
        Log-Output "Running diagnostic: $($this.Text)..."
        $result = & $this.Tag
        $txtDiag.Text = $result
        Log-Output "Diagnostic complete."
    })
    
    $pageDiagnostics.Controls.Add($btn)
    $btnY += 50
}

$pageDiagnostics.Controls.AddRange(@($lblDiagTitle, $txtDiag))
$pages["Diagnostics"] = $pageDiagnostics

# === NETWORK PAGE ===
$pageNetwork = New-Object System.Windows.Forms.Panel
$pageNetwork.Dock = "Fill"
$pageNetwork.BackColor = $Theme.Background
$pageNetwork.AutoScroll = $true

$lblNetTitle = New-Object System.Windows.Forms.Label
$lblNetTitle.Text = "Network Tools"
$lblNetTitle.Location = New-Object System.Drawing.Point(20, 20)
$lblNetTitle.AutoSize = $true
$lblNetTitle.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)

$txtNet = New-Object System.Windows.Forms.TextBox
$txtNet.Multiline = $true
$txtNet.ScrollBars = "Both"
$txtNet.ReadOnly = $true
$txtNet.Location = New-Object System.Drawing.Point(20, 60)
$txtNet.Size = New-Object System.Drawing.Size(650, 300)
$txtNet.BackColor = $Theme.Surface
$txtNet.ForeColor = $Theme.Text
$txtNet.Font = New-Object System.Drawing.Font("Consolas", 9)

$netButtons = @(
    @{Text = "IP Configuration"; Action = { ipconfig /all | Out-String }}
    @{Text = "ARP Table"; Action = { arp -a | Out-String }}
    @{Text = "Test Internet"; Action = { 
        "Testing connectivity...`r`n"
        Test-Connection -ComputerName 8.8.8.8 -Count 4 | Format-Table Address, ResponseTime, Status | Out-String 
    }}
    @{Text = "Active Connections"; Action = { netstat -an | Out-String }}
    @{Text = "DNS Servers"; Action = { Get-DnsClientServerAddress | Format-Table InterfaceAlias, ServerAddresses | Out-String }}
    @{Text = "Routing Table"; Action = { route print | Out-String }}
)

$btnY = 60
foreach ($net in $netButtons) {
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $net.Text
    $btn.Location = New-Object System.Drawing.Point(690, $btnY)
    $btn.Size = New-Object System.Drawing.Size(150, 40)
    $btn.FlatStyle = "Flat"
    $btn.BackColor = $Theme.Card
    $btn.ForeColor = $Theme.Text
    $btn.FlatAppearance.BorderSize = 0
    $btn.Tag = $net.Action
    
    $btn.Add_Click({
        Log-Output "Running: $($this.Text)..."
        $result = & $this.Tag
        $txtNet.Text = $result
    })
    
    $pageNetwork.Controls.Add($btn)
    $btnY += 50
}

$pageNetwork.Controls.AddRange(@($lblNetTitle, $txtNet))
$pages["Network"] = $pageNetwork

# === NINJAONE PAGE ===
$pageNinja = New-Object System.Windows.Forms.Panel
$pageNinja.Dock = "Fill"
$pageNinja.BackColor = $Theme.Background

$lblNinjaTitle = New-Object System.Windows.Forms.Label
$lblNinjaTitle.Text = "NinjaOne RMM Integration"
$lblNinjaTitle.Location = New-Object System.Drawing.Point(20, 20)
$lblNinjaTitle.AutoSize = $true
$lblNinjaTitle.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)

# Connection Panel
$panelNinjaConn = New-Object System.Windows.Forms.Panel
$panelNinjaConn.Location = New-Object System.Drawing.Point(20, 60)
$panelNinjaConn.Size = New-Object System.Drawing.Size(400, 200)
$panelNinjaConn.BackColor = $Theme.Card

$savedSettings = Get-NinjaSettings

$lblNinjaUrl = New-Object System.Windows.Forms.Label
$lblNinjaUrl.Text = "Instance URL:"
$lblNinjaUrl.Location = New-Object System.Drawing.Point(15, 15)
$lblNinjaUrl.AutoSize = $true

$txtNinjaUrl = New-Object System.Windows.Forms.TextBox
$txtNinjaUrl.Location = New-Object System.Drawing.Point(15, 35)
$txtNinjaUrl.Size = New-Object System.Drawing.Size(370, 25)
$txtNinjaUrl.Text = if ($savedSettings.Url) { $savedSettings.Url } else { "app.ninjarmm.com" }

$lblNinjaCid = New-Object System.Windows.Forms.Label
$lblNinjaCid.Text = "Client ID:"
$lblNinjaCid.Location = New-Object System.Drawing.Point(15, 65)
$lblNinjaCid.AutoSize = $true

$txtNinjaCid = New-Object System.Windows.Forms.TextBox
$txtNinjaCid.Location = New-Object System.Drawing.Point(15, 85)
$txtNinjaCid.Size = New-Object System.Drawing.Size(370, 25)
$txtNinjaCid.Text = $savedSettings.ClientId

$lblNinjaSec = New-Object System.Windows.Forms.Label
$lblNinjaSec.Text = "Client Secret:"
$lblNinjaSec.Location = New-Object System.Drawing.Point(15, 115)
$lblNinjaSec.AutoSize = $true

$txtNinjaSec = New-Object System.Windows.Forms.TextBox
$txtNinjaSec.Location = New-Object System.Drawing.Point(15, 135)
$txtNinjaSec.Size = New-Object System.Drawing.Size(370, 25)
$txtNinjaSec.UseSystemPasswordChar = $true
$txtNinjaSec.Text = $savedSettings.ClientSecret

$btnNinjaConnect = New-Object System.Windows.Forms.Button
$btnNinjaConnect.Text = "Connect"
$btnNinjaConnect.Location = New-Object System.Drawing.Point(15, 165)
$btnNinjaConnect.Size = New-Object System.Drawing.Size(100, 30)
$btnNinjaConnect.FlatStyle = "Flat"
$btnNinjaConnect.BackColor = $Theme.Accent
$btnNinjaConnect.ForeColor = "White"
$btnNinjaConnect.FlatAppearance.BorderSize = 0
$btnNinjaConnect.Add_Click({
    Save-NinjaSettings -Url $txtNinjaUrl.Text -Id $txtNinjaCid.Text -Secret $txtNinjaSec.Text
    $result = Connect-NinjaOne -ClientId $txtNinjaCid.Text -ClientSecret $txtNinjaSec.Text -InstanceUrl $txtNinjaUrl.Text
    if ($result) {
        $lblNinjaStatus.Text = "Connected!"
        $lblNinjaStatus.ForeColor = $Theme.Success
        Update-NinjaDeviceInfo
    } else {
        $lblNinjaStatus.Text = "Connection Failed"
        $lblNinjaStatus.ForeColor = $Theme.Error
    }
})

$lblNinjaStatus = New-Object System.Windows.Forms.Label
$lblNinjaStatus.Text = "Not Connected"
$lblNinjaStatus.Location = New-Object System.Drawing.Point(130, 172)
$lblNinjaStatus.AutoSize = $true
$lblNinjaStatus.ForeColor = $Theme.TextSecondary

$panelNinjaConn.Controls.AddRange(@($lblNinjaUrl, $txtNinjaUrl, $lblNinjaCid, $txtNinjaCid, $lblNinjaSec, $txtNinjaSec, $btnNinjaConnect, $lblNinjaStatus))

# Device Info Panel
$panelNinjaDevice = New-Object System.Windows.Forms.Panel
$panelNinjaDevice.Location = New-Object System.Drawing.Point(440, 60)
$panelNinjaDevice.Size = New-Object System.Drawing.Size(400, 300)
$panelNinjaDevice.BackColor = $Theme.Card

$lblNinjaDevTitle = New-Object System.Windows.Forms.Label
$lblNinjaDevTitle.Text = "Device Information (from Ninja)"
$lblNinjaDevTitle.Location = New-Object System.Drawing.Point(15, 10)
$lblNinjaDevTitle.AutoSize = $true
$lblNinjaDevTitle.ForeColor = $Theme.TextSecondary

$txtNinjaDevice = New-Object System.Windows.Forms.TextBox
$txtNinjaDevice.Multiline = $true
$txtNinjaDevice.ScrollBars = "Vertical"
$txtNinjaDevice.ReadOnly = $true
$txtNinjaDevice.Location = New-Object System.Drawing.Point(15, 35)
$txtNinjaDevice.Size = New-Object System.Drawing.Size(370, 250)
$txtNinjaDevice.BackColor = $Theme.Surface
$txtNinjaDevice.ForeColor = $Theme.Text
$txtNinjaDevice.Font = New-Object System.Drawing.Font("Consolas", 9)

function Update-NinjaDeviceInfo {
    if (-not $global:NinjaDeviceData) {
        $txtNinjaDevice.Text = "No device data available."
        return
    }
    
    $d = $global:NinjaDeviceData
    $info = "=== DEVICE INFO ===`r`n"
    $info += "Name: $($d.systemName)`r`n"
    $info += "ID: $($d.id)`r`n"
    $info += "Org: $($d.organizationName)`r`n"
    $info += "Last Contact: $($d.lastContact)`r`n"
    $info += "Public IP: $($d.publicIP)`r`n`r`n"
    
    if ($d.alerts) {
        $info += "=== ACTIVE ALERTS ===`r`n"
        foreach ($a in $d.alerts) {
            $info += "- $($a.message)`r`n"
        }
        $info += "`r`n"
    }
    
    if ($d.osPatches) {
        $pending = ($d.osPatches | Where-Object { $_.status -ne "INSTALLED" }).Count
        $info += "=== PATCHES ===`r`n"
        $info += "Pending Updates: $pending`r`n`r`n"
    }
    
    if ($d.disks) {
        $info += "=== DISKS (Ninja) ===`r`n"
        foreach ($disk in $d.disks) {
            $info += "$($disk.name): $($disk.health)`r`n"
        }
        $info += "`r`n"
    }
    
    if ($d.activities) {
        $info += "=== RECENT ACTIVITIES ===`r`n"
        foreach ($act in ($d.activities | Select-Object -First 5)) {
            $info += "- $($act.activityType): $($act.statusCode)`r`n"
        }
    }
    
    $txtNinjaDevice.Text = $info
}

$panelNinjaDevice.Controls.AddRange(@($lblNinjaDevTitle, $txtNinjaDevice))

$pageNinja.Controls.AddRange(@($lblNinjaTitle, $panelNinjaConn, $panelNinjaDevice))
$pages["NinjaOne"] = $pageNinja

# === SECURITY AUDIT PAGE ===
$pageAudit = New-Object System.Windows.Forms.Panel
$pageAudit.Dock = "Fill"
$pageAudit.BackColor = $Theme.Background

$lblAuditTitle = New-Object System.Windows.Forms.Label
$lblAuditTitle.Text = "Security Audit Report"
$lblAuditTitle.Location = New-Object System.Drawing.Point(20, 20)
$lblAuditTitle.AutoSize = $true
$lblAuditTitle.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)

$lblAuditDesc = New-Object System.Windows.Forms.Label
$lblAuditDesc.Text = "Generate a comprehensive HIPAA-compliant security audit report for this system."
$lblAuditDesc.Location = New-Object System.Drawing.Point(20, 55)
$lblAuditDesc.AutoSize = $true
$lblAuditDesc.ForeColor = $Theme.TextSecondary

$btnGenerateAudit = New-Object System.Windows.Forms.Button
$btnGenerateAudit.Text = "Generate Security Audit Report"
$btnGenerateAudit.Location = New-Object System.Drawing.Point(20, 100)
$btnGenerateAudit.Size = New-Object System.Drawing.Size(300, 50)
$btnGenerateAudit.FlatStyle = "Flat"
$btnGenerateAudit.BackColor = $Theme.Accent
$btnGenerateAudit.ForeColor = "White"
$btnGenerateAudit.FlatAppearance.BorderSize = 0
$btnGenerateAudit.Font = New-Object System.Drawing.Font("Segoe UI", 11)
$btnGenerateAudit.Add_Click({
    Log-Output "Generating Security Audit Report..."
    [System.Windows.Forms.MessageBox]::Show("Security Audit generation would run here.`n`nThis connects to the full audit report generator from the original tool.", "Security Audit", "OK", "Information")
})

$pageAudit.Controls.AddRange(@($lblAuditTitle, $lblAuditDesc, $btnGenerateAudit))
$pages["Security Audit"] = $pageAudit

# --- Navigation Logic ---
$script:ActiveTab = "Dashboard"

function Show-Page {
    param($PageName)
    
    $panelContent.Controls.Clear()
    if ($pages.ContainsKey($PageName)) {
        $panelContent.Controls.Add($pages[$PageName])
        $script:ActiveTab = $PageName
        
        # Update nav button colors
        foreach ($btn in $navButtons) {
            if ($btn.Tag -eq $PageName) {
                $btn.BackColor = $Theme.Accent
            } else {
                $btn.BackColor = $Theme.Card
            }
        }
        
        Log-Output "Switched to: $PageName"
    }
}

# Wire up nav buttons
foreach ($btn in $navButtons) {
    $btn.Add_Click({
        Show-Page $this.Tag
    })
}

# --- Assemble Form ---
$form.Controls.Add($panelContent)
$form.Controls.Add($panelLog)
$form.Controls.Add($panelNav)
$form.Controls.Add($panelHeader)

# --- Initialize ---
$form.Add_Shown({
    Show-Page "Dashboard"
    $btnRefreshDash.PerformClick()
    
    # Auto-connect to Ninja if credentials saved
    $settings = Get-NinjaSettings
    if ($settings.ClientId -and $settings.ClientSecret) {
        Log-Output "Auto-connecting to NinjaOne..."
        $result = Connect-NinjaOne -ClientId $settings.ClientId -ClientSecret $settings.ClientSecret -InstanceUrl $settings.Url
        if ($result) {
            $lblNinjaStatus.Text = "Connected!"
            $lblNinjaStatus.ForeColor = $Theme.Success
        }
    }
})

# --- Run ---
Log-Output "WinFix Tool v2.0 Started"
[void]$form.ShowDialog()
