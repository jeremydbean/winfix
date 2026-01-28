<#
.SYNOPSIS
    WinFix Tool v2.1.1 - Lightweight Windows Maintenance & Diagnostics
    BUILD: 2026-01-28-FIXED (Server 2012 R2 Compatible)
.DESCRIPTION
    Fast, snappy GUI tool for Windows maintenance. No auto-loading - refresh on demand.
.NOTES
#>

$ErrorActionPreference = 'Stop'

# Ensure WinForms types are available and the UI thread runs STA.
try {
    if ([System.Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
        $self = $PSCommandPath
        if ($self -and (Test-Path $self)) {
            Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -STA -File `"$self`"" -WindowStyle Normal
            exit
        }
    }
} catch { }

try {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()
    [System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false)
} catch {
    try {
        $logPath = Join-Path $env:TEMP 'WinFix_Debug.log'
        "[$(Get-Date -Format s)] WinFixTool_v2 startup failed (WinForms load): $($_.Exception.Message)" | Out-File -FilePath $logPath -Append -Encoding UTF8
    } catch { }
    Write-Error "Failed to load WinForms assemblies. This tool must run on Windows PowerShell with .NET Framework WinForms available. Error: $($_.Exception.Message)"
    exit 1
}

# Provide a default theme palette so color assignments never receive $null.
$defaultTheme = @{
    Bg      = [System.Drawing.Color]::FromArgb(18, 18, 24)
    Surface = [System.Drawing.Color]::FromArgb(26, 27, 38)
    Card    = [System.Drawing.Color]::FromArgb(36, 37, 51)
    Text    = [System.Drawing.Color]::FromArgb(237, 237, 245)
    Dim     = [System.Drawing.Color]::FromArgb(148, 150, 172)
    Accent  = [System.Drawing.Color]::FromArgb(99, 102, 241)
    Green   = [System.Drawing.Color]::FromArgb(34, 197, 94)
    Yellow  = [System.Drawing.Color]::FromArgb(250, 204, 21)
    Red     = [System.Drawing.Color]::FromArgb(239, 68, 68)
}
if (-not $script:Theme) { $script:Theme = @{} }
foreach ($key in $defaultTheme.Keys) {
    if (-not $script:Theme.ContainsKey($key) -or -not $script:Theme[$key]) {
        $script:Theme[$key] = $defaultTheme[$key]
    }
}

# Basic logger used throughout the UI.
$script:LogPath = Join-Path $env:TEMP 'WinFix_Debug.log'
try { $null = New-Item -Path $script:LogPath -ItemType File -Force -ErrorAction SilentlyContinue } catch { }
function Log {
    param([string]$Message)
    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "[$timestamp] $Message"
    try { Add-Content -Path $script:LogPath -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue } catch { }
    if ($script:txtLog) {
        $script:txtLog.AppendText("[$((Get-Date).ToString('HH:mm:ss'))] $Message`r`n")
        $script:txtLog.SelectionStart = $script:txtLog.Text.Length
        $script:txtLog.ScrollToCaret()
    }
}

trap {
    try {
        $logPath = Join-Path $env:TEMP 'WinFix_Debug.log'
        "[$(Get-Date -Format s)] Unhandled error: $($_ | Out-String)" | Out-File -FilePath $logPath -Append -Encoding UTF8
    } catch { }
    try {
        [System.Windows.Forms.MessageBox]::Show("WinFixTool_v2 crashed. Details were written to %TEMP%\WinFix_Debug.log`r`n`r`n$($_.Exception.Message)", "WinFixTool_v2 Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
    } catch { }
    break
}

function Invoke-DeepDiskCleanup {
    $results = @()
    $hasErrors = $false
    
    function Get-FreeGB {
        try {
            $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -EA Stop
            return [math]::Round($disk.FreeSpace / 1GB, 2)
        } catch { return 0 }
    }
    
    function Stop-Svc {
        param([string]$Name)
        $svc = Get-Service -Name $Name -EA SilentlyContinue
        if (-not $svc) { return $true }
        if ($svc.Status -eq 'Running') {
            try {
                Stop-Service -Name $Name -Force -EA Stop
                $t = 0; while ((Get-Service $Name).Status -ne 'Stopped' -and $t -lt 30) { Start-Sleep 1; $t++ }
            } catch { return $false }
        }
        return (Get-Service $Name).Status -eq 'Stopped'
    }
    
    $startSpace = Get-FreeGB
    $results += "Starting cleanup on $env:COMPUTERNAME"
    $results += "Initial free space: $startSpace GB"
    $results += ""
    
    # 1. Windows Update Cache
    $results += "=== Windows Update Cache ==="
    $wuaStopped = Stop-Svc "wuauserv"

    $bitsStopped = Stop-Svc "bits"
    if ($wuaStopped -and $bitsStopped) {
        $swDist = "C:\Windows\SoftwareDistribution\Download\*"
        if (Test-Path $swDist) {
            try { Remove-Item $swDist -Recurse -Force -EA Stop; $results += "Cleared SoftwareDistribution" }
            catch { $results += "ERROR: SoftwareDistribution: $_"; $hasErrors = $true }
        }
    }
    Start-Service wuauserv, bits -EA SilentlyContinue
    
    # 2. System Temp
    $results += "`n=== Temp Folders ==="
    try { Remove-Item "C:\Windows\Temp\*" -Recurse -Force -EA SilentlyContinue; $results += "Cleaned System Temp" }
    catch { $results += "ERROR: System Temp: $_"; $hasErrors = $true }
    
    # 3. User Temp & App Caches
    try {
        $users = Get-ChildItem "C:\Users" -Directory -EA SilentlyContinue
        foreach ($u in $users) {
            $pathsToClean = @(
                "$($u.FullName)\AppData\Local\Temp\*",
                "$($u.FullName)\AppData\Roaming\Microsoft\Teams\Cache\*",
                "$($u.FullName)\AppData\Roaming\Microsoft\Teams\blob_storage\*",
                "$($u.FullName)\AppData\Roaming\Microsoft\Teams\GPUCache\*",
                "$($u.FullName)\AppData\Roaming\Adobe\Common\Media Cache Files\*",
                "$($u.FullName)\AppData\Local\CrashDumps\*",
                "$($u.FullName)\AppData\Local\Microsoft\Teams\Current\SquirrelTemp\*"
            )
            foreach ($p in $pathsToClean) {
                if (Test-Path $p) { Remove-Item $p -Recurse -Force -EA SilentlyContinue }
            }
        }
        $results += "Cleaned User Temp, Teams, Adobe, CrashDumps"
    } catch { $results += "ERROR: User caches: $_"; $hasErrors = $true }
    
    # 4. IIS Logs (30+ days old)
    if (Test-Path "C:\inetpub\logs\LogFiles") {
        $results += "`n=== IIS Logs ==="
        try {
            $oldLogs = Get-ChildItem "C:\inetpub\logs\LogFiles" -Recurse -File -EA SilentlyContinue | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) }
            if ($oldLogs) { $oldLogs | Remove-Item -Force -EA SilentlyContinue; $results += "Removed $($oldLogs.Count) old IIS logs" }
        } catch { $results += "ERROR: IIS logs: $_"; $hasErrors = $true }
    }
    
    # 5. Hibernation
    $results += "`n=== Hibernation ==="
    if (Test-Path "C:\hiberfil.sys") {
        try { powercfg.exe /h off; $results += "Disabled hibernation (reclaimed hiberfil.sys)" }
        catch { $results += "ERROR: Hibernation: $_"; $hasErrors = $true }
    } else { $results += "Hibernation already disabled" }
    
    # 6. Recycle Bin
    $results += "`n=== Recycle Bin ==="
    try { Clear-RecycleBin -DriveLetter C -Force -EA Stop; $results += "Emptied Recycle Bin" }
    catch { $results += "Recycle bin already empty or locked" }
    
    # 7. DISM Component Cleanup (ResetBase)
    $results += "`n=== DISM Component Cleanup ==="
    $results += "Running DISM /ResetBase (this may take several minutes)..."
    try {
        $dismProc = Start-Process "dism.exe" -ArgumentList "/Online /Cleanup-Image /StartComponentCleanup /ResetBase /NoRestart" -NoNewWindow -PassThru -Wait
        if ($dismProc.ExitCode -eq 0) { $results += "DISM cleanup complete" }
        else { $results += "DISM exited with code $($dismProc.ExitCode)"; $hasErrors = $true }
    } catch { $results += "ERROR: DISM: $_"; $hasErrors = $true }
    
    # 8. CleanMgr (Disk Cleanup)
    if (Get-Command "cleanmgr.exe" -EA SilentlyContinue) {
        $results += "`n=== Windows Disk Cleanup ==="
        try {
            $stateKeys = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
            $cleanItems = @("Active Setup Temp Folders","BranchCache","Device Driver Packages","Downloaded Program Files",
                "Internet Cache Files","Memory Dump Files","Old ChkDsk Files","Previous Installations",
                "Service Pack Cleanup","Setup Log Files","System error memory dump files","System error minidump files",
                "Temporary Files","Temporary Setup Files","Thumbnail Cache","Update Cleanup",
                "Upgrade Discarded Files","Windows Defender","Windows Error Reporting Files")
            foreach ($k in $cleanItems) {
                $p = "$stateKeys\$k"
                if (Test-Path $p) { New-ItemProperty -Path $p -Name StateFlags0001 -Value 2 -PropertyType DWord -Force -EA SilentlyContinue | Out-Null }
            }
            Start-Process cleanmgr.exe -ArgumentList "/sagerun:1" -WindowStyle Hidden -Wait
            $results += "Windows Disk Cleanup complete"
        } catch { $results += "ERROR: CleanMgr: $_"; $hasErrors = $true }
    }
    
    # 9. OS Compression (CompactOS)
    $results += "`n=== OS Compression ==="
    try {
        $results += "Running CompactOS..."
        compact.exe /CompactOS:always 2>&1 | Out-Null
        $results += "Compressing Program Files..."
        compact.exe /C /S /I /F "C:\Program Files\*" 2>&1 | Out-Null
        compact.exe /C /S /I /F "C:\Program Files (x86)\*" 2>&1 | Out-Null
        $results += "Compression complete"
    } catch { $results += "ERROR: Compression: $_"; $hasErrors = $true }
    
    # Final Report
    $endSpace = Get-FreeGB
    $reclaimed = [math]::Round($endSpace - $startSpace, 2)
    if ($reclaimed -lt 0) { $reclaimed = 0 }
    
    $results += "`n=========================================="
    $results += "CLEANUP COMPLETE"
    $results += "Initial: $startSpace GB | Final: $endSpace GB"
    $results += "Reclaimed: $reclaimed GB"
    $results += "Status: $(if ($hasErrors) { 'Completed with errors' } else { 'Success' })"
    $results += "=========================================="
    
    return $results -join "`r`n"
}

# --- Create Main Form ---
$form = New-Object System.Windows.Forms.Form
$form.Text = "WinFix Tool v2.1.1 (2026-01-28)"
$form.Size = New-Object System.Drawing.Size(780, 560)
$form.MinimumSize = New-Object System.Drawing.Size(640, 480)
$form.StartPosition = "CenterScreen"
$form.BackColor = $script:Theme.Bg
$form.ForeColor = $script:Theme.Text
$form.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$form.FormBorderStyle = "Sizable"

# --- Header ---
$panelHeader = New-Object System.Windows.Forms.Panel
$panelHeader.Dock = "Top"
$panelHeader.Height = 36
$panelHeader.BackColor = $script:Theme.Surface

$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = "WinFix Tool"
$lblTitle.Location = New-Object System.Drawing.Point(10, 8)
$lblTitle.AutoSize = $true
$lblTitle.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$lblTitle.ForeColor = $script:Theme.Accent

$lblPC = New-Object System.Windows.Forms.Label
$lblPC.Text = "$env:COMPUTERNAME"
$lblPC.Location = New-Object System.Drawing.Point(600, 10)
$lblPC.AutoSize = $true
$lblPC.Anchor = "Top, Right"
$lblPC.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)

$panelHeader.Controls.AddRange(@($lblTitle, $lblPC))

# --- Nav Panel ---
$panelNav = New-Object System.Windows.Forms.Panel
$panelNav.Dock = "Left"
$panelNav.Width = 100
$panelNav.BackColor = $script:Theme.Surface

$navItems = @("Dashboard", "Quick Fix", "Diagnostics", "Network", "Audit")
$navButtons = @()
$navY = 5

foreach ($nav in $navItems) {
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $nav
    $btn.Location = New-Object System.Drawing.Point(3, $navY)
    $btn.Size = New-Object System.Drawing.Size(94, 28)
    $btn.FlatStyle = "Flat"
    $btn.BackColor = $script:Theme.Card
    $btn.ForeColor = $script:Theme.Text
    $btn.FlatAppearance.BorderSize = 0
    $btn.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $btn.Tag = $nav
    $btn.Add_Click({ Show-Page $this.Tag })
    $panelNav.Controls.Add($btn)
    $navButtons += $btn
    $navY += 32
}

# --- Log Panel (collapsible) ---
$panelLog = New-Object System.Windows.Forms.Panel
$panelLog.Dock = "Bottom"
$panelLog.Height = 60
$panelLog.BackColor = $script:Theme.Surface

$lblLog = New-Object System.Windows.Forms.Label
$lblLog.Text = "Log"
$lblLog.Dock = "Top"
$lblLog.Height = 14
$lblLog.ForeColor = $script:Theme.Dim
$lblLog.Font = New-Object System.Drawing.Font("Segoe UI", 7)

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
$pageDash.AutoScroll = $true

# Status Grid - Left column
$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Text = "SYSTEM STATUS"
$lblStatus.Location = New-Object System.Drawing.Point(10, 8)
$lblStatus.AutoSize = $true
$lblStatus.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$lblStatus.ForeColor = $script:Theme.Dim

$script:lblCPU = New-Object System.Windows.Forms.Label
$script:lblCPU.Text = "$($script:StatusPending) CPU: --"
$script:lblCPU.Location = New-Object System.Drawing.Point(10, 32)
$script:lblCPU.Size = New-Object System.Drawing.Size(250, 18)
$script:lblCPU.Font = New-Object System.Drawing.Font("Consolas", 9)

$script:lblRAM = New-Object System.Windows.Forms.Label
$script:lblRAM.Text = "$($script:StatusPending) Memory: --"
$script:lblRAM.Location = New-Object System.Drawing.Point(10, 52)
$script:lblRAM.Size = New-Object System.Drawing.Size(250, 18)
$script:lblRAM.Font = New-Object System.Drawing.Font("Consolas", 9)

$script:lblDisk = New-Object System.Windows.Forms.Label
$script:lblDisk.Text = "$($script:StatusPending) Disk C: --"
$script:lblDisk.Location = New-Object System.Drawing.Point(10, 72)
$script:lblDisk.Size = New-Object System.Drawing.Size(250, 18)
$script:lblDisk.Font = New-Object System.Drawing.Font("Consolas", 9)

$script:lblUptime = New-Object System.Windows.Forms.Label
$script:lblUptime.Text = "$($script:StatusPending) Uptime: --"
$script:lblUptime.Location = New-Object System.Drawing.Point(10, 92)
$script:lblUptime.Size = New-Object System.Drawing.Size(250, 18)
$script:lblUptime.Font = New-Object System.Drawing.Font("Consolas", 9)

$script:lblUpdates = New-Object System.Windows.Forms.Label
$script:lblUpdates.Text = "$($script:StatusPending) Updates: --"
$script:lblUpdates.Location = New-Object System.Drawing.Point(10, 112)
$script:lblUpdates.Size = New-Object System.Drawing.Size(250, 18)
$script:lblUpdates.Font = New-Object System.Drawing.Font("Consolas", 9)

$script:lblServices = New-Object System.Windows.Forms.Label
$script:lblServices.Text = "$($script:StatusPending) Services: --"
$script:lblServices.Location = New-Object System.Drawing.Point(10, 132)
$script:lblServices.Size = New-Object System.Drawing.Size(250, 18)
$script:lblServices.Font = New-Object System.Drawing.Font("Consolas", 9)

# Right side - System Info
$lblInfoTitle = New-Object System.Windows.Forms.Label
$lblInfoTitle.Text = "SYSTEM INFO"
$lblInfoTitle.Location = New-Object System.Drawing.Point(270, 8)
$lblInfoTitle.AutoSize = $true
$lblInfoTitle.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$lblInfoTitle.ForeColor = $script:Theme.Dim

$script:lblSysInfo = New-Object System.Windows.Forms.Label
$script:lblSysInfo.Text = "Click Refresh to load..."
$script:lblSysInfo.Location = New-Object System.Drawing.Point(270, 32)
$script:lblSysInfo.Size = New-Object System.Drawing.Size(300, 140)
$script:lblSysInfo.Font = New-Object System.Drawing.Font("Consolas", 8)
$script:lblSysInfo.Anchor = "Top, Left, Right"

# Refresh Button
$btnRefresh = New-Object System.Windows.Forms.Button
$btnRefresh.Text = "Refresh Status"
$btnRefresh.Location = New-Object System.Drawing.Point(10, 180)
$btnRefresh.Size = New-Object System.Drawing.Size(120, 28)
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

$pageDash.Controls.AddRange(@($lblStatus, $script:lblCPU, $script:lblRAM, $script:lblDisk, $script:lblUptime, $script:lblUpdates, $script:lblServices, $lblInfoTitle, $script:lblSysInfo, $btnRefresh))
$pages["Dashboard"] = $pageDash

# === QUICK FIX PAGE ===
$pageQuick = New-Object System.Windows.Forms.Panel
$pageQuick.Dock = "Fill"
$pageQuick.BackColor = $script:Theme.Bg
$pageQuick.AutoScroll = $true

$lblQuickTitle = New-Object System.Windows.Forms.Label
$lblQuickTitle.Text = "QUICK FIXES"
$lblQuickTitle.Location = New-Object System.Drawing.Point(10, 8)
$lblQuickTitle.AutoSize = $true
$lblQuickTitle.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$lblQuickTitle.ForeColor = $script:Theme.Dim

$pageQuick.Controls.Add($lblQuickTitle)

$fixes = @(
    @{Name = "Deep Disk Cleanup"; Cmd = {
        $form = [System.Windows.Forms.Form]@{ Text="Deep Disk Cleanup"; Size="500,400"; StartPosition="CenterScreen"; BackColor=$script:Theme.Bg; ForeColor=$script:Theme.Text }
        $txt = [System.Windows.Forms.TextBox]@{ Multiline=$true; ScrollBars="Both"; ReadOnly=$true; Location="10,10"; Size="465,300"; BackColor=$script:Theme.Surface; ForeColor=$script:Theme.Text; Font=[System.Drawing.Font]::new("Consolas",8); Anchor="Top,Left,Right,Bottom" }
        $btn = [System.Windows.Forms.Button]@{ Text="Start Cleanup"; Location="10,320"; Size="465,30"; FlatStyle="Flat"; BackColor=$script:Theme.Accent; ForeColor="White" }
        $btn.FlatAppearance.BorderSize = 0
        $btn.Add_Click({
            $this.Enabled = $false; $this.Text = "Running... Please wait"
            $txt.Text = "Starting deep disk cleanup...`r`n`r`n"
            [System.Windows.Forms.Application]::DoEvents()
            $result = Invoke-DeepDiskCleanup
            $txt.Text = $result
            $this.Text = "Complete"; $this.Enabled = $true
        })
        $form.Controls.AddRange(@($txt,$btn)); $form.ShowDialog()
        "Deep Disk Cleanup window closed"
    }}
    @{Name = "Flush DNS"; Cmd = { ipconfig /flushdns }}
    @{Name = "Reset Network"; Cmd = { netsh winsock reset; netsh int ip reset; ipconfig /release; ipconfig /renew; "Done! Restart recommended." }}
    @{Name = "Fix Windows Update"; Cmd = { Stop-Service wuauserv,cryptSvc,bits,msiserver -Force -EA 0; Remove-Item "C:\Windows\SoftwareDistribution\*","C:\Windows\System32\catroot2\*" -Recurse -Force -EA 0; Start-Service wuauserv,cryptSvc,bits,msiserver -EA 0; "Done!" }}
    @{Name = "Clear Print Spooler"; Cmd = { Stop-Service Spooler -Force; Remove-Item "C:\Windows\System32\spool\PRINTERS\*" -Force -EA 0; Start-Service Spooler; "Done!" }}
    @{Name = "SFC Scan"; Cmd = { sfc /scannow }}
    @{Name = "DISM Repair"; Cmd = { DISM /Online /Cleanup-Image /RestoreHealth }}
    @{Name = "Sync Time"; Cmd = { w32tm /resync /force }}
    @{Name = "Restart Explorer"; Cmd = { Stop-Process -Name explorer -Force; Start-Process explorer; "Done!" }}
)

$fixY = 32; $fixX = 10; $fixCol = 0
foreach ($fix in $fixes) {
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $fix.Name
    $btn.Location = New-Object System.Drawing.Point($fixX, $fixY)
    $btn.Size = New-Object System.Drawing.Size(130, 32)
    $btn.FlatStyle = "Flat"
    $btn.BackColor = $script:Theme.Card
    $btn.ForeColor = $script:Theme.Text
    $btn.FlatAppearance.BorderSize = 0
    $btn.Font = New-Object System.Drawing.Font("Segoe UI", 8)
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
    if ($fixCol -ge 4) { $fixCol = 0; $fixX = 10; $fixY += 38 }
    else { $fixX += 138 }
}

$pages["Quick Fix"] = $pageQuick

# === DIAGNOSTICS PAGE ===
$pageDiag = New-Object System.Windows.Forms.Panel
$pageDiag.Dock = "Fill"
$pageDiag.BackColor = $script:Theme.Bg

$lblDiagTitle = New-Object System.Windows.Forms.Label
$lblDiagTitle.Text = "DIAGNOSTICS"
$lblDiagTitle.Location = New-Object System.Drawing.Point(10, 8)
$lblDiagTitle.AutoSize = $true
$lblDiagTitle.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$lblDiagTitle.ForeColor = $script:Theme.Dim

$txtDiag = New-Object System.Windows.Forms.TextBox
$txtDiag.Multiline = $true
$txtDiag.ScrollBars = "Both"
$txtDiag.ReadOnly = $true
$txtDiag.Location = New-Object System.Drawing.Point(10, 30)
$txtDiag.Size = New-Object System.Drawing.Size(400, 340)
$txtDiag.BackColor = $script:Theme.Surface
$txtDiag.ForeColor = $script:Theme.Text
$txtDiag.Font = New-Object System.Drawing.Font("Consolas", 8)
$txtDiag.Anchor = "Top, Left, Bottom"

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

$btnY = 30
foreach ($diag in $diagBtns) {
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $diag.Name
    $btn.Location = New-Object System.Drawing.Point(420, $btnY)
    $btn.Size = New-Object System.Drawing.Size(100, 26)
    $btn.FlatStyle = "Flat"
    $btn.BackColor = $script:Theme.Card
    $btn.ForeColor = $script:Theme.Text
    $btn.FlatAppearance.BorderSize = 0
    $btn.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $btn.Tag = $diag.Cmd
    $btn.Add_Click({ Log "Running: $($this.Text)..."; $txtDiag.Text = & $this.Tag; Log "Done." })
    $pageDiag.Controls.Add($btn)
    $btnY += 30
}

$pageDiag.Controls.AddRange(@($lblDiagTitle, $txtDiag))
$pages["Diagnostics"] = $pageDiag

# === NETWORK PAGE ===
$pageNet = New-Object System.Windows.Forms.Panel
$pageNet.Dock = "Fill"
$pageNet.BackColor = $script:Theme.Bg

$lblNetTitle = New-Object System.Windows.Forms.Label
$lblNetTitle.Text = "NETWORK TOOLS"
$lblNetTitle.Location = New-Object System.Drawing.Point(10, 8)
$lblNetTitle.AutoSize = $true
$lblNetTitle.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$lblNetTitle.ForeColor = $script:Theme.Dim

$txtNet = New-Object System.Windows.Forms.TextBox
$txtNet.Multiline = $true
$txtNet.ScrollBars = "Both"
$txtNet.ReadOnly = $true
$txtNet.Location = New-Object System.Drawing.Point(10, 30)
$txtNet.Size = New-Object System.Drawing.Size(400, 340)
$txtNet.BackColor = $script:Theme.Surface
$txtNet.ForeColor = $script:Theme.Text
$txtNet.Font = New-Object System.Drawing.Font("Consolas", 8)
$txtNet.Anchor = "Top, Left, Bottom"

$netBtns = @(
    @{Name = "IP Config"; Cmd = { ipconfig /all | Out-String }}
    @{Name = "ARP Table"; Cmd = { arp -a | Out-String }}
    @{Name = "Test Internet"; Cmd = { Test-Connection 8.8.8.8 -Count 4 | Format-Table Address, ResponseTime, Status | Out-String }}
    @{Name = "Connections"; Cmd = { netstat -an | Out-String }}
    @{Name = "DNS Servers"; Cmd = { Get-DnsClientServerAddress | Format-Table InterfaceAlias, ServerAddresses | Out-String }}
    @{Name = "Routes"; Cmd = { route print | Out-String }}
    @{Name = "WiFi Passwords"; Cmd = {
        $output = "=== SAVED WIFI NETWORKS & PASSWORDS ===`r`n`r`n"
        $profiles = netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object {
            ($_ -split ":")[-1].Trim()
        }
        if ($profiles) {
            foreach ($wifiProfileName in $profiles) {
                $output += "Network: $wifiProfileName`r`n"
                $details = netsh wlan show profile name="$wifiProfileName" key=clear 2>$null
                $keyContent = $details | Select-String "Key Content"
                if ($keyContent) {
                    $password = ($keyContent -split ":")[-1].Trim()
                    $output += "Password: $password`r`n"
                } else {
                    $output += "Password: (none/open network)`r`n"
                }
                $auth = $details | Select-String "Authentication"
                if ($auth) {
                    $authType = ($auth[0] -split ":")[-1].Trim()
                    $output += "Auth: $authType`r`n"
                }
                $output += "`r`n"
            }
        } else {
            $output += "No saved WiFi profiles found.`r`n"
        }
        $output
    }}
)

$btnY = 30
foreach ($net in $netBtns) {
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $net.Name
    $btn.Location = New-Object System.Drawing.Point(420, $btnY)
    $btn.Size = New-Object System.Drawing.Size(100, 26)
    $btn.FlatStyle = "Flat"
    $btn.BackColor = $script:Theme.Card
    $btn.ForeColor = $script:Theme.Text
    $btn.FlatAppearance.BorderSize = 0
    $btn.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $btn.Tag = $net.Cmd
    $btn.Add_Click({ Log "Running: $($this.Text)..."; $txtNet.Text = & $this.Tag; Log "Done." })
    $pageNet.Controls.Add($btn)
    $btnY += 30
}

$pageNet.Controls.AddRange(@($lblNetTitle, $txtNet))
$pages["Network"] = $pageNet

# === AUDIT PAGE ===
$pageAudit = New-Object System.Windows.Forms.Panel
$pageAudit.Dock = "Fill"
$pageAudit.BackColor = $script:Theme.Bg
$pageAudit.AutoScroll = $true

$lblAuditTitle = New-Object System.Windows.Forms.Label
$lblAuditTitle.Text = "SECURITY AUDIT"
$lblAuditTitle.Location = New-Object System.Drawing.Point(10, 8)
$lblAuditTitle.AutoSize = $true
$lblAuditTitle.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$lblAuditTitle.ForeColor = $script:Theme.Dim

$lblAuditDesc = New-Object System.Windows.Forms.Label
$lblAuditDesc.Text = "Generate Polar Nite Security & Backup Audit (HTML)."
$lblAuditDesc.Location = New-Object System.Drawing.Point(10, 32)
$lblAuditDesc.Size = New-Object System.Drawing.Size(600, 20)
$lblAuditDesc.Font = New-Object System.Drawing.Font("Segoe UI", 8)

$btnAudit = New-Object System.Windows.Forms.Button
$btnAudit.Text = "Generate Audit Report"
$btnAudit.Location = New-Object System.Drawing.Point(10, 60)
$btnAudit.Size = New-Object System.Drawing.Size(150, 32)
$btnAudit.FlatStyle = "Flat"
$btnAudit.BackColor = $script:Theme.Accent
$btnAudit.ForeColor = "White"
$btnAudit.FlatAppearance.BorderSize = 0
$btnAudit.Add_Click({
    Log "Generating Polar Nite Audit..."
    $this.Enabled = $false
    $this.Text = "Scanning..."
    [System.Windows.Forms.Application]::DoEvents()
    
    # --- Gather Local Data ---
    Log "Getting system information..."
    [System.Windows.Forms.Application]::DoEvents()
    $CompInfo = Get-CimInstance Win32_ComputerSystem -EA SilentlyContinue
    $OSInfo = Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue
    $AdminGroup = Get-LocalGroupMember -Group "Administrators" -EA SilentlyContinue
    
    $Uptime = "Unknown"
    if ($OSInfo -and $OSInfo.LastBootUpTime) {
        $upt = (Get-Date) - $OSInfo.LastBootUpTime
        $Uptime = "{0}D {1}H" -f $upt.Days, $upt.Hours
    }
    $IsVM = $CompInfo.Model -match "Virtual|VMware|Hyper-V|KVM|Xen"
    
    # EOS Check
    $EOSWarning = ""
    if ($OSInfo.Caption -match "Server 2003|Server 2008 [^R]|Server 2012 [^R]|Windows 7|Windows 8[^.]|SBS 2011") {
        $EOSWarning = "<span class='alert'>[END OF SUPPORT - SECURITY RISK]</span>"
    }
    # Note: Server 2008 R2 and 2012 R2 have extended support until 2023/2026
    
    # Roles
    Log "Detecting server roles..."
    [System.Windows.Forms.Application]::DoEvents()
    $DetectedRoles = "Workstation"
    if (Get-Command Get-WindowsFeature -EA SilentlyContinue) {
        try { 
            $DetectedRoles = "Checking (this may take a moment)..."
            $roles = Get-WindowsFeature | Where-Object Installed | Select-Object -First 50 -ExpandProperty Name
            $DetectedRoles = $roles -join ", "
        } catch { $DetectedRoles = "Unable to enumerate" }
    }
    
    # Backup Detection
    Log "Scanning for backup software..."
    [System.Windows.Forms.Application]::DoEvents()
    $BackupKeywords = @("Veeam","Acronis","Datto","Carbonite","Cyber Protect","Backup Exec","Backblaze","Ahsay","CrashPlan","ShadowProtect")
    $BackupServices = @()
    try {
        $BackupServices = Get-Service -EA SilentlyContinue | Where-Object {
            $name = $_.DisplayName
            $isMatch = $false
            foreach ($keyword in $BackupKeywords) {
                if ($name -and $name -like "*$keyword*") { $isMatch = $true; break }
            }
            $isMatch
        }
    } catch {}
    $BackupServiceNames = $BackupServices | Select-Object -ExpandProperty DisplayName -Unique
    $UninstallPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $BackupProgramNames = @()
    foreach ($path in $UninstallPaths) {
        try {
            $packages = Get-ItemProperty -Path $path -EA SilentlyContinue
            foreach ($pkg in $packages) {
                $display = $pkg.DisplayName
                if (-not $display) { continue }
                $isMatch = $false
                foreach ($keyword in $BackupKeywords) {
                    if ($display -like "*$keyword*") { $isMatch = $true; break }
                }
                if ($isMatch) { $BackupProgramNames += $display }
            }
        } catch {}
    }
    $BackupSoftwareListAll = ($BackupServiceNames + $BackupProgramNames) | Where-Object { $_ } | Sort-Object -Unique
    $BackupSoftwareListHtml = if ($BackupSoftwareListAll) {
        '<ul style="margin:0; padding-left:16px;">' + ($BackupSoftwareListAll | ForEach-Object { "<li>$(Escape-ForHtmlAttr $_)</li>" }) -join '' + '</ul>'
    } else { 'None detected' }
    $DetectedBackup = if ($BackupSoftwareListAll) { $BackupSoftwareListAll -join '; ' } else { 'Not Detected' }
    
    # Updates
    Log "Checking Windows Updates..."
    [System.Windows.Forms.Application]::DoEvents()
    $LastHotFix = Get-HotFix -EA SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 1
    $LastUpdateDate = if ($LastHotFix.InstalledOn) { $LastHotFix.InstalledOn.ToString('yyyy-MM-dd') } else { "Unknown" }
    $PendingReboot = (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") -or 
                     (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired")
    
    # AV
    Log "Checking antivirus status..."
    [System.Windows.Forms.Application]::DoEvents()
    $AV = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -EA SilentlyContinue
    $AVName = if ($AV) { $AV.displayName } else { "None Detected" }
    $Defender = $null
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        $Defender = Get-MpComputerStatus -EA SilentlyContinue
    }
    if ($Defender) {
        $RTPEnabled = if ($Defender.RealTimeProtectionEnabled) { "Yes" } else { "No" }
        $LastScan = if ($Defender.QuickScanEndTime) { $Defender.QuickScanEndTime.ToString("yyyy-MM-dd") } else { "Unknown" }
    } else {
        $RTPEnabled = "Unknown"
        $LastScan = "Unknown"
    }
    
    # BitLocker
    $BitLockerStatus = "Unknown"
    if ($IsVM) {
        $BitLockerStatus = "Virtual Machine - Check Host Encryption"
    } else {
        if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
            try {
                $bl = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
                $BitLockerStatus = if ($bl.ProtectionStatus -eq "On") { "Encrypted" } else { "Not Encrypted" }
            } catch {
                $BitLockerStatus = "Error checking BitLocker"
            }
        } else {
            $BitLockerStatus = "BitLocker Cmdlet Not Available"
        }
    }
    
    # Firewall
    $FWProfiles = "Unknown"
    if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
        $FWProfiles = (Get-NetFirewallProfile -EA SilentlyContinue | Where-Object Enabled).Name -join ", "
        if (-not $FWProfiles) { $FWProfiles = "DISABLED" }
    } else {
        # Fallback for older systems
        try {
            $fwPolicy = New-Object -ComObject HNetCfg.FwPolicy2 -EA Stop
            $profiles = @()
            if ($fwPolicy.FirewallEnabled(1)) { $profiles += "Domain" }
            if ($fwPolicy.FirewallEnabled(2)) { $profiles += "Private" }
            if ($fwPolicy.FirewallEnabled(4)) { $profiles += "Public" }
            $FWProfiles = if ($profiles) { $profiles -join ", " } else { "DISABLED" }
        } catch { $FWProfiles = "Unable to determine" }
    }
    
    # RDP
    $RDP = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -EA SilentlyContinue
    $RDPStatus = if ($RDP.fDenyTSConnections -eq 1) { "Disabled" } else { "Enabled" }
    $RdpFailureNotes = "No recent failures detected"
    try {
        $rdpFailures = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-30)} -MaxEvents 5 -EA SilentlyContinue
        if ($rdpFailures) { $RdpFailureNotes = "Yes ($($rdpFailures.Count) events in last 30 days)" }
    } catch {
        $RdpFailureNotes = "Unable to query Security log (requires elevated rights)"
    }
    
    # Disk Health & RAID
    $Disks = $null
    if (Get-Command Get-PhysicalDisk -ErrorAction SilentlyContinue) {
        $Disks = Get-PhysicalDisk -EA SilentlyContinue | Select-Object FriendlyName, MediaType, HealthStatus
    }
    $DiskHealth = if ($Disks) { ($Disks | ForEach-Object { "$($_.MediaType): $($_.HealthStatus)" }) -join "; " } else { "Unknown (cmdlet unavailable)" }
    
    $RAIDStatus = "Unknown"
    if ($IsVM) {
        $RAIDStatus = "Virtual Machine - Check Host RAID"
    } else {
        # Try local
        if (Get-Command Get-PhysicalDisk -ErrorAction SilentlyContinue) {
            $pDisks = Get-PhysicalDisk -ErrorAction SilentlyContinue
            if ($pDisks) {
                 $RAIDStatus = ($pDisks | Select-Object -ExpandProperty MediaType -Unique) -join ", "
            }
        } else {
            $RAIDStatus = "Physical disk cmdlet unavailable"
        }
    }
    
    # Storage Warning
    $CDrive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -EA SilentlyContinue
    $FreePct = if ($CDrive) { [math]::Round(($CDrive.FreeSpace / $CDrive.Size) * 100, 1) } else { 0 }
    $StorageWarn = if ($FreePct -lt 15) { "LOW DISK: $FreePct% Free" } else { "" }

    # Physical drives & TPM
    $PhysicalDrives = Get-CimInstance Win32_DiskDrive -EA SilentlyContinue
    $PhysicalDriveInfo = if ($PhysicalDrives) { ($PhysicalDrives | ForEach-Object { "$($_.DeviceID): $($_.Model) ($($_.Status))" }) -join "; " } else { "Not available" }
    $TpmStatus = "Not present or unsupported"
    if (Get-Command Get-Tpm -ErrorAction SilentlyContinue) {
        try {
            $tpm = Get-Tpm -ErrorAction Stop
            if ($tpm.TpmReady) { $TpmStatus = "Yes (TPM ready)" } else { $TpmStatus = "No (TPM present but not ready)" }
        } catch {
            $TpmStatus = "No (Get-Tpm failed)"
        }
    }
    
    # Local Users
    Log "Enumerating local users..."
    [System.Windows.Forms.Application]::DoEvents()
    $LocalUserCmd = Get-Command Get-LocalUser -ErrorAction SilentlyContinue
    $LocalUserObjects = if ($LocalUserCmd) { Get-LocalUser -EA SilentlyContinue } else { @() }
    $LocalUsersDetailed = @()
    if ($LocalUserObjects) {
        foreach ($user in $LocalUserObjects | Sort-Object Name) {
            $status = if ($user.Enabled) { "Enabled" } else { "Disabled" }
            $pwdDate = if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString('yyyy-MM-dd HH:mm') } else { 'Never' }
            $LocalUsersDetailed += "$($user.Name) [$status] - Last PW: $pwdDate"
        }
    } else {
        $LocalUsersDetailed += "Local account enumeration not supported on this host."
    }
    $LocalUsers = $LocalUsersDetailed -join "; "

    $AdminListEntries = @()
    $AdminDetails = @()
    if ($AdminGroup) {
        foreach ($member in $AdminGroup | Sort-Object Name -Unique) {
            $detail = [ordered]@{
                Name = $member.Name
                ObjectClass = $member.ObjectClass
                Enabled = "Unknown"
                PasswordLastSet = "Unknown"
            }
            if ($member.ObjectClass -eq "User") {
                if (-not $LocalUserCmd -or $member.Name -match '\\') {
                    $detail.Enabled = "Domain-managed"
                    $detail.PasswordLastSet = "Managed externally"
                } else {
                    $localUser = Get-LocalUser -Name $member.Name -EA SilentlyContinue
                    if ($localUser) {
                        $detail.Enabled = if ($localUser.Enabled) { "Enabled" } else { "Disabled" }
                        $detail.PasswordLastSet = if ($localUser.PasswordLastSet) { $localUser.PasswordLastSet.ToString('yyyy-MM-dd HH:mm') } else { 'Never' }
                    }
                }
            } elseif ($member.ObjectClass -eq "Group") {
                $detail.PasswordLastSet = "Group membership"
            }
            $AdminDetails += [pscustomobject]$detail
            $AdminListEntries += "<li>$($detail.Name) ($($detail.Enabled)) - Last PW: $($detail.PasswordLastSet)</li>"
        }
    }
    $AdminList = if ($AdminListEntries) { $AdminListEntries -join "" } else { "<li>Unknown</li>" }

    $AdminAccessSummary = if ($AdminDetails) { ($AdminDetails | ForEach-Object { "$($_.Name) [$($_.Enabled)] - Last PW: $($_.PasswordLastSet)" }) -join "; " } else { "Unable to enumerate administrators" }
    $AdminPasswordSummary = if ($AdminDetails) { ($AdminDetails | Where-Object { $_.ObjectClass -eq 'User' } | ForEach-Object { "$($_.Name): $($_.PasswordLastSet)" }) -join "; " } else { "Unknown" }
    $DisabledAdminList = ($AdminDetails | Where-Object { $_.Enabled -eq 'Disabled' } | Select-Object -ExpandProperty Name) -join ", "
    if (-not $DisabledAdminList) { $DisabledAdminList = "None" }
    $MfaStatus = "Unknown (verify with identity provider)"
    
    # Password Policy
    Log "Checking password policy..."
    [System.Windows.Forms.Application]::DoEvents()
    $PassComplex = "Unknown"
    $secPol = $null
    try {
        $secFile = "$env:TEMP\secpol.cfg"
        secedit /export /cfg $secFile /quiet 2>$null
        $secPol = Get-Content $secFile -EA SilentlyContinue
        if ($secPol -match "PasswordComplexity\s*=\s*1") { $PassComplex = "Yes" }
        elseif ($secPol -match "PasswordComplexity\s*=\s*0") { $PassComplex = "No" }
        Remove-Item $secFile -EA SilentlyContinue
    } catch {}

    $PasswordMinLength = Get-SecPolValue -Lines $secPol -Key "MinimumPasswordLength"
    $PasswordMaxAge = Get-SecPolValue -Lines $secPol -Key "MaximumPasswordAge"
    $PasswordHistory = Get-SecPolValue -Lines $secPol -Key "PasswordHistorySize"
    $PasswordPolicySummary = "MinLen: $($PasswordMinLength -or 'Unknown'); MaxAge: $($PasswordMaxAge -or 'Unknown'); History: $($PasswordHistory -or 'Unknown'); Complexity: $PassComplex"

    $PatchEntries = @()
    $PatchListHtml = 'Unknown'
    $PatchSummary = 'Unknown'
    Log "Checking for pending patches..."
    [System.Windows.Forms.Application]::DoEvents()
    
    # Simplified approach - run directly with timeout protection
    try {
        $wuSession = New-Object -ComObject 'Microsoft.Update.Session' -ErrorAction Stop
        $wuSearcher = $wuSession.CreateUpdateSearcher()
        $wuSearcher.Online = $false  # Search local cache only
        
        # Try to get update count
        try {
            $wuResult = $wuSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
            
            if ($wuResult -and $wuResult.Updates) {
                $pendingCount = $wuResult.Updates.Count
                
                if ($pendingCount -le 0) {
                    $PatchSummary = 'None detected'
                    $PatchListHtml = 'No pending patches detected.'
                } else {
                    $PatchSummary = "$pendingCount pending"
                    $maxToShow = [Math]::Min(10, $pendingCount)
                    
                    # Safely iterate updates
                    for ($i = 0; $i -lt $maxToShow; $i++) {
                        try {
                            $update = $wuResult.Updates.Item($i)
                            if ($update -and $update.Title) {
                                $PatchEntries += "<li>$(Escape-ForHtmlAttr $update.Title)</li>"
                            }
                        } catch {
                            # Skip update if error accessing it
                            continue
                        }
                    }
                    
                    $PatchListHtml = if ($PatchEntries.Count -gt 0) {
                        '<ul style="margin:0; padding-left:16px;">' + ($PatchEntries -join '') + '</ul>'
                    } else {
                        "$pendingCount pending (details unavailable)"
                    }
                }
            } else {
                $PatchSummary = 'No results'
                $PatchListHtml = 'Windows Update API returned no results'
            }
        } catch {
            $PatchSummary = 'Check failed'
            $PatchListHtml = "Error: $($_.Exception.Message)"
            Log "Patch check error: $_"
        }
    } catch {
        $PatchSummary = 'WU API unavailable'
        $PatchListHtml = 'Windows Update COM object unavailable'
        Log "Cannot create Windows Update Session: $_"
    }

    $BackupEncryptionMap = @{
        'Veeam' = 'AES-256 (Veeam default)'
        'Acronis' = 'AES-256 (Acronis encrypted vault)'
        'Datto' = 'AES-256 (Datto cloud)'
        'Carbonite' = 'AES-128 (Carbonite standard)'
        'ShadowProtect' = 'AES-256 (StorageCraft default)'
        'CrashPlan' = 'AES-256 (CrashPlan vault)'
        'Backup Exec' = 'AES-128 (Symantec Backup Exec)'
    }
    $lookupString = ($BackupSoftwareListAll -join '; ')
    $EncryptionDetails = @()
    foreach ($pattern in $BackupEncryptionMap.Keys) {
        if ($lookupString -match $pattern) { $EncryptionDetails += $BackupEncryptionMap[$pattern] }
    }
    $BackupEncryptionType = if ($EncryptionDetails) { $EncryptionDetails -join '; ' } else { 'Unknown (verify backup vendor settings)' }

    $BackupsEncrypted = 'Unknown'
    if ($EncryptionDetails) {
        $BackupsEncrypted = 'Yes (per vendor defaults)'
    }

    $BackupTransferEncrypted = 'Assumed TLS/SSL (vendor default)'

    $OffsiteCopy = 'Unknown'
    if ($OffsiteCopy -eq 'Unknown' -and $DetectedBackup -match 'Datto|Carbonite|Backblaze') {
        $OffsiteCopy = 'Yes (cloud-enabled vendor)'
    }

    $BackupFrequency = 'Unknown (check backup console)'
    $BackupRetention = 'Unknown'

    $BackupSuccess = "Unknown"
    $BackupLastSuccess = "Unknown"
    $BackupFailuresThisMonth = "Unknown"

    # Open Ports
    $OpenPorts = "Unknown"
    if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        try {
            $OpenPorts = (Get-NetTCPConnection -State Listen -EA SilentlyContinue | Select-Object -ExpandProperty LocalPort -Unique | Sort-Object {[int]$_}) -join ", "
        } catch {
            $OpenPorts = "Unable to enumerate"
        }
    } else {
        # Fallback for older systems
        try {
            $netstat = netstat -an | Select-String "LISTENING" | ForEach-Object {
                if ($_ -match ':([0-9]+)\s') { $matches[1] }
            } | Select-Object -Unique | Sort-Object {[int]$_}
            $OpenPorts = $netstat -join ", "
        } catch {
            $OpenPorts = "Unable to enumerate"
        }
    }

    # Security log metadata
    $SecurityLogInfo = $null
    try { $SecurityLogInfo = Get-WinEvent -ListLog Security -EA SilentlyContinue } catch {}
    $SecurityLogsEnabled = if ($SecurityLogInfo -and $SecurityLogInfo.IsEnabled) { "Yes" } else { "No" }
    $SecurityLogSizeMB = if ($SecurityLogInfo -and $SecurityLogInfo.MaximumSizeInBytes) { [math]::Round($SecurityLogInfo.MaximumSizeInBytes / 1MB, 0) } else { "Unknown" }

    # Application & database logs
    $AppErrors = @()
    try { $AppErrors = Get-WinEvent -FilterHashtable @{LogName='Application'; Level=1,2; StartTime=(Get-Date).AddDays(-30)} -MaxEvents 5 -EA SilentlyContinue } catch {}
    $AppErrorSummary = Format-EventSummary $AppErrors
    $DatabaseEvents = @()
    try {
        $DatabaseEvents = Get-WinEvent -FilterHashtable @{LogName='Application'; Level=2,3; StartTime=(Get-Date).AddDays(-30)} -MaxEvents 5 -EA SilentlyContinue | Where-Object { $_.ProviderName -match 'MSSQL|SQL' }
    } catch {}
    $DatabaseErrorSummary = Format-EventSummary $DatabaseEvents
    $PerformanceEvents = @()
    try { $PerformanceEvents = Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2; StartTime=(Get-Date).AddDays(-30)} -MaxEvents 5 -EA SilentlyContinue } catch {}
    $PerformanceSummary = Format-EventSummary $PerformanceEvents

    # Repeating critical/log entries (warnings/errors/critical) in last 30 days
    Log "Analyzing event logs..."
    [System.Windows.Forms.Application]::DoEvents()
    $EventFilters = @{ LogName = 'System','Application','Security'; Level = 1,2,3; StartTime = (Get-Date).AddDays(-30) }
    $RecentEventEntries = @()
    try { $RecentEventEntries = Get-WinEvent -FilterHashtable $EventFilters -MaxEvents 100 -EA SilentlyContinue } catch {}
    $RepeatedEvents = @()
    if ($RecentEventEntries) {
        $RepeatedEvents = $RecentEventEntries | Group-Object { "$($_.ProviderName)|$($_.Id)|$($_.Level)" } | Where-Object { $_.Count -gt 1 }
    }
    if ($RepeatedEvents) {
        $eventRows = $RepeatedEvents | ForEach-Object {
            $sample = $_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1
            $levelName = switch ($sample.Level) { 1 { 'Critical' } 2 { 'Error' } 3 { 'Warning' } default { "Level $($sample.Level)" } }
            $message = if ($sample.Message) { $sample.Message.Substring(0,[Math]::Min(150,$sample.Message.Length)) } else { 'No message' }
            $message = (Escape-ForHtmlAttr $message)
            "<tr><td>$(Escape-ForHtmlAttr $($sample.ProviderName))</td><td>$($sample.Id)</td><td>$levelName</td><td>$($_.Count)x</td><td>$($sample.TimeCreated.ToString('yyyy-MM-dd'))</td><td>$message</td></tr>"
        }
        $EventsHTML = "<table style='width:100%; font-size:0.85em;'><tr><th>Source</th><th>ID</th><th>Level</th><th>Count</th><th>Last Seen</th><th>Message</th></tr>" + ($eventRows -join '') + "</table>"
    } else {
        $EventsHTML = "No repeating warnings/errors/critical events detected in the last 30 days"
    }
    
    # --- Generate HTML ---
    Log "Generating HTML report..."
    [System.Windows.Forms.Application]::DoEvents()
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Security Audit: $env:COMPUTERNAME</title>
    <style>
        :root { --accent: #0056b3; --good: #27ae60; --warn: #f39c12; --alert: #e74c3c; }
        body { font-family: 'Segoe UI', sans-serif; background: #f4f7f6; color: #2c3e50; padding: 20px; font-size: 12px; line-height: 1.3; }
        h1 { color: var(--accent); border-bottom: 3px solid var(--accent); padding-bottom: 10px; }
        h2 { background: #e8f4f8; color: var(--accent); padding: 10px; border-top: 3px solid var(--accent); margin-top: 30px; }
        h3 { color: var(--accent); border-left: 4px solid var(--accent); padding-left: 10px; }
        table { border-collapse: collapse; width: 100%; background: white; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-bottom: 15px; font-size: 0.85rem; }
        th, td { padding: 10px; border-bottom: 1px solid #ecf0f1; text-align: left; font-size: 0.85rem; }
        th { background: #ecf0f1; width: 40%; font-weight: bold; }
        .alert { color: var(--alert); font-weight: bold; }
        .good { color: var(--good); font-weight: bold; }
        .warn { color: var(--warn); font-weight: bold; }
        .input { border: 1px solid #bdc3c7; padding: 5px; border-radius: 4px; width: 90%; }
        select { border: 1px solid #bdc3c7; padding: 5px; border-radius: 4px; }
        .copy-btn { background: var(--accent); color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; position: fixed; bottom: 30px; right: 30px; }
    </style>
    <script>
        function copyReport() {
            var clone = document.body.cloneNode(true);
            clone.querySelectorAll('.copy-btn').forEach(b => b.remove());
            clone.querySelectorAll('input, select, textarea').forEach(el => {
                var val = el.tagName === 'SELECT' ? el.options[el.selectedIndex]?.text : el.value;
                var span = document.createElement('span');
                span.textContent = val || 'N/A';
                span.style.fontWeight = 'bold';
                el.parentNode.replaceChild(span, el);
            });
            var temp = document.createElement('div');
            temp.style.transform = 'scale(0.75)';
            temp.style.transformOrigin = 'top left';
            temp.style.width = '133%';
            temp.innerHTML = clone.innerHTML;
            document.body.appendChild(temp);
            var range = document.createRange();
            range.selectNodeContents(temp);
            window.getSelection().removeAllRanges();
            window.getSelection().addRange(range);
            document.execCommand('copy');
            document.body.removeChild(temp);
            alert('Report copied to clipboard!');
        }
    </script>
</head>
<body>
<h1>INTERNAL SERVER SECURITY & BACKUP AUDIT FORM</h1>

<p><strong>Client:</strong> <input class='input' style='width:300px;' placeholder='Client name'></p>
<p><strong>Audit Month:</strong> $(Get-Date -Format 'MMMM yyyy')</p>
<p><strong>Completed By:</strong> $env:USERNAME</p>

<h3>Server Identifying Information</h3>
<table>
    <tr><th>Server Name</th><td>$(Escape-ForHtmlAttr $CompInfo.Name)</td></tr>
    <tr><th>Location (onsite/offsite)</th><td><input class='input' value='Onsite (confirm)'></td></tr>
    <tr><th>OS Version</th><td>$($OSInfo.Caption) (Build $($OSInfo.BuildNumber)) ($($OSInfo.OSArchitecture)) $EOSWarning</td></tr>
    <tr><th>Role(s)</th><td><input class='input' value='$(Escape-ForHtmlAttr $DetectedRoles)'></td></tr>
    <tr><th>Who has administrative access</th><td><ul>$AdminList</ul></td></tr>
    <tr><th>Last admin password changes</th><td><input class='input' value='$(Escape-ForHtmlAttr $AdminPasswordSummary)'></td></tr>
    <tr><th>Virtual Machine</th><td>$(if($IsVM){"Yes (Guest - check host RAID/BitLocker)"}else{"No (Physical)"})</td></tr>
</table>

<h2>1. Backup & Data Retention (HIPAA §164.308(a)(7))</h2>
<h3>A. Backup System Review</h3>
<table>
    <tr><th>Backup solution used</th><td><input class='input' value='$(Escape-ForHtmlAttr $DetectedBackup)'></td></tr>
    <tr><th>Are backups completing successfully?</th><td><input class='input' value='$(Escape-ForHtmlAttr $BackupSuccess)'></td></tr>
    <tr><th>Last successful backup date & time</th><td><input class='input' value='$(Escape-ForHtmlAttr $BackupLastSuccess)'></td></tr>
    <tr><th>Backup frequency</th><td><input class='input' value='$(Escape-ForHtmlAttr $BackupFrequency)'></td></tr>
    <tr><th>Are there any failed backups this month?</th><td><input class='input' value='$(Escape-ForHtmlAttr $BackupFailuresThisMonth)'></td></tr>
</table>

<h3>B. Backup Encryption</h3>
<table>
    <tr><th>Are backups encrypted at rest?</th><td><input class='input' value='$(Escape-ForHtmlAttr $BackupsEncrypted)'></td></tr>
    <tr><th>Encryption standard used</th><td><input class='input' value='$(Escape-ForHtmlAttr $BackupEncryptionType)'></td></tr>
    <tr><th>Are backup transfer channels encrypted?</th><td><input class='input' value='$(Escape-ForHtmlAttr $BackupTransferEncrypted)'></td></tr>
</table>

<h3>C. Backup Retention</h3>
<table>
    <tr><th>Retention period</th><td><input class='input' value='$(Escape-ForHtmlAttr $BackupRetention)'></td></tr>
    <tr><th>Does retention meet HIPAA’s 6-year requirement?</th><td><input class='input' value='Unknown (verify documentation)'></td></tr>
</table>

<h3>D. Restore Testing</h3>
<table>
    <tr><th>Was a test restore performed in the last 90 days?</th><td><input class='input' value='Unknown'></td></tr>
    <tr><th>Date of last verification restore</th><td><input class='input' placeholder='YYYY-MM-DD'></td></tr>
    <tr><th>Result</th><td><input class='input' value='Unknown'></td></tr>
</table>

<h2>2. Server Security & Patch Compliance (HIPAA §164.308(a)(1), §164.312(c))</h2>
<h3>A. Update Status</h3>
<table>
    <tr><th>Are Windows Updates current?</th><td>$(if($PendingReboot){"<span class='warn'>Reboot Pending</span>"}else{"<span class='good'>Yes</span>"})</td></tr>
    <tr><th>Last update date</th><td>$LastUpdateDate</td></tr>
    <tr><th>Pending patches?</th><td><input class='input' value='$(Escape-ForHtmlAttr $PatchSummary)'></td></tr>
</table>

<h3>B. Antivirus / EDR</h3>
<table>
    <tr><th>AV/EDR installed</th><td>$AVName</td></tr>
    <tr><th>Real-time protection enabled?</th><td>$(if($RTPEnabled -eq 'Yes'){"<span class='good'>Yes</span>"}else{"<span class='alert'>No</span>"})</td></tr>
    <tr><th>Last scan date</th><td>$LastScan</td></tr>
    <tr><th>Any detections this month?</th><td><input class='input' placeholder='Attach or summarize if yes'></td></tr>
</table>

<h3>C. Local User Accounts</h3>
<table>
    <tr><th>List all local server accounts</th><td><input class='input' value='$(Escape-ForHtmlAttr $LocalUsers)'></td></tr>
    <tr><th>Any accounts without MFA?</th><td><input class='input' value='$(Escape-ForHtmlAttr $MfaStatus)'></td></tr>
    <tr><th>Any disabled but unremoved accounts?</th><td><input class='input' value='$(Escape-ForHtmlAttr $DisabledAdminList)'></td></tr>
    <tr><th>Any unexpected accounts?</th><td><input class='input' value='Review local account list'></td></tr>
</table>

<h3>D. Administrator Access</h3>
<table>
    <tr><th>Who has administrative credentials</th><td><input class='input' value='$(Escape-ForHtmlAttr $AdminAccessSummary)'></td></tr>
    <tr><th>Are admin passwords changed regularly?</th><td><input class='input' value='$(Escape-ForHtmlAttr $AdminPasswordSummary)'></td></tr>
    <tr><th>Is password complexity enforced?</th><td><input class='input' value='$(Escape-ForHtmlAttr $PassComplex)'></td></tr>
    <tr><th>Password policy details</th><td><input class='input' value='$(Escape-ForHtmlAttr $PasswordPolicySummary)'></td></tr>
    <tr><th>Are there any shared admin accounts?</th><td><input class='input' value='Unknown (review team accounts)'></td></tr>
</table>

<h2>3. Server Encryption (HIPAA §164.312(a)(2)(iv))</h2>
<h3>A. Disk Encryption</h3>
<table>
    <tr><th>Is full-disk encryption enabled?</th><td>$(if($BitLockerStatus -eq 'Encrypted'){"<span class='good'>Yes (BitLocker)</span>"}else{"<span class='warn'>$BitLockerStatus</span>"})</td></tr>
    <tr><th>Encryption status</th><td>$BitLockerStatus</td></tr>
    <tr><th>TPM present/enabled</th><td>$TpmStatus</td></tr>
    <tr><th>If not encrypted, reason why</th><td><input class='input' value='$(Escape-ForHtmlAttr (if($IsVM){"Virtual Machine"}{"Verify host encryption"}))'></td></tr>
</table>

<h3>B. Data Encryption</h3>
<table>
    <tr><th>Are ChiroTouch data files stored in encrypted form?</th><td><input class='input' value='Unknown'></td></tr>
    <tr><th>Are database backups encrypted?</th><td><input class='input' value='$(Escape-ForHtmlAttr $BackupsEncrypted)'></td></tr>
</table>

<h2>4. Server Firewall & Network Security (HIPAA §164.312(e))</h2>
<h3>A. Local Firewall</h3>
<table>
    <tr><th>Windows Firewall enabled?</th><td>$(if($FWProfiles -ne 'DISABLED'){"<span class='good'>Enabled ($FWProfiles)</span>"}else{"<span class='alert'>DISABLED</span>"})</td></tr>
    <tr><th>Inbound rule review</th><td><textarea class='input' rows='2' placeholder='List allowed inbound ports'></textarea></td></tr>
    <tr><th>Outbound rule review</th><td><textarea class='input' rows='2' placeholder='Confirm non-essential ports are blocked'></textarea></td></tr>
    <tr><th>Open Ports</th><td style='font-size:0.85em;'>$(Escape-ForHtmlAttr $OpenPorts)</td></tr>
</table>

<h3>B. Remote Access</h3>
<table>
    <tr><th>Does anyone RDP to the server?</th><td>$(if($RDPStatus -eq 'Enabled'){"<span class='warn'>Yes</span>"}else{"<span class='good'>No</span>"})</td></tr>
    <tr><th>If yes: Is RDP protected by VPN?</th><td><input class='input' value='Unknown'></td></tr>
    <tr><th>MFA required?</th><td><input class='input' value='Unknown'></td></tr>
    <tr><th>External RDP open to internet?</th><td><input class='input' value='No (verify firewall)'></td></tr>
    <tr><th>Any failed RDP attempts this month?</th><td><input class='input' value='$(Escape-ForHtmlAttr $RdpFailureNotes)'></td></tr>
</table>

<h2>5. Server Monitoring & Logs (HIPAA §164.312(b))</h2>
<h3>A. Event Logs</h3>
<table>
    <tr><th>Security logs enabled?</th><td><input class='input' value='$(Escape-ForHtmlAttr $SecurityLogsEnabled)'></td></tr>
    <tr><th>Retention period (in days)</th><td><input class='input' value='Log max size: $SecurityLogSizeMB MB (per policy)'></td></tr>
    <tr><th>Any critical events found this month?</th><td>$EventsHTML</td></tr>
</table>

<h3>B. Application Logs</h3>
<table>
    <tr><th>Any application errors?</th><td><input class='input' value='$(Escape-ForHtmlAttr $AppErrorSummary)'></td></tr>
    <tr><th>Any database errors?</th><td><input class='input' value='$(Escape-ForHtmlAttr $DatabaseErrorSummary)'></td></tr>
    <tr><th>Any performance concerns logged?</th><td><input class='input' value='$(Escape-ForHtmlAttr $PerformanceSummary)'></td></tr>
</table>

<h3>C. Huntress / EDR Logs</h3>
<table>
    <tr><th>Any incidents detected on the server?</th><td><input class='input' value='Unknown (check EDR console)'></td></tr>
</table>

<h2>6. Physical Security (HIPAA §164.310)</h2>
<h3>A. Server Location</h3>
<table>
    <tr><th>Where is the server physically located?</th><td><input class='input' value='Onsite (rack/closet)'></td></tr>
    <tr><th>Is the room locked?</th><td><input class='input' value='Yes'></td></tr>
    <tr><th>Who has physical access?</th><td><input class='input' value='Facilities, Polar Nite IT'></td></tr>
    <tr><th>Any environmental risks?</th><td><input class='input' value='Unknown'></td></tr>
</table>

<h2>7. Contingency & Failover (HIPAA §164.308(a)(7)(ii)(C))</h2>
<h3>A. Disaster Recovery</h3>
<table>
    <tr><th>If the server failed, how would be restored?</th><td><input class='input' value='Bare metal restore / documented recovery plan'></td></tr>
    <tr><th>Estimated recovery time (RTO)</th><td><input class='input' value='Estimate required'></td></tr>
    <tr><th>Are offsite backups present?</th><td><input class='input' value='$(Escape-ForHtmlAttr $OffsiteCopy)'></td></tr>
</table>

<h3>B. Redundancy</h3>
<table>
    <tr><th>RAID status</th><td><input class='input' value='$(Escape-ForHtmlAttr $RAIDStatus)'></td></tr>
    <tr><th>Storage warnings</th><td>$(if($StorageWarn){"<span class='alert'>$StorageWarn</span>"}{"<span class='good'>None ($FreePct% free)</span>"})</td></tr>
    <tr><th>Drive SMART status</th><td><input class='input' value='$(Escape-ForHtmlAttr $DiskHealth)'></td></tr>
    <tr><th>Physical drives</th><td><input class='input' value='$(Escape-ForHtmlAttr $PhysicalDriveInfo)'></td></tr>
</table>

<h2>8. Server Exceptions (Anything Not Compliant)</h2>
<table>
    <tr><th>Description of issue</th><th>Safeguard</th><th>Risk rating</th><th>Owner</th><th>Status</th><th>Notes</th></tr>
    <tr>
        <td><textarea class='input' rows='2'></textarea></td>
        <td><input class='input'></td>
        <td><select><option>Low</option><option>Moderate</option><option>High</option></select></td>
        <td><select><option>Polar Nite IT</option><option>Client</option></select></td>
        <td><select><option>Planned</option><option>In Progress</option><option>Not Scheduled</option></select></td>
        <td><textarea class='input' rows='2'></textarea></td>
    </tr>
</table>

<button class='copy-btn' onclick='copyReport()'>Copy Report</button>
<p style='text-align:center; margin-top:50px; color:#95a5a6; font-size:0.8em;'>WinFix Polar Nite Audit v2.1</p>
</body>
</html>
"@


    # Save and open
    $reportPath = "$env:TEMP\SecurityAudit_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd_HHmm').html"
    $html | Out-File -FilePath $reportPath -Encoding UTF8
    Invoke-Item $reportPath
    
    Log "Audit report saved to $reportPath"
    $this.Text = "Generate Audit Report"
    $this.Enabled = $true
    [System.Windows.Forms.MessageBox]::Show("Audit report opened in browser.`n`nFile saved to:`n$reportPath", "Audit Complete", "OK", "Information")
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

function Get-SecPolValue {
    param([string[]]$Lines, [string]$Key)
    if (-not $Lines) { return $null }
    foreach ($line in $Lines) {
        if ($line -match "^\s*$Key\s*=\s*(.+)$") {
            return $matches[1].Trim()
        }
    }
    return $null
}

function Escape-ForHtmlAttr {
    param([string]$Value)
    if (-not $Value) { return "" }
    return ($Value -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' -replace "'","&#39;")
}

function Format-EventSummary {
    param([array]$Events)
    if (-not $Events) { return "None detected in the last 30 days" }
    return ($Events | ForEach-Object { "$($_.ProviderName) (#$($_.Id))" }) -join "; "
}

# --- Assemble Form ---
$form.Controls.Add($panelContent)
$form.Controls.Add($panelLog)
$form.Controls.Add($panelNav)
$form.Controls.Add($panelHeader)

# --- Initialize ---
$form.Add_Shown({
    Show-Page "Dashboard"
    Log "WinFix Tool v2.1.1 (Server 2012 R2 Fixed) ready - click Refresh to scan"
})

[void]$form.ShowDialog()
