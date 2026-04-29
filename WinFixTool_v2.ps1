<#
.SYNOPSIS
    WinFix Tool v5.3 - Max Audit Engine
    BUILD: 2026-04-29-FIXED
.DESCRIPTION
    - HIPAA-oriented Max Audit HTML report for MSP monthly reviews.
    - Robust Copy-to-Clipboard Engine (Freshdesk/Ninja ticket optimized).
    - Expanded detection for agents, remote access tools, and backup products using Registry, Services, Processes, and common paths.
    - Captures BitLocker, drives, updates, event logs, shares, printers, RDP, scheduled tasks, support lifecycle, and system specs.
    - PS 5.1 & Server 2012+ compatible syntax (no ternary operators).
#>

$ErrorActionPreference = 'Continue'

# --- STA Check ---
try {
    if ([System.Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
        $self = $PSCommandPath
        if ($self -and (Test-Path $self)) {
            Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -STA -File `"$self`"" -WindowStyle Normal
            exit
        }
    }
} catch { }

# --- Elevation check ---
$script:IsElevated = $false
try {
    $wid = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $wp  = New-Object System.Security.Principal.WindowsPrincipal($wid)
    $script:IsElevated = $wp.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {}

Add-Type -AssemblyName System.Windows.Forms, System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# --- Theme ---
$script:Theme = @{
    Bg      = [System.Drawing.Color]::FromArgb(18, 18, 24)
    Surface = [System.Drawing.Color]::FromArgb(26, 27, 38)
    Card    = [System.Drawing.Color]::FromArgb(36, 37, 51)
    Text    = [System.Drawing.Color]::FromArgb(237, 237, 245)
    Accent  = [System.Drawing.Color]::FromArgb(99, 102, 241)
    Green   = [System.Drawing.Color]::FromArgb(34, 197, 94)
    Red     = [System.Drawing.Color]::FromArgb(239, 68, 68)
}

# --- Logging ---
function Log {
    param([string]$Message)
    $ts = (Get-Date).ToString('HH:mm:ss')
    if ($script:txtLog) {
        $script:txtLog.AppendText("[$ts] $Message`r`n")
        $script:txtLog.SelectionStart = $script:txtLog.Text.Length; $script:txtLog.ScrollToCaret()
    }
}

# --- Background Job Management ---
$script:CurrentJob = $null
$script:JobTimer = New-Object System.Windows.Forms.Timer
$script:JobTimer.Interval = 500
$script:JobTimer.Add_Tick({
    if ($script:CurrentJob) {
        $res = Receive-Job -Job $script:CurrentJob
        foreach ($l in $res) { if ($l) { Log $l } }
        if ($script:CurrentJob.State -ne 'Running') {
            $script:JobTimer.Stop()
            $script:btnAudit.Enabled = $true; $script:btnAudit.Text = "GENERATE MASTER AUDIT"
            $latest = Get-ChildItem "$env:TEMP\WinFix_MaxAudit_*.html" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($latest) { Invoke-Item $latest.FullName }
            Remove-Job $script:CurrentJob -Force; $script:CurrentJob = $null
        }
    }
})

# --- Main Form ---
$form = New-Object System.Windows.Forms.Form
$form.Text = "WinFix Master Auditor v5.3"; $form.Size = New-Object System.Drawing.Size(900, 650)
$form.BackColor = $script:Theme.Bg; $form.ForeColor = $script:Theme.Text
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)

# --- Layout ---
$panelHeader = New-Object System.Windows.Forms.Panel
$panelHeader.Dock = "Top"; $panelHeader.Height = 45; $panelHeader.BackColor = $script:Theme.Surface
$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = "WINFIX MASTER AUDITOR v5.3"; $lblTitle.Location = New-Object System.Drawing.Point(15, 12); $lblTitle.AutoSize = $true
$lblTitle.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold); $lblTitle.ForeColor = $script:Theme.Accent
$panelHeader.Controls.Add($lblTitle)

$panelNav = New-Object System.Windows.Forms.Panel
$panelNav.Dock = "Left"; $panelNav.Width = 130; $panelNav.BackColor = $script:Theme.Surface
$panelContent = New-Object System.Windows.Forms.Panel
$panelContent.Dock = "Fill"; $panelContent.BackColor = $script:Theme.Bg

$panelLog = New-Object System.Windows.Forms.Panel
$panelLog.Dock = "Bottom"; $panelLog.Height = 120; $panelLog.BackColor = $script:Theme.Surface
$script:txtLog = New-Object System.Windows.Forms.TextBox
$script:txtLog.Multiline=$true; $script:txtLog.ReadOnly=$true; $script:txtLog.Dock="Fill"; $script:txtLog.BackColor=[System.Drawing.Color]::Black; $script:txtLog.ForeColor=$script:Theme.Green
$script:txtLog.Font=New-Object System.Drawing.Font("Consolas", 8); $script:txtLog.ScrollBars="Vertical"
$panelLog.Controls.Add($script:txtLog)

$pages = @{}; $navButtons = @()

function New-StubPage {
    param([string]$Title)
    $p = New-Object System.Windows.Forms.Panel
    $p.Dock = "Fill"; $p.BackColor = $script:Theme.Bg
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = "$Title — not implemented in this release"
    $lbl.AutoSize = $true; $lbl.ForeColor = $script:Theme.Text
    $lbl.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $lbl.Location = New-Object System.Drawing.Point(20, 20)
    $p.Controls.Add($lbl); return $p
}
foreach ($n in @("Dashboard", "Quick Fix", "Diagnostics", "Network")) { $pages[$n] = New-StubPage $n }

function Show-Page {
    param($n)
    $panelContent.Controls.Clear(); $panelContent.Controls.Add($pages[$n])
    foreach($b in $navButtons){ $b.BackColor = if($b.Tag -eq $n){$script:Theme.Accent}else{$script:Theme.Card} }
}
foreach($n in @("Dashboard", "Quick Fix", "Diagnostics", "Network", "Audit")){
    $b = New-Object System.Windows.Forms.Button
    $b.Text=$n; $b.Location=New-Object System.Drawing.Point(5, ($navButtons.Count * 36 + 5)); $b.Size=New-Object System.Drawing.Size(120, 32); $b.FlatStyle="Flat"; $b.Tag=$n
    $b.Add_Click({ Show-Page $this.Tag }); $panelNav.Controls.Add($b); $navButtons += $b
}

# === BACKGROUND AUDIT SCRIPT ===
$script:AuditScript = {
    param($ComputerName, $UserName, $TempPath)

    $script:_HKN = 0
    function New-HKey { $script:_HKN++; return "k$script:_HKN" }

    function Log-Worker { param([string]$Message) Write-Output $Message }
    function Escape-Html {
        param($Value)
        if ($null -eq $Value) { return "" }
        return ([string]$Value) -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' -replace "'",'&#39;'
    }
    function Get-SafeCim {
        param([string]$ClassName, [string]$Namespace = "root\cimv2", [string]$Filter = "")
        try {
            if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
                if ($Filter) { return Get-CimInstance -Namespace $Namespace -ClassName $ClassName -Filter $Filter -ErrorAction Stop }
                return Get-CimInstance -Namespace $Namespace -ClassName $ClassName -ErrorAction Stop
            }
            if ($Filter) { return Get-WmiObject -Namespace $Namespace -Class $ClassName -Filter $Filter -ErrorAction Stop }
            return Get-WmiObject -Namespace $Namespace -Class $ClassName -ErrorAction Stop
        } catch { return $null }
    }
    function New-Badge {
        param([string]$Text, [string]$State)
        $class = "badge-info"
        if ($State -eq "Good") { $class = "badge-good" }
        if ($State -eq "Bad")  { $class = "badge-bad" }
        if ($State -eq "Warn") { $class = "badge-warn" }
        return "<span class='badge $class'>$(Escape-Html $Text)</span>"
    }
    function New-Input {
        param([string]$Value = "", [string]$Placeholder = "Enter details")
        $key = New-HKey
        return "<input class='field' type='text' data-key='$key' value='$(Escape-Html $Value)' placeholder='$(Escape-Html $Placeholder)'>"
    }
    function New-TextArea {
        param([string]$Value = "", [string]$Placeholder = "Enter notes")
        $key = New-HKey
        return "<textarea class='field area' data-key='$key' placeholder='$(Escape-Html $Placeholder)'>$(Escape-Html $Value)</textarea>"
    }
    function New-Select {
        param([string[]]$Options = @("Select...", "Yes", "No", "N/A"), [string]$Selected = "")
        $key = New-HKey
        $html = "<select class='field select' data-key='$key'>"
        foreach ($opt in $Options) {
            $sel = if ($opt -eq $Selected) { " selected" } else { "" }
            $html += "<option$sel>$(Escape-Html $opt)</option>"
        }
        return $html + "</select>"
    }
    function Get-TableOrEmpty {
        param([string]$Rows, [string]$Empty = "No items detected.")
        if ([string]::IsNullOrWhiteSpace($Rows)) { return "<tr><td colspan='8' class='empty'>$(Escape-Html $Empty)</td></tr>" }
        return $Rows
    }
    function Get-RegistryEvidence {
        param([string[]]$Patterns)
        $hits = @()
        $paths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SYSTEM\CurrentControlSet\Services\*",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        foreach ($path in $paths) {
            try {
                foreach ($item in (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue)) {
                    $hay = "$($item.DisplayName) $($item.PSChildName) $($item.Publisher) $($item.InstallLocation)"
                    foreach ($pattern in $Patterns) {
                        if ($hay -match [regex]::Escape($pattern)) {
                            $label = $item.DisplayName
                            if (-not $label) { $label = $item.PSChildName }
                            if ($label) { $hits += "Registry: $label" }
                        }
                    }
                }
            } catch {}
        }
        return $hits
    }
    function Find-Tool {
        param([string]$Name, [string[]]$Patterns, [string[]]$Paths = @())
        $evidence = @()
        try {
            $services = Get-Service -ErrorAction SilentlyContinue | Where-Object {
                $svcText = "$($_.Name) $($_.DisplayName)"
                $matched = $false
                foreach ($pattern in $Patterns) { if ($svcText -match [regex]::Escape($pattern)) { $matched = $true } }
                $matched
            }
            foreach ($svc in $services) { $evidence += "Service: $($svc.DisplayName) [$($svc.Status)]" }
        } catch {}
        try {
            $processes = Get-Process -ErrorAction SilentlyContinue | Where-Object {
                $procText = "$($_.ProcessName) $($_.Path)"
                $matched = $false
                foreach ($pattern in $Patterns) { if ($procText -match [regex]::Escape($pattern)) { $matched = $true } }
                $matched
            }
            foreach ($proc in $processes) { $evidence += "Process: $($proc.ProcessName)" }
        } catch {}
        $evidence += Get-RegistryEvidence -Patterns $Patterns
        foreach ($path in $Paths) {
            try { if (Test-Path $path) { $evidence += "Path: $path" } } catch {}
        }
        $evidence = @($evidence | Where-Object { $_ } | Sort-Object -Unique)
        return New-Object PSObject -Property @{
            Name = $Name
            Detected = ($evidence.Count -gt 0)
            Evidence = $evidence
        }
    }
    function Get-OsSupportStatus {
        param($OSInfo)
        $build = 0
        [int]::TryParse([string]$OSInfo.BuildNumber, [ref]$build) | Out-Null
        $caption = [string]$OSInfo.Caption
        $today = Get-Date
        $eosTable = @{
            3790=[datetime]'2015-07-14'; 6002=[datetime]'2020-01-14'; 7601=[datetime]'2020-01-14'
            9200=[datetime]'2023-10-10'; 9600=[datetime]'2023-10-10'
            10240=[datetime]'2017-05-09'; 10586=[datetime]'2017-10-10'
            14393=[datetime]'2027-01-12'; 15063=[datetime]'2018-10-09'; 16299=[datetime]'2019-04-09'
            17134=[datetime]'2019-11-12'; 17763=[datetime]'2029-01-09'
            18362=[datetime]'2020-12-08'; 18363=[datetime]'2022-05-10'
            19041=[datetime]'2021-12-14'; 19042=[datetime]'2023-05-09'; 19043=[datetime]'2022-12-13'
            19044=[datetime]'2024-06-11'; 19045=[datetime]'2025-10-14'
            20348=[datetime]'2031-10-14'
            22000=[datetime]'2023-10-10'; 22621=[datetime]'2024-10-08'; 22631=[datetime]'2025-11-11'
            26100=[datetime]'2034-10-10'
        }
        $state = "Warn"
        $label = "$caption (build $build) — verify at aka.ms/WindowsLifecycle"
        if ($eosTable.ContainsKey($build)) {
            $endDate = $eosTable[$build]
            if ($today -le $endDate) {
                $months = [math]::Round(($endDate - $today).TotalDays / 30)
                $label = "$caption (build $build) — supported until $($endDate.ToString('yyyy-MM-dd')) ($months months remaining)"
                $state = if ($months -le 6) { "Warn" } else { "Good" }
            } else {
                $label = "$caption (build $build) — END OF SUPPORT $($endDate.ToString('yyyy-MM-dd'))"
                $state = "Bad"
            }
        }
        return New-Object PSObject -Property @{ Text = $label; State = $state }
    }

    try {
        Log-Worker "Max Audit: collecting operating system, hardware, and PowerShell details..."
        $OS = Get-SafeCim Win32_OperatingSystem
        $CS = Get-SafeCim Win32_ComputerSystem
        $BIOS = Get-SafeCim Win32_BIOS
        $CPU = Get-SafeCim Win32_Processor | Select-Object -First 1
        $OSSupport = Get-OsSupportStatus -OSInfo $OS
        $PSVer = $PSVersionTable.PSVersion.ToString()
        $Uptime = $null
        if ($OS -and $OS.LastBootUpTime) { $Uptime = (Get-Date) - $OS.LastBootUpTime }
        $UptimeText = "Unknown"
        if ($Uptime) { $UptimeText = "{0} days, {1} hours" -f $Uptime.Days, $Uptime.Hours }
        $IsVM = ($CS.Model -match "Virtual|VMware|KVM|VirtualBox|HVM|Hyper-V|VRTUAL|vbox" -or $CS.Manufacturer -match "VMware|Xen|QEMU|Microsoft Corporation|Parallels|innotek")

        $WinKey = "Not Found"
        try { $WinKey = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform" -ErrorAction Stop).BackupProductKeyDefault } catch {}

        Log-Worker "Max Audit: scanning RMM, EDR, remote access, and backup products..."
        $AgentTools = @(
            (Find-Tool "NinjaRMM" @("NinjaRMM", "NinjaRM", "NinjaOne", "NinjaRemote") @("$env:ProgramFiles\NinjaRMMAgent", "${env:ProgramFiles(x86)}\NinjaRMMAgent")),
            (Find-Tool "Huntress" @("Huntress", "HuntressAgent") @("$env:ProgramFiles\Huntress", "${env:ProgramFiles(x86)}\Huntress")),
            (Find-Tool "GoToAssist" @("GoToAssist", "GoTo Resolve", "g2ax", "GoTo Opener") @("$env:ProgramFiles\GoToAssist", "${env:ProgramFiles(x86)}\GoToAssist"))
        )
        $RemoteTools = @(
            (Find-Tool "TeamViewer" @("TeamViewer") @("$env:ProgramFiles\TeamViewer", "${env:ProgramFiles(x86)}\TeamViewer")),
            (Find-Tool "AnyDesk" @("AnyDesk") @("$env:ProgramFiles\AnyDesk", "${env:ProgramFiles(x86)}\AnyDesk")),
            (Find-Tool "Splashtop" @("Splashtop", "SRService") @("$env:ProgramFiles\Splashtop", "${env:ProgramFiles(x86)}\Splashtop")),
            (Find-Tool "ConnectWise Control" @("ScreenConnect", "ConnectWise Control") @("${env:ProgramFiles(x86)}\ScreenConnect Client")),
            (Find-Tool "RustDesk" @("RustDesk") @("$env:ProgramFiles\RustDesk", "${env:ProgramFiles(x86)}\RustDesk")),
            (Find-Tool "LogMeIn" @("LogMeIn", "LogMeInRemoteUser") @("$env:ProgramFiles\LogMeIn", "${env:ProgramFiles(x86)}\LogMeIn")),
            (Find-Tool "Chrome Remote Desktop" @("chromoting", "Chrome Remote Desktop") @("${env:ProgramFiles(x86)}\Google\Chrome Remote Desktop"))
        )
        $BackupTools = @(
            (Find-Tool "Synology Active Backup / Hyper Backup" @("Synology", "Active Backup", "Hyper Backup", "Synology Drive") @("$env:ProgramFiles\Synology", "${env:ProgramFiles(x86)}\Synology")),
            (Find-Tool "Veeam" @("Veeam") @("$env:ProgramFiles\Veeam", "${env:ProgramFiles(x86)}\Veeam")),
            (Find-Tool "Datto" @("Datto", "Datto Windows Agent", "ShadowSnap") @("$env:ProgramFiles\Datto", "${env:ProgramFiles(x86)}\Datto")),
            (Find-Tool "Acronis" @("Acronis") @("$env:ProgramFiles\Acronis", "${env:ProgramFiles(x86)}\Acronis")),
            (Find-Tool "Carbonite" @("Carbonite") @("$env:ProgramFiles\Carbonite", "${env:ProgramFiles(x86)}\Carbonite")),
            (Find-Tool "Windows Server Backup" @("wbengine", "Windows Server Backup") @())
        )

        $AgentRows = ""
        foreach ($tool in $AgentTools) {
            $badge = if ($tool.Detected) { New-Badge "Installed" "Good" } else { New-Badge "Not detected" "Bad" }
            $evidence = if ($tool.Detected) { Escape-Html (($tool.Evidence | Select-Object -First 4) -join "; ") } else { "No service, process, registry, or common path match." }
            $AgentRows += "<tr><th>$(Escape-Html $tool.Name)</th><td>$badge<div class='evidence'>$evidence</div></td></tr>"
        }
        $RemoteRows = ""
        foreach ($tool in $RemoteTools) {
            $badge = if ($tool.Detected) { New-Badge "Detected" "Warn" } else { New-Badge "Not detected" "Good" }
            $evidence = if ($tool.Detected) { Escape-Html (($tool.Evidence | Select-Object -First 4) -join "; ") } else { "No local signal found." }
            $RemoteRows += "<tr><th>$(Escape-Html $tool.Name)</th><td>$badge<div class='evidence'>$evidence</div></td></tr>"
        }
        $DetectedBackupTools = @($BackupTools | Where-Object { $_.Detected })
        $BackupRows = ""
        foreach ($tool in $BackupTools) {
            $badge = if ($tool.Detected) { New-Badge "Detected" "Good" } else { New-Badge "Not detected" "Info" }
            $evidence = if ($tool.Detected) { Escape-Html (($tool.Evidence | Select-Object -First 4) -join "; ") } else { "No local signal found." }
            $BackupRows += "<tr><th>$(Escape-Html $tool.Name)</th><td>$badge<div class='evidence'>$evidence</div></td></tr>"
        }
        $BackupSolution = "Not detected"
        $BackupSuccess = "N/A"
        $BackupFailed = "N/A"
        $BackupLast = "N/A"
        $BackupFrequency = "N/A"
        $BackupEncryption = "N/A"
        $BackupTransit = "N/A"
        $BackupRetention = "N/A"
        if ($DetectedBackupTools.Count -gt 0) {
            $BackupSolution = ($DetectedBackupTools | ForEach-Object { $_.Name }) -join "; "
            $BackupSuccess = "Review vendor console"
            $BackupFailed = "Review vendor console"
            $BackupLast = "Review vendor console"
            $BackupFrequency = "Review vendor console"
            $BackupEncryption = "Review vendor console / expected AES-256 where supported"
            $BackupTransit = "Review vendor console / expected TLS"
            $BackupRetention = "Review policy"
        }
        try {
            $WinBackupEvents = Get-WinEvent -LogName "Microsoft-Windows-Backup" -MaxEvents 10 -ErrorAction SilentlyContinue
            $LatestBackupEvent = $WinBackupEvents | Select-Object -First 1
            if ($LatestBackupEvent) {
                if ($DetectedBackupTools.Count -eq 0) { $BackupSolution = "Windows Server Backup event log present" }
                if ($LatestBackupEvent.Id -eq 4) { $BackupSuccess = "Yes"; $BackupFailed = "No" } else { $BackupSuccess = "No"; $BackupFailed = "Yes" }
                $BackupLast = $LatestBackupEvent.TimeCreated.ToString("yyyy-MM-dd HH:mm")
            }
        } catch {}

        Log-Worker "Max Audit: collecting patching, update history, Defender, firewall, and RDP posture..."
        $PendingReboot = $false
        foreach ($rebootKey in @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
            "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations"
        )) { try { if (Test-Path $rebootKey) { $PendingReboot = $true } } catch {} }

        $PendingUpdates = @()
        try {
            $UpdateSession = New-Object -ComObject Microsoft.Update.Session
            $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
            $SearchResult = $UpdateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
            for ($i = 0; $i -lt $SearchResult.Updates.Count; $i++) { $PendingUpdates += $SearchResult.Updates.Item($i).Title }
        } catch { $PendingUpdates += "Unable to query Windows Update COM API: $($_.Exception.Message)" }

        $LastPatchDate = "Unknown"
        $RecentUpdateRows = ""
        try {
            $uSess = New-Object -ComObject Microsoft.Update.Session
            $uSearch = $uSess.CreateUpdateSearcher()
            $uCount = $uSearch.GetTotalHistoryCount()
            if ($uCount -gt 0) {
                $uHist = $uSearch.QueryHistory(0, [math]::Min($uCount, 50))
                $uInstalled = @(for ($ui = 0; $ui -lt $uHist.Count; $ui++) { if ($uHist.Item($ui).ResultCode -eq 2) { $uHist.Item($ui) } }) | Sort-Object Date -Descending
                if ($uInstalled.Count -gt 0) {
                    $LastPatchDate = $uInstalled[0].Date.ToString('yyyy-MM-dd')
                    foreach ($uh in ($uInstalled | Select-Object -First 12)) {
                        $uhTitle = $uh.Title
                        if ($uhTitle.Length -gt 100) { $uhTitle = $uhTitle.Substring(0, 97) + '...' }
                        $RecentUpdateRows += "<tr><td>$(Escape-Html $uhTitle)</td><td>$(Escape-Html $uh.Date.ToString('yyyy-MM-dd'))</td></tr>"
                    }
                }
            }
        } catch {}
        if ($LastPatchDate -eq "Unknown") {
            try {
                $hfLast = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 1
                if ($hfLast -and $hfLast.InstalledOn) { $LastPatchDate = $hfLast.InstalledOn.ToString('yyyy-MM-dd') }
                if ([string]::IsNullOrWhiteSpace($RecentUpdateRows)) {
                    foreach ($hf in (Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 12)) {
                        $RecentUpdateRows += "<tr><td>$(Escape-Html "$($hf.HotFixID) -- $($hf.Description)")</td><td>$(Escape-Html $hf.InstalledOn)</td></tr>"
                    }
                }
            } catch {}
        }

        $AVText = "Not detected"
        try {
            $AV = Get-SafeCim -Namespace "root\SecurityCenter2" -ClassName "AntivirusProduct"
            if ($AV) { $AVText = (($AV | ForEach-Object { $_.displayName }) -join "; ") }
        } catch {}
        $DefenderText = "Not available"
        if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
            try {
                $Defender = Get-MpComputerStatus -ErrorAction Stop
                $sigAge = "Unknown"
                if ($Defender.AntivirusSignatureLastUpdated) {
                    $ageDays = [math]::Round(((Get-Date) - $Defender.AntivirusSignatureLastUpdated).TotalDays, 1)
                    $sigAge = "$ageDays days ago ($($Defender.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd')))"
                }
                $DefenderText = "Realtime: $($Defender.RealTimeProtectionEnabled); Signatures: $sigAge; Last scan: $($Defender.QuickScanEndTime)"
                if ($AVText -eq "Not detected") { $AVText = "Microsoft Defender" }
            } catch { $DefenderText = "Unable to query Defender: $($_.Exception.Message)" }
        }

        $FirewallText = "Unknown"
        try {
            if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
                $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
                $FirewallText = (($profiles | ForEach-Object { "$($_.Name): $($_.Enabled)" }) -join "; ")
            } else {
                $FirewallText = ((netsh advfirewall show allprofiles state) -join " ")
            }
        } catch {}
        $RDPEnabled = $false
        $RDPText = "Unknown"
        $NlaText = "Unknown"
        try {
            $rdpReg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -ErrorAction Stop
            if ($rdpReg.fDenyTSConnections -eq 0) { $RDPEnabled = $true; $RDPText = "Enabled" } else { $RDPText = "Disabled" }
            $nla = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ErrorAction SilentlyContinue
            if ($nla.UserAuthentication -eq 1) { $NlaText = "Enabled" } else { $NlaText = "Disabled or unknown" }
        } catch {}
        $RDPFailures = 0
        try {
            $failEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-30)} -MaxEvents 500 -ErrorAction SilentlyContinue
            if ($failEvents) {
                $RDPFailures = @($failEvents | Where-Object { try { $_.Properties[8].Value -eq 10 } catch { $false } }).Count
            }
        } catch {}

        Log-Worker "Max Audit: collecting storage, BitLocker, shares, printers, users, and scheduled tasks..."
        $BitLockerRows = ""
        $BitLockerSummary = "Not available"
        try {
            if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
                $blVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
                foreach ($bl in $blVolumes) {
                    $state = if ($bl.ProtectionStatus -eq "On") { "Good" } else { "Bad" }
                    $BitLockerRows += "<tr><td>$(Escape-Html $bl.MountPoint)</td><td>$(New-Badge $bl.ProtectionStatus $state)</td><td>$(Escape-Html $bl.VolumeStatus)</td><td>$(Escape-Html $bl.EncryptionPercentage)%</td></tr>"
                }
                if ($blVolumes) { $BitLockerSummary = (($blVolumes | ForEach-Object { "$($_.MountPoint) $($_.ProtectionStatus)" }) -join "; ") }
            } else {
                $wmiVolumes = Get-SafeCim -Namespace "root\CIMV2\Security\MicrosoftVolumeEncryption" -ClassName "Win32_EncryptableVolume"
                foreach ($vol in $wmiVolumes) {
                    $prot = "Off"
                    if ($vol.ProtectionStatus -eq 1) { $prot = "On" }
                    $state = if ($prot -eq "On") { "Good" } else { "Bad" }
                    $BitLockerRows += "<tr><td>$(Escape-Html $vol.DriveLetter)</td><td>$(New-Badge $prot $state)</td><td>WMI fallback</td><td>N/A</td></tr>"
                }
                if ($wmiVolumes) { $BitLockerSummary = "WMI fallback used" }
            }
        } catch { $BitLockerSummary = "Unable to query BitLocker: $($_.Exception.Message)" }
        if ([string]::IsNullOrWhiteSpace($BitLockerRows)) { $BitLockerRows = "<tr><td colspan='4'>BitLocker details unavailable. On older Server builds this may require optional components or admin rights.</td></tr>" }

        $DriveRows = ""
        $StorageWarning = "None"
        $logicalDisks = Get-SafeCim -ClassName Win32_LogicalDisk -Filter "DriveType=3"
        foreach ($d in $logicalDisks) {
            $sizeGb = 0; $freeGb = 0; $freePct = 0
            if ($d.Size -gt 0) {
                $sizeGb = [math]::Round($d.Size / 1GB, 1)
                $freeGb = [math]::Round($d.FreeSpace / 1GB, 1)
                $freePct = [math]::Round(($d.FreeSpace / $d.Size) * 100, 1)
            }
            $state = "Good"
            if ($freePct -lt 15) { $state = "Bad"; $StorageWarning = "Low disk space detected" }
            elseif ($freePct -lt 25) { $state = "Warn" }
            $DriveRows += "<tr><td>$(Escape-Html $d.DeviceID)</td><td>$sizeGb GB</td><td>$freeGb GB</td><td>$(New-Badge "$freePct% free" $state)</td><td>$(Escape-Html $d.VolumeName)</td></tr>"
        }
        $PhysicalDiskRows = ""
        try {
            if (Get-Command Get-PhysicalDisk -ErrorAction SilentlyContinue) {
                foreach ($pd in (Get-PhysicalDisk -ErrorAction SilentlyContinue)) { $PhysicalDiskRows += "<tr><td>$(Escape-Html $pd.FriendlyName)</td><td>$(Escape-Html $pd.MediaType)</td><td>$(Escape-Html $pd.HealthStatus)</td><td>$(Escape-Html $pd.OperationalStatus)</td></tr>" }
            }
        } catch {}

        $ShareRows = ""
        try {
            if (Get-Command Get-SmbShare -ErrorAction SilentlyContinue) {
                foreach ($s in (Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '\$$' })) { $ShareRows += "<tr><td>$(Escape-Html $s.Name)</td><td>$(Escape-Html $s.Path)</td><td>$(Escape-Html $s.Description)</td></tr>" }
            } else {
                foreach ($s in (Get-SafeCim Win32_Share | Where-Object { $_.Name -notmatch '\$$' })) { $ShareRows += "<tr><td>$(Escape-Html $s.Name)</td><td>$(Escape-Html $s.Path)</td><td>$(Escape-Html $s.Description)</td></tr>" }
            }
        } catch {}
        $PrinterRows = ""
        try {
            if (Get-Command Get-Printer -ErrorAction SilentlyContinue) {
                foreach ($p in (Get-Printer -ErrorAction SilentlyContinue | Where-Object { $_.Shared })) { $PrinterRows += "<tr><td>$(Escape-Html $p.Name)</td><td>$(Escape-Html $p.ShareName)</td><td>$(Escape-Html $p.DriverName)</td></tr>" }
            } else {
                foreach ($p in (Get-SafeCim Win32_Printer | Where-Object { $_.Shared })) { $PrinterRows += "<tr><td>$(Escape-Html $p.Name)</td><td>$(Escape-Html $p.ShareName)</td><td>$(Escape-Html $p.DriverName)</td></tr>" }
            }
        } catch {}

        $IsDC = $false
        try { if ($CS.DomainRole -ge 4) { $IsDC = $true } } catch {}
        $UserRows = ""
        $AdminsList = @()
        try {
            if ($IsDC) {
                $UserRows = "<tr><td colspan='4'>Domain Controller -- local user enumeration skipped. Use Active Directory tools.</td></tr>"
                $AdminsList = @("(Domain Controller -- see Active Directory)")
            } elseif (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
                foreach ($u in (Get-LocalUser -ErrorAction SilentlyContinue)) {
                    $status = if ($u.Enabled) { "Enabled" } else { "Disabled" }
                    $UserRows += "<tr><td>$(Escape-Html $u.Name)</td><td>$status</td><td>$(Escape-Html $u.PasswordLastSet)</td><td>$(Escape-Html $u.LastLogon)</td></tr>"
                }
                $AdminsList = Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
            } else {
                foreach ($u in (Get-SafeCim Win32_UserAccount -Filter "LocalAccount = True")) {
                    $status = if ($u.Disabled) { "Disabled" } else { "Enabled" }
                    $UserRows += "<tr><td>$(Escape-Html $u.Name)</td><td>$status</td><td>WMI fallback</td><td>WMI fallback</td></tr>"
                }
                try { $AdminsList = ([ADSI]"WinNT://$ComputerName/Administrators,group").psbase.Invoke("Members") | ForEach-Object { $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null) } } catch {}
            }
        } catch {}

        $TaskRows = ""
        try {
            if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
                $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike "\Microsoft\*" } | Select-Object -First 30
                foreach ($t in $tasks) { $TaskRows += "<tr><td>$(Escape-Html $t.TaskName)</td><td>$(Escape-Html $t.TaskPath)</td><td>$(Escape-Html $t.State)</td></tr>" }
            } else {
                $csv = schtasks /query /fo csv /v 2>$null | ConvertFrom-Csv
                foreach ($t in ($csv | Where-Object { $_.TaskName -notlike "\Microsoft\*" } | Select-Object -First 30)) { $TaskRows += "<tr><td>$(Escape-Html $t.TaskName)</td><td>Legacy schtasks</td><td>$(Escape-Html $t.Status)</td></tr>" }
            }
        } catch {}

        Log-Worker "Max Audit: collecting network configuration and event-log indicators..."
        $NetworkRows = ""
        try {
            if (Get-Command Get-NetIPConfiguration -ErrorAction SilentlyContinue) {
                foreach ($nic in (Get-NetIPConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.IPv4Address })) {
                    $ips = ($nic.IPv4Address | ForEach-Object { $_.IPAddress }) -join ", "
                    $dns = ($nic.DNSServer.ServerAddresses | Where-Object { $_ }) -join ", "
                    $gw = ($nic.IPv4DefaultGateway.NextHop | Where-Object { $_ }) -join ", "
                    $NetworkRows += "<tr><td>$(Escape-Html $nic.InterfaceAlias)</td><td>$(Escape-Html $ips)</td><td>$(Escape-Html $gw)</td><td>$(Escape-Html $dns)</td></tr>"
                }
            } else {
                foreach ($nic in (Get-SafeCim Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True")) {
                    $NetworkRows += "<tr><td>$(Escape-Html $nic.Description)</td><td>$(Escape-Html ($nic.IPAddress -join ', '))</td><td>$(Escape-Html ($nic.DefaultIPGateway -join ', '))</td><td>$(Escape-Html ($nic.DNSServerSearchOrder -join ', '))</td></tr>"
                }
            }
        } catch {}
        $OpenPortsRows = ""
        try {
            if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
                foreach ($port in (Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Group-Object LocalPort | Sort-Object { [int]$_.Name } | Select-Object -First 40)) { $OpenPortsRows += "<tr><td>TCP/$($port.Name)</td><td>$($port.Count) listener(s)</td></tr>" }
            } else {
                $netstat = netstat -ano -p tcp | Select-String "LISTENING"
                foreach ($line in ($netstat | Select-Object -First 40)) { $OpenPortsRows += "<tr><td colspan='2'>$(Escape-Html $line.Line)</td></tr>" }
            }
        } catch {}
        $EventRows = ""
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName='System','Application'; Level=1,2,3; StartTime=(Get-Date).AddDays(-30)} -MaxEvents 300 -ErrorAction SilentlyContinue
            $groups = $events | Group-Object { "$($_.ProviderName)|$($_.Id)|$($_.LevelDisplayName)" } | Sort-Object Count -Descending | Select-Object -First 20
            foreach ($g in $groups) {
                $sample = $g.Group[0]
                $msg = ""
                if ($sample.Message) { $msg = $sample.Message.Substring(0, [math]::Min($sample.Message.Length, 180)) }
                $EventRows += "<tr><td>$(Escape-Html $sample.LevelDisplayName)</td><td>$(Escape-Html $sample.ProviderName)</td><td>$(Escape-Html $sample.Id)</td><td>$($g.Count)x</td><td>$(Escape-Html $msg)</td></tr>"
            }
        } catch {}

        $PendingUpdatesHtml = ""
        if ($PendingUpdates.Count -gt 0) {
            foreach ($u in ($PendingUpdates | Select-Object -First 20)) { $PendingUpdatesHtml += "<li>$(Escape-Html $u)</li>" }
        } else { $PendingUpdatesHtml = "<li>No pending software updates detected by Windows Update search.</li>" }

        $ReportPath = Join-Path $TempPath "WinFix_MaxAudit_$($ComputerName)_$(Get-Date -Format 'yyyyMMdd_HHmm').html"
        Log-Worker "Max Audit: building professional HIPAA report..."
        $HTML = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>WinFix Max Audit - $(Escape-Html $ComputerName)</title>
<style>
    :root { --ink:#202733; --muted:#667085; --line:#d9e2ec; --panel:#ffffff; --soft:#f6f8fb; --brand:#145c9e; --brand2:#0f766e; --good:#157347; --bad:#b42318; --warn:#b45309; --info:#475467; }
    body { margin:0; padding:24px; background:#edf2f7; color:var(--ink); font-family:"Segoe UI", Arial, sans-serif; font-size:13px; line-height:1.45; }
    .copy-bar { position:sticky; top:0; z-index:999; width:100%; border:0; background:var(--brand); color:white; padding:12px 16px; font-weight:700; cursor:pointer; border-radius:6px; margin-bottom:14px; font-family:inherit; font-size:14px; }
    .copy-bar:hover { background:#0f4a8a; }
    .wrap { max-width:1040px; margin:0 auto; background:var(--panel); border:1px solid var(--line); border-radius:8px; overflow:hidden; box-shadow:0 10px 24px rgba(32,39,51,.08); }
    .hero { background:#12344d; color:#fff; padding:28px 32px; }
    .hero h1 { margin:0 0 8px 0; font-size:24px; letter-spacing:0; }
    .hero .meta { display:grid; grid-template-columns:repeat(4,1fr); gap:10px; margin-top:16px; }
    .metric { background:rgba(255,255,255,.12); border:1px solid rgba(255,255,255,.18); border-radius:6px; padding:10px; }
    .metric b { display:block; font-size:11px; color:#d7e9ff; text-transform:uppercase; margin-bottom:3px; }
    .summary { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; padding:16px 22px; background:#f8fafc; border-bottom:1px solid var(--line); }
    .summary-card { border-left:4px solid var(--brand2); background:white; padding:10px 12px; border-radius:6px; border-top:1px solid var(--line); border-right:1px solid var(--line); border-bottom:1px solid var(--line); }
    .summary-card b { display:block; color:var(--muted); font-size:11px; text-transform:uppercase; }
    .section { padding:20px 24px 4px 24px; }
    .section-head { margin:0 -24px 12px -24px; padding:11px 24px; background:#eaf3fb; border-top:1px solid var(--line); border-bottom:1px solid var(--line); color:var(--brand); font-weight:800; font-size:14px; }
    .subhead { margin:18px 0 8px; color:#344054; font-weight:800; }
    table { width:100%; border-collapse:collapse; margin:0 0 12px 0; background:white; }
    th, td { border:1px solid var(--line); padding:9px 10px; text-align:left; vertical-align:top; }
    th { background:#f8fafc; color:#344054; width:34%; }
    .data th { width:auto; }
    .badge { display:inline-block; border-radius:999px; padding:3px 9px; font-weight:800; font-size:12px; }
    .badge-good { color:var(--good); background:#dcfce7; }
    .badge-bad  { color:var(--bad);  background:#fee4e2; }
    .badge-warn { color:var(--warn); background:#fef3c7; }
    .badge-info { color:var(--info); background:#eef2f6; }
    .evidence { color:var(--muted); font-size:12px; margin-top:5px; }
    .field { box-sizing:border-box; width:100%; border:1px solid #cbd5e1; border-radius:5px; padding:7px 8px; font:inherit; background:#fff; color:#111827; }
    .select { max-width:260px; }
    .area { min-height:58px; resize:vertical; }
    .empty { color:var(--muted); background:#f8fafc; border:1px dashed var(--line); padding:10px; border-radius:6px; }
    ul.compact { margin:0; padding-left:18px; }
    @media (max-width:760px) { body{padding:8px;} .hero .meta,.summary{grid-template-columns:1fr;} th,td{display:block;width:auto;} }
</style>
<script>
function copyForFreshdesk() {
    var report = document.getElementById('report-main');
    var clone = report.cloneNode(true);
    var origMap = {};
    report.querySelectorAll('[data-key]').forEach(function(el) { origMap[el.getAttribute('data-key')] = el; });
    clone.querySelectorAll('[data-key]').forEach(function(clonedEl) {
        var key = clonedEl.getAttribute('data-key');
        var orig = origMap[key];
        var val = 'N/A';
        if (orig) {
            if (orig.tagName === 'SELECT') { val = orig.selectedIndex >= 0 ? orig.options[orig.selectedIndex].text : 'N/A'; }
            else { val = orig.value || 'N/A'; }
        }
        var span = document.createElement('span');
        span.textContent = val;
        span.style.fontWeight = '600';
        if (['No','Failed','Non-Compliant'].indexOf(val) !== -1) { span.style.color = '#b42318'; }
        else if (['Yes','Compliant','Encrypted'].indexOf(val) !== -1) { span.style.color = '#157347'; }
        clonedEl.parentNode.replaceChild(span, clonedEl);
    });
    var html = clone.outerHTML;
    var plain = clone.textContent;
    if (navigator.clipboard && window.ClipboardItem) {
        navigator.clipboard.write([new ClipboardItem({
            'text/html': new Blob([html], {type:'text/html'}),
            'text/plain': new Blob([plain], {type:'text/plain'})
        })]).then(function() {
            alert('Report copied! Paste into your Freshdesk / Ninja ticket note.');
        }).catch(function() { _fallbackCopy(clone); });
        return;
    }
    _fallbackCopy(clone);
}
function _fallbackCopy(clone) {
    var holder = document.createElement('div');
    holder.style.cssText = 'position:fixed;left:-9999px;top:0;';
    holder.appendChild(clone);
    document.body.appendChild(holder);
    var range = document.createRange();
    range.selectNode(clone);
    var sel = window.getSelection();
    sel.removeAllRanges(); sel.addRange(range);
    try { document.execCommand('copy'); alert('Report copied! Paste into your Freshdesk / Ninja ticket note.'); }
    catch(e) { alert('Copy failed -- select the report manually and copy.'); }
    sel.removeAllRanges();
    document.body.removeChild(holder);
}
</script>
</head>
<body>
<button class="copy-bar" onclick="copyForFreshdesk()">Copy Formatted Report for Freshdesk / Ninja Ticket Note</button>
<div id="report-main" class="wrap">
    <div class="hero">
        <h1>Max Audit: $(Escape-Html $ComputerName)</h1>
        <div>HIPAA-oriented MSP monthly audit report generated $(Escape-Html ((Get-Date).ToString("F")))</div>
        <div class="meta">
            <div class="metric"><b>Client</b>$(New-Input "" "Client name")</div>
            <div class="metric"><b>Auditor</b>$(Escape-Html $UserName)</div>
            <div class="metric"><b>Computer</b>$(Escape-Html $ComputerName)</div>
            <div class="metric"><b>Uptime</b>$(Escape-Html $UptimeText)</div>
        </div>
    </div>
    <div class="summary">
        <div class="summary-card"><b>OS Support</b>$(New-Badge $OSSupport.Text $OSSupport.State)</div>
        <div class="summary-card"><b>Backup</b>$(if($DetectedBackupTools.Count -gt 0){New-Badge "Detected" "Good"}else{New-Badge "Not detected" "Bad"})</div>
        <div class="summary-card"><b>RDP</b>$(if($RDPEnabled){New-Badge "Enabled" "Warn"}else{New-Badge "Disabled" "Good"})</div>
        <div class="summary-card"><b>Pending Updates</b>$(if($PendingUpdates.Count -gt 0){New-Badge "$($PendingUpdates.Count) found" "Warn"}else{New-Badge "None found" "Good"})</div>
    </div>

    <div class="section">
        <div class="section-head">System Inventory</div>
        <table>
            <tr><th>Windows version</th><td>$(Escape-Html $OS.Caption) build $(Escape-Html $OS.BuildNumber)</td></tr>
            <tr><th>Support status</th><td>$(New-Badge $OSSupport.Text $OSSupport.State)</td></tr>
            <tr><th>PowerShell version</th><td>$(Escape-Html $PSVer)</td></tr>
            <tr><th>Manufacturer / model</th><td>$(Escape-Html $CS.Manufacturer) / $(Escape-Html $CS.Model) $(if($IsVM){New-Badge "Virtual machine" "Info"}else{New-Badge "Physical/unknown" "Info"})</td></tr>
            <tr><th>Serial / Windows key</th><td>$(Escape-Html $BIOS.SerialNumber) / $(New-Input $WinKey "Windows product key")</td></tr>
            <tr><th>CPU / RAM</th><td>$(Escape-Html $CPU.Name) / $([math]::Round($CS.TotalPhysicalMemory / 1GB, 1)) GB</td></tr>
        </table>
    </div>

    <div class="section">
        <div class="section-head">Agent Status Indicators</div>
        <table>$AgentRows</table>
    </div>

    <div class="section">
        <div class="section-head">Remote Access Scan</div>
        <table>$RemoteRows</table>
        <table>
            <tr><th>Remote Desktop status</th><td>$(if($RDPEnabled){New-Badge "Enabled" "Warn"}else{New-Badge "Disabled" "Good"}) <span class="evidence">NLA: $(Escape-Html $NlaText); RDP logon failures (last 30d): $RDPFailures</span></td></tr>
            <tr><th>MSP review</th><td>$(New-TextArea "" "Confirm remote access is authorized, MFA-protected, and not exposed directly to the internet.")</td></tr>
        </table>
    </div>

    <div class="section">
        <div class="section-head">1. Backup &amp; Data Retention (HIPAA &sect;164.308(a)(7))</div>
        <table>
            <tr><th>Backup solution used</th><td>$(New-Input $BackupSolution "Backup product")</td></tr>
            <tr><th>Detected backup signals</th><td><table class="data"><tr><th>Product</th><th>Status</th></tr>$BackupRows</table></td></tr>
            <tr><th>Are backups completing successfully?</th><td>$(New-Select @("Select...", "Yes", "No", "N/A", "Review vendor console") $BackupSuccess)</td></tr>
            <tr><th>Last successful backup date &amp; time</th><td>$(New-Input $BackupLast "YYYY-MM-DD HH:MM")</td></tr>
            <tr><th>Backup frequency</th><td>$(New-Input $BackupFrequency "Hourly / daily / continuous / N/A")</td></tr>
            <tr><th>Failed backups this month?</th><td>$(New-Select @("Select...", "Yes", "No", "N/A", "Review vendor console") $BackupFailed)</td></tr>
            <tr><th>Encrypted at rest?</th><td>$(New-Input $BackupEncryption "AES-256 preferred or N/A")</td></tr>
            <tr><th>Encrypted in transit?</th><td>$(New-Input $BackupTransit "TLS/SSL or N/A")</td></tr>
            <tr><th>Retention meets HIPAA 6-year documentation need?</th><td>$(New-Input $BackupRetention "Policy / N/A")</td></tr>
            <tr><th>Restore test evidence</th><td>$(New-TextArea "" "Date, item restored, result, and ticket/reference.")</td></tr>
        </table>
    </div>

    <div class="section">
        <div class="section-head">2. Security &amp; User Audit (HIPAA &sect;164.308, &sect;164.312)</div>
        <table>
            <tr><th>AV / EDR installed</th><td>$(Escape-Html $AVText)</td></tr>
            <tr><th>Defender status</th><td>$(Escape-Html $DefenderText)</td></tr>
            <tr><th>Local administrators</th><td>$(New-TextArea (($AdminsList | Sort-Object -Unique) -join ", ") "Admin users/groups")</td></tr>
            <tr><th>Password / MFA notes</th><td>$(New-TextArea "" "Confirm password policy, admin MFA, shared admin accounts, disabled users.")</td></tr>
        </table>
        <div class="subhead">Local user accounts</div>
        <table class="data"><tr><th>User</th><th>Status</th><th>Password last set</th><th>Last logon</th></tr>$(Get-TableOrEmpty $UserRows "No local user data collected.")</table>
    </div>

    <div class="section">
        <div class="section-head">3. Server Encryption (HIPAA &sect;164.312(a)(2)(iv))</div>
        <table>
            <tr><th>BitLocker summary</th><td>$(Escape-Html $BitLockerSummary)</td></tr>
            <tr><th>Volumes</th><td><table class="data"><tr><th>Volume</th><th>Protection</th><th>Status</th><th>Percent</th></tr>$BitLockerRows</table></td></tr>
            <tr><th>Encryption exception / reason</th><td>$(New-TextArea "" "If not encrypted, document VM/storage-layer encryption or business exception.")</td></tr>
        </table>
    </div>

    <div class="section">
        <div class="section-head">4. Network Security (HIPAA &sect;164.312(e))</div>
        <table>
            <tr><th>Windows Firewall</th><td>$(Escape-Html $FirewallText)</td></tr>
            <tr><th>Network adapters</th><td><table class="data"><tr><th>Adapter</th><th>IPv4</th><th>Gateway</th><th>DNS</th></tr>$(Get-TableOrEmpty $NetworkRows "No active network adapters detected.")</table></td></tr>
            <tr><th>Listening TCP ports</th><td><table class="data"><tr><th>Port</th><th>Detail</th></tr>$(Get-TableOrEmpty $OpenPortsRows "Unable to collect listening ports.")</table></td></tr>
            <tr><th>Network review notes</th><td>$(New-TextArea "" "Firewall exceptions, exposed services, VLAN/VPN notes, unusual ports.")</td></tr>
        </table>
    </div>

    <div class="section">
        <div class="section-head">5. MSP Monthly Operations</div>
        <table>
            <tr><th>Pending reboot</th><td>$(if($PendingReboot){New-Badge "Yes - reboot needed" "Warn"}else{New-Badge "No" "Good"})</td></tr>
            <tr><th>Last installed update</th><td>$(Escape-Html $LastPatchDate)</td></tr>
            <tr><th>Pending Windows updates</th><td><ul class="compact">$PendingUpdatesHtml</ul></td></tr>
            <tr><th>Recent installed updates</th><td><table class="data"><tr><th>Update</th><th>Date</th></tr>$(Get-TableOrEmpty $RecentUpdateRows "No update history returned.")</table></td></tr>
            <tr><th>Drive usage</th><td><table class="data"><tr><th>Drive</th><th>Size</th><th>Free</th><th>Free %</th><th>Label</th></tr>$(Get-TableOrEmpty $DriveRows "No fixed disks detected.")</table></td></tr>
            <tr><th>Physical disk health</th><td><table class="data"><tr><th>Disk</th><th>Media</th><th>Health</th><th>Operational</th></tr>$(Get-TableOrEmpty $PhysicalDiskRows "Physical disk health unavailable on this OS.")</table></td></tr>
            <tr><th>Custom scheduled tasks</th><td><table class="data"><tr><th>Name</th><th>Path</th><th>State</th></tr>$(Get-TableOrEmpty $TaskRows "No non-Microsoft scheduled tasks detected.")</table></td></tr>
        </table>
    </div>

    <div class="section">
        <div class="section-head">6. Shares, Printers, and Local Resources</div>
        <table>
            <tr><th>Network shares</th><td><table class="data"><tr><th>Name</th><th>Path</th><th>Description</th></tr>$(Get-TableOrEmpty $ShareRows "No custom shares detected.")</table></td></tr>
            <tr><th>Shared printers</th><td><table class="data"><tr><th>Name</th><th>Share</th><th>Driver</th></tr>$(Get-TableOrEmpty $PrinterRows "No shared printers detected.")</table></td></tr>
        </table>
    </div>

    <div class="section">
        <div class="section-head">7. Monitoring &amp; Event Logs (HIPAA &sect;164.312(b))</div>
        <table>
            <tr><th>Potential issues to review</th><td><table class="data"><tr><th>Level</th><th>Source</th><th>ID</th><th>Count</th><th>Sample</th></tr>$(Get-TableOrEmpty $EventRows "No repeated warnings/errors found in the last 30 days.")</table></td></tr>
            <tr><th>MSP event review notes</th><td>$(New-TextArea "" "Document false positives, remediation taken, and tickets created.")</td></tr>
        </table>
    </div>

    <div class="section">
        <div class="section-head">8. Physical Security &amp; Contingency Planning (HIPAA &sect;164.310, &sect;164.308(a)(7))</div>
        <table>
            <tr><th>Physical location</th><td>$(New-Input "" "Server closet, rack, cloud, workstation desk")</td></tr>
            <tr><th>Room/rack locked?</th><td>$(New-Select)</td></tr>
            <tr><th>UPS / power protection</th><td>$(New-Input "" "UPS present, runtime, battery age")</td></tr>
            <tr><th>Disaster recovery method</th><td>$(New-TextArea "" "Recovery process, RTO/RPO, offsite copy, vendor escalation.")</td></tr>
            <tr><th>Audit exceptions</th><td>$(New-TextArea "" "Non-compliant items, owner, target date, and compensating control.")</td></tr>
        </table>
    </div>
</div>
</body>
</html>
"@
        try {
            [System.IO.File]::WriteAllText($ReportPath, $HTML, (New-Object System.Text.UTF8Encoding($false)))
        } catch {
            $fallbackPath = Join-Path $TempPath "WinFix_MaxAudit_fallback.html"
            try { [System.IO.File]::WriteAllText($fallbackPath, $HTML, (New-Object System.Text.UTF8Encoding($false))); $ReportPath = $fallbackPath } catch {}
        }
        Log-Worker "Audit Complete: $ReportPath"
    } catch {
        Log-Worker "CRITICAL ERROR: $($_.Exception.Message)"
        Log-Worker "Line: $($_.InvocationInfo.ScriptLineNumber)"
    }
}

# --- UI Assembly ---
$pageAudit = New-Object System.Windows.Forms.Panel
$pageAudit.Dock = "Fill"; $pageAudit.BackColor = $script:Theme.Bg

$infoLbl = New-Object System.Windows.Forms.Label
$infoLbl.Text = "Generates a HIPAA-oriented HTML audit report.`nReport opens automatically when complete."
$infoLbl.AutoSize = $true; $infoLbl.ForeColor = $script:Theme.Text
$infoLbl.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$infoLbl.Location = New-Object System.Drawing.Point(250, 160)

$script:btnAudit = New-Object System.Windows.Forms.Button
$script:btnAudit.Text = "GENERATE MASTER AUDIT"
$script:btnAudit.Size = New-Object System.Drawing.Size(300, 50)
$script:btnAudit.Location = New-Object System.Drawing.Point(250, 200)
$script:btnAudit.FlatStyle = "Flat"
$script:btnAudit.BackColor = $script:Theme.Accent
$script:btnAudit.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$script:btnAudit.Add_Click({
    if ($script:CurrentJob) { return }
    $this.Enabled = $false; $this.Text = "SCANNING..."
    $script:CurrentJob = Start-Job -Name "SecurityAudit" -ScriptBlock $script:AuditScript -ArgumentList @($env:COMPUTERNAME, $env:USERNAME, $env:TEMP)
    $script:JobTimer.Start()
})
$pageAudit.Controls.Add($infoLbl)
$pageAudit.Controls.Add($script:btnAudit)

if (-not $script:IsElevated) {
    $warnLbl = New-Object System.Windows.Forms.Label
    $warnLbl.Text = "WARNING: Not running as Administrator. Some checks may return incomplete results."
    $warnLbl.AutoSize = $true; $warnLbl.ForeColor = $script:Theme.Red
    $warnLbl.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $warnLbl.Location = New-Object System.Drawing.Point(250, 260)
    $pageAudit.Controls.Add($warnLbl)
}

$pages["Audit"] = $pageAudit

# --- Initialize ---
$form.Controls.AddRange(@($panelContent, $panelLog, $panelNav, $panelHeader))
$form.Add_Shown({ Show-Page "Audit" })
[void]$form.ShowDialog()
