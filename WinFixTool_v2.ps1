<#
.SYNOPSIS
    WinFix Tool v3.9 - The Ultimate Auditor
    BUILD: 2026-04-30-EXTREME-AUDIT
.DESCRIPTION
    Comprehensive audit adding Remote Access Tools, Network/Printer Shares, 
    and exhaustive security metrics. Fully Freshdesk-optimized.
#>

$ErrorActionPreference = 'Stop'

# --- Elevation & STA Check ---
try {
    if ([System.Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
        $self = $PSCommandPath
        if ($self -and (Test-Path $self)) {
            Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -STA -File `"$self`"" -WindowStyle Normal
            exit
        }
    }
} catch { }

# --- Load Assemblies ---
try {
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
    Add-Type -AssemblyName System.Drawing -ErrorAction Stop
} catch { exit 1 }

[System.Windows.Forms.Application]::EnableVisualStyles()

# --- Theme Configuration ---
$script:Theme = @{
    Bg      = [System.Drawing.Color]::FromArgb(18, 18, 24)
    Surface = [System.Drawing.Color]::FromArgb(26, 27, 38)
    Card    = [System.Drawing.Color]::FromArgb(36, 37, 51)
    Text    = [System.Drawing.Color]::FromArgb(237, 237, 245)
    Accent  = [System.Drawing.Color]::FromArgb(99, 102, 241)
    Green   = [System.Drawing.Color]::FromArgb(34, 197, 94)
    Red     = [System.Drawing.Color]::FromArgb(239, 68, 68)
}

# --- Shared UI Icons ---
$script:StatusPending = "⏳"

# --- Logging ---
$script:LogPath = Join-Path $env:TEMP 'WinFix_Debug.log'
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
            $script:btnAudit.Enabled = $true; $script:btnAudit.Text = "🚀 GENERATE MAX AUDIT"
            $latest = Get-ChildItem "$env:TEMP\WinFix_Audit_*.html" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($latest) { Invoke-Item $latest.FullName }
            Remove-Job $script:CurrentJob; $script:CurrentJob = $null
        }
    }
})

# --- Main Form ---
$form = New-Object System.Windows.Forms.Form
$form.Text = "WinFix Tool v3.9 - The Ultimate Auditor"; $form.Size = New-Object System.Drawing.Size(900, 650)
$form.BackColor = $script:Theme.Bg; $form.ForeColor = $script:Theme.Text
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)

# --- Layout Panels ---
$panelHeader = New-Object System.Windows.Forms.Panel
$panelHeader.Dock = "Top"; $panelHeader.Height = 45; $panelHeader.BackColor = $script:Theme.Surface
$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = "WINFIX AUDIT PRO v3.9"; $lblTitle.Location = New-Object System.Drawing.Point(15, 12); $lblTitle.AutoSize = $true
$lblTitle.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
$lblTitle.ForeColor = $script:Theme.Accent
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
function Show-Page {
    param($n)
    $panelContent.Controls.Clear(); $panelContent.Controls.Add($pages[$n])
    foreach($b in $navButtons){ $b.BackColor = if($b.Tag -eq $n){$script:Theme.Accent}else{$script:Theme.Card} }
}

$navItems = @("Dashboard", "Quick Fix", "Diagnostics", "Network", "Audit")
$navY = 5
foreach($n in @("Dashboard", "Quick Fix", "Diagnostics", "Network", "Audit")){
    $b = New-Object System.Windows.Forms.Button
    $b.Text=$n; $b.Location=New-Object System.Drawing.Point(5, $navY); $b.Size=New-Object System.Drawing.Size(120, 32); $b.FlatStyle="Flat"; $b.Tag=$n
    $b.Add_Click({ Show-Page $this.Tag }); $panelNav.Controls.Add($b); $navButtons += $b; $navY += 36
}

# === BACKGROUND AUDIT SCRIPT ===
$script:AuditScript = {
    param($ComputerName, $UserName, $TempPath)
    function Log-Worker($msg) { Write-Output $msg }
    function Escape-Html($v) { if($v){$v -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;'}else{""} }

    Log-Worker "Gathering Identity & Product Key..."
    $BIOS = Get-CimInstance Win32_Bios
    $WinKey = "Not Found"
    try { $WinKey = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform").BackupProductKeyDefault } catch {}

    Log-Worker "Scanning for Remote Access Tools..."
    $RATKeywords = @("TeamViewer", "AnyDesk", "LogMeIn", "ScreenConnect", "Ninja", "Splashtop", "BeyondTrust", "GoToMyPC", "RealVNC", "UltraVNC", "RustDesk", "ConnectWise", "N-able", "Atera", "Kaseya")
    $FoundRATs = Get-Service | Where-Object { $d = $_.DisplayName; $RATKeywords | Where-Object { $d -like "*$_*" } }
    $RATText = if($FoundRATs){ ($FoundRATs.DisplayName | Sort-Object -Unique) -join "; " } else { "None Detected" }

    Log-Worker "Enumerating Shares & Printers..."
    $Shares = Get-SmbShare | Where-Object { $_.Name -notmatch "\$" }
    $ShareRows = ""; foreach($s in $Shares){ $ShareRows += "<tr><td>$($s.Name)</td><td>$($s.Path)</td></tr>" }
    $Printers = Get-Printer | Where-Object Shared
    $PrinterRows = ""; foreach($p in $Printers){ $PrinterRows += "<tr><td>$($p.Name)</td><td>$($p.ShareName)</td></tr>" }

    Log-Worker "Analyzing Password Policies..."
    $secFile = "$TempPath\secpol.cfg"; secedit /export /cfg $secFile /quiet
    $secPol = Get-Content $secFile; Remove-Item $secFile -EA SilentlyContinue
    function Get-Pol($k) { if($secPol -match "$k\s*=\s*(\d+)") { $matches[1] } else { "Unknown" } }
    $MinLen = Get-Pol "MinimumPasswordLength"; $MaxAge = Get-Pol "MaximumPasswordAge"

    Log-Worker "Auditing Users..."
    $Users = Get-LocalUser | Select-Object Name, Enabled, PasswordExpired, PasswordLastSet
    $UserRows = ""; foreach($u in $Users) { 
        $st = if($u.Enabled){"Active"}else{"Disabled"}
        $UserRows += "<tr><td>$($u.Name)</td><td>$st</td><td>$($u.PasswordLastSet)</td></tr>" 
    }
    $Admins = (Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name) -join ", "

    Log-Worker "Pulling Performance Stats..."
    $OS = Get-CimInstance Win32_OperatingSystem; $CS = Get-CimInstance Win32_ComputerSystem
    $DiskRows = ""; foreach($d in (Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3")) {
        $DiskRows += "<tr><td>$($d.DeviceID)</td><td>$([math]::Round($d.Size/1GB,1)) GB</td><td>$([math]::Round($d.FreeSpace/1GB,1)) GB</td></tr>"
    }

    Log-Worker "Detecting Backups (Synology/Veeam)..."
    $BKeywords = @("Veeam","Acronis","Datto","Carbonite","Backblaze","Synology","Active Backup")
    $fB = Get-Service | Where-Object { $d = $_.DisplayName; $BKeywords | Where-Object { $d -like "*$_*" } }
    $BText = if($fB){($fB.DisplayName | Sort-Object -Unique) -join "; "}else{"Not Detected"}

    Log-Worker "Building v3.9 Extreme HTML Report..."
    $ReportPath = Join-Path $TempPath "WinFix_Audit_$($ComputerName)_$(Get-Date -Format 'yyyyMMdd_HHmm').html"
    $HTML = @"
<!DOCTYPE html><html><head><style>
    body { font-family: 'Segoe UI', Arial, sans-serif; background-color: #f4f7f9; padding: 40px; color: #333; line-height: 1.4; }
    .report-wrap { max-width: 900px; margin: auto; background: white; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); border: 1px solid #d1d8db; overflow: hidden; }
    .hero { background: #12344d; color: white; padding: 30px; }
    .hero h1 { margin: 0; font-size: 22px; text-transform: uppercase; }
    .section-head { background: #f8f9fa; border-bottom: 2px solid #1a73e8; padding: 12px 20px; font-weight: bold; color: #1a73e8; text-transform: uppercase; font-size: 13px; margin-top: 0; }
    table { width: 100%; border-collapse: collapse; }
    th { text-align: left; background: #fafafa; padding: 10px 20px; border-bottom: 1px solid #eee; width: 38%; color: #666; font-size: 12px; }
    td { padding: 10px 20px; border-bottom: 1px solid #eee; font-size: 12px; }
    .copy-bar { background: #1a73e8; color: white; padding: 12px; text-align: center; cursor: pointer; font-weight: bold; border: none; width: 100%; position: sticky; top: 0; z-index: 999; }
    input { border: 1px solid #ccc; padding: 5px; width: 92%; border-radius: 4px; font-family: inherit; font-size: 12px; }
</style>
<script>
    function copyForFreshdesk() {
        const report = document.getElementById('report-main');
        const clone = report.cloneNode(true);
        clone.querySelectorAll('input').forEach(i => {
            const s = document.createElement('span'); s.innerText = i.value || 'N/A';
            s.style.fontWeight = 'bold'; i.parentNode.replaceChild(s, i);
        });
        clone.style.border = '1px solid #d1d8db';
        clone.style.fontFamily = 'Segoe UI, Arial, sans-serif';
        clone.querySelectorAll('.hero').forEach(e => { e.style.backgroundColor='#12344d'; e.style.color='white'; e.style.padding='30px'; });
        clone.querySelectorAll('.section-head').forEach(e => { e.style.backgroundColor='#f8f9fa'; e.style.borderBottom='2px solid #1a73e8'; e.style.padding='12px 20px'; e.style.fontWeight='bold'; e.style.color='#1a73e8'; });
        clone.querySelectorAll('table').forEach(e => { e.style.width='100%'; e.style.borderCollapse='collapse'; });
        clone.querySelectorAll('th').forEach(e => { e.style.background='#fafafa'; e.style.padding='10px'; e.style.borderBottom='1px solid #eee'; e.style.textAlign='left'; });
        clone.querySelectorAll('td').forEach(e => { e.style.padding='10px'; e.style.borderBottom='1px solid #eee'; });
        const t = document.createElement('div'); t.style.position = 'fixed'; t.style.left = '-9999px';
        t.appendChild(clone); document.body.appendChild(temp=t);
        const r = document.createRange(); r.selectNodeContents(temp);
        window.getSelection().removeAllRanges(); window.getSelection().addRange(r);
        document.execCommand('copy'); document.body.removeChild(temp);
        alert('Ultimate Audit copied for Freshdesk!');
    }
</script></head>
<body>
    <button class="copy-bar" onclick="copyForFreshdesk()">📋 CLICK TO COPY FOR FRESHDESK TICKET</button>
    <div id="report-main" class="report-wrap">
        <div class="hero"><h1>HIPAA SECURITY AUDIT: $ComputerName</h1><p>Client: <input value="Enter Client Name"> | Date: $((Get-Date).ToString('F'))</p></div>
        
        <div class="section-head">Identity & Keys</div>
        <table>
            <tr><th>OS Version</th><td>$($OS.Caption)</td></tr>
            <tr><th>Serial Number</th><td>$($BIOS.SerialNumber)</td></tr>
            <tr><th>Windows Product Key</th><td><input value="$WinKey"></td></tr>
            <tr><th>Remote Access Tools</th><td style="color:#e74c3c; font-weight:bold;">$RATText</td></tr>
        </table>

        <div class="section-head">Network & Shares</div>
        <table><tr style="background:#fafafa; font-weight:bold;"><td>Share Name</td><td>Local Path</td></tr>$ShareRows</table>
        $(if(-not $ShareRows){"<p style='padding:10px; color:#999;'>No public network shares found.</p>"})
        
        <div class="section-head">Shared Printers</div>
        <table><tr style="background:#fafafa; font-weight:bold;"><td>Printer Name</td><td>Share Name</td></tr>$PrinterRows</table>
        $(if(-not $PrinterRows){"<p style='padding:10px; color:#999;'>No shared printers found.</p>"})

        <div class="section-head">Resource Stats</div>
        <table>
            <tr><th>RAM Capacity</th><td>$([math]::Round($CS.TotalPhysicalMemory/1GB,1)) GB</td></tr>
            <tr style="background:#fafafa; font-weight:bold;"><td>Volume</td><td>Capacity</td><td>Free Space</td></tr>
            $DiskRows
        </table>

        <div class="section-head">1. Backup (§164.308)</div>
        <table><tr><th>Solution</th><td><input value="$BText"></td></tr><tr><th>Status</th><td><input value="Healthy"></td></tr></table>

        <div class="section-head">2. Policies & Users (§164.308)</div>
        <table>
            <tr><th>Min PW Length</th><td>$MinLen Characters</td></tr>
            <tr><th>Max PW Age</th><td>$MaxAge Days</td></tr>
            <tr><th>Administrators</th><td><input value="$Admins"></td></tr>
        </table>
        <table><tr style="background:#fafafa; font-weight:bold;"><td>User</td><td>Status</td><td>Last PW Change</td></tr>$UserRows</table>
    </div>
</body></html>
"@
    $HTML | Out-File $ReportPath -Encoding UTF8
    Log-Worker "Audit Complete: $ReportPath"
}

# --- UI Assembly ---
$pageAudit = New-Object System.Windows.Forms.Panel
$pageAudit.Dock = "Fill"; $pageAudit.BackColor = $script:Theme.Bg
$script:btnAudit = New-Object System.Windows.Forms.Button
$script:btnAudit.Text = "🚀 GENERATE MAX AUDIT"; $script:btnAudit.Size = New-Object System.Drawing.Size(300, 50); $script:btnAudit.Location = New-Object System.Drawing.Point(250, 200)
$script:btnAudit.FlatStyle="Flat"; $script:btnAudit.BackColor=$script:Theme.Accent; $script:btnAudit.Font=New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$script:btnAudit.Add_Click({
    if ($script:CurrentJob) { return }
    $this.Enabled = $false; $this.Text = "SCANNING..."
    $script:CurrentJob = Start-Job -Name "SecurityAudit" -ScriptBlock $script:AuditScript -ArgumentList @($env:COMPUTERNAME, $env:USERNAME, $env:TEMP)
    $script:JobTimer.Start()
})
$pageAudit.Controls.Add($script:btnAudit)
$pages["Audit"] = $pageAudit

# --- Initialize ---
$form.Controls.AddRange(@($panelContent, $panelLog, $panelNav, $panelHeader))
$form.Add_Shown({ Show-Page "Audit" })
[void]$form.ShowDialog()
