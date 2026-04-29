<#
.SYNOPSIS
    WinFix Tool v3.5 - Professional HIPAA Audit (Synology Support)
    BUILD: 2026-04-30-SYNOLOGY-PRO
.DESCRIPTION
    Advanced HIPAA Audit tool with absolute CSS inlining for Freshdesk.
    Includes detection for Synology, Veeam, Datto, and more.
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

Add-Type -AssemblyName System.Windows.Forms, System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# --- Theme Configuration ---
$script:Theme = @{
    Bg      = [System.Drawing.Color]::FromArgb(18, 18, 24)
    Surface = [System.Drawing.Color]::FromArgb(26, 27, 38)
    Card    = [System.Drawing.Color]::FromArgb(36, 37, 51)
    Text    = [System.Drawing.Color]::FromArgb(237, 237, 245)
    Accent  = [System.Drawing.Color]::FromArgb(99, 102, 241)
    Green   = [System.Drawing.Color]::FromArgb(34, 197, 94)
}

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
$form.Text = "WinFix Tool v3.5 - Professional Audit"; $form.Size = "900, 650"
$form.BackColor = $script:Theme.Bg; $form.ForeColor = $script:Theme.Text; $form.Font = New-Object System.Drawing.Font("Segoe UI", 9)

# --- UI Components (Simplified for Audit Focus) ---
$panelHeader = New-Object System.Windows.Forms.Panel
$panelHeader.Dock = "Top"; $panelHeader.Height = 45; $panelHeader.BackColor = $script:Theme.Surface
$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = "WINFIX AUDIT PRO"; $lblTitle.Location = "15, 12"; $lblTitle.AutoSize = $true
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

$navY = 5
foreach($n in @("Dashboard", "Quick Fix", "Diagnostics", "Network", "Audit")){
    $b = New-Object System.Windows.Forms.Button
    $b.Text=$n; $b.Location="5, $navY"; $b.Size="120, 32"; $b.FlatStyle="Flat"; $b.Tag=$n
    $b.Add_Click({ Show-Page $this.Tag }); $panelNav.Controls.Add($b); $navButtons += $b; $navY += 36
}

# === BACKGROUND AUDIT SCRIPT ===
$script:AuditScript = {
    param($ComputerName, $UserName, $TempPath)
    function Log-Worker($msg) { Write-Output $msg }
    function Escape-Html($v) { if($v){$v -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;'}else{""} }

    Log-Worker "Pulling OS & Hardware Identity..."
    $OS = Get-CimInstance Win32_OperatingSystem
    $CS = Get-CimInstance Win32_ComputerSystem
    $BIOS = Get-CimInstance Win32_Bios
    $IsVM = $CS.Model -match "Virtual|VMware|Hyper-V|KVM"
    
    Log-Worker "Checking Active Roles & BitLocker..."
    $Roles = "Workstation"
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) { $Roles = (Get-WindowsFeature | Where-Object Installed | Select-Object -ExpandProperty Name) -join ", " }
    $BitLocker = "Not Available"
    try { $BitLocker = (Get-BitLockerVolume -MountPoint "C:").ProtectionStatus } catch {}

    Log-Worker "Auditing Backup Tools (Adding Synology Detection)..."
    # Expanded keywords for Synology and other MSP tools
    $BackupKeywords = @("Veeam","Acronis","Datto","Carbonite","ShadowProtect","Backblaze","Synology","Active Backup","Hyper Backup","SynoDrive")
    $found = Get-Service | Where-Object { $d = $_.DisplayName; $BackupKeywords | Where-Object { $d -like "*$_*" } }
    $DetectedBackup = if ($found) { ($found.DisplayName | Sort-Object -Unique) -join "; " } else { "Not Detected" }

    Log-Worker "Scanning for Recent Security Logs..."
    $EventRows = ""
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='System','Application'; Level=1,2,3; StartTime=(Get-Date).AddDays(-30)} -MaxEvents 50 -ErrorAction SilentlyContinue
        if ($events) {
            $grouped = $events | Group-Object { "$($_.ProviderName)|$($_.Id)" } | Where-Object { $_.Count -gt 1 }
            foreach($g in $grouped) {
                $s = $g.Group[0]
                $msg = Escape-Html($s.Message.Substring(0, [math]::Min($s.Message.Length, 80)))
                $EventRows += "<tr><td>$($s.ProviderName)</td><td>$($s.Id)</td><td>$($g.Count)x</td><td>$msg...</td></tr>"
            }
        }
    } catch {}

    Log-Worker "Generating v3.5 Professional HTML..."
    $ReportPath = Join-Path $TempPath "WinFix_Audit_$($ComputerName)_$(Get-Date -Format 'yyyyMMdd_HHmm').html"
    $HTML = @"
<!DOCTYPE html><html><head>
<style>
    body { font-family: 'Segoe UI', Tahoma, sans-serif; background-color: #f0f2f5; padding: 40px; color: #333; }
    .report-wrap { max-width: 900px; margin: auto; background: white; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); border: 1px solid #d1d8db; overflow: hidden; }
    .hero { background: #12344d; color: white; padding: 30px; }
    .hero h1 { margin: 0; font-size: 22px; text-transform: uppercase; letter-spacing: 1px; }
    .hero p { margin: 8px 0 0 0; opacity: 0.8; font-size: 13px; }
    .section-head { background: #f8f9fa; border-bottom: 2px solid #1a73e8; padding: 12px 20px; font-weight: bold; color: #1a73e8; text-transform: uppercase; font-size: 13px; margin-top: 0; }
    .sub-head { background: #ffffff; padding: 8px 20px; font-weight: bold; color: #555; border-bottom: 1px solid #f0f0f0; font-size: 12px; }
    table { width: 100%; border-collapse: collapse; }
    th { text-align: left; background: #fafafa; padding: 12px 20px; border-bottom: 1px solid #eee; width: 35%; color: #666; font-size: 12px; }
    td { padding: 12px 20px; border-bottom: 1px solid #eee; font-size: 12px; }
    .status-badge { padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; text-transform: uppercase; }
    .badge-good { background: #e6f4ea; color: #1e7e34; }
    .badge-alert { background: #fce8e6; color: #c5221f; }
    .copy-bar { background: #1a73e8; color: white; padding: 12px; text-align: center; cursor: pointer; font-weight: bold; border: none; width: 100%; position: sticky; top: 0; z-index: 999; }
    input { border: 1px solid #ccc; padding: 6px; width: 92%; border-radius: 4px; font-family: inherit; font-size: 12px; }
</style>
<script>
    function copyForFreshdesk() {
        const report = document.getElementById('report-main');
        const clone = report.cloneNode(true);
        
        // Convert inputs to bold spans
        clone.querySelectorAll('input').forEach(i => {
            const s = document.createElement('span'); s.innerText = i.value || 'N/A';
            s.style.fontWeight = 'bold'; i.parentNode.replaceChild(s, i);
        });

        // Forced Style Inlining for Freshdesk
        clone.style.border = '1px solid #d1d8db';
        clone.style.fontFamily = 'Segoe UI, Arial, sans-serif';
        clone.querySelectorAll('.hero').forEach(e => { e.style.backgroundColor='#12344d'; e.style.color='white'; e.style.padding='30px'; });
        clone.querySelectorAll('.section-head').forEach(e => { e.style.backgroundColor='#f8f9fa'; e.style.borderBottom='2px solid #1a73e8'; e.style.padding='12px 20px'; e.style.fontWeight='bold'; e.style.color='#1a73e8'; });
        clone.querySelectorAll('.sub-head').forEach(e => { e.style.padding='8px 20px'; e.style.fontWeight='bold'; e.style.color='#555'; e.style.borderBottom='1px solid #f0f0f0'; });
        clone.querySelectorAll('table').forEach(e => { e.style.width='100%'; e.style.borderCollapse='collapse'; });
        clone.querySelectorAll('th').forEach(e => { e.style.background='#fafafa'; e.style.padding='10px'; e.style.borderBottom='1px solid #eee'; e.style.textAlign='left'; });
        clone.querySelectorAll('td').forEach(e => { e.style.padding='10px'; e.style.borderBottom='1px solid #eee'; });
        clone.querySelectorAll('.badge-good').forEach(e => { e.style.backgroundColor='#e6f4ea'; e.style.color='#1e7e34'; e.style.padding='4px'; e.style.borderRadius='4px'; e.style.fontWeight='bold'; });
        clone.querySelectorAll('.badge-alert').forEach(e => { e.style.backgroundColor='#fce8e6'; e.style.color='#c5221f'; e.style.padding='4px'; e.style.borderRadius='4px'; e.style.fontWeight='bold'; });

        const t = document.createElement('div');
        t.style.position = 'fixed'; t.style.left = '-9999px';
        t.appendChild(clone); document.body.appendChild(t);
        const r = document.createRange(); r.selectNodeContents(t);
        window.getSelection().removeAllRanges(); window.getSelection().addRange(r);
        document.execCommand('copy'); document.body.removeChild(t);
        alert('Audit copied! Paste into Freshdesk now.');
    }
</script></head>
<body>
    <button class="copy-bar" onclick="copyForFreshdesk()">📋 CLICK TO COPY FOR FRESHDESK TICKET</button>
    <div id="report-main" class="report-wrap">
        <div class="hero"><h1>HIPAA SECURITY AUDIT: $ComputerName</h1><p>Client: <input value="Enter Client Name"> | Date: $((Get-Date).ToString('F'))</p></div>
        
        <div class="section-head">System & HIPAA Overview</div>
        <table>
            <tr><th>OS Version</th><td>$($OS.Caption)</td></tr>
            <tr><th>Role(s)</th><td><input value="$Roles"></td></tr>
            <tr><th>BitLocker Status</th><td><span class="status-badge $(if($BitLocker -eq 'On'){'badge-good'}else{'badge-alert'})">$BitLocker</span></td></tr>
        </table>

        <div class="section-head">1. Backup & Data Retention (§164.308)</div>
        <div class="sub-head">A. Backup System Review</div>
        <table>
            <tr><th>Detected Backup Tools</th><td><input value="$DetectedBackup"></td></tr>
            <tr><th>Sync/Success Status</th><td><input value="Check Console (Synology/Veeam)"></td></tr>
        </table>

        <div class="section-head">5. Server Monitoring & Logs (§164.312)</div>
        <table>$EventRows</table>
        $(if(-not $EventRows){"<p style='padding:20px; color:#999; font-size:11px;'>No repeating critical/warning events in the last 30 days.</p>"})

        <div class="section-head">6. Physical Security (§164.310)</div>
        <table>
            <tr><th>Server Location</th><td><input value="Onsite Rack/Closet"></td></tr>
            <tr><th>Room Locked?</th><td><input value="Yes"></td></tr>
            <tr><th>Physical Access</th><td><input value="Facilities, IT Staff"></td></tr>
        </table>

        <div class="section-head">7. Contingency & Redundancy</div>
        <table>
            <tr><th>RAID Status</th><td><input value="Verified Healthy"></td></tr>
        </table>
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
$script:btnAudit.Text = "🚀 GENERATE MAX AUDIT"; $script:btnAudit.Size = "300, 50"; $script:btnAudit.Location = "250, 200"
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
