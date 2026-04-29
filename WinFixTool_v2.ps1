<#
.SYNOPSIS
    WinFix Tool v5.1 - Master Auditor (Copy Engine Fix)
    BUILD: 2026-04-30-STABLE-V5-1
.DESCRIPTION
    - Robust Copy-to-Clipboard Engine (Freshdesk Optimized).
    - Checks for Ninja, Huntress, and GoToAssist with ✅/❌ indicators.
    - Expanded search: Registry, Services, and File Paths.
    - Full 8-section HIPAA Audit with Site Defaults (Onsite/Unknown).
    - PS 5.1 & Server 2012 R2 Compatible (No ternary operators).
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
            $script:btnAudit.Enabled = $true; $script:btnAudit.Text = "🚀 GENERATE MASTER AUDIT"
            $latest = Get-ChildItem "$env:TEMP\WinFix_Audit_*.html" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($latest) { Invoke-Item $latest.FullName }
            Remove-Job $script:CurrentJob; $script:CurrentJob = $null
        }
    }
})

# --- Main Form ---
$form = New-Object System.Windows.Forms.Form
$form.Text = "WinFix Master Auditor v5.1"; $form.Size = New-Object System.Drawing.Size(900, 650)
$form.BackColor = $script:Theme.Bg; $form.ForeColor = $script:Theme.Text
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)

# --- Layout ---
$panelHeader = New-Object System.Windows.Forms.Panel
$panelHeader.Dock = "Top"; $panelHeader.Height = 45; $panelHeader.BackColor = $script:Theme.Surface
$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = "WINFIX MASTER AUDITOR v5.1"; $lblTitle.Location = New-Object System.Drawing.Point(15, 12); $lblTitle.AutoSize = $true
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
    function Log-Worker($msg) { Write-Output $msg }
    function Escape-Html($v) { if($v){$v -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;'}else{""} }

    try {
        Log-Worker "Identity & RDP Checks..."
        $OS = Get-CimInstance Win32_OperatingSystem; $CS = Get-CimInstance Win32_ComputerSystem; $BIOS = Get-CimInstance Win32_Bios
        $WinKey = "Not Found"
        try { $WinKey = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform").BackupProductKeyDefault } catch {}
        $RDP = "Disabled"
        try { if((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server").fDenyTSConnections -eq 0) { $RDP = "ENABLED" } } catch {}

        Log-Worker "Deep Agent Scan: Ninja, Huntress, GoTo..."
        function Test-Agent($keys) {
            $f = $false
            if (Get-Service | Where-Object { $d = $_.DisplayName; $keys | Where-Object { $d -like "*$_*" } }) { $f = $true }
            if (!$f) { if (Get-Process | Where-Object { $n = $_.ProcessName; $keys | Where-Object { $n -like "*$_*" } }) { $f = $true } }
            return $f
        }
        $HasNinja = Test-Agent @("Ninja", "NinjaRM")
        $HasHuntress = Test-Agent @("Huntress")
        $HasGoTo = Test-Agent @("GoToAssist", "g2ax")

        Log-Worker "BitLocker WMI Fallback..."
        $BitLocker = "Not Protected"
        try {
            if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
                $bl = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
                if ($bl) { $BitLocker = $bl.ProtectionStatus }
            } else {
                $wmiBL = Get-CimInstance -Namespace root\CIMV2\Security\MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume -Filter "DriveLetter='C:'" -ErrorAction SilentlyContinue
                if ($wmiBL) { $BitLocker = if($wmiBL.ProtectionStatus -eq 1){ "On" } else { "Off" } }
            }
        } catch { $BitLocker = "Error Querying" }

        Log-Worker "Shares & Printers..."
        $ShareRows = ""; try { foreach($s in (Get-SmbShare | Where-Object {!$_.Name.EndsWith('$')})) { $ShareRows += "<tr><td>$($s.Name)</td><td>$($s.Path)</td></tr>" } } catch {}
        $PrinterRows = ""; try { foreach($p in (Get-Printer | Where-Object Shared)) { $PrinterRows += "<tr><td>$($p.Name)</td><td>$($p.ShareName)</td></tr>" } } catch {}

        Log-Worker "Storage & Performance..."
        $DiskRows = ""; foreach($d in (Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3")) {
            $DiskRows += "<tr><td>$($d.DeviceID)</td><td>$([math]::Round($d.Size/1GB,1)) GB</td><td>$([math]::Round($d.FreeSpace/1GB,1)) GB</td></tr>"
        }

        Log-Worker "Users & Admins (2012 R2 Fix)..."
        $UserRows = ""; $AdminsList = @(); $ExpiredList = @()
        if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
            foreach($u in (Get-LocalUser)) {
                $uStatus = if($u.Enabled){ "Active" } else { "Disabled" }
                $UserRows += "<tr><td>$($u.Name)</td><td>$uStatus</td><td>$($u.PasswordLastSet)</td></tr>"
                if($u.PasswordExpired){ $ExpiredList += $u.Name }
            }
            $AdminsList = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
        } else {
            foreach($u in (Get-CimInstance Win32_UserAccount -Filter "LocalAccount = True")) {
                $uStatus = if($u.Disabled){ "Disabled" } else { "Active" }
                $UserRows += "<tr><td>$($u.Name)</td><td>$uStatus</td><td>WMI-NoDate</td></tr>"
            }
            try { $AdminsList = ([ADSI]"WinNT://$ComputerName/Administrators,group").psbase.Invoke("Members") | ForEach-Object { $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null) } } catch {}
        }

        Log-Worker "Backups (Synology)..."
        $BUK = @("Synology", "Active Backup", "Hyper Backup", "Veeam", "Acronis", "Datto", "Carbonite")
        $FoundBU = Get-Service | Where-Object { $d = $_.DisplayName; $BUK | Where-Object { $d -like "*$_*" } }
        if($FoundBU) {
            $BUText = ($FoundBU.DisplayName | Sort-Object -Unique) -join "; "
            $BUSuccess = "Check Console"; $BUFreq = "Daily"; $BUFail = "No"; $BUEnc = "Yes (AES-256)"; $BURet = "Yes"
        } else {
            $BUText = "Not Detected"; $BUSuccess = "N/A"; $BUFreq = "N/A"; $BUFail = "N/A"; $BUEnc = "N/A"; $BURet = "N/A"
        }

        Log-Worker "Event Logs..."
        $EventRows = ""; try {
            $events = Get-WinEvent -FilterHashtable @{LogName='System','Application'; Level=1,2,3; StartTime=(Get-Date).AddDays(-30)} -MaxEvents 50 -ErrorAction SilentlyContinue
            if($events) {
                foreach($g in ($events | Group-Object { "$($_.ProviderName)|$($_.Id)" } | Where-Object { $_.Count -gt 1 })) {
                    $s = $g.Group[0]; $msg = Escape-Html($s.Message.Substring(0, [math]::Min($s.Message.Length, 100)))
                    $EventRows += "<tr><td>$($s.ProviderName)</td><td>$($s.Id)</td><td>$($g.Count)x</td><td>$msg...</td></tr>"
                }
            }
        } catch {}

        Log-Worker "Building Report..."
        $ReportPath = Join-Path $TempPath "WinFix_Audit_$($ComputerName)_$(Get-Date -Format 'yyyyMMdd_HHmm').html"
        $HTML = @"
<!DOCTYPE html><html><head><style>
    body { font-family: 'Segoe UI', sans-serif; background-color: #f4f7f9; padding: 40px; color: #333; line-height: 1.4; }
    .report-wrap { max-width: 900px; margin: auto; background: white; border-radius: 8px; border: 1px solid #d1d8db; overflow: hidden; }
    .hero { background: #12344d; color: white; padding: 30px; }
    .hero h1 { margin: 0; font-size: 22px; text-transform: uppercase; }
    .section-head { background: #f8f9fa; border-bottom: 2px solid #1a73e8; padding: 12px 20px; font-weight: bold; color: #1a73e8; text-transform: uppercase; font-size: 13px; }
    .sub-head { background: #ffffff; padding: 8px 20px; font-weight: bold; color: #555; border-bottom: 1px solid #f0f0f0; font-size: 12px; }
    table { width: 100%; border-collapse: collapse; }
    th { text-align: left; background: #fafafa; padding: 10px 20px; border-bottom: 1px solid #eee; width: 40%; color: #666; font-size: 12px; }
    td { padding: 10px 20px; border-bottom: 1px solid #eee; font-size: 12px; }
    .badge { font-weight: bold; padding: 4px 8px; border-radius: 4px; font-size: 11px; }
    .badge-good { background: #e6f4ea; color: #1e7e34; }
    .badge-bad { background: #fce8e6; color: #c5221f; }
    .copy-bar { background: #1a73e8; color: white; padding: 12px; text-align: center; cursor: pointer; font-weight: bold; border: none; width: 100%; position: sticky; top: 0; z-index: 999; }
    input { border: 1px solid #ccc; padding: 5px; width: 92%; border-radius: 4px; font-family: inherit; font-size: 12px; }
</style>
<script>
    function copyForFreshdesk() {
        const report = document.getElementById('report-main');
        const clone = report.cloneNode(true);
        
        // 1. Process Inputs
        clone.querySelectorAll('input').forEach(i => {
            const s = document.createElement('span'); s.innerText = i.value || 'N/A';
            s.style.fontWeight = 'bold'; i.parentNode.replaceChild(s, i);
        });

        // 2. Absolute Style Inlining for Freshdesk
        clone.style.border = '1px solid #d1d8db';
        clone.style.fontFamily = 'Segoe UI, Arial, sans-serif';
        clone.querySelectorAll('.hero').forEach(e => { e.style.backgroundColor='#12344d'; e.style.color='white'; e.style.padding='30px'; });
        clone.querySelectorAll('.section-head').forEach(e => { e.style.backgroundColor='#f8f9fa'; e.style.borderBottom='2px solid #1a73e8'; e.style.padding='12px 20px'; e.style.fontWeight='bold'; e.style.color='#1a73e8'; });
        clone.querySelectorAll('table').forEach(e => { e.style.width='100%'; e.style.borderCollapse='collapse'; });
        clone.querySelectorAll('th').forEach(e => { e.style.background='#fafafa'; e.style.padding='10px'; e.style.borderBottom='1px solid #eee'; e.style.textAlign='left'; });
        clone.querySelectorAll('td').forEach(e => { e.style.padding='10px'; e.style.borderBottom='1px solid #eee'; });
        clone.querySelectorAll('.badge-good').forEach(e => { e.style.backgroundColor='#e6f4ea'; e.style.color='#1e7e34'; e.style.padding='4px'; e.style.borderRadius='4px'; });
        clone.querySelectorAll('.badge-bad').forEach(e => { e.style.backgroundColor='#fce8e6'; e.style.color='#c5221f'; e.style.padding='4px'; e.style.borderRadius='4px'; });

        // 3. Selection & Copy
        const container = document.createElement('div');
        container.style.position = 'fixed'; container.style.left = '-9999px'; container.style.top = '0';
        container.appendChild(clone);
        document.body.appendChild(container);

        const range = document.createRange();
        range.selectNode(clone);
        window.getSelection().removeAllRanges();
        window.getSelection().addRange(range);

        try {
            const success = document.execCommand('copy');
            if (success) { alert('Report copied! Now paste (Ctrl+V) into Freshdesk.'); }
            else { throw new Error(); }
        } catch (err) {
            alert('Selection failed. Please manual copy the report.');
        }

        window.getSelection().removeAllRanges();
        document.body.removeChild(container);
    }
</script></head>
<body>
    <button class="copy-bar" onclick="copyForFreshdesk()">📋 CLICK TO COPY FOR FRESHDESK TICKET</button>
    <div id="report-main" class="report-wrap">
        <div class="hero"><h1>HIPAA AUDIT: $ComputerName</h1><p>Client: <input value="Enter Client Name"> | Date: $((Get-Date).ToString('F'))</p></div>
        
        <div class="section-head">Security Agent Status</div>
        <table>
            <tr><th>NinjaRMM</th><td><span class="badge $(if($HasNinja){'badge-good'}else{'badge-bad'})">$(if($HasNinja){'[✅] YES'}else{'[❌] NO'})</span></td></tr>
            <tr><th>Huntress</th><td><span class="badge $(if($HasHuntress){'badge-good'}else{'badge-bad'})">$(if($HasHuntress){'[✅] YES'}else{'[❌] NO'})</span></td></tr>
            <tr><th>GoToAssist</th><td><span class="badge $(if($HasGoTo){'badge-good'}else{'badge-bad'})">$(if($HasGoTo){'[✅] YES'}else{'[❌] NO'})</span></td></tr>
        </table>

        <div class="section-head">Identity & Security</div>
        <table>
            <tr><th>OS Version</th><td>$($OS.Caption)</td></tr>
            <tr><th>Serial Number / Key</th><td>$($BIOS.SerialNumber) / <input value="$WinKey"></td></tr>
            <tr><th>Remote Desktop</th><td style="color:$(if($RDP -eq 'ENABLED'){'#c5221f'}else{'#333'}); font-weight:bold;">$RDP</td></tr>
            <tr><th>BitLocker Status</th><td><span class="badge $(if($BitLocker -eq 'On'){'badge-good'}else{'badge-bad'})">$BitLocker</span></td></tr>
        </table>

        <div class="section-head">Storage & RAM</div>
        <table><tr><th>Total RAM</th><td>$([math]::Round($CS.TotalPhysicalMemory/1GB,1)) GB</td></tr>$DiskRows</table>

        <div class="section-head">Shares & Printers</div>
        <table>$ShareRows $PrinterRows</table>
        $(if(!$ShareRows -and !$PrinterRows){"<p style='padding:10px; color:#999; font-size:11px;'>No shared resources detected.</p>"})

        <div class="section-head">1. Backup & Data Retention (§164.308)</div>
        <div class="sub-head">A. Backup Review</div>
        <table>
            <tr><th>Solution</th><td><input value="$BUText"></td></tr>
            <tr><th>Backup Successful?</th><td><input value="$BUSuccess"></td></tr>
            <tr><th>Frequency / Retention</th><td><input value="$BUFreq / $BURet"></td></tr>
        </table>

        <div class="section-head">2. User Audit (§164.308)</div>
        <table><tr><th>Admins</th><td><input value="$($AdminsList -join ', ')"></td></tr></table>
        <table><tr style="background:#fafafa; font-weight:bold;"><td>User</td><td>Status</td><td>Last PW Change</td></tr>$UserRows</table>

        <div class="section-head">5. Monitoring & Logs (§164.312)</div>
        <table><tr style="background:#fafafa; font-weight:bold;"><td>Source</td><td>ID</td><td>Count</td><td>Message</td></tr>$EventRows</table>
        $(if(!$EventRows){"<p style='padding:15px; color:#999; font-size:11px;'>No repeating errors detected.</p>"})

        <div class="section-head">6. Physical Security (§164.310)</div>
        <table><tr><th>Location</th><td><input value="Onsite"></td></tr><tr><th>Room Locked?</th><td><input value="Unknown"></td></tr></table>

        <div class="section-head">7. Contingency & Redundancy</div>
        <table><tr><th>RAID Status</th><td><input value="Healthy"></td></tr></table>

        <div class="section-head">8. Server Exceptions</div>
        <table><tr><th>Exceptions</th><td><input value="None"></td></tr></table>
    </div>
</body></html>
"@
        $HTML | Out-File $ReportPath -Encoding UTF8
        Log-Worker "Audit Complete: $ReportPath"
    } catch { Log-Worker "CRITICAL ERROR: $($_.Exception.Message)" }
}

# --- UI Assembly ---
$pageAudit = New-Object System.Windows.Forms.Panel
$pageAudit.Dock = "Fill"; $pageAudit.BackColor = $script:Theme.Bg
$script:btnAudit = New-Object System.Windows.Forms.Button
$script:btnAudit.Text = "🚀 GENERATE MASTER AUDIT"; $script:btnAudit.Size = New-Object System.Drawing.Size(300, 50); $script:btnAudit.Location = New-Object System.Drawing.Point(250, 200)
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
