<#
.SYNOPSIS
    WinFix Tool v2.3 - "Freshdesk Optimized" Security Audit
    BUILD: 2026-04-29-MAX-AUDIT-PRO
.DESCRIPTION
    A maintenance and audit tool designed to generate high-fidelity, rich-text
    reports that can be pasted directly into Freshdesk ticket notes.
.NOTES
    Requires Administrator privileges for automated data collection.
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
} catch {
    exit 1
}

[System.Windows.Forms.Application]::EnableVisualStyles()
try { [System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false) } catch { }

# --- Theme Configuration ---
$script:Theme = @{
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

# --- Logging ---
$script:LogPath = Join-Path $env:TEMP 'WinFix_Debug.log'
function Log {
    param([string]$Message)
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    "[$ts] $Message" | Out-File -FilePath $script:LogPath -Append -Encoding UTF8 -ErrorAction SilentlyContinue
    if ($script:txtLog) {
        $script:txtLog.AppendText("[$((Get-Date).ToString('HH:mm:ss'))] $Message`r`n")
        $script:txtLog.SelectionStart = $script:txtLog.Text.Length
        $script:txtLog.ScrollToCaret()
    }
}

# --- Main Form ---
$form = New-Object System.Windows.Forms.Form
$form.Text = "WinFix Tool v2.3 - Freshdesk Audit Pro"
$form.Size = New-Object System.Drawing.Size(900, 650)
$form.BackColor = $script:Theme.Bg
$form.ForeColor = $script:Theme.Text
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)

# --- Layout Components ---
$panelHeader = New-Object System.Windows.Forms.Panel
$panelHeader.Dock = "Top"; $panelHeader.Height = 45; $panelHeader.BackColor = $script:Theme.Surface
$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = "WINFIX AUDIT PRO"; $lblTitle.Location = "15, 12"; $lblTitle.AutoSize = $true; $lblTitle.Font = "Segoe UI, 12, Bold"; $lblTitle.ForeColor = $script:Theme.Accent
$panelHeader.Controls.Add($lblTitle)

$panelNav = New-Object System.Windows.Forms.Panel
$panelNav.Dock = "Left"; $panelNav.Width = 120; $panelNav.BackColor = $script:Theme.Surface
$panelContent = New-Object System.Windows.Forms.Panel
$panelContent.Dock = "Fill"; $panelContent.BackColor = $script:Theme.Bg

$panelLog = New-Object System.Windows.Forms.Panel
$panelLog.Dock = "Bottom"; $panelLog.Height = 80; $panelLog.BackColor = $script:Theme.Surface
$script:txtLog = New-Object System.Windows.Forms.TextBox
$script:txtLog.Multiline=$true; $script:txtLog.ReadOnly=$true; $script:txtLog.Dock="Fill"; $script:txtLog.BackColor=[System.Drawing.Color]::Black; $script:txtLog.ForeColor=$script:Theme.Green; $script:txtLog.Font="Consolas, 8"
$panelLog.Controls.Add($script:txtLog)

$pages = @{}
function Show-Page {
    param($PageName)
    $panelContent.Controls.Clear()
    $panelContent.Controls.Add($pages[$PageName])
}

# === AUDIT PAGE ===
$pageAudit = New-Object System.Windows.Forms.Panel
$pageAudit.Dock = "Fill"; $pageAudit.BackColor = $script:Theme.Bg

$btnAudit = New-Object System.Windows.Forms.Button
$btnAudit.Text = "🚀 RUN FULL SYSTEM AUDIT"; $btnAudit.Size = "300, 50"; $btnAudit.Location = "250, 200"; $btnAudit.FlatStyle="Flat"; $btnAudit.BackColor=$script:Theme.Accent; $btnAudit.ForeColor="White"
$btnAudit.Font = "Segoe UI, 10, Bold"

$btnAudit.Add_Click({
    try {
        Log "Initializing Deep Audit for Freshdesk..."
        $this.Enabled = $false; $this.Text = "Gathering Data..."
        [System.Windows.Forms.Application]::DoEvents()

        # --- DATA GATHERING ---
        $OS = Get-CimInstance Win32_OperatingSystem
        $CS = Get-CimInstance Win32_ComputerSystem
        $BIOS = Get-CimInstance Win32_Bios
        
        # Security Hardening (VBS/CredGuard)
        $VBS = "Not Available"
        try {
            $DG = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
            if ($DG) { $VBS = if ($DG.VirtualizationBasedSecurityStatus -eq 2) { "Enabled" } else { "Disabled" } }
        } catch {}

        # Legacy Protocols & Risks
        $SMB1 = "Unknown"
        try { $SMB1 = (Get-SmbServerConfiguration).EnableSMB1Protocol } catch {}
        
        # User Audit
        $Admins = (Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name) -join ", "
        
        # Encryption
        $BitLocker = "Not Found"
        try {
            if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
                $bl = Get-BitLockerVolume -MountPoint "C:"
                $BitLocker = $bl.ProtectionStatus
            }
        } catch {}

        # Network/Ports
        $Ports = @()
        try {
            $tcp = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
            foreach($t in $tcp) {
                $proc = Get-Process -Id $t.OwningProcess -ErrorAction SilentlyContinue
                if ($proc) { $Ports += "$($t.LocalPort)/$($proc.ProcessName)" }
            }
        } catch {}
        $TopPorts = ($Ports | Select-Object -Unique | Select-Object -First 15) -join ", "

        # --- HTML OUTPUT (Optimized for Freshdesk Copy/Paste) ---
        $ReportPath = "$env:TEMP\WinFix_Audit_$(Get-Date -Format 'yyyyMMdd_HHmm').html"
        $HTML = @"
<!DOCTYPE html>
<html>
<head>
    <title>Security Audit - $env:COMPUTERNAME</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; background: #f4f7f9; color: #333; padding: 20px; }
        .audit-container { max-width: 800px; margin: auto; background: white; padding: 0; border: 1px solid #d1d8db; border-radius: 4px; overflow: hidden; }
        .header { background: #12344d; color: white; padding: 20px; }
        .header h1 { margin: 0; font-size: 22px; }
        .section { padding: 15px 20px; }
        .section-title { background: #f8f9fa; border-bottom: 2px solid #1a73e8; padding: 8px 15px; font-weight: bold; color: #1a73e8; text-transform: uppercase; font-size: 13px; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th { text-align: left; padding: 10px; border-bottom: 1px solid #eee; background: #fafafa; font-size: 13px; color: #666; width: 40%; }
        td { padding: 10px; border-bottom: 1px solid #eee; font-size: 13px; }
        .status-good { color: #27ae60; font-weight: bold; }
        .status-alert { color: #e74c3c; font-weight: bold; }
        .copy-banner { background: #1a73e8; color: white; padding: 10px; text-align: center; position: sticky; top: 0; z-index: 100; cursor: pointer; font-weight: bold; border: none; width: 100%; }
        input.user-edit { border: 1px solid #ccc; padding: 4px; width: 90%; font-family: inherit; }
    </style>
    <script>
        function copyForFreshdesk() {
            const container = document.getElementById('audit-report');
            const clone = container.cloneNode(true);
            
            // Convert inputs to plain text spans for pasting
            clone.querySelectorAll('input').forEach(input => {
                const span = document.createElement('span');
                span.innerText = input.value || 'N/A';
                span.style.fontWeight = 'bold';
                input.parentNode.replaceChild(span, input);
            });

            // Apply absolute inlining for Freshdesk's editor
            clone.style.fontFamily = 'Segoe UI, Arial, sans-serif';
            clone.style.border = '1px solid #d1d8db';
            
            clone.querySelectorAll('.section-title').forEach(el => {
                el.style.backgroundColor = '#f8f9fa';
                el.style.borderBottom = '2px solid #1a73e8';
                el.style.padding = '8px 15px';
                el.style.fontWeight = 'bold';
                el.style.color = '#1a73e8';
            });

            clone.querySelectorAll('table').forEach(el => {
                el.style.width = '100%';
                el.style.borderCollapse = 'collapse';
            });

            clone.querySelectorAll('th').forEach(el => {
                el.style.textAlign = 'left';
                el.style.padding = '10px';
                el.style.borderBottom = '1px solid #eeeeee';
                el.style.backgroundColor = '#fafafa';
                el.style.color = '#666666';
            });

            clone.querySelectorAll('td').forEach(el => {
                el.style.padding = '10px';
                el.style.borderBottom = '1px solid #eeeeee';
            });

            clone.querySelectorAll('.status-good').forEach(el => el.style.color = '#27ae60');
            clone.querySelectorAll('.status-alert').forEach(el => el.style.color = '#e74c3c');

            const temp = document.createElement('div');
            temp.style.position = 'fixed';
            temp.style.left = '-9999px';
            temp.appendChild(clone);
            document.body.appendChild(temp);

            const range = document.createRange();
            range.selectNodeContents(temp);
            const selection = window.getSelection();
            selection.removeAllRanges();
            selection.addRange(range);
            
            try {
                document.execCommand('copy');
                alert('Report copied! Now paste (Ctrl+V) into your Freshdesk ticket note.');
            } catch (err) {
                alert('Copy failed.');
            }
            document.body.removeChild(temp);
        }
    </script>
</head>
<body>
    <button class="copy-banner" onclick="copyForFreshdesk()">📋 CLICK TO COPY FOR FRESHDESK TICKET</button>
    <div id="audit-report" class="audit-container">
        <div class="header" style="background-color: #12344d; color: white; padding: 20px;">
            <h1 style="margin: 0;">SECURITY AUDIT: $env:COMPUTERNAME</h1>
            <p style="margin: 5px 0 0 0; opacity: 0.8; font-size: 12px;">Generated on: $(Get-Date -Format 'F')</p>
        </div>

        <div class="section">
            <p><strong>Client Name:</strong> <input class="user-edit" value="Enter Client..."></p>
            <p><strong>Audit Performed By:</strong> <input class="user-edit" value="$env:USERNAME"></p>
        </div>

        <div class="section-title">System & Hardening</div>
        <div class="section">
            <table>
                <tr><th>Operating System</th><td>$($OS.Caption) (Build $($OS.BuildNumber))</td></tr>
                <tr><th>Serial Number</th><td>$($BIOS.SerialNumber)</td></tr>
                <tr><th>VBS / Credential Guard</th><td class="$(if($VBS -eq 'Enabled'){'status-good'}else{'status-alert'})">$VBS</td></tr>
                <tr><th>BitLocker Status (C:)</th><td class="$(if($BitLocker -eq 'On'){'status-good'}else{'status-alert'})">$BitLocker</td></tr>
            </table>
        </div>

        <div class="section-title">Network Attack Surface</div>
        <div class="section">
            <table>
                <tr><th>SMBv1 Status</th><td class="$(if($SMB1 -eq $true){'status-alert'}else{'status-good'})">$(if($SMB1 -eq $true){'ENABLED (Vulnerable)'}else{'Disabled'})</td></tr>
                <tr><th>Listening Ports (Top 15)</th><td style="font-size: 11px;">$TopPorts</td></tr>
            </table>
        </div>

        <div class="section-title">Identity & Access</div>
        <div class="section">
            <table>
                <tr><th>Local Administrators</th><td style="font-size: 11px;">$Admins</td></tr>
                <tr><th>Uptime</th><td>$([math]::Round(((Get-Date) - $($OS.LastBootUpTime)).TotalDays, 1)) Days</td></tr>
            </table>
        </div>
        
        <div class="section" style="background: #fdfdfe; border-top: 1px solid #eee; font-style: italic; font-size: 11px; color: #999;">
            Note: This audit is a snapshot and does not replace regular compliance reviews.
        </div>
    </div>
    <div style="text-align: center; margin-top: 20px; color: #999; font-size: 11px;">WinFix Tool v2.3 - IT Toolkit</div>
</body>
</html>
"@
        $HTML | Out-File $ReportPath -Encoding UTF8
        Invoke-Item $ReportPath
        Log "Audit complete. HTML saved and opened: $ReportPath"
        
    } catch {
        Log "Audit Failed: $_"
    } finally {
        $this.Enabled = $true; $this.Text = "🚀 RUN FULL SYSTEM AUDIT"
    }
})

$pageAudit.Controls.Add($btnAudit)
$pages["Audit"] = $pageAudit

# --- Final Assembly ---
$form.Controls.AddRange(@($panelContent, $panelLog, $panelNav, $panelHeader))
$form.Add_Shown({ Show-Page "Audit" })
[void]$form.ShowDialog()
