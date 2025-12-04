<#
.SYNOPSIS
    WinFix Tool - All-in-One Windows Maintenance & Security Audit Utility
.DESCRIPTION
    A standalone GUI tool to perform common Windows fixes, gather system info, 
    run network scans, and generate the "Polar Nite" Security Audit report.
    Designed to be compiled into an EXE.
.NOTES
    Requires Administrator Privileges.
#>

# --- Request Admin Privileges ---
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    $newProcess = New-Object System.Diagnostics.ProcessStartInfo "PowerShell";
    $newProcess.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"";
    $newProcess.Verb = "runas";
    [System.Diagnostics.Process]::Start($newProcess);
    Exit;
}

# --- Load Assemblies ---
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# --- GUI Setup ---
$form = New-Object System.Windows.Forms.Form
$form.Text = "WinFix Tool & Security Audit"
$form.Size = New-Object System.Drawing.Size(800, 600)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false

# Tabs
$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Dock = "Fill"

# --- Tab 1: Common Fixes ---
$tabFixes = New-Object System.Windows.Forms.TabPage
$tabFixes.Text = "Common Fixes"
$tabFixes.Padding = New-Object System.Windows.Forms.Padding(10)

$flowFixes = New-Object System.Windows.Forms.FlowLayoutPanel
$flowFixes.Dock = "Top"
$flowFixes.AutoSize = $true
$flowFixes.FlowDirection = "TopDown"

# Helper to add buttons
function Add-Button($parent, $text, $action) {
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $text
    $btn.AutoSize = $true
    $btn.Padding = New-Object System.Windows.Forms.Padding(5)
    $btn.Margin = New-Object System.Windows.Forms.Padding(5)
    $btn.Width = 250
    $btn.Height = 40
    $btn.Add_Click($action)
    $parent.Controls.Add($btn)
}

Add-Button $flowFixes "Free Up Disk Space (Temp/Recycle)" {
    Log-Output "Cleaning Temp Folders and Recycle Bin..."
    try {
        Clear-RecycleBin -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:windir\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
        Log-Output "Cleanup Complete."
    } catch {
        Log-Output "Error during cleanup: $_"
    }
}

Add-Button $flowFixes "Disable Sleep & Hibernate" {
    Log-Output "Disabling Sleep and Hibernate..."
    try {
        powercfg -change -monitor-timeout-ac 0
        powercfg -change -disk-timeout-ac 0
        powercfg -change -standby-timeout-ac 0
        powercfg -change -hibernate-timeout-ac 0
        powercfg -h off
        Log-Output "Power settings updated (AC Power)."
    } catch {
        Log-Output "Error updating power settings: $_"
    }
}

Add-Button $flowFixes "Fix Network (Reset TCP/IP/DNS)" {
    Log-Output "Resetting Network Stack..."
    try {
        netsh int ip reset | Out-Null
        netsh winsock reset | Out-Null
        ipconfig /flushdns | Out-Null
        Log-Output "Network reset complete. A reboot may be required."
    } catch {
        Log-Output "Error resetting network: $_"
    }
}

Add-Button $flowFixes "Run System File Checker (SFC)" {
    Log-Output "Starting SFC Scan (This may take a while)..."
    Start-Process "sfc" -ArgumentList "/scannow" -Wait -NoNewWindow
    Log-Output "SFC Scan Complete."
}

Add-Button $flowFixes "DISM Repair Image" {
    Log-Output "Starting DISM RestoreHealth (This may take a while)..."
    Start-Process "dism" -ArgumentList "/online /cleanup-image /restorehealth" -Wait -NoNewWindow
    Log-Output "DISM Repair Complete."
}

Add-Button $flowFixes "Reset Windows Update" {
    Log-Output "Resetting Windows Update Components..."
    try {
        Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
        Stop-Service cryptSvc -Force -ErrorAction SilentlyContinue
        Stop-Service bits -Force -ErrorAction SilentlyContinue
        Stop-Service msiserver -Force -ErrorAction SilentlyContinue
        
        Remove-Item "$env:windir\SoftwareDistribution" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:windir\System32\catroot2" -Recurse -Force -ErrorAction SilentlyContinue
        
        Start-Service wuauserv -ErrorAction SilentlyContinue
        Start-Service cryptSvc -ErrorAction SilentlyContinue
        Start-Service bits -ErrorAction SilentlyContinue
        Start-Service msiserver -ErrorAction SilentlyContinue
        Log-Output "Windows Update Reset Complete."
    } catch {
        Log-Output "Error resetting Windows Update: $_"
    }
}

Add-Button $flowFixes "Clear Print Spooler" {
    Log-Output "Clearing Print Spooler..."
    try {
        Stop-Service Spooler -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:windir\System32\spool\PRINTERS\*" -Force -ErrorAction SilentlyContinue
        Start-Service Spooler -ErrorAction SilentlyContinue
        Log-Output "Print Spooler Cleared and Restarted."
    } catch {
        Log-Output "Error clearing spooler: $_"
    }
}

Add-Button $flowFixes "Restart Explorer" {
    Log-Output "Restarting Windows Explorer..."
    Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
    Log-Output "Explorer Restarted."
}

Add-Button $flowFixes "Sync System Time" {
    Log-Output "Syncing System Time..."
    try {
        Start-Service w32time -ErrorAction SilentlyContinue
        w32tm /resync | Out-String | ForEach-Object { Log-Output $_ }
        Log-Output "Time Sync Attempted."
    } catch {
        Log-Output "Error syncing time: $_"
    }
}

Add-Button $flowFixes "Run Microsoft Activation Scripts (MAS)" {
    Log-Output "Launching Microsoft Activation Scripts..."
    try {
        Start-Process powershell -ArgumentList "-NoProfile -Command `"iex (curl.exe -s --doh-url https://1.1.1.1/dns-query https://get.activated.win | Out-String)`""
        Log-Output "MAS launched in a new window."
    } catch {
        Log-Output "Error launching MAS: $_"
    }
}

Add-Button $flowFixes "Download & Run SpaceMonger" {
    Log-Output "Checking for SpaceMonger..."
    $smPath = "$env:TEMP\SpaceMonger.exe"
    # Using raw.githubusercontent.com for direct file download
    $url = "https://github.com/jeremydbean/winfix/raw/main/SpaceMonger.exe"
    
    if (-not (Test-Path $smPath)) {
        Log-Output "Downloading SpaceMonger from GitHub..."
        try {
            # TLS 1.2 enforcement for older OS
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $url -OutFile $smPath -ErrorAction Stop
            Log-Output "Download Complete."
        } catch {
            Log-Output "Error downloading SpaceMonger: $_"
            Log-Output "Ensure internet access is available."
            return
        }
    }
    
    Log-Output "Launching SpaceMonger..."
    try {
        Start-Process $smPath
    } catch {
        Log-Output "Error launching SpaceMonger: $_"
    }
}

$tabFixes.Controls.Add($flowFixes)

# --- Tab 2: System Info ---
$tabInfo = New-Object System.Windows.Forms.TabPage
$tabInfo.Text = "System Info"

$flowInfo = New-Object System.Windows.Forms.FlowLayoutPanel
$flowInfo.Dock = "Top"
$flowInfo.AutoSize = $true

Add-Button $flowInfo "Get System Specs" {
    Log-Output "Gathering System Specs..."
    $info = Get-ComputerInfo
    Log-Output "OS: $($info.OsName)"
    Log-Output "Version: $($info.OsVersion)"
    Log-Output "Manufacturer: $($info.CsManufacturer)"
    Log-Output "Model: $($info.CsModel)"
    Log-Output "RAM: $([math]::Round($info.CsTotalPhysicalMemory / 1GB, 2)) GB"
    Log-Output "Bios: $($info.BiosSVersion)"
}

Add-Button $flowInfo "List Printers" {
    Log-Output "Listing Printers..."
    Get-Printer | Select-Object Name, DriverName, PortName | Out-String | ForEach-Object { Log-Output $_ }
}

Add-Button $flowInfo "List Installed Software" {
    Log-Output "Listing Installed Software (via Registry)..."
    $keys = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    Get-ItemProperty $keys -ErrorAction SilentlyContinue | 
        Where-Object { $_.DisplayName -ne $null } | 
        Select-Object DisplayName, DisplayVersion | 
        Sort-Object DisplayName | 
        Out-String | ForEach-Object { Log-Output $_ }
}

$tabInfo.Controls.Add($flowInfo)

# --- Tab 3: Network Tools ---
$tabNet = New-Object System.Windows.Forms.TabPage
$tabNet.Text = "Network Tools"

$flowNet = New-Object System.Windows.Forms.FlowLayoutPanel
$flowNet.Dock = "Top"
$flowNet.AutoSize = $true

Add-Button $flowNet "Show IP Configuration" {
    Log-Output "IP Configuration:"
    ipconfig /all | Out-String | ForEach-Object { Log-Output $_ }
}

Add-Button $flowNet "Quick Network Scan (ARP)" {
    Log-Output "Scanning local ARP table..."
    arp -a | Out-String | ForEach-Object { Log-Output $_ }
}

Add-Button $flowNet "Test Internet Connection" {
    Log-Output "Pinging Google DNS (8.8.8.8)..."
    Test-Connection -ComputerName 8.8.8.8 -Count 4 | Select-Object Address, ResponseTime, Status | Out-String | ForEach-Object { Log-Output $_ }
}

$tabNet.Controls.Add($flowNet)

# --- Tab 4: Integrations (NinjaOne) ---
$tabIntegrations = New-Object System.Windows.Forms.TabPage
$tabIntegrations.Text = "Integrations"
$tabIntegrations.Padding = New-Object System.Windows.Forms.Padding(10)

$grpNinja = New-Object System.Windows.Forms.GroupBox
$grpNinja.Text = "NinjaOne API Connection"
$grpNinja.Dock = "Top"
$grpNinja.Height = 220

# Load Settings
$savedSettings = Get-NinjaSettings

# Inputs
$lblUrl = New-Object System.Windows.Forms.Label
$lblUrl.Text = "Instance URL (e.g. app.ninjarmm.com):"
$lblUrl.Location = New-Object System.Drawing.Point(10, 25)
$lblUrl.AutoSize = $true

$txtUrl = New-Object System.Windows.Forms.TextBox
$txtUrl.Location = New-Object System.Drawing.Point(10, 45)
$txtUrl.Width = 300
$txtUrl.Text = if ($savedSettings.Url) { $savedSettings.Url } else { "app.ninjarmm.com" }

$lblCid = New-Object System.Windows.Forms.Label
$lblCid.Text = "Client ID:"
$lblCid.Location = New-Object System.Drawing.Point(10, 75)
$lblCid.AutoSize = $true

$txtCid = New-Object System.Windows.Forms.TextBox
$txtCid.Location = New-Object System.Drawing.Point(10, 95)
$txtCid.Width = 300
$txtCid.Text = if ($savedSettings.ClientId) { $savedSettings.ClientId } else { "" }

$lblSec = New-Object System.Windows.Forms.Label
$lblSec.Text = "Client Secret:"
$lblSec.Location = New-Object System.Drawing.Point(10, 125)
$lblSec.AutoSize = $true

$txtSec = New-Object System.Windows.Forms.TextBox
$txtSec.Location = New-Object System.Drawing.Point(10, 145)
$txtSec.Width = 300
$txtSec.UseSystemPasswordChar = $true
$txtSec.Text = if ($savedSettings.ClientSecret) { $savedSettings.ClientSecret } else { "" }

$btnConnect = New-Object System.Windows.Forms.Button
$btnConnect.Text = "Connect & Sync"
$btnConnect.Location = New-Object System.Drawing.Point(10, 180)
$btnConnect.Width = 100
$btnConnect.Add_Click({
    Save-NinjaSettings -Url $txtUrl.Text -Id $txtCid.Text -Secret $txtSec.Text
    Connect-NinjaOne -ClientId $txtCid.Text -ClientSecret $txtSec.Text -InstanceUrl $txtUrl.Text
})

$grpNinja.Controls.Add($lblUrl)
$grpNinja.Controls.Add($txtUrl)
$grpNinja.Controls.Add($lblCid)
$grpNinja.Controls.Add($txtCid)
$grpNinja.Controls.Add($lblSec)
$grpNinja.Controls.Add($txtSec)
$grpNinja.Controls.Add($btnConnect)

$tabIntegrations.Controls.Add($grpNinja)

# --- Tab 5: Security Audit ---
$tabAudit = New-Object System.Windows.Forms.TabPage
$tabAudit.Text = "Monthly Security Audit"

$lblAudit = New-Object System.Windows.Forms.Label
$lblAudit.Text = "Generates the 'Polar Nite' Security & Backup Audit HTML Report."
$lblAudit.AutoSize = $true
$lblAudit.Dock = "Top"
$lblAudit.Padding = New-Object System.Windows.Forms.Padding(10)

$btnRunAudit = New-Object System.Windows.Forms.Button
$btnRunAudit.Text = "Generate Audit Report"
$btnRunAudit.Height = 50
$btnRunAudit.Dock = "Top"
$btnRunAudit.Add_Click({
    Log-Output "Starting Security Audit..."
    Invoke-SecurityAudit
})

$tabAudit.Controls.Add($btnRunAudit)
$tabAudit.Controls.Add($lblAudit)


# --- Output Console ---
$groupBoxOutput = New-Object System.Windows.Forms.GroupBox
$groupBoxOutput.Text = "Output Log"
$groupBoxOutput.Dock = "Bottom"
$groupBoxOutput.Height = 250

$txtOutput = New-Object System.Windows.Forms.TextBox
$txtOutput.Multiline = $true
$txtOutput.ScrollBars = "Vertical"
$txtOutput.ReadOnly = $true
$txtOutput.Dock = "Fill"
$txtOutput.Font = New-Object System.Drawing.Font("Consolas", 9)
$txtOutput.BackColor = "Black"
$txtOutput.ForeColor = "Lime"

$groupBoxOutput.Controls.Add($txtOutput)

# --- Assemble Form ---
$tabControl.Controls.Add($tabFixes)
$tabControl.Controls.Add($tabInfo)
$tabControl.Controls.Add($tabNet)
$tabControl.Controls.Add($tabIntegrations)
$tabControl.Controls.Add($tabAudit)

$form.Controls.Add($tabControl)
$form.Controls.Add($groupBoxOutput)

# --- Logging Function ---
function Log-Output($message) {
    $txtOutput.AppendText("[$((Get-Date).ToString('HH:mm:ss'))] $message`r`n")
    $txtOutput.SelectionStart = $txtOutput.Text.Length
    $txtOutput.ScrollToCaret()
    $form.Refresh()
}

# --- NinjaOne Integration Functions ---
$global:NinjaToken = $null
$global:NinjaInstance = $null
$global:NinjaDeviceData = $null

function Get-NinjaSettings {
    $configDir = "$env:APPDATA\WinFixTool"
    $configPath = "$configDir\ninja_config.xml"
    if (Test-Path $configPath) {
        try {
            return Import-Clixml $configPath
        } catch {
            Log-Output "Could not load saved settings."
        }
    }
    return $null
}

function Save-NinjaSettings {
    param($Url, $Id, $Secret)
    $configDir = "$env:APPDATA\WinFixTool"
    if (-not (Test-Path $configDir)) { New-Item -ItemType Directory -Path $configDir -Force | Out-Null }
    $configPath = "$configDir\ninja_config.xml"
    
    $settings = [PSCustomObject]@{
        Url = $Url
        ClientId = $Id
        ClientSecret = $Secret
    }
    $settings | Export-Clixml -Path $configPath
    Log-Output "Settings saved securely."
}

function Connect-NinjaOne {
    param($ClientId, $ClientSecret, $InstanceUrl)
    
    Log-Output "Connecting to NinjaOne ($InstanceUrl)..."
    $tokenUrl = "https://$InstanceUrl/v2/oauth/token"
    $body = @{
        grant_type = "client_credentials"
        client_id = $ClientId
        client_secret = $ClientSecret
        scope = "monitoring management" 
    }
    
    try {
        $response = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $body -ErrorAction Stop
        $global:NinjaToken = $response.access_token
        $global:NinjaInstance = $InstanceUrl
        Log-Output "Successfully connected to NinjaOne!"
        
        # Auto-fetch device data
        Get-NinjaDeviceData
    } catch {
        Log-Output "Failed to connect to NinjaOne: $($_.Exception.Message)"
        if ($_.ErrorDetails) { Log-Output "Details: $($_.ErrorDetails.Message)" }
    }
}

function Get-NinjaDeviceData {
    if (-not $global:NinjaToken) { Log-Output "Not connected to NinjaOne."; return }
    
    Log-Output "Searching for this device in NinjaOne..."
    $headers = @{ Authorization = "Bearer $global:NinjaToken" }
    
    # Search for device by serial number or hostname
    $serial = (Get-CimInstance Win32_Bios).SerialNumber
    $hostname = $env:COMPUTERNAME
    
    try {
        # Try searching by Serial first
        $searchUrl = "https://$($global:NinjaInstance)/v2/devices?df=serialNumber:$serial"
        $devices = Invoke-RestMethod -Uri $searchUrl -Headers $headers -ErrorAction Stop
        
        if (-not $devices) {
             # Fallback to hostname
             Log-Output "Serial search failed, trying hostname..."
             $searchUrl = "https://$($global:NinjaInstance)/v2/devices?df=systemName:$hostname"
             $devices = Invoke-RestMethod -Uri $searchUrl -Headers $headers -ErrorAction Stop
        }
        
        if ($devices) {
            $global:NinjaDeviceData = $devices[0] # Take first match
            Log-Output "Device found: $($global:NinjaDeviceData.systemName) (ID: $($global:NinjaDeviceData.id))"
            Log-Output "Organization: $($global:NinjaDeviceData.organizationId)"
            Log-Output "Last Contact: $($global:NinjaDeviceData.lastContact)"
        } else {
            Log-Output "Device not found in NinjaOne."
        }
    } catch {
        Log-Output "Error fetching device data: $($_.Exception.Message)"
    }
}

# --- SECURITY AUDIT LOGIC (Embedded) ---
function Invoke-SecurityAudit {
    # This function contains the logic provided by the user
    
    Log-Output "Initializing Polar Nite Audit..."
    
    # --- Configuration & Path Robustness ---
    # Robustly find the Desktop path (handles OneDrive redirection)
    $DesktopPath = [Environment]::GetFolderPath("Desktop")
    if (-not (Test-Path $DesktopPath)) { $DesktopPath = $env:TEMP } # Fallback to Temp if Desktop fails

    $ReportPath = Join-Path -Path $DesktopPath -ChildPath "PolarNite_SecurityAudit_$(Get-Date -Format 'yyyyMMdd_HHmm').html"
    $EventLookbackDays = 30
    $MaxEventsToShow = 15

    # --- Styling & Scripting (Polar Nite - Light Theme) ---
    $style = @"
    <style>
        :root {
            --bg-color: #f4f7f6;
            --card-bg: #ffffff;
            --text-main: #2c3e50;
            --accent-cyan: #0056b3; 
            --accent-blue: #3498db;
            --alert: #e74c3c;
            --good: #27ae60;
            --warn: #f39c12;
            --manual: #7f8c8d;
        }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: var(--bg-color); color: var(--text-main); margin: 0; padding: 20px; padding-bottom: 80px; }
        
        /* Header Block */
        .header-block { border-bottom: 3px solid var(--accent-cyan); margin-bottom: 30px; padding-bottom: 10px; }
        h1 { color: var(--accent-cyan); text-transform: uppercase; letter-spacing: 1px; margin: 0; font-size: 1.8em; }
        .meta-info { display: flex; justify-content: space-between; margin-top: 15px; font-weight: bold; color: #555; align-items: center; }
        
        /* Section Headers */
        h2 { 
            background-color: #e8f4f8; 
            color: var(--accent-cyan); 
            padding: 10px; 
            margin-top: 40px; 
            font-size: 1.2em; 
            border-top: 3px solid var(--accent-cyan);
            font-weight: bold;
        }
        h3 { color: var(--accent-cyan); margin-top: 20px; border-left: 4px solid var(--accent-blue); padding-left: 10px; font-size: 1.1em; }
        
        /* Tables */
        table { border-collapse: collapse; width: 100%; margin-bottom: 15px; background-color: var(--card-bg); box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #ecf0f1; vertical-align: top; }
        th { background-color: #ecf0f1; color: var(--text-main); font-weight: 700; width: 45%; }
        
        /* Inputs & Interactivity */
        .user-input {
            border: 1px solid #bdc3c7;
            padding: 5px;
            border-radius: 4px;
            width: 90%;
            font-family: inherit;
            background-color: #fafafa;
            color: #333; 
        }
        .user-input:focus { outline: 2px solid var(--accent-blue); background-color: #fff; }
        
        .user-select {
            border: 1px solid #bdc3c7;
            padding: 5px;
            border-radius: 4px;
            background-color: #fafafa;
            font-weight: bold;
            color: #333; 
        }
        
        /* Copy Button */
        .copy-btn {
            background-color: var(--accent-cyan);
            color: white; 
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            box-shadow: 0 4px 6px rgba(0,0,0,0.2);
            transition: background 0.2s;
        }
        .copy-btn:hover { background-color: var(--accent-blue); }
        
        .floating-action {
            position: fixed;
            bottom: 30px;
            right: 30px;
            z-index: 1000;
        }

        /* Status Colors */
        .alert { color: var(--alert); font-weight: bold; }
        .good { color: var(--good); font-weight: bold; }
        .warning { color: var(--warn); font-weight: bold; }
        
        /* AI Link */
        .ai-link {
            display: inline-block;
            margin-top: 5px;
            color: var(--accent-cyan);
            font-weight: bold;
            text-decoration: none;
            font-size: 0.85em;
            border: 1px solid var(--accent-blue);
            padding: 2px 6px;
            border-radius: 4px;
            background-color: white;
        }
    </style>

    <script>
        // --- Backup Knowledge Base (Hard-coded Standards) ---
        const backupDefaults = {
            "Datto": { enc: "AES-256 (Datto Default)", rest: "Yes", transit: "Yes (TLS/SSL)" },
            "Veeam": { enc: "AES-256 (Industry Standard)", rest: "Yes", transit: "Yes (TLS/SSL)" },
            "Ninja": { enc: "AES-256 (Ninja Backup)", rest: "Yes", transit: "Yes (TLS/SSL)" },
            "Acronis": { enc: "AES-256 (Acronis Cyber)", rest: "Yes", transit: "Yes (TLS/SSL)" },
            "Macrium": { enc: "AES-256 (Optional)", rest: "Yes", transit: "Yes (TLS/SSL)" },
            "Carbonite": { enc: "AES-256/Blowfish", rest: "Yes", transit: "Yes (TLS/SSL)" },
            "CrashPlan": { enc: "AES-256", rest: "Yes", transit: "Yes (TLS/SSL)" },
            "Veritas": { enc: "AES-128/256", rest: "Yes", transit: "Yes" },
            "Windows Server Backup": { enc: "None (Unless BitLocker used)", rest: "No", transit: "N/A" }
        };

        function updateBackupDefaults(selectElem) {
            const selected = selectElem.value;
            // Simple fuzzy match to find vendor in selection
            let key = Object.keys(backupDefaults).find(k => selected.includes(k));
            
            if (key && backupDefaults[key]) {
                const def = backupDefaults[key];
                document.getElementById('backupEncStd').value = def.enc;
                document.getElementById('backupEncRest').value = def.rest;
                document.getElementById('backupEncTransit').value = def.transit;
                
                // Visual feedback
                selectElem.style.borderColor = '#27ae60';
                document.getElementById('backupEncStd').style.borderColor = '#27ae60';
                setTimeout(() => {
                    selectElem.style.borderColor = '#bdc3c7';
                    document.getElementById('backupEncStd').style.borderColor = '#bdc3c7';
                }, 1000);
            }
        }

        function copyReport() {
            var originalInputs = document.querySelectorAll('input, textarea, select');
            var clone = document.body.cloneNode(true);
            var buttons = clone.querySelectorAll('.copy-btn, .floating-action');
            buttons.forEach(b => b.remove());

            // 1. Snapshot Live Inputs
            var cloneInputs = clone.querySelectorAll('input, textarea, select');
            for (var i = 0; i < originalInputs.length; i++) {
                var original = originalInputs[i];
                var cloneEl = cloneInputs[i];
                var val = "";
                
                if (original.tagName === 'SELECT') {
                    if (original.selectedIndex >= 0) val = original.options[original.selectedIndex].text;
                    else val = "Select...";
                } else { val = original.value; }

                if (!val) val = "N/A";

                var span = document.createElement('span');
                span.textContent = val;
                span.style.fontWeight = 'bold';
                
                if(val === 'No' || val === 'Failed' || val === 'Non-Compliant') span.style.color = '#e74c3c';
                else if(val === 'Yes' || val === 'Success' || val === 'Compliant' || val === 'Enabled') span.style.color = '#27ae60';
                else span.style.color = '#333';
                
                if (cloneEl && cloneEl.parentNode) cloneEl.parentNode.replaceChild(span, cloneEl);
            }

            // 2. TICKET MODE TRANSFORMATION
            var container = document.createElement('div');
            container.style.fontFamily = "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif";
            container.style.fontSize = "13px";
            container.style.lineHeight = "1.4";
            container.style.color = "#333";
            container.style.maxWidth = "600px";
            container.innerHTML = clone.innerHTML;

            // Simplify Headers
            container.querySelectorAll('h1').forEach(h => { h.style.fontSize="18px"; h.style.marginBottom="10px"; h.style.color="#0056b3"; });
            container.querySelectorAll('h2').forEach(h => { 
                h.style.fontSize="15px"; 
                h.style.backgroundColor="#e8f4f8"; 
                h.style.color="#0056b3"; 
                h.style.padding="5px"; 
                h.style.marginTop="20px";
                h.style.borderTop="2px solid #0056b3";
            });
            container.querySelectorAll('h3').forEach(h => { h.style.fontSize="14px"; h.style.marginTop="10px"; h.style.color="#0056b3"; });

            // Transform Wide Tables to Vertical Stacks
            var tables = container.querySelectorAll('table');
            tables.forEach(table => {
                var firstRow = table.querySelector('tr');
                var isFormTable = false;
                // Check if it's a "Label | Value" form table
                if (firstRow && firstRow.children.length === 2 && firstRow.children[0].tagName === 'TH') isFormTable = true;

                if (isFormTable) {
                    var listBlock = document.createElement('div');
                    listBlock.style.marginBottom = "15px";
                    
                    table.querySelectorAll('tr').forEach(row => {
                        var th = row.querySelector('th');
                        var td = row.querySelector('td');
                        if (th && td) {
                            var item = document.createElement('div');
                            item.style.marginBottom = "6px";
                            item.style.borderBottom = "1px solid #eee";
                            item.style.paddingBottom = "4px";

                            var label = th.textContent.trim();
                            if (!label.match(/[:?]$/)) label += ":";

                            item.innerHTML = "<strong style='color:#444;'>" + label + "</strong> <span style='margin-left:5px;'>" + td.innerHTML + "</span>";
                            listBlock.appendChild(item);
                        } else if (row.cells.length === 1) {
                            // Full width rows (Notes)
                            var item = document.createElement('div');
                            item.innerHTML = row.cells[0].innerHTML;
                            listBlock.appendChild(item);
                        }
                    });
                    if (table.parentNode) table.parentNode.replaceChild(listBlock, table);
                } else {
                    // Data Tables (Events, etc.) - Keep as table but compact
                    table.style.width = "100%";
                    table.style.border = "1px solid #ddd";
                    table.style.borderCollapse = "collapse";
                    table.querySelectorAll('th, td').forEach(c => {
                        c.style.padding = "4px";
                        c.style.border = "1px solid #ddd";
                        c.style.fontSize = "12px";
                    });
                }
            });

            // Flatten Meta Info
            container.querySelectorAll('.meta-info').forEach(meta => {
                var newMeta = document.createElement('div');
                newMeta.style.marginBottom = "10px";
                newMeta.style.color = "#666";
                meta.querySelectorAll('span').forEach(s => {
                    var p = document.createElement('div');
                    p.innerHTML = s.innerHTML;
                    newMeta.appendChild(p);
                });
                meta.parentNode.replaceChild(newMeta, meta);
            });

            // Copy
            var tempDiv = document.createElement('div');
            tempDiv.style.position = 'absolute';
            tempDiv.style.left = '-9999px';
            tempDiv.appendChild(container);
            document.body.appendChild(tempDiv);

            var range = document.createRange();
            range.selectNodeContents(tempDiv);
            var selection = window.getSelection();
            selection.removeAllRanges();
            selection.addRange(range);
            
            try {
                document.execCommand('copy');
                alert('Report Copied! Formatted for Ticket System (Vertical Layout).');
            } catch (err) {
                alert('Copy failed.');
            }

            document.body.removeChild(tempDiv);
            selection.removeAllRanges();
        }
    </script>
"@

    # --- Helper Functions ---
    function Get-EventSolution {
        param($Source, $Message)
        $predefined = @{
            "Disk" = "Check physical drive health (SMART)."; "Ntfs" = "File system corruption."; 
            "VSS" = "VSS Shadow Copy error."; "WindowsUpdate" = "Check Update Service."; 
            "BugCheck" = "BSOD detected."
        }
        foreach ($key in $predefined.Keys) { if ($Source -match $key) { return $predefined[$key] } }
        return "Check Event ID."
    }

    function Get-HtmlInput {
        param($Placeholder="Enter details...", $Value="", $Id="")
        $idAttr = if ($Id) { "id='$Id'" } else { "" }
        return "<input type='text' $idAttr class='user-input' placeholder='$Placeholder' value='$Value'>"
    }

    function Get-HtmlSelect {
        param($Options=@("Select...", "Yes", "No", "N/A"), $SelectedValue="", $Id="", $OnChange="")
        $idAttr = if ($Id) { "id='$Id'" } else { "" }
        $changeAttr = if ($OnChange) { "onchange='$OnChange'" } else { "" }
        $optHtml = ""
        # Ensure N/A is always an option if not explicitly excluded
        if (-not ($Options -contains "N/A")) { $Options += "N/A" }
        
        foreach($opt in $Options) { 
            $sel = if($opt -eq $SelectedValue){ "selected" } else { "" }
            $optHtml += "<option value='$opt' $sel>$opt</option>" 
        }
        return "<select class='user-select' $idAttr $changeAttr>$optHtml</select>"
    }

    function Get-HtmlTextArea {
        return "<textarea class='user-input' rows='3' placeholder='Enter details...'></textarea>"
    }

    Log-Output "Initializing Polar Nite Audit..."

    # --- DATA GATHERING & AUTOMATION ---

    # 0. Server Info
    Log-Output "[-] Gathering System Info..."
    $CompInfo = Get-CimInstance Win32_ComputerSystem
    $OSInfo = Get-CimInstance Win32_OperatingSystem
    $AdminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue

    # New: Uptime
    $Uptime = (Get-Date) - $OSInfo.LastBootUpTime
    $UptimeStr = "{0} Days, {1} Hours" -f $Uptime.Days, $Uptime.Hours

    # New: VM Detection
    $IsVM = ($CompInfo.Model -match "Virtual" -or $CompInfo.Model -match "VMware" -or $CompInfo.Manufacturer -match "Microsoft Corporation" -and $CompInfo.Model -match "Virtual")

    # New: End of Support Check
    $EOSWarning = ""
    $OSName = $OSInfo.Caption
    if ($OSName -match "Server 2003|Server 2008|Server 2012|Windows 7|Windows 8|Windows 10|SBS 2011|Windows XP|Vista") {
        $EOSWarning = "<span style='color:#dc3545; font-weight:bold; margin-left:10px;'> [WARNING: OS End of Support - Security Risk]</span>"
    }

    # New: Server Roles Auto-Detection (Server OS Only)
    $DetectedRoles = ""
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        try {
            $Feats = Get-WindowsFeature | Where-Object { $_.Installed -eq $True -and $_.FeatureType -eq 'Role' }
            if ($Feats) { $DetectedRoles = ($Feats.Name -join ", ") }
        } catch {
            $DetectedRoles = "Could not query roles"
        }
    } else {
        $DetectedRoles = "Workstation / Roles Not Available"
    }

    # 1. Backups
    Log-Output "[-] Checking Backup History..."
    $BackupKeywords = "*Veeam*","*Acronis*","*Macrium*","*Datto*","*Carbonite*","*Veritas*","*CrashPlan*","*Ninja*"
    $DetectedServices = Get-Service | Where-Object { $d = $_.DisplayName; ($BackupKeywords | Where-Object { $d -like $_ }) }

    # Build Backup Options Array
    $BackupOptions = @("Select...")
    if ($DetectedServices) {
        foreach ($svc in $DetectedServices) { $BackupOptions += "[DETECTED] $($svc.DisplayName)" }
        $BackupOptions += "----------------"
    }
    $BackupOptions += @("Datto", "Veeam", "Ninja Backup", "Acronis", "Macrium", "Carbonite", "CrashPlan", "Windows Server Backup", "Other (Manual)")

    $WinBackup = Get-WinEvent -LogName "Microsoft-Windows-Backup" -MaxEvents 1 -ErrorAction SilentlyContinue

    # Smart Backup Logic (Windows Native)
    $BackupSuccessSel = "Select..."
    $LastBackupTime = ""
    $BackupFailedSel = "Select..."
    if ($WinBackup) {
        if ($WinBackup.Id -eq 4) { $BackupSuccessSel = "Yes"; $BackupFailedSel = "No"; $LastBackupTime = $WinBackup.TimeCreated.ToString("yyyy-MM-dd HH:mm") }
        else { $BackupSuccessSel = "No"; $BackupFailedSel = "Yes"; $LastBackupTime = "Failed at " + $WinBackup.TimeCreated.ToString("yyyy-MM-dd HH:mm") }
    }

    # Ninja Backup Override
    if ($global:NinjaDeviceData -and $global:NinjaDeviceData.lastBackupJobStatus) {
        $BackupSuccessSel = if ($global:NinjaDeviceData.lastBackupJobStatus -eq 'SUCCESS') { "Yes" } else { "No" }
        $LastBackupTime = "Check Ninja Dashboard"
        if ($global:NinjaDeviceData.lastBackupJobStatus -ne 'SUCCESS') { $BackupFailedSel = "Yes" }
    }

    # 2. Security & Patching
    Log-Output "[-] Auditing Security & Updates..."
    $AV = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue
    # Windows Updates (COM)
    $MissingUpdatesCount = 0
    $MissingUpdatesHTML = ""
    try {
        $UpdateSession = New-Object -ComObject Microsoft.Update.Session
        $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
        $SearchResult = $UpdateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
        $MissingUpdatesCount = $SearchResult.Updates.Count
        if ($MissingUpdatesCount -gt 0) {
            foreach ($u in $SearchResult.Updates) {
                $uQuery = [uri]::EscapeDataString("Windows Update $($u.Title) problems")
                $MissingUpdatesHTML += "<li>$($u.Title) (<a href='https://www.google.com/search?q=$uQuery' target='_blank' class='ai-link'>Analyze</a>)</li>"
            }
        }
    } catch { $MissingUpdatesHTML = "Error querying Windows Update." }

    # Ninja Patch Override
    if ($global:NinjaDeviceData -and $global:NinjaDeviceData.osPatchStatus) {
        $pStatus = $global:NinjaDeviceData.osPatchStatus
        if ($pStatus.failed -gt 0 -or $pStatus.pending -gt 0) {
             $MissingUpdatesCount = $pStatus.failed + $pStatus.pending
             $MissingUpdatesHTML += "<li>Ninja Reports: $($pStatus.failed) Failed, $($pStatus.pending) Pending</li>"
        }
    }

    # Smart Update Logic (Last Hotfix + Pending Reboot)
    $LastHotFix = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
    $LastUpdateDate = if ($LastHotFix) { $LastHotFix.InstalledOn.ToString('yyyy-MM-dd') } else { "" }

    # Check Pending Reboot
    $PendingReboot = $false
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") { $PendingReboot = $true }
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") { $PendingReboot = $true }
    $UpdateNote = if ($PendingReboot) { "<span class='alert'><b>(Reboot Pending)</b></span>" } else { "" }


    # Smart Defender Logic
    $Defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
    $RTPEnabled = "Select..."
    $LastScanDate = ""
    if ($Defender) {
        $RTPEnabled = if ($Defender.RealTimeProtectionEnabled) { "Yes" } else { "No" }
        $LastScanDate = if ($Defender.QuickScanEndTime) { $Defender.QuickScanEndTime.ToString("yyyy-MM-dd") } else { "Never" }
    }

    # Ninja AV Override
    if ($global:NinjaDeviceData -and $global:NinjaDeviceData.antivirusStatus) {
        $avStat = $global:NinjaDeviceData.antivirusStatus
        if ($avStat.protectionStatus -eq 'ENABLED') { $RTPEnabled = "Yes" }
        if ($avStat.productName) { $AV = [PSCustomObject]@{ displayName = $avStat.productName } }
    }

    # Smart User Logic
    $LocalUsers = Get-LocalUser | Select-Object Name, Enabled, PasswordLastSet
    $DisabledUsers = $LocalUsers | Where-Object { $_.Enabled -eq $false }
    $DisabledUsersSel = if ($DisabledUsers) { "Yes" } else { "No" }

    # Smart Admin Password Last Set & Age Check
    $AdminPassLastSet = "Unknown / Domain Account"
    $AdminPassChangedRegularly = "Select..."
    try {
        $BuiltInAdmin = Get-LocalUser | Where-Object SID -like "*-500" -ErrorAction Stop
        if ($BuiltInAdmin) {
            $AdminPassLastSet = $BuiltInAdmin.PasswordLastSet.ToString("yyyy-MM-dd")
            $DaysSinceChange = (New-TimeSpan -Start $BuiltInAdmin.PasswordLastSet -End (Get-Date)).Days
            if ($DaysSinceChange -gt 90) { 
                $AdminPassChangedRegularly = "No" 
                $AdminPassLastSet += " ($DaysSinceChange days ago)"
            } else {
                $AdminPassChangedRegularly = "Yes"
            }
        }
    } catch {
        $AdminPassLastSet = "N/A (See AD)"
    }

    # Smart Password Policy (SecEdit)
    $PassComplexSel = "Select..."
    $PassInfoStr = ""
    try {
        $SecEditFile = "$env:TEMP\secpol.cfg"
        secedit /export /cfg $SecEditFile /quiet
        $SecPol = Get-Content $SecEditFile
        
        # Complexity
        if ($SecPol -match "PasswordComplexity\s*=\s*1") { 
            $PassComplexSel = "Yes" 
            $PassInfoStr += "Complexity: Enabled. "
        } elseif ($SecPol -match "PasswordComplexity\s*=\s*0") {
            $PassComplexSel = "No"
            $PassInfoStr += "Complexity: Disabled. "
        }

        # Length
        if ($SecPol -match "MinimumPasswordLength\s*=\s*(\d+)") {
            $PassInfoStr += "Min Length: $($matches[1])."
        }
        
        Remove-Item $SecEditFile -ErrorAction SilentlyContinue
    } catch {
        $PassInfoStr = "Could not verify local policy."
    }

    # 3. Encryption (BitLocker)
    Log-Output "[-] Checking Encryption..."
    $TPM = Get-Tpm -ErrorAction SilentlyContinue
    $BitLocker = if (Get-Command "Get-BitLockerVolume" -ErrorAction SilentlyContinue) { Get-BitLockerVolume -ErrorAction SilentlyContinue } else { $null }

    # Smart BitLocker Logic
    $BitLockerSel = "Select..."
    $BitLockerReason = ""
    if ($BitLocker -and ($BitLocker | Where-Object ProtectionStatus -eq 'On')) {
        $BitLockerSel = "Yes"
        $BitLockerStatus = ($BitLocker | ForEach-Object { "$($_.MountPoint) [$($_.ProtectionStatus)]" }) -join ", "
    } else {
        $BitLockerStatus = "Not Encrypted"
        if ($IsVM) {
            $BitLockerSel = "N/A"
            $BitLockerReason = "Virtual Machine"
        } else {
            $BitLockerSel = "No"
            $BitLockerReason = "Physical Server - No Encryption Detected"
        }
    }

    # 4. Firewall & RDP
    Log-Output "[-] Auditing Network & RDP..."
    $Firewall = Get-NetFirewallProfile | Where-Object Enabled -eq True
    $RDPReg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue

    # Smart RDP Logic
    $RDPVPNSel = "Select..."
    $RDPMFASel = "Select..."
    $RDPExternalSel = "Select..."
    $RDPFailSel = "Select..."
    $RDPFailCount = 0

    if ($RDPReg.fDenyTSConnections -ne 0) { 
        # RDP Disabled
        $RDPStatus = "<span class='good'>Disabled</span>"
        $RDPVPNSel = "N/A"
        $RDPMFASel = "N/A"
        $RDPExternalSel = "N/A"
        $RDPFailSel = "N/A"
    } else {
        # RDP Enabled
        $RDPStatus = "<span class='warning'>Enabled (Open)</span>"
        # RDP Failure Scan (Security Log ID 4625)
        $RDPFailures = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-30)} -ErrorAction SilentlyContinue
        $RDPFailCount = if ($RDPFailures) { $RDPFailures.Count } else { 0 }
        $RDPFailSel = if ($RDPFailCount -gt 0) { "Yes" } else { "No" }
        
        # Default assumptions for active RDP (Safe default)
        $RDPExternalSel = "No" 
    }

    # New: Listening Ports for Inbound Review
    $OpenPortsStr = ""
    try {
        $OpenPorts = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LocalPort -Unique | Sort-Object { [int]$_ }
        if ($OpenPorts) { $OpenPortsStr = "Open Ports: " + ($OpenPorts -join ", ") }
    } catch {}

    # 5. Logs & Hardware
    Log-Output "[-] Analyzing Logs & Health..."
    $LogSettings = Get-EventLog -List | Where-Object { $_.Log -eq 'Security' }
    $Events = Get-WinEvent -FilterHashtable @{LogName='System','Application'; Level=1,2; StartTime=(Get-Date).AddDays(-$EventLookbackDays)} -ErrorAction SilentlyContinue | Select-Object -First $MaxEventsToShow

    # App Error Scan
    $AppErrors = Get-WinEvent -FilterHashtable @{LogName='Application'; Level=2; StartTime=(Get-Date).AddDays(-30)} -ErrorAction SilentlyContinue | Select-Object -First 1
    $AppErrorSel = if ($AppErrors) { "Yes" } else { "No" }

    # New: Database Error Scan (SQL/MySQL/Oracle keywords)
    $DBErrors = Get-WinEvent -FilterHashtable @{LogName='Application'; Level=1,2; ProviderName='*SQL*','*Database*','*MySQL*','*Oracle*'} -MaxEvents 1 -ErrorAction SilentlyContinue
    $DBErrorSel = if ($DBErrors) { "Yes" } else { "No" }

    # Physical Disk Health & Space Check
    $Disks = Get-PhysicalDisk | Select-Object FriendlyName, MediaType, HealthStatus -ErrorAction SilentlyContinue
    $DiskHealthStr = if ($Disks) { ($Disks | ForEach-Object { "$($_.MediaType) ($($_.HealthStatus))" }) -join "; " } else { "Unknown" }

    # Smart Disk Space Check (C: Drive)
    $StorageWarning = ""
    try {
        $CDrive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
        $FreePct = [math]::Round(($CDrive.FreeSpace / $CDrive.Size) * 100, 1)
        if ($FreePct -lt 15) {
            $StorageWarning = "Low Disk Space on C: ($FreePct% Free)"
        }
    } catch {}

    # Ninja Extra Data Integration
    $ClientNameVal = ""
    $LocationDefault = ""
    if ($global:NinjaDeviceData) {
        if ($global:NinjaDeviceData.organizationId) { $ClientNameVal = "Ninja Org ID: $($global:NinjaDeviceData.organizationId)" }
        if ($global:NinjaDeviceData.locationId) { $LocationDefault += " (Ninja Loc: $($global:NinjaDeviceData.locationId))" }
        if ($global:NinjaDeviceData.publicIP) { $OpenPortsStr += " [Public IP: $($global:NinjaDeviceData.publicIP)]" }
    }

    # --- HTML GENERATION ---

    $HTMLBody = @"
    <div class='header-block'>
        <div style='display:flex; justify-content:space-between; align-items:flex-start;'>
            <div>
                <h1>Internal Server Security & Backup Audit Form</h1>
                <div class='meta-info'>
                    <span>Client: $(Get-HtmlInput "Client Name" -Value $ClientNameVal)</span>
                    <span style='margin-left:20px;'>Audit Month: $(Get-HtmlInput "e.g. October" -Value "$(Get-Date -Format 'MMMM')")</span>
                    <span style='margin-left:20px;'>Completed By: $env:USERNAME</span>
                </div>
                <div style='margin-top:5px; font-size:0.85em; color:#666;'>Uptime: $UptimeStr</div>
            </div>
            <button onclick="copyReport()" class="copy-btn">Copy to Clipboard</button>
        </div>
    </div>

    <h3>Server Identifying Information</h3>
    <table>
        <tr><th>Server Name</th><td>$($CompInfo.Name)</td></tr>
        <tr><th>Location (onsite/offsite)</th><td>$(Get-HtmlInput "e.g., Server Closet" -Value $LocationDefault)</td></tr>
        <tr><th>OS Version</th><td>$($OSInfo.Caption) (Build $($OSInfo.BuildNumber)) $EOSWarning</td></tr>
        <tr><th>Role(s)</th><td>$(Get-HtmlInput "e.g., DC, Database" -Value $DetectedRoles)</td></tr>
        <tr><th>Who has administrative access?</th><td><ul>$($AdminGroup.Name | ForEach-Object { "<li>$_</li>" })</ul></td></tr>
    </table>

    <h2>1. Backup & Data Retention (HIPAA §164.308(a)(7))</h2>
    <h3>A. Backup System Review</h3>
    <table>
        <tr><th>Backup solution used</th><td>
            $(Get-HtmlSelect -Options $BackupOptions -OnChange "updateBackupDefaults(this)")
            <br><small>Select to auto-fill encryption defaults.</small>
        </td></tr>
        <tr><th>Are backups completing successfully?</th><td>
            $(Get-HtmlSelect @("Select...", "Yes", "No", "N/A") -SelectedValue $BackupSuccessSel)
            $(if($WinBackup){ "<br><small>WinBackup Result: " + $WinBackup.Result + "</small>" })
        </td></tr>
        <tr><th>Last successful backup date & time</th><td>$(Get-HtmlInput "YYYY-MM-DD HH:MM" -Value $LastBackupTime)</td></tr>
        <tr><th>Backup frequency (hourly/daily)</th><td>$(Get-HtmlInput "e.g., Hourly")</td></tr>
        <tr><th>Are there any failed backups this month?</th><td>$(Get-HtmlSelect @("Select...", "Yes", "No", "N/A") -SelectedValue $BackupFailedSel)</td></tr>
    </table>

    <h3>B. Backup Encryption</h3>
    <table>
        <tr><th>Are backups encrypted at rest?</th><td>$(Get-HtmlSelect -Id "backupEncRest")</td></tr>
        <tr><th>Encryption standard used</th><td>$(Get-HtmlInput "AES-256 preferred" -Id "backupEncStd")</td></tr>
        <tr><th>Are backup transfer channels encrypted?</th><td>$(Get-HtmlSelect -Options @("Select...","Yes (TLS/SSL)","No","Other","N/A") -Id "backupEncTransit")</td></tr>
    </table>

    <h3>C. Backup Retention</h3>
    <table>
        <tr><th>Retention period</th><td>$(Get-HtmlInput "days/weeks/months/years")</td></tr>
        <tr><th>Does retention meet HIPAA’s 6-year requirement?</th><td>$(Get-HtmlSelect)</td></tr>
    </table>

    <h3>D. Restore Testing</h3>
    <table>
        <tr><th>Was a test restore performed in the last 90 days?</th><td>$(Get-HtmlSelect)</td></tr>
        <tr><th>Date of last verification restore</th><td>$(Get-HtmlInput "YYYY-MM-DD")</td></tr>
        <tr><th>Result</th><td>$(Get-HtmlInput "Successful / Issues found")</td></tr>
    </table>

    <h2>2. Server Security & Patch Compliance (HIPAA §164.308(a)(1), §164.312(c))</h2>
    <h3>A. Update Status</h3>
    <table>
        <tr><th>Are Windows Updates current?</th><td>$(if($MissingUpdatesCount -eq 0){"<span class='good'>Yes</span>"}else{"<span class='alert'>No ($MissingUpdatesCount Pending)</span>"}) $UpdateNote</td></tr>
        <tr><th>Last update date</th><td>$(Get-HtmlInput "Check Update History" -Value $LastUpdateDate)</td></tr>
        <tr><th>Pending patches?</th><td><ul>$MissingUpdatesHTML</ul></td></tr>
    </table>

    <h3>B. Antivirus / EDR</h3>
    <table>
        <tr><th>AV/EDR installed</th><td>$(if($AV){$AV.displayName}else{"<span class='alert'>None Detected</span>"})</td></tr>
        <tr><th>Real-time protection enabled?</th><td>$(Get-HtmlSelect @("Select...", "Yes", "No", "N/A") -SelectedValue $RTPEnabled)</td></tr>
        <tr><th>Last scan date</th><td>$(Get-HtmlInput "YYYY-MM-DD" -Value $LastScanDate)</td></tr>
        <tr><th>Any detections this month?</th><td>$(Get-HtmlSelect) $(Get-HtmlInput "Attach or summarize if yes")</td></tr>
    </table>

    <h3>C. Local User Accounts</h3>
    <table>
        <tr><th>List all local server accounts</th><td><ul>$((Get-LocalUser).Name | ForEach-Object{"<li>$_</li>"})</ul></td></tr>
        <tr><th>Any accounts without MFA?</th><td>$(Get-HtmlSelect)</td></tr>
        <tr><th>Any disabled but unremoved accounts?</th><td>$(Get-HtmlSelect @("Select...", "Yes", "No", "N/A") -SelectedValue $DisabledUsersSel) $(if($DisabledUsers){ "<br><small>Disabled: " + ($DisabledUsers.Name -join ", ") + "</small>" })</td></tr>
        <tr><th>Any unexpected accounts?</th><td>$(Get-HtmlSelect) $(Get-HtmlInput "Document if yes")</td></tr>
    </table>

    <h3>D. Administrator Access</h3>
    <table>
        <tr><th>Who has administrative credentials</th><td>(See Server Info Header)</td></tr>
        <tr><th>Are admin passwords changed regularly?</th><td>$(Get-HtmlSelect @("Select...", "Yes", "No", "N/A") -SelectedValue $AdminPassChangedRegularly) <br><small>Last Set: $AdminPassLastSet</small></td></tr>
        <tr><th>Is password complexity enforced?</th><td>$(Get-HtmlSelect @("Select...", "Yes", "No", "N/A") -SelectedValue $PassComplexSel) <small>$PassInfoStr</small></td></tr>
        <tr><th>Are there any shared admin accounts?</th><td>$(Get-HtmlSelect) $(Get-HtmlInput "Document if yes")</td></tr>
    </table>

    <h2>3. Server Encryption (HIPAA §164.312(a)(2)(iv))</h2>
    <h3>A. Disk Encryption</h3>
    <table>
        <tr><th>Is full-disk encryption enabled?</th><td>
            $(Get-HtmlSelect @("Select...", "Yes", "No", "N/A") -SelectedValue $BitLockerSel)
            $(if(-not $BitLocker){"<span class='warning'>(BitLocker cmdlets not available)</span>"})
        </td></tr>
        <tr><th>Encryption status</th><td>$(Get-HtmlInput "e.g. Encrypted" -Value $BitLockerStatus)</td></tr>
        <tr><th>TPM present/enabled</th><td>$(if($TPM.TpmPresent){"Yes"}else{"No"})</td></tr>
        <tr><th>If not encrypted, reason why</th><td>$(Get-HtmlInput "Reason..." -Value $BitLockerReason)</td></tr>
    </table>
    <h3>B. Data Encryption</h3>
    <table>
        <tr><th>Are ChiroTouch data files stored in encrypted form?</th><td>$(Get-HtmlSelect)</td></tr>
        <tr><th>Are database backups encrypted?</th><td>$(Get-HtmlSelect)</td></tr>
    </table>

    <h2>4. Server Firewall & Network Security (HIPAA §164.312(e))</h2>
    <h3>A. Local Firewall</h3>
    <table>
        <tr><th>Windows Firewall enabled?</th><td>$(if($Firewall){"Yes (Profiles: $($Firewall.Name -join ', '))"}else{"<span class='alert'>No</span>"})</td></tr>
        <tr><th>Inbound rule review</th><td>$(Get-HtmlInput "List allowed inbound ports" -Value $OpenPortsStr)</td></tr>
        <tr><th>Outbound rule review</th><td>$(Get-HtmlInput "Confirm non-essential ports blocked")</td></tr>
    </table>
    <h3>B. Remote Access</h3>
    <table>
        <tr><th>Does anyone RDP to the server?</th><td>Config Status: $RDPStatus $(Get-HtmlSelect)</td></tr>
        <tr><th>Is RDP protected by VPN?</th><td>$(Get-HtmlSelect @("Select...", "Yes", "No", "N/A") -SelectedValue $RDPVPNSel)</td></tr>
        <tr><th>MFA required?</th><td>$(Get-HtmlSelect @("Select...", "Yes", "No", "N/A") -SelectedValue $RDPMFASel)</td></tr>
        <tr><th>External RDP open to internet?</th><td>$(Get-HtmlSelect @("Select...", "Yes", "No", "N/A") -SelectedValue $RDPExternalSel) (Should be No)</td></tr>
        <tr><th>Any failed RDP attempts this month?</th><td>$(Get-HtmlSelect @("Select...", "Yes", "No", "N/A") -SelectedValue $RDPFailSel) <small>(Detected: $RDPFailCount)</small></td></tr>
    </table>

    <h2>5. Server Monitoring & Logs (HIPAA §164.312(b))</h2>
    <h3>A. Event Logs</h3>
    <table>
        <tr><th>Security logs enabled?</th><td>$(if($LogSettings){"Yes"}else{"No"})</td></tr>
        <tr><th>Retention period (in days)</th><td>$(Get-HtmlInput "Check Log Properties") (Size Limit: $(if($LogSettings){[math]::Round($LogSettings.MaximumKilobytes/1024,0)}else{"0"}) MB)</td></tr>
        <tr><th>Any critical events found this month?</th><td>
            $(if($Events){
                "<table style='font-size:0.9em; width:100%; border-collapse:collapse; border:1px solid #ddd;'><tr><th>Src</th><th>ID</th><th>Msg</th><th>Fix</th></tr>" + 
                ($Events | ForEach-Object {
                    $q = [uri]::EscapeDataString("Windows Event $($_.Id) $($_.ProviderName)")
                    "<tr><td>$($_.ProviderName)</td><td>$($_.Id)</td><td>$($_.Message.Substring(0,50))...</td><td><a href='https://www.google.com/search?q=$q' target='_blank' class='ai-link'>Ask AI</a></td></tr>"
                } | Out-String) + "</table>"
            } else { "None found." })
        </td></tr>
    </table>
    <h3>B. Application Logs</h3>
    <table>
        <tr><th>Any application errors?</th><td>$(Get-HtmlSelect @("Select...", "Yes", "No", "N/A") -SelectedValue $AppErrorSel) $(Get-HtmlInput "Describe..." -Value "See critical events above if Yes")</td></tr>
        <tr><th>Any database errors?</th><td>$(Get-HtmlSelect @("Select...", "Yes", "No", "N/A") -SelectedValue $DBErrorSel) $(Get-HtmlInput "Describe...")</td></tr>
        <tr><th>Any performance concerns logged?</th><td>$(Get-HtmlInput "Describe...")</td></tr>
    </table>
    <h3>C. Huntress / EDR Logs</h3>
    <table>
        <tr><th>Any incidents detected on the server?</th><td>$(Get-HtmlSelect) $(Get-HtmlInput "Attach if yes")</td></tr>
    </table>

    <h2>6. Physical Security (HIPAA §164.310)</h2>
    <h3>A. Server Location</h3>
    <table>
        <tr><th>Where is the server physically located?</th><td>$(Get-HtmlInput "closet, office, rack")</td></tr>
        <tr><th>Is the room locked?</th><td>$(Get-HtmlSelect)</td></tr>
        <tr><th>Who has physical access?</th><td>$(Get-HtmlInput "List roles/people")</td></tr>
        <tr><th>Any environmental risks?</th><td>$(Get-HtmlInput "Heat, water, unlocked room")</td></tr>
    </table>

    <h2>7. Contingency & Failover (HIPAA §164.308(a)(7)(ii)(C))</h2>
    <h3>A. Disaster Recovery</h3>
    <table>
        <tr><th>If the server failed, how would be restored?</th><td>$(Get-HtmlInput "Method...")</td></tr>
        <tr><th>Estimated recovery time (RTO)</th><td>$(Get-HtmlInput "e.g., 4 Hours")</td></tr>
        <tr><th>Are offsite backups present?</th><td>$(Get-HtmlSelect)</td></tr>
    </table>
    <h3>B. Redundancy</h3>
    <table>
        <tr><th>RAID status</th><td>$(Get-HtmlInput "e.g., RAID 5 Healthy")</td></tr>
        <tr><th>Storage warnings?</th><td>$(Get-HtmlInput "Describe..." -Value $StorageWarning)</td></tr>
        <tr><th>Drive SMART status (any failing drives?)</th><td>$(Get-HtmlInput "Describe..." -Value $DiskHealthStr) (Check App Logs above)</td></tr>
    </table>

    <h2>8. Server Exceptions (Anything Not Compliant)</h2>
    <table>
        <tr><th>Description of issue</th><th>Safeguard (Admin/Tech/Phys)</th><th>Risk</th><th>Owner</th><th>Status</th></tr>
        <tr>
            <td>$(Get-HtmlTextArea)</td>
            <td>$(Get-HtmlInput "Safeguard")</td>
            <td>$(Get-HtmlSelect @("Low", "Moderate", "High"))</td>
            <td>$(Get-HtmlSelect @("Polar Nite IT", "Client"))</td>
            <td>$(Get-HtmlSelect @("Planned", "In Progress", "Not Scheduled"))</td>
        </tr>
        <tr><td colspan="5"><strong>Notes:</strong> $(Get-HtmlInput "Additional Notes")</td></tr>
    </table>

    <button onclick="copyReport()" class="copy-btn floating-action">Copy Report for Ticket</button>
"@

    # --- OUTPUT ---
    $HTMLPage = @"
    <!DOCTYPE html>
    <html>
    <head>
        <title>Polar Nite Security Audit: $env:COMPUTERNAME</title>
        $style
    </head>
    <body>
        <div class='container'>
            $HTMLBody
            <p style='text-align:center; margin-top:50px; font-size:0.8em; color:#95a5a6;'>Polar Nite Audit Tool v7.0 (Ticket Mode)</p>
        </div>
    </body>
    </html>
"@

    $HTMLPage | Out-File -FilePath $ReportPath -Encoding UTF8
    Log-Output "Interactive Audit Generated. Opening Report..."
    Invoke-Item $ReportPath
}

# --- Show Form ---
$form.ShowDialog() | Out-Null
