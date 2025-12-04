<#
.SYNOPSIS
    WinFix Tool - All-in-One Windows Maintenance & Security Audit Utility
.DESCRIPTION
    A standalone GUI tool to perform common Windows fixes, gather system info, 
    run network scans, and generate the "Jeremy Bean" Security Audit report.
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

# --- Global Settings ---
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# --- Theme Colors (Modern Dark) ---
$Theme = @{
    Background = [System.Drawing.Color]::FromArgb(30, 30, 30)
    Panel      = [System.Drawing.Color]::FromArgb(45, 45, 48)
    Text       = [System.Drawing.Color]::FromArgb(241, 241, 241)
    Accent     = [System.Drawing.Color]::FromArgb(0, 122, 204) # VS Blue
    Button     = [System.Drawing.Color]::FromArgb(62, 62, 66)
    ButtonHover= [System.Drawing.Color]::FromArgb(80, 80, 80)
    OutputBg   = [System.Drawing.Color]::FromArgb(14, 14, 14)
    OutputFg   = [System.Drawing.Color]::FromArgb(0, 255, 0) # Lime
    Error      = [System.Drawing.Color]::FromArgb(255, 100, 100)
}

# --- GUI Setup ---
$form = New-Object System.Windows.Forms.Form
$form.Text = "WinFix Tool & Security Audit"
$form.Size = New-Object System.Drawing.Size(900, 700)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedSingle"
$form.MaximizeBox = $false
$form.BackColor = $Theme.Background
$form.ForeColor = $Theme.Text
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)

# --- Job Management ---
$global:CurrentJob = $null

function Start-WorkerJob {
    param($Name, $ScriptBlock, $ArgumentList = @())
    
    Log-Output "=== Start-WorkerJob Called: $Name ==="
    
    if (-not $ScriptBlock) {
        Log-Output "ERROR: No action defined for this button."
        return
    }

    if ($global:CurrentJob -and $global:CurrentJob.State -eq 'Running') {
        Log-Output "WARNING: A task is already running. Please wait or stop it."
        return
    }

    $btnStop.Enabled = $true
    Log-Output "Starting Task: $Name..."
    Log-Output "ArgumentList Count: $($ArgumentList.Count)"
    
    $global:CurrentJob = Start-Job -Name $Name -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
    Log-Output "Job Started. Job ID: $($global:CurrentJob.Id)"
    $timer.Start()
}

function Stop-WorkerJob {
    if ($global:CurrentJob -and $global:CurrentJob.State -eq 'Running') {
        Stop-Job $global:CurrentJob
        Log-Output "Task stopped by user."
        $btnStop.Enabled = $false
        $timer.Stop()
    }
}

# --- Output Console ---
$panelOutput = New-Object System.Windows.Forms.Panel
$panelOutput.Dock = "Bottom"
$panelOutput.Height = 250
$panelOutput.Padding = New-Object System.Windows.Forms.Padding(10)
$panelOutput.BackColor = $Theme.Panel

$lblLog = New-Object System.Windows.Forms.Label
$lblLog.Text = "Activity Log"
$lblLog.Dock = "Top"
$lblLog.Height = 20
$lblLog.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)

$txtOutput = New-Object System.Windows.Forms.TextBox
$txtOutput.Multiline = $true
$txtOutput.ScrollBars = "Vertical"
$txtOutput.ReadOnly = $true
$txtOutput.Dock = "Fill"
$txtOutput.Font = New-Object System.Drawing.Font("Consolas", 10)
$txtOutput.BackColor = $Theme.OutputBg
$txtOutput.ForeColor = $Theme.OutputFg
$txtOutput.BorderStyle = "FixedSingle"

# Control Bar (Copy / Stop)
$panelControls = New-Object System.Windows.Forms.Panel
$panelControls.Dock = "Right"
$panelControls.Width = 100
$panelControls.Padding = New-Object System.Windows.Forms.Padding(5)

$btnCopy = New-Object System.Windows.Forms.Button
$btnCopy.Text = "Copy Log"
$btnCopy.Dock = "Top"
$btnCopy.Height = 30
$btnCopy.FlatStyle = "Flat"
$btnCopy.BackColor = $Theme.Button
$btnCopy.ForeColor = $Theme.Text
$btnCopy.FlatAppearance.BorderSize = 0
$btnCopy.Add_Click({ [System.Windows.Forms.Clipboard]::SetText($txtOutput.Text) })

$btnOpenLog = New-Object System.Windows.Forms.Button
$btnOpenLog.Text = "Open Log"
$btnOpenLog.Dock = "Top"
$btnOpenLog.Height = 30
$btnOpenLog.FlatStyle = "Flat"
$btnOpenLog.BackColor = $Theme.Button
$btnOpenLog.ForeColor = $Theme.Text
$btnOpenLog.FlatAppearance.BorderSize = 0
$btnOpenLog.Add_Click({ if (Test-Path $LogFilePath) { Invoke-Item $LogFilePath } })

$btnStop = New-Object System.Windows.Forms.Button
$btnStop.Text = "STOP"
$btnStop.Dock = "Bottom"
$btnStop.Height = 40
$btnStop.FlatStyle = "Flat"
$btnStop.BackColor = $Theme.Error
$btnStop.ForeColor = "White"
$btnStop.FlatAppearance.BorderSize = 0
$btnStop.Enabled = $false
$btnStop.Add_Click({ Stop-WorkerJob })

$panelControls.Controls.Add($btnStop)
$panelControls.Controls.Add($btnOpenLog)
$panelControls.Controls.Add($btnCopy)

$panelOutput.Controls.Add($txtOutput)
$panelOutput.Controls.Add($panelControls)
$panelOutput.Controls.Add($lblLog)

# --- Logging Function ---
$LogFilePath = "$env:TEMP\WinFix_Debug.log"
$null = New-Item -Path $LogFilePath -ItemType File -Force -ErrorAction SilentlyContinue

function Log-Output($message) {
    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    $fullMessage = "[$timestamp] $message"
    Add-Content -Path $LogFilePath -Value $fullMessage -ErrorAction SilentlyContinue

    $txtOutput.AppendText("[$((Get-Date).ToString('HH:mm:ss'))] $message`r`n")
    $txtOutput.SelectionStart = $txtOutput.Text.Length
    $txtOutput.ScrollToCaret()
    $form.Refresh()
}

# Initial startup logging
Log-Output "=== WinFix Tool Started ==="
Log-Output "PowerShell Version: $($PSVersionTable.PSVersion)"
Log-Output "OS: $([System.Environment]::OSVersion.VersionString)"
Log-Output "User: $env:USERNAME"
Log-Output "Computer: $env:COMPUTERNAME"
Log-Output "Log File: $LogFilePath"

# --- Timer for Jobs ---
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 500
$timer.Add_Tick({
    if ($global:CurrentJob) {
        # Get any new output
        $results = Receive-Job -Job $global:CurrentJob
        foreach ($line in $results) {
            if ($line) { Log-Output $line }
        }

        if ($global:CurrentJob.State -ne 'Running') {
            Log-Output "Task Finished ($($global:CurrentJob.State))."
            $timer.Stop()
            $btnStop.Enabled = $false
            Remove-Job $global:CurrentJob
            $global:CurrentJob = $null
        }
    }
})

# --- NinjaOne Integration Functions ---
$global:NinjaToken = $null
$global:NinjaInstance = $null
$global:NinjaDeviceData = $null

function Get-NinjaSettings {
    $configDir = "$env:APPDATA\WinFixTool"
    $configPath = "$configDir\ninja_config.xml"
    if (Test-Path $configPath) { try { return Import-Clixml $configPath } catch { Log-Output "Could not load saved settings." } }
    return $null
}

function Save-NinjaSettings {
    param($Url, $Id, $Secret)
    $configDir = "$env:APPDATA\WinFixTool"
    if (-not (Test-Path $configDir)) { New-Item -ItemType Directory -Path $configDir -Force | Out-Null }
    $configPath = "$configDir\ninja_config.xml"
    [PSCustomObject]@{ Url = $Url; ClientId = $Id; ClientSecret = $Secret } | Export-Clixml -Path $configPath
    Log-Output "Settings saved securely."
}

function Decrypt-String {
    param($EncryptedString, $Password)
    try {
        $bytes = [Convert]::FromBase64String($EncryptedString)
        if ($bytes.Length -lt 32) { throw "Invalid data" }
        $salt = $bytes[0..15]; $iv = $bytes[16..31]; $cipherText = $bytes[32..($bytes.Length - 1)]
        $derive = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password, $salt, 100000, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
        $key = $derive.GetBytes(32)
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $key; $aes.IV = $iv
        $decryptor = $aes.CreateDecryptor()
        $ms = New-Object System.IO.MemoryStream(,$cipherText)
        $cs = New-Object System.Security.Cryptography.CryptoStream($ms, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)
        $sr = New-Object System.IO.StreamReader($cs)
        return $sr.ReadToEnd()
    } catch { Log-Output "Decryption Error: $_"; return $null }
}

function Connect-NinjaOne {
    param($ClientId, $ClientSecret, $InstanceUrl)
    
    Log-Output "=== Connect-NinjaOne Called ==="
    Log-Output "InstanceUrl (raw): $InstanceUrl"
    
    # Clean URL input (remove protocol and trailing slash)
    $InstanceUrl = $InstanceUrl -replace "^https?://", "" -replace "/$", ""
    Log-Output "InstanceUrl (cleaned): $InstanceUrl"

    $EncId = "lBPqaFXSjLrCJAKy9V7db00ImBVi7TmzocC4R1xmdaquRX+F0GzTWa+acd1lnhLb2U/h6ORrbF0vIKW55pihnQ=="
    $EncSec = "EiRj/vGljBBXUDGrBkAEoXYldnzwzmYL40JvGK8ahShnk8nzBKtbuRujuandJ41QEgPc04ttpCLkGfAsW6vTrkd85nfgGG3g0/gRrNsLoH8="
    $Pass = "smoke007"

    if ([string]::IsNullOrWhiteSpace($ClientId)) { Log-Output "Using embedded Client ID..."; $ClientId = Decrypt-String -EncryptedString $EncId -Password $Pass }
    if ([string]::IsNullOrWhiteSpace($ClientSecret)) { Log-Output "Using embedded Client Secret..."; $ClientSecret = Decrypt-String -EncryptedString $EncSec -Password $Pass }

    # Fix API URL if user enters dashboard URL
    $ApiUrl = $InstanceUrl
    if ($ApiUrl -match "^app\.") { $ApiUrl = $ApiUrl -replace "^app\.", "api." }
    elseif ($ApiUrl -match "^eu\.") { $ApiUrl = $ApiUrl -replace "^eu\.", "eu-api." }
    elseif ($ApiUrl -match "^oc\.") { $ApiUrl = $ApiUrl -replace "^oc\.", "oc-api." }
    elseif ($ApiUrl -match "^ca\.") { $ApiUrl = $ApiUrl -replace "^ca\.", "ca-api." }

    Log-Output "ApiUrl (derived): $ApiUrl"
    Log-Output "Connecting to NinjaOne ($ApiUrl)..."
    $tokenUrl = "https://$ApiUrl/ws/oauth/token"
    Log-Output "Token URL: $tokenUrl"
    
    # Scope: monitoring only (Read Only)
    $body = @{ grant_type = "client_credentials"; client_id = $ClientId; client_secret = $ClientSecret; scope = "monitoring" }
    Log-Output "OAuth Body: grant_type=client_credentials, scope=monitoring, client_id length=$($ClientId.Length)"
    
    try {
        Log-Output "Sending OAuth request..."
        $response = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $body -ErrorAction Stop
        $global:NinjaToken = $response.access_token
        $global:NinjaInstance = $ApiUrl
        Log-Output "OAuth Success! Token length: $($global:NinjaToken.Length)"
        Log-Output "Successfully connected to NinjaOne!"
        Get-NinjaDeviceData
    } catch {
        Log-Output "OAuth FAILED: $($_.Exception.Message)"
        Log-Output "HTTP Status: $($_.Exception.Response.StatusCode.value__)"
        if ($_.ErrorDetails) { Log-Output "Details: $($_.ErrorDetails.Message)" }
        
        # Fallback: Try the original instance URL if the derived API URL failed
        if ($ApiUrl -ne $InstanceUrl) {
             Log-Output "Retrying with original URL '$InstanceUrl'..."
             $tokenUrl = "https://$InstanceUrl/ws/oauth/token"
             Log-Output "Fallback Token URL: $tokenUrl"
             try {
                Log-Output "Sending fallback OAuth request..."
                $response = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $body -ErrorAction Stop
                $global:NinjaToken = $response.access_token
                $global:NinjaInstance = $InstanceUrl
                Log-Output "Fallback OAuth Success! Token length: $($global:NinjaToken.Length)"
                Log-Output "Successfully connected to NinjaOne (Fallback)!"
                Get-NinjaDeviceData
             } catch {
                Log-Output "Fallback OAuth FAILED: $($_.Exception.Message)"
                Log-Output "Fallback HTTP Status: $($_.Exception.Response.StatusCode.value__)"
             }
        }
    }
}

function Get-LocalNinjaNodeId {
    Log-Output "=== Get-LocalNinjaNodeId Called ==="
    $paths = @(
        "HKLM:\SOFTWARE\NinjaRMM\Agent",
        "HKLM:\SOFTWARE\WOW6432Node\NinjaRMM\Agent",
        "HKLM:\SOFTWARE\NinjaMSP\Agent",
        "HKLM:\SOFTWARE\WOW6432Node\NinjaMSP\Agent"
    )
    
    foreach ($path in $paths) {
        Log-Output "Checking registry path: $path"
        if (Test-Path $path) {
            Log-Output "Path exists: $path"
            $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            Log-Output "Properties found: $($props.PSObject.Properties.Name -join ', ')"
            # Check common property names for the Device ID
            if ($props.NodeID) { Log-Output "Found NodeID: $($props.NodeID)"; return $props.NodeID }
            if ($props.DeviceID) { Log-Output "Found DeviceID: $($props.DeviceID)"; return $props.DeviceID }
            if ($props.id) { Log-Output "Found id: $($props.id)"; return $props.id }
            if ($props.agent_id) { Log-Output "Found agent_id: $($props.agent_id)"; return $props.agent_id }
        } else {
            Log-Output "Path does not exist: $path"
        }
    }
    Log-Output "No local Ninja Node ID found in registry"
    return $null
}

function Get-NinjaDeviceData {
    Log-Output "=== Get-NinjaDeviceData Called ==="
    if (-not $global:NinjaToken) { Log-Output "ERROR: Not connected to NinjaOne (no token)."; return }
    
    Log-Output "Token exists, length: $($global:NinjaToken.Length)"
    Log-Output "Instance: $($global:NinjaInstance)"
    
    $headers = @{ Authorization = "Bearer $global:NinjaToken" }
    
    # 1. Try Local Registry ID First (Most Accurate)
    $localId = Get-LocalNinjaNodeId
    if ($localId) {
        Log-Output "Found Local Ninja Node ID: $localId"
        try {
            $url = "https://$($global:NinjaInstance)/v2/devices/$localId"
            Log-Output "Fetching device by ID: $url"
            $device = Invoke-RestMethod -Uri $url -Headers $headers -ErrorAction Stop
            if ($device) {
                $global:NinjaDeviceData = $device
                Log-Output "SUCCESS: Device found via Node ID: $($device.systemName)"
                return
            }
        } catch {
            Log-Output "ERROR: Could not fetch device by Node ID ($localId): $($_.Exception.Message)"
            Log-Output "HTTP Status: $($_.Exception.Response.StatusCode.value__)"
        }
    } else {
        Log-Output "No local Node ID found, proceeding to API search..."
    }

    # 2. Get ALL devices and filter locally (More reliable than API search filters)
    Log-Output "Fetching all devices from NinjaOne for local matching..."
    $serial = (Get-CimInstance Win32_Bios).SerialNumber
    $hostname = $env:COMPUTERNAME
    
    Log-Output "Local Serial Number: $serial"
    Log-Output "Local Hostname: $hostname"
    
    try {
        $allDevices = @()
        $pageSize = 1000
        $after = 0
        
        # Paginate through all devices
        do {
            $url = "https://$($global:NinjaInstance)/v2/devices?pageSize=$pageSize&after=$after"
            Log-Output "Fetching page (pageSize=$pageSize, after=$after): $url"
            
            try {
                $page = Invoke-RestMethod -Uri $url -Headers $headers -ErrorAction Stop
                Log-Output "Page returned $($page.Count) devices"
            } catch {
                Log-Output "ERROR: Page fetch failed: $($_.Exception.Message)"
                Log-Output "HTTP Status: $($_.Exception.Response.StatusCode.value__)"
                if ($_.ErrorDetails) { Log-Output "Error Details: $($_.ErrorDetails.Message)" }
                break
            }
            
            if ($page -and $page.Count -gt 0) {
                $allDevices += $page
                $after += $page.Count
                Log-Output "Total devices collected so far: $($allDevices.Count)"
            } else {
                Log-Output "No more devices to fetch (page was empty or null)"
                break
            }
        } while ($page.Count -eq $pageSize)
        
        Log-Output "Fetched $($allDevices.Count) total devices. Searching locally..."
        
        # Match by Serial Number
        if (-not [string]::IsNullOrWhiteSpace($serial)) {
            Log-Output "Searching for serial: '$serial'"
            $match = $allDevices | Where-Object { $_.serialNumber -eq $serial }
            if ($match) {
                $global:NinjaDeviceData = $match | Select-Object -First 1
                Log-Output "SUCCESS: Device matched by Serial: $($global:NinjaDeviceData.systemName) (ID: $($global:NinjaDeviceData.id))"
                return
            } else {
                Log-Output "No match found for serial"
            }
        }
        
        # Match by Hostname (systemName)
        Log-Output "Searching for systemName: '$hostname'"
        $match = $allDevices | Where-Object { $_.systemName -eq $hostname }
        if ($match) {
            $global:NinjaDeviceData = $match | Select-Object -First 1
            Log-Output "SUCCESS: Device matched by Hostname: $($global:NinjaDeviceData.systemName) (ID: $($global:NinjaDeviceData.id))"
            return
        } else {
            Log-Output "No match found for systemName"
        }
        
        # Match by nodeName (case-insensitive)
        Log-Output "Searching for nodeName (like): '$hostname'"
        $match = $allDevices | Where-Object { $_.nodeName -like $hostname }
        if ($match) {
            $global:NinjaDeviceData = $match | Select-Object -First 1
            Log-Output "SUCCESS: Device matched by NodeName: $($global:NinjaDeviceData.systemName) (ID: $($global:NinjaDeviceData.id))"
            return
        } else {
            Log-Output "No match found for nodeName"
        }
        
        Log-Output "ERROR: Device not found. Serial='$serial', Hostname='$hostname'"
        Log-Output "Sample device properties from first device:"
        if ($allDevices.Count -gt 0) {
            $sample = $allDevices[0]
            Log-Output "  id: $($sample.id)"
            Log-Output "  systemName: $($sample.systemName)"
            Log-Output "  nodeName: $($sample.nodeName)"
            Log-Output "  serialNumber: $($sample.serialNumber)"
        }
    } catch {
        Log-Output "FATAL ERROR in Get-NinjaDeviceData: $($_.Exception.Message)"
        Log-Output "Stack Trace: $($_.ScriptStackTrace)"
    }
}

# --- Tab Control Setup ---
$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Dock = "Fill"
$tabControl.SizeMode = "Fixed"
$tabControl.ItemSize = New-Object System.Drawing.Size(120, 30)
$tabControl.DrawMode = "OwnerDrawFixed"

# Custom Tab Drawing for Dark Theme
$tabControl.Add_DrawItem({
    param($sender, $e)
    $g = $e.Graphics
    $rect = $e.Bounds
    $text = $sender.TabPages[$e.Index].Text
    
    if ($e.Index -eq $sender.SelectedIndex) {
        $g.FillRectangle((New-Object System.Drawing.SolidBrush $Theme.Accent), $rect)
        $textColor = [System.Drawing.Color]::White
    } else {
        $g.FillRectangle((New-Object System.Drawing.SolidBrush $Theme.Panel), $rect)
        $textColor = [System.Drawing.Color]::Gray
    }
    
    $flags = [System.Windows.Forms.TextFormatFlags]::HorizontalCenter -bor [System.Windows.Forms.TextFormatFlags]::VerticalCenter
    [System.Windows.Forms.TextRenderer]::DrawText($g, $text, $sender.Font, $rect, $textColor, $flags)
})

# --- Helper to add buttons ---
function Add-Button($parent, $text, $scriptBlock) {
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $text
    $btn.AutoSize = $true
    $btn.Padding = New-Object System.Windows.Forms.Padding(10)
    $btn.Margin = New-Object System.Windows.Forms.Padding(5)
    $btn.Width = 280
    $btn.Height = 45
    $btn.FlatStyle = "Flat"
    $btn.BackColor = $Theme.Button
    $btn.ForeColor = $Theme.Text
    $btn.FlatAppearance.BorderSize = 0
    $btn.FlatAppearance.MouseOverBackColor = $Theme.ButtonHover
    
    # Action: Start Job
    # Explicitly capture variables for the closure to avoid null reference
    $jobName = $text
    $jobScript = $scriptBlock
    
    $btn.Add_Click({ 
        Start-WorkerJob -Name $jobName -ScriptBlock $jobScript 
    }.GetNewClosure())
    
    $parent.Controls.Add($btn)
}

# --- Tab 1: Common Fixes ---
$tabFixes = New-Object System.Windows.Forms.TabPage
$tabFixes.Text = "Common Fixes"
$tabFixes.BackColor = $Theme.Background
$tabFixes.Padding = New-Object System.Windows.Forms.Padding(20)

$flowFixes = New-Object System.Windows.Forms.FlowLayoutPanel
$flowFixes.Dock = "Fill"
$flowFixes.AutoScroll = $true
$flowFixes.FlowDirection = "TopDown"

Add-Button $flowFixes "Free Up Disk Space" {
    "Cleaning Temp Folders and Recycle Bin..."
    Clear-RecycleBin -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:windir\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
    "Cleanup Complete."
}

Add-Button $flowFixes "Disable Sleep & Hibernate" {
    "Disabling Sleep and Hibernate..."
    powercfg -change -monitor-timeout-ac 0
    powercfg -change -disk-timeout-ac 0
    powercfg -change -standby-timeout-ac 0
    powercfg -change -hibernate-timeout-ac 0
    powercfg -h off
    "Power settings updated (AC Power)."
}

Add-Button $flowFixes "Fix Network (Reset TCP/IP)" {
    "Resetting Network Stack..."
    netsh int ip reset | Out-Null
    netsh winsock reset | Out-Null
    ipconfig /flushdns | Out-Null
    "Network reset complete. A reboot may be required."
}

Add-Button $flowFixes "Run System File Checker (SFC)" {
    "Starting SFC Scan (This may take a while)..."
    Start-Process "sfc" -ArgumentList "/scannow" -Wait -NoNewWindow
    "SFC Scan Complete."
}

Add-Button $flowFixes "DISM Repair Image" {
    "Starting DISM RestoreHealth (This may take a while)..."
    Start-Process "dism" -ArgumentList "/online /cleanup-image /restorehealth" -Wait -NoNewWindow
    "DISM Repair Complete."
}

Add-Button $flowFixes "Reset Windows Update" {
    "Resetting Windows Update Components..."
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
    "Windows Update Reset Complete."
}

Add-Button $flowFixes "Clear Print Spooler" {
    "Clearing Print Spooler..."
    Stop-Service Spooler -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:windir\System32\spool\PRINTERS\*" -Force -ErrorAction SilentlyContinue
    Start-Service Spooler -ErrorAction SilentlyContinue
    "Print Spooler Cleared and Restarted."
}

Add-Button $flowFixes "Restart Explorer" {
    "Restarting Windows Explorer..."
    Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
    "Explorer Restarted."
}

Add-Button $flowFixes "Sync System Time" {
    "Syncing System Time..."
    Start-Service w32time -ErrorAction SilentlyContinue
    w32tm /resync | Out-String
    "Time Sync Attempted."
}

Add-Button $flowFixes "Run Microsoft Activation Scripts" {
    "Launching Microsoft Activation Scripts..."
    Start-Process powershell -ArgumentList "-NoProfile -Command `"iex (curl.exe -s --doh-url https://1.1.1.1/dns-query https://get.activated.win | Out-String)`""
    "MAS launched in a new window."
}

Add-Button $flowFixes "Download & Run SpaceMonger" {
    "Checking for SpaceMonger..."
    $smPath = "$env:TEMP\SpaceMonger.exe"
    $url = "https://github.com/jeremydbean/winfix/raw/main/SpaceMonger.exe"
    
    if (-not (Test-Path $smPath)) {
        "Downloading SpaceMonger from GitHub..."
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $url -OutFile $smPath -ErrorAction Stop
            "Download Complete."
        } catch {
            "Error downloading SpaceMonger: $_"
            return
        }
    }
    "Launching SpaceMonger..."
    Start-Process $smPath
}

$tabFixes.Controls.Add($flowFixes)

# --- Tab 2: System Info ---
$tabInfo = New-Object System.Windows.Forms.TabPage
$tabInfo.Text = "System Info"
$tabInfo.BackColor = $Theme.Background
$tabInfo.Padding = New-Object System.Windows.Forms.Padding(20)

$flowInfo = New-Object System.Windows.Forms.FlowLayoutPanel
$flowInfo.Dock = "Fill"
$flowInfo.AutoScroll = $true
$flowInfo.FlowDirection = "TopDown"

Add-Button $flowInfo "Get System Specs" {
    "Gathering System Specs..."
    $info = Get-ComputerInfo
    "OS: $($info.OsName)"
    "Version: $($info.OsVersion)"
    "Manufacturer: $($info.CsManufacturer)"
    "Model: $($info.CsModel)"
    "RAM: $([math]::Round($info.CsTotalPhysicalMemory / 1GB, 2)) GB"
    "Bios: $($info.BiosSVersion)"
}

Add-Button $flowInfo "List Printers" {
    "Listing Printers..."
    $printers = Get-Printer
    $ports = Get-PrinterPort
    
    $results = foreach ($p in $printers) {
        $port = $ports | Where-Object { $_.Name -eq $p.PortName }
        [PSCustomObject]@{
            Name = $p.Name
            Driver = $p.DriverName
            PortName = $p.PortName
            IPAddress = if ($port -and $port.PrinterHostAddress) { $port.PrinterHostAddress } else { "N/A" }
        }
    }
    $results | Out-String
}

Add-Button $flowInfo "List Installed Software" {
    "Listing Installed Software (via Registry)..."
    $keys = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    Get-ItemProperty $keys -ErrorAction SilentlyContinue | 
        Where-Object { $_.DisplayName -ne $null } | 
        Select-Object DisplayName, DisplayVersion | 
        Sort-Object DisplayName | 
        Out-String
}

$tabInfo.Controls.Add($flowInfo)

# --- Tab 3: Network Tools ---
$tabNet = New-Object System.Windows.Forms.TabPage
$tabNet.Text = "Network Tools"
$tabNet.BackColor = $Theme.Background
$tabNet.Padding = New-Object System.Windows.Forms.Padding(20)

$flowNet = New-Object System.Windows.Forms.FlowLayoutPanel
$flowNet.Dock = "Fill"
$flowNet.AutoScroll = $true
$flowNet.FlowDirection = "TopDown"

Add-Button $flowNet "Show IP Configuration" {
    "IP Configuration:"
    ipconfig /all | Out-String
}

Add-Button $flowNet "Quick Network Scan (ARP)" {
    "Scanning local ARP table..."
    arp -a | Out-String
}

Add-Button $flowNet "Test Internet Connection" {
    "Pinging Google DNS (8.8.8.8)..."
    Test-Connection -ComputerName 8.8.8.8 -Count 4 | Select-Object Address, ResponseTime, Status | Out-String
}

Add-Button $flowNet "Enable Network Sharing (Private/No FW)" {
    "Disabling Windows Firewall..."
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    "Setting Network Profiles to Private..."
    Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private
    "Enabling File & Printer Sharing (Netsh)..."
    netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes
    netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes
    "Network Sharing Enabled and Firewall Disabled."
}

$tabNet.Controls.Add($flowNet)

# --- Tab 4: Integrations (NinjaOne) ---
$tabIntegrations = New-Object System.Windows.Forms.TabPage
$tabIntegrations.Text = "Integrations"
$tabIntegrations.BackColor = $Theme.Background
$tabIntegrations.Padding = New-Object System.Windows.Forms.Padding(20)

$grpNinja = New-Object System.Windows.Forms.GroupBox
$grpNinja.Text = "NinjaOne API Connection"
$grpNinja.Dock = "Top"
$grpNinja.Height = 250
$grpNinja.ForeColor = $Theme.Text

# Load Settings
$savedSettings = Get-NinjaSettings

# Inputs
$lblUrl = New-Object System.Windows.Forms.Label
$lblUrl.Text = "Instance URL (e.g. app.ninjarmm.com):"
$lblUrl.Location = New-Object System.Drawing.Point(20, 30)
$lblUrl.AutoSize = $true

$txtUrl = New-Object System.Windows.Forms.TextBox
$txtUrl.Location = New-Object System.Drawing.Point(20, 55)
$txtUrl.Width = 350
$txtUrl.Text = if ($savedSettings.Url) { $savedSettings.Url } else { "app.ninjarmm.com" }

$lblCid = New-Object System.Windows.Forms.Label
$lblCid.Text = "Client ID (Leave blank for embedded):"
$lblCid.Location = New-Object System.Drawing.Point(20, 90)
$lblCid.AutoSize = $true

$txtCid = New-Object System.Windows.Forms.TextBox
$txtCid.Location = New-Object System.Drawing.Point(20, 115)
$txtCid.Width = 350
$txtCid.Text = if ($savedSettings.ClientId) { $savedSettings.ClientId } else { "" }

$lblSec = New-Object System.Windows.Forms.Label
$lblSec.Text = "Client Secret (Leave blank for embedded):"
$lblSec.Location = New-Object System.Drawing.Point(20, 150)
$lblSec.AutoSize = $true

$txtSec = New-Object System.Windows.Forms.TextBox
$txtSec.Location = New-Object System.Drawing.Point(20, 175)
$txtSec.Width = 350
$txtSec.UseSystemPasswordChar = $true
$txtSec.Text = if ($savedSettings.ClientSecret) { $savedSettings.ClientSecret } else { "" }

$btnConnect = New-Object System.Windows.Forms.Button
$btnConnect.Text = "Connect & Sync"
$btnConnect.Location = New-Object System.Drawing.Point(400, 173)
$btnConnect.Width = 150
$btnConnect.Height = 30
$btnConnect.FlatStyle = "Flat"
$btnConnect.BackColor = $Theme.Accent
$btnConnect.ForeColor = "White"
$btnConnect.FlatAppearance.BorderSize = 0
$btnConnect.Add_Click({
    Log-Output "=== Connect Button Clicked ==="
    Log-Output "URL Input: $($txtUrl.Text)"
    Log-Output "Client ID Input: $(if($txtCid.Text){'<provided>'}else{'<blank>'})"
    Log-Output "Client Secret Input: $(if($txtSec.Text){'<provided>'}else{'<blank>'})"
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

# --- Tab: User & Shares ---
$tabUsers = New-Object System.Windows.Forms.TabPage
$tabUsers.Text = "User & Shares"
$tabUsers.BackColor = $Theme.Background
$tabUsers.Padding = New-Object System.Windows.Forms.Padding(20)

# GroupBox: User Management
$grpUser = New-Object System.Windows.Forms.GroupBox
$grpUser.Text = "User Management"
$grpUser.Location = New-Object System.Drawing.Point(20, 20)
$grpUser.Size = New-Object System.Drawing.Size(400, 300)
$grpUser.ForeColor = $Theme.Text

$lblUName = New-Object System.Windows.Forms.Label
$lblUName.Text = "Username:"
$lblUName.Location = New-Object System.Drawing.Point(20, 30)
$lblUName.AutoSize = $true
$grpUser.Controls.Add($lblUName)

$txtUName = New-Object System.Windows.Forms.TextBox
$txtUName.Location = New-Object System.Drawing.Point(20, 50)
$txtUName.Width = 350
$grpUser.Controls.Add($txtUName)

$lblUPass = New-Object System.Windows.Forms.Label
$lblUPass.Text = "Password:"
$lblUPass.Location = New-Object System.Drawing.Point(20, 80)
$lblUPass.AutoSize = $true
$grpUser.Controls.Add($lblUPass)

$txtUPass = New-Object System.Windows.Forms.TextBox
$txtUPass.Location = New-Object System.Drawing.Point(20, 100)
$txtUPass.Width = 350
$grpUser.Controls.Add($txtUPass)

# Helper for User Buttons
function Add-UserButton($parent, $text, $x, $y, $script) {
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $text
    $btn.Location = New-Object System.Drawing.Point($x, $y)
    $btn.Width = 170
    $btn.Height = 30
    $btn.FlatStyle = "Flat"
    $btn.BackColor = $Theme.Button
    $btn.ForeColor = $Theme.Text
    $btn.FlatAppearance.BorderSize = 0
    $btn.Add_Click($script)
    $parent.Controls.Add($btn)
}

Add-UserButton $grpUser "Create User" 20 140 {
    $u = $txtUName.Text; $p = $txtUPass.Text
    if (-not $u) { Log-Output "Username required."; return }
    Start-WorkerJob -Name "Create User" -ArgumentList @($u, $p) -ScriptBlock {
        param($u, $p)
        try {
            $pass = ConvertTo-SecureString $p -AsPlainText -Force
            New-LocalUser -Name $u -Password $pass -PasswordNeverExpires -Description "Created by WinFix" -ErrorAction Stop
            "User '$u' created successfully."
            Add-LocalGroupMember -Group "Users" -Member $u
        } catch { "Error: $_" }
    }
}

Add-UserButton $grpUser "Reset Password" 20 180 {
    $u = $txtUName.Text; $p = $txtUPass.Text
    if (-not $u -or -not $p) { Log-Output "Username and Password required."; return }
    Start-WorkerJob -Name "Reset Password" -ArgumentList @($u, $p) -ScriptBlock {
        param($u, $p)
        try {
            $pass = ConvertTo-SecureString $p -AsPlainText -Force
            Set-LocalUser -Name $u -Password $pass -ErrorAction Stop
            "Password for '$u' reset successfully."
        } catch { "Error: $_" }
    }
}

Add-UserButton $grpUser "Add to Administrators" 20 220 {
    $u = $txtUName.Text
    if (-not $u) { Log-Output "Username required."; return }
    Start-WorkerJob -Name "Add Admin" -ArgumentList @($u) -ScriptBlock {
        param($u)
        try {
            Add-LocalGroupMember -Group "Administrators" -Member $u -ErrorAction Stop
            "User '$u' added to Administrators group."
        } catch { "Error: $_" }
    }
}

Add-UserButton $grpUser "Enable User" 200 140 {
    $u = $txtUName.Text
    if (-not $u) { Log-Output "Username required."; return }
    Start-WorkerJob -Name "Enable User" -ArgumentList @($u) -ScriptBlock { param($u); Enable-LocalUser $u; "User '$u' enabled." }
}

Add-UserButton $grpUser "Disable User" 200 180 {
    $u = $txtUName.Text
    if (-not $u) { Log-Output "Username required."; return }
    Start-WorkerJob -Name "Disable User" -ArgumentList @($u) -ScriptBlock { param($u); Disable-LocalUser $u; "User '$u' disabled." }
}

Add-UserButton $grpUser "Delete User" 200 220 {
    $u = $txtUName.Text
    if (-not $u) { Log-Output "Username required."; return }
    Start-WorkerJob -Name "Delete User" -ArgumentList @($u) -ScriptBlock { param($u); Remove-LocalUser $u -ErrorAction Stop; "User '$u' deleted." }
}

# GroupBox: Share Management
$grpShare = New-Object System.Windows.Forms.GroupBox
$grpShare.Text = "Network Shares"
$grpShare.Location = New-Object System.Drawing.Point(440, 20)
$grpShare.Size = New-Object System.Drawing.Size(400, 300)
$grpShare.ForeColor = $Theme.Text

$lblSPath = New-Object System.Windows.Forms.Label
$lblSPath.Text = "Folder Path (e.g. C:\Share):"
$lblSPath.Location = New-Object System.Drawing.Point(20, 30)
$lblSPath.AutoSize = $true
$grpShare.Controls.Add($lblSPath)

$txtSPath = New-Object System.Windows.Forms.TextBox
$txtSPath.Location = New-Object System.Drawing.Point(20, 50)
$txtSPath.Width = 350
$grpShare.Controls.Add($txtSPath)

$lblSName = New-Object System.Windows.Forms.Label
$lblSName.Text = "Share Name:"
$lblSName.Location = New-Object System.Drawing.Point(20, 80)
$lblSName.AutoSize = $true
$grpShare.Controls.Add($lblSName)

$txtSName = New-Object System.Windows.Forms.TextBox
$txtSName.Location = New-Object System.Drawing.Point(20, 100)
$txtSName.Width = 350
$grpShare.Controls.Add($txtSName)

Add-UserButton $grpShare "Create Share (Full Access)" 20 140 {
    $p = $txtSPath.Text; $n = $txtSName.Text
    if (-not $p -or -not $n) { Log-Output "Path and Name required."; return }
    Start-WorkerJob -Name "Create Share" -ArgumentList @($p, $n) -ScriptBlock {
        param($p, $n)
        try {
            if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
            New-SmbShare -Name $n -Path $p -FullAccess "Everyone" -ErrorAction Stop
            "Share '$n' created at '$p' with Full Access for Everyone."
        } catch { "Error: $_" }
    }
}
$grpShare.Controls[$grpShare.Controls.Count-1].Width = 350

Add-UserButton $grpShare "Delete Share" 20 180 {
    $n = $txtSName.Text
    if (-not $n) { Log-Output "Share Name required."; return }
    Start-WorkerJob -Name "Delete Share" -ArgumentList @($n) -ScriptBlock {
        param($n)
        try {
            Remove-SmbShare -Name $n -Force -ErrorAction Stop
            "Share '$n' deleted."
        } catch { "Error: $_" }
    }
}
$grpShare.Controls[$grpShare.Controls.Count-1].Width = 350

$tabUsers.Controls.Add($grpUser)
$tabUsers.Controls.Add($grpShare)

# --- Tab 5: Security Audit ---
$tabAudit = New-Object System.Windows.Forms.TabPage
$tabAudit.Text = "Security Audit"
$tabAudit.BackColor = $Theme.Background
$tabAudit.Padding = New-Object System.Windows.Forms.Padding(20)

$lblAudit = New-Object System.Windows.Forms.Label
$lblAudit.Text = "Generates the 'Jeremy Bean' Security & Backup Audit HTML Report."
$lblAudit.AutoSize = $true
$lblAudit.Dock = "Top"
$lblAudit.Padding = New-Object System.Windows.Forms.Padding(0,0,0,20)

$btnRunAudit = New-Object System.Windows.Forms.Button
$btnRunAudit.Text = "Generate Audit Report"
$btnRunAudit.Height = 60
$btnRunAudit.Dock = "Top"
$btnRunAudit.FlatStyle = "Flat"
$btnRunAudit.BackColor = $Theme.Accent
$btnRunAudit.ForeColor = "White"
$btnRunAudit.FlatAppearance.BorderSize = 0
$btnRunAudit.Add_Click({
    Log-Output "Starting Security Audit..."
    Invoke-SecurityAudit
})

$tabAudit.Controls.Add($btnRunAudit)
$tabAudit.Controls.Add($lblAudit)

# --- Assemble Form ---
$tabControl.Controls.Add($tabFixes)
$tabControl.Controls.Add($tabInfo)
$tabControl.Controls.Add($tabNet)
$tabControl.Controls.Add($tabIntegrations)
$tabControl.Controls.Add($tabUsers)
$tabControl.Controls.Add($tabAudit)

$form.Controls.Add($tabControl)
$form.Controls.Add($panelOutput)

# --- SECURITY AUDIT LOGIC (Embedded) ---
function Invoke-SecurityAudit {
    # This function contains the logic provided by the user
    
    Log-Output "Initializing Jeremy Bean Audit..."
    
    # --- Configuration & Path Robustness ---
    # Robustly find the Desktop path (handles OneDrive redirection)
    $DesktopPath = [Environment]::GetFolderPath("Desktop")
    if (-not (Test-Path $DesktopPath)) { $DesktopPath = $env:TEMP } # Fallback to Temp if Desktop fails

    $ReportPath = Join-Path -Path $DesktopPath -ChildPath "JeremyBean_SecurityAudit_$(Get-Date -Format 'yyyyMMdd_HHmm').html"
    $EventLookbackDays = 30
    $MaxEventsToShow = 15

    # --- Styling & Scripting (Jeremy Bean - Light Theme) ---
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
    try {
        $LocalUsers = Get-LocalUser -ErrorAction Stop | Select-Object Name, Enabled, PasswordLastSet
    } catch {
        $LocalUsers = @()
        Log-Output "Warning: Could not list local users."
    }
    $DisabledUsers = $LocalUsers | Where-Object { $_.Enabled -eq $false }
    $DisabledUsersSel = if ($DisabledUsers) { "Yes" } else { "No" }

    # Smart Admin Password Last Set & Age Check
    $AdminPassLastSet = "Unknown / Domain Account"
    $AdminPassChangedRegularly = "Select..."
    try {
        $BuiltInAdmin = $LocalUsers | Where-Object SID -like "*-500"
        if (-not $BuiltInAdmin) { 
            # Fallback if SID not available in previous select
            $BuiltInAdmin = Get-LocalUser | Where-Object SID -like "*-500" -ErrorAction Stop 
        }
        
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
    $C_Encrypted = $false
    if ($BitLocker -and ($BitLocker | Where-Object ProtectionStatus -eq 'On')) {
        $BitLockerSel = "Yes"
        $BitLockerStatus = ($BitLocker | ForEach-Object { "$($_.MountPoint) [$($_.ProtectionStatus)]" }) -join ", "
        if ($BitLocker | Where-Object { $_.MountPoint -like "C:*" -and $_.ProtectionStatus -eq 'On' }) { $C_Encrypted = $true }
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

    # Smart ChiroTouch Logic
    $ChiroPath = "C:\Program Files\PSChiro"
    $ChiroInstalled = (Test-Path $ChiroPath)
    $ChiroEncryptedSel = "Select..."
    if ($ChiroInstalled) {
        $ChiroEncryptedSel = if ($C_Encrypted) { "Yes" } else { "No" }
    } else {
        $ChiroEncryptedSel = "N/A"
    }

    # 4. Firewall & RDP
    Log-Output "[-] Auditing Network & RDP..."
    $Firewall = Get-NetFirewallProfile | Where-Object Enabled -eq True
    $RDPReg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
    
    # Smart SMB Share Logic
    $Shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @("IPC$", "ADMIN$", "C$", "D$", "E$") }
    $ShareList = if ($Shares) { "Shares: " + ($Shares.Name -join ", ") } else { "No Custom Shares" }

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
        
        # Fetch Detailed Info (Software/Disks)
        try {
            $headers = @{ Authorization = "Bearer $global:NinjaToken" }
            $devId = $global:NinjaDeviceData.id
            
            # Check Software for ChiroTouch
            $nSoft = Invoke-RestMethod -Uri "https://$($global:NinjaInstance)/v2/devices/$devId/software" -Headers $headers -ErrorAction SilentlyContinue
            if ($nSoft -and ($nSoft | Where-Object { $_.name -match "ChiroTouch" })) { 
                $ChiroInstalled = $true
                if ($ChiroEncryptedSel -eq "N/A") { $ChiroEncryptedSel = if ($C_Encrypted) { "Yes" } else { "No" } }
            }
        } catch { Log-Output "Ninja Detail Fetch Error: $_" }
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
        <tr><th>List all local server accounts</th><td><ul>$($LocalUsers.Name | ForEach-Object{"<li>$_</li>"})</ul></td></tr>
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
        <tr><th>Are ChiroTouch data files stored in encrypted form?</th><td>$(Get-HtmlSelect @("Select...", "Yes", "No", "N/A") -SelectedValue $ChiroEncryptedSel)</td></tr>
        <tr><th>Are database backups encrypted?</th><td>$(Get-HtmlSelect)</td></tr>
    </table>

    <h2>4. Server Firewall & Network Security (HIPAA §164.312(e))</h2>
    <h3>A. Local Firewall</h3>
    <table>
        <tr><th>Windows Firewall enabled?</th><td>$(if($Firewall){"Yes (Profiles: $($Firewall.Name -join ', '))"}else{"<span class='alert'>No</span>"})</td></tr>
        <tr><th>Inbound rule review</th><td>$(Get-HtmlInput "List allowed inbound ports" -Value "$OpenPortsStr | $ShareList")</td></tr>
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
            <td>$(Get-HtmlSelect @("Jeremy Bean IT", "Client"))</td>
            <td>$(Get-HtmlSelect @("Planned", "In Progress", "Not Scheduled"))</td>
        </tr>
        <tr><td colspan="5"><strong>Notes:</strong> $(Get-HtmlInput "Additional Notes")</td></tr>
    </table>

    <button onclick="copyReport()" class="copy-btn floating-action">Copy Report for Ticket</button>
"@

    if ([string]::IsNullOrWhiteSpace($HTMLBody)) { Log-Output "Error: HTML Body is empty!" }
    
    $HTMLPage = "<html><head><title>Security Audit Report</title>$style</head><body>$HTMLBody</body></html>"
    
    try {
        $HTMLPage | Out-File -FilePath $ReportPath -Encoding UTF8 -ErrorAction Stop
        Log-Output "Report generated at: $ReportPath"
        Log-Output "Report Size: $( (Get-Item $ReportPath).Length ) bytes"
        Invoke-Item $ReportPath
    } catch {
        Log-Output "Failed to write report file: $($_.Exception.Message)"
    }
}

# --- Show Form ---
Log-Output "=== Displaying Main Form ==="
$form.ShowDialog() | Out-Null
Log-Output "=== Form Closed ==="
