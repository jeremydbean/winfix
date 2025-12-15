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
    $newProcess = New-Object System.Diagnostics.ProcessStartInfo "powershell.exe";
    # Include -STA so WinForms/Clipboard features work reliably after elevation.
    $newProcess.Arguments = "-NoProfile -ExecutionPolicy Bypass -STA -File `"$PSCommandPath`"";
    $newProcess.Verb = "runas";
    [System.Diagnostics.Process]::Start($newProcess);
    Exit;
}

# --- Ensure STA Thread for WinForms/Clipboard ---
# Many WinForms/Clipboard operations require STA; relaunch once if needed.
try {
    if ([System.Threading.Thread]::CurrentThread.ApartmentState -ne [System.Threading.ApartmentState]::STA) {
        if (-not $env:WINFIX_STA) {
            $env:WINFIX_STA = "1"
            $argsList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-STA", "-File", "`"$PSCommandPath`"")
            # Already elevated (admin check above); don't prompt again.
            Start-Process -FilePath "powershell.exe" -ArgumentList ($argsList -join ' ')
            Exit
        }
    }
} catch {
    # If STA detection fails, continue (WinForms may still work, but Clipboard could be impacted)
}

# --- Load Assemblies ---
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# --- Global Settings ---
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# --- Theme Colors (Modern Dark - Redesigned) ---
$Theme = @{
    # Main Colors
    Background    = [System.Drawing.Color]::FromArgb(18, 18, 24)      # Deep dark blue-black
    Surface       = [System.Drawing.Color]::FromArgb(26, 27, 38)      # Card background
    SurfaceLight  = [System.Drawing.Color]::FromArgb(36, 37, 51)      # Elevated surface
    
    # Text
    TextPrimary   = [System.Drawing.Color]::FromArgb(237, 237, 245)   # White text
    TextSecondary = [System.Drawing.Color]::FromArgb(148, 150, 172)   # Muted text
    TextMuted     = [System.Drawing.Color]::FromArgb(90, 92, 110)     # Very muted
    
    # Accent Colors
    Accent        = [System.Drawing.Color]::FromArgb(99, 102, 241)    # Indigo
    AccentHover   = [System.Drawing.Color]::FromArgb(129, 132, 255)   # Lighter indigo
    AccentGlow    = [System.Drawing.Color]::FromArgb(99, 102, 241)    # For effects
    
    # Semantic Colors
    Success       = [System.Drawing.Color]::FromArgb(34, 197, 94)     # Green
    Warning       = [System.Drawing.Color]::FromArgb(250, 204, 21)    # Yellow
    Error         = [System.Drawing.Color]::FromArgb(239, 68, 68)     # Red
    Info          = [System.Drawing.Color]::FromArgb(59, 130, 246)    # Blue
    
    # UI Elements
    Border        = [System.Drawing.Color]::FromArgb(55, 57, 75)      # Subtle border
    ButtonBg      = [System.Drawing.Color]::FromArgb(45, 46, 62)      # Button background
    ButtonHover   = [System.Drawing.Color]::FromArgb(60, 62, 82)      # Button hover
    InputBg       = [System.Drawing.Color]::FromArgb(30, 31, 44)      # Input background
    
    # Console
    ConsoleBg     = [System.Drawing.Color]::FromArgb(13, 13, 18)      # Terminal black
    ConsoleFg     = [System.Drawing.Color]::FromArgb(74, 222, 128)    # Terminal green
    ConsoleAccent = [System.Drawing.Color]::FromArgb(147, 197, 253)   # Cyan-ish for highlights
}

# Legacy compatibility mappings
$Theme.Panel = $Theme.Surface
$Theme.Text = $Theme.TextPrimary
$Theme.Button = $Theme.ButtonBg
$Theme.OutputBg = $Theme.ConsoleBg
$Theme.OutputFg = $Theme.ConsoleFg

# --- GUI Setup ---
$form = New-Object System.Windows.Forms.Form
$form.Text = "WinFix Tool"
$form.Size = New-Object System.Drawing.Size(1100, 750)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedSingle"
$form.MaximizeBox = $false
$form.BackColor = $Theme.Background
$form.ForeColor = $Theme.TextPrimary
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9.5)

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

# --- Output Console (Redesigned) ---
$panelOutput = New-Object System.Windows.Forms.Panel
$panelOutput.Dock = "Bottom"
$panelOutput.Height = 200
$panelOutput.Padding = New-Object System.Windows.Forms.Padding(15, 10, 15, 10)
$panelOutput.BackColor = $Theme.Surface

# Header bar for console
$panelLogHeader = New-Object System.Windows.Forms.Panel
$panelLogHeader.Dock = "Top"
$panelLogHeader.Height = 36
$panelLogHeader.BackColor = $Theme.SurfaceLight
$panelLogHeader.Padding = New-Object System.Windows.Forms.Padding(12, 0, 12, 0)

$lblLog = New-Object System.Windows.Forms.Label
$lblLog.Text = [char]0x25B6 + "  ACTIVITY LOG"
$lblLog.Dock = "Left"
$lblLog.AutoSize = $true
$lblLog.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$lblLog.ForeColor = $Theme.TextSecondary
$lblLog.Padding = New-Object System.Windows.Forms.Padding(0, 10, 0, 0)

# Control buttons in header
$flowLogControls = New-Object System.Windows.Forms.FlowLayoutPanel
$flowLogControls.Dock = "Right"
$flowLogControls.AutoSize = $true
$flowLogControls.FlowDirection = "LeftToRight"
$flowLogControls.Padding = New-Object System.Windows.Forms.Padding(0, 5, 0, 0)

$btnCopy = New-Object System.Windows.Forms.Button
$btnCopy.Text = "Copy"
$btnCopy.Width = 65
$btnCopy.Height = 26
$btnCopy.FlatStyle = "Flat"
$btnCopy.BackColor = $Theme.ButtonBg
$btnCopy.ForeColor = $Theme.TextSecondary
$btnCopy.FlatAppearance.BorderSize = 1
$btnCopy.FlatAppearance.BorderColor = $Theme.Border
$btnCopy.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$btnCopy.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnCopy.Add_Click({ 
    [System.Windows.Forms.Clipboard]::SetText($txtOutput.Text)
    $btnCopy.Text = "Copied!"
    $timer2 = New-Object System.Windows.Forms.Timer
    $timer2.Interval = 1500
    $timer2.Add_Tick({ $btnCopy.Text = "Copy"; $timer2.Stop(); $timer2.Dispose() })
    $timer2.Start()
})

$btnOpenLog = New-Object System.Windows.Forms.Button
$btnOpenLog.Text = "Open File"
$btnOpenLog.Width = 70
$btnOpenLog.Height = 26
$btnOpenLog.FlatStyle = "Flat"
$btnOpenLog.BackColor = $Theme.ButtonBg
$btnOpenLog.ForeColor = $Theme.TextSecondary
$btnOpenLog.FlatAppearance.BorderSize = 1
$btnOpenLog.FlatAppearance.BorderColor = $Theme.Border
$btnOpenLog.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$btnOpenLog.Margin = New-Object System.Windows.Forms.Padding(5, 0, 0, 0)
$btnOpenLog.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnOpenLog.Add_Click({ if (Test-Path $LogFilePath) { Invoke-Item $LogFilePath } })

$btnClear = New-Object System.Windows.Forms.Button
$btnClear.Text = "Clear"
$btnClear.Width = 55
$btnClear.Height = 26
$btnClear.FlatStyle = "Flat"
$btnClear.BackColor = $Theme.ButtonBg
$btnClear.ForeColor = $Theme.TextSecondary
$btnClear.FlatAppearance.BorderSize = 1
$btnClear.FlatAppearance.BorderColor = $Theme.Border
$btnClear.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$btnClear.Margin = New-Object System.Windows.Forms.Padding(5, 0, 0, 0)
$btnClear.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnClear.Add_Click({ $txtOutput.Clear() })

$btnStop = New-Object System.Windows.Forms.Button
$btnStop.Text = [char]0x25A0 + " STOP"
$btnStop.Width = 70
$btnStop.Height = 26
$btnStop.FlatStyle = "Flat"
$btnStop.BackColor = $Theme.Error
$btnStop.ForeColor = "White"
$btnStop.FlatAppearance.BorderSize = 0
$btnStop.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
$btnStop.Margin = New-Object System.Windows.Forms.Padding(10, 0, 0, 0)
$btnStop.Enabled = $false
$btnStop.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnStop.Add_Click({ Stop-WorkerJob })

$flowLogControls.Controls.Add($btnCopy)
$flowLogControls.Controls.Add($btnOpenLog)
$flowLogControls.Controls.Add($btnClear)
$flowLogControls.Controls.Add($btnStop)

$panelLogHeader.Controls.Add($lblLog)
$panelLogHeader.Controls.Add($flowLogControls)

$txtOutput = New-Object System.Windows.Forms.TextBox
$txtOutput.Multiline = $true
$txtOutput.ScrollBars = "Vertical"
$txtOutput.ReadOnly = $true
$txtOutput.Dock = "Fill"
$txtOutput.Font = New-Object System.Drawing.Font("Cascadia Code, Consolas", 9)
$txtOutput.BackColor = $Theme.ConsoleBg
$txtOutput.ForeColor = $Theme.ConsoleFg
$txtOutput.BorderStyle = "None"
$txtOutput.Padding = New-Object System.Windows.Forms.Padding(10)

$panelOutput.Controls.Add($txtOutput)
$panelOutput.Controls.Add($panelLogHeader)

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
    # Strip any path/query fragments if user pasted a full dashboard/docs URL
    if ($InstanceUrl -match "/") { $InstanceUrl = ($InstanceUrl -split "/")[0] }
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
        if ($_.Exception -and $_.Exception.Response -and $_.Exception.Response.StatusCode) {
            Log-Output "HTTP Status: $($_.Exception.Response.StatusCode.value__)"
        }
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
                if ($_.Exception -and $_.Exception.Response -and $_.Exception.Response.StatusCode) {
                    Log-Output "Fallback HTTP Status: $($_.Exception.Response.StatusCode.value__)"
                }
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
            if ($_.Exception -and $_.Exception.Response -and $_.Exception.Response.StatusCode) {
                Log-Output "HTTP Status: $($_.Exception.Response.StatusCode.value__)"
            }
        }
    } else {
        Log-Output "No local Node ID found, proceeding to API search..."
    }

    # 2. Get ALL devices and filter locally (More reliable than API search filters)
    Log-Output "Fetching all devices from NinjaOne for local matching..."
    $serial = ""
    try { $serial = (Get-CimInstance Win32_Bios -ErrorAction Stop).SerialNumber } catch { $serial = "" }
    $hostname = $env:COMPUTERNAME
    
    Log-Output "Local Serial Number: $serial"
    Log-Output "Local Hostname: $hostname"
    
    try {
        $allDevices = @()
        $pageSize = 1000
        $after = 0
        $lastAfter = $null
        $pageNum = 0
        $maxPages = 200
        
        # Paginate through all devices
        do {
            $pageNum++
            if ($pageNum -gt $maxPages) {
                Log-Output "WARNING: Reached maxPages=$maxPages while fetching devices. Stopping pagination to avoid long/infinite loops."
                break
            }

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
                # Offset-style pagination (most consistent). Guard against non-advancing cursor.
                $after += $page.Count
                if ($null -ne $lastAfter -and $after -eq $lastAfter) {
                    Log-Output "WARNING: Pagination not advancing (after=$after). Stopping to avoid infinite loop."
                    break
                }
                $lastAfter = $after
                Log-Output "Total devices collected so far: $($allDevices.Count)"
                # Keep UI responsive during long fetch operations
                if ($form -and $form.Visible) { [System.Windows.Forms.Application]::DoEvents() }
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
        $match = $allDevices | Where-Object { $_.nodeName -like "*$hostname*" }
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

# --- Tab Control Setup (Redesigned with Side Navigation) ---
# Create main split container
$mainContainer = New-Object System.Windows.Forms.Panel
$mainContainer.Dock = "Fill"
$mainContainer.BackColor = $Theme.Background
$mainContainer.Padding = New-Object System.Windows.Forms.Padding(0)

# Left sidebar navigation
$sideNav = New-Object System.Windows.Forms.Panel
$sideNav.Dock = "Left"
$sideNav.Width = 200
$sideNav.BackColor = $Theme.Surface
$sideNav.Padding = New-Object System.Windows.Forms.Padding(0)

# App branding header
$brandPanel = New-Object System.Windows.Forms.Panel
$brandPanel.Dock = "Top"
$brandPanel.Height = 70
$brandPanel.BackColor = $Theme.SurfaceLight
$brandPanel.Padding = New-Object System.Windows.Forms.Padding(15, 15, 15, 10)

$lblBrand = New-Object System.Windows.Forms.Label
$lblBrand.Text = [char]0x2699 + " WinFix"
$lblBrand.Font = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Bold)
$lblBrand.ForeColor = $Theme.TextPrimary
$lblBrand.AutoSize = $true
$lblBrand.Location = New-Object System.Drawing.Point(15, 12)

$lblVersion = New-Object System.Windows.Forms.Label
$lblVersion.Text = "v2.5 - IT Toolkit"
$lblVersion.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$lblVersion.ForeColor = $Theme.TextMuted
$lblVersion.AutoSize = $true
$lblVersion.Location = New-Object System.Drawing.Point(17, 42)

$brandPanel.Controls.Add($lblBrand)
$brandPanel.Controls.Add($lblVersion)

# Navigation buttons container
$navContainer = New-Object System.Windows.Forms.FlowLayoutPanel
$navContainer.Dock = "Fill"
$navContainer.FlowDirection = "TopDown"
$navContainer.WrapContents = $false
$navContainer.Padding = New-Object System.Windows.Forms.Padding(8, 15, 8, 15)
$navContainer.AutoScroll = $true

# Create tab control (hidden, used for content switching)
$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Dock = "Fill"
$tabControl.Appearance = "FlatButtons"
$tabControl.ItemSize = New-Object System.Drawing.Size(0, 1)
$tabControl.SizeMode = "Fixed"

# Navigation items definition
$navItems = @(
    @{ Icon = [char]0x25A3; Text = "Dashboard"; Index = 0 }
    @{ Icon = [char]0x2699; Text = "Maintenance"; Index = 1 }
    @{ Icon = [char]0x2139; Text = "Diagnostics"; Index = 2 }
    @{ Icon = [char]0x21C4; Text = "Network"; Index = 3 }
    @{ Icon = [char]0x2261; Text = "Integrations"; Index = 4 }
    @{ Icon = [char]0x263A; Text = "Users & Shares"; Index = 5 }
    @{ Icon = [char]0x2713; Text = "Security Audit"; Index = 6 }
)

$global:NavButtons = @()

function Update-NavSelection {
    param($selectedIndex)
    foreach ($btn in $global:NavButtons) {
        if ($btn.Tag -eq $selectedIndex) {
            $btn.BackColor = $Theme.Accent
            $btn.ForeColor = [System.Drawing.Color]::White
        } else {
            $btn.BackColor = [System.Drawing.Color]::Transparent
            $btn.ForeColor = $Theme.TextSecondary
        }
    }
    $tabControl.SelectedIndex = $selectedIndex
}

foreach ($item in $navItems) {
    $navBtn = New-Object System.Windows.Forms.Button
    $navBtn.Text = "  $($item.Icon)   $($item.Text)"
    $navBtn.Width = 180
    $navBtn.Height = 42
    $navBtn.FlatStyle = "Flat"
    $navBtn.FlatAppearance.BorderSize = 0
    $navBtn.FlatAppearance.MouseOverBackColor = $Theme.SurfaceLight
    $navBtn.BackColor = [System.Drawing.Color]::Transparent
    $navBtn.ForeColor = $Theme.TextSecondary
    $navBtn.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $navBtn.TextAlign = "MiddleLeft"
    $navBtn.Padding = New-Object System.Windows.Forms.Padding(10, 0, 0, 0)
    $navBtn.Margin = New-Object System.Windows.Forms.Padding(0, 2, 0, 2)
    $navBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $navBtn.Tag = $item.Index
    
    $idx = $item.Index
    $navBtn.Add_Click({
        Update-NavSelection -selectedIndex $this.Tag
    }.GetNewClosure())
    
    $global:NavButtons += $navBtn
    $navContainer.Controls.Add($navBtn)
}

# Status indicator at bottom of sidebar
$statusPanel = New-Object System.Windows.Forms.Panel
$statusPanel.Dock = "Bottom"
$statusPanel.Height = 60
$statusPanel.BackColor = $Theme.SurfaceLight
$statusPanel.Padding = New-Object System.Windows.Forms.Padding(12)

$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Text = [char]0x25CF + " Ready"
$lblStatus.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$lblStatus.ForeColor = $Theme.Success
$lblStatus.AutoSize = $true
$lblStatus.Location = New-Object System.Drawing.Point(15, 10)

$lblComputer = New-Object System.Windows.Forms.Label
$lblComputer.Text = $env:COMPUTERNAME
$lblComputer.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$lblComputer.ForeColor = $Theme.TextMuted
$lblComputer.AutoSize = $true
$lblComputer.Location = New-Object System.Drawing.Point(15, 32)

$statusPanel.Controls.Add($lblStatus)
$statusPanel.Controls.Add($lblComputer)

$sideNav.Controls.Add($navContainer)
$sideNav.Controls.Add($statusPanel)
$sideNav.Controls.Add($brandPanel)

# Content area
$contentPanel = New-Object System.Windows.Forms.Panel
$contentPanel.Dock = "Fill"
$contentPanel.BackColor = $Theme.Background
$contentPanel.Padding = New-Object System.Windows.Forms.Padding(20, 15, 20, 15)

$contentPanel.Controls.Add($tabControl)
$mainContainer.Controls.Add($contentPanel)
$mainContainer.Controls.Add($sideNav)

# --- Redesigned Helper to add buttons ---
function Add-Button($parent, $text, $scriptBlock, $icon = "") {
    $btn = New-Object System.Windows.Forms.Button
    $displayText = if ($icon) { "  $icon  $text" } else { $text }
    $btn.Text = $displayText
    $btn.Width = 260
    $btn.Height = 44
    $btn.Margin = New-Object System.Windows.Forms.Padding(0, 0, 10, 10)
    $btn.FlatStyle = "Flat"
    $btn.BackColor = $Theme.ButtonBg
    $btn.ForeColor = $Theme.TextPrimary
    $btn.FlatAppearance.BorderSize = 1
    $btn.FlatAppearance.BorderColor = $Theme.Border
    $btn.FlatAppearance.MouseOverBackColor = $Theme.ButtonHover
    $btn.Font = New-Object System.Drawing.Font("Segoe UI", 9.5)
    $btn.TextAlign = "MiddleLeft"
    $btn.Padding = New-Object System.Windows.Forms.Padding(12, 0, 0, 0)
    $btn.Cursor = [System.Windows.Forms.Cursors]::Hand
    
    $jobName = $text
    $jobScript = $scriptBlock
    
    $btn.Add_Click({ 
        Start-WorkerJob -Name $jobName -ScriptBlock $jobScript 
    }.GetNewClosure())
    
    $parent.Controls.Add($btn)
}

# --- Section Header Helper ---
function Add-SectionHeader($parent, $text) {
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = $text.ToUpper()
    $lbl.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $lbl.ForeColor = $Theme.TextMuted
    $lbl.AutoSize = $true
    $lbl.Margin = New-Object System.Windows.Forms.Padding(0, 20, 0, 10)
    $parent.Controls.Add($lbl)
}

# ========================================
# TAB ORGANIZATION
# ========================================
# Tab 0: Dashboard - System overview and real-time status
# Tab 1: Maintenance - Disk cleanup, repairs, updates
# Tab 2: Diagnostics - System info, logs, hardware details
# Tab 3: Network - IP config, scanning, sharing
# Tab 4: Users & Shares - User/share management
# Tab 5: Integrations - NinjaOne RMM
# Tab 6: Security Audit - HIPAA compliance report

# --- Tab 0: Dashboard (Redesigned) ---
$tabDashboard = New-Object System.Windows.Forms.TabPage
$tabDashboard.Text = "Dashboard"
$tabDashboard.BackColor = $Theme.Background
$tabDashboard.Padding = New-Object System.Windows.Forms.Padding(0)

# Dashboard header
$dashHeader = New-Object System.Windows.Forms.Panel
$dashHeader.Dock = "Top"
$dashHeader.Height = 60
$dashHeader.BackColor = $Theme.Background
$dashHeader.Padding = New-Object System.Windows.Forms.Padding(0, 10, 0, 10)

$lblDashTitle = New-Object System.Windows.Forms.Label
$lblDashTitle.Text = "System Overview"
$lblDashTitle.Font = New-Object System.Drawing.Font("Segoe UI", 20, [System.Drawing.FontStyle]::Bold)
$lblDashTitle.ForeColor = $Theme.TextPrimary
$lblDashTitle.AutoSize = $true
$lblDashTitle.Location = New-Object System.Drawing.Point(0, 10)

$btnRefreshDash = New-Object System.Windows.Forms.Button
$btnRefreshDash.Text = [char]0x21BB + " Refresh"
$btnRefreshDash.Width = 100
$btnRefreshDash.Height = 34
$btnRefreshDash.Location = New-Object System.Drawing.Point(740, 15)
$btnRefreshDash.FlatStyle = "Flat"
$btnRefreshDash.BackColor = $Theme.Accent
$btnRefreshDash.ForeColor = "White"
$btnRefreshDash.FlatAppearance.BorderSize = 0
$btnRefreshDash.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$btnRefreshDash.Cursor = [System.Windows.Forms.Cursors]::Hand

$dashHeader.Controls.Add($lblDashTitle)
$dashHeader.Controls.Add($btnRefreshDash)

# Dashboard content with stats cards
$dashContent = New-Object System.Windows.Forms.Panel
$dashContent.Dock = "Fill"
$dashContent.BackColor = $Theme.Background
$dashContent.AutoScroll = $true

# Quick stats cards row
$statsRow = New-Object System.Windows.Forms.FlowLayoutPanel
$statsRow.Location = New-Object System.Drawing.Point(0, 0)
$statsRow.Size = New-Object System.Drawing.Size(850, 90)
$statsRow.FlowDirection = "LeftToRight"

function New-StatCard($title, $value, $color) {
    $card = New-Object System.Windows.Forms.Panel
    $card.Size = New-Object System.Drawing.Size(195, 75)
    $card.BackColor = $Theme.Surface
    $card.Margin = New-Object System.Windows.Forms.Padding(0, 0, 12, 0)
    
    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Text = $title
    $lblTitle.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $lblTitle.ForeColor = $Theme.TextMuted
    $lblTitle.Location = New-Object System.Drawing.Point(15, 12)
    $lblTitle.AutoSize = $true
    
    $lblValue = New-Object System.Windows.Forms.Label
    $lblValue.Text = $value
    $lblValue.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
    $lblValue.ForeColor = $color
    $lblValue.Location = New-Object System.Drawing.Point(15, 35)
    $lblValue.AutoSize = $true
    $lblValue.Name = "Value"
    
    $card.Controls.Add($lblTitle)
    $card.Controls.Add($lblValue)
    return $card
}

$cardCPU = New-StatCard "CPU USAGE" "..." $Theme.Info
$cardRAM = New-StatCard "MEMORY" "..." $Theme.Success
$cardDisk = New-StatCard "DISK (C:)" "..." $Theme.Warning
$cardUptime = New-StatCard "UPTIME" "..." $Theme.TextPrimary

$statsRow.Controls.Add($cardCPU)
$statsRow.Controls.Add($cardRAM)
$statsRow.Controls.Add($cardDisk)
$statsRow.Controls.Add($cardUptime)

# Main dashboard output
$txtDashboard = New-Object System.Windows.Forms.TextBox
$txtDashboard.Multiline = $true
$txtDashboard.ScrollBars = "Vertical"
$txtDashboard.ReadOnly = $true
$txtDashboard.Location = New-Object System.Drawing.Point(0, 100)
$txtDashboard.Size = New-Object System.Drawing.Size(850, 380)
$txtDashboard.Font = New-Object System.Drawing.Font("Cascadia Code, Consolas", 9)
$txtDashboard.BackColor = $Theme.Surface
$txtDashboard.ForeColor = $Theme.ConsoleFg
$txtDashboard.BorderStyle = "None"

$dashContent.Controls.Add($statsRow)
$dashContent.Controls.Add($txtDashboard)

$tabDashboard.Controls.Add($dashContent)
$tabDashboard.Controls.Add($dashHeader)
$btnRefreshDash.Add_Click({
    Log-Output "Refreshing Dashboard..."
    $txtDashboard.Clear()
    
    $dash = @()
    $dash += "=" * 80
    $dash += "SYSTEM OVERVIEW"
    $dash += "=" * 80
    $dash += ""
    
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $cs = Get-CimInstance Win32_ComputerSystem
        $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
        $bios = Get-CimInstance Win32_Bios
        
        $dash += "Computer Name:    $($cs.Name)"
        $dash += "Manufacturer:     $($cs.Manufacturer)"
        $dash += "Model:            $($cs.Model)"
        $dash += "Serial Number:    $($bios.SerialNumber)"
        $dash += "OS:               $($os.Caption) (Build $($os.BuildNumber))"
        $dash += "OS Architecture:  $($os.OSArchitecture)"
        $dash += ""
        
        # CPU
        $dash += "=" * 80
        $dash += "CPU INFORMATION"
        $dash += "=" * 80
        $dash += "Processor:        $($cpu.Name)"
        $dash += "Cores:            $($cpu.NumberOfCores)"
        $dash += "Logical Proc:     $($cpu.NumberOfLogicalProcessors)"
        $dash += ""
        
        # CPU Usage
        $dash += "=" * 80
        $dash += "CPU USAGE"
        $dash += "=" * 80
        $cpuLoad = (Get-CimInstance Win32_Processor).LoadPercentage
        if ($null -eq $cpuLoad) { $cpuLoad = 0 }
        $dash += "Current Load:     $cpuLoad%"
        if ($cpuLoad -gt 90) { $dash += "WARNING: High CPU usage!" }
        $dash += ""
        
        # Memory
        $dash += "=" * 80
        $dash += "MEMORY USAGE"
        $dash += "=" * 80
        $totalRAM = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        $freeRAM = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
        $usedRAM = $totalRAM - $freeRAM
        $usedPct = [math]::Round(($usedRAM / $totalRAM) * 100, 1)
        $dash += "Total RAM:        $totalRAM GB"
        $dash += "Used RAM:         $usedRAM GB ($usedPct%)"
        $dash += "Free RAM:         $freeRAM GB"
        if ($usedPct -gt 90) { $dash += "WARNING: High memory usage!" }
        $dash += ""
        
        # Disk Usage
        $dash += "=" * 80
        $dash += "DISK USAGE"
        $dash += "=" * 80
        $disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3"
        foreach ($d in $disks) {
            $size = [math]::Round($d.Size / 1GB, 2)
            $free = [math]::Round($d.FreeSpace / 1GB, 2)
            $used = $size - $free
            $pct = [math]::Round(($used / $size) * 100, 1)
            $dash += "Drive $($d.DeviceID)       Total: $size GB | Used: $used GB ($pct%) | Free: $free GB"
            if ($pct -gt 85) { $dash += "  [WARNING] Low disk space on $($d.DeviceID)!" }
        }
        $dash += ""
        
        # Physical Disks Health
        $dash += "=" * 80
        $dash += "PHYSICAL DISK HEALTH"
        $dash += "=" * 80
        $physDisks = Get-PhysicalDisk -ErrorAction SilentlyContinue
        if ($physDisks) {
            foreach ($pd in $physDisks) {
                $dash += "$($pd.FriendlyName)"
                $dash += "  Type: $($pd.MediaType) | Health: $($pd.HealthStatus) | Op Status: $($pd.OperationalStatus)"
                if ($pd.HealthStatus -ne "Healthy") { $dash += "  [ALERT] Disk health issue detected!" }
            }
        } else {
            $dash += "Unable to query physical disks (WMI limitation)"
        }
        $dash += ""
        
        # Uptime
        $dash += "=" * 80
        $dash += "UPTIME & PERFORMANCE"
        $dash += "=" * 80
        $uptime = (Get-Date) - $os.LastBootUpTime
        $dash += "Last Boot:        $($os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss'))"
        $dash += "Uptime:           $($uptime.Days) days, $($uptime.Hours) hours, $($uptime.Minutes) minutes"
        if ($uptime.Days -gt 30) { $dash += "WARNING: System has not rebooted in over 30 days!" }
        $dash += ""
        
        # Network
        $dash += "=" * 80
        $dash += "NETWORK ADAPTERS"
        $dash += "=" * 80
        $adapters = Get-NetAdapter | Where-Object Status -eq "Up"
        foreach ($a in $adapters) {
            $dash += "$($a.Name) ($($a.InterfaceDescription))"
            $dash += "  Status: $($a.Status) | Speed: $($a.LinkSpeed)"
            $ip = (Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
            if ($ip) { $dash += "  IP: $ip" }
        }
        $dash += ""
        
        # Event Log Errors
        $dash += "=" * 80
        $dash += "RECENT CRITICAL EVENTS (Last 7 Days)"
        $dash += "=" * 80
        $criticalEvents = Get-WinEvent -FilterHashtable @{LogName='System','Application'; Level=1,2; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 10 -ErrorAction SilentlyContinue
        if ($criticalEvents) {
            foreach ($e in $criticalEvents) {
                $dash += "[$($e.TimeCreated.ToString('MM-dd HH:mm'))] $($e.LogName)/$($e.ProviderName) - ID:$($e.Id)"
                $msgText = if ($e.Message) { $e.Message } else { "(No message)" }
                $truncLen = [Math]::Min(120, $msgText.Length)
                $dash += "  $($msgText.Substring(0, $truncLen))..."
            }
        } else {
            $dash += "No critical events in the last 7 days."
        }
        $dash += ""
        
        # NinjaOne Status
        if ($global:NinjaDeviceData) {
            $dash += "=" * 80
            $dash += "NINJARMM STATUS"
            $dash += "=" * 80
            $dash += "Device ID:        $($global:NinjaDeviceData.id)"
            $dash += "Organization:     $(if($global:NinjaDeviceData.organizationName){$global:NinjaDeviceData.organizationName}else{'ID: ' + $global:NinjaDeviceData.organizationId})"
            $dash += "Last Contact:     $($global:NinjaDeviceData.lastContact)"
            if ($global:NinjaDeviceData.publicIP) { $dash += "Public IP:        $($global:NinjaDeviceData.publicIP)" }
            $dash += ""
        }
        
        $dash += "=" * 80
        $dash += "Dashboard refreshed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        $dash += "=" * 80
        
        # Update stat cards
        $cardCPU.Controls["Value"].Text = "$cpuLoad%"
        $cardCPU.Controls["Value"].ForeColor = if ($cpuLoad -gt 80) { $Theme.Error } elseif ($cpuLoad -gt 50) { $Theme.Warning } else { $Theme.Success }
        
        $cardRAM.Controls["Value"].Text = "$usedPct%"
        $cardRAM.Controls["Value"].ForeColor = if ($usedPct -gt 85) { $Theme.Error } elseif ($usedPct -gt 70) { $Theme.Warning } else { $Theme.Success }
        
        $cDrive = $disks | Where-Object { $_.DeviceID -eq "C:" }
        if ($cDrive) {
            $cPct = [math]::Round((($cDrive.Size - $cDrive.FreeSpace) / $cDrive.Size) * 100, 0)
            $cardDisk.Controls["Value"].Text = "$cPct%"
            $cardDisk.Controls["Value"].ForeColor = if ($cPct -gt 90) { $Theme.Error } elseif ($cPct -gt 75) { $Theme.Warning } else { $Theme.Success }
        }
        
        $cardUptime.Controls["Value"].Text = "$($uptime.Days)d $($uptime.Hours)h"
        $cardUptime.Controls["Value"].ForeColor = if ($uptime.Days -gt 30) { $Theme.Warning } else { $Theme.TextPrimary }
        
    } catch {
        $dash += "Error gathering system information: $_"
        Log-Output "Dashboard error: $_"
    }
    
    $txtDashboard.Lines = $dash
})

# Auto-load dashboard on startup
$form.Add_Shown({
    $btnRefreshDash.PerformClick()
    Update-NavSelection -selectedIndex 0
})

# --- Tab 1: Maintenance (Redesigned) ---
$tabFixes = New-Object System.Windows.Forms.TabPage
$tabFixes.Text = "Maintenance"
$tabFixes.BackColor = $Theme.Background
$tabFixes.Padding = New-Object System.Windows.Forms.Padding(0)

# Page header
$fixHeader = New-Object System.Windows.Forms.Label
$fixHeader.Text = "System Maintenance"
$fixHeader.Font = New-Object System.Drawing.Font("Segoe UI", 20, [System.Drawing.FontStyle]::Bold)
$fixHeader.ForeColor = $Theme.TextPrimary
$fixHeader.Dock = "Top"
$fixHeader.Height = 50
$fixHeader.Padding = New-Object System.Windows.Forms.Padding(0, 10, 0, 0)

$flowFixes = New-Object System.Windows.Forms.FlowLayoutPanel
$flowFixes.Dock = "Fill"
$flowFixes.AutoScroll = $true
$flowFixes.FlowDirection = "LeftToRight"
$flowFixes.WrapContents = $true
$flowFixes.Padding = New-Object System.Windows.Forms.Padding(0, 10, 0, 0)

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
    "Opening Microsoft activation troubleshooting guidance..."
    Start-Process "https://support.microsoft.com/windows/activate-windows"
    "Opened Microsoft activation support page."
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
$tabFixes.Controls.Add($fixHeader)

# --- Tab 2: Diagnostics (Redesigned) ---
$tabInfo = New-Object System.Windows.Forms.TabPage
$tabInfo.Text = "Diagnostics"
$tabInfo.BackColor = $Theme.Background
$tabInfo.Padding = New-Object System.Windows.Forms.Padding(0)

$infoHeader = New-Object System.Windows.Forms.Label
$infoHeader.Text = "System Diagnostics"
$infoHeader.Font = New-Object System.Drawing.Font("Segoe UI", 20, [System.Drawing.FontStyle]::Bold)
$infoHeader.ForeColor = $Theme.TextPrimary
$infoHeader.Dock = "Top"
$infoHeader.Height = 50
$infoHeader.Padding = New-Object System.Windows.Forms.Padding(0, 10, 0, 0)

$flowInfo = New-Object System.Windows.Forms.FlowLayoutPanel
$flowInfo.Dock = "Fill"
$flowInfo.AutoScroll = $true
$flowInfo.FlowDirection = "LeftToRight"
$flowInfo.WrapContents = $true
$flowInfo.Padding = New-Object System.Windows.Forms.Padding(0, 10, 0, 0)

# --- Section: System Information ---
$lblSysInfoSection = New-Object System.Windows.Forms.Label
$lblSysInfoSection.Text = "━━━ System Information ━━━"
$lblSysInfoSection.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$lblSysInfoSection.ForeColor = $Theme.Accent
$lblSysInfoSection.AutoSize = $true
$lblSysInfoSection.Margin = New-Object System.Windows.Forms.Padding(0, 5, 0, 5)
$flowInfo.Controls.Add($lblSysInfoSection)

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
$tabInfo.Controls.Add($infoHeader)

# --- Tab 3: Network Tools (Redesigned) ---
$tabNet = New-Object System.Windows.Forms.TabPage
$tabNet.Text = "Network"
$tabNet.BackColor = $Theme.Background
$tabNet.Padding = New-Object System.Windows.Forms.Padding(0)

$netHeader = New-Object System.Windows.Forms.Label
$netHeader.Text = "Network Tools"
$netHeader.Font = New-Object System.Drawing.Font("Segoe UI", 20, [System.Drawing.FontStyle]::Bold)
$netHeader.ForeColor = $Theme.TextPrimary
$netHeader.Dock = "Top"
$netHeader.Height = 50
$netHeader.Padding = New-Object System.Windows.Forms.Padding(0, 10, 0, 0)

$flowNet = New-Object System.Windows.Forms.FlowLayoutPanel
$flowNet.Dock = "Fill"
$flowNet.AutoScroll = $true
$flowNet.FlowDirection = "LeftToRight"
$flowNet.WrapContents = $true
$flowNet.Padding = New-Object System.Windows.Forms.Padding(0, 10, 0, 0)

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

Add-Button $flowNet "Scan Network Printers (Port 9100)" {
    "Scanning for network printers..."
    
    # Auto-detect subnet
    $Subnet = $null
    try {
        $IPObj = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { 
            $_.IPAddress -notmatch '^127\.' -and $_.IPAddress -notmatch '^169\.254\.' 
        } | Select-Object -First 1
        
        if ($IPObj -and $IPObj.IPAddress -match "^(\d{1,3}\.\d{1,3}\.\d{1,3})\.") {
            $Subnet = $matches[1]
            "Auto-detected subnet: ${Subnet}.x"
            ""
        }
    } catch {
        "Could not auto-detect subnet. Aborting scan."
        return
    }
    
    if (-not $Subnet) {
        "Failed to detect local subnet. Aborting scan."
        return
    }
    
    "Scanning ${Subnet}.1-254 for Port 9100 (JetDirect)..."
    "This will take 30-60 seconds..."
    ""
    
    $ScriptBlock = {
        param($IP, $Timeout)
        
        function Get-SnmpModel {
            param($TargetIP)
            try {
                $Udp = New-Object System.Net.Sockets.UdpClient
                $Udp.Client.ReceiveTimeout = 3000
                $Udp.Connect($TargetIP, 161)
                $Bytes = @(0x30, 0x29, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 
                    0xa0, 0x1c, 0x02, 0x04, 0x19, 0x54, 0x78, 0x33, 0x02, 0x01, 0x00, 0x02, 0x01, 
                    0x00, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 
                    0x01, 0x00, 0x05, 0x00)
                [void]$Udp.Send($Bytes, $Bytes.Length)
                $RemoteEP = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                $ResponseBytes = $Udp.Receive([ref]$RemoteEP)
                $Udp.Close()
                
                $oidBytes = 0x2b,0x06,0x01,0x02,0x01,0x01,0x01,0x00
                $startIndex = -1
                for ($i = 0; $i -le $ResponseBytes.Length - $oidBytes.Length; $i++) {
                    $match = $true
                    for ($j = 0; $j -lt $oidBytes.Length; $j++) {
                        if ($ResponseBytes[$i + $j] -ne $oidBytes[$j]) { $match = $false; break }
                    }
                    if ($match) { $startIndex = $i + $oidBytes.Length; break }
                }
                if ($startIndex -lt 0) { return $null }
                
                $idx = $startIndex
                while ($idx -lt ($ResponseBytes.Length - 2) -and $ResponseBytes[$idx] -ne 0x04) { $idx++ }
                if ($idx -ge ($ResponseBytes.Length - 2)) { return $null }
                
                $len = [int]$ResponseBytes[$idx + 1]
                if ($idx + 2 + $len -gt $ResponseBytes.Length) { $len = $ResponseBytes.Length - $idx - 2 }
                
                $strBytes = $ResponseBytes[($idx + 2)..($idx + 1 + $len)]
                $text = [System.Text.Encoding]::ASCII.GetString($strBytes)
                $CleanString = $text -replace "[^a-zA-Z0-9\s\-\.\_\(\)]", " " -replace "\s+", " "
                return $CleanString.Trim()
            } catch { return $null }
        }
        
        function Get-WebData {
            param($Url)
            try {
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
                [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
                $Request = [System.Net.WebRequest]::Create($Url)
                $Request.Timeout = 3000
                $Request.UserAgent = "Mozilla/5.0"
                $Response = $Request.GetResponse()
                $Stream = $Response.GetResponseStream()
                $Reader = New-Object System.IO.StreamReader($Stream)
                $Content = $Reader.ReadToEnd()
                $Reader.Close(); $Response.Close()
                
                $Result = @{ Found = $false; Info = "" }
                if ($Content -match "(?si)<title>\s*(.*?)\s*</title>") { 
                    $Result.Found = $true
                    $Result.Info = $matches[1].Trim()
                }
                if ($Content -match '(?si)<meta\s+name=["'']description["'']\s+content=["''](.*?)["'']') {
                    $Result.Found = $true
                    $desc = $matches[1].Trim()
                    if ($Result.Info.Length -eq 0 -or $Result.Info -match "Remote UI") {
                        $Result.Info = "$($Result.Info) [$desc]"
                    }
                }
                return $Result
            } catch { return $null }
        }
        
        try {
            $Client = New-Object System.Net.Sockets.TcpClient
            $Connect = $Client.BeginConnect($IP, 9100, $null, $null)
            $Wait = $Connect.AsyncWaitHandle.WaitOne($Timeout, $false)
            
            if ($Wait) {
                $Client.EndConnect($Connect)
                $Client.Close()
                
                $HostName = "Unknown"
                $Model = "Unknown"
                
                try { 
                    $HostEntry = [System.Net.Dns]::GetHostEntry($IP)
                    if ($HostEntry) { $HostName = $HostEntry.HostName }
                } catch {}
                
                $SnmpResult = Get-SnmpModel -TargetIP $IP
                if ($SnmpResult) {
                    $Model = $SnmpResult
                } else {
                    $WebPorts = @(80, 443)
                    foreach ($Port in $WebPorts) {
                        $Scheme = if ($Port -eq 443) { "https" } else { "http" }
                        $TargetUrl = "{0}://{1}:{2}" -f $Scheme, $IP, $Port
                        $WebData = Get-WebData -Url $TargetUrl
                        if ($WebData -and $WebData.Found -and $WebData.Info.Length -gt 0) {
                            $Model = "$($WebData.Info) (Port $Port)"
                            break
                        }
                    }
                }
                
                if (($Model -eq "Unknown" -or [string]::IsNullOrWhiteSpace($Model)) -and $HostName -ne "Unknown") {
                    $Model = "[$HostName]"
                }
                
                return [PSCustomObject]@{
                    IPAddress = $IP
                    HostName  = $HostName
                    Model     = $Model
                }
            }
        } catch { }
    }
    
    $RunspacePool = [runspacefactory]::CreateRunspacePool(1, 50)
    $RunspacePool.Open()
    $Jobs = @()
    
    for ($i = 1; $i -le 254; $i++) {
        $TargetIP = "$Subnet.$i"
        $Pipeline = [powershell]::Create()
        $Pipeline.RunspacePool = $RunspacePool
        [void]$Pipeline.AddScript($ScriptBlock)
        [void]$Pipeline.AddArgument($TargetIP)
        [void]$Pipeline.AddArgument(500)
        $Job = $Pipeline.BeginInvoke()
        $Jobs += [PSCustomObject]@{ Pipeline = $Pipeline; Job = $Job }
    }
    
    $Results = @()
    foreach ($JobObj in $Jobs) {
        try {
            $Result = $JobObj.Pipeline.EndInvoke($JobObj.Job)
            if ($Result) { $Results += $Result }
        } catch { } finally {
            $JobObj.Pipeline.Dispose()
        }
    }
    
    $RunspacePool.Close()
    
    if ($Results.Count -gt 0) {
        "Found $($Results.Count) printer(s):"
        ""
        $Results | Sort-Object IPAddress | Format-Table IPAddress, HostName, Model -AutoSize | Out-String
    } else {
        "No printers found on ${Subnet}.x network."
    }
}

Add-Button $flowNet "Enable Network Sharing (Private/No FW)" {
    "Disabling Windows Firewall..."
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    "Setting Network Profiles to Private..."
    Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private
    "Enabling File and Printer Sharing (Netsh)..."
    netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes
    netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes
    "Network Sharing Enabled and Firewall Disabled."
}

$tabNet.Controls.Add($flowNet)
$tabNet.Controls.Add($netHeader)

# --- Tab 5: Integrations (NinjaOne) - Redesigned ---
$tabIntegrations = New-Object System.Windows.Forms.TabPage
$tabIntegrations.Text = "Integrations"
$tabIntegrations.BackColor = $Theme.Background
$tabIntegrations.Padding = New-Object System.Windows.Forms.Padding(0)

$intHeader = New-Object System.Windows.Forms.Label
$intHeader.Text = "Integrations"
$intHeader.Font = New-Object System.Drawing.Font("Segoe UI", 20, [System.Drawing.FontStyle]::Bold)
$intHeader.ForeColor = $Theme.TextPrimary
$intHeader.Dock = "Top"
$intHeader.Height = 50
$intHeader.Padding = New-Object System.Windows.Forms.Padding(0, 10, 0, 0)

$grpNinja = New-Object System.Windows.Forms.Panel
$grpNinja.Location = New-Object System.Drawing.Point(0, 60)
$grpNinja.Size = New-Object System.Drawing.Size(500, 280)
$grpNinja.BackColor = $Theme.Surface

# Ninja header
$lblNinjaTitle = New-Object System.Windows.Forms.Label
$lblNinjaTitle.Text = [char]0x2601 + "  NinjaOne RMM"
$lblNinjaTitle.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
$lblNinjaTitle.ForeColor = $Theme.TextPrimary
$lblNinjaTitle.Location = New-Object System.Drawing.Point(20, 15)
$lblNinjaTitle.AutoSize = $true
$grpNinja.Controls.Add($lblNinjaTitle)

$lblNinjaDesc = New-Object System.Windows.Forms.Label
$lblNinjaDesc.Text = "Connect to pull device data for Security Audit"
$lblNinjaDesc.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$lblNinjaDesc.ForeColor = $Theme.TextMuted
$lblNinjaDesc.Location = New-Object System.Drawing.Point(20, 40)
$lblNinjaDesc.AutoSize = $true
$grpNinja.Controls.Add($lblNinjaDesc)

# Load Settings
$savedSettings = Get-NinjaSettings

# Inputs
$lblUrl = New-Object System.Windows.Forms.Label
$lblUrl.Text = "Instance URL"
$lblUrl.Location = New-Object System.Drawing.Point(20, 75)
$lblUrl.AutoSize = $true
$lblUrl.ForeColor = $Theme.TextSecondary
$lblUrl.Font = New-Object System.Drawing.Font("Segoe UI", 8)

$txtUrl = New-Object System.Windows.Forms.TextBox
$txtUrl.Location = New-Object System.Drawing.Point(20, 95)
$txtUrl.Width = 440
$txtUrl.Height = 28
$txtUrl.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$txtUrl.BackColor = $Theme.InputBg
$txtUrl.ForeColor = $Theme.TextPrimary
$txtUrl.BorderStyle = "FixedSingle"
$txtUrl.Text = if ($savedSettings.Url) { $savedSettings.Url } else { "app.ninjarmm.com" }

$lblCid = New-Object System.Windows.Forms.Label
$lblCid.Text = "Client ID (blank = use embedded)"
$lblCid.Location = New-Object System.Drawing.Point(20, 130)
$lblCid.AutoSize = $true
$lblCid.ForeColor = $Theme.TextSecondary
$lblCid.Font = New-Object System.Drawing.Font("Segoe UI", 8)

$txtCid = New-Object System.Windows.Forms.TextBox
$txtCid.Location = New-Object System.Drawing.Point(20, 150)
$txtCid.Width = 440
$txtCid.Height = 28
$txtCid.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$txtCid.BackColor = $Theme.InputBg
$txtCid.ForeColor = $Theme.TextPrimary
$txtCid.BorderStyle = "FixedSingle"
$txtCid.Text = if ($savedSettings.ClientId) { $savedSettings.ClientId } else { "" }

$lblSec = New-Object System.Windows.Forms.Label
$lblSec.Text = "Client Secret (blank = use embedded)"
$lblSec.Location = New-Object System.Drawing.Point(20, 185)
$lblSec.AutoSize = $true
$lblSec.ForeColor = $Theme.TextSecondary
$lblSec.Font = New-Object System.Drawing.Font("Segoe UI", 8)

$txtSec = New-Object System.Windows.Forms.TextBox
$txtSec.Location = New-Object System.Drawing.Point(20, 205)
$txtSec.Width = 440
$txtSec.Height = 28
$txtSec.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$txtSec.BackColor = $Theme.InputBg
$txtSec.ForeColor = $Theme.TextPrimary
$txtSec.BorderStyle = "FixedSingle"
$txtSec.UseSystemPasswordChar = $true
$txtSec.Text = if ($savedSettings.ClientSecret) { $savedSettings.ClientSecret } else { "" }

$btnConnect = New-Object System.Windows.Forms.Button
$btnConnect.Text = [char]0x2192 + "  Connect & Sync"
$btnConnect.Location = New-Object System.Drawing.Point(20, 245)
$btnConnect.Width = 180
$btnConnect.Height = 36
$btnConnect.FlatStyle = "Flat"
$btnConnect.BackColor = $Theme.Accent
$btnConnect.ForeColor = "White"
$btnConnect.FlatAppearance.BorderSize = 0
$btnConnect.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$btnConnect.Cursor = [System.Windows.Forms.Cursors]::Hand
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
$tabIntegrations.Controls.Add($intHeader)

# --- Tab 4: User & Shares (Redesigned) ---
$tabUsers = New-Object System.Windows.Forms.TabPage
$tabUsers.Text = "Users & Shares"
$tabUsers.BackColor = $Theme.Background
$tabUsers.Padding = New-Object System.Windows.Forms.Padding(0)

$usersHeader = New-Object System.Windows.Forms.Label
$usersHeader.Text = "Users & Network Shares"
$usersHeader.Font = New-Object System.Drawing.Font("Segoe UI", 20, [System.Drawing.FontStyle]::Bold)
$usersHeader.ForeColor = $Theme.TextPrimary
$usersHeader.Dock = "Top"
$usersHeader.Height = 50
$usersHeader.Padding = New-Object System.Windows.Forms.Padding(0, 10, 0, 0)

# Panel: User Management
$grpUser = New-Object System.Windows.Forms.Panel
$grpUser.Location = New-Object System.Drawing.Point(0, 60)
$grpUser.Size = New-Object System.Drawing.Size(400, 380)
$grpUser.BackColor = $Theme.Surface

$lblUserTitle = New-Object System.Windows.Forms.Label
$lblUserTitle.Text = [char]0x263A + "  User Management"
$lblUserTitle.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$lblUserTitle.ForeColor = $Theme.TextPrimary
$lblUserTitle.Location = New-Object System.Drawing.Point(15, 12)
$lblUserTitle.AutoSize = $true
$grpUser.Controls.Add($lblUserTitle)

$lblUserList = New-Object System.Windows.Forms.Label
$lblUserList.Text = "LOCAL USERS"
$lblUserList.Location = New-Object System.Drawing.Point(15, 45)
$lblUserList.AutoSize = $true
$lblUserList.ForeColor = $Theme.TextMuted
$lblUserList.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$grpUser.Controls.Add($lblUserList)

$lstUsers = New-Object System.Windows.Forms.ListBox
$lstUsers.Location = New-Object System.Drawing.Point(15, 65)
$lstUsers.Size = New-Object System.Drawing.Size(370, 80)
$lstUsers.BackColor = $Theme.InputBg
$lstUsers.ForeColor = $Theme.TextPrimary
$lstUsers.BorderStyle = "FixedSingle"
$lstUsers.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$lstUsers.Add_SelectedIndexChanged({
    if ($lstUsers.SelectedItem) {
        $txtUName.Text = $lstUsers.SelectedItem
        Log-Output "Selected user: $($lstUsers.SelectedItem)"
    }
})
$grpUser.Controls.Add($lstUsers)

$btnRefreshUsers = New-Object System.Windows.Forms.Button
$btnRefreshUsers.Text = [char]0x21BB
$btnRefreshUsers.Location = New-Object System.Drawing.Point(350, 40)
$btnRefreshUsers.Width = 35
$btnRefreshUsers.Height = 22
$btnRefreshUsers.FlatStyle = "Flat"
$btnRefreshUsers.BackColor = $Theme.ButtonBg
$btnRefreshUsers.ForeColor = $Theme.TextSecondary
$btnRefreshUsers.FlatAppearance.BorderSize = 1
$btnRefreshUsers.FlatAppearance.BorderColor = $Theme.Border
$btnRefreshUsers.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnRefreshUsers.Add_Click({
    Log-Output "Refreshing user list..."
    $lstUsers.Items.Clear()
    try {
        $users = Get-LocalUser | Select-Object -ExpandProperty Name
        foreach ($u in $users) { $lstUsers.Items.Add($u) | Out-Null }
        Log-Output "Loaded $($users.Count) users"
    } catch { Log-Output "Error loading users: $_" }
})
$grpUser.Controls.Add($btnRefreshUsers)

$lblUName = New-Object System.Windows.Forms.Label
$lblUName.Text = "USERNAME"
$lblUName.Location = New-Object System.Drawing.Point(15, 155)
$lblUName.AutoSize = $true
$lblUName.ForeColor = $Theme.TextMuted
$lblUName.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$grpUser.Controls.Add($lblUName)

$txtUName = New-Object System.Windows.Forms.TextBox
$txtUName.Location = New-Object System.Drawing.Point(15, 173)
$txtUName.Width = 370
$txtUName.Height = 26
$txtUName.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$txtUName.BackColor = $Theme.InputBg
$txtUName.ForeColor = $Theme.TextPrimary
$txtUName.BorderStyle = "FixedSingle"
$grpUser.Controls.Add($txtUName)

$lblUPass = New-Object System.Windows.Forms.Label
$lblUPass.Text = "PASSWORD"
$lblUPass.Location = New-Object System.Drawing.Point(15, 205)
$lblUPass.AutoSize = $true
$lblUPass.ForeColor = $Theme.TextMuted
$lblUPass.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$grpUser.Controls.Add($lblUPass)

$txtUPass = New-Object System.Windows.Forms.TextBox
$txtUPass.Location = New-Object System.Drawing.Point(15, 223)
$txtUPass.Width = 370
$txtUPass.Height = 26
$txtUPass.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$txtUPass.BackColor = $Theme.InputBg
$txtUPass.ForeColor = $Theme.TextPrimary
$txtUPass.BorderStyle = "FixedSingle"
$grpUser.Controls.Add($txtUPass)

# Helper for User Buttons
function Add-UserButton($parent, $text, $x, $y, $script) {
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $text
    $btn.Location = New-Object System.Drawing.Point($x, $y)
    $btn.Width = 120
    $btn.Height = 28
    $btn.FlatStyle = "Flat"
    $btn.BackColor = $Theme.ButtonBg
    $btn.ForeColor = $Theme.TextPrimary
    $btn.FlatAppearance.BorderSize = 1
    $btn.FlatAppearance.BorderColor = $Theme.Border
    $btn.FlatAppearance.MouseOverBackColor = $Theme.ButtonHover
    $btn.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $btn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $btn.Add_Click($script)
    $parent.Controls.Add($btn)
}

Add-UserButton $grpUser "Create User" 15 260 {
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

Add-UserButton $grpUser "Reset Password" 140 260 {
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

Add-UserButton $grpUser "Add to Admins" 265 260 {
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

Add-UserButton $grpUser "Enable User" 15 295 {
    $u = $txtUName.Text
    if (-not $u) { Log-Output "Username required."; return }
    Start-WorkerJob -Name "Enable User" -ArgumentList @($u) -ScriptBlock { param($u); Enable-LocalUser $u; "User '$u' enabled." }
}

Add-UserButton $grpUser "Disable User" 140 295 {
    $u = $txtUName.Text
    if (-not $u) { Log-Output "Username required."; return }
    Start-WorkerJob -Name "Disable User" -ArgumentList @($u) -ScriptBlock { param($u); Disable-LocalUser $u; "User '$u' disabled." }
}

Add-UserButton $grpUser "Delete User" 265 295 {
    $u = $txtUName.Text
    if (-not $u) { Log-Output "Username required."; return }
    Start-WorkerJob -Name "Delete User" -ArgumentList @($u) -ScriptBlock { param($u); Remove-LocalUser $u -ErrorAction Stop; "User '$u' deleted." }
}

# Panel: Share Management
$grpShare = New-Object System.Windows.Forms.Panel
$grpShare.Location = New-Object System.Drawing.Point(420, 60)
$grpShare.Size = New-Object System.Drawing.Size(400, 380)
$grpShare.BackColor = $Theme.Surface

$lblShareTitle = New-Object System.Windows.Forms.Label
$lblShareTitle.Text = [char]0x21C4 + "  Network Shares"
$lblShareTitle.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$lblShareTitle.ForeColor = $Theme.TextPrimary
$lblShareTitle.Location = New-Object System.Drawing.Point(15, 12)
$lblShareTitle.AutoSize = $true
$grpShare.Controls.Add($lblShareTitle)

$lblShareList = New-Object System.Windows.Forms.Label
$lblShareList.Text = "NETWORK SHARES"
$lblShareList.Location = New-Object System.Drawing.Point(15, 45)
$lblShareList.AutoSize = $true
$lblShareList.ForeColor = $Theme.TextMuted
$lblShareList.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$grpShare.Controls.Add($lblShareList)

$lstShares = New-Object System.Windows.Forms.ListBox
$lstShares.Location = New-Object System.Drawing.Point(15, 65)
$lstShares.Size = New-Object System.Drawing.Size(370, 80)
$lstShares.BackColor = $Theme.InputBg
$lstShares.ForeColor = $Theme.TextPrimary
$lstShares.BorderStyle = "FixedSingle"
$lstShares.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$lstShares.Add_SelectedIndexChanged({
    if ($lstShares.SelectedItem) {
        $shareName = $lstShares.SelectedItem -replace " \(.*\)$", ""
        $txtSName.Text = $shareName
        try {
            $share = Get-SmbShare -Name $shareName -ErrorAction Stop
            $txtSPath.Text = $share.Path
            Log-Output "Selected share: $shareName -> $($share.Path)"
        } catch { Log-Output "Error loading share details: $_" }
    }
})
$grpShare.Controls.Add($lstShares)

$btnRefreshShares = New-Object System.Windows.Forms.Button
$btnRefreshShares.Text = [char]0x21BB
$btnRefreshShares.Location = New-Object System.Drawing.Point(350, 40)
$btnRefreshShares.Width = 35
$btnRefreshShares.Height = 22
$btnRefreshShares.FlatStyle = "Flat"
$btnRefreshShares.BackColor = $Theme.ButtonBg
$btnRefreshShares.ForeColor = $Theme.TextSecondary
$btnRefreshShares.FlatAppearance.BorderSize = 1
$btnRefreshShares.FlatAppearance.BorderColor = $Theme.Border
$btnRefreshShares.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnRefreshShares.Add_Click({
    Log-Output "Refreshing share list..."
    $lstShares.Items.Clear()
    try {
        $shares = Get-SmbShare | Where-Object { $_.Name -notin @("IPC$", "ADMIN$", "C$", "D$", "E$") }
        foreach ($s in $shares) { $lstShares.Items.Add("$($s.Name) ($($s.Path))") | Out-Null }
        Log-Output "Loaded $($shares.Count) shares"
    } catch { Log-Output "Error loading shares: $_" }
})
$grpShare.Controls.Add($btnRefreshShares)

$lblSPath = New-Object System.Windows.Forms.Label
$lblSPath.Text = "FOLDER PATH"
$lblSPath.Location = New-Object System.Drawing.Point(15, 155)
$lblSPath.AutoSize = $true
$lblSPath.ForeColor = $Theme.TextMuted
$lblSPath.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$grpShare.Controls.Add($lblSPath)

$txtSPath = New-Object System.Windows.Forms.TextBox
$txtSPath.Location = New-Object System.Drawing.Point(15, 173)
$txtSPath.Width = 370
$txtSPath.Height = 26
$txtSPath.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$txtSPath.BackColor = $Theme.InputBg
$txtSPath.ForeColor = $Theme.TextPrimary
$txtSPath.BorderStyle = "FixedSingle"
$grpShare.Controls.Add($txtSPath)

$lblSName = New-Object System.Windows.Forms.Label
$lblSName.Text = "SHARE NAME"
$lblSName.Location = New-Object System.Drawing.Point(15, 205)
$lblSName.AutoSize = $true
$lblSName.ForeColor = $Theme.TextMuted
$lblSName.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$grpShare.Controls.Add($lblSName)

$txtSName = New-Object System.Windows.Forms.TextBox
$txtSName.Location = New-Object System.Drawing.Point(15, 223)
$txtSName.Width = 370
$txtSName.Height = 26
$txtSName.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$txtSName.BackColor = $Theme.InputBg
$txtSName.ForeColor = $Theme.TextPrimary
$txtSName.BorderStyle = "FixedSingle"
$grpShare.Controls.Add($txtSName)

Add-UserButton $grpShare "Create Share (Full Access)" 15 260 {
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
$grpShare.Controls[$grpShare.Controls.Count-1].Width = 180

Add-UserButton $grpShare "Delete Share" 205 260 {
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
$grpShare.Controls[$grpShare.Controls.Count-1].Width = 180

# Auto-load on tab open
$tabUsers.Controls.Add($grpUser)
$tabUsers.Controls.Add($grpShare)
$tabUsers.Controls.Add($usersHeader)

# Trigger initial load when tab is selected
$tabControl.Add_Selected({
    if ($tabControl.SelectedTab -eq $tabUsers) {
        if ($lstUsers.Items.Count -eq 0) { $btnRefreshUsers.PerformClick() }
        if ($lstShares.Items.Count -eq 0) { $btnRefreshShares.PerformClick() }
    }
})

# --- Tab 6: Security Audit (Redesigned) ---
$tabAudit = New-Object System.Windows.Forms.TabPage
$tabAudit.Text = "Security Audit"
$tabAudit.BackColor = $Theme.Background
$tabAudit.Padding = New-Object System.Windows.Forms.Padding(0)

$auditHeader = New-Object System.Windows.Forms.Label
$auditHeader.Text = "Security Audit"
$auditHeader.Font = New-Object System.Drawing.Font("Segoe UI", 20, [System.Drawing.FontStyle]::Bold)
$auditHeader.ForeColor = $Theme.TextPrimary
$auditHeader.Dock = "Top"
$auditHeader.Height = 50
$auditHeader.Padding = New-Object System.Windows.Forms.Padding(0, 10, 0, 0)

# Audit card
$auditCard = New-Object System.Windows.Forms.Panel
$auditCard.Location = New-Object System.Drawing.Point(0, 60)
$auditCard.Size = New-Object System.Drawing.Size(500, 200)
$auditCard.BackColor = $Theme.Surface

$lblAuditIcon = New-Object System.Windows.Forms.Label
$lblAuditIcon.Text = [char]0x2713
$lblAuditIcon.Font = New-Object System.Drawing.Font("Segoe UI", 32)
$lblAuditIcon.ForeColor = $Theme.Success
$lblAuditIcon.Location = New-Object System.Drawing.Point(20, 20)
$lblAuditIcon.AutoSize = $true
$auditCard.Controls.Add($lblAuditIcon)

$lblAuditTitle = New-Object System.Windows.Forms.Label
$lblAuditTitle.Text = "HIPAA Security Audit"
$lblAuditTitle.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
$lblAuditTitle.ForeColor = $Theme.TextPrimary
$lblAuditTitle.Location = New-Object System.Drawing.Point(80, 25)
$lblAuditTitle.AutoSize = $true
$auditCard.Controls.Add($lblAuditTitle)

$lblAudit = New-Object System.Windows.Forms.Label
$lblAudit.Text = "Generates a comprehensive Security and Backup Audit`nHTML report for HIPAA compliance documentation."
$lblAudit.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$lblAudit.ForeColor = $Theme.TextSecondary
$lblAudit.Location = New-Object System.Drawing.Point(80, 55)
$lblAudit.AutoSize = $true
$auditCard.Controls.Add($lblAudit)

$btnRunAudit = New-Object System.Windows.Forms.Button
$btnRunAudit.Text = [char]0x2192 + "  Generate Audit Report"
$btnRunAudit.Location = New-Object System.Drawing.Point(20, 130)
$btnRunAudit.Width = 220
$btnRunAudit.Height = 50
$btnRunAudit.FlatStyle = "Flat"
$btnRunAudit.BackColor = $Theme.Accent
$btnRunAudit.ForeColor = "White"
$btnRunAudit.FlatAppearance.BorderSize = 0
$btnRunAudit.Font = New-Object System.Drawing.Font("Segoe UI", 11)
$btnRunAudit.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnRunAudit.Add_Click({
    Log-Output "=== Generate Audit Report Clicked ==="
    
    # Warn user about UI freeze
    $btnRunAudit.Text = "Generating... Please Wait"
    $btnRunAudit.Enabled = $false
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    [System.Windows.Forms.Application]::DoEvents()
    
    try {
        # Auto-connect to NinjaOne if not already connected
        if (-not $global:NinjaToken) {
            Log-Output "Not connected to NinjaOne. Attempting auto-connect..."
            $savedSettings = Get-NinjaSettings
            if ($savedSettings -and $savedSettings.Url) {
                Connect-NinjaOne -ClientId $savedSettings.ClientId -ClientSecret $savedSettings.ClientSecret -InstanceUrl $savedSettings.Url
            } else {
                Log-Output "No saved NinjaOne settings. Skipping Ninja integration."
            }
        } else {
            Log-Output "Already connected to NinjaOne. Token exists."
            # Refresh device data if we have a token but no device data
            if (-not $global:NinjaDeviceData) {
                Log-Output "No device data cached. Fetching..."
                Get-NinjaDeviceData
            }
        }
        
        Log-Output "Starting Security Audit..."
        Invoke-SecurityAudit
    } finally {
        # Restore button state
        $btnRunAudit.Text = [char]0x2192 + "  Generate Audit Report"
        $btnRunAudit.Enabled = $true
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
    }
})

$auditCard.Controls.Add($btnRunAudit)
$tabAudit.Controls.Add($auditCard)
$tabAudit.Controls.Add($auditHeader)

# --- Assemble Form ---
$tabControl.Controls.Add($tabDashboard)
$tabControl.Controls.Add($tabFixes)
$tabControl.Controls.Add($tabInfo)
$tabControl.Controls.Add($tabNet)
$tabControl.Controls.Add($tabIntegrations)
$tabControl.Controls.Add($tabUsers)
$tabControl.Controls.Add($tabAudit)

$form.Controls.Add($panelOutput)
$form.Controls.Add($mainContainer)

# --- SECURITY AUDIT LOGIC (Embedded) ---
function Invoke-SecurityAudit {
    # This function contains the logic provided by the user
    
    Log-Output "Initializing Jeremy Bean Audit..."
    Log-Output "NOTE: This process takes 30-60 seconds. The window may appear unresponsive."
    if ($form -and $form.Visible) { [System.Windows.Forms.Application]::DoEvents() }
    
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
    if ($form -and $form.Visible) { [System.Windows.Forms.Application]::DoEvents() }
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
    if ($form -and $form.Visible) { [System.Windows.Forms.Application]::DoEvents() }
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
             # If we have valid Ninja data, we can overwrite a local error message
             if ($MissingUpdatesHTML -like "Error*") { $MissingUpdatesHTML = "" }
             
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
        
        # Fix for Server OS where SecurityCenter2 is missing
        if (-not $AV) {
            $AV = [PSCustomObject]@{ displayName = "Windows Defender" }
        }
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
        # Get-LocalUser with SID filter (LocalUsers select doesn't include SID)
        $BuiltInAdmin = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.SID -like "*-500" }
        
        if ($BuiltInAdmin -and $BuiltInAdmin.PasswordLastSet) {
            $AdminPassLastSet = $BuiltInAdmin.PasswordLastSet.ToString("yyyy-MM-dd")
            $DaysSinceChange = (New-TimeSpan -Start $BuiltInAdmin.PasswordLastSet -End (Get-Date)).Days
            if ($DaysSinceChange -gt 90) { 
                $AdminPassChangedRegularly = "No" 
                $AdminPassLastSet += " ($DaysSinceChange days ago)"
            } else {
                $AdminPassChangedRegularly = "Yes"
            }
        } elseif ($BuiltInAdmin) {
            $AdminPassLastSet = "Never Set"
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
    if ($form -and $form.Visible) { [System.Windows.Forms.Application]::DoEvents() }
    $TPM = $null
    try {
        # TBS service may not be available on all systems
        $TPM = Get-Tpm -ErrorAction Stop
    } catch {
        Log-Output "TPM check skipped (TBS service not available or not supported): $_"
    }
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
    if ($form -and $form.Visible) { [System.Windows.Forms.Application]::DoEvents() }
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
    if ($form -and $form.Visible) { [System.Windows.Forms.Application]::DoEvents() }
    $LogSettings = Get-EventLog -List | Where-Object { $_.Log -eq 'Security' }
    $Events = Get-WinEvent -FilterHashtable @{LogName='System','Application'; Level=1,2; StartTime=(Get-Date).AddDays(-$EventLookbackDays)} -ErrorAction SilentlyContinue | Select-Object -First $MaxEventsToShow

    # App Error Scan
    $AppErrors = Get-WinEvent -FilterHashtable @{LogName='Application'; Level=2; StartTime=(Get-Date).AddDays(-30)} -ErrorAction SilentlyContinue | Select-Object -First 1
    $AppErrorSel = if ($AppErrors) { "Yes" } else { "No" }

    # New: Database Error Scan (SQL/MySQL/Oracle keywords)
    # ProviderName wildcards are not reliable in FilterHashtable; do a bounded fetch and match locally.
    $DBErrors = $null
    try {
        $recentApp = Get-WinEvent -FilterHashtable @{LogName='Application'; Level=1,2; StartTime=(Get-Date).AddDays(-30)} -MaxEvents 300 -ErrorAction SilentlyContinue
        if ($recentApp) {
            $DBErrors = $recentApp | Where-Object {
                ($_.ProviderName -match 'SQL|Database|MySQL|Oracle') -or ($_.Message -match 'SQL|Database|MySQL|Oracle')
            } | Select-Object -First 1
        }
    } catch {
        $DBErrors = $null
    }
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
    $NinjaOrgName = ""
    $NinjaLocationName = ""
    $NinjaRAIDStatus = ""  # Will be populated from /v2/device/{id}/disks
    $NinjaDiskInfo = ""    # Disk health summary
    $NinjaLastReboot = ""
    $NinjaLastLoggedUser = ""
    $NinjaCustomFields = @{}
    
    Log-Output "Initializing Ninja integration variables..."
    
    if ($global:NinjaDeviceData) {
        Log-Output "[-] Fetching extended NinjaOne device data..."
        
        # Basic identifiers
        if ($global:NinjaDeviceData.organizationId) { $ClientNameVal = "Ninja Org ID: $($global:NinjaDeviceData.organizationId)" }
        if ($global:NinjaDeviceData.locationId) { $LocationDefault += " (Ninja Loc: $($global:NinjaDeviceData.locationId))" }
        if ($global:NinjaDeviceData.publicIP) { $OpenPortsStr += " [Public IP: $($global:NinjaDeviceData.publicIP)]" }
        
        # Last Reboot
        if ($global:NinjaDeviceData.lastReboot) { 
            $NinjaLastReboot = $global:NinjaDeviceData.lastReboot 
            Log-Output "Ninja Last Reboot: $NinjaLastReboot"
        }
        
        # Last Logged In User
        if ($global:NinjaDeviceData.lastLoggedInUser) { 
            $NinjaLastLoggedUser = $global:NinjaDeviceData.lastLoggedInUser 
            Log-Output "Ninja Last User: $NinjaLastLoggedUser"
        }
        
        # Fetch Detailed Info (Software/Disks/RAID/Custom Fields)
        try {
            $headers = @{ Authorization = "Bearer $global:NinjaToken" }
            $devId = $global:NinjaDeviceData.id
            Log-Output "Device ID for extended queries: $devId"
            
            # Organization Name
            try {
                if ($global:NinjaDeviceData.organizationId) {
                    $orgUrl = "https://$($global:NinjaInstance)/v2/organizations/$($global:NinjaDeviceData.organizationId)"
                    $org = Invoke-RestMethod -Uri $orgUrl -Headers $headers -ErrorAction Stop
                    $NinjaOrgName = $org.name
                    $ClientNameVal = $NinjaOrgName
                    Log-Output "Organization Name: $NinjaOrgName"
                }
            } catch { Log-Output "Could not fetch organization name: $_" }
            
            # Location Name
            try {
                if ($global:NinjaDeviceData.locationId) {
                    $locUrl = "https://$($global:NinjaInstance)/v2/organization/$($global:NinjaDeviceData.organizationId)/locations/$($global:NinjaDeviceData.locationId)"
                    $loc = Invoke-RestMethod -Uri $locUrl -Headers $headers -ErrorAction Stop
                    $NinjaLocationName = $loc.name
                    $LocationDefault = $NinjaLocationName
                    Log-Output "Location Name: $NinjaLocationName"
                }
            } catch { Log-Output "Could not fetch location name: $_" }
            
            # Software Inventory (ChiroTouch)
            try {
                $nSoft = Invoke-RestMethod -Uri "https://$($global:NinjaInstance)/v2/device/$devId/software" -Headers $headers -ErrorAction Stop
                if ($nSoft -and ($nSoft | Where-Object { $_.name -match "ChiroTouch" })) { 
                    $ChiroInstalled = $true
                    if ($ChiroEncryptedSel -eq "N/A") { $ChiroEncryptedSel = if ($C_Encrypted) { "Yes" } else { "No" } }
                    Log-Output "ChiroTouch detected via Ninja"
                }
            } catch { Log-Output "Could not fetch software inventory: $_" }
            
            # Disk/RAID Status
            try {
                $nDisks = Invoke-RestMethod -Uri "https://$($global:NinjaInstance)/v2/device/$devId/disks" -Headers $headers -ErrorAction Stop
                if ($nDisks) {
                    Log-Output "Disk data retrieved from Ninja: $($nDisks.Count) disks"
                    
                    # Look for RAID information
                    $raidDisks = $nDisks | Where-Object { $_.raidType -or $_.volumeType -match "RAID" }
                    if ($raidDisks) {
                        $NinjaRAIDStatus = ($raidDisks | ForEach-Object { 
                            "$($_.name): $($_.raidType) - $($_.health)" 
                        }) -join "; "
                        Log-Output "RAID Status from Ninja: $NinjaRAIDStatus"
                    }
                    
                    # Disk health summary
                    $unhealthyDisks = $nDisks | Where-Object { $_.health -ne "Healthy" -and $_.health -ne $null }
                    if ($unhealthyDisks) {
                        $NinjaDiskInfo = "WARNING: " + ($unhealthyDisks | ForEach-Object { 
                            "$($_.name) ($($_.health))" 
                        }) -join ", "
                    } else {
                        $NinjaDiskInfo = "All disks healthy"
                    }
                    Log-Output "Disk Health: $NinjaDiskInfo"
                }
            } catch { Log-Output "Could not fetch disk data: $_" }
            
            # Custom Fields (for client-specific data)
            try {
                $nCustom = Invoke-RestMethod -Uri "https://$($global:NinjaInstance)/v2/device/$devId/custom-fields" -Headers $headers -ErrorAction Stop
                if ($nCustom) {
                    foreach ($prop in $nCustom.PSObject.Properties) {
                        $NinjaCustomFields[$prop.Name] = $prop.Value
                    }
                    Log-Output "Custom Fields: $($NinjaCustomFields.Keys -join ', ')"
                }
            } catch { Log-Output "Could not fetch custom fields: $_" }
            
        } catch { 
            Log-Output "Ninja Detail Fetch Error: $_" 
        }
    } else {
        Log-Output "No NinjaOne device data available for extended queries."
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
        $(if($NinjaLastLoggedUser){"<tr><th>Last Logged User (Ninja)</th><td>$NinjaLastLoggedUser</td></tr>"})
        $(if($NinjaLastReboot){"<tr><th>Last Reboot (Ninja)</th><td>$NinjaLastReboot</td></tr>"})
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
                    $evtMsg = if ($_.Message) { $_.Message.Substring(0, [Math]::Min(50, $_.Message.Length)) } else { "(No message)" }
                    "<tr><td>$($_.ProviderName)</td><td>$($_.Id)</td><td>$evtMsg...</td><td><a href='https://www.google.com/search?q=$q' target='_blank' class='ai-link'>Ask AI</a></td></tr>"
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
        <tr><th>RAID status</th><td>$(Get-HtmlInput "e.g., RAID 5 Healthy" -Value $(if($NinjaRAIDStatus){$NinjaRAIDStatus}else{""}))</td></tr>
        <tr><th>Storage warnings?</th><td>$(Get-HtmlInput "Describe..." -Value $(if($StorageWarning -or $NinjaDiskInfo){"$StorageWarning $(if($NinjaDiskInfo){" | Ninja: $NinjaDiskInfo"})"}else{""}))</td></tr>
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
