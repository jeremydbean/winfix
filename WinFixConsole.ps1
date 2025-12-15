<#
.SYNOPSIS
  WinFix Console - menu-driven PowerShell version (no WinForms / no EXE).
.DESCRIPTION
  Provides the same operational features as WinFixTool.ps1, but runs in a PowerShell console.
  Designed for quick launch from any PowerShell session. Supports running selected tasks
  in a new PowerShell window that stays open for log checking.
.NOTES
  Requires Administrator privileges for most actions.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TaskName,

    [Parameter(Mandatory = $false)]
    [string[]]$TaskArgs = @(),

    [Parameter(Mandatory = $false)]
    [switch]$NoNewWindow
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Elevate if needed ---
try {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
} catch {
    $isAdmin = $false
}

if (-not $isAdmin) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'powershell.exe'
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" + $(if ($TaskName) { " -TaskName `"$TaskName`"" } else { '' })
    $psi.Verb = 'runas'
    try { [System.Diagnostics.Process]::Start($psi) | Out-Null } catch { }
    exit
}

# --- Logging ---
$script:LogFilePath = Join-Path $env:TEMP 'WinFix_Debug.log'
$null = New-Item -Path $script:LogFilePath -ItemType File -Force -ErrorAction SilentlyContinue

function Write-Log {
    param([Parameter(Mandatory)] [string]$Message)

    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    $line = "[$ts] $Message"
    try { Add-Content -Path $script:LogFilePath -Value $line -ErrorAction SilentlyContinue } catch { }
    Write-Host $line
}

function Pause-Window {
    param([string]$Prompt = 'Press Enter to close this window...')
    try { $null = Read-Host $Prompt } catch { }
}

function Start-TaskWindow {
    param(
        [Parameter(Mandatory)] [string]$Name,
        [string[]]$Args = @()
    )

    if ($NoNewWindow) {
        Invoke-Task -Name $Name -Args $Args
        Pause-Window
        return
    }

    $argLiteral = if ($Args -and $Args.Count -gt 0) {
        # Quote each arg for PowerShell -Command
        $quoted = $Args | ForEach-Object { '"' + ($_ -replace '"', '\\"') + '"' }
        "-TaskArgs @($($quoted -join ', '))"
    } else {
        "-TaskArgs @()"
    }

    $cmd = "& `"$PSCommandPath`" -TaskName `"$Name`" $argLiteral; exit"
    $full = "-NoProfile -ExecutionPolicy Bypass -NoExit -Command `"$cmd; Read-Host 'Press Enter to close' | Out-Null`""

    Write-Log "Launching task in new window: $Name"
    Start-Process -FilePath 'powershell.exe' -ArgumentList $full | Out-Null
}

# --- NinjaOne helpers (ported) ---
$global:NinjaToken = $null
$global:NinjaInstance = $null
$global:NinjaDeviceData = $null

function Get-NinjaSettings {
    $configDir = Join-Path $env:APPDATA 'WinFixTool'
    $configPath = Join-Path $configDir 'ninja_config.xml'
    if (Test-Path $configPath) {
        try { return Import-Clixml $configPath } catch { Write-Log 'Could not load saved NinjaOne settings.' }
    }
    return $null
}

function Save-NinjaSettings {
    param([string]$Url, [string]$Id, [string]$Secret)
    $configDir = Join-Path $env:APPDATA 'WinFixTool'
    if (-not (Test-Path $configDir)) { New-Item -ItemType Directory -Path $configDir -Force | Out-Null }
    $configPath = Join-Path $configDir 'ninja_config.xml'
    [PSCustomObject]@{ Url = $Url; ClientId = $Id; ClientSecret = $Secret } | Export-Clixml -Path $configPath
    Write-Log 'NinjaOne settings saved.'
}

function Decrypt-String {
    param([string]$EncryptedString, [string]$Password)
    try {
        $bytes = [Convert]::FromBase64String($EncryptedString)
        if ($bytes.Length -lt 32) { throw 'Invalid data' }
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
    } catch {
        Write-Log "Decryption error: $_"
        return $null
    }
}

function Get-LocalNinjaNodeId {
    $paths = @(
        'HKLM:\SOFTWARE\NinjaRMM\Agent',
        'HKLM:\SOFTWARE\WOW6432Node\NinjaRMM\Agent',
        'HKLM:\SOFTWARE\NinjaMSP\Agent',
        'HKLM:\SOFTWARE\WOW6432Node\NinjaMSP\Agent'
    )

    foreach ($path in $paths) {
        if (Test-Path $path) {
            $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            if ($props.NodeID) { return $props.NodeID }
            if ($props.DeviceID) { return $props.DeviceID }
            if ($props.id) { return $props.id }
            if ($props.agent_id) { return $props.agent_id }
        }
    }
    return $null
}

function Connect-NinjaOne {
    param(
        [string]$ClientId,
        [string]$ClientSecret,
        [Parameter(Mandatory)] [string]$InstanceUrl
    )

    Write-Log '=== Connect-NinjaOne ==='

    $InstanceUrl = $InstanceUrl -replace '^https?://', '' -replace '/$', ''
    if ($InstanceUrl -match '/') { $InstanceUrl = ($InstanceUrl -split '/')[0] }

    $EncId = "lBPqaFXSjLrCJAKy9V7db00ImBVi7TmzocC4R1xmdaquRX+F0GzTWa+acd1lnhLb2U/h6ORrbF0vIKW55pihnQ=="
    $EncSec = "EiRj/vGljBBXUDGrBkAEoXYldnzwzmYL40JvGK8ahShnk8nzBKtbuRujuandJ41QEgPc04ttpCLkGfAsW6vTrkd85nfgGG3g0/gRrNsLoH8="
    $Pass = 'smoke007'

    if ([string]::IsNullOrWhiteSpace($ClientId)) { Write-Log 'Using embedded Client ID...'; $ClientId = Decrypt-String -EncryptedString $EncId -Password $Pass }
    if ([string]::IsNullOrWhiteSpace($ClientSecret)) { Write-Log 'Using embedded Client Secret...'; $ClientSecret = Decrypt-String -EncryptedString $EncSec -Password $Pass }

    $apiHost = $InstanceUrl
    if ($apiHost -match '^app\.') { $apiHost = $apiHost -replace '^app\.', 'api.' }
    elseif ($apiHost -match '^eu\.') { $apiHost = $apiHost -replace '^eu\.', 'eu-api.' }
    elseif ($apiHost -match '^oc\.') { $apiHost = $apiHost -replace '^oc\.', 'oc-api.' }
    elseif ($apiHost -match '^ca\.') { $apiHost = $apiHost -replace '^ca\.', 'ca-api.' }

    $tokenUrl = "https://$apiHost/ws/oauth/token"
    $body = @{ grant_type = 'client_credentials'; client_id = $ClientId; client_secret = $ClientSecret; scope = 'monitoring' }

    try {
        $resp = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $body -ErrorAction Stop
        $global:NinjaToken = $resp.access_token
        $global:NinjaInstance = $apiHost
        Write-Log "Connected to NinjaOne. Token length: $($global:NinjaToken.Length)"
        Get-NinjaDeviceData
    } catch {
        Write-Log "OAuth FAILED: $($_.Exception.Message)"
        if ($_.Exception -and $_.Exception.Response -and $_.Exception.Response.StatusCode) {
            Write-Log "HTTP Status: $($_.Exception.Response.StatusCode.value__)"
        }
        throw
    }
}

function Get-NinjaDeviceData {
    Write-Log '=== Get-NinjaDeviceData ==='
    if (-not $global:NinjaToken) { Write-Log 'Not connected (no token).'; return }

    $headers = @{ Authorization = "Bearer $global:NinjaToken" }

    $localId = Get-LocalNinjaNodeId
    if ($localId) {
        try {
            $url = "https://$($global:NinjaInstance)/v2/devices/$localId"
            $device = Invoke-RestMethod -Uri $url -Headers $headers -ErrorAction Stop
            if ($device) {
                $global:NinjaDeviceData = $device
                Write-Log "Device found via Node ID: $($device.systemName)"
                return
            }
        } catch {
            Write-Log "Could not fetch by Node ID ($localId): $($_.Exception.Message)"
        }
    }

    $serial = ''
    try { $serial = (Get-CimInstance Win32_Bios -ErrorAction Stop).SerialNumber } catch { $serial = '' }
    $hostname = $env:COMPUTERNAME

    $allDevices = @()
    $pageSize = 1000
    $after = 0
    $pageNum = 0
    $maxPages = 200
    $lastAfter = $null

    do {
        $pageNum++
        if ($pageNum -gt $maxPages) { Write-Log "Reached maxPages=$maxPages; stopping."; break }

        $url = "https://$($global:NinjaInstance)/v2/devices?pageSize=$pageSize&after=$after"
        $page = Invoke-RestMethod -Uri $url -Headers $headers -ErrorAction Stop

        if ($page -and $page.Count -gt 0) {
            $allDevices += $page
            $after += $page.Count
            if ($null -ne $lastAfter -and $after -eq $lastAfter) { Write-Log "Pagination not advancing (after=$after); stopping."; break }
            $lastAfter = $after
        } else {
            break
        }
    } while ($page.Count -eq $pageSize)

    if (-not $allDevices -or $allDevices.Count -eq 0) { Write-Log 'No devices returned.'; return }

    if (-not [string]::IsNullOrWhiteSpace($serial)) {
        $m = $allDevices | Where-Object { $_.serialNumber -eq $serial } | Select-Object -First 1
        if ($m) { $global:NinjaDeviceData = $m; Write-Log "Matched by Serial: $($m.systemName)"; return }
    }

    $m = $allDevices | Where-Object { $_.systemName -eq $hostname } | Select-Object -First 1
    if ($m) { $global:NinjaDeviceData = $m; Write-Log "Matched by Hostname: $($m.systemName)"; return }

    $m = $allDevices | Where-Object { $_.nodeName -like "*$hostname*" } | Select-Object -First 1
    if ($m) { $global:NinjaDeviceData = $m; Write-Log "Matched by NodeName: $($m.systemName)"; return }

    Write-Log "Device not found. Serial='$serial' Hostname='$hostname'"
}

# --- Core tasks (same behavior as GUI version) ---
function Invoke-FreeDisk {
    Write-Log 'Cleaning temp folders and recycle bin...'
    Clear-RecycleBin -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:windir\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Log 'Cleanup complete.'
}

function Invoke-DisableSleepHibernate {
    Write-Log 'Disabling sleep/hibernate (AC)...'
    powercfg -change -monitor-timeout-ac 0
    powercfg -change -disk-timeout-ac 0
    powercfg -change -standby-timeout-ac 0
    powercfg -change -hibernate-timeout-ac 0
    powercfg -h off
    Write-Log 'Power settings updated.'
}

function Invoke-FixNetworkReset {
    Write-Log 'Resetting network stack...'
    netsh int ip reset | Out-Null
    netsh winsock reset | Out-Null
    ipconfig /flushdns | Out-Null
    Write-Log 'Network reset complete. Reboot may be required.'
}

function Invoke-Sfc {
    Write-Log 'Starting SFC /scannow...'
    Start-Process 'sfc' -ArgumentList '/scannow' -Wait -NoNewWindow
    Write-Log 'SFC complete.'
}

function Invoke-Dism {
    Write-Log 'Starting DISM /restorehealth...'
    Start-Process 'dism' -ArgumentList '/online /cleanup-image /restorehealth' -Wait -NoNewWindow
    Write-Log 'DISM complete.'
}

function Invoke-ResetWindowsUpdate {
    Write-Log 'Resetting Windows Update components...'
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
    Write-Log 'Windows Update reset complete.'
}

function Invoke-MaintenanceBundle {
    Write-Log '=== Maintenance Bundle (SFC -> DISM -> Reset Windows Update) ==='

    $target = 'SFC /scannow, DISM /restorehealth, and Windows Update reset (SoftwareDistribution + catroot2).'
    if (-not (Confirm-DestructiveAction -Action 'RUN the Maintenance Bundle' -Target $target)) {
        Write-Log 'Cancelled.'
        return
    }

    try {
        $pre = Test-PendingReboot
        if ($pre.Pending) { Write-Log "Pre-check: pending reboot already present ($($pre.Reasons))" }
    } catch { }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        Invoke-Sfc
        Invoke-Dism
        Invoke-ResetWindowsUpdate
    } finally {
        $sw.Stop()
        $elapsed = $sw.Elapsed
        Write-Log ("Bundle runtime: {0:00}:{1:00}:{2:00}" -f $elapsed.Hours, $elapsed.Minutes, $elapsed.Seconds)

        try {
            $post = Test-PendingReboot
            if ($post.Pending) {
                Write-Log "Post-check: pending reboot detected ($($post.Reasons)). Reboot recommended."
            } else {
                Write-Log 'Post-check: no pending reboot indicators detected.'
            }
        } catch { }
    }
}

function Invoke-ClearPrintSpooler {
    Write-Log 'Clearing print spooler...'
    Stop-Service Spooler -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:windir\System32\spool\PRINTERS\*" -Force -ErrorAction SilentlyContinue
    Start-Service Spooler -ErrorAction SilentlyContinue
    Write-Log 'Print spooler cleared.'
}

function Invoke-RestartExplorer {
    Write-Log 'Restarting explorer.exe...'
    Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
    Write-Log 'Explorer restarted.'
}

function Invoke-SyncTime {
    Write-Log 'Syncing system time...'
    Start-Service w32time -ErrorAction SilentlyContinue
    w32tm /resync | Out-String | ForEach-Object { if ($_){ Write-Log $_.TrimEnd() } }
    Write-Log 'Time sync attempted.'
}

function Invoke-DownloadSpaceMonger {
    $smPath = Join-Path $env:TEMP 'SpaceMonger.exe'
    $url = 'https://github.com/jeremydbean/winfix/raw/main/SpaceMonger.exe'
    if (-not (Test-Path $smPath)) {
        Write-Log 'Downloading SpaceMonger...'
        Invoke-WebRequest -Uri $url -OutFile $smPath -ErrorAction Stop
        Write-Log 'Download complete.'
    }
    Write-Log 'Launching SpaceMonger...'
    Start-Process $smPath | Out-Null
}

function Invoke-ShowIpConfig {
    ipconfig /all | Out-String | Write-Host
}

function Invoke-ArpScan {
    arp -a | Out-String | Write-Host
}

function Invoke-TestInternet {
    Test-Connection -ComputerName 8.8.8.8 -Count 4 | Select-Object Address, ResponseTime, Status | Out-String | Write-Host
}

function Invoke-EnableNetworkSharing {
    Write-Log 'Disabling Windows Firewall...'
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    Write-Log 'Setting network profiles to Private...'
    Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private
    Write-Log 'Enabling File/Printer Sharing + Network Discovery...'
    netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes
    netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes
    Write-Log 'Network sharing enabled and firewall disabled.'
}

function Invoke-RefreshDashboard {
    Write-Log '=== SYSTEM OVERVIEW ==='
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $bios = Get-CimInstance Win32_Bios

    Write-Host "Computer Name:   $($cs.Name)"
    Write-Host "Manufacturer:    $($cs.Manufacturer)"
    Write-Host "Model:           $($cs.Model)"
    Write-Host "Serial Number:   $($bios.SerialNumber)"
    Write-Host "OS:              $($os.Caption) (Build $($os.BuildNumber))"

    $cpuLoad = (Get-CimInstance Win32_Processor).LoadPercentage
    if ($null -eq $cpuLoad) { $cpuLoad = 0 }
    Write-Host "CPU Load:        $cpuLoad%"

    $uptime = (Get-Date) - $os.LastBootUpTime
    Write-Host "Uptime:          $($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m"

    if ($global:NinjaDeviceData) {
        Write-Host "Ninja Device ID: $($global:NinjaDeviceData.id)"
        Write-Host "Last Contact:    $($global:NinjaDeviceData.lastContact)"
    }
}

# --- Users & Shares ---
function Invoke-ListLocalUsers {
    Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet | Format-Table -AutoSize | Out-String | Write-Host
}

function Invoke-CreateLocalUser {
    param([string]$UserName, [string]$Password)
    if (-not $UserName) { throw 'Username required.' }
    $pass = ConvertTo-SecureString $Password -AsPlainText -Force
    New-LocalUser -Name $UserName -Password $pass -PasswordNeverExpires -Description 'Created by WinFix' -ErrorAction Stop | Out-Null
    Add-LocalGroupMember -Group 'Users' -Member $UserName -ErrorAction SilentlyContinue
    Write-Log "User '$UserName' created."
}

function Invoke-ResetLocalUserPassword {
    param([string]$UserName, [string]$Password)
    if (-not $UserName -or -not $Password) { throw 'Username + Password required.' }
    $pass = ConvertTo-SecureString $Password -AsPlainText -Force
    Set-LocalUser -Name $UserName -Password $pass -ErrorAction Stop
    Write-Log "Password reset for '$UserName'."
}

function Invoke-AddUserToAdmins {
    param([string]$UserName)
    if (-not $UserName) { throw 'Username required.' }
    Add-LocalGroupMember -Group 'Administrators' -Member $UserName -ErrorAction Stop
    Write-Log "User '$UserName' added to Administrators."
}

function Invoke-EnableLocalUser {
    param([string]$UserName)
    if (-not $UserName) { throw 'Username required.' }
    Enable-LocalUser -Name $UserName
    Write-Log "User '$UserName' enabled."
}

function Invoke-DisableLocalUser {
    param([string]$UserName)
    if (-not $UserName) { throw 'Username required.' }
    Disable-LocalUser -Name $UserName
    Write-Log "User '$UserName' disabled."
}

function Confirm-DestructiveAction {
    param(
        [Parameter(Mandatory)] [string]$Action,
        [Parameter(Mandatory)] [string]$Target
    )

    Write-Host ''
    Write-Host "WARNING: This will ${Action}: $Target" -ForegroundColor Yellow
    $confirm = Read-Host "Type YES to confirm"
    return ($confirm -eq 'YES')
}

function Invoke-DeleteLocalUser {
    param([string]$UserName)
    if (-not $UserName) { throw 'Username required.' }

    if (-not (Confirm-DestructiveAction -Action 'DELETE local user' -Target $UserName)) {
        Write-Log 'Cancelled.'
        return
    }

    Remove-LocalUser -Name $UserName -ErrorAction Stop
    Write-Log "User '$UserName' deleted."
}

function Invoke-ListShares {
    Get-SmbShare | Where-Object { $_.Name -notin @('IPC$', 'ADMIN$', 'C$', 'D$', 'E$') } |
        Select-Object Name, Path, Description |
        Format-Table -AutoSize | Out-String | Write-Host
}

function Invoke-CreateShare {
    param([string]$Path, [string]$Name)
    if (-not $Path -or -not $Name) { throw 'Path + Share name required.' }
    if (-not (Test-Path $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
    New-SmbShare -Name $Name -Path $Path -FullAccess 'Everyone' -ErrorAction Stop | Out-Null
    Write-Log "Share '$Name' created at '$Path' with FullAccess Everyone."
}

function Invoke-DeleteShare {
    param([string]$Name)
    if (-not $Name) { throw 'Share name required.' }

    if (-not (Confirm-DestructiveAction -Action 'DELETE SMB share' -Target $Name)) {
        Write-Log 'Cancelled.'
        return
    }

    Remove-SmbShare -Name $Name -Force -ErrorAction Stop
    Write-Log "Share '$Name' deleted."
}

function Test-TcpPort {
    param(
        [Parameter(Mandatory)] [string]$Host,
        [Parameter(Mandatory)] [int]$Port,
        [int]$TimeoutMs = 250
    )

    $client = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect($Host, $Port, $null, $null)
        $ok = $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if (-not $ok) { return $false }
        $client.EndConnect($iar)
        return $client.Connected
    } catch {
        return $false
    } finally {
        try { if ($client) { $client.Close() } } catch { }
    }
}

function Invoke-ScanPrintersPort9100 {
    Write-Log '=== Scan Network Printers (Port 9100) ==='

    $defaultPrefix = $null
    try {
        $ip = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object {
                $_.IPAddress -and
                $_.IPAddress -notlike '127.*' -and
                $_.IPAddress -notlike '169.254.*' -and
                $_.PrefixLength -ge 16 -and $_.PrefixLength -le 24
            } |
            Sort-Object -Property PrefixLength -Descending |
            Select-Object -First 1

        if ($ip -and $ip.IPAddress -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.') {
            $defaultPrefix = "$($Matches[1]).$($Matches[2]).$($Matches[3])"
        }
    } catch { }

    if (-not $defaultPrefix) { $defaultPrefix = '192.168.1' }

    $prefix = Read-Host "Subnet prefix a.b.c (default: $defaultPrefix)"
    if ([string]::IsNullOrWhiteSpace($prefix)) { $prefix = $defaultPrefix }

    $startStr = Read-Host 'Start host (default: 1)'
    $endStr = Read-Host 'End host (default: 254)'
    $start = if ($startStr -match '^\d+$') { [int]$startStr } else { 1 }
    $end = if ($endStr -match '^\d+$') { [int]$endStr } else { 254 }

    if ($start -lt 1) { $start = 1 }
    if ($end -gt 254) { $end = 254 }
    if ($start -gt $end) { $tmp = $start; $start = $end; $end = $tmp }

    $found = New-Object System.Collections.Generic.List[string]
    $total = ($end - $start + 1)
    $i = 0

    for ($h = $start; $h -le $end; $h++) {
        $i++
        $addr = "$prefix.$h"
        Write-Progress -Activity 'Scanning Port 9100' -Status $addr -PercentComplete ([int](($i / $total) * 100))

        if (Test-TcpPort -Host $addr -Port 9100 -TimeoutMs 250) {
            $found.Add($addr) | Out-Null
            Write-Log "OPEN: $addr:9100 (JetDirect/RAW printing)"
        }
    }

    Write-Progress -Activity 'Scanning Port 9100' -Completed
    Write-Host ''

    if ($found.Count -eq 0) {
        Write-Log 'No devices found with port 9100 open in the scanned range.'
        return
    }

    Write-Log "Found $($found.Count) device(s):"
    $found | ForEach-Object { Write-Host " - $_" }
}

function Test-PendingReboot {
    $reasons = New-Object System.Collections.Generic.List[string]
    try {
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
            $reasons.Add('CBS: RebootPending') | Out-Null
        }
    } catch { }
    try {
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
            $reasons.Add('WindowsUpdate: RebootRequired') | Out-Null
        }
    } catch { }
    try {
        $p = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue
        if ($p -and $p.PendingFileRenameOperations) { $reasons.Add('SessionManager: PendingFileRenameOperations') | Out-Null }
    } catch { }

    [PSCustomObject]@{
        Pending = ($reasons.Count -gt 0)
        Reasons = ($reasons -join '; ')
    }
}

function Invoke-ShowPendingReboot {
    Write-Log '=== Pending Reboot Check ==='
    $r = Test-PendingReboot
    if ($r.Pending) {
        Write-Log "PENDING REBOOT: Yes ($($r.Reasons))"
    } else {
        Write-Log 'PENDING REBOOT: No'
    }
}

function Invoke-ShowRecentCriticalEvents {
    param([int]$LookbackDays = 7, [int]$Max = 25)
    Write-Log "=== Recent System Events (last $LookbackDays days) ==="

    try {
        $start = (Get-Date).AddDays(-1 * [Math]::Abs($LookbackDays))
        $events = Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $start } -ErrorAction Stop |
            Where-Object { $_.Level -in 1,2,3 } |
            Select-Object -First $Max

        if (-not $events) {
            Write-Log 'No recent critical/error/warning events found.'
            return
        }

        $events |
            Select-Object TimeCreated, LevelDisplayName, ProviderName, Id, Message |
            Format-Table -AutoSize |
            Out-String |
            Write-Host
    } catch {
        Write-Log "Could not read System event log: $($_.Exception.Message)"
    }
}

function Invoke-ShowBitLockerStatus {
    Write-Log '=== BitLocker Status ==='

    if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
        try {
            Get-BitLockerVolume |
                Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionPercentage, LockStatus |
                Format-Table -AutoSize |
                Out-String |
                Write-Host
            return
        } catch {
            Write-Log "Get-BitLockerVolume failed: $($_.Exception.Message)"
        }
    }

    if (Get-Command manage-bde.exe -ErrorAction SilentlyContinue) {
        try { manage-bde.exe -status | Out-String | Write-Host } catch { }
        return
    }

    Write-Log 'BitLocker commands not available on this system.'
}

function Invoke-ShowFirewallStatus {
    Write-Log '=== Windows Firewall Profiles ==='
    try {
        Get-NetFirewallProfile |
            Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction |
            Format-Table -AutoSize |
            Out-String |
            Write-Host
    } catch {
        Write-Log "Get-NetFirewallProfile failed: $($_.Exception.Message)"
    }
}

function Invoke-QuickTriage {
    Write-Log '=== Quick Triage Bundle (read-only) ==='

    $desktop = [Environment]::GetFolderPath('Desktop')
    if (-not (Test-Path $desktop)) { $desktop = $env:TEMP }
    $outPath = Join-Path $desktop "WinFix_Triage_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("WinFix Triage") | Out-Null
    $lines.Add("Timestamp: $(Get-Date)") | Out-Null
    $lines.Add("Computer: $env:COMPUTERNAME") | Out-Null
    $lines.Add("User: $env:USERNAME") | Out-Null
    $lines.Add('') | Out-Null

    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $lines.Add("OS: $($os.Caption) ($($os.Version))") | Out-Null
        $lines.Add("Last boot: $([Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime))") | Out-Null
    } catch {
        $lines.Add("OS: (unavailable) $($_.Exception.Message)") | Out-Null
    }

    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $lines.Add("Manufacturer: $($cs.Manufacturer)") | Out-Null
        $lines.Add("Model: $($cs.Model)") | Out-Null
    } catch { }

    $r = Test-PendingReboot
    $lines.Add("Pending reboot: $($r.Pending) $($r.Reasons)") | Out-Null

    $lines.Add('') | Out-Null
    $lines.Add('Disk:') | Out-Null
    try {
        Get-PSDrive -PSProvider FileSystem |
            Select-Object Name, @{n='FreeGB';e={[math]::Round($_.Free/1GB,1)}}, @{n='UsedGB';e={[math]::Round(($_.Used)/1GB,1)}}, @{n='TotalGB';e={[math]::Round(($_.Used+$_.Free)/1GB,1)}} |
            ForEach-Object { $lines.Add(("  {0}: Free {1} GB / Total {3} GB" -f $_.Name, $_.FreeGB, $_.UsedGB, $_.TotalGB)) | Out-Null }
    } catch { }

    $lines.Add('') | Out-Null
    $lines.Add('Network:') | Out-Null
    try {
        $ipcfg = Get-NetIPConfiguration -ErrorAction Stop | Where-Object { $_.IPv4Address } | Select-Object -First 3
        foreach ($n in $ipcfg) {
            $lines.Add("  Interface: $($n.InterfaceAlias)") | Out-Null
            $lines.Add("    IPv4: $($n.IPv4Address.IPAddress)") | Out-Null
            if ($n.IPv4DefaultGateway) { $lines.Add("    GW: $($n.IPv4DefaultGateway.NextHop)") | Out-Null }
            if ($n.DnsServer) { $lines.Add("    DNS: $($n.DnsServer.ServerAddresses -join ', ')") | Out-Null }
        }
    } catch { }

    $lines.Add('') | Out-Null
    $lines.Add("WinFix Log: $script:LogFilePath") | Out-Null

    try {
        $lines | Out-File -FilePath $outPath -Encoding UTF8 -ErrorAction Stop
        Write-Log "Triage saved: $outPath"
        Invoke-Item $outPath
    } catch {
        Write-Log "Failed to write triage file: $($_.Exception.Message)"
    }
}

function Invoke-TailLog {
    Write-Log '=== Tail Log (Ctrl+C to stop) ==='
    if (-not (Test-Path $script:LogFilePath)) {
        Write-Log 'Log file not found.'
        return
    }
    Get-Content -Path $script:LogFilePath -Tail 200 -Wait
}

function Invoke-ExportWinFixBundle {
    Write-Log '=== Export WinFix Bundle ==='

    $desktop = [Environment]::GetFolderPath('Desktop')
    if (-not (Test-Path $desktop)) { $desktop = $env:TEMP }

    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $workDir = Join-Path $env:TEMP "WinFixBundle_$stamp"
    $null = New-Item -ItemType Directory -Path $workDir -Force -ErrorAction SilentlyContinue

    try {
        if (Test-Path $script:LogFilePath) {
            Copy-Item -Path $script:LogFilePath -Destination (Join-Path $workDir 'WinFix_Debug.log') -Force -ErrorAction SilentlyContinue
        }
    } catch { }

    try {
        $latestAudit = Get-ChildItem -Path $desktop -Filter 'JeremyBean_SecurityAudit_*.html' -ErrorAction SilentlyContinue |
            Sort-Object -Property LastWriteTime -Descending |
            Select-Object -First 1

        if ($latestAudit) {
            Copy-Item -Path $latestAudit.FullName -Destination (Join-Path $workDir $latestAudit.Name) -Force -ErrorAction SilentlyContinue
        }
    } catch { }

    $zipPath = Join-Path $desktop "WinFixBundle_$stamp.zip"
    try {
        if (Test-Path $zipPath) { Remove-Item $zipPath -Force -ErrorAction SilentlyContinue }
        Compress-Archive -Path (Join-Path $workDir '*') -DestinationPath $zipPath -Force -ErrorAction Stop
        Write-Log "Bundle created: $zipPath"
        Invoke-Item $zipPath
    } catch {
        Write-Log "Failed to create bundle: $($_.Exception.Message)"
    } finally {
        try { Remove-Item -Path $workDir -Recurse -Force -ErrorAction SilentlyContinue } catch { }
    }
}

# --- Security Audit (reuses GUI logic by generating the same HTML report) ---
function Invoke-SecurityAudit {
    Write-Log 'Initializing Security Audit...'

    $desktop = [Environment]::GetFolderPath('Desktop')
    if (-not (Test-Path $desktop)) { $desktop = $env:TEMP }

    $reportPath = Join-Path $desktop "JeremyBean_SecurityAudit_$(Get-Date -Format 'yyyyMMdd_HHmm').html"
    $eventLookbackDays = 30
    $maxEventsToShow = 15

    # NOTE: This is intentionally kept close to WinFixTool.ps1 behavior.

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
        .header-block { border-bottom: 3px solid var(--accent-cyan); margin-bottom: 30px; padding-bottom: 10px; }
        h1 { color: var(--accent-cyan); text-transform: uppercase; letter-spacing: 1px; margin: 0; font-size: 1.8em; }
        .meta-info { display: flex; justify-content: space-between; margin-top: 15px; font-weight: bold; color: #555; align-items: center; }
        h2 { background-color: #e8f4f8; color: var(--accent-cyan); padding: 10px; margin-top: 40px; font-size: 1.2em; border-top: 3px solid var(--accent-cyan); font-weight: bold; }
        h3 { color: var(--accent-cyan); margin-top: 20px; border-left: 4px solid var(--accent-blue); padding-left: 10px; font-size: 1.1em; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 15px; background-color: var(--card-bg); box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #ecf0f1; vertical-align: top; }
        th { background-color: #ecf0f1; color: var(--text-main); font-weight: 700; width: 45%; }
        .user-input { border: 1px solid #bdc3c7; padding: 5px; border-radius: 4px; width: 90%; font-family: inherit; background-color: #fafafa; color: #333; }
        .user-input:focus { outline: 2px solid var(--accent-blue); background-color: #fff; }
        .user-select { border: 1px solid #bdc3c7; padding: 5px; border-radius: 4px; background-color: #fafafa; font-weight: bold; color: #333; }
        .copy-btn { background-color: var(--accent-cyan); color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; font-weight: bold; box-shadow: 0 4px 6px rgba(0,0,0,0.2); transition: background 0.2s; }
        .copy-btn:hover { background-color: var(--accent-blue); }
        .floating-action { position: fixed; bottom: 30px; right: 30px; z-index: 1000; }
        .alert { color: var(--alert); font-weight: bold; }
        .good { color: var(--good); font-weight: bold; }
        .warning { color: var(--warn); font-weight: bold; }
        .ai-link { display: inline-block; margin-top: 5px; color: var(--accent-cyan); font-weight: bold; text-decoration: none; font-size: 0.85em; border: 1px solid var(--accent-blue); padding: 2px 6px; border-radius: 4px; }
        .ai-link:hover { background-color: #e8f4f8; }
    </style>

    <script>
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
            let key = Object.keys(backupDefaults).find(k => selected.includes(k));
            if (key && backupDefaults[key]) {
                const def = backupDefaults[key];
                document.getElementById('backupEncStd').value = def.enc;
                document.getElementById('backupEncRest').value = def.rest;
                document.getElementById('backupEncTransit').value = def.transit;
            }
        }

        function copyReport() {
            var originalInputs = document.querySelectorAll('input, textarea, select');
            var clone = document.body.cloneNode(true);
            var buttons = clone.querySelectorAll('.copy-btn, .floating-action');
            buttons.forEach(b => b.remove());

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

            var tempDiv = document.createElement('div');
            tempDiv.style.position = 'absolute';
            tempDiv.style.left = '-9999px';
            tempDiv.innerHTML = clone.innerHTML;
            document.body.appendChild(tempDiv);

            var range = document.createRange();
            range.selectNodeContents(tempDiv);
            var selection = window.getSelection();
            selection.removeAllRanges();
            selection.addRange(range);

            try {
                document.execCommand('copy');
                alert('Report Copied!');
            } catch (err) {
                alert('Copy failed.');
            }

            document.body.removeChild(tempDiv);
            selection.removeAllRanges();
        }
    </script>
"@

    function Get-HtmlInput {
        param([string]$Placeholder = 'Enter details...', [string]$Value = '', [string]$Id = '')
        $idAttr = if ($Id) { "id='$Id'" } else { '' }
        return "<input type='text' $idAttr class='user-input' placeholder='$Placeholder' value='$Value'>"
    }

    function Get-HtmlSelect {
        param([string[]]$Options = @('Select...', 'Yes', 'No', 'N/A'), [string]$SelectedValue = '', [string]$Id = '', [string]$OnChange = '')
        $idAttr = if ($Id) { "id='$Id'" } else { '' }
        $changeAttr = if ($OnChange) { "onchange='$OnChange'" } else { '' }
        if (-not ($Options -contains 'N/A')) { $Options += 'N/A' }
        $optHtml = ''
        foreach ($opt in $Options) {
            $sel = if ($opt -eq $SelectedValue) { 'selected' } else { '' }
            $optHtml += "<option value='$opt' $sel>$opt</option>"
        }
        return "<select class='user-select' $idAttr $changeAttr>$optHtml</select>"
    }

    function Get-HtmlTextArea {
        return "<textarea class='user-input' rows='3' placeholder='Enter details...'></textarea>"
    }

    Write-Log 'Gathering system info...'
    $comp = Get-CimInstance Win32_ComputerSystem
    $os = Get-CimInstance Win32_OperatingSystem
    $bios = Get-CimInstance Win32_Bios
    $adminGroup = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue

    $uptime = (Get-Date) - $os.LastBootUpTime
    $uptimeStr = "{0} Days, {1} Hours" -f $uptime.Days, $uptime.Hours

    $isVm = ($comp.Model -match 'Virtual' -or $comp.Model -match 'VMware' -or ($comp.Manufacturer -match 'Microsoft Corporation' -and $comp.Model -match 'Virtual'))

    $eosWarning = ''
    if ($os.Caption -match 'Server 2003|Server 2008|Server 2012|Windows 7|Windows 8|Windows 10|SBS 2011|Windows XP|Vista') {
        $eosWarning = "<span style='color:#dc3545; font-weight:bold; margin-left:10px;'> [WARNING: OS End of Support - Security Risk]</span>"
    }

    $detectedRoles = ''
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        try {
            $feats = Get-WindowsFeature | Where-Object { $_.Installed -eq $true -and $_.FeatureType -eq 'Role' }
            if ($feats) { $detectedRoles = ($feats.Name -join ', ') }
        } catch { $detectedRoles = 'Could not query roles' }
    } else {
        $detectedRoles = 'Workstation / Roles Not Available'
    }

    # Backups
    $backupKeywords = '*Veeam*','*Acronis*','*Macrium*','*Datto*','*Carbonite*','*Veritas*','*CrashPlan*','*Ninja*'
    $detectedServices = Get-Service | Where-Object { $d = $_.DisplayName; ($backupKeywords | Where-Object { $d -like $_ }) }

    $backupOptions = @('Select...')
    if ($detectedServices) {
        foreach ($svc in $detectedServices) { $backupOptions += "[DETECTED] $($svc.DisplayName)" }
        $backupOptions += '----------------'
    }
    $backupOptions += @('Datto', 'Veeam', 'Ninja Backup', 'Acronis', 'Macrium', 'Carbonite', 'CrashPlan', 'Windows Server Backup', 'Other (Manual)')

    $winBackup = Get-WinEvent -LogName 'Microsoft-Windows-Backup' -MaxEvents 1 -ErrorAction SilentlyContinue
    $backupSuccessSel = 'Select...'
    $backupFailedSel = 'Select...'
    $lastBackupTime = ''
    if ($winBackup) {
        if ($winBackup.Id -eq 4) { $backupSuccessSel = 'Yes'; $backupFailedSel = 'No'; $lastBackupTime = $winBackup.TimeCreated.ToString('yyyy-MM-dd HH:mm') }
        else { $backupSuccessSel = 'No'; $backupFailedSel = 'Yes'; $lastBackupTime = 'Failed at ' + $winBackup.TimeCreated.ToString('yyyy-MM-dd HH:mm') }
    }

    # Ninja override
    if ($global:NinjaDeviceData -and $global:NinjaDeviceData.lastBackupJobStatus) {
        $backupSuccessSel = if ($global:NinjaDeviceData.lastBackupJobStatus -eq 'SUCCESS') { 'Yes' } else { 'No' }
        $lastBackupTime = 'Check Ninja Dashboard'
        if ($global:NinjaDeviceData.lastBackupJobStatus -ne 'SUCCESS') { $backupFailedSel = 'Yes' }
    }

    # Updates
    $missingUpdatesCount = 0
    $missingUpdatesHtml = ''
    try {
        $sess = New-Object -ComObject Microsoft.Update.Session
        $searcher = $sess.CreateUpdateSearcher()
        $res = $searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
        $missingUpdatesCount = $res.Updates.Count
        if ($missingUpdatesCount -gt 0) {
            foreach ($u in $res.Updates) {
                $q = [uri]::EscapeDataString("Windows Update $($u.Title) problems")
                $missingUpdatesHtml += "<li>$($u.Title) (<a href='https://www.google.com/search?q=$q' target='_blank' class='ai-link'>Analyze</a>)</li>"
            }
        }
    } catch { $missingUpdatesHtml = 'Error querying Windows Update.' }

    if ($global:NinjaDeviceData -and $global:NinjaDeviceData.osPatchStatus) {
        $pStatus = $global:NinjaDeviceData.osPatchStatus
        if ($pStatus.failed -gt 0 -or $pStatus.pending -gt 0) {
            if ($missingUpdatesHtml -like 'Error*') { $missingUpdatesHtml = '' }
            $missingUpdatesCount = $pStatus.failed + $pStatus.pending
            $missingUpdatesHtml += "<li>Ninja Reports: $($pStatus.failed) Failed, $($pStatus.pending) Pending</li>"
        }
    }

    $lastHotFix = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
    $lastUpdateDate = if ($lastHotFix) { $lastHotFix.InstalledOn.ToString('yyyy-MM-dd') } else { '' }

    $pendingReboot = $false
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pendingReboot = $true }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pendingReboot = $true }
    $updateNote = if ($pendingReboot) { "<span class='alert'><b>(Reboot Pending)</b></span>" } else { '' }

    # AV
    $av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue
    $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
    $rtpEnabled = 'Select...'
    $lastScanDate = ''
    if ($defender) {
        $rtpEnabled = if ($defender.RealTimeProtectionEnabled) { 'Yes' } else { 'No' }
        $lastScanDate = if ($defender.QuickScanEndTime) { $defender.QuickScanEndTime.ToString('yyyy-MM-dd') } else { 'Never' }
        if (-not $av) { $av = [PSCustomObject]@{ displayName = 'Windows Defender' } }
    }

    if ($global:NinjaDeviceData -and $global:NinjaDeviceData.antivirusStatus) {
        $avStat = $global:NinjaDeviceData.antivirusStatus
        if ($avStat.protectionStatus -eq 'ENABLED') { $rtpEnabled = 'Yes' }
        if ($avStat.productName) { $av = [PSCustomObject]@{ displayName = $avStat.productName } }
    }

    # Users
    try { $localUsers = Get-LocalUser -ErrorAction Stop | Select-Object Name, Enabled, PasswordLastSet } catch { $localUsers = @() }
    $disabledUsers = $localUsers | Where-Object { $_.Enabled -eq $false }
    $disabledUsersSel = if ($disabledUsers) { 'Yes' } else { 'No' }

    $adminPassLastSet = 'Unknown / Domain Account'
    $adminPassChangedRegularly = 'Select...'
    try {
        $builtInAdmin = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.SID -like '*-500' } | Select-Object -First 1
        if ($builtInAdmin -and $builtInAdmin.PasswordLastSet) {
            $adminPassLastSet = $builtInAdmin.PasswordLastSet.ToString('yyyy-MM-dd')
            $days = (New-TimeSpan -Start $builtInAdmin.PasswordLastSet -End (Get-Date)).Days
            if ($days -gt 90) { $adminPassChangedRegularly = 'No'; $adminPassLastSet += " ($days days ago)" } else { $adminPassChangedRegularly = 'Yes' }
        } elseif ($builtInAdmin) {
            $adminPassLastSet = 'Never Set'
        }
    } catch { $adminPassLastSet = 'N/A (See AD)' }

    # Password policy
    $passComplexSel = 'Select...'
    $passInfoStr = ''
    try {
        $cfg = Join-Path $env:TEMP 'secpol.cfg'
        secedit /export /cfg $cfg /quiet
        $secPol = Get-Content $cfg
        if ($secPol -match 'PasswordComplexity\s*=\s*1') { $passComplexSel = 'Yes'; $passInfoStr += 'Complexity: Enabled. ' }
        elseif ($secPol -match 'PasswordComplexity\s*=\s*0') { $passComplexSel = 'No'; $passInfoStr += 'Complexity: Disabled. ' }
        if ($secPol -match 'MinimumPasswordLength\s*=\s*(\d+)') { $passInfoStr += "Min Length: $($matches[1])." }
        Remove-Item $cfg -ErrorAction SilentlyContinue
    } catch { $passInfoStr = 'Could not verify local policy.' }

    # BitLocker
    $tpm = $null
    try { $tpm = Get-Tpm -ErrorAction Stop } catch { $tpm = $null }
    $bitLocker = if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) { Get-BitLockerVolume -ErrorAction SilentlyContinue } else { $null }

    $bitLockerSel = 'Select...'
    $bitLockerReason = ''
    $cEncrypted = $false
    if ($bitLocker -and ($bitLocker | Where-Object ProtectionStatus -eq 'On')) {
        $bitLockerSel = 'Yes'
        $bitLockerStatus = ($bitLocker | ForEach-Object { "$($_.MountPoint) [$($_.ProtectionStatus)]" }) -join ', '
        if ($bitLocker | Where-Object { $_.MountPoint -like 'C:*' -and $_.ProtectionStatus -eq 'On' }) { $cEncrypted = $true }
    } else {
        $bitLockerStatus = 'Not Encrypted'
        if ($isVm) { $bitLockerSel = 'N/A'; $bitLockerReason = 'Virtual Machine' }
        else { $bitLockerSel = 'No'; $bitLockerReason = 'Physical Server - No Encryption Detected' }
    }

    $chiroPath = 'C:\Program Files\PSChiro'
    $chiroInstalled = Test-Path $chiroPath
    $chiroEncryptedSel = if ($chiroInstalled) { if ($cEncrypted) { 'Yes' } else { 'No' } } else { 'N/A' }

    # Firewall & RDP
    $firewall = Get-NetFirewallProfile | Where-Object Enabled -eq $true
    $rdpReg = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue

    $shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @('IPC$', 'ADMIN$', 'C$', 'D$', 'E$') }
    $shareList = if ($shares) { 'Shares: ' + ($shares.Name -join ', ') } else { 'No Custom Shares' }

    $rdpVpnSel = 'Select...'
    $rdpMfaSel = 'Select...'
    $rdpExternalSel = 'Select...'
    $rdpFailSel = 'Select...'
    $rdpFailCount = 0

    if ($rdpReg.fDenyTSConnections -ne 0) {
        $rdpStatus = "<span class='good'>Disabled</span>"
        $rdpVpnSel = 'N/A'
        $rdpMfaSel = 'N/A'
        $rdpExternalSel = 'N/A'
        $rdpFailSel = 'N/A'
    } else {
        $rdpStatus = "<span class='warning'>Enabled (Open)</span>"
        $rdpFailures = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-30)} -ErrorAction SilentlyContinue
        $rdpFailCount = if ($rdpFailures) { $rdpFailures.Count } else { 0 }
        $rdpFailSel = if ($rdpFailCount -gt 0) { 'Yes' } else { 'No' }
        $rdpExternalSel = 'No'
    }

    $openPortsStr = ''
    try {
        $openPorts = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LocalPort -Unique | Sort-Object { [int]$_ }
        if ($openPorts) { $openPortsStr = 'Open Ports: ' + ($openPorts -join ', ') }
    } catch { }

    # Logs
    $logSettings = Get-EventLog -List | Where-Object { $_.Log -eq 'Security' }
    $events = Get-WinEvent -FilterHashtable @{LogName='System','Application'; Level=1,2; StartTime=(Get-Date).AddDays(-$eventLookbackDays)} -ErrorAction SilentlyContinue | Select-Object -First $maxEventsToShow

    $appErrors = Get-WinEvent -FilterHashtable @{LogName='Application'; Level=2; StartTime=(Get-Date).AddDays(-30)} -MaxEvents 1 -ErrorAction SilentlyContinue
    $appErrorSel = if ($appErrors) { 'Yes' } else { 'No' }

    $dbErrors = $null
    try {
        $recentApp = Get-WinEvent -FilterHashtable @{LogName='Application'; Level=1,2; StartTime=(Get-Date).AddDays(-30)} -MaxEvents 300 -ErrorAction SilentlyContinue
        if ($recentApp) {
            $dbErrors = $recentApp | Where-Object { ($_.ProviderName -match 'SQL|Database|MySQL|Oracle') -or ($_.Message -match 'SQL|Database|MySQL|Oracle') } | Select-Object -First 1
        }
    } catch { $dbErrors = $null }
    $dbErrorSel = if ($dbErrors) { 'Yes' } else { 'No' }

    $disks = Get-PhysicalDisk -ErrorAction SilentlyContinue | Select-Object FriendlyName, MediaType, HealthStatus
    $diskHealthStr = if ($disks) { ($disks | ForEach-Object { "$($_.MediaType) ($($_.HealthStatus))" }) -join '; ' } else { 'Unknown' }

    $storageWarning = ''
    try {
        $cDrive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
        $freePct = [math]::Round(($cDrive.FreeSpace / $cDrive.Size) * 100, 1)
        if ($freePct -lt 15) { $storageWarning = "Low Disk Space on C: ($freePct% Free)" }
    } catch { }

    $clientNameVal = ''
    $locationDefault = ''
    $ninjaRaidStatus = ''
    $ninjaDiskInfo = ''
    $ninjaLastReboot = ''
    $ninjaLastLoggedUser = ''

    if ($global:NinjaDeviceData) {
        if ($global:NinjaDeviceData.organizationId) { $clientNameVal = "Ninja Org ID: $($global:NinjaDeviceData.organizationId)" }
        if ($global:NinjaDeviceData.locationId) { $locationDefault = "(Ninja Loc: $($global:NinjaDeviceData.locationId))" }
        if ($global:NinjaDeviceData.lastReboot) { $ninjaLastReboot = $global:NinjaDeviceData.lastReboot }
        if ($global:NinjaDeviceData.lastLoggedInUser) { $ninjaLastLoggedUser = $global:NinjaDeviceData.lastLoggedInUser }

        try {
            $headers = @{ Authorization = "Bearer $global:NinjaToken" }
            $devId = $global:NinjaDeviceData.id
            $nDisks = Invoke-RestMethod -Uri "https://$($global:NinjaInstance)/v2/device/$devId/disks" -Headers $headers -ErrorAction Stop
            if ($nDisks) {
                $raidDisks = $nDisks | Where-Object { $_.raidType -or ($_.volumeType -match 'RAID') }
                if ($raidDisks) {
                    $ninjaRaidStatus = ($raidDisks | ForEach-Object { "$($_.name): $($_.raidType) - $($_.health)" }) -join '; '
                }
                $unhealthy = $nDisks | Where-Object { $_.health -ne 'Healthy' -and $_.health -ne $null }
                if ($unhealthy) { $ninjaDiskInfo = 'WARNING: ' + (($unhealthy | ForEach-Object { "$($_.name) ($($_.health))" }) -join ', ') }
                else { $ninjaDiskInfo = 'All disks healthy' }
            }
        } catch { }
    }

    $htmlBody = @"
    <div class='header-block'>
        <div style='display:flex; justify-content:space-between; align-items:flex-start;'>
            <div>
                <h1>Internal Server Security & Backup Audit Form</h1>
                <div class='meta-info'>
                    <span>Client: $(Get-HtmlInput "Client Name" -Value $clientNameVal)</span>
                    <span style='margin-left:20px;'>Audit Month: $(Get-HtmlInput "e.g. October" -Value "$(Get-Date -Format 'MMMM')")</span>
                    <span style='margin-left:20px;'>Completed By: $env:USERNAME</span>
                </div>
                <div style='margin-top:5px; font-size:0.85em; color:#666;'>Uptime: $uptimeStr</div>
            </div>
            <button onclick="copyReport()" class="copy-btn">Copy to Clipboard</button>
        </div>
    </div>

    <h3>Server Identifying Information</h3>
    <table>
        <tr><th>Server Name</th><td>$($comp.Name)</td></tr>
        <tr><th>Location (onsite/offsite)</th><td>$(Get-HtmlInput "e.g., Server Closet" -Value $locationDefault)</td></tr>
        <tr><th>OS Version</th><td>$($os.Caption) (Build $($os.BuildNumber)) $eosWarning</td></tr>
        <tr><th>Role(s)</th><td>$(Get-HtmlInput "e.g., DC, Database" -Value $detectedRoles)</td></tr>
        <tr><th>Who has administrative access?</th><td><ul>$($adminGroup.Name | ForEach-Object { "<li>$_</li>" })</ul></td></tr>
        $(if($ninjaLastLoggedUser){"<tr><th>Last Logged User (Ninja)</th><td>$ninjaLastLoggedUser</td></tr>"})
        $(if($ninjaLastReboot){"<tr><th>Last Reboot (Ninja)</th><td>$ninjaLastReboot</td></tr>"})
    </table>

    <h2>1. Backup & Data Retention (HIPAA §164.308(a)(7))</h2>
    <h3>A. Backup System Review</h3>
    <table>
        <tr><th>Backup solution used</th><td>
            $(Get-HtmlSelect -Options $backupOptions -OnChange "updateBackupDefaults(this)")
            <br><small>Select to auto-fill encryption defaults.</small>
        </td></tr>
        <tr><th>Are backups completing successfully?</th><td>
            $(Get-HtmlSelect @("Select...", "Yes", "No", "N/A") -SelectedValue $backupSuccessSel)
            $(if($winBackup){ "<br><small>WinBackup Result: " + $winBackup.Result + "</small>" })
        </td></tr>
        <tr><th>Last successful backup date & time</th><td>$(Get-HtmlInput "YYYY-MM-DD HH:MM" -Value $lastBackupTime)</td></tr>
        <tr><th>Backup frequency (hourly/daily)</th><td>$(Get-HtmlInput "e.g., Hourly")</td></tr>
        <tr><th>Are there any failed backups this month?</th><td>$(Get-HtmlSelect @("Select...", "Yes", "No", "N/A") -SelectedValue $backupFailedSel)</td></tr>
    </table>

    <h3>B. Backup Encryption</h3>
    <table>
        <tr><th>Are backups encrypted at rest?</th><td>$(Get-HtmlSelect -Id "backupEncRest")</td></tr>
        <tr><th>Encryption standard used</th><td>$(Get-HtmlInput "AES-256 preferred" -Id "backupEncStd")</td></tr>
        <tr><th>Are backup transfer channels encrypted?</th><td>$(Get-HtmlSelect -Options @("Select...","Yes (TLS/SSL)","No","Other","N/A") -Id "backupEncTransit")</td></tr>
    </table>

    <h2>2. Server Security & Patch Compliance</h2>
    <h3>A. Update Status</h3>
    <table>
        <tr><th>Are Windows Updates current?</th><td>$(if($missingUpdatesCount -eq 0){"<span class='good'>Yes</span>"}else{"<span class='alert'>No ($missingUpdatesCount Pending)</span>"}) $updateNote</td></tr>
        <tr><th>Last update date</th><td>$(Get-HtmlInput "Check Update History" -Value $lastUpdateDate)</td></tr>
        <tr><th>Pending patches?</th><td><ul>$missingUpdatesHtml</ul></td></tr>
    </table>

    <h3>B. Antivirus / EDR</h3>
    <table>
        <tr><th>AV/EDR installed</th><td>$(if($av){$av.displayName}else{"<span class='alert'>None Detected</span>"})</td></tr>
        <tr><th>Real-time protection enabled?</th><td>$(Get-HtmlSelect @("Select...", "Yes", "No", "N/A") -SelectedValue $rtpEnabled)</td></tr>
        <tr><th>Last scan date</th><td>$(Get-HtmlInput "YYYY-MM-DD" -Value $lastScanDate)</td></tr>
        <tr><th>Any detections this month?</th><td>$(Get-HtmlSelect) $(Get-HtmlInput "Attach or summarize if yes")</td></tr>
    </table>

    <h3>C. Local User Accounts</h3>
    <table>
        <tr><th>List all local server accounts</th><td><ul>$($localUsers.Name | ForEach-Object{"<li>$_</li>"})</ul></td></tr>
        <tr><th>Any disabled but unremoved accounts?</th><td>$(Get-HtmlSelect @("Select...", "Yes", "No", "N/A") -SelectedValue $disabledUsersSel)</td></tr>
    </table>

    <h3>D. Administrator Access</h3>
    <table>
        <tr><th>Are admin passwords changed regularly?</th><td>$(Get-HtmlSelect @("Select...", "Yes", "No", "N/A") -SelectedValue $adminPassChangedRegularly) <br><small>Last Set: $adminPassLastSet</small></td></tr>
        <tr><th>Is password complexity enforced?</th><td>$(Get-HtmlSelect @("Select...", "Yes", "No", "N/A") -SelectedValue $passComplexSel) <small>$passInfoStr</small></td></tr>
    </table>

    <h2>3. Server Encryption</h2>
    <table>
        <tr><th>Is full-disk encryption enabled?</th><td>$(Get-HtmlSelect @("Select...", "Yes", "No", "N/A") -SelectedValue $bitLockerSel)</td></tr>
        <tr><th>Encryption status</th><td>$(Get-HtmlInput "e.g. Encrypted" -Value $bitLockerStatus)</td></tr>
        <tr><th>TPM present/enabled</th><td>$(if($tpm -and $tpm.TpmPresent){"Yes"}else{"No"})</td></tr>
        <tr><th>If not encrypted, reason why</th><td>$(Get-HtmlInput "Reason..." -Value $bitLockerReason)</td></tr>
        <tr><th>Are ChiroTouch data files stored encrypted?</th><td>$(Get-HtmlSelect @("Select...", "Yes", "No", "N/A") -SelectedValue $chiroEncryptedSel)</td></tr>
    </table>

    <h2>4. Server Firewall & Network Security</h2>
    <table>
        <tr><th>Windows Firewall enabled?</th><td>$(if($firewall){"Yes (Profiles: $($firewall.Name -join ', '))"}else{"<span class='alert'>No</span>"})</td></tr>
        <tr><th>Inbound rule review</th><td>$(Get-HtmlInput "List allowed inbound ports" -Value "$openPortsStr | $shareList")</td></tr>
        <tr><th>Does anyone RDP to the server?</th><td>Config Status: $rdpStatus $(Get-HtmlSelect)</td></tr>
        <tr><th>Any failed RDP attempts this month?</th><td>$(Get-HtmlSelect @("Select...", "Yes", "No", "N/A") -SelectedValue $rdpFailSel) <small>(Detected: $rdpFailCount)</small></td></tr>
    </table>

    <h2>5. Server Monitoring & Logs</h2>
    <table>
        <tr><th>Security logs enabled?</th><td>$(if($logSettings){"Yes"}else{"No"})</td></tr>
        <tr><th>Any critical events found this month?</th><td>
            $(if($events){
                "<table style='font-size:0.9em; width:100%; border-collapse:collapse; border:1px solid #ddd;'><tr><th>Src</th><th>ID</th><th>Msg</th><th>Fix</th></tr>" +
                ($events | ForEach-Object {
                    $q = [uri]::EscapeDataString("Windows Event $($_.Id) $($_.ProviderName)")
                    $evtMsg = if ($_.Message) { $_.Message.Substring(0, [Math]::Min(50, $_.Message.Length)) } else { "(No message)" }
                    "<tr><td>$($_.ProviderName)</td><td>$($_.Id)</td><td>$evtMsg...</td><td><a href='https://www.google.com/search?q=$q' target='_blank' class='ai-link'>Ask AI</a></td></tr>"
                } | Out-String) + "</table>"
            } else { "None found." })
        </td></tr>
        <tr><th>Any application errors?</th><td>$(Get-HtmlSelect @("Select...", "Yes", "No", "N/A") -SelectedValue $appErrorSel)</td></tr>
        <tr><th>Any database errors?</th><td>$(Get-HtmlSelect @("Select...", "Yes", "No", "N/A") -SelectedValue $dbErrorSel)</td></tr>
    </table>

    <h2>6. Contingency & Failover</h2>
    <table>
        <tr><th>RAID status</th><td>$(Get-HtmlInput "e.g., RAID 5 Healthy" -Value $(if($ninjaRaidStatus){$ninjaRaidStatus}else{''}))</td></tr>
        <tr><th>Storage warnings?</th><td>$(Get-HtmlInput "Describe..." -Value $(if($storageWarning -or $ninjaDiskInfo){"$storageWarning $(if($ninjaDiskInfo){" | Ninja: $ninjaDiskInfo"})"}else{''}))</td></tr>
        <tr><th>Drive SMART status</th><td>$(Get-HtmlInput "Describe..." -Value $diskHealthStr)</td></tr>
    </table>

    <button onclick="copyReport()" class="copy-btn floating-action">Copy Report for Ticket</button>
"@

    $htmlPage = "<html><head><title>Security Audit Report</title>$style</head><body>$htmlBody</body></html>"
    $htmlPage | Out-File -FilePath $reportPath -Encoding UTF8 -ErrorAction Stop
    Write-Log "Report generated: $reportPath"
    Invoke-Item $reportPath
}

function Invoke-NinjaConnectInteractive {
    $saved = Get-NinjaSettings
    $url = Read-Host "NinjaOne Instance URL (default: $($saved.Url ?? 'app.ninjarmm.com'))"
    if ([string]::IsNullOrWhiteSpace($url)) { $url = if ($saved -and $saved.Url) { $saved.Url } else { 'app.ninjarmm.com' } }

    $cid = Read-Host 'Client ID (blank = use embedded)'
    if ([string]::IsNullOrWhiteSpace($cid) -and $saved -and $saved.ClientId) { $cid = $saved.ClientId }

    $sec = Read-Host 'Client Secret (blank = use embedded)'
    if ([string]::IsNullOrWhiteSpace($sec) -and $saved -and $saved.ClientSecret) { $sec = $saved.ClientSecret }

    $save = Read-Host 'Save these settings? (y/N)'
    if ($save -match '^(y|yes)$') { Save-NinjaSettings -Url $url -Id $cid -Secret $sec }

    Connect-NinjaOne -ClientId $cid -ClientSecret $sec -InstanceUrl $url
}

# --- Task dispatcher ---
function Invoke-Task {
    param(
        [Parameter(Mandatory)] [string]$Name,
        [string[]]$Args = @()
    )

    Write-Log "=== TASK START: $Name ==="
    try {
        switch ($Name) {
            'Dashboard' { Invoke-RefreshDashboard }
            'FreeDisk' { Invoke-FreeDisk }
            'DisableSleepHibernate' { Invoke-DisableSleepHibernate }
            'FixNetworkReset' { Invoke-FixNetworkReset }
            'SFC' { Invoke-Sfc }
            'DISM' { Invoke-Dism }
            'ResetWindowsUpdate' { Invoke-ResetWindowsUpdate }
            'MaintenanceBundle' { Invoke-MaintenanceBundle }
            'ClearPrintSpooler' { Invoke-ClearPrintSpooler }
            'RestartExplorer' { Invoke-RestartExplorer }
            'SyncTime' { Invoke-SyncTime }
            'SpaceMonger' { Invoke-DownloadSpaceMonger }

            'ShowIpConfig' { Invoke-ShowIpConfig }
            'ArpScan' { Invoke-ArpScan }
            'TestInternet' { Invoke-TestInternet }
            'EnableNetworkSharing' { Invoke-EnableNetworkSharing }

            'ScanPrinters9100' { Invoke-ScanPrintersPort9100 }

            'NinjaConnect' { Invoke-NinjaConnectInteractive }

            'ListUsers' { Invoke-ListLocalUsers }
            'CreateUser' { Invoke-CreateLocalUser -UserName $Args[0] -Password $Args[1] }
            'ResetPassword' { Invoke-ResetLocalUserPassword -UserName $Args[0] -Password $Args[1] }
            'AddToAdmins' { Invoke-AddUserToAdmins -UserName $Args[0] }
            'EnableUser' { Invoke-EnableLocalUser -UserName $Args[0] }
            'DisableUser' { Invoke-DisableLocalUser -UserName $Args[0] }
            'DeleteUser' { Invoke-DeleteLocalUser -UserName $Args[0] }

            'ListShares' { Invoke-ListShares }
            'CreateShare' { Invoke-CreateShare -Path $Args[0] -Name $Args[1] }
            'DeleteShare' { Invoke-DeleteShare -Name $Args[0] }

            'SecurityAudit' { Invoke-SecurityAudit }

            'QuickTriage' { Invoke-QuickTriage }
            'PendingReboot' { Invoke-ShowPendingReboot }
            'RecentEvents' { Invoke-ShowRecentCriticalEvents }
            'BitLockerStatus' { Invoke-ShowBitLockerStatus }
            'FirewallStatus' { Invoke-ShowFirewallStatus }
            'TailLog' { Invoke-TailLog }
            'ExportBundle' { Invoke-ExportWinFixBundle }

            default { throw "Unknown task: $Name" }
        }
    } catch {
        Write-Log "TASK ERROR ($Name): $_"
        throw
    } finally {
        Write-Log "=== TASK END: $Name ==="
        Write-Log "Log file: $script:LogFilePath"
    }
}

# --- Menu UI ---
function Show-Header {
    Clear-Host
    Write-Host ''
    Write-Host 'WinFix Console' -ForegroundColor Cyan
    Write-Host "Log: $script:LogFilePath" -ForegroundColor DarkGray
    Write-Host ''
}

function Show-MainMenu {
    Show-Header
    Write-Host '1) Dashboard / System Overview'
    Write-Host '2) Maintenance'
    Write-Host '3) Network'
    Write-Host '4) Users & Shares'
    Write-Host '5) Integrations (NinjaOne)'
    Write-Host '6) Security Audit'
    Write-Host '7) Diagnostics / Triage'
    Write-Host ''
    Write-Host 'L) Open log file'
    Write-Host 'T) Tail log (live)'
    Write-Host 'E) Export bundle (zip)'
    Write-Host 'Q) Quit'
    Write-Host ''
}

function Open-LogFile {
    if (Test-Path $script:LogFilePath) { Invoke-Item $script:LogFilePath }
}

function Read-Choice([string]$Prompt = 'Select:') {
    Write-Host ''
    return (Read-Host $Prompt).Trim()
}

function Menu-Maintenance {
    while ($true) {
        Show-Header
        Write-Host 'Maintenance'
        Write-Host '1) Free Up Disk Space'
        Write-Host '2) Disable Sleep & Hibernate'
        Write-Host '3) Fix Network (Reset TCP/IP)'
        Write-Host '4) Run System File Checker (SFC)'
        Write-Host '5) DISM Repair Image'
        Write-Host '6) Reset Windows Update'
        Write-Host '7) Clear Print Spooler'
        Write-Host '8) Restart Explorer'
        Write-Host '9) Sync System Time'
        Write-Host '10) Download & Run SpaceMonger'
        Write-Host '11) Run Maintenance Bundle (SFC + DISM + Reset WU)'
        Write-Host ''
        Write-Host 'B) Back'
        Write-Host 'L) Open log file'

        $c = Read-Choice
        switch ($c.ToUpperInvariant()) {
            '1' { Start-TaskWindow -Name 'FreeDisk' }
            '2' { Start-TaskWindow -Name 'DisableSleepHibernate' }
            '3' { Start-TaskWindow -Name 'FixNetworkReset' }
            '4' { Start-TaskWindow -Name 'SFC' }
            '5' { Start-TaskWindow -Name 'DISM' }
            '6' { Start-TaskWindow -Name 'ResetWindowsUpdate' }
            '7' { Start-TaskWindow -Name 'ClearPrintSpooler' }
            '8' { Start-TaskWindow -Name 'RestartExplorer' }
            '9' { Start-TaskWindow -Name 'SyncTime' }
            '10' { Start-TaskWindow -Name 'SpaceMonger' }
            '11' { Start-TaskWindow -Name 'MaintenanceBundle' }
            'B' { return }
            'L' { Open-LogFile }
            default { }
        }
    }
}

function Menu-Network {
    while ($true) {
        Show-Header
        Write-Host 'Network'
        Write-Host '1) Show IP Configuration'
        Write-Host '2) Quick ARP Scan'
        Write-Host '3) Test Internet Connection'
        Write-Host '4) Enable Network Sharing (Private/No FW)'
        Write-Host '5) Scan Network Printers (Port 9100)'
        Write-Host ''
        Write-Host 'B) Back'
        Write-Host 'L) Open log file'

        $c = Read-Choice
        switch ($c.ToUpperInvariant()) {
            '1' { Start-TaskWindow -Name 'ShowIpConfig' }
            '2' { Start-TaskWindow -Name 'ArpScan' }
            '3' { Start-TaskWindow -Name 'TestInternet' }
            '4' { Start-TaskWindow -Name 'EnableNetworkSharing' }
            '5' { Start-TaskWindow -Name 'ScanPrinters9100' }
            'B' { return }
            'L' { Open-LogFile }
            default { }
        }
    }
}

function Menu-Diagnostics {
    while ($true) {
        Show-Header
        Write-Host 'Diagnostics / Triage'
        Write-Host '1) Quick Triage (save + open txt)'
        Write-Host '2) Pending Reboot Check'
        Write-Host '3) Recent System Events (warnings/errors)'
        Write-Host '4) BitLocker Status'
        Write-Host '5) Firewall Profile Status'
        Write-Host '6) Export bundle (zip: log + latest audit)'
        Write-Host '7) Tail log (live)'
        Write-Host ''
        Write-Host 'B) Back'
        Write-Host 'L) Open log file'

        $c = Read-Choice
        switch ($c.ToUpperInvariant()) {
            '1' { Start-TaskWindow -Name 'QuickTriage' }
            '2' { Start-TaskWindow -Name 'PendingReboot' }
            '3' { Start-TaskWindow -Name 'RecentEvents' }
            '4' { Start-TaskWindow -Name 'BitLockerStatus' }
            '5' { Start-TaskWindow -Name 'FirewallStatus' }
            '6' { Start-TaskWindow -Name 'ExportBundle' }
            '7' { Start-TaskWindow -Name 'TailLog' }
            'B' { return }
            'L' { Open-LogFile }
            default { }
        }
    }
}

function Menu-UsersShares {
    while ($true) {
        Show-Header
        Write-Host 'Users & Shares'
        Write-Host '1) List local users'
        Write-Host '2) Create user'
        Write-Host '3) Reset user password'
        Write-Host '4) Add user to Administrators'
        Write-Host '5) Enable user'
        Write-Host '6) Disable user'
        Write-Host '7) Delete user'
        Write-Host ''
        Write-Host '8) List shares'
        Write-Host '9) Create share (Full Access Everyone)'
        Write-Host '10) Delete share'
        Write-Host ''
        Write-Host 'B) Back'
        Write-Host 'L) Open log file'

        $c = Read-Choice
        switch ($c.ToUpperInvariant()) {
            '1' { Start-TaskWindow -Name 'ListUsers' }
            '2' {
                $u = Read-Host 'Username'
                $p = Read-Host 'Password'
                Start-TaskWindow -Name 'CreateUser' -Args @($u, $p)
            }
            '3' {
                $u = Read-Host 'Username'
                $p = Read-Host 'New Password'
                Start-TaskWindow -Name 'ResetPassword' -Args @($u, $p)
            }
            '4' {
                $u = Read-Host 'Username'
                Start-TaskWindow -Name 'AddToAdmins' -Args @($u)
            }
            '5' {
                $u = Read-Host 'Username'
                Start-TaskWindow -Name 'EnableUser' -Args @($u)
            }
            '6' {
                $u = Read-Host 'Username'
                Start-TaskWindow -Name 'DisableUser' -Args @($u)
            }
            '7' {
                $u = Read-Host 'Username'
                Start-TaskWindow -Name 'DeleteUser' -Args @($u)
            }
            '8' { Start-TaskWindow -Name 'ListShares' }
            '9' {
                $path = Read-Host 'Folder path'
                $name = Read-Host 'Share name'
                Start-TaskWindow -Name 'CreateShare' -Args @($path, $name)
            }
            '10' {
                $name = Read-Host 'Share name'
                Start-TaskWindow -Name 'DeleteShare' -Args @($name)
            }
            'B' { return }
            'L' { Open-LogFile }
            default { }
        }
    }
}

function Menu-Integrations {
    while ($true) {
        Show-Header
        Write-Host 'Integrations'
        Write-Host '1) Connect to NinjaOne'
        Write-Host '2) Refresh Ninja device data'
        Write-Host ''
        Write-Host 'B) Back'
        Write-Host 'L) Open log file'

        $c = Read-Choice
        switch ($c.ToUpperInvariant()) {
            '1' { Start-TaskWindow -Name 'NinjaConnect' }
            '2' {
                if (-not $global:NinjaToken) {
                    Write-Log 'Not connected to NinjaOne. Use option 1 first.'
                    Pause-Window
                } else {
                    Start-TaskWindow -Name 'Dashboard'
                }
            }
            'B' { return }
            'L' { Open-LogFile }
            default { }
        }
    }
}

# --- Entry ---
Write-Log '=== WinFix Console Started ==='
Write-Log "Computer: $env:COMPUTERNAME"
Write-Log "User: $env:USERNAME"

if ($TaskName) {
    Invoke-Task -Name $TaskName -Args $TaskArgs
    Pause-Window
    exit
}

while ($true) {
    Show-MainMenu
    $choice = Read-Choice

    switch ($choice.ToUpperInvariant()) {
        '1' { Start-TaskWindow -Name 'Dashboard' }
        '2' { Menu-Maintenance }
        '3' { Menu-Network }
        '4' { Menu-UsersShares }
        '5' { Menu-Integrations }
        '6' { Start-TaskWindow -Name 'SecurityAudit' }
        '7' { Menu-Diagnostics }
        'L' { Open-LogFile }
        'T' { Start-TaskWindow -Name 'TailLog' }
        'E' { Start-TaskWindow -Name 'ExportBundle' }
        'Q' { break }
        default { }
    }
}

Write-Log '=== WinFix Console Exiting ==='
