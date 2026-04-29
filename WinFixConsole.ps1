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

function Enable-Tls12 {
    try {
        $current = [Net.ServicePointManager]::SecurityProtocol
        if (($current -band [Net.SecurityProtocolType]::Tls12) -eq 0) {
            [Net.ServicePointManager]::SecurityProtocol = $current -bor [Net.SecurityProtocolType]::Tls12
        }
    } catch {
        # Best-effort; some hardened environments may block changes.
    }
}

Enable-Tls12

# Resolve script path reliably (works when dot-sourced, iex'd, or run via -File)
$script:ScriptPath = if ($PSCommandPath) { $PSCommandPath } elseif ($MyInvocation.MyCommand.Path) { $MyInvocation.MyCommand.Path } else { $null }

# --- Elevate if needed ---
try {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
} catch {
    $isAdmin = $false
}

if (-not $isAdmin) {
    if (-not $script:ScriptPath) {
        Write-Host 'ERROR: Cannot elevate - script path unknown. Save the script to a file and run it directly.' -ForegroundColor Red
        Read-Host 'Press Enter to exit'
        exit 1
    }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'powershell.exe'
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$($script:ScriptPath)`"" + $(if ($TaskName) { " -TaskName `"$TaskName`"" } else { '' })
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
        try {
            Invoke-Task -Name $Name -Args $Args
        } finally {
            Pause-Window
        }
        return
    }

    if (-not $script:ScriptPath) {
        Write-Log 'ERROR: Cannot launch task window - script path unknown.'
        Pause-Window 'Press Enter...'
        return
    }

    $argLiteral = if ($Args -and $Args.Count -gt 0) {
        # Quote each arg for PowerShell -Command
        $quoted = $Args | ForEach-Object { '"' + ($_ -replace '"', '\\"') + '"' }
        "-TaskArgs @($($quoted -join ', '))"
    } else {
        "-TaskArgs @()"
    }

    $cmd = "& '$($script:ScriptPath -replace "'", "''")' -TaskName '$Name' $argLiteral"
    $full = "-NoProfile -ExecutionPolicy Bypass -NoExit -Command `"$cmd`""

    Write-Log "Launching task in new window: $Name"
    Start-Process -FilePath 'powershell.exe' -ArgumentList $full | Out-Null
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
        Enable-Tls12
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
        [Parameter(Mandatory)] [string]$TargetHost,
        [Parameter(Mandatory)] [int]$Port,
        [int]$TimeoutMs = 250
    )

    $client = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect($TargetHost, $Port, $null, $null)
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

        if (Test-TcpPort -TargetHost $addr -Port 9100 -TimeoutMs 250) {
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
    Write-Log "Initializing Security Audit..."
    Write-Log "NOTE: This process may take 30-90 seconds depending on Windows Update cache."

    # --- Elevation check ---
    $isElevated = $false
    try {
        $wid = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $wp = New-Object System.Security.Principal.WindowsPrincipal($wid)
        $isElevated = $wp.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {}
    if (-not $isElevated) {
        Write-Log "WARNING: Not running as Administrator. Several checks (secedit, BitLocker, Security log, TPM) will be blank."
    }

    # --- Output path with TEMP fallback ---
    $DesktopPath = [Environment]::GetFolderPath("Desktop")
    if ([string]::IsNullOrWhiteSpace($DesktopPath) -or -not (Test-Path $DesktopPath)) { $DesktopPath = $env:TEMP }
    $ReportPath = Join-Path -Path $DesktopPath -ChildPath "JeremyBean_SecurityAudit_$(Get-Date -Format 'yyyyMMdd_HHmm').html"
    $EventLookbackDays = 30
    $MaxEventsToShow = 15

    # --- Helpers ---
    function HtmlEnc {
        param($Value)
        if ($null -eq $Value) { return '' }
        $s = [string]$Value
        $s = $s -replace '&','&amp;'
        $s = $s -replace '<','&lt;'
        $s = $s -replace '>','&gt;'
        $s = $s -replace '"','&quot;'
        $s = $s -replace "'",'&#39;'
        return $s
    }

    $script:_AuditKeyN = 0
    function New-AuditKey { $script:_AuditKeyN++; return "audit-$script:_AuditKeyN" }

    function Get-HtmlInput {
        param($Placeholder="Enter details...", $Value="", $Id="")
        $key = New-AuditKey
        $idAttr = if ($Id) { "id='$(HtmlEnc $Id)'" } else { "" }
        $ph = HtmlEnc $Placeholder
        $vl = HtmlEnc $Value
        return "<input type='text' $idAttr data-key='$key' class='user-input' placeholder='$ph' value='$vl'>"
    }

    function Get-HtmlSelect {
        param($Options=@("Select...", "Yes", "No", "N/A"), $SelectedValue="", $Id="", $OnChange="")
        $key = New-AuditKey
        $idAttr = if ($Id) { "id='$(HtmlEnc $Id)'" } else { "" }
        $changeAttr = if ($OnChange) { "onchange='$(HtmlEnc $OnChange)'" } else { "" }
        if (-not ($Options -contains "N/A")) { $Options += "N/A" }
        $optHtml = ""
        foreach($opt in $Options) {
            $sel = if($opt -eq $SelectedValue){ "selected" } else { "" }
            $oEnc = HtmlEnc $opt
            $optHtml += "<option value='$oEnc' $sel>$oEnc</option>"
        }
        return "<select class='user-select' $idAttr $changeAttr data-key='$key'>$optHtml</select>"
    }

    function Get-HtmlTextArea {
        $key = New-AuditKey
        return "<textarea class='user-input' rows='3' placeholder='Enter details...' data-key='$key'></textarea>"
    }

    function Get-OSEndOfSupport {
        param([int]$Build, [string]$Caption)
        $eosTable = @{
            3790  = @{ Name='Server 2003 / XP x64';   End=[datetime]'2015-07-14' }
            6002  = @{ Name='Server 2008 / Vista';    End=[datetime]'2020-01-14' }
            7601  = @{ Name='Server 2008 R2 / Win 7'; End=[datetime]'2020-01-14' }
            9200  = @{ Name='Server 2012 / Win 8';    End=[datetime]'2023-10-10' }
            9600  = @{ Name='Server 2012 R2 / 8.1';   End=[datetime]'2023-10-10' }
            10240 = @{ Name='Win 10 1507';            End=[datetime]'2017-05-09' }
            10586 = @{ Name='Win 10 1511';            End=[datetime]'2017-10-10' }
            14393 = @{ Name='Server 2016 / Win10 1607'; End=[datetime]'2027-01-12' }
            15063 = @{ Name='Win 10 1703';            End=[datetime]'2018-10-09' }
            16299 = @{ Name='Win 10 1709';            End=[datetime]'2019-04-09' }
            17134 = @{ Name='Win 10 1803';            End=[datetime]'2019-11-12' }
            17763 = @{ Name='Server 2019 / Win10 1809'; End=[datetime]'2029-01-09' }
            18362 = @{ Name='Win 10 1903';            End=[datetime]'2020-12-08' }
            18363 = @{ Name='Win 10 1909';            End=[datetime]'2022-05-10' }
            19041 = @{ Name='Win 10 2004';            End=[datetime]'2021-12-14' }
            19042 = @{ Name='Win 10 20H2';            End=[datetime]'2023-05-09' }
            19043 = @{ Name='Win 10 21H1';            End=[datetime]'2022-12-13' }
            19044 = @{ Name='Win 10 21H2';            End=[datetime]'2024-06-11' }
            19045 = @{ Name='Win 10 22H2';            End=[datetime]'2025-10-14' }
            20348 = @{ Name='Server 2022';            End=[datetime]'2031-10-14' }
            22000 = @{ Name='Win 11 21H2';            End=[datetime]'2023-10-10' }
            22621 = @{ Name='Win 11 22H2';            End=[datetime]'2024-10-08' }
            22631 = @{ Name='Win 11 23H2';            End=[datetime]'2025-11-11' }
            26100 = @{ Name='Win 11 24H2 / Server 2025'; End=[datetime]'2034-10-10' }
        }
        if ($eosTable.ContainsKey($Build)) {
            $row = $eosTable[$Build]
            return [PSCustomObject]@{
                Name = $row.Name
                EndDate = $row.End
                IsEOL = ((Get-Date) -gt $row.End)
            }
        }
        return $null
    }

    function Get-EventSolution {
        param($Source, $Message)
        $predefined = @{
            "Disk" = "Check physical drive health (SMART)."
            "Ntfs" = "File system corruption."
            "VSS"  = "VSS Shadow Copy error."
            "WindowsUpdate" = "Check Update Service."
            "BugCheck" = "BSOD detected."
        }
        foreach ($key in $predefined.Keys) { if ($Source -match $key) { return $predefined[$key] } }
        return "Check Event ID."
    }

    # --- Styling & Scripting ---
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
        .ai-link { display: inline-block; margin-top: 5px; color: var(--accent-cyan); font-weight: bold; text-decoration: none; font-size: 0.85em; border: 1px solid var(--accent-blue); padding: 2px 6px; border-radius: 4px; background-color: white; }
    </style>

    <script>
        const backupDefaults = {
            "Datto":     { enc: "AES-256 (Datto Default)",     rest: "Yes", transit: "Yes (TLS/SSL)" },
            "Veeam":     { enc: "AES-256 (Industry Standard)", rest: "Yes", transit: "Yes (TLS/SSL)" },
            "Acronis":   { enc: "AES-256 (Acronis Cyber)",     rest: "Yes", transit: "Yes (TLS/SSL)" },
            "Macrium":   { enc: "AES-256 (Optional)",          rest: "Yes", transit: "Yes (TLS/SSL)" },
            "Carbonite": { enc: "AES-256/Blowfish",             rest: "Yes", transit: "Yes (TLS/SSL)" },
            "CrashPlan": { enc: "AES-256",                      rest: "Yes", transit: "Yes (TLS/SSL)" },
            "Veritas":   { enc: "AES-128/256",                  rest: "Yes", transit: "Yes" },
            "Cove":      { enc: "AES-256",                      rest: "Yes", transit: "Yes (TLS/SSL)" },
            "Axcient":   { enc: "AES-256",                      rest: "Yes", transit: "Yes (TLS/SSL)" },
            "Rubrik":    { enc: "AES-256",                      rest: "Yes", transit: "Yes (TLS/SSL)" },
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
                selectElem.style.borderColor = '#27ae60';
                document.getElementById('backupEncStd').style.borderColor = '#27ae60';
                setTimeout(() => {
                    selectElem.style.borderColor = '#bdc3c7';
                    document.getElementById('backupEncStd').style.borderColor = '#bdc3c7';
                }, 1000);
            }
        }

        function buildSnapshotContainer() {
            const clone = document.body.cloneNode(true);
            clone.querySelectorAll('.copy-btn, .floating-action').forEach(b => b.remove());

            // Snapshot inputs by data-key
            const originals = document.querySelectorAll('[data-key]');
            const cloneMap = {};
            clone.querySelectorAll('[data-key]').forEach(el => { cloneMap[el.getAttribute('data-key')] = el; });
            originals.forEach(orig => {
                const key = orig.getAttribute('data-key');
                const target = cloneMap[key];
                if (!target) return;
                let val = '';
                if (orig.tagName === 'SELECT') {
                    val = (orig.selectedIndex >= 0) ? orig.options[orig.selectedIndex].text : 'Select...';
                } else {
                    val = orig.value;
                }
                if (!val) val = 'N/A';
                const span = document.createElement('span');
                span.textContent = val;
                span.style.fontWeight = 'bold';
                if (val === 'No' || val === 'Failed' || val === 'Non-Compliant') span.style.color = '#e74c3c';
                else if (val === 'Yes' || val === 'Success' || val === 'Compliant' || val === 'Enabled') span.style.color = '#27ae60';
                else span.style.color = '#333';
                if (target.parentNode) target.parentNode.replaceChild(span, target);
            });

            const container = document.createElement('div');
            container.style.fontFamily = "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif";
            container.style.fontSize = '13px';
            container.style.lineHeight = '1.4';
            container.style.color = '#333';
            container.style.maxWidth = '600px';
            container.innerHTML = clone.innerHTML;

            container.querySelectorAll('h1').forEach(h => { h.style.fontSize='18px'; h.style.marginBottom='10px'; h.style.color='#0056b3'; });
            container.querySelectorAll('h2').forEach(h => {
                h.style.fontSize='15px'; h.style.backgroundColor='#e8f4f8'; h.style.color='#0056b3';
                h.style.padding='5px'; h.style.marginTop='20px'; h.style.borderTop='2px solid #0056b3';
            });
            container.querySelectorAll('h3').forEach(h => { h.style.fontSize='14px'; h.style.marginTop='10px'; h.style.color='#0056b3'; });

            container.querySelectorAll('table').forEach(table => {
                const firstRow = table.querySelector('tr');
                let isFormTable = false;
                if (firstRow && firstRow.children.length === 2 && firstRow.children[0].tagName === 'TH') isFormTable = true;
                if (isFormTable) {
                    const listBlock = document.createElement('div');
                    listBlock.style.marginBottom = '15px';
                    table.querySelectorAll('tr').forEach(row => {
                        const th = row.querySelector('th');
                        const td = row.querySelector('td');
                        if (th && td) {
                            const item = document.createElement('div');
                            item.style.marginBottom = '6px';
                            item.style.borderBottom = '1px solid #eee';
                            item.style.paddingBottom = '4px';
                            let label = th.textContent.trim();
                            if (!label.match(/[:?]$/)) label += ':';
                            item.innerHTML = "<strong style='color:#444;'>" + label + "</strong> <span style='margin-left:5px;'>" + td.innerHTML + "</span>";
                            listBlock.appendChild(item);
                        } else if (row.cells.length === 1) {
                            const item = document.createElement('div');
                            item.innerHTML = row.cells[0].innerHTML;
                            listBlock.appendChild(item);
                        }
                    });
                    if (table.parentNode) table.parentNode.replaceChild(listBlock, table);
                } else {
                    table.style.width = '100%';
                    table.style.border = '1px solid #ddd';
                    table.style.borderCollapse = 'collapse';
                    table.querySelectorAll('th, td').forEach(c => {
                        c.style.padding='4px'; c.style.border='1px solid #ddd'; c.style.fontSize='12px';
                    });
                }
            });

            container.querySelectorAll('.meta-info').forEach(meta => {
                const newMeta = document.createElement('div');
                newMeta.style.marginBottom = '10px';
                newMeta.style.color = '#666';
                meta.querySelectorAll('span').forEach(s => {
                    const p = document.createElement('div');
                    p.innerHTML = s.innerHTML;
                    newMeta.appendChild(p);
                });
                meta.parentNode.replaceChild(newMeta, meta);
            });

            return container;
        }

        async function copyReport() {
            const container = buildSnapshotContainer();
            const html = container.outerHTML;
            const plain = container.textContent;
            try {
                if (navigator.clipboard && window.ClipboardItem) {
                    await navigator.clipboard.write([new ClipboardItem({
                        'text/html': new Blob([html], { type: 'text/html' }),
                        'text/plain': new Blob([plain], { type: 'text/plain' })
                    })]);
                    alert('Report Copied! Formatted for Ticket System (Vertical Layout).');
                    return;
                }
            } catch (e) { /* fall through to legacy path */ }

            // Legacy fallback: select node + execCommand
            const tempDiv = document.createElement('div');
            tempDiv.style.position = 'absolute';
            tempDiv.style.left = '-9999px';
            tempDiv.appendChild(container);
            document.body.appendChild(tempDiv);
            const range = document.createRange();
            range.selectNodeContents(tempDiv);
            const sel = window.getSelection();
            sel.removeAllRanges();
            sel.addRange(range);
            try {
                document.execCommand('copy');
                alert('Report Copied! Formatted for Ticket System (Vertical Layout).');
            } catch (err) {
                alert('Copy failed.');
            }
            document.body.removeChild(tempDiv);
            sel.removeAllRanges();
        }
    </script>
"@

    # --- DATA GATHERING ---

    # 0. Server Info
    Write-Log "[-] Gathering System Info..."
    $CompInfo = Get-CimInstance Win32_ComputerSystem
    $OSInfo = Get-CimInstance Win32_OperatingSystem

    # Domain Controller detection (DomainRole 4 = Backup DC, 5 = Primary DC)
    $IsDC = ($CompInfo.DomainRole -ge 4)

    # Administrators group via well-known SID (locale-independent)
    $AdminGroup = @()
    try {
        $AdminGroup = Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop
    } catch {
        try { $AdminGroup = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue } catch { $AdminGroup = @() }
    }

    $Uptime = (Get-Date) - $OSInfo.LastBootUpTime
    $UptimeStr = "{0} Days, {1} Hours" -f $Uptime.Days, $Uptime.Hours

    # Broadened VM detection
    $vmHints = @('Virtual','VMware','VirtualBox','KVM','QEMU','Xen','Parallels','Hyper-V','Bochs','innotek')
    $modelStr = "$($CompInfo.Model) $($CompInfo.Manufacturer)"
    $IsVM = $false
    foreach ($h in $vmHints) { if ($modelStr -match [regex]::Escape($h)) { $IsVM = $true; break } }
    if (-not $IsVM) {
        $vmSvcs = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -in @('vmtools','VMTools','vmicheartbeat','vmicvss','vmicshutdown','vboxservice') -and $_.Status -eq 'Running' }
        if ($vmSvcs) { $IsVM = $true }
    }

    # OS End-of-Support (build-based table)
    $EOSWarning = ''
    $eos = Get-OSEndOfSupport -Build ([int]$OSInfo.BuildNumber) -Caption $OSInfo.Caption
    if ($eos -and $eos.IsEOL) {
        $endStr = HtmlEnc ($eos.EndDate.ToString('yyyy-MM-dd'))
        $nameEnc = HtmlEnc $eos.Name
        $EOSWarning = "<span style='color:#dc3545; font-weight:bold; margin-left:10px;'> [WARNING: $nameEnc reached End-of-Support on $endStr]</span>"
    }

    # Server Roles (Server SKUs only)
    $DetectedRoles = ""
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        try {
            $Feats = Get-WindowsFeature | Where-Object { $_.Installed -eq $true -and $_.FeatureType -eq 'Role' }
            if ($Feats) { $DetectedRoles = ($Feats.Name -join ", ") }
        } catch { $DetectedRoles = "Could not query roles" }
    } else {
        $DetectedRoles = "Workstation / Roles Not Available"
    }

    # 1. Backups
    Write-Log "[-] Checking Backup History..."
    $BackupKeywords = "*Veeam*","*Acronis*","*Macrium*","*Datto*","*Carbonite*","*Veritas*","*CrashPlan*","*Cove*","*Axcient*","*Rubrik*","*N-able*","*SentinelOne*"
    $DetectedServices = Get-Service -ErrorAction SilentlyContinue | Where-Object { $d = $_.DisplayName; ($BackupKeywords | Where-Object { $d -like $_ }) }

    $BackupOptions = @("Select...")
    if ($DetectedServices) {
        foreach ($svc in $DetectedServices) { $BackupOptions += "[DETECTED] $($svc.DisplayName)" }
        $BackupOptions += "----------------"
    }
    $BackupOptions += @("Datto","Veeam","Acronis","Macrium","Carbonite","CrashPlan","Cove","Axcient","Rubrik","Windows Server Backup","Other (Manual)")

    # Pull last 30 backup events to count successes/failures, not just the most recent
    $WinBackupEvents = Get-WinEvent -LogName "Microsoft-Windows-Backup" -MaxEvents 30 -ErrorAction SilentlyContinue
    $BackupSuccessSel = "Select..."
    $LastBackupTime = ""
    $BackupFailedSel = "Select..."
    $BackupSummary = ""
    if ($WinBackupEvents) {
        $succ = @($WinBackupEvents | Where-Object { $_.Id -eq 4 })
        $fail = @($WinBackupEvents | Where-Object { $_.Id -ne 4 })
        if ($succ.Count -gt 0) {
            $BackupSuccessSel = "Yes"
            $LastBackupTime = $succ[0].TimeCreated.ToString("yyyy-MM-dd HH:mm")
        } else {
            $BackupSuccessSel = "No"
        }
        $BackupFailedSel = if ($fail.Count -gt 0) { "Yes" } else { "No" }
        $BackupSummary = "Last 30 events: $($succ.Count) success / $($fail.Count) failure"
    }

    # 2. Updates - prefer Update Session history over Get-HotFix
    Write-Log "[-] Auditing Security & Updates..."
    $AV = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue

    $LastUpdateDate = ""
    try {
        $UpdateSession = New-Object -ComObject Microsoft.Update.Session
        $hist = $UpdateSession.QueryHistory(0, 50) | Where-Object { $_.ResultCode -eq 2 } | Sort-Object Date -Descending | Select-Object -First 1
        if ($hist) { $LastUpdateDate = $hist.Date.ToString('yyyy-MM-dd') }
    } catch {}
    if (-not $LastUpdateDate) {
        try {
            $LastHotFix = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 1
            if ($LastHotFix -and $LastHotFix.InstalledOn) { $LastUpdateDate = $LastHotFix.InstalledOn.ToString('yyyy-MM-dd') }
        } catch {}
    }

    # Missing updates - run search in a background job with timeout to avoid hanging the UI
    $MissingUpdatesCount = 0
    $MissingUpdatesHTML = ""
    try {
        $job = Start-Job -ScriptBlock {
            $sess = New-Object -ComObject Microsoft.Update.Session
            $searcher = $sess.CreateUpdateSearcher()
            $res = $searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
            $titles = @()
            foreach ($u in $res.Updates) { $titles += [string]$u.Title }
            return @{ Count = [int]$res.Updates.Count; Titles = $titles }
        }
        $finished = Wait-Job $job -Timeout 90
        if ($finished) {
            $r = Receive-Job $job -ErrorAction SilentlyContinue
            $MissingUpdatesCount = [int]$r.Count
            if ($MissingUpdatesCount -gt 0) {
                foreach ($t in $r.Titles) {
                    $tEnc = HtmlEnc $t
                    $uQuery = [uri]::EscapeDataString("Windows Update $t problems")
                    $MissingUpdatesHTML += "<li>$tEnc (<a href='https://www.google.com/search?q=$uQuery' target='_blank' class='ai-link'>Analyze</a>)</li>"
                }
            }
        } else {
            $MissingUpdatesHTML = "Update search timed out after 90 seconds (WSUS unreachable?)."
        }
        Remove-Job $job -Force -ErrorAction SilentlyContinue
    } catch {
        $MissingUpdatesHTML = "Error querying Windows Update: " + (HtmlEnc $_.Exception.Message)
    }

    # Pending Reboot
    $PendingReboot = $false
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") { $PendingReboot = $true }
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") { $PendingReboot = $true }
    $UpdateNote = if ($PendingReboot) { "<span class='alert'><b>(Reboot Pending)</b></span>" } else { "" }

    # Defender
    $Defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
    $RTPEnabled = "Select..."
    $LastScanDate = ""
    if ($Defender) {
        $RTPEnabled = if ($Defender.RealTimeProtectionEnabled) { "Yes" } else { "No" }
        $LastScanDate = if ($Defender.QuickScanEndTime) { $Defender.QuickScanEndTime.ToString("yyyy-MM-dd") } else { "Never" }
        if (-not $AV) { $AV = [PSCustomObject]@{ displayName = "Windows Defender" } }
    }

    # Local users (skip on DC - no local SAM)
    $LocalUsers = @()
    $DisabledUsers = @()
    $DisabledUsersSel = "Select..."
    $LocalUsersNote = ""
    if ($IsDC) {
        $LocalUsersNote = "Domain Controller - see Active Directory Users"
        $DisabledUsersSel = "N/A"
    } else {
        try {
            $LocalUsers = Get-LocalUser -ErrorAction Stop | Select-Object Name, Enabled, PasswordLastSet, SID
            $DisabledUsers = $LocalUsers | Where-Object { $_.Enabled -eq $false }
            $DisabledUsersSel = if ($DisabledUsers) { "Yes" } else { "No" }
        } catch {
            $LocalUsersNote = "Could not enumerate local users"
        }
    }

    # Built-in Administrator (RID -500)
    $AdminPassLastSet = "Unknown / Domain Account"
    $AdminPassChangedRegularly = "Select..."
    $AdminEnabledNote = ""
    try {
        $BuiltInAdmin = $null
        if (-not $IsDC) {
            $BuiltInAdmin = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.SID -like "*-500" } | Select-Object -First 1
        }
        if ($BuiltInAdmin) {
            $AdminEnabledNote = if ($BuiltInAdmin.Enabled) { " (Built-in Administrator: ENABLED)" } else { " (Built-in Administrator: disabled)" }
            if ($BuiltInAdmin.PasswordLastSet) {
                $AdminPassLastSet = $BuiltInAdmin.PasswordLastSet.ToString("yyyy-MM-dd")
                $DaysSinceChange = (New-TimeSpan -Start $BuiltInAdmin.PasswordLastSet -End (Get-Date)).Days
                if ($DaysSinceChange -gt 90) {
                    $AdminPassChangedRegularly = "No"
                    $AdminPassLastSet += " ($DaysSinceChange days ago)"
                } else {
                    $AdminPassChangedRegularly = "Yes"
                }
            } else {
                $AdminPassLastSet = "Never Set"
            }
        } elseif ($IsDC) {
            $AdminPassLastSet = "Domain Controller - see AD"
        }
    } catch {
        $AdminPassLastSet = "N/A (See AD)"
    }

    # Password policy (requires admin)
    $PassComplexSel = "Select..."
    $PassInfoStr = ""
    if ($isElevated) {
        try {
            $SecEditFile = Join-Path $env:TEMP "secpol_$([guid]::NewGuid().ToString('N')).cfg"
            secedit /export /cfg $SecEditFile /quiet | Out-Null
            if (Test-Path $SecEditFile) {
                $SecPol = Get-Content $SecEditFile
                if ($SecPol -match "PasswordComplexity\s*=\s*1") { $PassComplexSel = "Yes"; $PassInfoStr += "Complexity: Enabled. " }
                elseif ($SecPol -match "PasswordComplexity\s*=\s*0") { $PassComplexSel = "No"; $PassInfoStr += "Complexity: Disabled. " }
                if ($SecPol -match "MinimumPasswordLength\s*=\s*(\d+)") { $PassInfoStr += "Min Length: $($matches[1])." }
                Remove-Item $SecEditFile -ErrorAction SilentlyContinue
            }
        } catch { $PassInfoStr = "Could not verify local policy." }
    } else {
        $PassInfoStr = "(Elevation required to read policy.)"
    }

    # 3. BitLocker / TPM
    Write-Log "[-] Checking Encryption..."
    $TPM = $null
    try { $TPM = Get-Tpm -ErrorAction Stop } catch { Write-Log "TPM check skipped: $($_.Exception.Message)" }
    $BitLocker = if (Get-Command "Get-BitLockerVolume" -ErrorAction SilentlyContinue) { Get-BitLockerVolume -ErrorAction SilentlyContinue } else { $null }

    $BitLockerSel = "Select..."
    $BitLockerReason = ""
    $BitLockerStatus = "Not Encrypted"
    $C_Encrypted = $false
    if ($BitLocker -and ($BitLocker | Where-Object ProtectionStatus -EQ 'On')) {
        $BitLockerSel = "Yes"
        $BitLockerStatus = ($BitLocker | ForEach-Object { "$($_.MountPoint) [$($_.ProtectionStatus)]" }) -join ", "
        if ($BitLocker | Where-Object { $_.MountPoint -like "C:*" -and $_.ProtectionStatus -eq 'On' }) { $C_Encrypted = $true }
    } else {
        if ($IsVM) { $BitLockerSel = "N/A"; $BitLockerReason = "Virtual Machine" }
        else { $BitLockerSel = "No"; $BitLockerReason = "Physical Server - No Encryption Detected" }
    }

    $ChiroPath = "C:\Program Files\PSChiro"
    $ChiroInstalled = (Test-Path $ChiroPath)
    $ChiroEncryptedSel = if ($ChiroInstalled) { if ($C_Encrypted) { "Yes" } else { "No" } } else { "N/A" }

    # 4. Firewall & RDP
    Write-Log "[-] Auditing Network & RDP..."
    $Firewall = Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object Enabled -EQ $true
    $RDPReg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue

    $Shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @("IPC$","ADMIN$","C$","D$","E$") }
    $ShareList = if ($Shares) { "Shares: " + ($Shares.Name -join ", ") } else { "No Custom Shares" }

    $RDPVPNSel = "Select..."; $RDPMFASel = "Select..."; $RDPExternalSel = "Select..."; $RDPFailSel = "Select..."; $RDPFailCount = 0
    if ($RDPReg -and $RDPReg.fDenyTSConnections -ne 0) {
        $RDPStatus = "<span class='good'>Disabled</span>"
        $RDPVPNSel = "N/A"; $RDPMFASel = "N/A"; $RDPExternalSel = "N/A"; $RDPFailSel = "N/A"
    } else {
        $RDPStatus = "<span class='warning'>Enabled (Open)</span>"
        if ($isElevated) {
            $RDPFailures = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-30)} -MaxEvents 500 -ErrorAction SilentlyContinue
            $RDPFailCount = if ($RDPFailures) { @($RDPFailures).Count } else { 0 }
            $RDPFailSel = if ($RDPFailCount -gt 0) { "Yes" } else { "No" }
        } else {
            $RDPFailSel = "Select..."
        }
        $RDPExternalSel = "No"
    }

    $OpenPortsStr = ""
    try {
        $OpenPorts = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LocalPort -Unique | Sort-Object { [int]$_ }
        if ($OpenPorts) { $OpenPortsStr = "Open Ports: " + ($OpenPorts -join ", ") }
    } catch {}

    # 5. Logs & Hardware
    Write-Log "[-] Analyzing Logs & Health..."

    $SecurityLogInfo = Get-WinEvent -ListLog 'Security' -ErrorAction SilentlyContinue
    $LogSettings = if ($SecurityLogInfo) {
        [PSCustomObject]@{
            Log = 'Security'
            MaximumKilobytes = [math]::Round($SecurityLogInfo.MaximumSizeInBytes / 1KB, 0)
            IsEnabled = $SecurityLogInfo.IsEnabled
        }
    } else { $null }

    $Events = Get-WinEvent -FilterHashtable @{LogName='System','Application'; Level=1,2; StartTime=(Get-Date).AddDays(-$EventLookbackDays)} -MaxEvents $MaxEventsToShow -ErrorAction SilentlyContinue

    $AppErrors = Get-WinEvent -FilterHashtable @{LogName='Application'; Level=2; StartTime=(Get-Date).AddDays(-30)} -MaxEvents 1 -ErrorAction SilentlyContinue
    $AppErrorSel = if ($AppErrors) { "Yes" } else { "No" }

    # DB error scan - whitelist provider names instead of substring matching messages
    $DBProviderRegex = '^(MSSQLSERVER|MSSQL\$|SQLAgent|SQLBrowser|MySQL|MariaDB|OracleService|OracleOraDb|PostgreSQL)'
    $DBErrors = $null
    try {
        $recentApp = Get-WinEvent -FilterHashtable @{LogName='Application'; Level=1,2; StartTime=(Get-Date).AddDays(-30)} -MaxEvents 500 -ErrorAction SilentlyContinue
        if ($recentApp) {
            $DBErrors = $recentApp | Where-Object { $_.ProviderName -match $DBProviderRegex } | Select-Object -First 1
        }
    } catch { $DBErrors = $null }
    $DBErrorSel = if ($DBErrors) { "Yes" } else { "No" }

    # Disk health
    $Disks = Get-PhysicalDisk -ErrorAction SilentlyContinue | Select-Object FriendlyName, MediaType, HealthStatus
    $DiskHealthStr = if ($Disks) { ($Disks | ForEach-Object { "$($_.MediaType) ($($_.HealthStatus))" }) -join "; " } else { "Unknown" }

    $StorageWarning = ""
    try {
        $CDrive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction SilentlyContinue
        if ($CDrive -and $CDrive.Size -gt 0) {
            $FreePct = [math]::Round(($CDrive.FreeSpace / $CDrive.Size) * 100, 1)
            if ($FreePct -lt 15) { $StorageWarning = "Low Disk Space on C: ($FreePct% Free)" }
        }
    } catch {}

    $ClientNameVal = ""
    $LocationDefault = ""

    # --- Pre-render encoded values used in HTML ---
    $compNameEnc = HtmlEnc $CompInfo.Name
    $osCaptionEnc = HtmlEnc $OSInfo.Caption
    $osBuildEnc = HtmlEnc $OSInfo.BuildNumber
    $rolesValue = if ($IsDC) { "Domain Controller" + (if ($DetectedRoles) { " - $DetectedRoles" } else { "" }) } else { $DetectedRoles }

    $adminListHtml = if ($AdminGroup -and $AdminGroup.Count -gt 0) {
        ($AdminGroup | ForEach-Object { "<li>$(HtmlEnc $_.Name)</li>" }) -join ''
    } else { "<li><em>(none / could not enumerate)</em></li>" }

    $localUserListHtml = if ($IsDC) {
        "<li><em>$(HtmlEnc $LocalUsersNote)</em></li>"
    } elseif ($LocalUsers -and $LocalUsers.Count -gt 0) {
        ($LocalUsers | ForEach-Object {
            $tag = if ($_.Enabled) { '' } else { ' (disabled)' }
            "<li>$(HtmlEnc $_.Name)$(HtmlEnc $tag)</li>"
        }) -join ''
    } else {
        "<li><em>$(HtmlEnc $LocalUsersNote)</em></li>"
    }

    $disabledNoteHtml = if ($DisabledUsers -and $DisabledUsers.Count -gt 0) {
        "<br><small>Disabled: " + (HtmlEnc (($DisabledUsers.Name) -join ", ")) + "</small>"
    } else { "" }

    $eventTableHtml = if ($Events) {
        $rows = ($Events | ForEach-Object {
            $q = [uri]::EscapeDataString("Windows Event $($_.Id) $($_.ProviderName)")
            $msg = if ($_.Message) { $_.Message.Substring(0, [Math]::Min(80, $_.Message.Length)) } else { "(No message)" }
            "<tr><td>$(HtmlEnc $_.ProviderName)</td><td>$(HtmlEnc $_.Id)</td><td>$(HtmlEnc $msg)...</td><td><a href='https://www.google.com/search?q=$q' target='_blank' class='ai-link'>Ask AI</a></td></tr>"
        }) -join ''
        "<table style='font-size:0.9em; width:100%; border-collapse:collapse; border:1px solid #ddd;'><tr><th>Src</th><th>ID</th><th>Msg</th><th>Fix</th></tr>$rows</table>"
    } else { "None found." }

    $missingUpdatesUlContent = if ($MissingUpdatesHTML) { $MissingUpdatesHTML } else { "<li>None pending.</li>" }
    $secLogSizeMB = if ($LogSettings) { [math]::Round($LogSettings.MaximumKilobytes/1024,0) } else { 0 }

    $elevationBanner = if (-not $isElevated) {
        "<div style='background:#fff3cd; border:1px solid #ffe69c; color:#664d03; padding:10px; margin-bottom:15px; border-radius:4px;'><strong>Notice:</strong> This audit was generated without Administrator rights. Several fields (BitLocker, secedit policy, Security log queries, TPM) may be blank or incomplete.</div>"
    } else { "" }

    # --- HTML BODY ---
    $HTMLBody = @"
    $elevationBanner
    <div class='header-block'>
        <div style='display:flex; justify-content:space-between; align-items:flex-start;'>
            <div>
                <h1>Internal Server Security &amp; Backup Audit Form</h1>
                <div class='meta-info'>
                    <span>Client: $(Get-HtmlInput "Client Name" -Value $ClientNameVal)</span>
                    <span style='margin-left:20px;'>Audit Month: $(Get-HtmlInput "e.g. October" -Value "$(Get-Date -Format 'MMMM')")</span>
                    <span style='margin-left:20px;'>Completed By: $(HtmlEnc $env:USERNAME)</span>
                </div>
                <div style='margin-top:5px; font-size:0.85em; color:#666;'>Uptime: $(HtmlEnc $UptimeStr)</div>
            </div>
            <button onclick="copyReport()" class="copy-btn">Copy to Clipboard</button>
        </div>
    </div>

    <h3>Server Identifying Information</h3>
    <table>
        <tr><th>Server Name</th><td>$compNameEnc</td></tr>
        <tr><th>Location (onsite/offsite)</th><td>$(Get-HtmlInput "e.g., Server Closet" -Value $LocationDefault)</td></tr>
        <tr><th>OS Version</th><td>$osCaptionEnc (Build $osBuildEnc) $EOSWarning</td></tr>
        <tr><th>Role(s)</th><td>$(Get-HtmlInput "e.g., DC, Database" -Value $rolesValue)</td></tr>
        <tr><th>Who has administrative access?</th><td><ul>$adminListHtml</ul></td></tr>
    </table>

    <h2>1. Backup &amp; Data Retention (HIPAA &#167;164.308(a)(7))</h2>
    <h3>A. Backup System Review</h3>
    <table>
        <tr><th>Backup solution used</th><td>
            $(Get-HtmlSelect -Options $BackupOptions -OnChange "updateBackupDefaults(this)")
            <br><small>Select to auto-fill encryption defaults.</small>
        </td></tr>
        <tr><th>Are backups completing successfully?</th><td>
            $(Get-HtmlSelect @("Select...","Yes","No","N/A") -SelectedValue $BackupSuccessSel)
            $(if ($BackupSummary) { "<br><small>" + (HtmlEnc $BackupSummary) + "</small>" })
        </td></tr>
        <tr><th>Last successful backup date &amp; time</th><td>$(Get-HtmlInput "YYYY-MM-DD HH:MM" -Value $LastBackupTime)</td></tr>
        <tr><th>Backup frequency (hourly/daily)</th><td>$(Get-HtmlInput "e.g., Hourly")</td></tr>
        <tr><th>Are there any failed backups this month?</th><td>$(Get-HtmlSelect @("Select...","Yes","No","N/A") -SelectedValue $BackupFailedSel)</td></tr>
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
        <tr><th>Does retention meet HIPAA's 6-year requirement?</th><td>$(Get-HtmlSelect)</td></tr>
    </table>

    <h3>D. Restore Testing</h3>
    <table>
        <tr><th>Was a test restore performed in the last 90 days?</th><td>$(Get-HtmlSelect)</td></tr>
        <tr><th>Date of last verification restore</th><td>$(Get-HtmlInput "YYYY-MM-DD")</td></tr>
        <tr><th>Result</th><td>$(Get-HtmlInput "Successful / Issues found")</td></tr>
    </table>

    <h2>2. Server Security &amp; Patch Compliance</h2>
    <h3>A. Update Status</h3>
    <table>
        <tr><th>Are Windows Updates current?</th><td>$(if($MissingUpdatesCount -eq 0){"<span class='good'>Yes</span>"}else{"<span class='alert'>No ($MissingUpdatesCount Pending)</span>"}) $UpdateNote</td></tr>
        <tr><th>Last update date</th><td>$(Get-HtmlInput "Check Update History" -Value $LastUpdateDate)</td></tr>
        <tr><th>Pending patches?</th><td><ul>$missingUpdatesUlContent</ul></td></tr>
    </table>

    <h3>B. Antivirus / EDR</h3>
    <table>
        <tr><th>AV/EDR installed</th><td>$(if($AV){HtmlEnc $AV.displayName}else{"<span class='alert'>None Detected</span>"})</td></tr>
        <tr><th>Real-time protection enabled?</th><td>$(Get-HtmlSelect @("Select...","Yes","No","N/A") -SelectedValue $RTPEnabled)</td></tr>
        <tr><th>Last scan date</th><td>$(Get-HtmlInput "YYYY-MM-DD" -Value $LastScanDate)</td></tr>
        <tr><th>Any detections this month?</th><td>$(Get-HtmlSelect) $(Get-HtmlInput "Attach or summarize if yes")</td></tr>
    </table>

    <h3>C. Local User Accounts</h3>
    <table>
        <tr><th>List all local server accounts</th><td><ul>$localUserListHtml</ul></td></tr>
        <tr><th>Any accounts without MFA?</th><td>$(Get-HtmlSelect)</td></tr>
        <tr><th>Any disabled but unremoved accounts?</th><td>$(Get-HtmlSelect @("Select...","Yes","No","N/A") -SelectedValue $DisabledUsersSel) $disabledNoteHtml</td></tr>
        <tr><th>Any unexpected accounts?</th><td>$(Get-HtmlSelect) $(Get-HtmlInput "Document if yes")</td></tr>
    </table>

    <h3>D. Administrator Access</h3>
    <table>
        <tr><th>Who has administrative credentials</th><td>(See Server Info Header)</td></tr>
        <tr><th>Are admin passwords changed regularly?</th><td>$(Get-HtmlSelect @("Select...","Yes","No","N/A") -SelectedValue $AdminPassChangedRegularly) <br><small>Last Set: $(HtmlEnc $AdminPassLastSet)$(HtmlEnc $AdminEnabledNote)</small></td></tr>
        <tr><th>Is password complexity enforced?</th><td>$(Get-HtmlSelect @("Select...","Yes","No","N/A") -SelectedValue $PassComplexSel) <small>$(HtmlEnc $PassInfoStr)</small></td></tr>
        <tr><th>Are there any shared admin accounts?</th><td>$(Get-HtmlSelect) $(Get-HtmlInput "Document if yes")</td></tr>
    </table>

    <h2>3. Server Encryption (HIPAA &#167;164.312(a)(2)(iv))</h2>
    <h3>A. Disk Encryption</h3>
    <table>
        <tr><th>Is full-disk encryption enabled?</th><td>
            $(Get-HtmlSelect @("Select...","Yes","No","N/A") -SelectedValue $BitLockerSel)
            $(if(-not $BitLocker){"<span class='warning'>(BitLocker cmdlets not available)</span>"})
        </td></tr>
        <tr><th>Encryption status</th><td>$(Get-HtmlInput "e.g. Encrypted" -Value $BitLockerStatus)</td></tr>
        <tr><th>TPM present/enabled</th><td>$(if($TPM -and $TPM.TpmPresent){"Yes"}else{"No"})</td></tr>
        <tr><th>If not encrypted, reason why</th><td>$(Get-HtmlInput "Reason..." -Value $BitLockerReason)</td></tr>
    </table>
    <h3>B. Data Encryption</h3>
    <table>
        <tr><th>Are ChiroTouch data files stored in encrypted form?</th><td>$(Get-HtmlSelect @("Select...","Yes","No","N/A") -SelectedValue $ChiroEncryptedSel)</td></tr>
        <tr><th>Are database backups encrypted?</th><td>$(Get-HtmlSelect)</td></tr>
    </table>

    <h2>4. Server Firewall &amp; Network Security (HIPAA &#167;164.312(e))</h2>
    <h3>A. Local Firewall</h3>
    <table>
        <tr><th>Windows Firewall enabled?</th><td>$(if($Firewall){"Yes (Profiles: " + (HtmlEnc ($Firewall.Name -join ', ')) + ")"}else{"<span class='alert'>No</span>"})</td></tr>
        <tr><th>Inbound rule review</th><td>$(Get-HtmlInput "List allowed inbound ports" -Value "$OpenPortsStr | $ShareList")</td></tr>
        <tr><th>Outbound rule review</th><td>$(Get-HtmlInput "Confirm non-essential ports blocked")</td></tr>
    </table>
    <h3>B. Remote Access</h3>
    <table>
        <tr><th>Does anyone RDP to the server?</th><td>Config Status: $RDPStatus $(Get-HtmlSelect)</td></tr>
        <tr><th>Is RDP protected by VPN?</th><td>$(Get-HtmlSelect @("Select...","Yes","No","N/A") -SelectedValue $RDPVPNSel)</td></tr>
        <tr><th>MFA required?</th><td>$(Get-HtmlSelect @("Select...","Yes","No","N/A") -SelectedValue $RDPMFASel)</td></tr>
        <tr><th>External RDP open to internet?</th><td>$(Get-HtmlSelect @("Select...","Yes","No","N/A") -SelectedValue $RDPExternalSel) (Should be No)</td></tr>
        <tr><th>Any failed RDP attempts this month?</th><td>$(Get-HtmlSelect @("Select...","Yes","No","N/A") -SelectedValue $RDPFailSel) <small>(Detected: $RDPFailCount)</small></td></tr>
    </table>

    <h2>5. Server Monitoring &amp; Logs (HIPAA &#167;164.312(b))</h2>
    <h3>A. Event Logs</h3>
    <table>
        <tr><th>Security logs enabled?</th><td>$(if($LogSettings){"Yes"}else{"Unknown"})</td></tr>
        <tr><th>Retention period (in days)</th><td>$(Get-HtmlInput "Check Log Properties") (Size Limit: $secLogSizeMB MB)</td></tr>
        <tr><th>Any critical events found this month?</th><td>$eventTableHtml</td></tr>
    </table>
    <h3>B. Application Logs</h3>
    <table>
        <tr><th>Any application errors?</th><td>$(Get-HtmlSelect @("Select...","Yes","No","N/A") -SelectedValue $AppErrorSel) $(Get-HtmlInput "Describe..." -Value "See critical events above if Yes")</td></tr>
        <tr><th>Any database errors?</th><td>$(Get-HtmlSelect @("Select...","Yes","No","N/A") -SelectedValue $DBErrorSel) $(Get-HtmlInput "Describe...")</td></tr>
        <tr><th>Any performance concerns logged?</th><td>$(Get-HtmlInput "Describe...")</td></tr>
    </table>
    <h3>C. Huntress / EDR Logs</h3>
    <table>
        <tr><th>Any incidents detected on the server?</th><td>$(Get-HtmlSelect) $(Get-HtmlInput "Attach if yes")</td></tr>
    </table>

    <h2>6. Physical Security (HIPAA &#167;164.310)</h2>
    <h3>A. Server Location</h3>
    <table>
        <tr><th>Where is the server physically located?</th><td>$(Get-HtmlInput "closet, office, rack")</td></tr>
        <tr><th>Is the room locked?</th><td>$(Get-HtmlSelect)</td></tr>
        <tr><th>Who has physical access?</th><td>$(Get-HtmlInput "List roles/people")</td></tr>
        <tr><th>Any environmental risks?</th><td>$(Get-HtmlInput "Heat, water, unlocked room")</td></tr>
    </table>

    <h2>7. Contingency &amp; Failover (HIPAA &#167;164.308(a)(7)(ii)(C))</h2>
    <h3>A. Disaster Recovery</h3>
    <table>
        <tr><th>If the server failed, how would it be restored?</th><td>$(Get-HtmlInput "Method...")</td></tr>
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
            <td>$(Get-HtmlSelect @("Low","Moderate","High"))</td>
            <td>$(Get-HtmlSelect @("Jeremy Bean IT","Client"))</td>
            <td>$(Get-HtmlSelect @("Planned","In Progress","Not Scheduled"))</td>
        </tr>
        <tr><td colspan="5"><strong>Notes:</strong> $(Get-HtmlInput "Additional Notes")</td></tr>
    </table>

    <button onclick="copyReport()" class="copy-btn floating-action">Copy Report for Ticket</button>
"@

    if ([string]::IsNullOrWhiteSpace($HTMLBody)) { Write-Log "Error: HTML Body is empty!" }

    $HTMLPage = "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Security Audit Report</title>$style</head><body>$HTMLBody</body></html>"

    # Write UTF-8 without BOM, with TEMP fallback if write to Desktop fails
    $writeOk = $false
    try {
        [System.IO.File]::WriteAllText($ReportPath, $HTMLPage, (New-Object System.Text.UTF8Encoding($false)))
        $writeOk = $true
    } catch {
        Write-Log "Failed to write report to ${ReportPath}: $($_.Exception.Message). Falling back to TEMP."
        $ReportPath = Join-Path -Path $env:TEMP -ChildPath (Split-Path -Leaf $ReportPath)
        try {
            [System.IO.File]::WriteAllText($ReportPath, $HTMLPage, (New-Object System.Text.UTF8Encoding($false)))
            $writeOk = $true
        } catch {
            Write-Log "Failed to write report to TEMP: $($_.Exception.Message)"
        }
    }

    if ($writeOk) {
        Write-Log "Report generated at: $ReportPath"
        try { Write-Log "Report Size: $((Get-Item $ReportPath).Length) bytes" } catch {}
        try { Invoke-Item $ReportPath } catch { Write-Log "Could not auto-open report: $($_.Exception.Message)" }
    }
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
    Write-Host '5) Security Audit'
    Write-Host '6) Diagnostics / Triage'
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

# --- Entry ---
Write-Log '=== WinFix Console Started ==='
Write-Log "Computer: $env:COMPUTERNAME"
Write-Log "User: $env:USERNAME"

if ($TaskName) {
    $exitCode = 0
    try {
        Invoke-Task -Name $TaskName -Args $TaskArgs
    } catch {
        Write-Log "UNHANDLED TASK ERROR ($TaskName): $_"
        $exitCode = 1
    } finally {
        Pause-Window
    }
    exit $exitCode
}

while ($true) {
    Show-MainMenu
    $choice = Read-Choice

    switch ($choice.ToUpperInvariant()) {
        '1' { Start-TaskWindow -Name 'Dashboard' }
        '2' { Menu-Maintenance }
        '3' { Menu-Network }
        '4' { Menu-UsersShares }
        '5' { Start-TaskWindow -Name 'SecurityAudit' }
        '6' { Menu-Diagnostics }
        'L' { Open-LogFile }
        'T' { Start-TaskWindow -Name 'TailLog' }
        'E' { Start-TaskWindow -Name 'ExportBundle' }
        'Q' { break }
        'QUIT' { break }
        'EXIT' { break }
        default { }
    }
}

Write-Log '=== WinFix Console Exiting ==='
