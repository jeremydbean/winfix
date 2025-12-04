# WinFix Tool & Security Audit

Windows system maintenance and security audit tool with NinjaOne RMM integration.

## 🚀 Quick Start - One Line Install

**Copy and paste this into PowerShell:**

```powershell
irm https://raw.githubusercontent.com/jeremydbean/winfix/main/install.ps1 | iex
```

✅ Automatically requests admin privileges  
✅ No installation required  
✅ No prerequisites needed  
✅ Works on any Windows 10/11 or Server 2016+

---

## Features

*   **Common Fixes**:
    *   Free up disk space (cleans Temp folders and Recycle Bin).
    *   Disable Sleep & Hibernate (optimizes power settings for servers/always-on PCs).
    *   Fix Network (Resets TCP/IP stack, Winsock, and flushes DNS).
    *   Run System File Checker (SFC).
    *   **DISM Repair Image** (Restores Windows image health).
    *   **Reset Windows Update** (Clears cache and restarts services).
    *   **Clear Print Spooler** (Fixes stuck print jobs).
    *   **Restart Explorer** (Quickly restarts the shell).
    *   **Sync System Time** (Forces time synchronization).
    *   **Run Microsoft Activation Scripts (MAS)** (Launches the MAS activator).
    *   **Download & Run SpaceMonger** (Downloads and runs the classic disk usage visualization tool).
*   **System Info**:
    *   Get System Specs (OS, RAM, Model, etc.).
    *   List Printers.
    *   List Installed Software.
*   **Network Tools**:
    *   Show IP Configuration.
    *   Quick Network Scan (ARP table).
    *   Test Internet Connection (Ping).
*   **Security Audit**:
    *   Generates the interactive HTML report for the Monthly Security Audit.
*   **Integrations**:
    *   **NinjaOne API**: Connect to your NinjaOne instance to automatically pull device data (Patch status, AV status, Backup status) into the Security Audit.
    *   **Smart Local Detection**: Automatically detects the local NinjaRMM agent ID from the registry for accurate device matching.

## Troubleshooting

If you encounter issues (e.g., API connection failures), the tool now generates a debug log.
*   **Log Location**: `%TEMP%\WinFix_Debug.log`
*   **View Log**: Click the **"Open Log"** button in the bottom-right corner of the tool to view the log file instantly.

## Quick Start (One-Line Install)

**Paste this into PowerShell (automatically requests admin):**

```powershell
irm https://raw.githubusercontent.com/jeremydbean/winfix/main/install.ps1 | iex
```

This will:
1. Request Administrator privileges automatically
2. Download `WinFixTool.ps1` to a temp directory
3. Launch the GUI immediately
4. Clean up temporary files when closed

**That's it!** No installation, no prerequisites, just paste and run.

## Manual Build & Run

1.  Clone or download this repository.
2.  Double-click **`Build_and_Run.bat`**.
3.  Accept the Administrator prompt (required to install the compiler module).
4.  Wait for the process to finish.
5.  The tool will launch automatically, and you will find `WinFixTool.exe` in the folder, ready to be uploaded to Google Drive.

## How to Run (PowerShell)

**Method 1: Right-Click (Easiest)**
1.  Right-click `WinFixTool.ps1`.
2.  Select **Run with PowerShell**.
3.  If prompted for Administrator privileges, click **Yes**.

**Method 2: Terminal**
Open PowerShell as Administrator, navigate to the folder, and run:
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
.\WinFixTool.ps1
```

**Note on SpaceMonger**:
The "Download & Run SpaceMonger" feature requires an active internet connection to fetch the executable from GitHub if it is not already present in your Temp folder.

## How to Create a Standalone EXE

To distribute this tool as a single `.exe` file (e.g., via Google Drive), you can compile the PowerShell script using the popular `PS2EXE` module.

### Step 1: Install PS2EXE
Open PowerShell as Administrator and run:
```powershell
Install-Module -Name ps2exe -Scope CurrentUser
```

### Step 2: Compile the Script
Run the following command to create the EXE:

```powershell
Invoke-PS2EXE -InputFile ".\WinFixTool.ps1" -OutputFile ".\WinFixTool.exe" -Icon "" -Title "WinFix Tool" -Version "1.0" -noConsole
```

*   `-noConsole`: Hides the background console window so only the GUI appears.
*   You can add a custom icon by providing a path to an `.ico` file with the `-Icon` parameter.

### Step 3: Distribute
You can now upload `WinFixTool.exe` to Google Drive or a USB drive. It will run on any modern Windows machine without needing to install scripts or modules.

## Requirements
*   Windows 10, Windows 11, or Windows Server 2016+.
*   PowerShell 5.1 (Default on Windows).
*   **Administrator Privileges** are required for most fixes.
