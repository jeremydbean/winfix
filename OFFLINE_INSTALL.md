# WinFix Tool - Offline Installation Guide

## Problem
The Windows server has **no internet access**, so the build script cannot download PS2EXE from PowerShell Gallery.

## Solutions

### Option 1: Run Directly (Recommended for Offline)
**No compilation needed. Works immediately.**

```batch
Run_Direct.bat
```

This launches the PowerShell script directly with admin privileges. No internet required.

---

### Option 2: Use VBS Wrapper
If `Build_and_Run.bat` fails due to missing PS2EXE, it automatically creates `WinFixTool_Wrapper.vbs`.

**Double-click:** `WinFixTool_Wrapper.vbs`

This launches the PS1 script silently in the background.

---

### Option 3: Manual PowerShell Launch
Open PowerShell as Administrator and run:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
cd C:\path\to\winfix
.\WinFixTool.ps1
```

---

### Option 4: Pre-Install PS2EXE (From Machine with Internet)

1. On a machine **with internet**, download PS2EXE:
   ```powershell
   Install-Module -Name ps2exe -Scope CurrentUser -Force
   ```

2. Copy the module to the offline machine:
   - **Source:** `C:\Users\<YourUser>\Documents\WindowsPowerShell\Modules\ps2exe`
   - **Destination (Offline):** `C:\Users\Administrator\Documents\WindowsPowerShell\Modules\ps2exe`

3. Run `Build_and_Run.bat` on the offline machine - it will now work!

---

### Option 5: Manual PS2EXE Download
1. Download PS2EXE manually from GitHub: https://github.com/MScholtes/PS2EXE/releases
2. Extract to: `C:\Users\Administrator\Documents\WindowsPowerShell\Modules\ps2exe\`
3. Run `Build_and_Run.bat`

---

## Recommended Workflow for Offline Environments

1. **Development**: Use a machine with internet to test and compile
2. **Copy Files**: Transfer these to the offline server:
   - `WinFixTool.exe` (if pre-compiled)
   - OR `WinFixTool.ps1` + `Run_Direct.bat`
3. **Deploy**: Run the executable or use `Run_Direct.bat`

---

## Files Included

| File | Purpose | Requires Internet? |
|------|---------|-------------------|
| `WinFixTool.ps1` | Main PowerShell script | ❌ No |
| `Run_Direct.bat` | Launch PS1 directly | ❌ No |
| `Build_and_Run.bat` | Compile to EXE and run | ✅ Yes (first time only) |
| `WinFixTool_Wrapper.vbs` | VBS launcher (auto-created) | ❌ No |

---

## Current Error Explained

```
Install-Module : NuGet provider is required to interact with NuGet-based repositories.
```

**Cause:** PowerShell cannot download the NuGet provider because:
- No internet connection
- Firewall blocking `https://go.microsoft.com/fwlink/?LinkID=627338`
- Proxy not configured

**Solution:** Use `Run_Direct.bat` instead of compiling to EXE.
