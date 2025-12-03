# WinFix - Quick Start Guide

## What is WinFix?

WinFix is a Windows PC repair tool that helps you fix common computer problems. It's organized by how serious the problem is (tiers).

## How to Use

### Step 1: Download
Download `WinFix.exe` from the provided link (Google Drive or GitHub).

### Step 2: Run as Administrator
**IMPORTANT**: You MUST run as administrator or it won't work!

1. Find the downloaded `WinFix.exe` file
2. **Right-click** on it
3. Select **"Run as administrator"**
4. Click **"Yes"** when Windows asks for permission

### Step 3: Choose What You Need

The program shows a menu with different repair options:

#### TIER 1 - Critical System Repairs
Use these if your computer has serious problems:
- **System File Checker**: Fixes corrupted Windows files (takes 10-30 minutes)
- **DISM Repair**: Repairs Windows system image (takes 15-45 minutes)
- **Schedule Disk Check**: Checks your hard drive for errors (runs on restart)

⚠️ **Warning**: Tier 1 repairs take time and may require restarting your computer.

#### TIER 2 - Important Repairs & Maintenance
Use these for common problems:
- **Clean Disk Space**: Removes temporary files to free up space
- **Reset Network**: Fixes internet and WiFi connection problems

#### TIER 3 - Utilities & Information
Helpful tools and information:
- **Export WiFi Passwords**: Saves all your WiFi passwords to a text file
- **System Audit**: Creates a detailed report about your computer
- **Install Common Tools**: Shows you useful programs you can download

## Where to Find Results

WinFix creates folders in your user directory:

- **Logs**: `C:\Users\YourName\WinFix_Logs`
- **WiFi Passwords**: `C:\Users\YourName\WinFix_WiFi_Export`
- **System Reports**: `C:\Users\YourName\WinFix_System_Audit`

## Tips

1. **Start with Tier 2** if you're not sure what's wrong
2. **Run Tier 1** only if you have serious system problems
3. **Close other programs** before running repairs
4. **Backup important files** before using Tier 1 repairs
5. **Restart your computer** after running repairs

## Common Issues

### "Administrator privileges required"
- You didn't run as administrator
- Right-click and select "Run as administrator"

### Antivirus blocks WinFix
- This is normal for system repair tools
- Add an exception in your antivirus
- Make sure you downloaded from a trusted source

### Repairs take a long time
- This is normal, especially for Tier 1 repairs
- Be patient and don't close the program
- Some repairs can take 30+ minutes

### Nothing seems to work
- Try restarting your computer first
- Run Tier 2 "Reset Network" if it's an internet problem
- Check the log files in WinFix_Logs folder

## Need More Help?

1. Check the log files in `WinFix_Logs` folder
2. Read the full README.md for detailed information
3. Contact your IT support person

## Safety

- WinFix only uses built-in Windows tools
- It doesn't connect to the internet (except to show tool links)
- All actions are logged
- It won't delete your personal files

---

**Remember**: Always run as administrator and be patient with repairs!
