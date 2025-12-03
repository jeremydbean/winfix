# WinFix - Windows PC Repair Tool

A comprehensive standalone Windows repair utility that performs common PC maintenance and repair tasks organized by tier of seriousness.

## Features

### Tier 1: Critical System Repairs
- **System File Checker (SFC)**: Scans and repairs corrupted Windows system files
- **DISM Repair**: Checks and restores Windows system image health
- **Disk Check (CHKDSK)**: Schedules disk integrity check on next reboot

### Tier 2: Important Repairs & Maintenance
- **Disk Space Cleanup**: Automatically cleans temporary files, cache, and prefetch data
- **Network Reset**: Resets network adapters, TCP/IP stack, and DNS cache

### Tier 3: Utilities & Information
- **WiFi Password Export**: Exports all saved WiFi SSIDs and passwords to a text file
- **System Audit**: Generates comprehensive system information report
- **Install Common Tools**: Provides links to download useful diagnostic and repair utilities

## Requirements

- Windows 7 or later
- Administrator privileges (required for most operations)
- Python 3.6+ (for development and building)

## Usage

### Using the Pre-built Executable

1. Download `WinFix.exe` from the releases or Google Drive link
2. **Right-click** on `WinFix.exe` and select **"Run as administrator"**
3. Select the tier of repairs you need:
   - **Tier 1** for critical system issues
   - **Tier 2** for performance and connectivity problems
   - **Tier 3** for information gathering and utilities
4. Follow the on-screen prompts
5. Restart your computer when prompted to apply changes

### Output Locations

The tool creates the following folders in your user directory:
- `%USERPROFILE%\WinFix_Logs` - Operation logs
- `%USERPROFILE%\WinFix_WiFi_Export` - Exported WiFi passwords
- `%USERPROFILE%\WinFix_System_Audit` - System audit reports

## Building from Source

### Prerequisites

Install Python 3.6 or later and pip, then install PyInstaller:

```bash
pip install pyinstaller
```

### Build Instructions

1. Clone the repository:
```bash
git clone https://github.com/jeremydbean/winfix.git
cd winfix
```

2. Build the standalone executable:
```bash
pyinstaller winfix.spec
```

3. The executable will be created in the `dist` folder:
```
dist/WinFix.exe
```

### Alternative Build Command

If you don't want to use the spec file:

```bash
pyinstaller --onefile --name WinFix --uac-admin --console winfix.py
```

## Deployment to Google Drive

1. Build the executable using the instructions above
2. Upload `dist/WinFix.exe` to your Google Drive
3. Right-click the file and select "Get shareable link"
4. Set permissions to "Anyone with the link can view"
5. Share the link with users who need the tool

### Recommended Google Drive Folder Structure

```
WinFix/
├── WinFix.exe (latest version)
├── README.txt (usage instructions)
└── versions/
    ├── WinFix_v1.0.exe
    └── WinFix_v1.1.exe
```

## Important Notes

- **Always run as administrator** - Most repair operations require elevated privileges
- **Some operations require a restart** - Particularly Tier 1 repairs
- **Backup your data** - Before performing system repairs
- **Antivirus warnings** - Some antivirus software may flag the executable as suspicious because it requests admin privileges and modifies system settings. This is normal for system repair tools.

## Security Considerations

- This tool only uses Windows built-in commands
- No external network connections are made (except when you manually visit tool download links)
- All operations are logged to the `WinFix_Logs` folder
- Source code is open for inspection

## Troubleshooting

### "Administrator privileges required" error
- Right-click the executable and select "Run as administrator"
- Make sure you're logged in with an administrator account

### Operations fail or show warnings
- Check the log files in `%USERPROFILE%\WinFix_Logs`
- Some operations may fail if files are in use - try closing other applications
- Restart your computer and try again

### Antivirus blocks the executable
- Add an exception for WinFix.exe in your antivirus software
- Verify the file is from a trusted source
- Build from source yourself to ensure authenticity

## License

This project is open source and available for personal and educational use.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## Disclaimer

This tool is provided "as-is" without warranty. Always backup your important data before performing system repairs. The authors are not responsible for any data loss or system issues that may occur from using this tool.
