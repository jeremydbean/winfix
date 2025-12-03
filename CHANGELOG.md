# Changelog

All notable changes to WinFix will be documented in this file.

## [1.0.0] - 2025-12-03

### Added
- Initial release of WinFix Windows PC Repair Tool
- Tier 1 Critical System Repairs:
  - System File Checker (sfc /scannow)
  - DISM repair commands (CheckHealth, ScanHealth, RestoreHealth)
  - Schedule disk check (CHKDSK) on next reboot
- Tier 2 Important Repairs & Maintenance:
  - Disk space cleanup (temp files, cache, prefetch folders)
  - Network reset (IP, DNS, Winsock, TCP/IP stack)
- Tier 3 Maintenance & Utilities:
  - WiFi password export functionality
  - Comprehensive system audit reporting
  - Install common tools information
- Interactive menu system organized by tier
- Logging system for all operations
- Administrator privilege checking
- PyInstaller configuration for standalone .exe build
- Comprehensive documentation:
  - README.md with full documentation
  - USAGE.md for end users
  - Build script for easy compilation
- GitHub Actions workflow for automated builds
- Test suite for basic functionality verification

### Security
- All operations logged for audit trail
- Specific exception handling to avoid information leakage
- Admin privilege enforcement
- No external dependencies or network connections

## [Unreleased]

### Planned Features
- GUI interface option
- Scheduled task creation for automated maintenance
- More granular disk cleanup options
- Driver update checking
- Windows Update troubleshooting
- Performance optimization tools
- Malware scan integration
- System restore point creation
