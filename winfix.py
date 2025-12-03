#!/usr/bin/env python3
"""
WinFix - Windows PC Repair Tool
A comprehensive utility for common Windows PC repairs and maintenance tasks.
"""

import subprocess
import sys
import os
import json
import ctypes
import shutil
from pathlib import Path
from datetime import datetime


def is_admin():
    """Check if the script is running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def request_admin():
    """Request administrator privileges."""
    if not is_admin():
        print("\n" + "="*70)
        print("ADMINISTRATOR PRIVILEGES REQUIRED")
        print("="*70)
        print("This tool requires administrator privileges to run properly.")
        print("Please right-click the executable and select 'Run as administrator'")
        print("="*70)
        input("\nPress Enter to exit...")
        sys.exit(1)


def run_command(command, shell=True, capture_output=False):
    """Execute a system command with proper error handling."""
    try:
        if capture_output:
            result = subprocess.run(
                command,
                shell=shell,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore'
            )
            return result
        else:
            result = subprocess.run(command, shell=shell)
            return result
    except Exception as e:
        print(f"Error executing command: {e}")
        return None


def log_action(action, status="SUCCESS"):
    """Log actions to a file."""
    log_dir = Path.home() / "WinFix_Logs"
    log_dir.mkdir(exist_ok=True)
    log_file = log_dir / f"winfix_{datetime.now().strftime('%Y%m%d')}.log"
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"[{timestamp}] {action} - {status}\n"
    
    try:
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(log_entry)
    except Exception as e:
        print(f"Warning: Could not write to log file: {e}")


def clear_screen():
    """Clear the console screen."""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_header(title):
    """Print a formatted header."""
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70 + "\n")


def print_separator():
    """Print a separator line."""
    print("-" * 70)


# ============================================================================
# TIER 1: CRITICAL SYSTEM REPAIRS
# ============================================================================

def run_sfc_scan():
    """Run System File Checker scan."""
    print_header("TIER 1: System File Checker")
    print("Running System File Checker (sfc /scannow)...")
    print("This may take 10-30 minutes. Please be patient.\n")
    
    log_action("Starting SFC Scan")
    result = run_command("sfc /scannow")
    
    if result and result.returncode == 0:
        log_action("SFC Scan completed", "SUCCESS")
        print("\n✓ System File Checker completed successfully.")
    else:
        log_action("SFC Scan completed with errors", "WARNING")
        print("\n⚠ System File Checker completed with warnings. Check the log.")
    
    input("\nPress Enter to continue...")


def run_dism_repair():
    """Run DISM repair commands."""
    print_header("TIER 1: DISM System Repair")
    
    commands = [
        ("Checking system health...", "DISM /Online /Cleanup-Image /CheckHealth"),
        ("Scanning system health...", "DISM /Online /Cleanup-Image /ScanHealth"),
        ("Restoring system health...", "DISM /Online /Cleanup-Image /RestoreHealth")
    ]
    
    for description, command in commands:
        print(f"\n{description}")
        log_action(f"DISM: {description}")
        result = run_command(command)
        
        if result and result.returncode == 0:
            print(f"✓ {description} completed successfully.")
            log_action(f"DISM: {description}", "SUCCESS")
        else:
            print(f"⚠ {description} completed with warnings.")
            log_action(f"DISM: {description}", "WARNING")
    
    print("\n✓ DISM repair sequence completed.")
    input("\nPress Enter to continue...")


def run_chkdsk_schedule():
    """Schedule a Check Disk scan on next reboot."""
    print_header("TIER 1: Schedule Disk Check")
    print("This will schedule a disk check on your system drive (C:) at next reboot.")
    print("The disk check will run before Windows starts.\n")
    
    confirm = input("Do you want to schedule a disk check? (y/n): ").strip().lower()
    
    if confirm == 'y':
        log_action("Scheduling CHKDSK")
        result = run_command("echo y | chkdsk C: /f /r /x")
        print("\n✓ Disk check scheduled for next reboot.")
        print("Your computer will need to restart to perform the disk check.")
        log_action("CHKDSK scheduled", "SUCCESS")
    else:
        print("\nDisk check cancelled.")
    
    input("\nPress Enter to continue...")


# ============================================================================
# TIER 2: IMPORTANT REPAIRS AND MAINTENANCE
# ============================================================================

def clean_disk_space():
    """Clean common locations that fill up quickly."""
    print_header("TIER 2: Disk Space Cleanup")
    
    locations = [
        (Path(os.environ.get('TEMP', '')), "Windows Temp folder"),
        (Path(os.environ.get('TMP', '')), "User Temp folder"),
        (Path(os.environ.get('SystemRoot', 'C:\\Windows')) / 'Temp', "System Temp folder"),
        (Path(os.environ.get('SystemRoot', 'C:\\Windows')) / 'Prefetch', "Prefetch folder"),
        (Path(os.environ.get('LOCALAPPDATA', '')) / 'Microsoft' / 'Windows' / 'INetCache', "IE Cache"),
    ]
    
    total_freed = 0
    
    print("Scanning and cleaning temporary files...\n")
    
    for location, description in locations:
        if not location.exists():
            continue
        
        try:
            # Calculate size before cleaning
            size_before = sum(f.stat().st_size for f in location.rglob('*') if f.is_file())
            size_before_mb = size_before / (1024 * 1024)
            
            print(f"Cleaning {description}...")
            print(f"  Location: {location}")
            print(f"  Size before: {size_before_mb:.2f} MB")
            
            # Clean the directory
            for item in location.iterdir():
                try:
                    if item.is_file():
                        item.unlink()
                    elif item.is_dir():
                        shutil.rmtree(item, ignore_errors=True)
                except Exception as e:
                    # Skip files in use
                    pass
            
            # Calculate size after cleaning
            size_after = sum(f.stat().st_size for f in location.rglob('*') if f.is_file())
            size_after_mb = size_after / (1024 * 1024)
            freed_mb = size_before_mb - size_after_mb
            total_freed += freed_mb
            
            print(f"  Size after: {size_after_mb:.2f} MB")
            print(f"  Freed: {freed_mb:.2f} MB")
            print(f"  ✓ Completed\n")
            
            log_action(f"Cleaned {description}: {freed_mb:.2f} MB freed")
            
        except Exception as e:
            print(f"  ⚠ Error cleaning {description}: {e}\n")
            log_action(f"Error cleaning {description}", "ERROR")
    
    # Run Windows Disk Cleanup utility
    print("Running Windows Disk Cleanup utility...")
    log_action("Running Disk Cleanup utility")
    run_command("cleanmgr /sagerun:1")
    
    print(f"\n✓ Disk cleanup completed. Total space freed: {total_freed:.2f} MB")
    log_action(f"Disk cleanup completed: {total_freed:.2f} MB total", "SUCCESS")
    
    input("\nPress Enter to continue...")


def reset_network():
    """Reset network settings."""
    print_header("TIER 2: Network Reset")
    print("This will reset network adapters and TCP/IP stack.\n")
    
    commands = [
        ("Releasing IP address...", "ipconfig /release"),
        ("Flushing DNS cache...", "ipconfig /flushdns"),
        ("Renewing IP address...", "ipconfig /renew"),
        ("Resetting Winsock catalog...", "netsh winsock reset"),
        ("Resetting TCP/IP stack...", "netsh int ip reset"),
    ]
    
    for description, command in commands:
        print(f"{description}")
        log_action(f"Network Reset: {description}")
        result = run_command(command)
        
        if result and result.returncode == 0:
            print(f"✓ {description} completed.\n")
            log_action(f"Network Reset: {description}", "SUCCESS")
        else:
            print(f"⚠ {description} completed with warnings.\n")
            log_action(f"Network Reset: {description}", "WARNING")
    
    print("✓ Network reset completed.")
    print("Note: You may need to restart your computer for changes to take effect.")
    log_action("Network reset completed", "SUCCESS")
    
    input("\nPress Enter to continue...")


# ============================================================================
# TIER 3: MAINTENANCE AND UTILITIES
# ============================================================================

def export_wifi_passwords():
    """Export all saved WiFi SSIDs and passwords."""
    print_header("TIER 3: Export WiFi Passwords")
    
    output_dir = Path.home() / "WinFix_WiFi_Export"
    output_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = output_dir / f"wifi_passwords_{timestamp}.txt"
    
    print("Retrieving saved WiFi profiles...\n")
    log_action("Exporting WiFi passwords")
    
    # Get list of WiFi profiles
    result = run_command("netsh wlan show profiles", capture_output=True)
    
    if not result or result.returncode != 0:
        print("⚠ Could not retrieve WiFi profiles.")
        log_action("WiFi export failed", "ERROR")
        input("\nPress Enter to continue...")
        return
    
    profiles = []
    for line in result.stdout.split('\n'):
        if "All User Profile" in line:
            profile_name = line.split(':')[1].strip()
            profiles.append(profile_name)
    
    if not profiles:
        print("No WiFi profiles found.")
        input("\nPress Enter to continue...")
        return
    
    wifi_data = []
    print(f"Found {len(profiles)} WiFi profile(s). Extracting passwords...\n")
    
    for profile in profiles:
        result = run_command(f'netsh wlan show profile name="{profile}" key=clear', capture_output=True)
        
        password = "N/A"
        if result and result.returncode == 0:
            for line in result.stdout.split('\n'):
                if "Key Content" in line:
                    password = line.split(':')[1].strip()
                    break
        
        wifi_data.append({
            'ssid': profile,
            'password': password
        })
        print(f"✓ {profile}: {password}")
    
    # Write to file
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("="*70 + "\n")
            f.write("WinFix - WiFi Passwords Export\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*70 + "\n\n")
            
            for wifi in wifi_data:
                f.write(f"SSID: {wifi['ssid']}\n")
                f.write(f"Password: {wifi['password']}\n")
                f.write("-"*70 + "\n\n")
        
        print(f"\n✓ WiFi passwords exported to:")
        print(f"  {output_file}")
        log_action(f"WiFi passwords exported: {len(wifi_data)} profiles", "SUCCESS")
        
    except Exception as e:
        print(f"\n⚠ Error writing to file: {e}")
        log_action("WiFi export file write failed", "ERROR")
    
    input("\nPress Enter to continue...")


def run_system_audit():
    """Perform a comprehensive system audit."""
    print_header("TIER 3: System Audit")
    
    output_dir = Path.home() / "WinFix_System_Audit"
    output_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = output_dir / f"system_audit_{timestamp}.txt"
    
    print("Performing system audit...\n")
    log_action("Starting system audit")
    
    audit_commands = [
        ("System Information", "systeminfo"),
        ("Disk Information", "wmic diskdrive get model,size,status"),
        ("Memory Information", "wmic memorychip get capacity,speed,manufacturer"),
        ("Network Adapters", "ipconfig /all"),
        ("Active Network Connections", "netstat -ano"),
        ("Installed Programs", "wmic product get name,version"),
        ("Running Processes", "tasklist"),
        ("Startup Programs", "wmic startup get caption,command"),
        ("Windows Version", "ver"),
        ("Driver List", "driverquery /v /fo csv"),
    ]
    
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("="*70 + "\n")
            f.write("WinFix - System Audit Report\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*70 + "\n\n")
            
            for description, command in audit_commands:
                print(f"Collecting: {description}...")
                f.write("\n" + "="*70 + "\n")
                f.write(f"{description}\n")
                f.write("="*70 + "\n\n")
                
                result = run_command(command, capture_output=True)
                
                if result and result.returncode == 0:
                    f.write(result.stdout)
                    print(f"✓ {description}")
                else:
                    f.write(f"Error collecting {description}\n")
                    print(f"⚠ {description} - Error")
                
                f.write("\n\n")
        
        print(f"\n✓ System audit completed. Report saved to:")
        print(f"  {output_file}")
        log_action("System audit completed", "SUCCESS")
        
    except Exception as e:
        print(f"\n⚠ Error generating audit report: {e}")
        log_action("System audit failed", "ERROR")
    
    input("\nPress Enter to continue...")


def install_common_tools():
    """Install common PC repair and diagnostic tools."""
    print_header("TIER 3: Install Common Tools")
    
    print("This feature helps you install common diagnostic and repair tools.\n")
    print("Available tools to download:")
    print("1. Ninite - Bulk installer for common software")
    print("2. CCleaner - System cleaner and optimizer")
    print("3. CrystalDiskInfo - Hard drive health monitor")
    print("4. HWMonitor - Hardware monitoring tool")
    print("5. Malwarebytes - Malware scanner")
    print("\n")
    
    print("Tool installation links:")
    print("- Ninite: https://ninite.com/")
    print("- CCleaner: https://www.ccleaner.com/ccleaner/download")
    print("- CrystalDiskInfo: https://crystalmark.info/en/software/crystaldiskinfo/")
    print("- HWMonitor: https://www.cpuid.com/softwares/hwmonitor.html")
    print("- Malwarebytes: https://www.malwarebytes.com/")
    
    print("\n")
    print("Note: This tool provides information about useful utilities.")
    print("Please visit the URLs above to download and install the tools.")
    print("Always download software from official sources only.")
    
    log_action("Displayed install tools information")
    
    input("\nPress Enter to continue...")


# ============================================================================
# MENU SYSTEM
# ============================================================================

def show_tier1_menu():
    """Display Tier 1 (Critical) menu."""
    while True:
        clear_screen()
        print_header("TIER 1: CRITICAL SYSTEM REPAIRS")
        print("These tools fix critical system issues and require a restart.\n")
        print("1. Run System File Checker (sfc /scannow)")
        print("2. Run DISM System Repair")
        print("3. Schedule Disk Check (CHKDSK)")
        print("4. Run All Tier 1 Repairs")
        print("0. Back to Main Menu")
        print_separator()
        
        choice = input("\nEnter your choice: ").strip()
        
        if choice == '1':
            run_sfc_scan()
        elif choice == '2':
            run_dism_repair()
        elif choice == '3':
            run_chkdsk_schedule()
        elif choice == '4':
            run_sfc_scan()
            run_dism_repair()
            run_chkdsk_schedule()
        elif choice == '0':
            break
        else:
            print("\nInvalid choice. Please try again.")
            input("Press Enter to continue...")


def show_tier2_menu():
    """Display Tier 2 (Important) menu."""
    while True:
        clear_screen()
        print_header("TIER 2: IMPORTANT REPAIRS AND MAINTENANCE")
        print("These tools address common issues and optimize system performance.\n")
        print("1. Clean Disk Space")
        print("2. Reset Network Settings")
        print("3. Run All Tier 2 Repairs")
        print("0. Back to Main Menu")
        print_separator()
        
        choice = input("\nEnter your choice: ").strip()
        
        if choice == '1':
            clean_disk_space()
        elif choice == '2':
            reset_network()
        elif choice == '3':
            clean_disk_space()
            reset_network()
        elif choice == '0':
            break
        else:
            print("\nInvalid choice. Please try again.")
            input("Press Enter to continue...")


def show_tier3_menu():
    """Display Tier 3 (Maintenance) menu."""
    while True:
        clear_screen()
        print_header("TIER 3: MAINTENANCE AND UTILITIES")
        print("Utility functions for system information and setup.\n")
        print("1. Export WiFi Passwords")
        print("2. Run System Audit")
        print("3. Install Common Tools (Info)")
        print("4. Run All Tier 3 Tasks")
        print("0. Back to Main Menu")
        print_separator()
        
        choice = input("\nEnter your choice: ").strip()
        
        if choice == '1':
            export_wifi_passwords()
        elif choice == '2':
            run_system_audit()
        elif choice == '3':
            install_common_tools()
        elif choice == '4':
            export_wifi_passwords()
            run_system_audit()
            install_common_tools()
        elif choice == '0':
            break
        else:
            print("\nInvalid choice. Please try again.")
            input("Press Enter to continue...")


def show_main_menu():
    """Display the main menu."""
    while True:
        clear_screen()
        print("\n" + "="*70)
        print("  ██╗    ██╗██╗███╗   ██╗███████╗██╗██╗  ██╗")
        print("  ██║    ██║██║████╗  ██║██╔════╝██║╚██╗██╔╝")
        print("  ██║ █╗ ██║██║██╔██╗ ██║█████╗  ██║ ╚███╔╝ ")
        print("  ██║███╗██║██║██║╚██╗██║██╔══╝  ██║ ██╔██╗ ")
        print("  ╚███╔███╔╝██║██║ ╚████║██║     ██║██╔╝ ██╗")
        print("   ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝")
        print("="*70)
        print("  Windows PC Repair Tool")
        print("  Version 1.0")
        print("="*70)
        print("\nMAIN MENU\n")
        print("1. TIER 1 - Critical System Repairs")
        print("2. TIER 2 - Important Repairs & Maintenance")
        print("3. TIER 3 - Utilities & Information")
        print("4. Run ALL Repairs (Tier 1 + 2 + 3)")
        print("5. View Logs")
        print("0. Exit")
        print_separator()
        
        choice = input("\nEnter your choice: ").strip()
        
        if choice == '1':
            show_tier1_menu()
        elif choice == '2':
            show_tier2_menu()
        elif choice == '3':
            show_tier3_menu()
        elif choice == '4':
            confirm = input("\nThis will run all repair tasks. Continue? (y/n): ").strip().lower()
            if confirm == 'y':
                # Tier 1
                run_sfc_scan()
                run_dism_repair()
                run_chkdsk_schedule()
                # Tier 2
                clean_disk_space()
                reset_network()
                # Tier 3
                export_wifi_passwords()
                run_system_audit()
                install_common_tools()
                print("\n✓ All repairs completed!")
                input("\nPress Enter to continue...")
        elif choice == '5':
            view_logs()
        elif choice == '0':
            print("\nThank you for using WinFix!")
            print("Please restart your computer to apply all changes.\n")
            break
        else:
            print("\nInvalid choice. Please try again.")
            input("Press Enter to continue...")


def view_logs():
    """View recent log files."""
    clear_screen()
    print_header("WinFix Logs")
    
    log_dir = Path.home() / "WinFix_Logs"
    
    if not log_dir.exists():
        print("No logs found.")
        input("\nPress Enter to continue...")
        return
    
    log_files = sorted(log_dir.glob("*.log"), reverse=True)
    
    if not log_files:
        print("No log files found.")
        input("\nPress Enter to continue...")
        return
    
    print(f"Log directory: {log_dir}\n")
    print("Recent log files:")
    
    for i, log_file in enumerate(log_files[:5], 1):
        print(f"{i}. {log_file.name} ({log_file.stat().st_size} bytes)")
    
    print("\nEnter file number to view (or 0 to go back): ", end='')
    choice = input().strip()
    
    try:
        choice_num = int(choice)
        if choice_num == 0:
            return
        elif 1 <= choice_num <= len(log_files[:5]):
            clear_screen()
            print_header(f"Log: {log_files[choice_num-1].name}")
            
            with open(log_files[choice_num-1], 'r', encoding='utf-8') as f:
                print(f.read())
            
            input("\nPress Enter to continue...")
        else:
            print("Invalid selection.")
            input("\nPress Enter to continue...")
    except ValueError:
        print("Invalid input.")
        input("\nPress Enter to continue...")


def main():
    """Main entry point."""
    # Check for admin privileges
    request_admin()
    
    # Start the application
    try:
        log_action("WinFix started")
        show_main_menu()
        log_action("WinFix closed normally")
    except KeyboardInterrupt:
        print("\n\nApplication interrupted by user.")
        log_action("WinFix interrupted by user")
    except Exception as e:
        print(f"\nAn error occurred: {e}")
        log_action(f"WinFix error: {e}", "ERROR")
        input("\nPress Enter to exit...")


if __name__ == "__main__":
    main()
