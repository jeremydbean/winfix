"""
Simple tests for WinFix functionality
Note: These tests check basic structure and imports only.
Full testing requires Windows environment with admin privileges.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test that all required modules can be imported."""
    import subprocess
    import sys
    import os
    import json
    import shutil
    from pathlib import Path
    from datetime import datetime
    print("✓ All imports successful")


def test_script_structure():
    """Test that the main script has the expected structure."""
    with open('winfix.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check for main function definitions
    required_functions = [
        'def is_admin(',
        'def request_admin(',
        'def run_command(',
        'def log_action(',
        'def run_sfc_scan(',
        'def run_dism_repair(',
        'def clean_disk_space(',
        'def reset_network(',
        'def export_wifi_passwords(',
        'def run_system_audit(',
        'def install_common_tools(',
        'def show_main_menu(',
        'def main(',
    ]
    
    missing = []
    for func in required_functions:
        if func not in content:
            missing.append(func)
    
    if missing:
        print(f"✗ Missing functions: {', '.join(missing)}")
        return False
    
    print("✓ All required functions present")
    return True


def test_tier_structure():
    """Test that tier menus are defined."""
    with open('winfix.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    tier_checks = [
        'TIER 1: CRITICAL SYSTEM REPAIRS',
        'TIER 2: IMPORTANT REPAIRS',
        'TIER 3: MAINTENANCE AND UTILITIES',
    ]
    
    missing = []
    for check in tier_checks:
        if check not in content:
            missing.append(check)
    
    if missing:
        print(f"✗ Missing tier sections: {', '.join(missing)}")
        return False
    
    print("✓ All tier sections present")
    return True


def test_file_structure():
    """Test that all required files exist."""
    required_files = [
        'winfix.py',
        'winfix.spec',
        'requirements.txt',
        'build.bat',
        'README.md',
        '.gitignore',
    ]
    
    missing = []
    for file in required_files:
        if not os.path.exists(file):
            missing.append(file)
    
    if missing:
        print(f"✗ Missing files: {', '.join(missing)}")
        return False
    
    print("✓ All required files present")
    return True


def main():
    """Run all tests."""
    print("="*70)
    print("WinFix Tests")
    print("="*70)
    print()
    
    all_passed = True
    
    print("Test 1: Imports")
    try:
        test_imports()
    except Exception as e:
        print(f"✗ Import test failed: {e}")
        all_passed = False
    print()
    
    print("Test 2: File Structure")
    if not test_file_structure():
        all_passed = False
    print()
    
    print("Test 3: Script Structure")
    if not test_script_structure():
        all_passed = False
    print()
    
    print("Test 4: Tier Structure")
    if not test_tier_structure():
        all_passed = False
    print()
    
    print("="*70)
    if all_passed:
        print("✓ All tests passed!")
        print("="*70)
        return 0
    else:
        print("✗ Some tests failed")
        print("="*70)
        return 1


if __name__ == "__main__":
    sys.exit(main())
