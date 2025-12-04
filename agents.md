# Agent Notes - NinjaOne API Integration

## Current Status
**Date:** December 3, 2025
**Objective:** Integrate NinjaOne API into `WinFixTool.ps1` to automate data gathering for the Security Audit.

## What I Am Doing
I have completed the core integration of the NinjaOne API, including authentication, device discovery (via Registry and Search), and data integration into the Security Audit report. I am now finalizing documentation and ensuring the tool is robust for deployment.

## What I Have Done
1.  **Implemented Authentication**:
    *   Added `Connect-NinjaOne` function to `WinFixTool.ps1`.
    *   Uses **Client Credentials Flow** (OAuth2).
    *   Added URL sanitization to handle user input errors (e.g., pasting full dashboard URLs).

2.  **Implemented Device Discovery**:
    *   **Registry Detection (Primary)**: Checks `HKLM:\SOFTWARE\NinjaRMM\Agent` (and variants) for `NodeID` or `DeviceID`. This ensures 100% accuracy when running on a managed device.
    *   **API Search (Fallback)**: If registry detection fails, searches via API using Serial Number and Hostname.

3.  **Integrated Data into Security Audit**:
    *   **Backups**: Overrides local checks if `lastBackupJobStatus` is present in the API response.
    *   **Patching**: Checks `osPatchStatus` for failed/pending patches.
    *   **Antivirus**: Checks `antivirusStatus` for protection status and product name.

4.  **Troubleshooting & Stability**:
    *   **Logging**: Implemented a debug log (`%TEMP%\WinFix_Debug.log`) and an "Open Log" button in the GUI.
    *   **Crash Fixes**: Resolved `DrawString` type mismatch and `ScriptBlock` variable scope issues.
    *   **Button Logic**: Fixed "ScriptBlock is null" error by explicitly capturing variables in the closure.
    *   **API Robustness**: Added fallback logic to `Connect-NinjaOne` to retry the original URL if the derived API URL fails.
    *   **Endpoint Correction**: Discovered that the OAuth token endpoint is `/ws/oauth/token` (not `/v2/oauth/token`), while the rest of the API uses `/v2/`. Updated `Connect-NinjaOne` to use the correct auth path.
    *   **Report Generation**: Fixed a bug where `Invoke-SecurityAudit` could produce a blank report if `Get-LocalUser` failed. Added error handling and safe variable usage.

## API References & Notes
*   **Documentation Root**: [NinjaOne API Beta Docs](https://app.ninjarmm.com/apidocs-beta/authorization/overview)
*   **Authorization**:
    *   Type: OAuth 2.0
    *   Grant Type: `client_credentials`
    *   Scope: `monitoring management` (Required for reading device status).

## Future Improvements
*   **Ticket Creation**: Could implement `POST /v2/tickets` to automatically open a ticket if the audit fails critical checks.
*   **Software Inventory**: Compare local software list with Ninja's inventory record.
