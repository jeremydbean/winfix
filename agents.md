# Agent Notes - NinjaOne API Integration

## Current Status
**Date:** December 3, 2025
**Objective:** Integrate NinjaOne API into `WinFixTool.ps1` to automate data gathering for the Security Audit.

## What I Am Doing
I am researching the NinjaOne Public API (Beta/v2) to ensure the integration uses the correct authentication flows and endpoints. The goal is to allow the WinFix tool to "phone home" to the NinjaOne RMM instance and retrieve accurate status information for the machine it is running on, rather than relying solely on local WMI/CIM queries which can sometimes be incomplete.

## What I Have Done
1.  **Implemented Authentication**:
    *   Added `Connect-NinjaOne` function to `WinFixTool.ps1`.
    *   Uses **Client Credentials Flow** (OAuth2) to exchange a Client ID and Client Secret for a Bearer Token.
    *   Endpoint: `https://<instance>/v2/oauth/token`.

2.  **Implemented Device Discovery**:
    *   Added `Get-NinjaDeviceData` function.
    *   Logic: Fetches the local machine's Serial Number (via `Win32_Bios`) and Hostname.
    *   Search: Queries `/v2/devices` using the `df` (device filter) parameter.
        *   Primary: `df=serialNumber:<serial>`
        *   Fallback: `df=systemName:<hostname>`

3.  **Integrated Data into Security Audit**:
    *   **Backups**: Overrides local checks if `lastBackupJobStatus` is present in the API response.
    *   **Patching**: Checks `osPatchStatus` for failed/pending patches to populate the "Windows Updates" section.
    *   **Antivirus**: Checks `antivirusStatus` to confirm if a managed AV is enabled and what product is used.

## API References & Notes
*   **Documentation Root**: [NinjaOne API Beta Docs](https://app.ninjarmm.com/apidocs-beta/authorization/overview)
*   **Authorization**:
    *   Type: OAuth 2.0
    *   Grant Type: `client_credentials`
    *   Scope: `monitoring management` (Required for reading device status).
*   **Key Endpoints**:
    *   `POST /v2/oauth/token`: Get Access Token.
    *   `GET /v2/devices`: Search and list devices. Returns a rich object with status fields.
*   **Data Fields of Interest**:
    *   `lastBackupJobStatus`: Returns `SUCCESS`, `FAILED`, etc.
    *   `osPatchStatus`: Object containing `failed`, `pending`, `installed` counts.
    *   `antivirusStatus`: Object containing `protectionStatus` (e.g., `ENABLED`) and `productName`.

## Future Improvements
*   **Ticket Creation**: Could implement `POST /v2/tickets` to automatically open a ticket if the audit fails critical checks.
*   **Software Inventory**: Compare local software list with Ninja's inventory record.
