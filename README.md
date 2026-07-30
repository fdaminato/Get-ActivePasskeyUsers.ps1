## 📝 Description

    Generates CSV and interactive HTML reports for enabled Microsoft Entra ID users
    who have at least one currently registered passkey (FIDO2) method.

    - Connects interactively to Microsoft Graph.
    - Reuses an already-loaded Microsoft.Graph.Authentication module.
    - Handles Graph assembly-version conflicts by restarting in a clean process.
    - Uses StrictMode-safe Microsoft Graph pagination.
    - Confirms each user is enabled and each passkey still exists.
    - Generates:
        * User summary CSV
        * Detailed passkey CSV
        * Failure CSV, when applicable
        * Standalone interactive HTML dashboard

## ⚡ Exemple 1

```bash

Use .\Get-ActivePasskeyUsers.ps1 -TenantId "TENANTID" -OpenHtml

## ⚡ Exemple 2

```bash

Use .\Get-ActivePasskeyUsers.ps1 -TenantId "contoso.onmicrosoft.com" -OpenHtml
