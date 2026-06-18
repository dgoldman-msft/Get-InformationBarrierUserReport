# Get-InformationBarrierUserReport

A PowerShell module for Microsoft Purview **Information Barriers** compliance reporting. Given one or more user or guest UPNs, a segment name, or the `-ListAll` switch, it reports whether each identity has Information Barrier policies assigned, which segments they belong to, and which other segments (and optionally individual users) are blocked or allowed from communicating with them.

## What are Information Barriers?

Microsoft Purview Information Barriers (IB) let administrators define policies that restrict communication and collaboration between designated groups of users across Microsoft 365 services — Teams, SharePoint, OneDrive, and Exchange. Groups are defined as **organization segments** based on user attributes (e.g., `Department`, `UserGroupId`), and **IB policies** declare which segment pairs are **allowed** or **blocked** from interacting.

Typical use cases include:
- Preventing investment bankers from communicating with research analysts (Chinese Wall / ethical wall)
- Restricting communication between competing business units
- Controlling guest access to prevent cross-organizational leakage

This module closes the visibility gap: the Microsoft 365 Admin Center and Purview portal do not provide an easy way to look up a specific user or guest and see exactly which IB policies apply to them, which segments are blocked, and who those blocked users are.

## What this module reports

For each identity processed:

| Field | Description |
| --- | --- |
| **UPN** | The user principal name |
| **DisplayName** | Resolved display name |
| **AccountType** | `Internal`, `Guest`, or `MailUser` |
| **IBStatus** | `Active`, `NoPolicyAssigned`, `NoSegment`, or `Error` |
| **Segments** | Organization segment(s) the user belongs to |
| **ActivePolicies** | Active IB policies applied to this user |
| **BlockedSegments** | Segment names the user is blocked from communicating with |
| **AllowedSegments** | Segment names explicitly allowed to communicate with this user |
| **BlockedUsers** | Individual UPNs in blocked segments (when `-EnumerateUsers` is specified) |
| **AllowedUsers** | Individual UPNs in allowed segments (when `-EnumerateUsers` is specified) |

### IBStatus values

| Status | Meaning |
| --- | --- |
| `Active` | User is in at least one segment with an active IB policy |
| `NoPolicyAssigned` | User is in a segment but no active policy applies to it |
| `NoSegment` | User is not assigned to any IB segment |
| `Error` | IB data could not be retrieved for this identity |

## Input modes

| Mode | Switch/Parameter | Description |
| --- | --- | --- |
| **UPN lookup** | `-UserPrincipalName` | Look up one or more specific users or guests |
| **Segment enumeration** | `-Segment` | Enumerate all users in one or more matching segments (supports wildcards), then report each |
| **Tenant-wide matrix** | `-ListAll` | Print all active IB policy relationships without per-user lookup |

## Requirements

- PowerShell 7.1 or later
- `ExchangeOnlineManagement` module v3.0.0 or later (installed automatically if absent)
- An authenticated identity with at least one of:
  - Information Barriers Administrator
  - Compliance Administrator
  - Global Administrator
- For `-EnumerateUsers`: the authenticated identity also needs **Exchange View-Only Recipients** or **Recipient Management** to call `Get-EXORecipient`

## Installation

Clone the repository and import:

```powershell
git clone https://github.com/dgoldman-msft/Get-InformationBarrierUserReport.git
Import-Module .\Get-InformationBarrierUserReport\1.0\Get-InformationBarrierUserReport.psd1
```

Or copy the `1.0` folder into a directory on `$env:PSModulePath`:

```
C:\Users\<you>\Documents\PowerShell\Modules\Get-InformationBarrierUserReport\1.0\
```

If you downloaded a ZIP from GitHub, unblock first:

```powershell
Get-ChildItem 'C:\temp\Get-InformationBarrierUserReport-main' -Recurse | Unblock-File
Import-Module 'C:\temp\Get-InformationBarrierUserReport-main\1.0\Get-InformationBarrierUserReport.psd1'
```

## Usage examples

```powershell
PS C:> Get-InformationBarrierUserReport -UserPrincipalName jdoe@contoso.com
```

Reports the IB segment membership, active policies, and blocked/allowed segments for a single internal user using interactive browser authentication.

```powershell
PS C:> Get-InformationBarrierUserReport -UserPrincipalName 'alice_fabrikam.com#EXT#@contoso.onmicrosoft.com'
```

Looks up an external guest by their full EXT UPN and reports their IB status.

```powershell
PS C:> Get-InformationBarrierUserReport -UserPrincipalName jdoe@contoso.com, jsmith@contoso.com
```

Processes two users in a single authenticated session and produces a combined report for both.

```powershell
PS C:> Get-InformationBarrierUserReport -Segment Finance
```

Enumerates every recipient assigned to the Finance segment and reports the IB status for each discovered user.

```powershell
PS C:> Get-InformationBarrierUserReport -Segment 'Contoso*'
```

Enumerates every segment whose name starts with `Contoso` and reports IB status for all users across those matching segments in a single run — useful when segment names follow a company-based naming convention (e.g. `Contoso_Guests`, `Contoso_Allowed`).

```powershell
PS C:> Get-InformationBarrierUserReport -Segment Finance -UserPrincipalName jdoe@contoso.com
```

Combines segment enumeration with a specific UPN lookup, reporting IB status for all Finance segment members plus the individually named user in one run.

```powershell
PS C:> Get-InformationBarrierUserReport -Segment 'Contoso*'
```

Enumerates every segment whose name starts with `Contoso` and reports IB status for all users across those matching segments in a single run — useful when segment names follow a company-based naming convention (e.g. `Contoso_Guests`, `Contoso_Allowed`).

```powershell
PS C:> Get-InformationBarrierUserReport -Segment Finance -EnumerateUsers -MaxUsersPerSegment 25
```

Enumerates Finance segment users and, for each blocked or allowed segment, lists up to 25 individual UPNs so you can see exactly who is affected.

```powershell
PS C:> Get-InformationBarrierUserReport -ListAll
```

Prints a tenant-wide matrix of all active IB policy relationships, showing which segment pairs are blocked or allowed without performing a per-user lookup.

```powershell
PS C:> Get-InformationBarrierUserReport -UserPrincipalName jdoe@contoso.com `
    -UseDeviceAuthentication -Organization contoso.onmicrosoft.com
```

Authenticates via device-code flow instead of a browser pop-up, which is useful for headless or remote sessions where interactive sign-in is not available.

```powershell
PS C:> Get-InformationBarrierUserReport -UserPrincipalName jdoe@contoso.com `
    -ApplicationId '00000000-0000-0000-0000-000000000000' `
    -Organization 'contoso.onmicrosoft.com' `
    -CertificateThumbprint 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
```

Authenticates as an Azure app registration using a certificate thumbprint from the local certificate store, suitable for unattended/automated runs.

```powershell
PS C:> $cert = Get-PfxCertificate -FilePath 'C:\certs\myapp.pfx'
PS C:> Get-InformationBarrierUserReport -UserPrincipalName jdoe@contoso.com `
    -ApplicationId '00000000-0000-0000-0000-000000000000' `
    -Organization 'contoso.onmicrosoft.com' `
    -Certificate $cert
```

Same as above but passes the certificate as an in-memory `X509Certificate2` object loaded from a PFX file rather than relying on the local cert store.

```powershell
PS C:> $cred = Get-Credential
PS C:> Get-InformationBarrierUserReport -UserPrincipalName jdoe@contoso.com -Credential $cred
```

Authenticates with a `PSCredential` object for accounts that do not have MFA enforced.

```powershell
PS C:> Get-InformationBarrierUserReport -UserPrincipalName jdoe@contoso.com `
    -ManagedIdentity -Organization contoso.onmicrosoft.com
```

Authenticates using the managed identity assigned to the Azure-hosted workload (e.g., an Azure Automation account or VM), with no credentials required.

```powershell
PS C:> GIBUR -UserPrincipalName jdoe@contoso.com
```

Uses the `GIBUR` alias as a shorter alternative to the full function name.

```powershell
$report = Get-InformationBarrierUserReport -UserPrincipalName jdoe@contoso.com, jsmith@contoso.com
$report | Where-Object IBStatus -eq 'Active' | Select-Object UPN, BlockedSegments
```

Captures the output as objects and uses the pipeline to filter down to only users with an active IB policy, showing just their UPN and blocked segments.

```powershell
PS C:> Get-InformationBarrierUserReport -UserPrincipalName jdoe@contoso.com -MediumDetails
```

Prints a consolidated seven-column summary table (UPN, AccountType, IBStatus, Segments, ActivePolicies, BlockedSegments, AllowedSegments) for all processed records in addition to the default per-user output.

```powershell
PS C:> Get-InformationBarrierUserReport -UserPrincipalName jdoe@contoso.com -FullDetails
```

Prints every property of every record as a `Format-List`, useful when you need to inspect all fields including `BlockedUsers` and `AllowedUsers`.

```powershell
PS C:> Get-InformationBarrierUserReport -UserPrincipalName jdoe@contoso.com -StayConnected
PS C:> Get-InformationBarrierUserReport -UserPrincipalName jsmith@contoso.com -StayConnected
PS C:> Disconnect-ExchangeOnline -Confirm:$false
```

Keeps the IPPS session alive between multiple calls so you avoid re-authenticating on each run; disconnect manually when finished.

```powershell
PS C:> Get-InformationBarrierUserReport -UserPrincipalName jdoe@contoso.com `
    -LoggingDirectory 'C:\IBReports'
```

Writes the timestamped log file and CSV export to a custom directory instead of the default `$env:TEMP\Get-InformationBarrierUserReport` location.

## Output

Every run writes two files to `-LoggingDirectory` (default: `$env:TEMP\Get-InformationBarrierUserReport`):

| File | Description |
| --- | --- |
| `Logging_yyyyMMdd_HHmmss.txt` | Full timestamped log of all operations and console output |
| `IBReport_yyyyMMdd_HHmmss.csv` | All records exported for further analysis or audit |

## Authentication methods

| Parameter set | Parameters | Notes |
| --- | --- | --- |
| `Interactive` (default) | `-UseDeviceAuthentication` (optional), `-Organization` (optional) | Browser MFA or device-code flow |
| `Credential` | `-Credential` | PSCredential; no MFA |
| `ServicePrincipal` | `-ApplicationId`, `-Organization`, `-CertificateThumbprint` or `-Certificate` | App-only; requires `Exchange.ManageAsApp` |
| `ManagedIdentity` | `-ManagedIdentity`, `-Organization` | Azure-hosted workloads |

## Related links

- [Information Barriers overview](https://learn.microsoft.com/en-us/purview/information-barriers)
- [Get-InformationBarrierRecipientStatus](https://learn.microsoft.com/en-us/powershell/module/exchange/get-informationbarrierrecipientstatus)
- [Get-OrganizationSegment](https://learn.microsoft.com/en-us/powershell/module/exchange/get-organizationsegment)
- [Get-InformationBarrierPolicy](https://learn.microsoft.com/en-us/powershell/module/exchange/get-informationbarrierpolicy)
- [Connect-IPPSSession](https://learn.microsoft.com/en-us/powershell/module/exchange/connect-ippssession)
