# Get-InformationBarrierUserReport

## Synopsis

Reports Information Barrier policy assignments for users and guests, identifies blocked/allowed segments and users.

## Description

See [README.md](../README.md) for full documentation.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `UserPrincipalName` | `string[]` | No | UPN(s) of users/guests to investigate |
| `Segment` | `string` | No | Segment name to enumerate users from; supports wildcards (e.g. `Contoso*`) |
| `ListAll` | `switch` | No | Print all IB policy relationships as a matrix |
| `EnumerateUsers` | `switch` | No | Also list individual UPNs in blocked/allowed segments |
| `MaxUsersPerSegment` | `int` | No | Cap on enumerated users per segment (default 50, 0 = unlimited) |
| `LoggingDirectory` | `string` | No | Log output directory (default `$env:TEMP\Get-InformationBarrierUserReport`) |
| `Organization` | `string` | Conditional | Tenant domain; required for ServicePrincipal/ManagedIdentity auth |
| `UseDeviceAuthentication` | `switch` | No | Device-code flow (Interactive set) |
| `Credential` | `PSCredential` | Conditional | Credential auth (Credential set) |
| `ApplicationId` | `string` | Conditional | App ID (ServicePrincipal set) |
| `CertificateThumbprint` | `string` | Conditional | Cert thumbprint (ServicePrincipal set) |
| `Certificate` | `X509Certificate2` | Conditional | Cert object (ServicePrincipal set) |
| `ManagedIdentity` | `switch` | Conditional | Managed identity (ManagedIdentity set) |
| `StayConnected` | `switch` | No | Keep IPPS session alive after function completes |
| `FullDetails` | `switch` | No | Print full Format-List for all records |
| `MediumDetails` | `switch` | No | Print 7-column table for all records |

## Examples

```powershell
Get-InformationBarrierUserReport -UserPrincipalName jdoe@contoso.com
```

```powershell
Get-InformationBarrierUserReport -Segment Finance -EnumerateUsers
```

```powershell
Get-InformationBarrierUserReport -Segment 'Contoso*'
```

```powershell
Get-InformationBarrierUserReport -ListAll
```

## Alias

`GIBUR`

## Outputs

`InformationBarrierUserReport.Record` — PSCustomObject with fields:
`UPN`, `DisplayName`, `AccountType`, `IBStatus`, `Segments`, `ActivePolicies`, `BlockedSegments`, `AllowedSegments`, `BlockedUsers`, `AllowedUsers`
