@{
    RootModule        = 'Get-InformationBarrierUserReport.psm1'
    ModuleVersion     = '1.0'
    GUID              = 'f3a1c2d4-b5e6-4789-9abc-de0f12345678'
    Author            = 'Dave Goldman'
    CompanyName       = ' '
    Copyright         = '(c) Dave Goldman. All rights reserved.'
    Description       = 'Reports Information Barrier policy assignments for users and guests, identifies which segments and users are blocked or allowed, and supports both individual lookup and segment-wide enumeration.'
    PowerShellVersion = '7.1'
    RequiredModules   = @()
    FormatsToProcess  = @()
    FunctionsToExport = @('Get-InformationBarrierUserReport')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @('GIBUR')
    PrivateData       = @{
        PSData = @{
            Tags         = @('M365', 'InformationBarriers', 'Compliance', 'Purview', 'ExchangeOnline', 'SecurityAndCompliance', 'eDiscovery', 'Guests')
            ProjectUri   = 'https://github.com/dgoldman-msft/Get-InformationBarrierUserReport'
            LicenseUri   = 'https://github.com/dgoldman-msft/Get-InformationBarrierUserReport/blob/main/LICENSE'
            ReleaseNotes = '1.0 - Initial release'
        }
    }
}
