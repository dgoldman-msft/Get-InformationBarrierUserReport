#Requires -Version 7.1

function Get-InformationBarrierUserReport {
    <#
    .SYNOPSIS
        Reports Information Barrier policy assignments for users and guests, and
        identifies which segments and users are blocked or allowed.

    .DESCRIPTION
        Get-InformationBarrierUserReport is an advanced function that queries the
        Microsoft Purview Information Barriers configuration in your tenant and
        produces a human-readable compliance report for one or more identities.

        WHAT ARE INFORMATION BARRIERS?
        ───────────────────────────────
        Microsoft Purview Information Barriers (IB) let administrators define
        policies that prevent certain groups of users from communicating or
        collaborating with each other in Microsoft 365 services (Teams, SharePoint,
        OneDrive, Exchange). Segments are defined by user attributes (e.g.,
        Department, UserGroupId) and policies specify which segment-pairs are
        allowed or blocked.

        WHAT THIS FUNCTION REPORTS
        ───────────────────────────
        For each supplied identity (internal user or guest):
          1. Whether the user is assigned to any organization segment.
          2. Which IB policies are actively applied to that user.
          3. Which segments — and optionally which individual users — are BLOCKED
             from communicating with the target user.
          4. Which segments — and optionally which individual users — are ALLOWED
             to communicate with the target user.

        INPUT MODES
        ────────────
          -UserPrincipalName   Look up one or more specific users/guests by UPN.
          -Segment             Look up all users assigned to a named segment, then
                               report IB status for each discovered user. Can be
                               combined with -UserPrincipalName.
          -ListAll             Enumerate every unique segment in the tenant and
                               report which segment-pairs are blocked or allowed.
                               Does not enumerate per-user status; use with caution
                               in large tenants.

        GUEST SUPPORT
        ─────────────
        External guests are represented in Exchange Online as mail-enabled
        contacts or mail users with a UPN in the form guest_name_domain.com#EXT#
        @tenant.onmicrosoft.com. Pass the full EXT UPN or the guest's primary
        SMTP address — the function resolves either form via Get-EXORecipient.

        REQUIRED PERMISSIONS
        ─────────────────────
        The authenticated identity must hold at least one of:
          - Information Barriers Administrator
          - Compliance Administrator
          - Global Administrator
        Roles are checked in the Security & Compliance Center (IPPS).

        Ref: https://learn.microsoft.com/en-us/purview/information-barriers-policies
        Ref: https://learn.microsoft.com/en-us/purview/information-barriers-solution-overview

    .PARAMETER UserPrincipalName
        One or more UPNs of the users or guests to investigate.
        Accepts an array — each UPN is processed in sequence within the same session.
        Prompted interactively if omitted (unless -Segment or -ListAll is supplied).
        Guest EXT UPNs (user_domain.com#EXT#@tenant.onmicrosoft.com) are supported.

    .PARAMETER Segment
        Name of an organization segment to investigate. Accepts wildcards — for
        example, 'Contoso*' will match all segments whose names start with 'Contoso'.
        The function enumerates all recipients assigned to every matching segment
        and reports their IB status. Can be combined with -UserPrincipalName.

    .PARAMETER ListAll
        When specified, loads all organization segments and all active IB policies
        and prints a segment-pair matrix showing blocked and allowed relationships.
        Does not require -UserPrincipalName. Cannot be combined with -Segment.

    .PARAMETER EnumerateUsers
        When specified, the report also lists the individual UPNs of users found in
        each blocked or allowed segment (resolved via Get-EXORecipient per segment
        filter). In large tenants this may be slow; use -MaxUsersPerSegment to cap
        the result set per segment.

    .PARAMETER MaxUsersPerSegment
        Maximum number of user UPNs to return per blocked or allowed segment when
        -EnumerateUsers is specified. Default 50. Set to 0 for unlimited.

    .PARAMETER LoggingDirectory
        Directory where the timestamped log file is written.
        Defaults to $env:TEMP\Get-InformationBarrierUserReport.

    .PARAMETER Organization
        Tenant domain name (e.g. contoso.onmicrosoft.com). Required for
        ServicePrincipal and ManagedIdentity auth; optional for Interactive and
        Credential.

    .PARAMETER UseDeviceAuthentication
        (Interactive set) Use device-code flow instead of a browser pop-up.
        Useful for headless or remote sessions.

    .PARAMETER Credential
        (Credential set) PSCredential for organizational-ID accounts without MFA.

    .PARAMETER ApplicationId
        (ServicePrincipal set) Azure app registration Application (client) ID.

    .PARAMETER CertificateThumbprint
        (ServicePrincipal set) Thumbprint of the certificate in the local cert store.
        Provide this or -Certificate.

    .PARAMETER Certificate
        (ServicePrincipal set) X509Certificate2 object loaded from a .pfx file.
        Provide this or -CertificateThumbprint.

    .PARAMETER ManagedIdentity
        (ManagedIdentity set) Connect using the Azure managed service identity
        assigned to the current host.

    .PARAMETER StayConnected
        When specified, the Security & Compliance session is NOT disconnected after
        the function completes. Useful when chaining multiple compliance operations.
        If an IPPS session is already active (detected via Get-OrganizationSegment),
        the function reuses it and skips the Connect-IPPSSession call entirely.

    .PARAMETER FullDetails
        When specified, prints every record property as Format-List for all
        processed identities. Cannot be combined with -MediumDetails.

    .PARAMETER MediumDetails
        When specified, prints the seven-column summary table
        (UPN, AccountType, IBStatus, Segments, ActivePolicies,
         BlockedSegments, AllowedSegments) for all records. Cannot be combined
        with -FullDetails.

    .EXAMPLE
        C:\PS> Get-InformationBarrierUserReport -UserPrincipalName jdoe@contoso.com

        Interactive browser/MFA. Reports IB segment, active policies, blocked
        and allowed segments for jdoe@contoso.com.

    .EXAMPLE
        C:\PS> Get-InformationBarrierUserReport `
            -UserPrincipalName jdoe@contoso.com, guest_fabrikam.com#EXT#@contoso.onmicrosoft.com

        Investigate both an internal user and a guest in one run.

    .EXAMPLE
        C:\PS> Get-InformationBarrierUserReport -Segment Finance -EnumerateUsers

        List all users in the Finance segment, report their IB status, and
        enumerate individual UPNs in any blocked or allowed segments.

    .EXAMPLE
        C:\PS> Get-InformationBarrierUserReport -Segment 'Contoso*'

        Enumerate all segments whose names start with 'Contoso' and report the
        IB status of every user found across those segments in a single run.

    .EXAMPLE
        C:\PS> Get-InformationBarrierUserReport -ListAll

        Print a segment-pair matrix of all blocked and allowed IB relationships
        in the tenant without enumerating individual users.

    .EXAMPLE
        C:\PS> Get-InformationBarrierUserReport -UserPrincipalName jdoe@contoso.com `
            -EnumerateUsers -MaxUsersPerSegment 25

        Report IB status and list up to 25 users per blocked/allowed segment.

    .EXAMPLE
        C:\PS> Get-InformationBarrierUserReport -UserPrincipalName jdoe@contoso.com `
            -UseDeviceAuthentication -Organization contoso.onmicrosoft.com

        Device-code flow for headless or remote sessions.

    .EXAMPLE
        C:\PS> $cred = Get-Credential
        C:\PS> Get-InformationBarrierUserReport -UserPrincipalName jdoe@contoso.com `
            -Credential $cred

        PSCredential authentication.

    .EXAMPLE
        C:\PS> Get-InformationBarrierUserReport -UserPrincipalName jdoe@contoso.com `
            -ApplicationId '00000000-0000-0000-0000-000000000000' `
            -Organization 'contoso.onmicrosoft.com' `
            -CertificateThumbprint 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'

        Service principal authentication using a certificate thumbprint.

    .EXAMPLE
        C:\PS> GIBUR -UserPrincipalName jdoe@contoso.com

        Uses the GIBUR alias.

    .EXAMPLE
        C:\PS> $report = Get-InformationBarrierUserReport -UserPrincipalName jdoe@contoso.com
        C:\PS> $report | Where-Object IBStatus -eq 'Active' | Select-Object UPN, BlockedSegments

        Pipeline use — filter to users with active IB policies.

    .INPUTS
        None. This function does not accept pipeline input.

    .OUTPUTS
        None (display only) when no output variable is assigned.
        A timestamped CSV (IBReport_yyyyMMdd_HHmmss.csv) is always written to
        -LoggingDirectory.

        Record type: InformationBarrierUserReport.Record
        Fields:
          UPN, DisplayName, AccountType, IBStatus, Segments, ActivePolicies,
          BlockedSegments, AllowedSegments, BlockedUsers, AllowedUsers.

        IBStatus values:
          Active           User is in at least one segment with an active IB policy.
          NoPolicyAssigned User is in a segment but no active policy applies to it.
          NoSegment        User is not assigned to any IB segment.
          Error            Could not retrieve IB data for this identity.

    .NOTES
        Alias: GIBUR
        Requires PowerShell 7.1 or later.
        The ExchangeOnlineManagement module is installed automatically from
        PSGallery if absent (version 3.0.0 or later required for modern auth).
        ServicePrincipal auth requires app registration with:
          Exchange.ManageAsApp application permission in Azure AD, plus the
          Compliance Administrator or Information Barriers Administrator role
          assigned to the service principal in the Security & Compliance Center.

        Display modes:
          (default)       Per-user IB report + summary lines only
          -MediumDetails  Adds a consolidated seven-column table after the summaries
          -FullDetails    Adds a full Format-List of every property after the summaries

        Session reuse: when -StayConnected is specified and an active IPPS session
        is detected (via Get-OrganizationSegment), Connect-IPPSSession is skipped.

        Ref: https://learn.microsoft.com/en-us/powershell/module/exchange/get-informationbarrierrecipientstatus
        Ref: https://learn.microsoft.com/en-us/powershell/module/exchange/get-organizationsegment
        Ref: https://learn.microsoft.com/en-us/powershell/module/exchange/get-informationbarrierpolicy
    #>

    [Alias('GIBUR')]
    [CmdletBinding(DefaultParameterSetName = 'Interactive', SupportsShouldProcess)]
    param (
        # ── Common ────────────────────────────────────────────────────────────
        [Parameter(Mandatory = $false, HelpMessage = 'UPN(s) of the users/guests to investigate')]
        [string[]]$UserPrincipalName,

        [Parameter(Mandatory = $false, HelpMessage = 'Segment name to enumerate and investigate')]
        [string]$Segment,

        [Parameter(Mandatory = $false, HelpMessage = 'Report all segment-pair relationships without per-user lookup')]
        [switch]$ListAll,

        [Parameter(Mandatory = $false, HelpMessage = 'Also enumerate individual users in blocked/allowed segments')]
        [switch]$EnumerateUsers,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 10000)]
        [int]$MaxUsersPerSegment = 50,

        [Parameter(Mandatory = $false, HelpMessage = 'Directory for log files')]
        [string]$LoggingDirectory = (Join-Path $env:TEMP 'Get-InformationBarrierUserReport'),

        [Parameter()]
        [switch]$StayConnected,

        [Parameter()]
        [switch]$FullDetails,

        [Parameter()]
        [switch]$MediumDetails,

        # ── Organization (tenant domain) ──────────────────────────────────────
        [Parameter(ParameterSetName = 'Interactive',      Mandatory = $false)]
        [Parameter(ParameterSetName = 'Credential',       Mandatory = $false)]
        [Parameter(ParameterSetName = 'ServicePrincipal', Mandatory = $true)]
        [Parameter(ParameterSetName = 'ManagedIdentity',  Mandatory = $true)]
        [string]$Organization,

        # ── Interactive (default) ─────────────────────────────────────────────
        [Parameter(ParameterSetName = 'Interactive', Mandatory = $false)]
        [switch]$UseDeviceAuthentication,

        # ── Credential ────────────────────────────────────────────────────────
        [Parameter(ParameterSetName = 'Credential', Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        # ── ServicePrincipal ──────────────────────────────────────────────────
        [Parameter(ParameterSetName = 'ServicePrincipal', Mandatory = $true)]
        [string]$ApplicationId,

        [Parameter(ParameterSetName = 'ServicePrincipal', Mandatory = $false)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'ServicePrincipal', Mandatory = $false)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        # ── ManagedIdentity ───────────────────────────────────────────────────
        [Parameter(ParameterSetName = 'ManagedIdentity', Mandatory = $true)]
        [switch]$ManagedIdentity
    )

    begin {
        #region ── Validate parameter combinations ────────────────────────────

        if ($FullDetails -and $MediumDetails) {
            throw '-FullDetails and -MediumDetails cannot be used together.'
        }
        if ($ListAll -and $Segment) {
            throw '-ListAll and -Segment cannot be used together.'
        }
        if ($ListAll -and $UserPrincipalName) {
            throw '-ListAll cannot be combined with -UserPrincipalName. Use -Segment or individual UPN lookups instead.'
        }

        #endregion

        #region ── Initialize log file ────────────────────────────────────────

        if (-not (Test-Path -Path $LoggingDirectory)) {
            New-Item -Path $LoggingDirectory -ItemType Directory -Force | Out-Null
        }

        $runStamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
        $logFile   = Join-Path $LoggingDirectory "Logging_$runStamp.txt"
        $csvFile   = Join-Path $LoggingDirectory "IBReport_$runStamp.csv"
        $separator = '-' * 80

        Write-ToLogFile -StringObject $separator -LogFile $logFile
        Write-ToLogFile -StringObject 'Starting Get-InformationBarrierUserReport' -LogFile $logFile
        Write-ToLogFile -StringObject "Log file : $logFile" -LogFile $logFile -ForegroundColor DarkGray
        Write-ToLogFile -StringObject "CSV file : $csvFile"  -LogFile $logFile -ForegroundColor DarkGray

        #endregion

        #region ── Module bootstrap ───────────────────────────────────────────

        $requiredModule = 'ExchangeOnlineManagement'
        $requiredVersion = [version]'3.0.0'

        Write-ToLogFile -StringObject "Checking for module: $requiredModule (>= $requiredVersion)" -LogFile $logFile

        $installed = Get-Module -ListAvailable -Name $requiredModule |
                     Sort-Object Version -Descending |
                     Select-Object -First 1

        if (-not $installed -or $installed.Version -lt $requiredVersion) {
            $action = if ($installed) { "Updating $requiredModule from v$($installed.Version)" } else { "Installing $requiredModule" }
            Write-ToLogFile -StringObject "$action from PSGallery..." -LogFile $logFile -ForegroundColor Yellow
            try {
                Install-Module -Name $requiredModule -Scope CurrentUser -Force -AllowClobber -MinimumVersion $requiredVersion -ErrorAction Stop
                Write-ToLogFile -StringObject "$requiredModule installed/updated successfully." -LogFile $logFile
            }
            catch {
                Write-ToLogFile -StringObject "ERROR: $requiredModule install/update failed. $($_.Exception.Message)" `
                    -LogFile $logFile -ForegroundColor Red
                throw "[$requiredModule] install failed: $($_.Exception.Message)"
            }
        }
        else {
            Write-ToLogFile -StringObject "$requiredModule found v$($installed.Version)." -LogFile $logFile
        }

        if (-not (Get-Module -Name $requiredModule)) {
            try {
                Import-Module -Name $requiredModule -ErrorAction Stop
                Write-ToLogFile -StringObject "$requiredModule imported." -LogFile $logFile
            }
            catch {
                Write-ToLogFile -StringObject "ERROR: $requiredModule import failed. $($_.Exception.Message)" `
                    -LogFile $logFile -ForegroundColor Red
                throw "[$requiredModule] import failed: $($_.Exception.Message)"
            }
        }
        else {
            Write-ToLogFile -StringObject "$requiredModule already loaded." -LogFile $logFile
        }

        #endregion

        #region ── Security & Compliance (IPPS) connection ───────────────────
        # Ref: https://learn.microsoft.com/en-us/powershell/module/exchange/connect-ippssession

        $alreadyConnected = $false
        if ($StayConnected) {
            try {
                $null = Get-OrganizationSegment -ErrorAction Stop
                $null = Get-EXORecipient -ResultSize 1 -ErrorAction Stop
                $alreadyConnected = $true
                Write-ToLogFile -StringObject 'Active IPPS and Exchange Online sessions detected — skipping connections (-StayConnected).' `
                    -LogFile $logFile -ForegroundColor Cyan
            }
            catch {
                $alreadyConnected = $false
                Write-ToLogFile -StringObject 'No active sessions found. New connections will be established.' `
                    -LogFile $logFile -ForegroundColor DarkGray
            }
        }

        if (-not $alreadyConnected -and $PSCmdlet.ShouldProcess('Security and Compliance Center', 'Connect-IPPSSession')) {
            Write-ToLogFile -StringObject 'Connecting to Security and Compliance Center (IPPS)...' `
                -LogFile $logFile -ForegroundColor Cyan
            Write-ToLogFile -StringObject "Auth method: $($PSCmdlet.ParameterSetName)" -LogFile $logFile

            try {
                switch ($PSCmdlet.ParameterSetName) {

                    'Interactive' {
                        $connectParams = @{ ShowBanner = $false }
                        if ($Organization)             { $connectParams['DelegatedOrganization'] = $Organization }
                        if ($UseDeviceAuthentication)  { $connectParams['UseDeviceAuthentication'] = $true }
                        Connect-IPPSSession @connectParams -ErrorAction Stop
                    }

                    'Credential' {
                        $connectParams = @{ Credential = $Credential; ShowBanner = $false }
                        if ($Organization) { $connectParams['DelegatedOrganization'] = $Organization }
                        Connect-IPPSSession @connectParams -ErrorAction Stop
                    }

                    'ServicePrincipal' {
                        if (-not $CertificateThumbprint -and -not $Certificate) {
                            throw 'ServicePrincipal auth requires -CertificateThumbprint or -Certificate.'
                        }
                        $connectParams = @{
                            AppId        = $ApplicationId
                            Organization = $Organization
                            ShowBanner   = $false
                        }
                        if ($CertificateThumbprint) { $connectParams['CertificateThumbprint'] = $CertificateThumbprint }
                        if ($Certificate)           { $connectParams['Certificate']           = $Certificate }
                        Connect-IPPSSession @connectParams -ErrorAction Stop
                    }

                    'ManagedIdentity' {
                        Connect-IPPSSession -ManagedIdentity -Organization $Organization -ShowBanner:$false -ErrorAction Stop
                    }
                }

                Write-ToLogFile -StringObject 'Successfully connected to Security and Compliance Center.' `
                    -LogFile $logFile -ForegroundColor Green
            }
            catch {
                Write-ToLogFile -StringObject "ERROR: IPPS connection failed. $($_.Exception.Message)" `
                    -LogFile $logFile -ForegroundColor Red
                throw "Could not connect to Security and Compliance Center: $($_.Exception.Message)"
            }

            # Also connect Exchange Online for recipient resolution (Get-EXORecipient / Get-Recipient)
            Write-ToLogFile -StringObject 'Connecting to Exchange Online...' -LogFile $logFile -ForegroundColor Cyan
            try {
                switch ($PSCmdlet.ParameterSetName) {
                    'Interactive' {
                        $exoParams = @{ ShowBanner = $false }
                        if ($Organization)            { $exoParams['Organization'] = $Organization }
                        if ($UseDeviceAuthentication) { $exoParams['UseDeviceAuthentication'] = $true }
                        Connect-ExchangeOnline @exoParams -ErrorAction Stop
                    }
                    'Credential' {
                        Connect-ExchangeOnline -Credential $Credential -ShowBanner:$false -ErrorAction Stop
                    }
                    'ServicePrincipal' {
                        $exoParams = @{ AppId = $ApplicationId; Organization = $Organization; ShowBanner = $false }
                        if ($CertificateThumbprint) { $exoParams['CertificateThumbprint'] = $CertificateThumbprint }
                        if ($Certificate)           { $exoParams['Certificate']           = $Certificate }
                        Connect-ExchangeOnline @exoParams -ErrorAction Stop
                    }
                    'ManagedIdentity' {
                        Connect-ExchangeOnline -ManagedIdentity -Organization $Organization -ShowBanner:$false -ErrorAction Stop
                    }
                }
                Write-ToLogFile -StringObject 'Successfully connected to Exchange Online.' -LogFile $logFile -ForegroundColor Green
            }
            catch {
                Write-ToLogFile -StringObject "ERROR: Exchange Online connection failed. $($_.Exception.Message)" `
                    -LogFile $logFile -ForegroundColor Red
                throw "Could not connect to Exchange Online: $($_.Exception.Message)"
            }
        }

        # Detect IB version: v2 tenants expose Get-ExoInformationBarrierRelationship after connecting EXO
        $script:isIBv2 = $null -ne (Get-Command -Name 'Get-ExoInformationBarrierRelationship' -ErrorAction SilentlyContinue)
        Write-ToLogFile -StringObject "Information Barriers version: $(if ($script:isIBv2) { 'v2' } else { 'v1' })" `
            -LogFile $logFile -ForegroundColor DarkGray

        #endregion

        #region ── Load all segments and policies (cached) ────────────────────

        Write-ToLogFile -StringObject 'Loading all organization segments...' -LogFile $logFile
        try {
            $allSegments = @(Get-OrganizationSegment -ErrorAction Stop)
            Write-ToLogFile -StringObject "Loaded $($allSegments.Count) segment(s)." -LogFile $logFile -ForegroundColor Green
        }
        catch {
            Write-ToLogFile -StringObject "ERROR: Could not retrieve segments. $($_.Exception.Message)" `
                -LogFile $logFile -ForegroundColor Red
            throw "Get-OrganizationSegment failed: $($_.Exception.Message)"
        }

        Write-ToLogFile -StringObject 'Loading all active Information Barrier policies...' -LogFile $logFile
        try {
            $allPolicies = @(Get-InformationBarrierPolicy -ErrorAction Stop | Where-Object { $_.State -eq 'Active' })
            Write-ToLogFile -StringObject "Loaded $($allPolicies.Count) active policy(ies)." -LogFile $logFile -ForegroundColor Green
        }
        catch {
            Write-ToLogFile -StringObject "ERROR: Could not retrieve IB policies. $($_.Exception.Message)" `
                -LogFile $logFile -ForegroundColor Red
            throw "Get-InformationBarrierPolicy failed: $($_.Exception.Message)"
        }

        # Build a quick lookup: segment name -> segment object
        $segmentIndex = @{}
        foreach ($seg in $allSegments) {
            $segmentIndex[$seg.Name] = $seg
        }

        # Build a GUID/ObjectId -> segment name lookup for IB v2 tenants.
        # InformationBarrierSegments on a recipient stores the segment's object ID, not its name.
        $segmentGuidToName = @{}
        foreach ($seg in $allSegments) {
            # Try common GUID-bearing properties in order of likelihood
            foreach ($propName in @('ExternalDirectoryObjectId','Guid','Id','ObjectId','Identity')) {
                $propVal = $seg.PSObject.Properties[$propName]
                if ($propVal -and -not [string]::IsNullOrWhiteSpace($propVal.Value)) {
                    $segmentGuidToName[$propVal.Value.ToString()] = $seg.Name
                    break
                }
            }
        }

        # Collection for all records across all UPNs
        $allRecords = [System.Collections.Generic.List[pscustomobject]]::new()

        #endregion

        #region ── Helper: Resolve UPNs in a segment filter ──────────────────

        # Returns an array of UPN strings for all recipients matching a segment's
        # UserGroupFilter attribute. Capped at $MaxUsersPerSegment (0 = unlimited).
        function Resolve-SegmentUsers {
            param(
                [Parameter(Mandatory)][string]$SegmentName
            )
            $seg = $segmentIndex[$SegmentName]
            if (-not $seg) { return @() }

            $filter = $seg.UserGroupFilter
            if (-not $filter) { return @() }

            try {
                $getParams = @{ Filter = $filter; RecipientTypeDetails = @('UserMailbox','GuestMailUser','MailUser'); ErrorAction = 'Stop' }
                if ($MaxUsersPerSegment -gt 0) { $getParams['ResultSize'] = $MaxUsersPerSegment }
                $recipients = @(Get-EXORecipient @getParams)
                # UserPrincipalName may be blank with REST-based cmdlets for some recipient types;
                # fall back to PrimarySmtpAddress so the identity can still be looked up.
                return $recipients | ForEach-Object {
                    if (-not [string]::IsNullOrWhiteSpace($_.UserPrincipalName)) { $_.UserPrincipalName }
                    elseif (-not [string]::IsNullOrWhiteSpace($_.PrimarySmtpAddress)) { $_.PrimarySmtpAddress }
                }
            }
            catch {
                Write-ToLogFile -StringObject "  WARN: Could not enumerate users for segment '$SegmentName': $($_.Exception.Message)" `
                    -LogFile $logFile -ForegroundColor Yellow -LogOnly
                return @()
            }
        }

        #endregion

        #region ── Helper: Build a record for one UPN ─────────────────────────

        function Build-IBRecord {
            param([Parameter(Mandatory)][string]$UPN)

            Write-ToLogFile -StringObject "  Processing: $UPN" -LogFile $logFile

            # Resolve identity (handles both internal and guest EXT UPNs)
            $recipient = $null
            try {
                $recipient = Get-EXORecipient -Identity $UPN -ErrorAction Stop
            }
            catch {
                try {
                    # Try resolving by primary SMTP (guests may be addressed by alias)
                    $recipient = Get-EXORecipient -Filter "PrimarySmtpAddress -eq '$UPN'" -ErrorAction Stop |
                                 Select-Object -First 1
                }
                catch {
                    try {
                        # Final fallback: use Get-Recipient (non-EXO) which works for some recipient types
                        $recipient = Get-Recipient -Identity $UPN -ErrorAction Stop
                    }
                    catch {
                        Write-ToLogFile -StringObject "  WARN: Could not resolve recipient '$UPN'. $($_.Exception.Message)" `
                            -LogFile $logFile -ForegroundColor Yellow
                    }
                }
            }

            # Normalise display name — Get-Recipient may return it in a different property
            if ($recipient -and [string]::IsNullOrWhiteSpace($recipient.DisplayName)) {
                $candidate = $recipient.PSObject.Properties | Where-Object { $_.Name -like '*name*' -and $_.Value } | Select-Object -First 1
                if ($candidate) { $recipient | Add-Member -NotePropertyName DisplayName -NotePropertyValue $candidate.Value -Force }
            }

            $displayName  = if ($recipient) { $recipient.DisplayName }  else { $UPN }
            $accountType  = if ($recipient) {
                switch ($recipient.RecipientTypeDetails) {
                    'GuestMailUser' { 'Guest' }
                    'UserMailbox'   { 'Internal' }
                    'MailUser'      { 'MailUser' }
                    default         { $recipient.RecipientTypeDetails }
                }
            } else { 'Unknown' }

            # Get IB recipient status
            $ibStatus      = 'Unknown'
            $userSegments  = @()
            $activePolicies = @()

            if ($script:isIBv2) {
                # IB v2: Get-InformationBarrierRecipientStatus is not available; read segment membership from Get-Recipient
                try {
                    $recipientFull = Get-Recipient -Identity $UPN -ErrorAction Stop
                    # IB v2 stores segment membership in a property like OrganizationSegment,
                    # InformationBarrierSegment, or similar. Search broadly.
                    $segProp = $recipientFull.PSObject.Properties |
                               Where-Object { ($_.Name -like '*segment*' -or $_.Name -like '*barrier*') -and $_.Value } |
                               Select-Object -First 1
                    if ($segProp) {
                        $rawValue = $segProp.Value
                        # Value may be a single string, an array, or a semicolon-delimited string
                        if ($rawValue -is [System.Collections.IEnumerable] -and $rawValue -isnot [string]) {
                            $rawSegments = @($rawValue) | Where-Object { $_ }
                        } else {
                            $rawSegments = @($rawValue -split '[;,]') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                        }
                        # Translate GUIDs to segment names using the pre-built lookup
                        $userSegments = $rawSegments | ForEach-Object {
                            if ($segmentGuidToName.ContainsKey($_)) { $segmentGuidToName[$_] } else { $_ }
                        }
                        Write-ToLogFile -StringObject "  IB v2 segment property '$($segProp.Name)': $($userSegments -join ', ')" `
                            -LogFile $logFile -ForegroundColor DarkGray
                    } else {
                        # Log all properties for diagnostics so we can identify the right property name
                        $allProps = ($recipientFull.PSObject.Properties | Select-Object -ExpandProperty Name) -join ', '
                        Write-ToLogFile -StringObject "  IB v2: no segment property found. Available properties: $allProps" `
                            -LogFile $logFile -ForegroundColor DarkGray
                    }
                }
                catch {
                    $ibStatus = 'Error'
                    Write-ToLogFile -StringObject "  ERROR: Get-Recipient (IB v2) failed for '$UPN'. $($_.Exception.Message)" `
                        -LogFile $logFile -ForegroundColor Red
                }

                if ($ibStatus -ne 'Error') {
                    # Derive active policy names for this user's segments from the cached policy list
                    foreach ($segName in $userSegments) {
                        $allPolicies | Where-Object { $_.AssignedSegment -eq $segName } | ForEach-Object {
                            if ($activePolicies -notcontains $_.Name) { $activePolicies += $_.Name }
                        }
                    }

                    if ($userSegments.Count -eq 0) {
                        $ibStatus = 'NoSegment'
                    }
                    elseif ($activePolicies.Count -gt 0) {
                        $ibStatus = 'Active'
                    }
                    else {
                        $ibStatus = 'NoPolicyAssigned'
                    }
                }
            }
            else {
                # IB v1: use Get-InformationBarrierRecipientStatus
                try {
                    $ibRecipient = Get-InformationBarrierRecipientStatus -Identity $UPN -ErrorAction Stop

                    if ($ibRecipient.ExoSegments -and $ibRecipient.ExoSegments.Count -gt 0) {
                        $userSegments = @($ibRecipient.ExoSegments)
                    }
                    elseif ($ibRecipient.Segments -and $ibRecipient.Segments.Count -gt 0) {
                        $userSegments = @($ibRecipient.Segments)
                    }

                    if ($ibRecipient.ExoPolicies -and $ibRecipient.ExoPolicies.Count -gt 0) {
                        $activePolicies = @($ibRecipient.ExoPolicies)
                    }
                    elseif ($ibRecipient.Policies -and $ibRecipient.Policies.Count -gt 0) {
                        $activePolicies = @($ibRecipient.Policies)
                    }

                    if ($userSegments.Count -eq 0) {
                        $ibStatus = 'NoSegment'
                    }
                    elseif ($activePolicies.Count -gt 0) {
                        $ibStatus = 'Active'
                    }
                    else {
                        $ibStatus = 'NoPolicyAssigned'
                    }
                }
                catch {
                    $ibStatus = 'Error'
                    Write-ToLogFile -StringObject "  ERROR: Get-InformationBarrierRecipientStatus failed for '$UPN'. $($_.Exception.Message)" `
                        -LogFile $logFile -ForegroundColor Red
                }
            }

            # Identify blocked and allowed segments from matching policies
            $blockedSegments = [System.Collections.Generic.List[string]]::new()
            $allowedSegments = [System.Collections.Generic.List[string]]::new()

            foreach ($segName in $userSegments) {
                foreach ($policy in $allPolicies) {
                    # Policy assigned to THIS user's segment
                    if ($policy.AssignedSegment -eq $segName) {
                        foreach ($blocked in $policy.SegmentsBlocked) {
                            if (-not $blockedSegments.Contains($blocked)) { $blockedSegments.Add($blocked) }
                        }
                        foreach ($allowed in $policy.SegmentsAllowed) {
                            if (-not $allowedSegments.Contains($allowed)) { $allowedSegments.Add($allowed) }
                        }
                    }
                    # Policy assigned to ANOTHER segment that blocks THIS user's segment
                    elseif ($policy.SegmentsBlocked -contains $segName) {
                        if (-not $blockedSegments.Contains($policy.AssignedSegment)) {
                            $blockedSegments.Add($policy.AssignedSegment)
                        }
                    }
                }
            }

            # Enumerate individual users per segment (optional)
            $blockedUsers = @()
            $allowedUsers = @()

            if ($EnumerateUsers) {
                foreach ($seg in $blockedSegments) {
                    $blockedUsers += Resolve-SegmentUsers -SegmentName $seg
                }
                foreach ($seg in $allowedSegments) {
                    $allowedUsers += Resolve-SegmentUsers -SegmentName $seg
                }
            }

            $record = [pscustomobject]@{
                UPN             = $UPN
                DisplayName     = $displayName
                AccountType     = $accountType
                IBStatus        = $ibStatus
                Segments        = ($userSegments -join '; ')
                ActivePolicies  = ($activePolicies -join '; ')
                BlockedSegments = ($blockedSegments -join '; ')
                AllowedSegments = ($allowedSegments -join '; ')
                BlockedUsers    = ($blockedUsers -join '; ')
                AllowedUsers    = ($allowedUsers -join '; ')
            }
            $record.PSObject.TypeNames.Insert(0, 'InformationBarrierUserReport.Record')
            return $record
        }

        #endregion
    }

    process {
        #region ── -ListAll mode ──────────────────────────────────────────────

        if ($ListAll) {
            Write-ToLogFile -StringObject $separator -LogFile $logFile
            Write-ToLogFile -StringObject 'MODE: List All Segment Relationships' -LogFile $logFile -ForegroundColor Cyan
            Write-ToLogFile -StringObject $separator -LogFile $logFile

            $matrixRows = [System.Collections.Generic.List[pscustomobject]]::new()

            foreach ($policy in $allPolicies) {
                $row = [pscustomobject]@{
                    PolicyName      = $policy.Name
                    State           = $policy.State
                    AssignedSegment = $policy.AssignedSegment
                    BlockedSegments = ($policy.SegmentsBlocked -join '; ')
                    AllowedSegments = ($policy.SegmentsAllowed -join '; ')
                }
                $matrixRows.Add($row)

                $blocked = if ($policy.SegmentsBlocked) { ($policy.SegmentsBlocked -join ', ') } else { 'None' }
                $allowed = if ($policy.SegmentsAllowed) { ($policy.SegmentsAllowed -join ', ') } else { 'None' }

                Write-ToLogFile -StringObject "  Policy   : $($policy.Name)" -LogFile $logFile -ForegroundColor White
                Write-ToLogFile -StringObject "  Segment  : $($policy.AssignedSegment)" -LogFile $logFile
                Write-ToLogFile -StringObject "  Blocked  : $blocked" -LogFile $logFile -ForegroundColor $(if ($policy.SegmentsBlocked) { 'Red' } else { 'DarkGray' })
                Write-ToLogFile -StringObject "  Allowed  : $allowed" -LogFile $logFile -ForegroundColor $(if ($policy.SegmentsAllowed) { 'Green' } else { 'DarkGray' })
                Write-ToLogFile -StringObject '' -LogFile $logFile
            }

            if ($matrixRows.Count -eq 0) {
                Write-ToLogFile -StringObject 'No active Information Barrier policies found in this tenant.' `
                    -LogFile $logFile -ForegroundColor Yellow
            }
            else {
                Write-ToLogFile -StringObject $separator -LogFile $logFile
                Write-ToLogFile -StringObject "Total active policies: $($matrixRows.Count)" -LogFile $logFile -ForegroundColor Cyan
                Write-ToLogFile -StringObject "Total segments       : $($allSegments.Count)"  -LogFile $logFile -ForegroundColor Cyan
                $matrixRows | Format-Table -AutoSize
                $matrixRows | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
                Write-ToLogFile -StringObject "CSV exported: $csvFile" -LogFile $logFile -ForegroundColor DarkGray
            }
            return
        }

        #endregion

        #region ── -Segment mode: discover UPNs in named segment(s) ──────────

        if ($Segment) {
            # Resolve wildcard: match against all loaded segment names
            $matchedSegments = @($allSegments | Where-Object { $_.Name -like $Segment })

            if ($matchedSegments.Count -eq 0) {
                $available = ($allSegments | Select-Object -ExpandProperty Name) -join ', '
                Write-ToLogFile -StringObject "ERROR: No segments matched '$Segment'. Available segments: $available" `
                    -LogFile $logFile -ForegroundColor Red
                throw "No segments matched '$Segment' in this tenant."
            }

            $isWildcard = [System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters($Segment)
            Write-ToLogFile -StringObject $separator -LogFile $logFile
            Write-ToLogFile -StringObject "MODE: Enumerate segment$(if ($matchedSegments.Count -gt 1) { 's' }) matching '$Segment' ($($matchedSegments.Count) matched)" `
                -LogFile $logFile -ForegroundColor Cyan
            Write-ToLogFile -StringObject $separator -LogFile $logFile

            if ($isWildcard) {
                Write-ToLogFile -StringObject "Matched segments: $(($matchedSegments | Select-Object -ExpandProperty Name) -join ', ')" `
                    -LogFile $logFile -ForegroundColor DarkGray
            }

            foreach ($matchedSeg in $matchedSegments) {
                Write-ToLogFile -StringObject "--- Segment: $($matchedSeg.Name) ---" -LogFile $logFile -ForegroundColor DarkCyan

                $segmentUpns = Resolve-SegmentUsers -SegmentName $matchedSeg.Name
                if ($segmentUpns.Count -eq 0) {
                    Write-ToLogFile -StringObject "No users found in segment '$($matchedSeg.Name)' (filter may yield no results or segment uses unsupported attribute)." `
                        -LogFile $logFile -ForegroundColor Yellow
                }
                else {
                    Write-ToLogFile -StringObject "Found $($segmentUpns.Count) user(s) in segment '$($matchedSeg.Name)'. Processing..." `
                        -LogFile $logFile -ForegroundColor Green

                    foreach ($upn in $segmentUpns) {
                        $record = Build-IBRecord -UPN $upn
                        $allRecords.Add($record)
                    }
                }
            }
        }

        #endregion

        #region ── -UserPrincipalName mode ───────────────────────────────────

        if (-not $UserPrincipalName -and -not $Segment -and -not $ListAll) {
            Write-ToLogFile -StringObject 'No -UserPrincipalName, -Segment, or -ListAll specified.' `
                -LogFile $logFile -ForegroundColor Yellow

            do {
                $input = (Read-Host 'Enter UPN(s) to investigate (comma-separated)').Trim()
            } while ([string]::IsNullOrWhiteSpace($input))

            $UserPrincipalName = $input -split '\s*,\s*' | Where-Object { $_ -ne '' }
        }

        if ($UserPrincipalName) {
            foreach ($upn in $UserPrincipalName) {
                $upn = $upn.Trim()
                if ([string]::IsNullOrWhiteSpace($upn)) { continue }

                Write-ToLogFile -StringObject $separator -LogFile $logFile
                Write-ToLogFile -StringObject "Processing UPN: $upn" -LogFile $logFile -ForegroundColor Cyan
                Write-ToLogFile -StringObject $separator -LogFile $logFile

                $record = Build-IBRecord -UPN $upn
                $allRecords.Add($record)

                # Per-user inline report
                $statusColor = switch ($record.IBStatus) {
                    'Active'           { 'Green' }
                    'NoPolicyAssigned' { 'Yellow' }
                    'NoSegment'        { 'DarkYellow' }
                    'Error'            { 'Red' }
                    default            { 'Gray' }
                }

                Write-ToLogFile -StringObject "  Display Name     : $($record.DisplayName)"     -LogFile $logFile
                Write-ToLogFile -StringObject "  Account Type     : $($record.AccountType)"     -LogFile $logFile
                Write-ToLogFile -StringObject "  IB Status        : $($record.IBStatus)"        -LogFile $logFile -ForegroundColor $statusColor
                Write-ToLogFile -StringObject "  Segments         : $(if ($record.Segments) { $record.Segments } else { '(none)' })" -LogFile $logFile
                Write-ToLogFile -StringObject "  Active Policies  : $(if ($record.ActivePolicies)  { $record.ActivePolicies }  else { '(none)' })" -LogFile $logFile
                Write-ToLogFile -StringObject "  Blocked Segments : $(if ($record.BlockedSegments) { $record.BlockedSegments } else { '(none)' })" `
                    -LogFile $logFile -ForegroundColor $(if ($record.BlockedSegments) { 'Red' } else { 'DarkGray' })
                Write-ToLogFile -StringObject "  Allowed Segments : $(if ($record.AllowedSegments) { $record.AllowedSegments } else { '(none)' })" `
                    -LogFile $logFile -ForegroundColor $(if ($record.AllowedSegments) { 'Green' } else { 'DarkGray' })

                if ($EnumerateUsers) {
                    Write-ToLogFile -StringObject "  Blocked Users    : $(if ($record.BlockedUsers) { $record.BlockedUsers } else { '(none)' })" `
                        -LogFile $logFile -ForegroundColor $(if ($record.BlockedUsers) { 'Red' } else { 'DarkGray' })
                    Write-ToLogFile -StringObject "  Allowed Users    : $(if ($record.AllowedUsers) { $record.AllowedUsers } else { '(none)' })" `
                        -LogFile $logFile -ForegroundColor $(if ($record.AllowedUsers) { 'Green' } else { 'DarkGray' })
                }
            }
        }

        #endregion
    }

    end {
        if ($allRecords.Count -eq 0) { return }

        #region ── Summary ────────────────────────────────────────────────────

        Write-ToLogFile -StringObject $separator -LogFile $logFile
        Write-ToLogFile -StringObject 'INFORMATION BARRIER USER REPORT — SUMMARY' -LogFile $logFile -ForegroundColor Cyan
        Write-ToLogFile -StringObject $separator -LogFile $logFile

        $activeCount = ($allRecords | Where-Object IBStatus -eq 'Active').Count
        $noPolicyCount = ($allRecords | Where-Object IBStatus -eq 'NoPolicyAssigned').Count
        $noSegmentCount = ($allRecords | Where-Object IBStatus -eq 'NoSegment').Count
        $errorCount  = ($allRecords | Where-Object IBStatus -eq 'Error').Count

        Write-ToLogFile -StringObject "  Identities processed     : $($allRecords.Count)"    -LogFile $logFile -ForegroundColor White
        Write-ToLogFile -StringObject "  Active IB policies       : $activeCount"             -LogFile $logFile -ForegroundColor $(if ($activeCount   -gt 0) { 'Green' }  else { 'DarkGray' })
        Write-ToLogFile -StringObject "  Segment / no active policy: $noPolicyCount"          -LogFile $logFile -ForegroundColor $(if ($noPolicyCount -gt 0) { 'Yellow' } else { 'DarkGray' })
        Write-ToLogFile -StringObject "  No segment assigned      : $noSegmentCount"          -LogFile $logFile -ForegroundColor $(if ($noSegmentCount -gt 0) { 'DarkYellow' } else { 'DarkGray' })
        Write-ToLogFile -StringObject "  Errors                   : $errorCount"              -LogFile $logFile -ForegroundColor $(if ($errorCount    -gt 0) { 'Red' }    else { 'DarkGray' })
        Write-ToLogFile -StringObject $separator -LogFile $logFile

        #endregion

        #region ── Optional detail views ──────────────────────────────────────

        if ($MediumDetails) {
            Write-ToLogFile -StringObject 'MEDIUM DETAILS — All Records' -LogFile $logFile -ForegroundColor Cyan
            $allRecords | Select-Object UPN, AccountType, IBStatus, Segments, ActivePolicies, BlockedSegments, AllowedSegments |
                Format-Table -AutoSize
        }

        if ($FullDetails) {
            Write-ToLogFile -StringObject 'FULL DETAILS — All Records' -LogFile $logFile -ForegroundColor Cyan
            $allRecords | Format-List
        }

        #endregion

        #region ── CSV export ─────────────────────────────────────────────────

        try {
            $allRecords | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            Write-ToLogFile -StringObject "CSV exported: $csvFile" -LogFile $logFile -ForegroundColor DarkGray
        }
        catch {
            Write-ToLogFile -StringObject "WARN: CSV export failed. $($_.Exception.Message)" `
                -LogFile $logFile -ForegroundColor Yellow
        }

        #endregion

        #region ── Disconnect ─────────────────────────────────────────────────

        if (-not $StayConnected) {
            try {
                Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                Write-ToLogFile -StringObject 'Disconnected from Security and Compliance Center.' `
                    -LogFile $logFile -ForegroundColor DarkGray
            }
            catch {
                # Non-fatal — session may have already expired
            }
        }
        else {
            Write-ToLogFile -StringObject 'Session retained (-StayConnected). Call Disconnect-ExchangeOnline when done.' `
                -LogFile $logFile -ForegroundColor Cyan
        }

        #endregion

        Write-ToLogFile -StringObject 'Get-InformationBarrierUserReport complete.' -LogFile $logFile -ForegroundColor Green
        Write-ToLogFile -StringObject $separator -LogFile $logFile

        # Return the records to the pipeline for further processing
        return $allRecords
    }
}
