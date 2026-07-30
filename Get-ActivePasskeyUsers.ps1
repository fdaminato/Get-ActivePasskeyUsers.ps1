<#
.SYNOPSIS
    Generates CSV and interactive HTML reports for enabled Microsoft Entra ID
    users who have at least one currently registered passkey (FIDO2) method.

.DESCRIPTION
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

.REQUIREMENTS
    Microsoft.Graph.Authentication

.DELEGATED GRAPH PERMISSIONS
    AuditLog.Read.All
    User.Read.All
    UserAuthMethod-Passkey.Read.All

.EXAMPLE
    .\Get-ActivePasskeyUsers.ps1 `
        -TenantId "contoso.onmicrosoft.com" `
        -OpenHtml

.EXAMPLE
    .\Get-ActivePasskeyUsers.ps1 `
        -TenantId "XXXXXXX-52bc-4575-a1c7-6ff0f2802e24" `
        -OpenHtml
        
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CsvPath = "$env:USERPROFILE\Downloads\Active-Passkey-Users.csv",

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$HtmlPath = "$env:USERPROFILE\Downloads\Active-Passkey-Users.html",

    [Parameter()]
    [switch]$IncludeGuests,

    [Parameter()]
    [switch]$UseDeviceCode,

    [Parameter()]
    [switch]$OpenHtml,

    [Parameter(DontShow = $true)]
    [switch]$CleanProcess
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

#region Safe value and formatting helpers

function Get-SafePropertyValue {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter()]
        [AllowNull()]
        [object]$Default = $null
    )

    if ($null -eq $InputObject) {
        return $Default
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) {
            return $InputObject[$Name]
        }

        return $Default
    }

    $Property = $InputObject.PSObject.Properties[$Name]

    if ($null -ne $Property) {
        return $Property.Value
    }

    return $Default
}

function ConvertTo-UtcString {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Value
    )

    if (
        $null -eq $Value -or
        [string]::IsNullOrWhiteSpace([string]$Value)
    ) {
        return $null
    }

    try {
        return ([datetimeoffset]$Value).ToUniversalTime().ToString(
            "yyyy-MM-ddTHH:mm:ssZ"
        )
    }
    catch {
        return [string]$Value
    }
}

function ConvertTo-HtmlText {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Value,

        [Parameter()]
        [string]$Fallback = "—"
    )

    if (
        $null -eq $Value -or
        [string]::IsNullOrWhiteSpace([string]$Value)
    ) {
        return [System.Net.WebUtility]::HtmlEncode($Fallback)
    }

    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Join-UniqueValues {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [object[]]$Values
    )

    return (
        @($Values) |
        Where-Object {
            $null -ne $_ -and
            -not [string]::IsNullOrWhiteSpace([string]$_)
        } |
        ForEach-Object { [string]$_ } |
        Sort-Object -Unique
    ) -join "; "
}

function ConvertTo-CssNumber {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [double]$Value
    )

    return [string]::Format(
        [System.Globalization.CultureInfo]::InvariantCulture,
        "{0:0.##}",
        $Value
    )
}

function New-DonutGradient {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$First,

        [Parameter(Mandatory)]
        [int]$Second,

        [Parameter(Mandatory)]
        [int]$Third,

        [Parameter(Mandatory)]
        [string]$FirstColor,

        [Parameter(Mandatory)]
        [string]$SecondColor,

        [Parameter(Mandatory)]
        [string]$ThirdColor
    )

    $Total = $First + $Second + $Third

    if ($Total -le 0) {
        return "conic-gradient(var(--surface3) 0 100%)"
    }

    $FirstEnd = ($First / $Total) * 100
    $SecondEnd = (($First + $Second) / $Total) * 100

    $FirstEndCss = ConvertTo-CssNumber -Value $FirstEnd
    $SecondEndCss = ConvertTo-CssNumber -Value $SecondEnd

    return (
        "conic-gradient({0} 0 {1}%, {2} {1}% {3}%, {4} {3}% 100%)" -f
        $FirstColor,
        $FirstEndCss,
        $SecondColor,
        $SecondEndCss,
        $ThirdColor
    )
}

function Get-PasskeyTypeLabel {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [string]$Value
    )

    switch -Regex ($Value) {
        "^deviceBound$"       { return "Device-bound" }
        "^synced$"            { return "Synced" }
        "^unknownFutureValue$" { return "Unknown future value" }
        default                { return "Unknown" }
    }
}

function Get-AttestationLabel {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [string]$Value
    )

    switch -Regex ($Value) {
        "^attested$"          { return "Attested" }
        "^notAttested$"       { return "Not attested" }
        "^unknownFutureValue$" { return "Unknown future value" }
        default                { return "Unknown" }
    }
}

function New-PillHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Text,

        [Parameter()]
        [ValidateSet("", "good", "bad", "warn", "info")]
        [string]$Class = ""
    )

    $ClassAttribute = if ([string]::IsNullOrWhiteSpace($Class)) {
        "pill"
    }
    else {
        "pill $Class"
    }

    return '<span class="{0}">{1}</span>' -f `
        $ClassAttribute,
        (ConvertTo-HtmlText -Value $Text)
}

#endregion

#region Microsoft Graph request helpers

function Get-GraphHttpStatusCode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    try {
        $Response = Get-SafePropertyValue `
            -InputObject $ErrorRecord.Exception `
            -Name "Response"

        $StatusCode = Get-SafePropertyValue `
            -InputObject $Response `
            -Name "StatusCode"

        if ($null -ne $StatusCode) {
            return [int]$StatusCode
        }
    }
    catch {
        # Continue with message-based detection.
    }

    $Message = [string]$ErrorRecord.Exception.Message

    if (
        $Message -match
        "\b(400|401|403|404|408|409|429|500|502|503|504)\b"
    ) {
        return [int]$Matches[1]
    }

    return $null
}

function Invoke-GraphGetWithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Uri,

        [Parameter()]
        [hashtable]$Headers,

        [Parameter()]
        [ValidateRange(1, 20)]
        [int]$MaximumAttempts = 6
    )

    for ($Attempt = 1; $Attempt -le $MaximumAttempts; $Attempt++) {
        try {
            $RequestParameters = @{
                Method      = "GET"
                Uri         = $Uri
                OutputType  = "PSObject"
                ErrorAction = "Stop"
            }

            if ($null -ne $Headers -and $Headers.Count -gt 0) {
                $RequestParameters.Headers = $Headers
            }

            return Invoke-MgGraphRequest @RequestParameters
        }
        catch {
            $StatusCode = Get-GraphHttpStatusCode -ErrorRecord $_
            $RetryableStatusCodes = @(408, 429, 500, 502, 503, 504)

            if (
                $Attempt -lt $MaximumAttempts -and
                $StatusCode -in $RetryableStatusCodes
            ) {
                $DelaySeconds = [int][math]::Min(
                    60,
                    [math]::Pow(2, $Attempt)
                )

                Write-Warning (
                    "Microsoft Graph returned HTTP {0}. Retrying in {1} " +
                    "seconds. Attempt {2} of {3}." -f
                    $StatusCode,
                    $DelaySeconds,
                    $Attempt,
                    $MaximumAttempts
                )

                Start-Sleep -Seconds $DelaySeconds
                continue
            }

            throw
        }
    }
}

function Get-GraphCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Uri,

        [Parameter()]
        [hashtable]$Headers
    )

    $Items = [System.Collections.Generic.List[object]]::new()
    $NextLink = $Uri

    while (-not [string]::IsNullOrWhiteSpace($NextLink)) {
        $Page = Invoke-GraphGetWithRetry `
            -Uri $NextLink `
            -Headers $Headers

        $PageValues = Get-SafePropertyValue `
            -InputObject $Page `
            -Name "value" `
            -Default @()

        foreach ($Item in @($PageValues)) {
            if ($null -ne $Item) {
                $Items.Add($Item)
            }
        }

        # Graph only returns @odata.nextLink when another page exists.
        $ReturnedNextLink = Get-SafePropertyValue `
            -InputObject $Page `
            -Name "@odata.nextLink"

        if (
            $null -ne $ReturnedNextLink -and
            -not [string]::IsNullOrWhiteSpace([string]$ReturnedNextLink)
        ) {
            $NextLink = [string]$ReturnedNextLink
        }
        else {
            $NextLink = $null
        }
    }

    return $Items.ToArray()
}

#endregion

#region CSV helper

function Export-ReportCsv {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$InputObject,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Columns
    )

    $Objects = @($InputObject)

    if ($Objects.Count -gt 0) {
        $Objects |
            Select-Object -Property $Columns |
            Export-Csv `
                -LiteralPath $Path `
                -NoTypeInformation `
                -Encoding UTF8

        return
    }

    $CsvHeader = (
        $Columns |
        ForEach-Object {
            '"' + ($_ -replace '"', '""') + '"'
        }
    ) -join ","

    Set-Content `
        -LiteralPath $Path `
        -Value $CsvHeader `
        -Encoding UTF8
}

#endregion

#region Clean-process restart and safe module loading

function Restart-InCleanPowerShell {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Reason
    )

    if ($CleanProcess) {
        $InstalledModules = (
            Get-Module -ListAvailable Microsoft.Graph.Authentication |
            Sort-Object Version -Descending |
            Select-Object Name, Version, ModuleBase |
            Format-Table -AutoSize |
            Out-String
        )

        throw @"
Microsoft.Graph.Authentication could not be loaded in a clean process.

Reason:
$Reason

Installed modules:
$InstalledModules
"@
    }

    if ([string]::IsNullOrWhiteSpace($PSCommandPath)) {
        throw "The script path could not be determined for a clean restart."
    }

    $PowerShellCommand = Get-Command "pwsh.exe" -ErrorAction SilentlyContinue |
        Select-Object -First 1

    if (-not $PowerShellCommand) {
        $PowerShellCommand = Get-Command "pwsh" -ErrorAction SilentlyContinue |
            Select-Object -First 1
    }

    if (-not $PowerShellCommand) {
        $PowerShellCommand = Get-Command "powershell.exe" -ErrorAction SilentlyContinue |
            Select-Object -First 1
    }

    if (-not $PowerShellCommand) {
        throw "No PowerShell executable was found for a clean restart."
    }

    Write-Warning $Reason
    Write-Host "`nRestarting in a clean PowerShell process..." `
        -ForegroundColor Yellow

    $ChildArguments = @(
        "-NoLogo"
        "-NoProfile"
        "-ExecutionPolicy"
        "Bypass"
        "-File"
        $PSCommandPath
    )

    if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
        $ChildArguments += @("-TenantId", $TenantId)
    }

    if (-not [string]::IsNullOrWhiteSpace($CsvPath)) {
        $ChildArguments += @("-CsvPath", $CsvPath)
    }

    if (-not [string]::IsNullOrWhiteSpace($HtmlPath)) {
        $ChildArguments += @("-HtmlPath", $HtmlPath)
    }

    if ($IncludeGuests) { $ChildArguments += "-IncludeGuests" }
    if ($UseDeviceCode) { $ChildArguments += "-UseDeviceCode" }
    if ($OpenHtml) { $ChildArguments += "-OpenHtml" }

    $ChildArguments += "-CleanProcess"

    & $PowerShellCommand.Source @ChildArguments

    if ($null -ne $LASTEXITCODE -and $LASTEXITCODE -ne 0) {
        throw "The clean PowerShell process exited with code $LASTEXITCODE."
    }
}

$LoadedGraphModule = Get-Module Microsoft.Graph.Authentication |
    Sort-Object Version -Descending |
    Select-Object -First 1

if ($LoadedGraphModule) {
    Write-Host (
        "Using already loaded Microsoft.Graph.Authentication {0}" -f
        $LoadedGraphModule.Version
    ) -ForegroundColor DarkGray
}
else {
    $LoadedGraphAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
        Where-Object {
            $_.GetName().Name -eq "Microsoft.Graph.Authentication"
        } |
        Select-Object -First 1

    if ($LoadedGraphAssembly) {
        Restart-InCleanPowerShell -Reason (
            "Microsoft.Graph.Authentication assembly {0} is loaded, but its " +
            "PowerShell module is unavailable in this session." -f
            $LoadedGraphAssembly.GetName().Version
        )

        return
    }

    $AvailableGraphModule = Get-Module `
        -ListAvailable `
        Microsoft.Graph.Authentication |
        Sort-Object Version -Descending |
        Select-Object -First 1

    if (-not $AvailableGraphModule) {
        Write-Host "Installing Microsoft.Graph.Authentication..." `
            -ForegroundColor Cyan

        Install-Module `
            -Name Microsoft.Graph.Authentication `
            -Repository PSGallery `
            -Scope CurrentUser `
            -Force `
            -AllowClobber `
            -ErrorAction Stop

        $AvailableGraphModule = Get-Module `
            -ListAvailable `
            Microsoft.Graph.Authentication |
            Sort-Object Version -Descending |
            Select-Object -First 1
    }

    try {
        Import-Module `
            -Name $AvailableGraphModule.Path `
            -ErrorAction Stop

        $LoadedGraphModule = Get-Module Microsoft.Graph.Authentication |
            Sort-Object Version -Descending |
            Select-Object -First 1

        Write-Host (
            "Loaded Microsoft.Graph.Authentication {0}" -f
            $LoadedGraphModule.Version
        ) -ForegroundColor DarkGray
    }
    catch {
        $ImportError = [string]$_.Exception.Message

        if ($ImportError -match "(?i)(assembly|already loaded|could not load file)") {
            Restart-InCleanPowerShell -Reason (
                "A Microsoft Graph assembly conflict was detected: {0}" -f
                $ImportError
            )

            return
        }

        throw
    }
}

$RequiredGraphCommands = @(
    "Connect-MgGraph"
    "Disconnect-MgGraph"
    "Get-MgContext"
    "Invoke-MgGraphRequest"
)

$MissingGraphCommands = @(
    foreach ($CommandName in $RequiredGraphCommands) {
        if (-not (Get-Command $CommandName -ErrorAction SilentlyContinue)) {
            $CommandName
        }
    }
)

if ($MissingGraphCommands.Count -gt 0) {
    Restart-InCleanPowerShell -Reason (
        "The Graph authentication module is missing required commands: {0}" -f
        ($MissingGraphCommands -join ", ")
    )

    return
}

#endregion

#region Prepare output paths

function Resolve-OutputPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath(
        (Join-Path -Path (Get-Location).Path -ChildPath $Path)
    )
}

$CsvPath = Resolve-OutputPath -Path $CsvPath
$HtmlPath = Resolve-OutputPath -Path $HtmlPath

$CsvDirectory = Split-Path -Path $CsvPath -Parent
$HtmlDirectory = Split-Path -Path $HtmlPath -Parent

foreach ($Directory in @($CsvDirectory, $HtmlDirectory) | Sort-Object -Unique) {
    if (-not (Test-Path -LiteralPath $Directory)) {
        New-Item -Path $Directory -ItemType Directory -Force | Out-Null
    }
}

$CsvBaseName = [System.IO.Path]::GetFileNameWithoutExtension($CsvPath)
$DetailedCsvPath = Join-Path $CsvDirectory "$CsvBaseName-Details.csv"
$FailureCsvPath = Join-Path $CsvDirectory "$CsvBaseName-Failures.csv"

#endregion

#region Connect and retrieve report data

$GraphConnected = $false

try {
    $Scopes = @(
        "AuditLog.Read.All"
        "User.Read.All"
        "UserAuthMethod-Passkey.Read.All"
    )

    $ConnectParameters = @{
        Scopes       = $Scopes
        ContextScope = "Process"
        NoWelcome    = $true
        ErrorAction  = "Stop"
    }

    if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
        $ConnectParameters.TenantId = $TenantId
    }

    if ($UseDeviceCode) {
        $ConnectParameters.UseDeviceAuthentication = $true
    }

    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

    Write-Host "`nConnecting to Microsoft Graph..." -ForegroundColor Cyan
    Connect-MgGraph @ConnectParameters
    $GraphConnected = $true

    $GraphContext = Get-MgContext
    $ConnectedAccount = [string](
        Get-SafePropertyValue -InputObject $GraphContext -Name "Account"
    )
    $ConnectedTenantId = [string](
        Get-SafePropertyValue -InputObject $GraphContext -Name "TenantId"
    )

    Write-Host "Connected account : $ConnectedAccount" -ForegroundColor Green
    Write-Host "Connected tenant  : $ConnectedTenantId" -ForegroundColor Green
    Write-Host "Graph module      : $($LoadedGraphModule.Version)" `
        -ForegroundColor Green

    Write-Host "`nRetrieving the authentication-method registration report..." `
        -ForegroundColor Cyan

    $RegistrationUri = (
        "https://graph.microsoft.com/v1.0/" +
        "reports/authenticationMethods/userRegistrationDetails?`$top=999"
    )

    $RegistrationDetails = @(
        Get-GraphCollection -Uri $RegistrationUri
    )

    Write-Host (
        "Registration records retrieved: {0}" -f
        $RegistrationDetails.Count
    ) -ForegroundColor DarkGray

    $Candidates = [System.Collections.Generic.List[object]]::new()

    foreach ($RegistrationRecord in $RegistrationDetails) {
        $MethodsRegistered = @(
            Get-SafePropertyValue `
                -InputObject $RegistrationRecord `
                -Name "methodsRegistered" `
                -Default @()
        )

        $RegisteredMethodText = (
            $MethodsRegistered |
            ForEach-Object { [string]$_ }
        ) -join ";"

        if ($RegisteredMethodText -notmatch "(?i)(passkey|fido)") {
            continue
        }

        $RegistrationUserType = [string](
            Get-SafePropertyValue `
                -InputObject $RegistrationRecord `
                -Name "userType"
        )

        if (-not $IncludeGuests -and $RegistrationUserType -ieq "guest") {
            continue
        }

        $Candidates.Add($RegistrationRecord)
    }

    Write-Host (
        "Potential passkey users found: {0}" -f
        $Candidates.Count
    ) -ForegroundColor Cyan

    $SummaryResults = [System.Collections.Generic.List[object]]::new()
    $DetailedResults = [System.Collections.Generic.List[object]]::new()
    $Failures = [System.Collections.Generic.List[object]]::new()

    $CurrentCandidate = 0

    foreach ($Candidate in $Candidates) {
        $CurrentCandidate++

        $CandidateUserId = [string](
            Get-SafePropertyValue -InputObject $Candidate -Name "id"
        )
        $CandidateUpn = [string](
            Get-SafePropertyValue `
                -InputObject $Candidate `
                -Name "userPrincipalName"
        )
        $CandidateDisplayName = [string](
            Get-SafePropertyValue `
                -InputObject $Candidate `
                -Name "userDisplayName"
        )

        $PercentComplete = if ($Candidates.Count -gt 0) {
            [math]::Round(($CurrentCandidate / $Candidates.Count) * 100)
        }
        else {
            100
        }

        Write-Progress `
            -Activity "Retrieving registered passkeys" `
            -Status (
                "{0} of {1}: {2}" -f
                $CurrentCandidate,
                $Candidates.Count,
                $CandidateUpn
            ) `
            -PercentComplete $PercentComplete

        if ([string]::IsNullOrWhiteSpace($CandidateUserId)) {
            $Failures.Add(
                [pscustomobject][ordered]@{
                    DisplayName       = $CandidateDisplayName
                    UserPrincipalName = $CandidateUpn
                    UserId            = $null
                    HttpStatusCode     = $null
                    Error             = "The registration report did not return a user ID."
                }
            )

            continue
        }

        try {
            $UserUri = (
                "https://graph.microsoft.com/v1.0/users/" +
                "${CandidateUserId}?" +
                "`$select=id,displayName,userPrincipalName," +
                "accountEnabled,userType"
            )

            $User = Invoke-GraphGetWithRetry -Uri $UserUri

            $UserId = [string](
                Get-SafePropertyValue -InputObject $User -Name "id"
            )
            $DisplayName = [string](
                Get-SafePropertyValue -InputObject $User -Name "displayName"
            )
            $UserPrincipalName = [string](
                Get-SafePropertyValue `
                    -InputObject $User `
                    -Name "userPrincipalName"
            )
            $UserType = [string](
                Get-SafePropertyValue -InputObject $User -Name "userType"
            )
            $AccountEnabled = (
                Get-SafePropertyValue `
                    -InputObject $User `
                    -Name "accountEnabled" `
                    -Default $false
            ) -eq $true

            if (-not $AccountEnabled) {
                continue
            }

            if (-not $IncludeGuests -and $UserType -ieq "guest") {
                continue
            }

            $PasskeyUri = (
                "https://graph.microsoft.com/v1.0/users/" +
                "$UserId/authentication/fido2Methods"
            )

            $Passkeys = @(Get-GraphCollection -Uri $PasskeyUri)

            # The registration report can lag behind deletion events.
            if ($Passkeys.Count -eq 0) {
                continue
            }

            $IsAdmin = (
                Get-SafePropertyValue `
                    -InputObject $Candidate `
                    -Name "isAdmin" `
                    -Default $false
            ) -eq $true

            $IsPasswordlessCapable = (
                Get-SafePropertyValue `
                    -InputObject $Candidate `
                    -Name "isPasswordlessCapable" `
                    -Default $false
            ) -eq $true

            $IsMfaCapable = (
                Get-SafePropertyValue `
                    -InputObject $Candidate `
                    -Name "isMfaCapable" `
                    -Default $false
            ) -eq $true

            $PasskeyTypes = [System.Collections.Generic.List[string]]::new()
            $PasskeyDisplayNames = [System.Collections.Generic.List[string]]::new()
            $PasskeyModels = [System.Collections.Generic.List[string]]::new()
            $AttestationLevels = [System.Collections.Generic.List[string]]::new()
            $AAGUIDs = [System.Collections.Generic.List[string]]::new()
            $RegistrationDates = [System.Collections.Generic.List[datetimeoffset]]::new()

            foreach ($Passkey in $Passkeys) {
                $PasskeyType = [string](
                    Get-SafePropertyValue `
                        -InputObject $Passkey `
                        -Name "passkeyType"
                )
                $PasskeyDisplayName = [string](
                    Get-SafePropertyValue `
                        -InputObject $Passkey `
                        -Name "displayName"
                )
                $PasskeyModel = [string](
                    Get-SafePropertyValue -InputObject $Passkey -Name "model"
                )
                $AttestationLevel = [string](
                    Get-SafePropertyValue `
                        -InputObject $Passkey `
                        -Name "attestationLevel"
                )
                $AAGUID = [string](
                    Get-SafePropertyValue -InputObject $Passkey -Name "aaGuid"
                )
                $CreatedDateTime = Get-SafePropertyValue `
                    -InputObject $Passkey `
                    -Name "createdDateTime"

                if (-not [string]::IsNullOrWhiteSpace($PasskeyType)) {
                    $PasskeyTypes.Add($PasskeyType)
                }
                if (-not [string]::IsNullOrWhiteSpace($PasskeyDisplayName)) {
                    $PasskeyDisplayNames.Add($PasskeyDisplayName)
                }
                if (-not [string]::IsNullOrWhiteSpace($PasskeyModel)) {
                    $PasskeyModels.Add($PasskeyModel)
                }
                if (-not [string]::IsNullOrWhiteSpace($AttestationLevel)) {
                    $AttestationLevels.Add($AttestationLevel)
                }
                if (-not [string]::IsNullOrWhiteSpace($AAGUID)) {
                    $AAGUIDs.Add($AAGUID)
                }

                if (
                    $null -ne $CreatedDateTime -and
                    -not [string]::IsNullOrWhiteSpace([string]$CreatedDateTime)
                ) {
                    try {
                        $RegistrationDates.Add([datetimeoffset]$CreatedDateTime)
                    }
                    catch {
                        # Keep processing if an unexpected date value is returned.
                    }
                }

                $DetailedResults.Add(
                    [pscustomobject][ordered]@{
                        DisplayName            = $DisplayName
                        UserPrincipalName      = $UserPrincipalName
                        UserType               = $UserType
                        AccountEnabled         = $AccountEnabled
                        IsAdmin                = $IsAdmin
                        PasskeyDisplayName      = $PasskeyDisplayName
                        PasskeyType             = $PasskeyType
                        PasskeyTypeLabel        = Get-PasskeyTypeLabel `
                            -Value $PasskeyType
                        Model                   = $PasskeyModel
                        AAGUID                  = $AAGUID
                        AttestationLevel        = $AttestationLevel
                        AttestationLabel        = Get-AttestationLabel `
                            -Value $AttestationLevel
                        RegisteredDateUTC       = ConvertTo-UtcString `
                            -Value $CreatedDateTime
                        AuthenticationMethodId  = Get-SafePropertyValue `
                            -InputObject $Passkey `
                            -Name "id"
                        UserId                  = $UserId
                    }
                )
            }

            $OldestRegistration = $null
            $NewestRegistration = $null

            if ($RegistrationDates.Count -gt 0) {
                $SortedDates = @($RegistrationDates.ToArray() | Sort-Object)
                $OldestRegistration = $SortedDates[0]
                $NewestRegistration = $SortedDates[-1]
            }

            $SummaryResults.Add(
                [pscustomobject][ordered]@{
                    DisplayName                   = $DisplayName
                    UserPrincipalName             = $UserPrincipalName
                    UserType                      = $UserType
                    AccountEnabled                = $AccountEnabled
                    IsAdmin                       = $IsAdmin
                    PasskeyCount                  = $Passkeys.Count
                    PasskeyTypes                  = Join-UniqueValues `
                        -Values $PasskeyTypes.ToArray()
                    PasskeyDisplayNames           = Join-UniqueValues `
                        -Values $PasskeyDisplayNames.ToArray()
                    PasskeyModels                 = Join-UniqueValues `
                        -Values $PasskeyModels.ToArray()
                    AttestationLevels             = Join-UniqueValues `
                        -Values $AttestationLevels.ToArray()
                    AAGUIDs                       = Join-UniqueValues `
                        -Values $AAGUIDs.ToArray()
                    OldestPasskeyRegistrationUTC  = ConvertTo-UtcString `
                        -Value $OldestRegistration
                    NewestPasskeyRegistrationUTC  = ConvertTo-UtcString `
                        -Value $NewestRegistration
                    IsPasswordlessCapable         = $IsPasswordlessCapable
                    IsMfaCapable                  = $IsMfaCapable
                    RegisteredMethods             = Join-UniqueValues `
                        -Values @(
                            Get-SafePropertyValue `
                                -InputObject $Candidate `
                                -Name "methodsRegistered" `
                                -Default @()
                        )
                    ReportLastUpdatedUTC          = ConvertTo-UtcString `
                        -Value (
                            Get-SafePropertyValue `
                                -InputObject $Candidate `
                                -Name "lastUpdatedDateTime"
                        )
                    UserId                        = $UserId
                }
            )
        }
        catch {
            $StatusCode = Get-GraphHttpStatusCode -ErrorRecord $_

            $Failures.Add(
                [pscustomobject][ordered]@{
                    DisplayName       = $CandidateDisplayName
                    UserPrincipalName = $CandidateUpn
                    UserId            = $CandidateUserId
                    HttpStatusCode     = $StatusCode
                    Error             = [string]$_.Exception.Message
                }
            )

            Write-Warning (
                "Unable to process {0}: {1}" -f
                $CandidateUpn,
                $_.Exception.Message
            )
        }
    }

    Write-Progress -Activity "Retrieving registered passkeys" -Completed

    $FinalSummary = @(
        $SummaryResults.ToArray() |
        Sort-Object UserPrincipalName
    )
    $FinalDetails = @(
        $DetailedResults.ToArray() |
        Sort-Object UserPrincipalName, RegisteredDateUTC
    )
    $FinalFailures = @(
        $Failures.ToArray() |
        Sort-Object UserPrincipalName
    )

    #region CSV exports

    $SummaryColumns = @(
        "DisplayName"
        "UserPrincipalName"
        "UserType"
        "AccountEnabled"
        "IsAdmin"
        "PasskeyCount"
        "PasskeyTypes"
        "PasskeyDisplayNames"
        "PasskeyModels"
        "AttestationLevels"
        "AAGUIDs"
        "OldestPasskeyRegistrationUTC"
        "NewestPasskeyRegistrationUTC"
        "IsPasswordlessCapable"
        "IsMfaCapable"
        "RegisteredMethods"
        "ReportLastUpdatedUTC"
        "UserId"
    )

    $DetailColumns = @(
        "DisplayName"
        "UserPrincipalName"
        "UserType"
        "AccountEnabled"
        "IsAdmin"
        "PasskeyDisplayName"
        "PasskeyType"
        "PasskeyTypeLabel"
        "Model"
        "AAGUID"
        "AttestationLevel"
        "AttestationLabel"
        "RegisteredDateUTC"
        "AuthenticationMethodId"
        "UserId"
    )

    $FailureColumns = @(
        "DisplayName"
        "UserPrincipalName"
        "UserId"
        "HttpStatusCode"
        "Error"
    )

    Export-ReportCsv `
        -InputObject $FinalSummary `
        -Path $CsvPath `
        -Columns $SummaryColumns

    Export-ReportCsv `
        -InputObject $FinalDetails `
        -Path $DetailedCsvPath `
        -Columns $DetailColumns

    if ($FinalFailures.Count -gt 0) {
        Export-ReportCsv `
            -InputObject $FinalFailures `
            -Path $FailureCsvPath `
            -Columns $FailureColumns
    }
    elseif (Test-Path -LiteralPath $FailureCsvPath) {
        Remove-Item -LiteralPath $FailureCsvPath -Force
    }

    #endregion

    #region HTML calculations and rows

    $TotalUsers = $FinalSummary.Count
    $TotalPasskeys = $FinalDetails.Count
    $AdminUsers = @($FinalSummary | Where-Object { $_.IsAdmin -eq $true }).Count
    $StandardUsers = [math]::Max(0, $TotalUsers - $AdminUsers)
    $MemberUsers = @(
        $FinalSummary |
        Where-Object { $_.UserType -ieq "member" }
    ).Count
    $GuestUsers = @(
        $FinalSummary |
        Where-Object { $_.UserType -ieq "guest" }
    ).Count

    $DeviceBoundCount = @(
        $FinalDetails |
        Where-Object { $_.PasskeyType -ieq "deviceBound" }
    ).Count
    $SyncedCount = @(
        $FinalDetails |
        Where-Object { $_.PasskeyType -ieq "synced" }
    ).Count
    $UnknownTypeCount = [math]::Max(
        0,
        $TotalPasskeys - $DeviceBoundCount - $SyncedCount
    )

    $AttestedCount = @(
        $FinalDetails |
        Where-Object { $_.AttestationLevel -ieq "attested" }
    ).Count
    $NotAttestedCount = @(
        $FinalDetails |
        Where-Object { $_.AttestationLevel -ieq "notAttested" }
    ).Count
    $UnknownAttestationCount = [math]::Max(
        0,
        $TotalPasskeys - $AttestedCount - $NotAttestedCount
    )

    $PasskeyTypeGradient = New-DonutGradient `
        -First $DeviceBoundCount `
        -Second $SyncedCount `
        -Third $UnknownTypeCount `
        -FirstColor "var(--accent)" `
        -SecondColor "var(--green)" `
        -ThirdColor "var(--amber)"

    $PrivilegeGradient = New-DonutGradient `
        -First $AdminUsers `
        -Second $StandardUsers `
        -Third 0 `
        -FirstColor "var(--red)" `
        -SecondColor "var(--accent)" `
        -ThirdColor "var(--surface3)"

    $AttestationGradient = New-DonutGradient `
        -First $AttestedCount `
        -Second $NotAttestedCount `
        -Third $UnknownAttestationCount `
        -FirstColor "var(--green)" `
        -SecondColor "var(--amber)" `
        -ThirdColor "var(--red)"

    $DistinctModels = @(
        $FinalDetails |
        ForEach-Object {
            if (-not [string]::IsNullOrWhiteSpace([string]$_.Model)) {
                ([string]$_.Model).Trim()
            }
        } |
        Sort-Object -Unique
    )

    $HasUnknownModel = @(
        $FinalDetails |
        Where-Object { [string]::IsNullOrWhiteSpace([string]$_.Model) }
    ).Count -gt 0

    $UserModelFiltersBuilder = [System.Text.StringBuilder]::new()
    $PasskeyModelFiltersBuilder = [System.Text.StringBuilder]::new()

    foreach ($Model in $DistinctModels) {
        $EncodedModel = ConvertTo-HtmlText -Value $Model

        [void]$UserModelFiltersBuilder.AppendLine(
            '<label class="check-filter"><input class="user-filter" type="checkbox" data-filter="model" value="{0}">{0}</label>' -f
            $EncodedModel
        )
        [void]$PasskeyModelFiltersBuilder.AppendLine(
            '<label class="check-filter"><input class="passkey-filter" type="checkbox" data-filter="model" value="{0}">{0}</label>' -f
            $EncodedModel
        )
    }

    if ($HasUnknownModel) {
        [void]$UserModelFiltersBuilder.AppendLine(
            '<label class="check-filter"><input class="user-filter" type="checkbox" data-filter="model" value="__unknown__">Unknown</label>'
        )
        [void]$PasskeyModelFiltersBuilder.AppendLine(
            '<label class="check-filter"><input class="passkey-filter" type="checkbox" data-filter="model" value="__unknown__">Unknown</label>'
        )
    }

    if ($DistinctModels.Count -eq 0 -and -not $HasUnknownModel) {
        [void]$UserModelFiltersBuilder.AppendLine(
            '<span class="filter-empty">No models available</span>'
        )
        [void]$PasskeyModelFiltersBuilder.AppendLine(
            '<span class="filter-empty">No models available</span>'
        )
    }

    $UserModelFilterValuesByUserId = @{}

    foreach ($DetailRow in $FinalDetails) {
        $ModelUserId = [string]$DetailRow.UserId

        if ([string]::IsNullOrWhiteSpace($ModelUserId)) {
            continue
        }

        if (-not $UserModelFilterValuesByUserId.ContainsKey($ModelUserId)) {
            $UserModelFilterValuesByUserId[$ModelUserId] = @()
        }

        $ModelFilterValue = if (
            [string]::IsNullOrWhiteSpace([string]$DetailRow.Model)
        ) {
            "__unknown__"
        }
        else {
            ([string]$DetailRow.Model).Trim()
        }

        if (
            $ModelFilterValue -notin
            @($UserModelFilterValuesByUserId[$ModelUserId])
        ) {
            $UserModelFilterValuesByUserId[$ModelUserId] = @(
                $UserModelFilterValuesByUserId[$ModelUserId]
            ) + $ModelFilterValue
        }
    }

    $UserRowsBuilder = [System.Text.StringBuilder]::new()

    foreach ($Row in $FinalSummary) {
        $AdminPill = if ($Row.IsAdmin) {
            New-PillHtml -Text "Administrator" -Class "warn"
        }
        else {
            New-PillHtml -Text "Standard user" -Class "info"
        }

        $UserTypeClass = if ($Row.UserType -ieq "guest") { "warn" } else { "" }
        $UserTypePill = New-PillHtml `
            -Text $(if ($Row.UserType) { $Row.UserType } else { "Unknown" }) `
            -Class $UserTypeClass

        $TypePills = [System.Text.StringBuilder]::new()
        $RawTypes = @(
            ([string]$Row.PasskeyTypes -split ";") |
            ForEach-Object { $_.Trim() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        )

        if ($RawTypes.Count -eq 0) {
            [void]$TypePills.Append((New-PillHtml -Text "Unknown" -Class "warn"))
        }
        else {
            foreach ($Type in $RawTypes) {
                $TypeClass = switch -Regex ($Type) {
                    "^deviceBound$" { "info"; break }
                    "^synced$"      { "good"; break }
                    default          { "warn" }
                }

                [void]$TypePills.Append(
                    (New-PillHtml `
                        -Text (Get-PasskeyTypeLabel -Value $Type) `
                        -Class $TypeClass)
                )
                [void]$TypePills.Append(" ")
            }
        }

        $RowUserId = [string]$Row.UserId
        $RowModelFilterValues = "__unknown__"

        if (
            -not [string]::IsNullOrWhiteSpace($RowUserId) -and
            $UserModelFilterValuesByUserId.ContainsKey($RowUserId)
        ) {
            $RowModelFilterValues = @(
                $UserModelFilterValuesByUserId[$RowUserId] |
                Sort-Object
            ) -join ";"
        }

        $RowHtml = @"
<tr data-row="true" data-user-type="$(ConvertTo-HtmlText -Value $Row.UserType -Fallback 'unknown')" data-admin="$(([string]$Row.IsAdmin).ToLowerInvariant())" data-models="$(ConvertTo-HtmlText -Value $RowModelFilterValues -Fallback '__unknown__')">
    <td data-sort="$(ConvertTo-HtmlText -Value $Row.DisplayName)"><strong>$(ConvertTo-HtmlText -Value $Row.DisplayName)</strong></td>
    <td data-sort="$(ConvertTo-HtmlText -Value $Row.UserPrincipalName)">$(ConvertTo-HtmlText -Value $Row.UserPrincipalName)</td>
    <td>$UserTypePill</td>
    <td>$AdminPill</td>
    <td data-sort="$($Row.PasskeyCount)"><strong>$($Row.PasskeyCount)</strong></td>
    <td>$($TypePills.ToString())</td>
    <td>$(ConvertTo-HtmlText -Value $Row.PasskeyDisplayNames)</td>
    <td>$(ConvertTo-HtmlText -Value $Row.PasskeyModels)</td>
    <td class="mono" data-sort="$(ConvertTo-HtmlText -Value $Row.NewestPasskeyRegistrationUTC -Fallback '')">$(ConvertTo-HtmlText -Value $Row.NewestPasskeyRegistrationUTC)</td>
</tr>
"@

        [void]$UserRowsBuilder.AppendLine($RowHtml)
    }

    if ($FinalSummary.Count -eq 0) {
        [void]$UserRowsBuilder.AppendLine(
            '<tr><td colspan="9" class="empty">No enabled users with registered passkeys were found.</td></tr>'
        )
    }

    $PasskeyRowsBuilder = [System.Text.StringBuilder]::new()

    foreach ($Row in $FinalDetails) {
        $TypeClass = switch -Regex ($Row.PasskeyType) {
            "^deviceBound$" { "info"; break }
            "^synced$"      { "good"; break }
            default          { "warn" }
        }
        $TypePill = New-PillHtml `
            -Text $Row.PasskeyTypeLabel `
            -Class $TypeClass

        $AttestationClass = switch -Regex ($Row.AttestationLevel) {
            "^attested$"    { "good"; break }
            "^notAttested$" { "warn"; break }
            default          { "bad" }
        }
        $AttestationPill = New-PillHtml `
            -Text $Row.AttestationLabel `
            -Class $AttestationClass

        $AdminPill = if ($Row.IsAdmin) {
            New-PillHtml -Text "Yes" -Class "warn"
        }
        else {
            New-PillHtml -Text "No"
        }

        $RowHtml = @"
<tr data-row="true" data-user-type="$(ConvertTo-HtmlText -Value $Row.UserType -Fallback 'unknown')" data-admin="$(([string]$Row.IsAdmin).ToLowerInvariant())" data-passkey-type="$(ConvertTo-HtmlText -Value $Row.PasskeyType -Fallback 'unknown')" data-attestation="$(ConvertTo-HtmlText -Value $Row.AttestationLevel -Fallback 'unknown')" data-model="$(ConvertTo-HtmlText -Value $Row.Model -Fallback '')">
    <td data-sort="$(ConvertTo-HtmlText -Value $Row.DisplayName)"><strong>$(ConvertTo-HtmlText -Value $Row.DisplayName)</strong></td>
    <td data-sort="$(ConvertTo-HtmlText -Value $Row.UserPrincipalName)">$(ConvertTo-HtmlText -Value $Row.UserPrincipalName)</td>
    <td>$AdminPill</td>
    <td>$(ConvertTo-HtmlText -Value $Row.PasskeyDisplayName)</td>
    <td>$TypePill</td>
    <td>$(ConvertTo-HtmlText -Value $Row.Model)</td>
    <td class="mono">$(ConvertTo-HtmlText -Value $Row.AAGUID)</td>
    <td>$AttestationPill</td>
    <td class="mono" data-sort="$(ConvertTo-HtmlText -Value $Row.RegisteredDateUTC -Fallback '')">$(ConvertTo-HtmlText -Value $Row.RegisteredDateUTC)</td>
</tr>
"@

        [void]$PasskeyRowsBuilder.AppendLine($RowHtml)
    }

    if ($FinalDetails.Count -eq 0) {
        [void]$PasskeyRowsBuilder.AppendLine(
            '<tr><td colspan="9" class="empty">No registered passkeys were found.</td></tr>'
        )
    }

    $GeneratedDisplay = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss zzz")

    #endregion

    #region Standalone HTML template

    $HtmlTemplate = @'
<!doctype html>
<html lang="en" data-theme="light">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Microsoft Entra Passkey Report</title>
<style> :root { --bg:#f4f7fb; --surface:#ffffff; --surface2:#eef3f9; --surface3:#dde7f2; --border:#e2eaf3; --text:#0f1e33; --muted:#5e7292; --accent:#2563eb; --navy:#1e3a8a; --green:#059669; --green-soft:#d1fae5; --red:#dc2626; --red-soft:#fde2e2; --amber:#d97706; --amber-soft:#fef3c7; --radius:12px; --radius-sm:8px; --shadow:0 2px 6px rgb(30 60 120 / .06), 0 1px 2px rgb(30 60 120 / .04); --shadow-hover:0 8px 22px rgb(30 60 120 / .13); --font:Inter, "Segoe UI", system-ui, -apple-system, BlinkMacSystemFont, Roboto, sans-serif; } [data-theme="dark"] { --bg:#0c1524; --surface:#14213a; --surface2:#1c2c49; --surface3:#284066; --border:#243a5e; --text:#e8f0fb; --muted:#93a7c4; --accent:#60a5fa; --navy:#93c5fd; --green:#34d399; --green-soft:rgba(16,185,129,.15); --red:#f87171; --red-soft:rgba(239,68,68,.15); --amber:#fbbf24; --amber-soft:rgba(245,158,11,.15); --shadow:0 2px 6px rgb(0 0 0 / .30); --shadow-hover:0 8px 22px rgb(0 0 0 / .45); } * { box-sizing:border-box; } html { scroll-behavior:smooth; } body { margin:0; min-height:100vh; background:var(--bg); color:var(--text); font:14px/1.45 var(--font); } button, input { font:inherit; } header { position:sticky; top:0; z-index:100; } .topbar { min-height:68px; display:flex; align-items:center; gap:18px; padding:12px 28px; background:var(--surface); border-top:3px solid var(--accent); border-bottom:1px solid var(--border); box-shadow:var(--shadow); } .brand-left { min-width:0; display:flex; align-items:center; gap:12px; } .logo-fallback { width:38px; height:38px; min-width:38px; overflow:hidden; padding:0 7px; border-radius:10px; display:flex; align-items:center; justify-content:center; background:linear-gradient(135deg,var(--accent),var(--navy)); color:#fff; font-size:10px; line-height:1.05; text-align:center; font-weight:800; box-shadow:var(--shadow); } h1 { margin:0; font-size:16px; line-height:1.2; letter-spacing:-.01em; } .subtitle { margin-top:3px; color:var(--muted); font-size:11.5px; } .topbar-actions { margin-left:auto; display:flex; align-items:center; gap:10px; } .btn { border:1px solid var(--border); border-radius:var(--radius-sm); padding:8px 12px; background:var(--surface); color:var(--text); cursor:pointer; font-size:12.5px; font-weight:600; white-space:nowrap; transition:.15s ease; } .btn:hover { background:var(--surface2); transform:translateY(-1px); } .generated { min-width:164px; padding-left:12px; border-left:1px solid var(--border); color:var(--muted); font-size:11.5px; line-height:1.35; text-align:right; } .generated strong { color:var(--text); font-weight:700; } .layout { max-width:1800px; margin:0 auto; padding:26px 32px 38px; } .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:14px; margin-bottom:26px; } .grid > .card { position:relative; min-height:132px; padding:16px 17px; background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); box-shadow:var(--shadow); overflow:hidden; transition:.15s ease; } .grid > .card:hover { box-shadow:var(--shadow-hover); transform:translateY(-1px); } .grid > .card::before { content:""; position:absolute; top:0; left:0; right:0; height:3px; background:var(--accent); opacity:.8; } .card-title { color:var(--muted); font-size:10.5px; font-weight:700; line-height:1.35; text-transform:uppercase; letter-spacing:.055em; } .card-value { margin-top:9px; color:var(--text); font-size:27px; font-weight:800; line-height:1; letter-spacing:-.025em; } .card-note { margin-top:7px; color:var(--muted); font-size:11.5px; line-height:1.4; } .good { color:var(--green) !important; } .bad { color:var(--red) !important; } .warn { color:var(--amber) !important; } .info { color:var(--accent) !important; } .section { margin-top:26px; } .section h2 { display:flex; align-items:center; gap:8px; margin:0 0 13px; color:var(--muted); font-size:12.5px; font-weight:800; text-transform:uppercase; letter-spacing:.065em; } .section h2::before { content:""; width:4px; height:17px; border-radius:999px; background:var(--accent); } .mini-grid { display:grid; grid-template-columns:repeat(3,minmax(260px,1fr)); gap:14px; } .section .card { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); box-shadow:var(--shadow); } .chart-card { min-height:204px; display:grid; grid-template-columns:138px minmax(0,1fr); align-items:center; gap:17px; padding:16px; } .pie { position:relative; width:132px; height:132px; border-radius:50%; box-shadow:inset 0 0 0 1px var(--border); } .pie::after { content:""; position:absolute; inset:26px; background:var(--surface); border:1px solid var(--border); border-radius:50%; } .pie-center { position:absolute; inset:0; z-index:1; display:flex; align-items:center; justify-content:center; color:var(--text); font-size:18px; font-weight:800; } .legend { display:grid; gap:8px; color:var(--text); font-size:12px; } .legend-row { display:grid; grid-template-columns:11px 1fr auto; gap:8px; align-items:center; } .legend-row strong { color:var(--text); font-size:11.5px; } .dot { width:10px; height:10px; border-radius:999px; } .dot.green { background:var(--green); } .dot.red { background:var(--red); } .dot.blue { background:var(--accent); } .dot.orange { background:var(--amber); } .toolbar { display:flex; gap:9px; flex-wrap:wrap; padding:14px; background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); box-shadow:var(--shadow); margin-bottom:13px; } input { min-height:38px; padding:8px 10px; background:var(--surface); border:1px solid var(--border); border-radius:var(--radius-sm); color:var(--text); font-size:12.5px; min-width:360px; } input::placeholder { color:var(--muted); } .table-wrap { overflow:auto; max-height:760px; background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); box-shadow:var(--shadow); } table { width:100%; border-collapse:collapse; font-size:12.5px; white-space:nowrap; } th { position:sticky; top:0; z-index:2; padding:11px 12px; background:var(--surface2); border-bottom:1px solid var(--border); color:var(--muted); text-align:left; font-size:10px; font-weight:800; text-transform:uppercase; letter-spacing:.045em; cursor:pointer; } td { padding:10px 12px; border-bottom:1px solid var(--border); vertical-align:top; } tbody tr:hover td { background:var(--surface2); } tbody tr:last-child td { border-bottom:0; } .pill { display:inline-flex; align-items:center; padding:3px 8px; border:1px solid var(--border); border-radius:999px; background:var(--surface3); color:var(--muted); font-size:10.5px; font-weight:700; } .pill.good { background:var(--green-soft); border-color:transparent; color:var(--green) !important; } .pill.bad { background:var(--red-soft); border-color:transparent; color:var(--red) !important; } .pill.warn { background:var(--amber-soft); border-color:transparent; color:var(--amber) !important; } footer { max-width:1800px; margin:0 auto; padding:0 32px 32px; color:var(--muted); font-size:11.5px; } @media (max-width:1180px) { .mini-grid { grid-template-columns:1fr; } } @media print { header { position:static; } .topbar-actions .btn, .toolbar { display:none !important; } .table-wrap, .grid > .card, .section .card { box-shadow:none; } } </style>
<style>
.toolbar { align-items:flex-start; }
.toolbar input[type="search"] { flex:1 1 360px; }
.toolbar .btn { min-height:38px; align-self:center; }
.filter-group { display:flex; flex-wrap:wrap; align-items:center; gap:6px; min-height:38px; padding:5px 7px; background:var(--surface2); border:1px solid var(--border); border-radius:var(--radius-sm); }
.filter-group-title { margin:0 3px 0 1px; color:var(--muted); font-size:10px; font-weight:800; text-transform:uppercase; letter-spacing:.045em; white-space:nowrap; } .model-filter-group { max-width:100%; max-height:116px; overflow:auto; align-content:flex-start; } .filter-empty { padding:3px 8px; color:var(--muted); font-size:11.5px; font-style:italic; }
.check-filter { position:relative; display:inline-flex; align-items:center; gap:6px; min-height:26px; padding:3px 8px; background:var(--surface); border:1px solid var(--border); border-radius:999px; color:var(--text); font-size:11.5px; font-weight:600; cursor:pointer; user-select:none; transition:.15s ease; }
.check-filter:hover { background:var(--surface3); }
.check-filter:has(input:focus-visible) { outline:2px solid var(--accent); outline-offset:2px; }
.check-filter input[type="checkbox"] { width:14px; height:14px; min-width:14px; min-height:14px; margin:0; padding:0; border-radius:4px; accent-color:var(--accent); cursor:pointer; }
.check-filter:has(input:not(:checked)) { color:var(--muted); opacity:.68; }
.table-meta { margin-left:auto; align-self:center; color:var(--muted); font-size:11.5px; font-weight:600; white-space:nowrap; }
.mono { font-family:"Cascadia Mono",Consolas,monospace; font-size:11.5px; }
.empty { padding:32px !important; color:var(--muted); text-align:center; }
.note-card { padding:15px 17px; color:var(--muted); font-size:12px; }
.note-card strong { color:var(--text); }
.chart-copy { min-width:0; }
.chart-copy h3 { margin:0 0 10px; font-size:13px; }
.hidden-row { display:none; }
th[aria-sort="ascending"]::after { content:" ▲"; color:var(--accent); }
th[aria-sort="descending"]::after { content:" ▼"; color:var(--accent); }
@media (max-width:760px) { .topbar { align-items:flex-start; padding:12px 16px; flex-wrap:wrap; } .topbar-actions { width:100%; margin-left:0; } .generated { margin-left:auto; } .layout { padding:20px 14px 30px; } .toolbar input[type="search"] { min-width:100%; width:100%; } .filter-group { width:100%; } .table-meta { width:100%; margin-left:0; } footer { padding:0 14px 24px; } }
</style>
</head>
<body>
<header>
  <div class="topbar">
    <div class="brand-left">
      <div class="logo-fallback">ENTRA</div>
      <div>
        <h1>Microsoft Entra Passkey Report</h1>
        <div class="subtitle">Enabled users with currently registered passkey (FIDO2) authentication methods</div>
      </div>
    </div>
    <div class="topbar-actions">
      <button class="btn" id="themeToggle" type="button">Dark mode</button>
      <button class="btn" id="printBtn" type="button">Print report</button>
      <div class="generated"><strong>Generated</strong><br>{{GENERATED}}</div>
    </div>
  </div>
</header>

<main class="layout">
  <section class="grid">
    <div class="card"><div class="card-title">Enabled users</div><div class="card-value info">{{TOTAL_USERS}}</div><div class="card-note">Accounts with at least one current passkey</div></div>
    <div class="card"><div class="card-title">Registered passkeys</div><div class="card-value">{{TOTAL_PASSKEYS}}</div><div class="card-note">Total FIDO2 method objects</div></div>
    <div class="card"><div class="card-title">Device-bound</div><div class="card-value info">{{DEVICE_BOUND}}</div><div class="card-note">Hardware or device-bound credentials</div></div>
    <div class="card"><div class="card-title">Synced</div><div class="card-value good">{{SYNCED}}</div><div class="card-note">Passkeys synchronized by a provider</div></div>
    <div class="card"><div class="card-title">Administrators</div><div class="card-value warn">{{ADMIN_USERS}}</div><div class="card-note">Privileged accounts with passkeys</div></div>
    <div class="card"><div class="card-title">Processing failures</div><div class="card-value {{FAILURE_CLASS}}">{{FAILURES}}</div><div class="card-note">Requests that could not be completed</div></div>
  </section>

  <section class="section">
    <h2>Registration overview</h2>
    <div class="mini-grid">
      <div class="card chart-card">
        <div class="pie" style="background:{{PASSKEY_GRADIENT}}"><div class="pie-center">{{TOTAL_PASSKEYS}}</div></div>
        <div class="chart-copy"><h3>Passkey type</h3><div class="legend">
          <div class="legend-row"><span class="dot blue"></span><span>Device-bound</span><strong>{{DEVICE_BOUND}}</strong></div>
          <div class="legend-row"><span class="dot green"></span><span>Synced</span><strong>{{SYNCED}}</strong></div>
          <div class="legend-row"><span class="dot orange"></span><span>Unknown</span><strong>{{UNKNOWN_TYPE}}</strong></div>
        </div></div>
      </div>
      <div class="card chart-card">
        <div class="pie" style="background:{{PRIVILEGE_GRADIENT}}"><div class="pie-center">{{TOTAL_USERS}}</div></div>
        <div class="chart-copy"><h3>User privilege</h3><div class="legend">
          <div class="legend-row"><span class="dot red"></span><span>Administrators</span><strong>{{ADMIN_USERS}}</strong></div>
          <div class="legend-row"><span class="dot blue"></span><span>Standard users</span><strong>{{STANDARD_USERS}}</strong></div>
          <div class="legend-row"><span class="dot orange"></span><span>Guests</span><strong>{{GUEST_USERS}}</strong></div>
        </div></div>
      </div>
      <div class="card chart-card">
        <div class="pie" style="background:{{ATTESTATION_GRADIENT}}"><div class="pie-center">{{TOTAL_PASSKEYS}}</div></div>
        <div class="chart-copy"><h3>Attestation</h3><div class="legend">
          <div class="legend-row"><span class="dot green"></span><span>Attested</span><strong>{{ATTESTED}}</strong></div>
          <div class="legend-row"><span class="dot orange"></span><span>Not attested</span><strong>{{NOT_ATTESTED}}</strong></div>
          <div class="legend-row"><span class="dot red"></span><span>Unknown</span><strong>{{UNKNOWN_ATTESTATION}}</strong></div>
        </div></div>
      </div>
    </div>
  </section>

  <section class="section">
    <h2>Users with passkeys</h2>
    <div class="toolbar">
      <input id="userSearch" type="search" placeholder="Search display name, UPN, model, or passkey...">
      <div class="filter-group" role="group" aria-label="User type filters">
        <span class="filter-group-title">User type</span>
        <label class="check-filter"><input class="user-filter" type="checkbox" data-filter="userType" value="member">Members</label>
        <label class="check-filter"><input class="user-filter" type="checkbox" data-filter="userType" value="guest">Guests</label>
      </div>
      <div class="filter-group" role="group" aria-label="Privilege filters">
        <span class="filter-group-title">Privilege</span>
        <label class="check-filter"><input class="user-filter" type="checkbox" data-filter="admin" value="true">Administrators</label>
        <label class="check-filter"><input class="user-filter" type="checkbox" data-filter="admin" value="false">Standard users</label>
      </div>
      <div class="filter-group model-filter-group" role="group" aria-label="Model filters">
        <span class="filter-group-title">Models</span>
        {{USER_MODEL_FILTERS}}
      </div>
      <button class="btn" id="userReset" type="button">Reset filters</button>
      <div class="table-meta" id="userCount">{{TOTAL_USERS}} of {{TOTAL_USERS}} users</div>
    </div>
    <div class="table-wrap">
      <table id="userTable">
        <thead><tr>
          <th>Name</th><th>User principal name</th><th>User type</th><th>Privilege</th><th>Passkeys</th><th>Types</th><th>Display names</th><th>Models</th><th data-type="date">Newest registration UTC</th>
        </tr></thead>
        <tbody>{{USER_ROWS}}</tbody>
      </table>
    </div>
  </section>

  <section class="section">
    <h2>Passkey inventory</h2>
    <div class="toolbar">
      <input id="passkeySearch" type="search" placeholder="Search user, passkey name, model, or AAGUID...">
      <div class="filter-group" role="group" aria-label="Passkey type filters">
        <span class="filter-group-title">Passkey type</span>
        <label class="check-filter"><input class="passkey-filter" type="checkbox" data-filter="passkeyType" value="devicebound">Device-bound</label>
        <label class="check-filter"><input class="passkey-filter" type="checkbox" data-filter="passkeyType" value="synced">Synced</label>
        <label class="check-filter"><input class="passkey-filter" type="checkbox" data-filter="passkeyType" value="unknown">Unknown</label>
      </div>
      <div class="filter-group" role="group" aria-label="Attestation filters">
        <span class="filter-group-title">Attestation</span>
        <label class="check-filter"><input class="passkey-filter" type="checkbox" data-filter="attestation" value="attested">Attested</label>
        <label class="check-filter"><input class="passkey-filter" type="checkbox" data-filter="attestation" value="notattested">Not attested</label>
        <label class="check-filter"><input class="passkey-filter" type="checkbox" data-filter="attestation" value="unknown">Unknown</label>
      </div>
      <div class="filter-group" role="group" aria-label="Privilege filters">
        <span class="filter-group-title">Privilege</span>
        <label class="check-filter"><input class="passkey-filter" type="checkbox" data-filter="admin" value="true">Administrators</label>
        <label class="check-filter"><input class="passkey-filter" type="checkbox" data-filter="admin" value="false">Standard users</label>
      </div>
      <div class="filter-group model-filter-group" role="group" aria-label="Model filters">
        <span class="filter-group-title">Models</span>
        {{PASSKEY_MODEL_FILTERS}}
      </div>
      <button class="btn" id="passkeyReset" type="button">Reset filters</button>
      <div class="table-meta" id="passkeyCount">{{TOTAL_PASSKEYS}} of {{TOTAL_PASSKEYS}} passkeys</div>
    </div>
    <div class="table-wrap">
      <table id="passkeyTable">
        <thead><tr>
          <th>Name</th><th>User principal name</th><th>Admin</th><th>Passkey name</th><th>Type</th><th>Model</th><th>AAGUID</th><th>Attestation</th><th data-type="date">Registered UTC</th>
        </tr></thead>
        <tbody>{{PASSKEY_ROWS}}</tbody>
      </table>
    </div>
  </section>

  <section class="section">
    <h2>Report context</h2>
    <div class="card note-card">
      <strong>Tenant:</strong> {{TENANT_ID}} &nbsp;·&nbsp;
      <strong>Connected account:</strong> {{ACCOUNT}} &nbsp;·&nbsp;
      <strong>Members:</strong> {{MEMBER_USERS}} &nbsp;·&nbsp;
      <strong>Guests:</strong> {{GUEST_USERS}}<br>
      “Active” in this report means that the Entra account is enabled and the passkey method object is currently registered. This report does not indicate recent passkey usage.
    </div>
  </section>
</main>

<footer>Generated from Microsoft Graph v1.0 authentication-method registration and FIDO2 method endpoints.</footer>

<script>
(function () {
  const root = document.documentElement;
  const themeButton = document.getElementById('themeToggle');
  const savedTheme = localStorage.getItem('entra-passkey-report-theme');
  if (savedTheme === 'dark' || savedTheme === 'light') root.dataset.theme = savedTheme;

  function refreshThemeLabel() {
    themeButton.textContent = root.dataset.theme === 'dark' ? 'Light mode' : 'Dark mode';
  }
  refreshThemeLabel();

  themeButton.addEventListener('click', function () {
    root.dataset.theme = root.dataset.theme === 'dark' ? 'light' : 'dark';
    localStorage.setItem('entra-passkey-report-theme', root.dataset.theme);
    refreshThemeLabel();
  });

  document.getElementById('printBtn').addEventListener('click', function () {
    window.print();
  });

  function normalize(value) {
    return (value || '').toString().trim().toLowerCase();
  }

  function setupSortableTable(tableId) {
    const table = document.getElementById(tableId);
    const headers = Array.from(table.querySelectorAll('thead th'));
    headers.forEach(function (header) {
      header.addEventListener('click', function () {
        const tbody = table.tBodies[0];
        const rows = Array.from(tbody.querySelectorAll('tr[data-row="true"]'));
        const columnIndex = header.cellIndex;
        const current = header.getAttribute('aria-sort');
        const direction = current === 'ascending' ? 'descending' : 'ascending';

        headers.forEach(function (item) { item.removeAttribute('aria-sort'); });
        header.setAttribute('aria-sort', direction);

        const type = header.dataset.type || 'text';
        rows.sort(function (a, b) {
          const aCell = a.cells[columnIndex];
          const bCell = b.cells[columnIndex];
          let aValue = aCell.dataset.sort || aCell.textContent.trim();
          let bValue = bCell.dataset.sort || bCell.textContent.trim();

          let result;
          if (type === 'date') {
            const aDate = Date.parse(aValue) || 0;
            const bDate = Date.parse(bValue) || 0;
            result = aDate - bDate;
          } else if (/^-?\d+(\.\d+)?$/.test(aValue) && /^-?\d+(\.\d+)?$/.test(bValue)) {
            result = Number(aValue) - Number(bValue);
          } else {
            result = aValue.localeCompare(bValue, undefined, { numeric:true, sensitivity:'base' });
          }

          return direction === 'ascending' ? result : -result;
        });

        rows.forEach(function (row) { tbody.appendChild(row); });
      });
    });
  }

  function getCheckedValues(container, filterName) {
    return new Set(
      Array.from(container.querySelectorAll('input[type="checkbox"][data-filter="' + filterName + '"]:checked'))
        .map(function (checkbox) { return normalize(checkbox.value); })
    );
  }

  function matchesOptionalCheckedValue(checkedValues, rowValue) {
    return checkedValues.size === 0 || checkedValues.has(normalize(rowValue));
  }

  function normalizeModel(value) {
    const normalized = normalize(value);
    return normalized || '__unknown__';
  }

  function matchesOptionalModels(checkedModels, rowModelsValue) {
    if (checkedModels.size === 0) return true;

    const rowModels = (rowModelsValue || '')
      .split(';')
      .map(normalizeModel)
      .filter(function (value, index, values) {
        return value && values.indexOf(value) === index;
      });

    if (rowModels.length === 0) rowModels.push('__unknown__');
    return rowModels.some(function (model) { return checkedModels.has(model); });
  }

  function setupUserFilters() {
    const table = document.getElementById('userTable');
    const rows = Array.from(table.querySelectorAll('tbody tr[data-row="true"]'));
    const toolbar = table.closest('.section').querySelector('.toolbar');
    const search = document.getElementById('userSearch');
    const checkboxes = Array.from(toolbar.querySelectorAll('.user-filter'));
    const count = document.getElementById('userCount');

    function apply() {
      const query = normalize(search.value);
      const selectedTypes = getCheckedValues(toolbar, 'userType');
      const selectedAdminValues = getCheckedValues(toolbar, 'admin');
      const selectedModels = getCheckedValues(toolbar, 'model');
      let visible = 0;

      rows.forEach(function (row) {
        const matchesSearch = !query || normalize(row.textContent).includes(query);
        const matchesType = matchesOptionalCheckedValue(selectedTypes, row.dataset.userType);
        const matchesAdmin = matchesOptionalCheckedValue(selectedAdminValues, row.dataset.admin);
        const matchesModel = matchesOptionalModels(selectedModels, row.dataset.models);
        const show = matchesSearch && matchesType && matchesAdmin && matchesModel;
        row.classList.toggle('hidden-row', !show);
        if (show) visible++;
      });

      count.textContent = visible + ' of ' + rows.length + ' users';
    }

    search.addEventListener('input', apply);
    checkboxes.forEach(function (checkbox) {
      checkbox.addEventListener('change', apply);
    });

    document.getElementById('userReset').addEventListener('click', function () {
      search.value = '';
      checkboxes.forEach(function (checkbox) { checkbox.checked = false; });
      apply();
    });

    apply();
  }

  function setupPasskeyFilters() {
    const table = document.getElementById('passkeyTable');
    const rows = Array.from(table.querySelectorAll('tbody tr[data-row="true"]'));
    const toolbar = table.closest('.section').querySelector('.toolbar');
    const search = document.getElementById('passkeySearch');
    const checkboxes = Array.from(toolbar.querySelectorAll('.passkey-filter'));
    const count = document.getElementById('passkeyCount');

    function normalizedType(rowValue) {
      const value = normalize(rowValue);
      if (value === 'devicebound' || value === 'synced') return value;
      return 'unknown';
    }

    function normalizedAttestation(rowValue) {
      const value = normalize(rowValue);
      if (value === 'attested' || value === 'notattested') return value;
      return 'unknown';
    }

    function apply() {
      const query = normalize(search.value);
      const selectedTypes = getCheckedValues(toolbar, 'passkeyType');
      const selectedAttestations = getCheckedValues(toolbar, 'attestation');
      const selectedAdminValues = getCheckedValues(toolbar, 'admin');
      const selectedModels = getCheckedValues(toolbar, 'model');
      let visible = 0;

      rows.forEach(function (row) {
        const matchesSearch = !query || normalize(row.textContent).includes(query);
        const matchesType = selectedTypes.size === 0 || selectedTypes.has(normalizedType(row.dataset.passkeyType));
        const matchesAttestation = selectedAttestations.size === 0 || selectedAttestations.has(normalizedAttestation(row.dataset.attestation));
        const matchesAdmin = matchesOptionalCheckedValue(selectedAdminValues, row.dataset.admin);
        const matchesModel = selectedModels.size === 0 || selectedModels.has(normalizeModel(row.dataset.model));
        const show = matchesSearch && matchesType && matchesAttestation && matchesAdmin && matchesModel;
        row.classList.toggle('hidden-row', !show);
        if (show) visible++;
      });

      count.textContent = visible + ' of ' + rows.length + ' passkeys';
    }

    search.addEventListener('input', apply);
    checkboxes.forEach(function (checkbox) {
      checkbox.addEventListener('change', apply);
    });

    document.getElementById('passkeyReset').addEventListener('click', function () {
      search.value = '';
      checkboxes.forEach(function (checkbox) { checkbox.checked = false; });
      apply();
    });

    apply();
  }

  setupSortableTable('userTable');
  setupSortableTable('passkeyTable');
  setupUserFilters();
  setupPasskeyFilters();
})();
</script>
</body>
</html>
'@

    $ReplacementMap = [ordered]@{
        "{{GENERATED}}"              = ConvertTo-HtmlText -Value $GeneratedDisplay
        "{{TOTAL_USERS}}"            = [string]$TotalUsers
        "{{TOTAL_PASSKEYS}}"         = [string]$TotalPasskeys
        "{{DEVICE_BOUND}}"           = [string]$DeviceBoundCount
        "{{SYNCED}}"                 = [string]$SyncedCount
        "{{UNKNOWN_TYPE}}"           = [string]$UnknownTypeCount
        "{{ADMIN_USERS}}"            = [string]$AdminUsers
        "{{STANDARD_USERS}}"         = [string]$StandardUsers
        "{{MEMBER_USERS}}"           = [string]$MemberUsers
        "{{GUEST_USERS}}"            = [string]$GuestUsers
        "{{FAILURES}}"               = [string]$FinalFailures.Count
        "{{FAILURE_CLASS}}"          = $(if ($FinalFailures.Count -gt 0) { "bad" } else { "good" })
        "{{ATTESTED}}"               = [string]$AttestedCount
        "{{NOT_ATTESTED}}"           = [string]$NotAttestedCount
        "{{UNKNOWN_ATTESTATION}}"    = [string]$UnknownAttestationCount
        "{{PASSKEY_GRADIENT}}"       = $PasskeyTypeGradient
        "{{PRIVILEGE_GRADIENT}}"     = $PrivilegeGradient
        "{{ATTESTATION_GRADIENT}}"   = $AttestationGradient
        "{{TENANT_ID}}"              = ConvertTo-HtmlText -Value $ConnectedTenantId
        "{{ACCOUNT}}"                = ConvertTo-HtmlText -Value $ConnectedAccount
        "{{USER_MODEL_FILTERS}}"     = $UserModelFiltersBuilder.ToString()
        "{{PASSKEY_MODEL_FILTERS}}"  = $PasskeyModelFiltersBuilder.ToString()
        "{{USER_ROWS}}"              = $UserRowsBuilder.ToString()
        "{{PASSKEY_ROWS}}"           = $PasskeyRowsBuilder.ToString()
    }

    $HtmlContent = $HtmlTemplate

    foreach ($Token in $ReplacementMap.Keys) {
        $HtmlContent = $HtmlContent.Replace(
            [string]$Token,
            [string]$ReplacementMap[$Token]
        )
    }

    Set-Content `
        -LiteralPath $HtmlPath `
        -Value $HtmlContent `
        -Encoding UTF8

    #endregion

    #region Console output

    Write-Host (
        "`nEnabled users with registered passkeys: {0}" -f
        $TotalUsers
    ) -ForegroundColor Green
    Write-Host (
        "Total registered passkeys: {0}" -f
        $TotalPasskeys
    ) -ForegroundColor Green

    if ($FinalSummary.Count -gt 0) {
        $FinalSummary |
            Select-Object `
                DisplayName,
                UserPrincipalName,
                UserType,
                IsAdmin,
                PasskeyCount,
                PasskeyTypes,
                PasskeyModels,
                NewestPasskeyRegistrationUTC |
            Format-Table -AutoSize
    }
    else {
        Write-Warning "No enabled users with registered passkeys were found."
    }

    Write-Host "`nSummary CSV:" -ForegroundColor Cyan
    Write-Host $CsvPath -ForegroundColor White

    Write-Host "`nDetailed CSV:" -ForegroundColor Cyan
    Write-Host $DetailedCsvPath -ForegroundColor White

    Write-Host "`nHTML dashboard:" -ForegroundColor Cyan
    Write-Host $HtmlPath -ForegroundColor White

    if ($FinalFailures.Count -gt 0) {
        Write-Warning (
            "{0} user(s) could not be processed." -f
            $FinalFailures.Count
        )
        Write-Host "Failure CSV:" -ForegroundColor Yellow
        Write-Host $FailureCsvPath -ForegroundColor White
    }

    if ($OpenHtml) {
        Start-Process -FilePath $HtmlPath
    }

    #endregion
}
finally {
    if ($GraphConnected) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
}

#endregion
