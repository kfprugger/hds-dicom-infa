# .SYNOPSIS
#   Infrastructure provisioning script for Health Data Services DICOM workloads.
# .DESCRIPTION
#   This script provisions Azure Storage Accounts and OneLake folders for DICOM data ingestion to be used in Fabric. Also creates shortcuts in Fabric referencing the storage accounts created in the first part of the script
# .AUTHOR
#   Joey Brakefield, Microsoft - jbrakefield@microsoft.com


#requires -Modules Az.Accounts, Az.Resources
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId = '8d038e6a-9b7d-4cb8-bbcf-e84dff156478',  # Microsoft tenant ID default

    [Parameter(Mandatory = $true)]
    [string]$location = 'westus3', # default location

    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId = '9bbee190-dc61-4c58-ab47-1275cb04018f', # Microsoft subscription ID default

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName = 'rg-DICOM', # default resource group name

    [Parameter(Mandatory = $true)]
    [string]$FacilityCsvPath,

    [Parameter(Mandatory = $true)]
    [string]$hdsWorkspaceName = 'DICOM-Integration', # default workspace name

    [string]$PrefixName = 'sa',

    [string]$LocationSuffix = 'wu3', #typically should be the short form of the location. I will create a mapping table later.

    [string]$stoBicepTemplatePath = '.\\infra\\storageAccounts.bicep',

    [string]$DeploymentName = 'hds-storage-provisioning',

    [string]$StorageAccountSkuName = 'Standard_LRS',

    [string]$StorageAccountKind = 'StorageV2',

    [string]$ImageBlobAccountCoreName = 'imgdcm',

    [string]$ImageOperationsAccountCoreName = 'imgops',

    [Parameter(Mandatory = $true)]
    [string]$FabricWorkspaceId = "93acd72f-a23e-4b93-968d-c139600891e7",    # Fabric workspace GUID. I will create a REST lookup based on the -hdsWorkspaceName later.

    [Parameter(Mandatory = $true)]
    [string]$HdsBronzeLakehouse = "74f52728-9f52-456f-aeb0-a9e250371087",


    [Parameter(Mandatory = $true)]
    [string]$DicomAdmSecGrpId,

    [string]$FabricManagementEndpoint = 'https://api.fabric.microsoft.com',

    

    [hashtable]$GlobalTags = @{},

    [switch]$SkipStorageDeployment,

    [switch]$SkipFabricFolders,

    [switch]$SkipFabricShortcuts

)

$TrustedWorkspacePrincipalType = 'ServicePrincipal'
$FabricApiEndpoint = 'https://onelake.dfs.fabric.microsoft.com'

# Standard Lakehouse FHIR .ndjson Operations path.
$LakehouseOperationsPath = '/Files/External/Imaging/DICOM/Operations'

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$VerbosePreference = 'Continue'
$InformationPreference = 'Continue'

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'u'
    switch ($Level) {
        'INFO' { Write-Information "[$timestamp][INFO] $Message" }
        'WARN' { Write-Warning "[$timestamp][WARN] $Message" }
        'ERROR' { Write-Error "[$timestamp][ERROR] $Message" }
        'DEBUG' { Write-Verbose "[$timestamp][DEBUG] $Message" }
    }
}

function Convert-SecureStringToPlainText {
    param(
        [Parameter(Mandatory = $true)]
        [Security.SecureString]$SecureString
    )

    if ($null -eq $SecureString) {
        return ''
    }

    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Confirm-AzLogin {
    param(
        [Parameter(Mandatory = $true)][string]$Tenant,
        [Parameter(Mandatory = $true)][string]$Subscription
    )

    $context = Get-AzContext -ErrorAction SilentlyContinue
    if ($null -ne $context) {
        $detectedSubscription = if ($context.Subscription) { $context.Subscription.Id } else { '<none>' }
        $detectedTenant = if ($context.Tenant) { $context.Tenant.Id } else { '<none>' }
        Write-Log "Detected existing Azure context for subscription '$detectedSubscription' and tenant '$detectedTenant'." 'INFO'
        return
    }

    $message = 'No Azure session detected. Please run Connect-AzAccount before executing this script.'

    try {
        Add-Type -AssemblyName PresentationFramework -ErrorAction Stop
        [System.Windows.MessageBox]::Show($message, 'Azure Login Required', 'OK', 'Error') | Out-Null
    } catch {
        Write-Log $message 'ERROR'
    }

    throw $message
}

function Get-SanitizedContainerName {
    param(
        [Parameter(Mandatory = $true)][string]$Value
    )

    $sanitized = ($Value.ToLowerInvariant() -replace '[^a-z0-9-]', '-')
    $sanitized = ($sanitized -replace '-{2,}', '-')
    $sanitized = $sanitized.Trim('-')

    if ([string]::IsNullOrWhiteSpace($sanitized)) {
        throw "Study location '$Value' cannot be sanitized into a container name."
    }

    if ($sanitized.Length -gt 63) {
        $sanitized = $sanitized.Substring(0, 63)
        $sanitized = $sanitized.Trim('-')
        if ([string]::IsNullOrWhiteSpace($sanitized)) {
            $sanitized = $Value.ToLowerInvariant().Substring(0, 63)
            $sanitized = ($sanitized -replace '[^a-z0-9-]', '-')
            $sanitized = ($sanitized -replace '-{2,}', '-')
            $sanitized = $sanitized.Trim('-')
        }
    }

    if ($sanitized.Length -lt 3) {
        $sanitized = $sanitized.PadRight(3, '0')
    }

    return $sanitized
}

function Get-InventoryContainerName {
    param(
        [Parameter(Mandatory = $true)][string]$BaseContainerName
    )

    $suffix = '-inv'
    $maxBaseLength = 63 - $suffix.Length
    $trimmedBase = $BaseContainerName

    if ($trimmedBase.Length -gt $maxBaseLength) {
        $trimmedBase = $trimmedBase.Substring(0, $maxBaseLength)
        $trimmedBase = $trimmedBase.Trim('-')

        if ([string]::IsNullOrWhiteSpace($trimmedBase)) {
            $trimmedBase = $BaseContainerName.Substring(0, $maxBaseLength)
            $trimmedBase = $trimmedBase.Trim('-')
        }
    }

    if ([string]::IsNullOrWhiteSpace($trimmedBase)) {
        $trimmedBase = $BaseContainerName
    }

    $inventoryName = "$trimmedBase$suffix"

    if ($inventoryName.Length -lt 3) {
        $inventoryName = $inventoryName.PadRight(3, '0')
    }

    return $inventoryName
}

function Get-InventoryRuleName {
    param(
        [Parameter(Mandatory = $true)][string]$BaseContainerName
    )

    $suffix = '-blob-inventory'
    $maxBaseLength = 63 - $suffix.Length
    $ruleBase = $BaseContainerName

    if ($ruleBase.Length -gt $maxBaseLength) {
        $ruleBase = $ruleBase.Substring(0, $maxBaseLength)
        $ruleBase = $ruleBase.Trim('-')
        if ([string]::IsNullOrWhiteSpace($ruleBase)) {
            $ruleBase = $BaseContainerName.Substring(0, $maxBaseLength)
        }
    }

    $ruleName = "$ruleBase$suffix"

    if ($ruleName.Length -lt 3) {
        $ruleName = $ruleName.PadRight(3, '0')
    }

    return $ruleName
}

function Get-SharedStorageAccountName {
    param(
        [Parameter(Mandatory = $true)][string]$Prefix,
        [Parameter(Mandatory = $true)][string]$CoreSegment,
        [Parameter(Mandatory = $true)][string]$Suffix
    )

    $composed = "${Prefix}${CoreSegment}${Suffix}"
    $sanitized = ($composed -replace '[^a-z0-9]', '').ToLowerInvariant()
    $wasTrimmed = $false

    if ([string]::IsNullOrWhiteSpace($sanitized)) {
        throw "Storage account name derived from '$Prefix', '$CoreSegment', and '$Suffix' is empty after sanitization."
    }

    if ($sanitized.Length -gt 24) {
        $sanitized = $sanitized.Substring(0, 24)
        $wasTrimmed = $true
    }

    if ($sanitized.Length -lt 3) {
        $sanitized = $sanitized.PadRight(3, '0')
    }

    return [pscustomobject]@{
        Name = $sanitized
        WasTrimmed = $wasTrimmed
    }
}

function Import-StmoDefinitions {
    param(
        [Parameter(Mandatory = $true)][string]$CsvPath
    )

    if (-not (Test-Path -Path $CsvPath -PathType Leaf)) {
        throw "Study location CSV '$CsvPath' does not exist."
    }

    $records = Import-Csv -Path $CsvPath
    if (-not $records) {
        throw "Study location CSV '$CsvPath' does not contain any rows."
    }

    $propertyNames = $records[0].PSObject.Properties.Name
    $propertyMap = @{}
    foreach ($name in $propertyNames) {
        $propertyMap[$name.ToLowerInvariant()] = $name
    }

    $studyProperty = $null
    $studyCandidates = @('studylocation', 'study', 'stmo')
    foreach ($candidate in $studyCandidates) {
        if ($propertyMap.ContainsKey($candidate)) {
            $studyProperty = $propertyMap[$candidate]
            break
        }
    }

    if (-not $studyProperty) {
        throw "Unable to locate a study column in CSV. Expected one of: $($studyCandidates -join ', ')."
    }

    $containerMap = [ordered]@{}
    foreach ($row in $records) {
        $studyRaw = ($row.PSObject.Properties[$studyProperty].Value)
        $studyValue = if ($studyRaw) { $studyRaw.ToString().Trim() } else { '' }

        if ([string]::IsNullOrWhiteSpace($studyValue)) {
            Write-Log 'Skipping CSV row with empty study value.' 'WARN'
            continue
        }

        $sanitizedContainer = Get-SanitizedContainerName -Value $studyValue
        if (-not $containerMap.Contains($sanitizedContainer)) {
            $inventoryContainer = Get-InventoryContainerName -BaseContainerName $sanitizedContainer
            $ruleName = Get-InventoryRuleName -BaseContainerName $sanitizedContainer

            $containerMap[$sanitizedContainer] = [pscustomobject]@{
                OriginalName           = $studyValue
                ContainerName          = $sanitizedContainer
                InventoryContainerName = $inventoryContainer
                RuleName               = $ruleName
                PrefixMatch            = "${sanitizedContainer}/"
            }
        }
    }

    if ($containerMap.Count -eq 0) {
        throw "Study location CSV '$CsvPath' did not contain any valid study identifiers."
    }

    $definitions = $containerMap.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { $_.Value }
    return $definitions
}

function Invoke-StorageDeployment {
    param(
        [Parameter(Mandatory = $true)][string]$DeploymentName,
        [Parameter(Mandatory = $true)][string]$ResourceGroup,
        [Parameter(Mandatory = $true)][string]$TemplatePath,
        [Parameter(Mandatory = $true)][hashtable]$TemplateParameters,
        [switch]$WhatIf
    )

    $resolvedTemplate = (Resolve-Path -Path $TemplatePath).Path
    Write-Log "Resolved Bicep template: $resolvedTemplate" 'DEBUG'

    Write-Log 'Running template validation (Test-AzResourceGroupDeployment).' 'INFO'
    Test-AzResourceGroupDeployment -ResourceGroupName $ResourceGroup -TemplateFile $resolvedTemplate -TemplateParameterObject $TemplateParameters -ErrorAction Stop | Out-Null

    $deploymentParams = @{
        ResourceGroupName = $ResourceGroup
        TemplateFile = $resolvedTemplate
        TemplateParameterObject = $TemplateParameters
        Name = $DeploymentName
        Mode = 'Incremental'
    }

    if ($WhatIf.IsPresent) {
        Write-Log 'Executing storage deployment in WhatIf mode.' 'INFO'
        New-AzResourceGroupDeployment @deploymentParams -WhatIf -ErrorAction Stop
    } else {
        Write-Log 'Deploying storage accounts and containers with New-AzResourceGroupDeployment.' 'INFO'
        New-AzResourceGroupDeployment @deploymentParams -ErrorAction Stop -DeploymentDebugLogLevel All 
    }
}

function Resolve-LakehouseSegments {
    param(
        [Parameter(Mandatory = $true)][string]$WorkspaceId,
        [Parameter(Mandatory = $true)][string]$LakehouseId
    )

    $workspaceSegment = if ($WorkspaceId -match '^[0-9a-fA-F-]{36}$') {
        $WorkspaceId.ToLowerInvariant()
    } else {
        [Uri]::EscapeDataString($WorkspaceId)
    }

    $lakehouseSegment = if ($LakehouseId -match '^[0-9a-fA-F-]{36}$') {
        $LakehouseId.ToLowerInvariant()
    } else {
        [Uri]::EscapeDataString($LakehouseId.TrimEnd('.'))
    }

    return [pscustomobject]@{
        Workspace = $workspaceSegment
        Lakehouse = $lakehouseSegment
    }
}

function Get-OneLakeAccessToken {
    Write-Log 'Requesting OneLake access token with storage audience.' 'INFO'
    $tokenResponse = Get-AzAccessToken -ResourceTypeName Storage -ErrorAction Stop

    if ($null -eq $tokenResponse) {
        Write-Log 'Get-AzAccessToken returned null response.' 'ERROR'
        throw 'Failed to acquire OneLake access token.'
    }

    $resourceProp = $tokenResponse.PSObject.Properties['Resource']
    $audienceProp = $tokenResponse.PSObject.Properties['TokenAudience']
    $resource = if ($resourceProp) {
        $resourceProp.Value
    } elseif ($audienceProp) {
        $audienceProp.Value
    } else {
        'UnknownResource'
    }

    $expiresProp = $tokenResponse.PSObject.Properties['ExpiresOn']
    $expires = if ($expiresProp) {
        $expiresProp.Value.ToLocalTime().ToString('u')
    } else {
        'UnknownExpiry'
    }

    $tokenProp = $tokenResponse.PSObject.Properties['Token']
    if (-not $tokenProp -or $null -eq $tokenProp.Value) {
        Write-Log 'Access token response did not include a usable token value.' 'ERROR'
        throw 'Failed to acquire OneLake access token.'
    }

    $tokenValue = if ($tokenProp.Value -is [Security.SecureString]) {
        Convert-SecureStringToPlainText -SecureString $tokenProp.Value
    } else {
        [string]$tokenProp.Value
    }

    if ([string]::IsNullOrWhiteSpace($tokenValue)) {
        Write-Log 'Access token string was empty after conversion.' 'ERROR'
        throw 'Failed to acquire OneLake access token.'
    }

    $tokenPreview = $tokenValue.Substring(0, [Math]::Min(10, $tokenValue.Length))
    Write-Log "Acquired access token for resource '$resource' expiring at $expires (preview: $tokenPreview...)." 'DEBUG'

    return $tokenValue
}

function Get-FabricApiAccessToken {
    param(
        [string]$ResourceUrl = 'https://api.fabric.microsoft.com'
    )

    Write-Log "Requesting Fabric API access token for resource '$ResourceUrl'." 'INFO'
    $tokenResponse = Get-AzAccessToken -ResourceUrl $ResourceUrl -ErrorAction Stop

    if ($null -eq $tokenResponse) {
        Write-Log 'Get-AzAccessToken returned null response for Fabric API.' 'ERROR'
        throw 'Failed to acquire Fabric API access token.'
    }

    $resourceProp = $tokenResponse.PSObject.Properties['Resource']
    $audienceProp = $tokenResponse.PSObject.Properties['TokenAudience']
    $resource = if ($resourceProp) {
        $resourceProp.Value
    } elseif ($audienceProp) {
        $audienceProp.Value
    } else {
        'UnknownResource'
    }

    $expiresProp = $tokenResponse.PSObject.Properties['ExpiresOn']
    $expires = if ($expiresProp) {
        $expiresProp.Value.ToLocalTime().ToString('u')
    } else {
        'UnknownExpiry'
    }

    $tokenProp = $tokenResponse.PSObject.Properties['Token']
    if (-not $tokenProp -or $null -eq $tokenProp.Value) {
        Write-Log 'Fabric API access token response did not include a usable token value.' 'ERROR'
        throw 'Failed to acquire Fabric API access token.'
    }

    $tokenValue = if ($tokenProp.Value -is [Security.SecureString]) {
        Convert-SecureStringToPlainText -SecureString $tokenProp.Value
    } else {
        [string]$tokenProp.Value
    }

    if ([string]::IsNullOrWhiteSpace($tokenValue)) {
        Write-Log 'Fabric API access token string was empty after conversion.' 'ERROR'
        throw 'Failed to acquire Fabric API access token.'
    }

    $tokenPreview = $tokenValue.Substring(0, [Math]::Min(10, $tokenValue.Length))
    Write-Log "Acquired Fabric API access token for resource '$resource' expiring at $expires (preview: $tokenPreview...)." 'DEBUG'

    return $tokenValue
}

function Invoke-FabricApiRequest {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Get', 'Post', 'Put', 'Delete', 'Patch', 'Head')]
        [string]$Method,
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][hashtable]$Headers,
        [object]$Body,
        [string]$Description
    )

    $sanitizedDescription = if ([string]::IsNullOrWhiteSpace($Description)) { '<unspecified>' } else { $Description }
    $logPrefix = "FABRIC API"

    Write-Log "$logPrefix request: $Method $Uri (operation: $sanitizedDescription)." 'INFO'

    $statusCode = $null
    $responseHeaders = $null
    $bodyPayload = $null

    if ($PSBoundParameters.ContainsKey('Body') -and $null -ne $Body) {
        $bodyPayload = if ($Body -is [string]) {
            $Body
        } else {
            $Body | ConvertTo-Json -Depth 10
        }

        Write-Log "$logPrefix request body: $bodyPayload" 'DEBUG'
    }

    try {
        $invokeParams = @{
            Method      = $Method
            Uri         = $Uri
            Headers     = $Headers
            ErrorAction = 'Stop'
        }

        if ($null -ne $bodyPayload) {
            $invokeParams['Body'] = $bodyPayload
            $invokeParams['ContentType'] = 'application/json'
        }

        $iwrCommand = Get-Command -Name Invoke-WebRequest -ErrorAction Stop
        if ($iwrCommand.Parameters.ContainsKey('SkipHttpErrorCheck')) {
            $invokeParams['SkipHttpErrorCheck'] = $true
        }

        $rawResponse = Invoke-WebRequest @invokeParams

        $statusCode = if ($rawResponse.PSObject.Properties['StatusCode']) { [int]$rawResponse.StatusCode } else { -1 }
        $responseHeaders = if ($rawResponse.PSObject.Properties['Headers']) { $rawResponse.Headers } else { $null }
        $rawContent = if ($rawResponse.PSObject.Properties['Content']) { [string]$rawResponse.Content } else { '' }

        if ($statusCode -lt 200 -or $statusCode -ge 300) {
            $errorBody = if ([string]::IsNullOrWhiteSpace($rawContent)) { '<no-response-body>' } else { $rawContent }
            $errorMessage = "$logPrefix failure: $Method $Uri returned status $statusCode ('<no-description>'). Message: $errorBody"
            Write-Log $errorMessage 'ERROR'
            throw [System.Net.Http.HttpRequestException]::new($errorMessage)
        }

        $statusLabel = [int]$statusCode
        $successMessage = "$logPrefix response: $Method $Uri returned status $statusLabel."
        Write-Log $successMessage 'INFO'

        $parsedResponse = $null
        if (-not [string]::IsNullOrWhiteSpace($rawContent)) {
            try {
                $parsedResponse = $rawContent | ConvertFrom-Json -Depth 50 -ErrorAction Stop
            } catch {
                $parsedResponse = $rawContent
            }
        }

        return [pscustomobject]@{
            Response   = $parsedResponse
            StatusCode = $statusCode
            Headers    = $responseHeaders
            RawContent = $rawContent
        }
    } catch {
        $caughtError = $_
        if ($caughtError.Exception -and -not ($caughtError.Exception -is [System.Net.Http.HttpRequestException])) {
            $errorMessage = "$logPrefix failure: $Method $Uri experienced an unexpected error: $($caughtError.Exception.Message)"
        } else {
            $errorMessage = $caughtError.Exception.Message
        }

        Write-Log $errorMessage 'ERROR'
        throw
    }
}

function New-OneLakeDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Endpoint,
        [Parameter(Mandatory = $true)][string]$WorkspaceSegment,
        [Parameter(Mandatory = $true)][string]$LakehouseSegment,
        [Parameter(Mandatory = $true)][string[]]$PathSegments,
        [Parameter(Mandatory = $true)][string]$AccessToken
    )

    # Directory creation follows the OneLake REST parity guidelines for ADLS as documented at
    # https://learn.microsoft.com/fabric/onelake/onelake-api-parity.
    $escapedSegments = $PathSegments | ForEach-Object { [Uri]::EscapeDataString($_) }
    $relativePath = ($escapedSegments -join '/')
    $uri = "{0}/{1}/{2}/Files/{3}/?resource=directory" -f $Endpoint.TrimEnd('/'), $WorkspaceSegment, $LakehouseSegment, $relativePath.TrimEnd('/')

    Write-Log "Preparing OneLake directory request. Endpoint='$Endpoint', WorkspaceSegment='$WorkspaceSegment', LakehouseSegment='$LakehouseSegment', RelativePath='$relativePath', Uri='$uri'." 'DEBUG'

    $headers = @{
        Authorization       = "Bearer $AccessToken"
        'x-ms-version'      = '2021-06-08'
        'x-ms-date'         = (Get-Date -Format 'R')
        'Content-Length'    = '0'
        'x-ms-client-request-id' = [Guid]::NewGuid().ToString()
    }

    $sanitizedHeaderPreview = @()
    foreach ($entry in $headers.GetEnumerator()) {
        $headerValue = if ($entry.Key -eq 'Authorization') { '<redacted>' } else { $entry.Value }
        $sanitizedHeaderPreview += ('{0}: {1}' -f $entry.Key, $headerValue)
    }

    Write-Log ("PUT {0} HTTP/1.1" -f $uri) 'INFO'
    Write-Log ("Headers: {0}" -f ($sanitizedHeaderPreview -join '; ')) 'INFO'

    $maxAttempts = 3

    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            Write-Log "Attempt ${attempt}: invoking PUT for '$relativePath'." 'DEBUG'
            Invoke-RestMethod -Method Put -Uri $uri -Headers $headers -TimeoutSec 60 -ErrorAction Stop
            Write-Log "Ensured OneLake directory '/$relativePath'." 'DEBUG'
            return
        } catch {
            $response = $_.Exception.Response
            if ($response -and $response.StatusCode.value__ -eq 409) {
                Write-Log "Directory '/$relativePath' already exists." 'DEBUG'
                return
            }

            $statusCodeProp = $null
            $statusDescriptionProp = $null
            if ($response) {
                $statusCodeProp = $response.PSObject.Properties['StatusCode']
                $statusDescriptionProp = $response.PSObject.Properties['StatusDescription']
            }

            $statusCode = if ($statusCodeProp -and $statusCodeProp.Value) {
                $statusValue = $statusCodeProp.Value
                if ($statusValue.PSObject.Properties['value__']) {
                    $statusValue.value__
                } else {
                    [string]$statusValue
                }
            } else {
                '<no-status>'
            }

            $statusDescription = if ($statusDescriptionProp) {
                $statusDescriptionProp.Value
            } else {
                '<no-description>'
            }

            $responseContent = '<no-response-body>'
            if ($response) {
                try {
                    $streamMethod = $response.PSObject.Methods['GetResponseStream']
                    if ($streamMethod) {
                        $stream = $response.GetResponseStream()
                    } else {
                        $streamProperty = $response.PSObject.Properties['ResponseStream']
                        $stream = if ($streamProperty) { $streamProperty.Value } else { $null }
                    }

                    if ($stream) {
                        try {
                            $reader = New-Object System.IO.StreamReader($stream)
                            $responseContent = $reader.ReadToEnd()
                        } finally {
                            if ($reader) { $reader.Dispose() }
                            if ($stream -and ($stream -is [System.IDisposable])) { $stream.Dispose() }
                        }
                    }
                } catch {
                    $responseContent = "<failed-to-read-body: $($_.Exception.Message)>"
                }
            }

            $headerDump = '<no-headers>'
            if ($response -and $response.Headers) {
                $pairs = @()
                $headerObject = $response.Headers

                if ($headerObject -is [System.Net.WebHeaderCollection]) {
                    foreach ($key in $headerObject.AllKeys) {
                        $pairs += ('{0}: {1}' -f $key, $headerObject[$key])
                    }
                } elseif ($headerObject -is [System.Collections.IDictionary]) {
                    foreach ($entry in $headerObject.GetEnumerator()) {
                        $pairs += ('{0}: {1}' -f $entry.Key, $entry.Value)
                    }
                } elseif ($headerObject -is [System.Collections.IEnumerable]) {
                    foreach ($entry in $headerObject) {
                        $pairs += [string]$entry
                    }
                } else {
                    $pairs += [string]$headerObject
                }

                if ($pairs.Count -gt 0) {
                    $headerDump = $pairs -join '; '
                }
            }

            Write-Log "Request for '/$relativePath' failed with status '$statusCode' ('$statusDescription') and message '$($_.Exception.Message)'. Response body: $responseContent. Response headers: $headerDump" 'WARN'
            if ($attempt -ge $maxAttempts) {
                throw "Failed to create OneLake directory '/$relativePath': $($_.Exception.Message)"
            }

            $retryInterval = [math]::Pow(2, $attempt)
            Write-Log "Transient error creating '/$relativePath'. Retrying in $retryInterval second(s)." 'WARN'
            Start-Sleep -Seconds $retryInterval
        }
    }
}

function Test-OneLakeDirectoryExists {
    param(
        [Parameter(Mandatory = $true)][string]$Endpoint,
        [Parameter(Mandatory = $true)][string]$WorkspaceSegment,
        [Parameter(Mandatory = $true)][string]$LakehouseSegment,
        [Parameter(Mandatory = $true)][string[]]$PathSegments,
        [Parameter(Mandatory = $true)][string]$AccessToken
    )

    $escapedSegments = $PathSegments | ForEach-Object { [Uri]::EscapeDataString($_) }
    $relativePath = ($escapedSegments -join '/')
    $uri = "{0}/{1}/{2}/Files/{3}/?resource=directory" -f $Endpoint.TrimEnd('/'), $WorkspaceSegment, $LakehouseSegment, $relativePath.TrimEnd('/')

    $headers = @{
        Authorization  = "Bearer $AccessToken"
        'x-ms-version' = '2021-06-08'
        'x-ms-date'    = (Get-Date -Format 'R')
    }

    try {
        Invoke-RestMethod -Method Head -Uri $uri -Headers $headers -TimeoutSec 30 -ErrorAction Stop | Out-Null
        Write-Log "Directory exists at '/$relativePath'." 'DEBUG'
        return $true
    } catch {
        $response = $_.Exception.Response
        if ($response -and $response.StatusCode.value__ -eq 404) {
            Write-Log "Directory '/$relativePath' not found (HEAD returned 404)." 'DEBUG'
            return $false
        }

        Write-Log "HEAD request for '/$relativePath' failed: $($_.Exception.Message)" 'WARN'
        throw
    }
}

function New-FabricInventoryFolders {
    param(
        [Parameter(Mandatory = $true)][string]$Endpoint,
        [Parameter(Mandatory = $true)][string]$WorkspaceId,
        [Parameter(Mandatory = $true)][string]$LakehouseId,
        [Parameter(Mandatory = $true)][string]$AccessToken,
        [Parameter(Mandatory = $true)][psobject[]]$StmoDefinitions
    )

    $segments = Resolve-LakehouseSegments -WorkspaceId $WorkspaceId -LakehouseId $LakehouseId
    $endpointRoot = $Endpoint.TrimEnd('/')

    foreach ($definition in $StmoDefinitions) {
        $containerName = $definition.ContainerName
        $ingestStudyPath = @('Ingest', 'Imaging', 'DICOM', $containerName)
        $ingestStudyRelative = ($ingestStudyPath | ForEach-Object { [Uri]::EscapeDataString($_) }) -join '/'
        $ingestStudyUri = "{0}/{1}/{2}/Files/{3}" -f $endpointRoot, $segments.Workspace, $segments.Lakehouse, $ingestStudyRelative

        if (Test-OneLakeDirectoryExists -Endpoint $Endpoint -WorkspaceSegment $segments.Workspace -LakehouseSegment $segments.Lakehouse -PathSegments $ingestStudyPath -AccessToken $AccessToken) {
            Write-Log "Lakehouse study folder already exists: $ingestStudyUri" 'INFO'
        } else {
            Write-Log "Creating lakehouse study folder: $ingestStudyUri" 'INFO'
            New-OneLakeDirectory -Endpoint $Endpoint -WorkspaceSegment $segments.Workspace -LakehouseSegment $segments.Lakehouse -PathSegments $ingestStudyPath -AccessToken $AccessToken
        }

        $inventoryPath = $ingestStudyPath + @('InventoryFiles')
        $inventoryRelative = ($inventoryPath | ForEach-Object { [Uri]::EscapeDataString($_) }) -join '/'
        $inventoryUri = "{0}/{1}/{2}/Files/{3}" -f $endpointRoot, $segments.Workspace, $segments.Lakehouse, $inventoryRelative

        if (Test-OneLakeDirectoryExists -Endpoint $Endpoint -WorkspaceSegment $segments.Workspace -LakehouseSegment $segments.Lakehouse -PathSegments $inventoryPath -AccessToken $AccessToken) {
            Write-Log "Inventory subfolder already exists: $inventoryUri" 'INFO'
        } else {
            Write-Log "Creating inventory subfolder: $inventoryUri" 'INFO'
            New-OneLakeDirectory -Endpoint $Endpoint -WorkspaceSegment $segments.Workspace -LakehouseSegment $segments.Lakehouse -PathSegments $inventoryPath -AccessToken $AccessToken
        }
    }
}

function Get-LakehousePathSegments {
    param([Parameter(Mandatory = $true)][string]$FullPath)

    $trimmed = $FullPath.Trim('/').Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        return @()
    }

    $parts = $trimmed.Split('/', [System.StringSplitOptions]::RemoveEmptyEntries)
    if ($parts.Count -gt 0 -and $parts[0].Equals('Files', [System.StringComparison]::OrdinalIgnoreCase)) {
        if ($parts.Count -gt 1) {
            return $parts[1..($parts.Count - 1)]
        }
        return @()
    }

    return $parts
}

function New-LakehouseDirectoryPath {
    param(
        [Parameter(Mandatory = $true)][string]$Endpoint,
        [Parameter(Mandatory = $true)][string]$WorkspaceSegment,
        [Parameter(Mandatory = $true)][string]$LakehouseSegment,
        [Parameter(Mandatory = $true)][string[]]$PathSegments,
        [Parameter(Mandatory = $true)][string]$AccessToken
    )

    if (-not $PathSegments -or $PathSegments.Count -eq 0) {
        return
    }

    for ($i = 0; $i -lt $PathSegments.Count; $i++) {
        $currentSegments = $PathSegments[0..$i]
        if (-not (Test-OneLakeDirectoryExists -Endpoint $Endpoint -WorkspaceSegment $WorkspaceSegment -LakehouseSegment $LakehouseSegment -PathSegments $currentSegments -AccessToken $AccessToken)) {
            Write-Log "Ensuring lakehouse path segment '/$([string]::Join('/', $currentSegments))'." 'INFO'
            New-OneLakeDirectory -Endpoint $Endpoint -WorkspaceSegment $WorkspaceSegment -LakehouseSegment $LakehouseSegment -PathSegments $currentSegments -AccessToken $AccessToken
        }
    }
}

function Get-FabricApiHeaders {
    param([Parameter(Mandatory = $true)][string]$AccessToken)

    return @{
        Authorization = "Bearer $AccessToken"
        'Content-Type' = 'application/json'
    }
}

function Get-FabricConnectionByDisplayName {
    param(
        [Parameter(Mandatory = $true)][string]$Endpoint,
        [Parameter(Mandatory = $true)][string]$AccessToken,
        [Parameter(Mandatory = $true)][string]$DisplayName,
        [string]$WorkspaceId
    )

    $headers = Get-FabricApiHeaders -AccessToken $AccessToken
    $uri = "$($Endpoint.TrimEnd('/'))/v1/connections"

    try {
        $result = Invoke-FabricApiRequest -Method 'Get' -Uri $uri -Headers $headers -Description 'List Fabric connections'
    } catch {
        Write-Log "Unable to retrieve Fabric connections for display name lookup: $($_.Exception.Message)" 'WARN'
        return $null
    }

    $response = $result.Response
    $items = @()
    if ($null -ne $response) {
        if ($response.PSObject.Properties['value']) {
            $items = @($response.value)
        } elseif ($response -is [System.Collections.IEnumerable] -and -not ($response -is [string])) {
            $items = @($response)
        } else {
            $items = @($response)
        }
    }

    foreach ($item in $items) {
        $nameMatches = $item.PSObject.Properties['displayName'] -and $item.displayName -eq $DisplayName
        if (-not $nameMatches) {
            continue
        }

        if ($WorkspaceId -and $item.PSObject.Properties['workspaceId'] -and -not ($item.workspaceId -eq $WorkspaceId)) {
            continue
        }

        if ($WorkspaceId -and -not $item.PSObject.Properties['workspaceId']) {
            # Some APIs omit workspaceId for tenant-level connections. Skip when a specific workspace scope is requested.
            continue
        }

        if (-not $WorkspaceId -and $item.PSObject.Properties['workspaceId']) {
            # Connection is workspace-scoped but caller requested global search. Accept match.
            return $item
        }

        if (-not $WorkspaceId) {
            return $item
        }

        if ($WorkspaceId -and $item.workspaceId -eq $WorkspaceId) {
            return $item
        }
    }

    return $null
}

function Get-FabricAdlsConnectionMetadata {
    param(
        [Parameter(Mandatory = $true)][string]$Endpoint,
        [Parameter(Mandatory = $true)][string]$AccessToken,
        [string[]]$PreferredTypes = @('AdlsGen2', 'AzureDataLakeStorage', 'AzureDataLakeStorageGen2')
    )

    if (Test-Path 'variable:script:FabricAdlsConnectionMetadataCache') {
        $cached = Get-Variable -Name FabricAdlsConnectionMetadataCache -Scope Script -ValueOnly
        if ($null -ne $cached) {
            return $cached
        }
    }

    $headers = Get-FabricApiHeaders -AccessToken $AccessToken
    $uri = "$($Endpoint.TrimEnd('/'))/v1/connections/supportedConnectionTypes"

    try {
        $result = Invoke-FabricApiRequest -Method 'Get' -Uri $uri -Headers $headers -Description 'List supported connection types'
    } catch {
        Write-Log "Unable to retrieve supported connection types: $($_.Exception.Message)" 'WARN'
        return $null
    }

    $response = $result.Response
    if (-not $response) {
        return $null
    }

    $entries = @()
    if ($response.PSObject.Properties['value']) {
        $entries = @($response.value)
    } elseif ($response -is [System.Collections.IEnumerable] -and -not ($response -is [string])) {
        $entries = @($response)
    }

    foreach ($entry in $entries) {
        if ($entry -and $entry.PSObject.Properties['type']) {
            $typeLabel = [string]$entry.type
            Write-Log "Supported connection type detected: '$typeLabel'." 'DEBUG'
        }
    }

    $matching = @($entries | Where-Object {
        $PreferredTypes -contains $_.type -and $_.supportedCredentialTypes -contains 'WorkspaceIdentity'
    })

    if (-not $matching -or $matching.Length -eq 0) {
        Write-Log 'Supported connection metadata does not expose an ADLS Gen2 type with workspace identity credentials.' 'WARN'
        return $null
    }

    $selected = $matching | Sort-Object {
        $index = [Array]::IndexOf($PreferredTypes, $_.type)
        if ($index -ge 0) { $index } else { [int]::MaxValue }
    } | Select-Object -First 1
    Set-Variable -Name FabricAdlsConnectionMetadataCache -Scope Script -Value $selected
    return $selected
}

function Get-FabricBlobConnectionMetadata {
    param(
        [Parameter(Mandatory = $true)][string]$Endpoint,
        [Parameter(Mandatory = $true)][string]$AccessToken,
        [string[]]$PreferredTypes = @('AzureBlobs', 'AzureBlobStorage', 'BlobStorage', 'AzureBlobStorageConnector')
    )

    if (Test-Path 'variable:script:FabricBlobConnectionMetadataCache') {
        $cached = Get-Variable -Name FabricBlobConnectionMetadataCache -Scope Script -ValueOnly
        if ($null -ne $cached) {
            return $cached
        }
    }

    $headers = Get-FabricApiHeaders -AccessToken $AccessToken
    $uri = "$($Endpoint.TrimEnd('/'))/v1/connections/supportedConnectionTypes"

    try {
        $result = Invoke-FabricApiRequest -Method 'Get' -Uri $uri -Headers $headers -Description 'List supported connection types'
    } catch {
        Write-Log "Unable to retrieve supported connection types: $($_.Exception.Message)" 'WARN'
        return $null
    }

    $response = $result.Response
    if (-not $response) {
        return $null
    }

    $entries = @()
    if ($response.PSObject.Properties['value']) {
        $entries = @($response.value)
    } elseif ($response -is [System.Collections.IEnumerable] -and -not ($response -is [string])) {
        $entries = @($response)
    }

    foreach ($entry in $entries) {
        if ($entry -and $entry.PSObject.Properties['type']) {
            $typeLabel = [string]$entry.type
            Write-Log "Supported connection type detected: '$typeLabel'." 'DEBUG'
        }
    }

    $matching = @($entries | Where-Object {
        ($PreferredTypes -contains $_.type -or $_.type -match 'blob') -and $_.supportedCredentialTypes -contains 'WorkspaceIdentity'
    })

    if (-not $matching -or $matching.Length -eq 0) {
        Write-Log 'Supported connection metadata does not expose a blob storage type with workspace identity credentials.' 'WARN'
        return $null
    }

    $selected = $matching | Sort-Object {
        $index = [Array]::IndexOf($PreferredTypes, $_.type)
        if ($index -ge 0) { $index } else { [int]::MaxValue }
    } | Select-Object -First 1
    Set-Variable -Name FabricBlobConnectionMetadataCache -Scope Script -Value $selected
    return $selected
}

function New-FabricBlobConnection {
    param(
        [Parameter(Mandatory = $true)][string]$Endpoint,
        [Parameter(Mandatory = $true)][string]$WorkspaceId,
        [Parameter(Mandatory = $true)][string]$AccessToken,
        [Parameter(Mandatory = $true)][string]$DisplayName,
        [Parameter(Mandatory = $true)][string]$StorageLocation,
        [string]$DefaultContainerName
    )

    $existing = Get-FabricConnectionByDisplayName -Endpoint $Endpoint -AccessToken $AccessToken -DisplayName $DisplayName -WorkspaceId $WorkspaceId
    if (-not $existing) {
        $existing = Get-FabricConnectionByDisplayName -Endpoint $Endpoint -AccessToken $AccessToken -DisplayName $DisplayName
        if ($existing) {
            Write-Log "Found tenant-scoped Fabric connection '$DisplayName'; reusing it." 'INFO'
        }
    }
    if ($existing -and $existing.PSObject.Properties['id']) {
        $existingId = [string]$existing.id
        Write-Log "Reusing Fabric connection '$DisplayName' (ID: $existingId)." 'INFO'
        return $existingId
    }

    $metadata = Get-FabricBlobConnectionMetadata -Endpoint $Endpoint -AccessToken $AccessToken

    if ($metadata) {
        try {
            Write-Log ("Supported blob metadata: {0}" -f ($metadata | ConvertTo-Json -Depth 6 -Compress)) 'DEBUG'
        } catch {
            Write-Log "Failed to serialize blob metadata for diagnostics: $($_.Exception.Message)" 'DEBUG'
        }
    }

    $accountUrl = $StorageLocation.TrimEnd('/')
    $accountHost = $accountUrl
    $accountDomain = 'blob.core.windows.net'

    $accountUri = $null
    if ([System.Uri]::TryCreate($accountUrl, [System.UriKind]::Absolute, [ref]$accountUri)) {
        if ($accountUri.Host) {
            $accountHost = $accountUri.Host
            $hostParts = $accountUri.Host.Split('.', [System.StringSplitOptions]::RemoveEmptyEntries)
            if ($hostParts.Length -gt 1) {
                $accountDomain = [string]::Join('.', $hostParts[1..($hostParts.Length - 1)])
            } else {
                $accountDomain = $accountUri.Host
            }
            if ($accountUri.IsDefaultPort -eq $false -and $accountUri.Port -gt 0) {
                $accountHost = "$($accountUri.Host):$($accountUri.Port)"
            }
        }
    } else {
        $accountHost = ($accountUrl -replace '^[a-zA-Z][a-zA-Z0-9+.-]*://', '').Trim('/')
        if ($accountHost -match '\.') {
            $hostParts = $accountHost.Split('.', [System.StringSplitOptions]::RemoveEmptyEntries)
            if ($hostParts.Length -gt 1) {
                $accountDomain = [string]::Join('.', $hostParts[1..($hostParts.Length - 1)])
            } else {
                $accountDomain = $accountHost
            }
        }
    }

    $connectionType = 'AzureBlobs'
    $creationMethodName = 'AzureBlobs'
    $parameterObjects = @()
    $encryptionOption = 'NotEncrypted'

    if ($metadata) {
        $connectionType = if ($metadata.PSObject.Properties['type']) { [string]$metadata.type } else { $connectionType }

        $method = $null
        if ($metadata.PSObject.Properties['creationMethods']) {
            $method = $metadata.creationMethods | Select-Object -First 1
        }

        if ($metadata.PSObject.Properties['supportedConnectionEncryptionTypes']) {
            $supported = @($metadata.supportedConnectionEncryptionTypes)
            if ($supported.Length -gt 0) {
                if ($supported -contains 'Encrypted') {
                    $encryptionOption = 'Encrypted'
                } else {
                    $encryptionOption = [string]$supported[0]
                }
            }
        }

        if ($method -and $method.PSObject.Properties['name']) {
            $creationMethodName = [string]$method.name

            if ($method.PSObject.Properties['parameters']) {
                foreach ($parameter in $method.parameters) {
                    $paramName = [string]$parameter.name
                    $compactName = ($paramName -replace '[^a-zA-Z0-9]', '').ToLowerInvariant()
                    $value = $null

                    if ($compactName -match 'server|host') {
                        $value = $accountHost
                    } elseif ($compactName -match 'account|endpoint|url|location|blob') {
                        $value = $accountUrl
                    } elseif ($compactName -match 'container|root') {
                        if (-not [string]::IsNullOrWhiteSpace($DefaultContainerName)) {
                            $value = $DefaultContainerName
                        } else {
                            $value = ''
                        }
                    } elseif ($compactName -match 'path|subpath|relativepath|folder|directory') {
                        $value = ''
                    } elseif ($compactName -match 'domain') {
                        $value = $accountDomain
                    }

                    if ($parameter.required -and [string]::IsNullOrWhiteSpace($value)) {
                        if ($compactName -match 'container|root' -and -not [string]::IsNullOrWhiteSpace($DefaultContainerName)) {
                            $value = $DefaultContainerName
                        } else {
                            Write-Log "Unable to auto-map required parameter '$paramName'. Metadata: $(($parameter | ConvertTo-Json -Compress -Depth 3))" 'WARN'
                            throw "Unable to map required parameter '$paramName' for blob storage connection creation."
                        }
                    }

                    if (-not [string]::IsNullOrWhiteSpace($value)) {
                        $parameterObjects += @{
                            name     = $paramName
                            dataType = if ($parameter.PSObject.Properties['dataType']) { [string]$parameter.dataType } else { 'Text' }
                            value    = $value
                        }
                    }
                }
            }
        }
    }

    if ($parameterObjects.Length -gt 0) {
        for ($index = 0; $index -lt $parameterObjects.Length; $index++) {
            $param = $parameterObjects[$index]
            if (-not ($param -is [System.Collections.IDictionary])) {
                continue
            }

            $paramName = [string]$param['name']
            $valueCandidate = $param['value']

            if ($valueCandidate -is [System.Collections.IEnumerable] -and -not ($valueCandidate -is [string])) {
                $segments = @()
                foreach ($segment in $valueCandidate) {
                    if ($null -ne $segment) {
                        $segments += [string]$segment
                    }
                }

                if ($segments.Count -eq 0) {
                    $valueCandidate = ''
                } elseif ($segments.Count -eq 1) {
                    $valueCandidate = $segments[0]
                } elseif (($segments | Where-Object { $_.Length -gt 1 }).Count -gt 0) {
                    $valueCandidate = [string]::Join('/', $segments)
                } else {
                    $valueCandidate = -join $segments
                }
            }

            if ($paramName) {
                if ($paramName.Equals('path', [System.StringComparison]::OrdinalIgnoreCase) -or $paramName.Equals('subpath', [System.StringComparison]::OrdinalIgnoreCase)) {
                    $valueCandidate = ''
                } elseif ($paramName.Equals('server', [System.StringComparison]::OrdinalIgnoreCase)) {
                    $valueCandidate = $accountHost
                } elseif ($paramName -match 'container|root') {
                    if (-not [string]::IsNullOrWhiteSpace($DefaultContainerName)) {
                        $valueCandidate = $DefaultContainerName
                    }
                } elseif ($paramName -match 'account|endpoint|url|location|blob') {
                    $valueCandidate = $accountUrl
                } elseif ($paramName -match 'domain') {
                    $valueCandidate = $accountDomain
                }
            }

            $parameterObjects[$index]['value'] = $valueCandidate
        }
    }

    if ($parameterObjects.Length -eq 0) {
        $parameterObjects = @(
            @{ name = 'server'; dataType = 'Text'; value = $accountHost }
            @{ name = 'url';    dataType = 'Text'; value = $accountUrl }
            @{ name = 'domain'; dataType = 'Text'; value = $accountDomain }
        )
    }

    $credentialDetails = @{
        singleSignOnType     = 'None'
        connectionEncryption = $encryptionOption
        skipTestConnection   = $false
        credentials = @{
            credentialType = 'WorkspaceIdentity'
        }
    }

    $body = @{
        connectivityType = 'ShareableCloud'
        displayName      = $DisplayName
        privacyLevel     = 'Organizational'
        connectionDetails = @{
            type           = $connectionType
            creationMethod = $creationMethodName
            parameters     = $parameterObjects
        }
        credentialDetails = $credentialDetails
    }

    Write-Log "Creating blob connection using type '$connectionType' and method '$creationMethodName'." 'DEBUG'

    $headers = Get-FabricApiHeaders -AccessToken $AccessToken
    $uri = "$($Endpoint.TrimEnd('/'))/v1/connections"

    try {
        $result = Invoke-FabricApiRequest -Method 'Post' -Uri $uri -Headers $headers -Body $body -Description "Create blob storage connection '$DisplayName'"
    } catch {
        $message = $_.Exception.Message
        Write-Log "Failed to create Fabric connection '$DisplayName': $message" 'ERROR'
        throw
    }

    $response = $result.Response
    if ($response -and $response.PSObject.Properties['id']) {
        $connectionId = [string]$response.id
        Write-Log "Created Fabric connection '$DisplayName' (ID: $connectionId)." 'INFO'
        return $connectionId
    }

    throw "Fabric connection response did not include an identifier for '$DisplayName'."
}

function New-FabricAdlsConnection {
    param(
        [Parameter(Mandatory = $true)][string]$Endpoint,
        [Parameter(Mandatory = $true)][string]$WorkspaceId,
        [Parameter(Mandatory = $true)][string]$AccessToken,
        [Parameter(Mandatory = $true)][string]$DisplayName,
    [Parameter(Mandatory = $true)][string]$StorageLocation,
    [string]$ContainerSubpath
    )

    $existing = Get-FabricConnectionByDisplayName -Endpoint $Endpoint -AccessToken $AccessToken -DisplayName $DisplayName -WorkspaceId $WorkspaceId
    if ($existing -and $existing.PSObject.Properties['id']) {
        $existingId = [string]$existing.id
        Write-Log "Reusing Fabric connection '$DisplayName' (ID: $existingId)." 'INFO'
        return $existingId
    }

    $metadata = Get-FabricAdlsConnectionMetadata -Endpoint $Endpoint -AccessToken $AccessToken

    if ($metadata) {
        try {
            Write-Log ("Supported ADLS Gen2 metadata: {0}" -f ($metadata | ConvertTo-Json -Depth 6 -Compress)) 'DEBUG'
        } catch {
            Write-Log "Failed to serialize ADLS metadata for diagnostics: $($_.Exception.Message)" 'DEBUG'
        }
    }

    $accountUrl = $StorageLocation.TrimEnd('/')
    $accountHost = $accountUrl

    $accountUri = $null
    if ([System.Uri]::TryCreate($accountUrl, [System.UriKind]::Absolute, [ref]$accountUri)) {
        if ($accountUri.Host) {
            $accountHost = $accountUri.Host
            if ($accountUri.IsDefaultPort -eq $false -and $accountUri.Port -gt 0) {
                $accountHost = "$($accountUri.Host):$($accountUri.Port)"
            }
        }
    } else {
        $accountHost = ($accountUrl -replace '^[a-zA-Z][a-zA-Z0-9+.-]*://', '').Trim('/')
    }

    $containerSubpathString = if ($PSBoundParameters.ContainsKey('ContainerSubpath')) { [string]$ContainerSubpath } else { '' }
    $containerPathTrimmed = if ([string]::IsNullOrWhiteSpace($containerSubpathString)) { '' } else { $containerSubpathString.Trim('/') }

    $rawSegments = if ([string]::IsNullOrWhiteSpace($containerPathTrimmed)) {
        @()
    } else {
        @($containerPathTrimmed.Split('/', [System.StringSplitOptions]::RemoveEmptyEntries))
    }

    $containerSegments = @()
    foreach ($segment in $rawSegments) {
        if ($null -eq $segment) {
            continue
        }

        $segmentText = ($segment -as [string])
        if (-not [string]::IsNullOrWhiteSpace($segmentText)) {
            $containerSegments += $segmentText.Trim()
        }
    }

    $segmentCount = $containerSegments.Count
    $fileSystemName = if ($segmentCount -gt 0) { $containerSegments[0] } else { $null }
    $relativePath = if ($segmentCount -gt 1) { [string]::Join('/', $containerSegments[1..($segmentCount - 1)]) } else { $null }
    $fullPathRelative = if ($segmentCount -gt 0) { [string]::Join('/', $containerSegments) } else { $null }
    $isRootRequest = [string]::IsNullOrWhiteSpace($containerPathTrimmed)

    if (-not $fileSystemName -and -not $isRootRequest) {
        throw "Container subpath '$ContainerSubpath' did not resolve to an ADLS Gen2 file system for connection creation."
    }

    $pathWithLeadingSlash = if ($fullPathRelative) { "/$fullPathRelative" } else { '/' }
    $fullPathAbsolute = if ($fullPathRelative) { "$accountUrl/$fullPathRelative" } else { $accountUrl }
    $pathParameterValue = if ($fullPathRelative) { $fullPathRelative } else { '/' }

    $connectionType = 'AdlsGen2'
    $creationMethodName = 'AdlsGen2'
    $parameterObjects = @()
    $encryptionOption = 'NotEncrypted'

    


    if ($metadata) {
        $connectionType = if ($metadata.PSObject.Properties['type']) { [string]$metadata.type } else { $connectionType }

        $method = $null
        if ($metadata.PSObject.Properties['creationMethods']) {
            $method = $metadata.creationMethods | Select-Object -First 1
        }

        if ($metadata.PSObject.Properties['supportedConnectionEncryptionTypes']) {
            $supported = @($metadata.supportedConnectionEncryptionTypes)
            if ($supported.Length -gt 0) {
                if ($supported -contains 'Encrypted') {
                    $encryptionOption = 'Encrypted'
                } else {
                    $encryptionOption = [string]$supported[0]
                }
            }
        }

        if ($method -and $method.PSObject.Properties['name']) {
            $creationMethodName = [string]$method.name

            if ($method.PSObject.Properties['parameters']) {
                foreach ($parameter in $method.parameters) {
                    $paramName = [string]$parameter.name
                    $compactName = ($paramName -replace '[^a-zA-Z0-9]', '').ToLowerInvariant()
                    $value = $null
                    
                    Write-Host "Full relative Path" $fullPathRelative
                    Write-Host "Path with leading slash" $pathWithLeadingSlash
                    Write-Host "Full absolute path" $fullPathAbsolute

                    if ($compactName -match 'pathuri|pathurl|urlpath') {
                        $value = $fullPathAbsolute
                    } elseif ($compactName -match 'fullpath') {
                        $value = $pathParameterValue
                    } elseif ($compactName -eq 'path') {
                        $value = $pathParameterValue
                    } elseif ($compactName -match 'server|host') {
                        $value = $accountHost
                    } elseif ($compactName -match 'account|endpoint|url|location|dfs') {
                        $value = $accountUrl
                    } elseif ($compactName -match 'filesystem|container|root') {
                        $value = if ($fileSystemName) { $fileSystemName } elseif ($isRootRequest) { '/' } else { $null }
                    } elseif ($compactName -match 'subpath|relativepath|folder|directory') {
                        if (-not [string]::IsNullOrWhiteSpace($relativePath)) {
                            $value = $relativePath
                        } elseif ($isRootRequest) {
                            $value = '/'
                        } elseif (-not [string]::IsNullOrWhiteSpace($fileSystemName)) {
                            $value = ''
                        }
                    }

                    if ($parameter.required -and [string]::IsNullOrWhiteSpace($value) -and -not $isRootRequest) {
                        Write-Log "Unable to auto-map required parameter '$paramName'. Metadata: $(($parameter | ConvertTo-Json -Compress -Depth 3))" 'WARN'
                        throw "Unable to map required parameter '$paramName' for ADLS Gen2 connection creation."
                    }

                    $shouldAddParameter = -not [string]::IsNullOrWhiteSpace($value)
                    if (-not $shouldAddParameter -and $isRootRequest -and ($compactName -match 'filesystem|container|root|subpath|relativepath|folder|directory')) {
                        $shouldAddParameter = $true
                        $value = if ($compactName -match 'filesystem|container|root') { '/' } else { '/' }
                    }

                    if ($shouldAddParameter) {
                        $parameterObjects += @{
                            name    = $paramName
                            dataType = if ($parameter.PSObject.Properties['dataType']) { [string]$parameter.dataType } else { 'Text' }
                            value   = $value
                        }
                    }
                }
            }
        }
    }

    if ($parameterObjects.Length -gt 0) {
        for ($index = 0; $index -lt $parameterObjects.Length; $index++) {
            $param = $parameterObjects[$index]
            if (-not ($param -is [System.Collections.IDictionary])) {
                continue
            }

            $paramName = [string]$param['name']
            $valueCandidate = $param['value']

            if ($valueCandidate -is [System.Collections.IEnumerable] -and -not ($valueCandidate -is [string])) {
                $segments = @()
                foreach ($segment in $valueCandidate) {
                    if ($null -ne $segment) {
                        $segments += [string]$segment
                    }
                }

                if ($segments.Count -eq 0) {
                    $valueCandidate = ''
                } elseif ($segments.Count -eq 1) {
                    $valueCandidate = $segments[0]
                } elseif (($segments | Where-Object { $_.Length -gt 1 }).Count -gt 0) {
                    $valueCandidate = [string]::Join('/', $segments)
                } else {
                    $valueCandidate = -join $segments
                }
            }

            if ($paramName) {
                if ($paramName.Equals('path', [System.StringComparison]::OrdinalIgnoreCase)) {
                    $valueCandidate = $pathParameterValue
                } elseif ($paramName.Equals('server', [System.StringComparison]::OrdinalIgnoreCase)) {
                    $valueCandidate = $accountHost
                } elseif ($paramName -match 'filesystem|container|root') {
                    $valueCandidate = if ($fileSystemName) { $fileSystemName } elseif ($isRootRequest) { '/' } else { $fileSystemName }
                } elseif ($paramName -match 'subpath|relativepath|folder|directory') {
                    if (-not [string]::IsNullOrWhiteSpace($relativePath)) {
                        $valueCandidate = $relativePath
                    } elseif ($isRootRequest) {
                        $valueCandidate = '/'
                    } elseif (-not [string]::IsNullOrWhiteSpace($fileSystemName)) {
                        $valueCandidate = ''
                    }
                }
            }

            $parameterObjects[$index]['value'] = $valueCandidate
        }
    }

    if ($parameterObjects.Length -eq 0) {
        $parameterObjects = @(
            @{ name = 'server'; dataType = 'Text'; value = $accountHost }
            @{ name = 'path';   dataType = 'Text'; value = $pathParameterValue }
        )
    }

    $credentialDetails = @{
        singleSignOnType      = 'None'
        connectionEncryption  = $encryptionOption
        skipTestConnection    = $false
        credentials = @{
            credentialType = 'WorkspaceIdentity'
        }
    }

    $body = @{
        connectivityType = 'ShareableCloud'
        displayName      = $DisplayName
        privacyLevel     = 'Organizational'
        connectionDetails = @{
            type           = $connectionType
            creationMethod = $creationMethodName
            parameters     = $parameterObjects
        }
        credentialDetails = $credentialDetails
    }

    Write-Log "Creating ADLS connection using type '$connectionType' and method '$creationMethodName'." 'DEBUG'

    $headers = Get-FabricApiHeaders -AccessToken $AccessToken
    $uri = "$($Endpoint.TrimEnd('/'))/v1/connections"

    # Per https://learn.microsoft.com/en-us/rest/api/fabric/core/connections/create-connection
    try {
        $result = Invoke-FabricApiRequest -Method 'Post' -Uri $uri -Headers $headers -Body $body -Description "Create ADLS Gen2 connection '$DisplayName'"
    } catch {
        $message = $_.Exception.Message
        Write-Log "Failed to create Fabric connection '$DisplayName': $message" 'ERROR'
        throw
    }

    $response = $result.Response
    if ($response -and $response.PSObject.Properties['id']) {
        $connectionId = [string]$response.id
        Write-Log "Created Fabric connection '$DisplayName' (ID: $connectionId)." 'INFO'
        return $connectionId
    }

    throw "Fabric connection response did not include an identifier for '$DisplayName'."
}

function Get-FabricShortcutByName {
    param(
        [Parameter(Mandatory = $true)][string]$Endpoint,
        [Parameter(Mandatory = $true)][string]$AccessToken,
        [Parameter(Mandatory = $true)][string]$WorkspaceId,
        [Parameter(Mandatory = $true)][string]$LakehouseId,
        [Parameter(Mandatory = $true)][string]$ShortcutName,
        [Parameter(Mandatory = $true)][string]$ShortcutPath
    )

    $headers = Get-FabricApiHeaders -AccessToken $AccessToken
    $workspaceIdEncoded = [Uri]::EscapeDataString($WorkspaceId)
    $lakehouseIdEncoded = [Uri]::EscapeDataString($LakehouseId)
    $uri = "$($Endpoint.TrimEnd('/'))/v1/workspaces/$workspaceIdEncoded/items/$lakehouseIdEncoded/shortcuts"

    try {
        $result = Invoke-FabricApiRequest -Method 'Get' -Uri $uri -Headers $headers -Description "List Fabric shortcuts for lakehouse '$LakehouseId'"
    } catch {
        Write-Log "Unable to list Fabric shortcuts for lakehouse '$LakehouseId': $($_.Exception.Message)" 'WARN'
        return $null
    }

    $response = $result.Response
    $items = @()
    if ($null -ne $response) {
        if ($response.PSObject.Properties['value']) {
            $items = @($response.value)
        } elseif ($response -is [System.Collections.IEnumerable] -and -not ($response -is [string])) {
            $items = @($response)
        } else {
            $items = @($response)
        }
    }

    foreach ($item in $items) {
        $nameMatches = $item.PSObject.Properties['name'] -and $item.name -eq $ShortcutName
        $pathMatches = $item.PSObject.Properties['path'] -and $item.path -eq $ShortcutPath
        if ($nameMatches -and $pathMatches) {
            return $item
        }
    }

    return $null
}

function Get-FabricShortcutIndex {
    param(
        [Parameter(Mandatory = $true)][string]$Endpoint,
        [Parameter(Mandatory = $true)][string]$AccessToken,
        [Parameter(Mandatory = $true)][string]$WorkspaceId,
        [Parameter(Mandatory = $true)][string]$LakehouseId
    )

    $headers = Get-FabricApiHeaders -AccessToken $AccessToken
    $workspaceIdEncoded = [Uri]::EscapeDataString($WorkspaceId)
    $lakehouseIdEncoded = [Uri]::EscapeDataString($LakehouseId)
    $uri = "$($Endpoint.TrimEnd('/'))/v1/workspaces/$workspaceIdEncoded/items/$lakehouseIdEncoded/shortcuts"

    try {
        $result = Invoke-FabricApiRequest -Method 'Get' -Uri $uri -Headers $headers -Description "List Fabric shortcuts for lakehouse '$LakehouseId'"
    } catch {
        Write-Log "Unable to index Fabric shortcuts for lakehouse '$LakehouseId': $($_.Exception.Message)" 'WARN'
        return [pscustomobject]@{
            Success = $false
            Items   = @()
            ByName  = @{}
            ByPath  = @{}
        }
    }

    $response = $result.Response
    $items = @()
    if ($null -ne $response) {
        if ($response.PSObject.Properties['value']) {
            $items = @($response.value)
        } elseif ($response -is [System.Collections.IEnumerable] -and -not ($response -is [string])) {
            $items = @($response)
        } else {
            $items = @($response)
        }
    }

    $byName = @{}
    $byPath = @{}

    foreach ($item in $items) {
        if (-not $item) {
            continue
        }

        $nameValue = if ($item.PSObject.Properties['name']) { [string]$item.name } else { $null }
        if (-not [string]::IsNullOrWhiteSpace($nameValue)) {
            $byName[$nameValue.ToLowerInvariant()] = $item
        }

        $pathValue = if ($item.PSObject.Properties['path']) { [string]$item.path } else { $null }
        if (-not [string]::IsNullOrWhiteSpace($pathValue)) {
            $byPath[$pathValue.ToLowerInvariant()] = $item
        }
    }

    return [pscustomobject]@{
        Success = $true
        Items   = $items
        ByName  = $byName
        ByPath  = $byPath
    }
}

function Remove-FabricShortcut {
    param(
        [Parameter(Mandatory = $true)][string]$Endpoint,
        [Parameter(Mandatory = $true)][string]$AccessToken,
        [Parameter(Mandatory = $true)][string]$WorkspaceId,
        [Parameter(Mandatory = $true)][string]$LakehouseId,
        [Parameter(Mandatory = $true)][string]$ShortcutId,
        [string]$ShortcutName
    )

    $headers = Get-FabricApiHeaders -AccessToken $AccessToken
    $workspaceIdEncoded = [Uri]::EscapeDataString($WorkspaceId)
    $lakehouseIdEncoded = [Uri]::EscapeDataString($LakehouseId)
    $shortcutIdEncoded = [Uri]::EscapeDataString($ShortcutId)
    $uri = "$($Endpoint.TrimEnd('/'))/v1/workspaces/$workspaceIdEncoded/items/$lakehouseIdEncoded/shortcuts/$shortcutIdEncoded"

    $displayName = if ([string]::IsNullOrWhiteSpace($ShortcutName)) { $ShortcutId } else { $ShortcutName }
    Write-Log "Deleting Fabric shortcut '$displayName' (ID: $ShortcutId)." 'INFO'

    try {
        Invoke-FabricApiRequest -Method 'Delete' -Uri $uri -Headers $headers -Description "Delete Fabric shortcut '$displayName'" | Out-Null
        return $true
    } catch {
        $caughtError = $_
        Write-Log "Failed to delete Fabric shortcut '$displayName': $($caughtError.Exception.Message)" 'ERROR'
        return $false
    }
}

function Get-FabricBlobConnectionId {
    param(
        [Parameter(Mandatory = $true)][string]$FabricEndpoint,
        [Parameter(Mandatory = $true)][string]$WorkspaceId,
        [Parameter(Mandatory = $true)][string]$FabricAccessToken,
        [Parameter(Mandatory = $true)][string]$BlobConnectionDisplayName,
        [Parameter(Mandatory = $true)][string]$BlobEndpoint,
        [string]$DefaultContainerName,
        [switch]$SkipExistingDetailLog
    )

    $existingBlobConnection = Get-FabricConnectionByDisplayName -Endpoint $FabricEndpoint -AccessToken $FabricAccessToken -DisplayName $BlobConnectionDisplayName -WorkspaceId $WorkspaceId

    if ($existingBlobConnection -and $existingBlobConnection.PSObject.Properties['id']) {
        $connectionId = [string]$existingBlobConnection.id
        Write-Log "Found existing Fabric blob connection '$BlobConnectionDisplayName' (ID: $connectionId)." 'INFO'

        if (-not $SkipExistingDetailLog.IsPresent) {
            try {
                if ($existingBlobConnection.PSObject.Properties['connectionDetails']) {
                    $connectionDetailsJson = $existingBlobConnection.connectionDetails | ConvertTo-Json -Depth 5 -Compress
                    Write-Log "Existing connection details: $connectionDetailsJson" 'DEBUG'
                }
            } catch {
                Write-Log "Unable to serialize existing connection details for '$BlobConnectionDisplayName': $($_.Exception.Message)" 'DEBUG'
            }
        }
    } else {
        $newConnectionParams = @{
            Endpoint        = $FabricEndpoint
            WorkspaceId     = $WorkspaceId
            AccessToken     = $FabricAccessToken
            DisplayName     = $BlobConnectionDisplayName
            StorageLocation = $BlobEndpoint
        }

        if (-not [string]::IsNullOrWhiteSpace($DefaultContainerName)) {
            $newConnectionParams['DefaultContainerName'] = $DefaultContainerName
        }

        $connectionId = New-FabricBlobConnection @newConnectionParams
    }

    if ([string]::IsNullOrWhiteSpace($connectionId)) {
        throw "Unable to resolve a Fabric connection ID for '$BlobConnectionDisplayName'."
    }

    return $connectionId
}

function Get-FabricAdlsConnectionId {
    param(
        [Parameter(Mandatory = $true)][string]$FabricEndpoint,
        [Parameter(Mandatory = $true)][string]$WorkspaceId,
        [Parameter(Mandatory = $true)][string]$FabricAccessToken,
        [Parameter(Mandatory = $true)][string]$AdlsConnectionDisplayName,
        [Parameter(Mandatory = $true)][string]$AdlsEndpoint,
        [string]$DefaultContainerSubpath,
        [switch]$SkipExistingDetailLog
    )

    $existingAdlsConnection = Get-FabricConnectionByDisplayName -Endpoint $FabricEndpoint -AccessToken $FabricAccessToken -DisplayName $AdlsConnectionDisplayName -WorkspaceId $WorkspaceId
    if (-not $existingAdlsConnection) {
        $existingAdlsConnection = Get-FabricConnectionByDisplayName -Endpoint $FabricEndpoint -AccessToken $FabricAccessToken -DisplayName $AdlsConnectionDisplayName
        if ($existingAdlsConnection) {
            Write-Log "Found tenant-scoped Fabric ADLS connection '$AdlsConnectionDisplayName'." 'INFO'
        }
    }

    if ($existingAdlsConnection -and $existingAdlsConnection.PSObject.Properties['id']) {
        $connectionId = [string]$existingAdlsConnection.id
        Write-Log "Found existing Fabric ADLS connection '$AdlsConnectionDisplayName' (ID: $connectionId)." 'INFO'

        if (-not $SkipExistingDetailLog.IsPresent) {
            try {
                if ($existingAdlsConnection.PSObject.Properties['connectionDetails']) {
                    $connectionDetailsJson = $existingAdlsConnection.connectionDetails | ConvertTo-Json -Depth 5 -Compress
                    Write-Log "Existing ADLS connection details: $connectionDetailsJson" 'DEBUG'
                }
            } catch {
                Write-Log "Unable to serialize existing ADLS connection details for '$AdlsConnectionDisplayName': $($_.Exception.Message)" 'DEBUG'
            }
        }
    } else {
        $newConnectionParams = @{
            Endpoint        = $FabricEndpoint
            WorkspaceId     = $WorkspaceId
            AccessToken     = $FabricAccessToken
            DisplayName     = $AdlsConnectionDisplayName
            StorageLocation = $AdlsEndpoint
        }

        if ($PSBoundParameters.ContainsKey('DefaultContainerSubpath')) {
            $newConnectionParams['ContainerSubpath'] = $DefaultContainerSubpath
        }

        $connectionId = New-FabricAdlsConnection @newConnectionParams
    }

    if ([string]::IsNullOrWhiteSpace($connectionId)) {
        throw "Unable to resolve a Fabric connection ID for '$AdlsConnectionDisplayName'."
    }

    return $connectionId
}

function New-FabricImageShortcuts {
    param(
        [Parameter(Mandatory = $true)][string]$OneLakeEndpoint,
        [Parameter(Mandatory = $true)][string]$FabricEndpoint,
        [Parameter(Mandatory = $true)][string]$WorkspaceId,
        [Parameter(Mandatory = $true)][string]$LakehouseId,
        [Parameter(Mandatory = $true)][string]$OneLakeAccessToken,
        [Parameter(Mandatory = $true)][string]$FabricAccessToken,
        [Parameter(Mandatory = $true)][psobject[]]$StmoDefinitions,
        [Parameter(Mandatory = $true)][string]$BlobStorageAccountName,
        [Parameter(Mandatory = $true)][string]$BlobConnectionDisplayName
    )

    if (-not $StmoDefinitions -or $StmoDefinitions.Count -eq 0) {
        Write-Log 'No STMO definitions provided for inventory shortcut creation.' 'WARN'
        return
    }

    $segments = Resolve-LakehouseSegments -WorkspaceId $WorkspaceId -LakehouseId $LakehouseId
    $basePath = '/Files/Ingest/Imaging/DICOM'
    $baseSegments = Get-LakehousePathSegments -FullPath $basePath
    if ($baseSegments.Count -gt 0) {
        New-LakehouseDirectoryPath -Endpoint $OneLakeEndpoint -WorkspaceSegment $segments.Workspace -LakehouseSegment $segments.Lakehouse -PathSegments $baseSegments -AccessToken $OneLakeAccessToken
    }

    $blobEndpoint = "https://$BlobStorageAccountName.blob.core.windows.net"
    $defaultDefinition = $StmoDefinitions | Select-Object -First 1
    $defaultInventoryContainerName = if ($defaultDefinition -and $defaultDefinition.PSObject.Properties['InventoryContainerName']) {
        [string]$defaultDefinition.InventoryContainerName
    } elseif ($defaultDefinition -and $defaultDefinition.PSObject.Properties['ContainerName']) {
        [string]$defaultDefinition.ContainerName
    } else {
        $null
    }

    $connectionId = Get-FabricBlobConnectionId -FabricEndpoint $FabricEndpoint -WorkspaceId $WorkspaceId -FabricAccessToken $FabricAccessToken -BlobConnectionDisplayName $BlobConnectionDisplayName -BlobEndpoint $blobEndpoint -DefaultContainerName $defaultInventoryContainerName

    $shortcutIndex = Get-FabricShortcutIndex -Endpoint $FabricEndpoint -AccessToken $FabricAccessToken -WorkspaceId $WorkspaceId -LakehouseId $LakehouseId
    if (-not $shortcutIndex.Success) {
        Write-Log 'Unable to evaluate existing lakehouse shortcuts; skipping inventory shortcut creation to avoid conflicts.' 'WARN'
        return
    }

    $existingByName = if ($shortcutIndex.ByName) { $shortcutIndex.ByName } else { @{} }
    $existingByPath = if ($shortcutIndex.ByPath) { $shortcutIndex.ByPath } else { @{} }

    foreach ($definition in $StmoDefinitions) {
        $containerName = [string]$definition.ContainerName
        $inventoryContainerName = if ($definition.PSObject.Properties['InventoryContainerName']) { [string]$definition.InventoryContainerName } else { $null }

        if ([string]::IsNullOrWhiteSpace($containerName)) {
            Write-Log 'Encountered STMO definition without a container name; skipping.' 'WARN'
            continue
        }

        if ([string]::IsNullOrWhiteSpace($inventoryContainerName)) {
            Write-Log "STMO '$containerName' does not have an inventory container name; skipping inventory shortcut creation." 'WARN'
            continue
        }

        $pathSegments = @($baseSegments + $containerName + 'InventoryFiles')
        if ($pathSegments.Count -gt 0) {
            New-LakehouseDirectoryPath -Endpoint $OneLakeEndpoint -WorkspaceSegment $segments.Workspace -LakehouseSegment $segments.Lakehouse -PathSegments $pathSegments -AccessToken $OneLakeAccessToken
        }

        $shortcutPath = "Files/Ingest/Imaging/DICOM/$containerName/InventoryFiles"
        $shortcutName = "$containerName-inv"

        $shortcutPathKey = $shortcutPath.ToLowerInvariant()
        $shortcutNameKey = $shortcutName.ToLowerInvariant()

        if ($existingByPath.ContainsKey($shortcutPathKey)) {
            $existingEntry = $existingByPath[$shortcutPathKey]
            $existingName = if ($existingEntry -and $existingEntry.PSObject.Properties['name']) { [string]$existingEntry.name } else { '<unknown>' }
            Write-Log "Inventory shortcut path '$shortcutPath' already exists and is mapped to '$existingName'; skipping creation." 'INFO'
            continue
        }

        if ($existingByName.ContainsKey($shortcutNameKey)) {
            $existingEntryByName = $existingByName[$shortcutNameKey]
            $existingPath = if ($existingEntryByName -and $existingEntryByName.PSObject.Properties['path']) { [string]$existingEntryByName.path } else { '<unknown>' }
            Write-Log "Inventory shortcut name '$shortcutName' already exists at path '$existingPath'; skipping creation." 'INFO'
            continue
        }

        $body = @{
            path = $shortcutPath
            name = $shortcutName
            target = @{
                azureBlobStorage = @{
                    location = $blobEndpoint
                    subpath  = "/$inventoryContainerName"
                    connectionId = $connectionId
                }
            }
        }

        $headers = Get-FabricApiHeaders -AccessToken $FabricAccessToken
        $workspaceIdEncoded = [Uri]::EscapeDataString($WorkspaceId)
        $lakehouseIdEncoded = [Uri]::EscapeDataString($LakehouseId)
        $uri = "$($FabricEndpoint.TrimEnd('/'))/v1/workspaces/$workspaceIdEncoded/items/$lakehouseIdEncoded/shortcuts?shortcutConflictPolicy=Abort"

        try {
            $creationResult = Invoke-FabricApiRequest -Method 'Post' -Uri $uri -Headers $headers -Body $body -Description "Create inventory shortcut '$shortcutName'"
            Write-Log "Created Fabric inventory shortcut '$shortcutName' -> '$blobEndpoint/$inventoryContainerName'." 'INFO'

            if ($creationResult -and $creationResult.Response) {
                $createdShortcut = $creationResult.Response
                if ($createdShortcut.PSObject.Properties['name']) {
                    $existingByName[$shortcutNameKey] = $createdShortcut
                }
                if ($createdShortcut.PSObject.Properties['path']) {
                    $existingByPath[$shortcutPathKey] = $createdShortcut
                }
            } else {
                $existingByName[$shortcutNameKey] = $true
                $existingByPath[$shortcutPathKey] = $true
            }
        } catch {
            $caughtError = $_
            $handledConflict = $false

            if ($caughtError.Exception -and $caughtError.Exception.Response) {
                $response = $caughtError.Exception.Response
                $statusCodeValue = $null

                if ($response -is [System.Net.Http.HttpResponseMessage]) {
                    $statusCodeValue = [int]$response.StatusCode
                } elseif ($response.PSObject.Properties['StatusCode']) {
                    $statusCodeRaw = $response.StatusCode
                    try {
                        $statusCodeValue = [int]$statusCodeRaw
                    } catch {
                        if ($statusCodeRaw -and $statusCodeRaw.PSObject.Properties['value__']) {
                            $statusCodeValue = [int]$statusCodeRaw.value__
                        }
                    }
                }

                if ($statusCodeValue -eq 409) {
                    Write-Log "Inventory shortcut '$shortcutName' already exists according to Fabric API (HTTP 409). Skipping creation." 'WARN'
                    $existingByPath[$shortcutPathKey] = $true
                    $existingByName[$shortcutNameKey] = $true
                    $handledConflict = $true
                }
            }

            if (-not $handledConflict) {
                $errorMessage = "Failed to create inventory shortcut '$shortcutName': $($caughtError.Exception.Message)"
                Write-Log $errorMessage 'ERROR'
                throw
            }
        }
    }
}

function New-FabricOperationsShortcuts {
    param(
        [Parameter(Mandatory = $true)][string]$OneLakeEndpoint,
        [Parameter(Mandatory = $true)][string]$FabricEndpoint,
        [Parameter(Mandatory = $true)][string]$WorkspaceId,
        [Parameter(Mandatory = $true)][string]$LakehouseId,
        [Parameter(Mandatory = $true)][string]$OneLakeAccessToken,
        [Parameter(Mandatory = $true)][string]$FabricAccessToken,
        [Parameter(Mandatory = $true)][psobject[]]$StmoDefinitions,
        [Parameter(Mandatory = $true)][string]$OperationsPath,
        [Parameter(Mandatory = $true)][string]$InventoryStorageAccountName
    )

    $normalizedOperationsPath = $OperationsPath.Trim()
    if (-not $normalizedOperationsPath.StartsWith('/')) {
        $normalizedOperationsPath = "/$normalizedOperationsPath"
    }

    if (-not [string]::IsNullOrWhiteSpace($LakehouseOperationsPath) -and -not $normalizedOperationsPath.Equals($LakehouseOperationsPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        $message = "Operations shortcut path '$normalizedOperationsPath' does not match required lakehouse path '$LakehouseOperationsPath'."
        Write-Log $message 'ERROR'
        throw $message
    }

    $segments = Resolve-LakehouseSegments -WorkspaceId $WorkspaceId -LakehouseId $LakehouseId
    $operationsSegments = Get-LakehousePathSegments -FullPath $normalizedOperationsPath
    New-LakehouseDirectoryPath -Endpoint $OneLakeEndpoint -WorkspaceSegment $segments.Workspace -LakehouseSegment $segments.Lakehouse -PathSegments $operationsSegments -AccessToken $OneLakeAccessToken

    $shortcutPath = $normalizedOperationsPath.TrimStart('/')
    if ([string]::IsNullOrWhiteSpace($shortcutPath)) {
        Write-Log 'Lakehouse shortcut path resolved to an empty string; skipping shortcut creation.' 'WARN'
        return
    }

    $operationsEndpoint = "https://$InventoryStorageAccountName.dfs.core.windows.net"
    $operationsConnectionDisplayName = "fab-$InventoryStorageAccountName-adls-conn"
    $operationsConnectionId = Get-FabricAdlsConnectionId -FabricEndpoint $FabricEndpoint -WorkspaceId $WorkspaceId -FabricAccessToken $FabricAccessToken -AdlsConnectionDisplayName $operationsConnectionDisplayName -AdlsEndpoint $operationsEndpoint -DefaultContainerSubpath '/'
    Write-Log "Using Fabric ADLS connection '$operationsConnectionDisplayName' (ID: $operationsConnectionId) for operations shortcuts." 'INFO'

    $shortcutIndex = Get-FabricShortcutIndex -Endpoint $FabricEndpoint -AccessToken $FabricAccessToken -WorkspaceId $WorkspaceId -LakehouseId $LakehouseId
    if (-not $shortcutIndex.Success) {
        Write-Log 'Unable to evaluate existing lakehouse shortcuts; skipping operations shortcut creation to avoid conflicts.' 'WARN'
        return
    }

    $shortcutItems = if ($shortcutIndex.Items) { @($shortcutIndex.Items) } else { @() }
    $processedContainers = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $loggedConflicts = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($definition in $StmoDefinitions) {
        $operationsContainer = $definition.ContainerName
        if ([string]::IsNullOrWhiteSpace($operationsContainer)) {
            Write-Log 'Encountered STMO definition without a container name for operations shortcut; skipping.' 'WARN'
            continue
        }

        if (-not $processedContainers.Add($operationsContainer)) {
            Write-Log "Operations shortcut for container '$operationsContainer' already processed; skipping duplicate definition." 'INFO'
            continue
        }

        $containerSubpath = "/$operationsContainer"

        $shortcutName = $operationsContainer
        $shortcutNameKey = $shortcutName.ToLowerInvariant()
        $targetPath = "/$shortcutPath"

        $existingShortcut = $shortcutItems | Where-Object {
            $_ -and $_.PSObject.Properties['name'] -and $_.PSObject.Properties['path'] -and
            [string]::Equals([string]$_.name, $shortcutName, [System.StringComparison]::OrdinalIgnoreCase) -and
            [string]::Equals([string]$_.path, $targetPath, [System.StringComparison]::OrdinalIgnoreCase)
        } | Select-Object -First 1

        $conflictingShortcuts = $shortcutItems | Where-Object {
            $_ -and $_.PSObject.Properties['name'] -and [string]::Equals([string]$_.name, $shortcutName, [System.StringComparison]::OrdinalIgnoreCase) -and (
                -not ($_.PSObject.Properties['path'] -and [string]::Equals([string]$_.path, $targetPath, [System.StringComparison]::OrdinalIgnoreCase))
            )
        }

        foreach ($conflict in $conflictingShortcuts) {
            $conflictPath = if ($conflict.PSObject.Properties['path']) { [string]$conflict.path } else { '<unknown>' }
            if ($loggedConflicts.Add("$shortcutNameKey|$conflictPath")) {
                Write-Log "Found shortcut '$shortcutName' at non-operations path '$conflictPath'; leaving in place." 'INFO'
            }
        }

        if ($existingShortcut) {
            $targetObject = $null
            if ($existingShortcut.PSObject.Properties['target']) {
                $targetObject = $existingShortcut.target
            }

            $adlsTarget = $null
            if ($targetObject -and $targetObject.PSObject.Properties['adlsGen2']) {
                $adlsTarget = $targetObject.adlsGen2
            }

            $locationMatches = $false
            $subpathMatches = $false

            if ($adlsTarget) {
                if ($adlsTarget.PSObject.Properties['location']) {
                    $locationMatches = [string]::Equals([string]$adlsTarget.location, $operationsEndpoint, [System.StringComparison]::OrdinalIgnoreCase)
                }

                if ($adlsTarget.PSObject.Properties['subpath']) {
                    $subpathMatches = [string]::Equals([string]$adlsTarget.subpath, $containerSubpath, [System.StringComparison]::OrdinalIgnoreCase)
                }
            }

            if ($locationMatches -and $subpathMatches) {
                Write-Log "Operations shortcut '$shortcutName' already exists at path '$targetPath' with the correct ADLS target; skipping creation." 'INFO'
                continue
            }

            Write-Log "Operations shortcut '$shortcutName' exists at path '$targetPath' but points to a different target; recreating." 'WARN'

            $shortcutId = if ($existingShortcut.PSObject.Properties['id']) { [string]$existingShortcut.id } else { $null }
            if ([string]::IsNullOrWhiteSpace($shortcutId)) {
                Write-Log "Unable to remediate shortcut '$shortcutName' because the existing entry did not include an id; skipping." 'ERROR'
                continue
            }

            $deleteSucceeded = Remove-FabricShortcut -Endpoint $FabricEndpoint -AccessToken $FabricAccessToken -WorkspaceId $WorkspaceId -LakehouseId $LakehouseId -ShortcutId $shortcutId -ShortcutName $shortcutName
            if (-not $deleteSucceeded) {
                Write-Log "Skipping recreation of operations shortcut '$shortcutName' due to delete failure." 'ERROR'
                continue
            }

            $shortcutItems = $shortcutItems | Where-Object {
                if ($_.PSObject.Properties['id']) {
                    -not [string]::Equals([string]$_.id, $shortcutId, [System.StringComparison]::OrdinalIgnoreCase)
                } else {
                    -not (
                        $_.PSObject.Properties['name'] -and [string]::Equals([string]$_.name, $shortcutName, [System.StringComparison]::OrdinalIgnoreCase) -and
                        $_.PSObject.Properties['path'] -and [string]::Equals([string]$_.path, $targetPath, [System.StringComparison]::OrdinalIgnoreCase)
                    )
                }
            }
        }

        $body = @{
            path = $shortcutPath
            name = $shortcutName
            target = @{
                adlsGen2 = @{
                    location = $operationsEndpoint
                    subpath  = $containerSubpath
                    connectionId = $operationsConnectionId
                }
            }
        }

        $headers = Get-FabricApiHeaders -AccessToken $FabricAccessToken
        $workspaceIdEncoded = [Uri]::EscapeDataString($WorkspaceId)
        $lakehouseIdEncoded = [Uri]::EscapeDataString($LakehouseId)
        $uri = "$($FabricEndpoint.TrimEnd('/'))/v1/workspaces/$workspaceIdEncoded/items/$lakehouseIdEncoded/shortcuts?shortcutConflictPolicy=Abort"

        try {
            $creationResult = Invoke-FabricApiRequest -Method 'Post' -Uri $uri -Headers $headers -Body $body -Description "Create operations shortcut '$shortcutName'"
            $successMessage = "Created Fabric operations shortcut '$shortcutName' -> '$operationsEndpoint$containerSubpath'."
            Write-Log $successMessage 'INFO'

            if ($creationResult -and $creationResult.Response) {
                $createdShortcut = $creationResult.Response
                if ($createdShortcut) {
                    $shortcutItems = @($shortcutItems + $createdShortcut)
                }
            }
        } catch {
            $caughtError = $_
            $handledConflict = $false

            if ($caughtError.Exception -and $caughtError.Exception.Response) {
                $response = $caughtError.Exception.Response
                $statusCodeValue = $null

                if ($response -is [System.Net.Http.HttpResponseMessage]) {
                    $statusCodeValue = [int]$response.StatusCode
                } elseif ($response.PSObject.Properties['StatusCode']) {
                    $statusCodeRaw = $response.StatusCode
                    try {
                        $statusCodeValue = [int]$statusCodeRaw
                    } catch {
                        if ($statusCodeRaw -and $statusCodeRaw.PSObject.Properties['value__']) {
                            $statusCodeValue = [int]$statusCodeRaw.value__
                        }
                    }
                }

                if ($statusCodeValue -eq 409) {
                    Write-Log "Operations shortcut '$shortcutName' already exists according to Fabric API (HTTP 409). Skipping creation." 'WARN'
                    $handledConflict = $true

                    $refreshedIndex = Get-FabricShortcutIndex -Endpoint $FabricEndpoint -AccessToken $FabricAccessToken -WorkspaceId $WorkspaceId -LakehouseId $LakehouseId
                    if ($refreshedIndex.Success) {
                        $shortcutItems = if ($refreshedIndex.Items) { @($refreshedIndex.Items) } else { @() }
                    }
                }
            }

            if (-not $handledConflict) {
                $errorMessage = "Failed to create operations shortcut '$shortcutName': $($caughtError.Exception.Message)"
                Write-Log $errorMessage 'ERROR'
                throw
            }
        }
    }
}

Write-Log 'Starting HDS DICOM infrastructure orchestration.' 'INFO'

$moduleNames = @('Az.Accounts', 'Az.Resources')
foreach ($name in $moduleNames) {
    if (-not (Get-Module -Name $name)) {
        Import-Module $name -ErrorAction Stop
    }
}

$facilityCsvPathResolved = (Resolve-Path -Path $FacilityCsvPath).Path
$stmoDefinitions = Import-StmoDefinitions -CsvPath $facilityCsvPathResolved
Write-Log "Loaded $($stmoDefinitions.Count) study location definition(s) from CSV." 'INFO'
foreach ($definition in $stmoDefinitions) {
    Write-Log "Study '$($definition.OriginalName)' sanitized to container '$($definition.ContainerName)' (inventory '$($definition.InventoryContainerName)')." 'DEBUG'
}

$blobAccount = Get-SharedStorageAccountName -Prefix $PrefixName -CoreSegment $ImageBlobAccountCoreName -Suffix $LocationSuffix
$operationsAccount = Get-SharedStorageAccountName -Prefix $PrefixName -CoreSegment $ImageOperationsAccountCoreName -Suffix $LocationSuffix

$imageBlobAccountName = $blobAccount.Name
$imageOperationsAccountName = $operationsAccount.Name

if ($blobAccount.WasTrimmed) {
    Write-Log "Blob storage account name trimmed to '$imageBlobAccountName' to satisfy Azure naming limits." 'WARN'
}

if ($operationsAccount.WasTrimmed) {
    Write-Log "Operations storage account name trimmed to '$imageOperationsAccountName' to satisfy Azure naming limits." 'WARN'
}

if ($imageBlobAccountName -eq $imageOperationsAccountName) {
    throw "Derived blob and operations storage account names are identical ('$imageBlobAccountName'). Adjust core name parameters to ensure unique names."
}

Write-Log "Using blob storage account '$imageBlobAccountName' and operations storage account '$imageOperationsAccountName'." 'INFO'

Confirm-AzLogin -Tenant $TenantId -Subscription $SubscriptionId

try {
    Select-AzSubscription -SubscriptionId $SubscriptionId -TenantId $TenantId -ErrorAction Stop | Out-Null
    Write-Log "Using subscription '$SubscriptionId' in tenant '$TenantId'." 'INFO'
} catch {
    $message = "Failed to select subscription '$SubscriptionId' in tenant '$TenantId'. Ensure you are logged in with sufficient permissions."
    Write-Log $message 'ERROR'
    throw $_
}

$assignTrustedWorkspaceIdentityEffective = $true
$trustedWorkspacePrincipalId = (Get-AzADServicePrincipal -DisplayName $hdsWorkspaceName).AppId

try {
    $trustedWorkspacePrincipalId = Get-AzADServicePrincipal -DisplayName $hdsWorkspaceName -ErrorAction Stop |
        Select-Object -First 1 -ExpandProperty Id
} catch {
    throw "Unable to locate a service principal named '$hdsWorkspaceName'. Ensure the Fabric workspace managed identity exists."
}

if ([string]::IsNullOrWhiteSpace($trustedWorkspacePrincipalId)) {
    throw "Fabric workspace managed identity '$hdsWorkspaceName' could not be resolved to an object ID."
}

Write-Log "Workspace identity '$hdsWorkspaceName' resolved to object ID '$trustedWorkspacePrincipalId'." 'INFO'

if (-not $SkipStorageDeployment) {
    $stmoTemplateDefinitions = @()
    foreach ($definition in $stmoDefinitions) {
        $stmoTemplateDefinitions += @{
            containerName          = $definition.ContainerName
            inventoryContainerName = $definition.InventoryContainerName
            ruleName               = $definition.RuleName
            prefixMatch            = $definition.PrefixMatch
        }
    }

    Write-Log "Assigning security group '$DicomAdmSecGrpId' to each storage account as Storage Blob Data Contributor." 'INFO'

    $templateParameters = @{
        stmoDefinitions                 = $stmoTemplateDefinitions
        imageBlobAccountName            = $imageBlobAccountName
        imageOperationsAccountName      = $imageOperationsAccountName
        storageAccountSkuName           = $StorageAccountSkuName
        storageAccountKind              = $StorageAccountKind
        allowSharedKeyAccess            = $false
        globalTags                      = $GlobalTags
        assignTrustedWorkspaceIdentity  = $assignTrustedWorkspaceIdentityEffective
        trustedWorkspacePrincipalId     = if ($assignTrustedWorkspaceIdentityEffective) { $trustedWorkspacePrincipalId } else { '' }
        trustedWorkspacePrincipalType   = $TrustedWorkspacePrincipalType
        dicomAdminSecurityGroupId       = $DicomAdmSecGrpId
    }


        Invoke-StorageDeployment -DeploymentName $DeploymentName -ResourceGroup $ResourceGroupName -TemplatePath $stoBicepTemplatePath -TemplateParameters $templateParameters 
} else {
    Write-Log 'Storage deployment skipped by user request.' 'WARN'
}

$oneLakeAccessToken = $null
$fabricApiAccessToken = $null

if (-not $SkipFabricFolders) {
    if (-not $oneLakeAccessToken) {
        $oneLakeAccessToken = Get-OneLakeAccessToken
    }

    New-FabricInventoryFolders -Endpoint $FabricApiEndpoint -WorkspaceId $FabricWorkspaceId -LakehouseId $HdsBronzeLakehouse -AccessToken $oneLakeAccessToken -StmoDefinitions $stmoDefinitions
    Write-Log 'Fabric inventory folders created or verified successfully.' 'INFO'
} else {
    Write-Log 'Fabric folder creation skipped by user request.' 'WARN'
}

if (-not $SkipFabricShortcuts) {
    if (-not $oneLakeAccessToken) {
        $oneLakeAccessToken = Get-OneLakeAccessToken
    }

    if (-not $fabricApiAccessToken) {
        $fabricApiAccessToken = Get-FabricApiAccessToken
    }

    $blobConnectionDisplayName = "fab-$imageBlobAccountName-blob-conn"

    New-FabricImageShortcuts -OneLakeEndpoint $FabricApiEndpoint -FabricEndpoint $FabricManagementEndpoint -WorkspaceId $FabricWorkspaceId -LakehouseId $HdsBronzeLakehouse -OneLakeAccessToken $oneLakeAccessToken -FabricAccessToken $fabricApiAccessToken -StmoDefinitions $stmoDefinitions -BlobStorageAccountName $imageBlobAccountName -BlobConnectionDisplayName $blobConnectionDisplayName

    New-FabricOperationsShortcuts -OneLakeEndpoint $FabricApiEndpoint -FabricEndpoint $FabricManagementEndpoint -WorkspaceId $FabricWorkspaceId -LakehouseId $HdsBronzeLakehouse -OneLakeAccessToken $oneLakeAccessToken -FabricAccessToken $fabricApiAccessToken -StmoDefinitions $stmoDefinitions -OperationsPath $LakehouseOperationsPath -InventoryStorageAccountName $imageOperationsAccountName
    Write-Log 'Fabric inventory (blob) and operations shortcuts created or verified successfully.' 'INFO'
} else {
    Write-Log 'Fabric shortcut creation skipped by user request.' 'WARN'
}

Write-Log 'HDS DICOM infrastructure orchestration completed.' 'INFO'
