<#
.SYNOPSIS
    Deploys Azure Health Data Services DICOM infrastructure with integrated Fabric storage.

.DESCRIPTION
    This script provisions and configures Azure Health Data Services (HDS) DICOM infrastructure,
    including storage accounts, Fabric workspace integration, lakehouse shortcuts, and folder
    structures. It supports bulk deployment for multiple facilities using a CSV input file.

.AUTHOR
    Joey Brakefield

.DATE
    December 9, 2025

.EXAMPLE
    .\hds-dicom-infra.ps1 `
        -FacilityCsvPath .\example-stmos.csv `
        -TenantId 8d038e6a-9b7d-4cb8-bbcf-e84dff156478 `
        -location westus3 `
        -SubscriptionId 9bbee190-dc61-4c58-ab47-1275cb04018f `
        -ResourceGroupName rg-DICOM `
        -hdsWorkspaceName DICOM-Integration

.EXAMPLE
    .\hds-dicom-infra.ps1 `
        -FacilityCsvPath .\example-stmos.csv `
        -TenantId 8d038e6a-9b7d-4cb8-bbcf-e84dff156478 `
        -location westus3 `
        -SubscriptionId 9bbee190-dc61-4c58-ab47-1275cb04018f `
        -ResourceGroupName rg-DICOM `
        -hdsWorkspaceName DICOM-Integration `
        -ImagesStorageAccountName saimgdcmwu3 `
        -FHIROpsStorageAccountName saimgopswu3 `
        -SkipStorageDeployment
    # Uses specified storage accounts and skips Bicep deployment if accounts already exist

.NOTES
    Requires Az.Accounts, Az.Resources, and Az.Storage PowerShell modules.
    More info: https://github.com/kfprugger/hds-dicom-infra
#>

# .\hds-dicom-infra.ps1 `
#   -FacilityCsvPath .\example-stmos.csv `
# -TenantId 8d038e6a-9b7d-4cb8-bbcf-e84dff156478 
# -location westus3 `
# -SubscriptionId 9bbee190-dc61-4c58-ab47-1275cb04018f 
# -ResourceGroupName rg-DICOM `
# -hdsWorkspaceName DICOM-Integration `
# -ImagesStorageAccountName saimgdcmwu3 `
# -FHIROpsStorageAccountName saimgopswu3 `
# -stoBicepTemplatePath '.\\infra\\storageAccounts.bicep' `
# -DeploymentName hds-storage-provisioning `
# -StorageAccountSkuName Standard_ZRS `
# -StorageAccountKind StorageV2 `
# -FabricWorkspaceId 93acd72f-a23e-4b93-968d-c139600891e7 `
# -HdsBronzeLakehouse 74f52728-9f52-456f-aeb0-a9e250371087 `
# -Debug `
# -DicomAdmSecGrpId 425d706b-afd7-4044-8110-f5fc4663f5bc `
# -SkipStorageDeployment `
# -SkipFabricFolders `
# -SkipFabricShortcuts 

#requires -Modules Az.Accounts, Az.Resources, Az.Storage
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

    [Parameter(Mandatory = $true)]
    [string]$ImagesStorageAccountName, # Name of the Azure Blob storage account for DICOM images and inventory files

    [Parameter(Mandatory = $true)]
    [string]$FHIROpsStorageAccountName, # Name of the Azure ADLS Gen2 storage account for FHIR operations files

    [string]$stoBicepTemplatePath = '.\\infra\\storageAccounts.bicep',

    [string]$DeploymentName = 'hds-storage-provisioning',

    [string]$StorageAccountSkuName = 'Standard_ZRS',

    [string]$StorageAccountKind = 'StorageV2',

    [Parameter(Mandatory = $true)]
    [string]$FabricWorkspaceId = "93acd72f-a23e-4b93-968d-c139600891e7",    # Fabric workspace GUID. I will create a REST lookup based on the -hdsWorkspaceName later.

    [Parameter(Mandatory = $true)]
    [string]$HdsBronzeLakehouse = "74f52728-9f52-456f-aeb0-a9e250371087",


    [Parameter(Mandatory = $true)]
    [string]$DicomAdmSecGrpId,

    [string]$FabricManagementEndpoint = 'https://api.fabric.microsoft.com',

    [Parameter(Mandatory = $true)]
    [string]$allowSharedKeyAccess = $true, # whether to allow shared key access on storage accounts

    
    [hashtable]$GlobalTags = @{},

    
    [switch]$SkipStorageDeployment, # explain to skip the Bicep deployment of storage accounts and containers

    [switch]$SkipFabricFolders, # explain to skip the creation of Fabric folders portion of the script

    [switch]$SkipFabricShortcuts # explain to skip the creation of Fabric shortcuts portion of the script

)

$TrustedWorkspacePrincipalType = 'ServicePrincipal'
$FabricApiEndpoint = 'https://onelake.dfs.fabric.microsoft.com'

# Standard Lakehouse FHIR .ndjson Operations path.
$LakehouseOperationsPath = '/Files/Ingest/Imaging/OPERATIONS/'

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

function Test-StorageAccountExists {
    param(
        [Parameter(Mandatory = $true)][string]$StorageAccountName,
        [Parameter(Mandatory = $true)][string]$ResourceGroupName
    )

    try {
        $account = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction Stop
        return $account
    } catch {
        if ($_.Exception.Message -match 'was not found|does not exist') {
            return $null
        }
        throw $_
    }
}

function Get-StorageAccountContainers {
    param(
        [Parameter(Mandatory = $true)][string]$StorageAccountName,
        [Parameter(Mandatory = $true)][string]$ResourceGroupName
    )

    $context = (Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName).Context
    $containers = Get-AzStorageContainer -Context $context -ErrorAction SilentlyContinue
    return $containers
}

function New-MissingContainers {
    param(
        [Parameter(Mandatory = $true)][string]$StorageAccountName,
        [Parameter(Mandatory = $true)][string]$ResourceGroupName,
        [Parameter(Mandatory = $true)][array]$RequiredContainers
    )

    $context = (Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName).Context
    $existingContainers = Get-AzStorageContainer -Context $context -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name

    foreach ($containerName in $RequiredContainers) {
        if ($existingContainers -notcontains $containerName) {
            Write-Log "Creating missing container '$containerName' in storage account '$StorageAccountName'." 'INFO'
            New-AzStorageContainer -Name $containerName -Context $context -Permission Off -ErrorAction Stop | Out-Null
        } else {
            Write-Log "Container '$containerName' already exists in storage account '$StorageAccountName'." 'DEBUG'
        }
    }
}

function Test-RoleAssignmentExists {
    param(
        [Parameter(Mandatory = $true)][string]$Scope,
        [Parameter(Mandatory = $true)][string]$PrincipalId,
        [Parameter(Mandatory = $true)][string]$RoleDefinitionId
    )

    $assignments = Get-AzRoleAssignment -Scope $Scope -PrincipalId $PrincipalId -ErrorAction SilentlyContinue
    $roleAssignment = $assignments | Where-Object { $_.RoleDefinitionId -eq $RoleDefinitionId }
    return ($null -ne $roleAssignment)
}

function New-MissingRoleAssignment {
    param(
        [Parameter(Mandatory = $true)][string]$Scope,
        [Parameter(Mandatory = $true)][string]$PrincipalId,
        [Parameter(Mandatory = $true)][string]$RoleDefinitionName,
        [Parameter(Mandatory = $true)][string]$PrincipalType,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $existingAssignment = Get-AzRoleAssignment -Scope $Scope -ObjectId $PrincipalId -RoleDefinitionName $RoleDefinitionName -ErrorAction SilentlyContinue

    if (-not $existingAssignment) {
        Write-Log "Assigning '$RoleDefinitionName' to $Description on scope '$Scope'." 'INFO'
        try {
            New-AzRoleAssignment -Scope $Scope -ObjectId $PrincipalId -RoleDefinitionName $RoleDefinitionName -ObjectType $PrincipalType -ErrorAction Stop | Out-Null
        }
        catch {
            # Handle "Conflict" error when role assignment already exists (race condition or propagation delay)
            if ($_.Exception.Message -match 'Conflict|RoleAssignmentExists|already exists') {
                Write-Log "'$RoleDefinitionName' already assigned to $Description on scope '$Scope' (detected during creation)." 'DEBUG'
            }
            else {
                throw $_
            }
        }
    } else {
        Write-Log "'$RoleDefinitionName' already assigned to $Description on scope '$Scope'." 'DEBUG'
    }
}

function Get-BlobInventoryPolicy {
    param(
        [Parameter(Mandatory = $true)][string]$StorageAccountName,
        [Parameter(Mandatory = $true)][string]$ResourceGroupName
    )

    try {
        $policy = Get-AzStorageBlobInventoryPolicy -StorageAccountResourceId "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName" -ErrorAction Stop
        return $policy
    } catch {
        if ($_.Exception.Message -match 'BlobInventoryPolicyNotFound|does not exist') {
            return $null
        }
        throw $_
    }
}

function New-MissingInventoryPolicy {
    param(
        [Parameter(Mandatory = $true)][string]$StorageAccountName,
        [Parameter(Mandatory = $true)][string]$ResourceGroupName,
        [Parameter(Mandatory = $true)][array]$StmoDefinitions
    )

    $existingPolicy = Get-BlobInventoryPolicy -StorageAccountName $StorageAccountName -ResourceGroupName $ResourceGroupName
    $existingRuleNames = @()
    
    if ($existingPolicy -and $existingPolicy.Policy -and $existingPolicy.Policy.Rules) {
        $existingRuleNames = $existingPolicy.Policy.Rules | Select-Object -ExpandProperty Name
    }

    $inventorySchemaFields = @(
        'Name', 'Creation-Time', 'Last-Modified', 'ETag', 'Content-Length', 'Content-Type',
        'Content-Encoding', 'Content-Language', 'Content-CRC64', 'Content-MD5', 'Cache-Control',
        'Content-Disposition', 'BlobType', 'AccessTier', 'AccessTierChangeTime', 'AccessTierInferred',
        'Metadata', 'LastAccessTime', 'LeaseStatus', 'LeaseState', 'LeaseDuration', 'ServerEncrypted',
        'CustomerProvidedKeySha256', 'RehydratePriority', 'ArchiveStatus', 'EncryptionScope',
        'CopyId', 'CopyStatus', 'CopySource', 'CopyProgress', 'CopyCompletionTime', 'CopyStatusDescription',
        'ImmutabilityPolicyUntilDate', 'ImmutabilityPolicyMode', 'LegalHold', 'Tags', 'TagCount'
    )

    $newRules = @()
    foreach ($definition in $StmoDefinitions) {
        if ($existingRuleNames -notcontains $definition.RuleName) {
            Write-Log "Adding inventory rule '$($definition.RuleName)' for container '$($definition.ContainerName)'." 'INFO'
            
            $filter = New-AzStorageBlobInventoryPolicyRule -Name $definition.RuleName `
                -Destination $definition.InventoryContainerName `
                -Format Parquet `
                -Schedule Daily `
                -BlobType blockBlob `
                -PrefixMatch @($definition.PrefixMatch) `
                -BlobSchemaField $inventorySchemaFields

            $newRules += $filter
        } else {
            Write-Log "Inventory rule '$($definition.RuleName)' already exists." 'DEBUG'
        }
    }

    if ($newRules.Count -gt 0) {
        # Combine existing rules with new rules
        $allRules = @()
        if ($existingPolicy -and $existingPolicy.Policy -and $existingPolicy.Policy.Rules) {
            foreach ($rule in $existingPolicy.Policy.Rules) {
                $existingRule = New-AzStorageBlobInventoryPolicyRule -Name $rule.Name `
                    -Destination $rule.Definition.Destination `
                    -Format $rule.Definition.Format `
                    -Schedule $rule.Definition.Schedule `
                    -BlobType $rule.Definition.Filters.BlobTypes `
                    -PrefixMatch $rule.Definition.Filters.PrefixMatch `
                    -BlobSchemaField $rule.Definition.SchemaFields
                $allRules += $existingRule
            }
        }
        $allRules += $newRules

        $storageAccountResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName"
        Set-AzStorageBlobInventoryPolicy -StorageAccountResourceId $storageAccountResourceId -Rule $allRules -ErrorAction Stop | Out-Null
        Write-Log "Inventory policy updated with $($newRules.Count) new rule(s) on storage account '$StorageAccountName'." 'INFO'
    } else {
        Write-Log "All required inventory rules already exist on storage account '$StorageAccountName'." 'DEBUG'
    }
}

function Set-AdlsContainerAcl {
    param(
        [Parameter(Mandatory = $true)][string]$StorageAccountName,
        [Parameter(Mandatory = $true)][string]$ResourceGroupName,
        [Parameter(Mandatory = $true)][string]$ContainerName,
        [Parameter(Mandatory = $true)][string]$PrincipalId,
        [Parameter(Mandatory = $true)]
        [ValidateSet('user', 'group', 'sp', 'other')]
        [string]$PrincipalType,
        [string]$Permissions = 'rwx'
    )

    $context = (Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName).Context
    
    # Map principal type to ACL accessor type
    $aclAccessorType = switch ($PrincipalType) {
        'user'  { 'user' }
        'group' { 'group' }
        'sp'    { 'user' }  # Service principals use 'user' type in ACLs
        'other' { 'other' }
    }

    # Build the ACL entry for both access and default ACLs
    $accessAclEntry = "default:$aclAccessorType`:$PrincipalId`:$Permissions,$aclAccessorType`:$PrincipalId`:$Permissions"

    Write-Log "Setting ACL on container '$ContainerName' for principal '$PrincipalId' with permissions '$Permissions' (type: $aclAccessorType)." 'INFO'

    try {
        # Get the root filesystem item (container)
        $filesystem = Get-AzDataLakeGen2Item -Context $context -FileSystem $ContainerName -ErrorAction Stop

        # Get current ACL
        $currentAcl = $filesystem.ACL

        # Parse existing ACL entries and check if our entry already exists
        $existingEntries = @()
        $hasAccessEntry = $false
        $hasDefaultEntry = $false

        foreach ($entry in $currentAcl) {
            $entryString = $entry.ToString()
            if ($entryString -match "^$aclAccessorType`:$PrincipalId`:") {
                $hasAccessEntry = $true
            }
            if ($entryString -match "^default:$aclAccessorType`:$PrincipalId`:") {
                $hasDefaultEntry = $true
            }
            $existingEntries += $entryString
        }

        # Build new ACL entries to add
        $newAclEntries = @()
        if (-not $hasAccessEntry) {
            $newAclEntries += "$aclAccessorType`:$PrincipalId`:$Permissions"
        }
        if (-not $hasDefaultEntry) {
            $newAclEntries += "default:$aclAccessorType`:$PrincipalId`:$Permissions"
        }

        if ($newAclEntries.Count -eq 0) {
            Write-Log "ACL entries for principal '$PrincipalId' already exist on container '$ContainerName'." 'DEBUG'
        } else {
            # Create the ACL object with new entries
            $acl = Set-AzDataLakeGen2ItemAclObject -AccessControlType $aclAccessorType -EntityId $PrincipalId -Permission $Permissions
            $acl = Set-AzDataLakeGen2ItemAclObject -AccessControlType $aclAccessorType -EntityId $PrincipalId -Permission $Permissions -DefaultScope -InputObject $acl

            # Update ACL on root with recursive cascade
            Write-Log "Applying ACL recursively on container '$ContainerName'..." 'INFO'
            Update-AzDataLakeGen2AclRecursive -Context $context -FileSystem $ContainerName -Acl $acl -ErrorAction Stop | Out-Null
            Write-Log "ACL applied recursively on container '$ContainerName' for principal '$PrincipalId'." 'INFO'
        }
    } catch {
        Write-Log "Failed to set ACL on container '$ContainerName': $($_.Exception.Message)" 'ERROR'
        throw
    }
}

function Confirm-ExistingStorageAccounts {
    param(
        [Parameter(Mandatory = $true)][string]$BlobStorageAccountName,
        [Parameter(Mandatory = $true)][string]$OperationsStorageAccountName,
        [Parameter(Mandatory = $true)][string]$ResourceGroupName,
        [Parameter(Mandatory = $true)][array]$StmoDefinitions,
        [Parameter(Mandatory = $true)][string]$TrustedWorkspacePrincipalId,
        [Parameter(Mandatory = $true)][string]$TrustedWorkspacePrincipalType,
        [Parameter(Mandatory = $true)][string]$DicomAdminSecurityGroupId
    )

    Write-Log "Validating existing blob storage account '$BlobStorageAccountName'..." 'INFO'
    $blobAccount = Test-StorageAccountExists -StorageAccountName $BlobStorageAccountName -ResourceGroupName $ResourceGroupName
    if (-not $blobAccount) {
        throw "Blob storage account '$BlobStorageAccountName' does not exist in resource group '$ResourceGroupName'."
    }
    Write-Log "Blob storage account '$BlobStorageAccountName' found." 'INFO'

    Write-Log "Validating existing operations storage account '$OperationsStorageAccountName'..." 'INFO'
    $operationsAccount = Test-StorageAccountExists -StorageAccountName $OperationsStorageAccountName -ResourceGroupName $ResourceGroupName
    if (-not $operationsAccount) {
        throw "Operations storage account '$OperationsStorageAccountName' does not exist in resource group '$ResourceGroupName'."
    }
    
    # Verify operations account has HNS enabled (ADLS Gen2) - this is required for Fabric integration
    if (-not $operationsAccount.EnableHierarchicalNamespace) {
        throw "Operations storage account '$OperationsStorageAccountName' does not have hierarchical namespace (ADLS Gen2) enabled. This is required for Fabric integration. Please use an ADLS Gen2 storage account."
    }
    Write-Log "Operations storage account '$OperationsStorageAccountName' found with HNS enabled." 'INFO'

    # Determine required containers for blob account (primary + inventory)
    $blobContainers = @()
    foreach ($definition in $StmoDefinitions) {
        $blobContainers += $definition.ContainerName
        $blobContainers += $definition.InventoryContainerName
    }
    $blobContainers = $blobContainers | Select-Object -Unique

    # Determine required containers for operations account
    $operationsContainers = $StmoDefinitions | Select-Object -ExpandProperty ContainerName -Unique

    Write-Log "Ensuring required containers exist on blob storage account '$BlobStorageAccountName'..." 'INFO'
    New-MissingContainers -StorageAccountName $BlobStorageAccountName -ResourceGroupName $ResourceGroupName -RequiredContainers $blobContainers

    Write-Log "Ensuring required containers exist on operations storage account '$OperationsStorageAccountName'..." 'INFO'
    New-MissingContainers -StorageAccountName $OperationsStorageAccountName -ResourceGroupName $ResourceGroupName -RequiredContainers $operationsContainers

    # Ensure inventory policy rules exist on blob storage account
    Write-Log "Ensuring inventory policy rules exist on blob storage account '$BlobStorageAccountName'..." 'INFO'
    New-MissingInventoryPolicy -StorageAccountName $BlobStorageAccountName -ResourceGroupName $ResourceGroupName -StmoDefinitions $StmoDefinitions

    # Assign role assignments if not present
    $storageBlobDataContributorRole = 'Storage Blob Data Contributor'

    if (-not [string]::IsNullOrWhiteSpace($TrustedWorkspacePrincipalId)) {
        Write-Log "Ensuring workspace identity has '$storageBlobDataContributorRole' role on storage accounts..." 'INFO'
        
        New-MissingRoleAssignment -Scope $blobAccount.Id -PrincipalId $TrustedWorkspacePrincipalId `
            -RoleDefinitionName $storageBlobDataContributorRole -PrincipalType $TrustedWorkspacePrincipalType `
            -Description "workspace identity '$TrustedWorkspacePrincipalId'"

        New-MissingRoleAssignment -Scope $operationsAccount.Id -PrincipalId $TrustedWorkspacePrincipalId `
            -RoleDefinitionName $storageBlobDataContributorRole -PrincipalType $TrustedWorkspacePrincipalType `
            -Description "workspace identity '$TrustedWorkspacePrincipalId'"
    }

    if (-not [string]::IsNullOrWhiteSpace($DicomAdminSecurityGroupId)) {
        Write-Log "Ensuring DICOM admin security group has '$storageBlobDataContributorRole' role on storage accounts..." 'INFO'
        
        New-MissingRoleAssignment -Scope $blobAccount.Id -PrincipalId $DicomAdminSecurityGroupId `
            -RoleDefinitionName $storageBlobDataContributorRole -PrincipalType 'Group' `
            -Description "DICOM admin security group '$DicomAdminSecurityGroupId'"

        New-MissingRoleAssignment -Scope $operationsAccount.Id -PrincipalId $DicomAdminSecurityGroupId `
            -RoleDefinitionName $storageBlobDataContributorRole -PrincipalType 'Group' `
            -Description "DICOM admin security group '$DicomAdminSecurityGroupId'"
    }

    # Apply ACLs on ADLS Gen2 (operations) containers with cascading
    Write-Log "Applying ACLs on ADLS Gen2 operations containers with recursive cascade..." 'INFO'
    foreach ($containerName in $operationsContainers) {
        # Apply ACL for workspace identity (service principal)
        if (-not [string]::IsNullOrWhiteSpace($TrustedWorkspacePrincipalId)) {
            Set-AdlsContainerAcl -StorageAccountName $OperationsStorageAccountName -ResourceGroupName $ResourceGroupName `
                -ContainerName $containerName -PrincipalId $TrustedWorkspacePrincipalId -PrincipalType 'sp' -Permissions 'rwx'
        }

        # Apply ACL for DICOM admin security group
        if (-not [string]::IsNullOrWhiteSpace($DicomAdminSecurityGroupId)) {
            Set-AdlsContainerAcl -StorageAccountName $OperationsStorageAccountName -ResourceGroupName $ResourceGroupName `
                -ContainerName $containerName -PrincipalId $DicomAdminSecurityGroupId -PrincipalType 'group' -Permissions 'rwx'
        }
    }
    Write-Log "ACLs applied successfully on ADLS Gen2 operations containers." 'INFO'

    Write-Log "Existing storage accounts validated and configured successfully." 'INFO'
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
    $uri = "{0}/{1}/{2}/Files/{3}?resource=directory" -f $Endpoint.TrimEnd('/'), $WorkspaceSegment, $LakehouseSegment, $relativePath.TrimEnd('/')

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
    # HEAD requests don't use ?resource=directory - that's only for PUT (create)
    $uri = "{0}/{1}/{2}/Files/{3}" -f $Endpoint.TrimEnd('/'), $WorkspaceSegment, $LakehouseSegment, $relativePath.TrimEnd('/')

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

    # Base path for DICOM HDS shortcuts: /Files/Inventory/Imaging/DICOM/DICOM-HDS
    $dicomHdsPath = @('Inventory', 'Imaging', 'DICOM', 'DICOM-HDS')
    $dicomHdsRelative = ($dicomHdsPath | ForEach-Object { [Uri]::EscapeDataString($_) }) -join '/'
    $dicomHdsUri = "{0}/{1}/{2}/Files/{3}" -f $endpointRoot, $segments.Workspace, $segments.Lakehouse, $dicomHdsRelative

    # Create /Files/Inventory/Imaging/DICOM/DICOM-HDS if it doesn't exist
    if (Test-OneLakeDirectoryExists -Endpoint $Endpoint -WorkspaceSegment $segments.Workspace -LakehouseSegment $segments.Lakehouse -PathSegments $dicomHdsPath -AccessToken $AccessToken) {
        Write-Log "DICOM-HDS base folder already exists: $dicomHdsUri" 'INFO'
    } else {
        Write-Log "Creating DICOM-HDS base folder: $dicomHdsUri" 'INFO'
        New-LakehouseDirectoryPath -Endpoint $Endpoint -WorkspaceSegment $segments.Workspace -LakehouseSegment $segments.Lakehouse -PathSegments $dicomHdsPath -AccessToken $AccessToken
    }

    # Create InventoryFiles subfolder under DICOM-HDS (shared for all STMO inventory shortcuts)
    $inventoryFilesPath = $dicomHdsPath + @('InventoryFiles')
    $inventoryFilesRelative = ($inventoryFilesPath | ForEach-Object { [Uri]::EscapeDataString($_) }) -join '/'
    $inventoryFilesUri = "{0}/{1}/{2}/Files/{3}" -f $endpointRoot, $segments.Workspace, $segments.Lakehouse, $inventoryFilesRelative

    if (Test-OneLakeDirectoryExists -Endpoint $Endpoint -WorkspaceSegment $segments.Workspace -LakehouseSegment $segments.Lakehouse -PathSegments $inventoryFilesPath -AccessToken $AccessToken) {
        Write-Log "InventoryFiles folder already exists: $inventoryFilesUri" 'INFO'
    } else {
        Write-Log "Creating InventoryFiles folder: $inventoryFilesUri" 'INFO'
        New-OneLakeDirectory -Endpoint $Endpoint -WorkspaceSegment $segments.Workspace -LakehouseSegment $segments.Lakehouse -PathSegments $inventoryFilesPath -AccessToken $AccessToken
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
        [Parameter(Mandatory = $true)][string]$ContainerSubpath
    )

    $existing = Get-FabricConnectionByDisplayName -Endpoint $Endpoint -AccessToken $AccessToken -DisplayName $DisplayName -WorkspaceId $WorkspaceId
    if (-not $existing) {
        # Also check for tenant-scoped connections
        $existing = Get-FabricConnectionByDisplayName -Endpoint $Endpoint -AccessToken $AccessToken -DisplayName $DisplayName
        if ($existing) {
            Write-Log "Found tenant-scoped Fabric ADLS connection '$DisplayName'; reusing it." 'INFO'
        }
    }
    if ($existing -and $existing.PSObject.Properties['id']) {
        $existingId = [string]$existing.id
        Write-Log "Reusing Fabric ADLS connection '$DisplayName' (ID: $existingId)." 'INFO'
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

    $containerSubpathString = [string]$ContainerSubpath
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
    if (-not $fileSystemName) {
        throw "Container subpath '$ContainerSubpath' did not resolve to an ADLS Gen2 file system for connection creation."
    }

    $pathWithLeadingSlash = "/$fullPathRelative"
    $fullPathAbsolute = "$accountUrl/$fullPathRelative"

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
                        $value = if ($fullPathRelative) { $fullPathRelative } else { $pathWithLeadingSlash }
                    } elseif ($compactName -eq 'path') {
                        if (-not [string]::IsNullOrWhiteSpace($fullPathRelative)) {
                            $value = $fullPathRelative
                        } else {
                            $value = $pathWithLeadingSlash
                        }
                    } elseif ($compactName -match 'server|host') {
                        $value = $accountHost
                    } elseif ($compactName -match 'account|endpoint|url|location|dfs') {
                        $value = $accountUrl
                    } elseif ($compactName -match 'filesystem|container|root') {
                        $value = $fileSystemName
                    } elseif ($compactName -match 'subpath|relativepath|folder|directory') {
                        if (-not [string]::IsNullOrWhiteSpace($relativePath)) {
                            $value = $relativePath
                        } elseif (-not [string]::IsNullOrWhiteSpace($fileSystemName)) {
                            $value = ''
                        }
                    }

                    if ($parameter.required -and [string]::IsNullOrWhiteSpace($value)) {
                        Write-Log "Unable to auto-map required parameter '$paramName'. Metadata: $(($parameter | ConvertTo-Json -Compress -Depth 3))" 'WARN'
                        throw "Unable to map required parameter '$paramName' for ADLS Gen2 connection creation."
                    }

                    if (-not [string]::IsNullOrWhiteSpace($value)) {
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
                    $valueCandidate = if ($fullPathRelative) { $fullPathRelative } else { $pathWithLeadingSlash.TrimStart('/') }
                } elseif ($paramName.Equals('server', [System.StringComparison]::OrdinalIgnoreCase)) {
                    $valueCandidate = $accountHost
                } elseif ($paramName -match 'filesystem|container|root') {
                    $valueCandidate = $fileSystemName
                } elseif ($paramName -match 'subpath|relativepath|folder|directory') {
                    if (-not [string]::IsNullOrWhiteSpace($relativePath)) {
                        $valueCandidate = $relativePath
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
            @{ name = 'path';   dataType = 'Text'; value = if ($fullPathRelative) { $fullPathRelative } else { $pathWithLeadingSlash.TrimStart('/') } }
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
        # Handle 409 DuplicateConnectionName - the connection may have been created by another process
        if ($message -match '409|DuplicateConnectionName') {
            Write-Log "Connection '$DisplayName' already exists (409 conflict). Attempting to retrieve existing connection..." 'WARN'
            # Try to find the existing connection again
            $existingRetry = Get-FabricConnectionByDisplayName -Endpoint $Endpoint -AccessToken $AccessToken -DisplayName $DisplayName -WorkspaceId $WorkspaceId
            if (-not $existingRetry) {
                $existingRetry = Get-FabricConnectionByDisplayName -Endpoint $Endpoint -AccessToken $AccessToken -DisplayName $DisplayName
            }
            if ($existingRetry -and $existingRetry.PSObject.Properties['id']) {
                $existingId = [string]$existingRetry.id
                Write-Log "Found existing Fabric ADLS connection '$DisplayName' (ID: $existingId) after conflict." 'INFO'
                return $existingId
            }
        }
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

function Remove-FabricShortcut {
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
    $shortcutNameEncoded = [Uri]::EscapeDataString($ShortcutName)
    $shortcutPathEncoded = [Uri]::EscapeDataString($ShortcutPath)
    $uri = "$($Endpoint.TrimEnd('/'))/v1/workspaces/$workspaceIdEncoded/items/$lakehouseIdEncoded/shortcuts/$shortcutPathEncoded/$shortcutNameEncoded"

    try {
        Invoke-FabricApiRequest -Method 'Delete' -Uri $uri -Headers $headers -Description "Delete shortcut '$ShortcutName' at '$ShortcutPath'"
        Write-Log "Deleted Fabric shortcut '$ShortcutName' at '$ShortcutPath'." 'INFO'
        return $true
    } catch {
        $errorMessage = $_.Exception.Message
        # Treat 404 as success - shortcut is already gone
        if ($errorMessage -match '404|EntityNotFound|ShortcutNotFound') {
            Write-Log "Shortcut '$ShortcutName' at '$ShortcutPath' was already deleted or does not exist." 'INFO'
            return $true
        }
        Write-Log "Failed to delete Fabric shortcut '$ShortcutName' at '$ShortcutPath': $errorMessage" 'ERROR'
        return $false
    }
}

function Resolve-ShortcutConflict {
    param(
        [Parameter(Mandatory = $true)][string]$Endpoint,
        [Parameter(Mandatory = $true)][string]$AccessToken,
        [Parameter(Mandatory = $true)][string]$WorkspaceId,
        [Parameter(Mandatory = $true)][string]$LakehouseId,
        [Parameter(Mandatory = $true)][string]$ShortcutName,
        [Parameter(Mandatory = $true)][string]$ShortcutPath,
        [int]$TimeoutSeconds = 10
    )

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "SHORTCUT CONFLICT DETECTED" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "A shortcut with the name '$ShortcutName' already exists at path '$ShortcutPath'." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Options:" -ForegroundColor White
    Write-Host "  [K] Keep existing shortcut and continue (DEFAULT - auto-selected in $TimeoutSeconds seconds)" -ForegroundColor Green
    Write-Host "  [R] Replace - Delete existing shortcut and create new one" -ForegroundColor Yellow
    Write-Host "  [A] Abort - Stop the script execution" -ForegroundColor Red
    Write-Host ""

    # Timed input with default selection
    $choice = $null
    $lastDisplayedSeconds = -1
    $startTime = [DateTime]::Now
    $endTime = $startTime.AddSeconds($TimeoutSeconds)
    
    Write-Host "Enter your choice (K/R/A) [Default: K in $TimeoutSeconds seconds]: " -NoNewline
    
    while ([DateTime]::Now -lt $endTime) {
        if ([Console]::KeyAvailable) {
            $key = [Console]::ReadKey($true)
            $choice = $key.KeyChar.ToString().ToUpper().Trim()
            if ($choice -in @('K', 'R', 'A')) {
                Write-Host $choice
                break
            } elseif ($key.Key -eq 'Enter') {
                # User pressed Enter without a choice - use default
                $choice = 'R'
                Write-Host "R (default)"
                break
            }
        }
        
        $remainingSeconds = [Math]::Ceiling(($endTime - [DateTime]::Now).TotalSeconds)
        if ($remainingSeconds -ge 0 -and $remainingSeconds -ne $lastDisplayedSeconds) {
            $lastDisplayedSeconds = $remainingSeconds
            # Update countdown on same line
            Write-Host "`r" -NoNewline
            Write-Host "Enter your choice (K/R/A) [Default: K in $remainingSeconds seconds]: " -NoNewline
        }
        
        Start-Sleep -Milliseconds 100
    }
    
    if (-not $choice) {
        $choice = 'K'
        Write-Host ""
        Write-Log "No input received within $TimeoutSeconds seconds. Auto-selecting 'Keep' (K)." 'INFO'
    }

    switch ($choice) {
        'K' {
            Write-Log "User chose to keep existing shortcut '$ShortcutName' at '$ShortcutPath'." 'INFO'
            return 'Keep'
        }
        'R' {
            Write-Log "User chose to replace shortcut '$ShortcutName' at '$ShortcutPath'." 'INFO'
            $deleted = Remove-FabricShortcut -Endpoint $Endpoint -AccessToken $AccessToken -WorkspaceId $WorkspaceId -LakehouseId $LakehouseId -ShortcutName $ShortcutName -ShortcutPath $ShortcutPath
            if ($deleted) {
                # Wait for API propagation before retrying creation
                Write-Log "Waiting 10 seconds for Fabric API to propagate shortcut deletion..." 'INFO'
                Start-Sleep -Seconds 10
                return 'Replace'
            } else {
                Write-Log "Failed to delete existing shortcut. Cannot proceed with replacement." 'ERROR'
                throw "Unable to delete existing shortcut '$ShortcutName' at '$ShortcutPath'."
            }
        }
        'A' {
            Write-Log "User chose to abort due to shortcut conflict." 'WARN'
            throw "Script aborted by user due to shortcut conflict for '$ShortcutName' at '$ShortcutPath'."
        }
    }
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
        [Parameter(Mandatory = $true)][string]$BlobConnectionDisplayName,
        [Parameter(Mandatory = $true)][string]$InventoryStorageAccountName
    )

    if (-not $StmoDefinitions -or $StmoDefinitions.Count -eq 0) {
        Write-Log 'No STMO definitions provided for image shortcut creation.' 'WARN'
        return
    }

    $segments = Resolve-LakehouseSegments -WorkspaceId $WorkspaceId -LakehouseId $LakehouseId

    # New layout: /Files/Inventory/Imaging/DICOM/DICOM-HDS for STMO shortcuts
    $basePath = '/Files/Inventory/Imaging/DICOM/DICOM-HDS'
    $baseSegments = Get-LakehousePathSegments -FullPath $basePath

    # InventoryFiles subfolder for inventory shortcuts
    $inventoryFilesPath = '/Files/Inventory/Imaging/DICOM/DICOM-HDS/InventoryFiles'
    $inventoryFilesSegments = Get-LakehousePathSegments -FullPath $inventoryFilesPath

    $blobEndpoint = "https://$BlobStorageAccountName.blob.core.windows.net"
    $defaultContainer = $StmoDefinitions | Select-Object -First 1
    $defaultContainerName = if ($defaultContainer -and $defaultContainer.PSObject.Properties['ContainerName']) { [string]$defaultContainer.ContainerName } else { $null }

    # Blob connection for STMO image containers
    $existingBlobConnection = Get-FabricConnectionByDisplayName -Endpoint $FabricEndpoint -AccessToken $FabricAccessToken -DisplayName $BlobConnectionDisplayName -WorkspaceId $WorkspaceId
    if (-not $existingBlobConnection) {
        $existingBlobConnection = Get-FabricConnectionByDisplayName -Endpoint $FabricEndpoint -AccessToken $FabricAccessToken -DisplayName $BlobConnectionDisplayName
        if ($existingBlobConnection) {
            Write-Log "Found tenant-scoped Fabric blob connection '$BlobConnectionDisplayName'." 'INFO'
        }
    }
    if ($existingBlobConnection -and $existingBlobConnection.PSObject.Properties['id']) {
        $connectionId = [string]$existingBlobConnection.id
        Write-Log "Found existing Fabric blob connection '$BlobConnectionDisplayName' (ID: $connectionId)." 'INFO'

        try {
            if ($existingBlobConnection.PSObject.Properties['connectionDetails']) {
                $connectionDetailsJson = $existingBlobConnection.connectionDetails | ConvertTo-Json -Depth 5 -Compress
                Write-Log "Existing connection details: $connectionDetailsJson" 'DEBUG'
            }
        } catch {
            Write-Log "Unable to serialize existing connection details for '$BlobConnectionDisplayName': $($_.Exception.Message)" 'DEBUG'
        }
    } else {
        $connectionId = New-FabricBlobConnection -Endpoint $FabricEndpoint -WorkspaceId $WorkspaceId -AccessToken $FabricAccessToken -DisplayName $BlobConnectionDisplayName -StorageLocation $blobEndpoint -DefaultContainerName $defaultContainerName
    }

    if ([string]::IsNullOrWhiteSpace($connectionId)) {
        throw "Unable to resolve a Fabric connection ID for '$BlobConnectionDisplayName'."
    }

    foreach ($definition in $StmoDefinitions) {
        $containerName = [string]$definition.ContainerName
        if ([string]::IsNullOrWhiteSpace($containerName)) {
            Write-Log 'Encountered STMO definition without a container name; skipping.' 'WARN'
            continue
        }

        # Create STMO image shortcut directly at /Files/Inventory/Imaging/DICOM/DICOM-HDS/{containerName}
        $shortcutPath = "Files/Inventory/Imaging/DICOM/DICOM-HDS"
        $existingShortcut = Get-FabricShortcutByName -Endpoint $FabricEndpoint -AccessToken $FabricAccessToken -WorkspaceId $WorkspaceId -LakehouseId $LakehouseId -ShortcutName $containerName -ShortcutPath $shortcutPath

        if ($existingShortcut) {
            Write-Log "Image shortcut '$containerName' already exists at '$shortcutPath'." 'INFO'
        } else {
            $body = @{
                path = $shortcutPath
                name = $containerName
                target = @{
                    azureBlobStorage = @{
                        location = $blobEndpoint
                        subpath  = "/$containerName"
                        connectionId = $connectionId
                    }
                }
            }

            $headers = Get-FabricApiHeaders -AccessToken $FabricAccessToken
            $workspaceIdEncoded = [Uri]::EscapeDataString($WorkspaceId)
            $lakehouseIdEncoded = [Uri]::EscapeDataString($LakehouseId)
            $uri = "$($FabricEndpoint.TrimEnd('/'))/v1/workspaces/$workspaceIdEncoded/items/$lakehouseIdEncoded/shortcuts?shortcutConflictPolicy=Abort"

            $retryCreate = $true
            while ($retryCreate) {
                $retryCreate = $false
                try {
                    Invoke-FabricApiRequest -Method 'Post' -Uri $uri -Headers $headers -Body $body -Description "Create image shortcut '$containerName'"
                    Write-Log "Created Fabric image shortcut '$containerName' -> '$blobEndpoint/$containerName'." 'INFO'
                } catch {
                    $errorMessage = $_.Exception.Message
                    # Check for 409 conflict (shortcut already exists)
                    if ($errorMessage -match '409|EntityConflict|ShorcutsOperationNotAllowed|shortcut.*already exists') {
                        Write-Log "Shortcut conflict detected for '$containerName' at '$shortcutPath'." 'WARN'
                        $resolution = Resolve-ShortcutConflict -Endpoint $FabricEndpoint -AccessToken $FabricAccessToken -WorkspaceId $WorkspaceId -LakehouseId $LakehouseId -ShortcutName $containerName -ShortcutPath $shortcutPath
                        if ($resolution -eq 'Replace') {
                            $retryCreate = $true
                        }
                        # If 'Keep', we just continue without retrying
                    } else {
                        Write-Log "Failed to create image shortcut '$containerName': $errorMessage" 'ERROR'
                        throw
                    }
                }
            }
        }

        # Create inventory shortcut at /Files/Inventory/Imaging/DICOM/DICOM-HDS/InventoryFiles/{containerName}-inventory
        # Inventory containers (-inv) are on the same blob storage account as the STMO image containers
        $inventoryContainerName = "$containerName-inv"
        $inventoryShortcutName = "$containerName-inventory"
        $inventoryShortcutPath = "Files/Inventory/Imaging/DICOM/DICOM-HDS/InventoryFiles"

        $existingInventoryShortcut = Get-FabricShortcutByName -Endpoint $FabricEndpoint -AccessToken $FabricAccessToken -WorkspaceId $WorkspaceId -LakehouseId $LakehouseId -ShortcutName $inventoryShortcutName -ShortcutPath $inventoryShortcutPath

        if ($existingInventoryShortcut) {
            Write-Log "Inventory shortcut '$inventoryShortcutName' already exists at '$inventoryShortcutPath'." 'INFO'
        } else {
            # Use the same blob connection as the image shortcuts (inventory is on the same blob storage account)
            $inventoryBody = @{
                path = $inventoryShortcutPath
                name = $inventoryShortcutName
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

            $retryCreate = $true
            while ($retryCreate) {
                $retryCreate = $false
                try {
                    Invoke-FabricApiRequest -Method 'Post' -Uri $uri -Headers $headers -Body $inventoryBody -Description "Create inventory shortcut '$inventoryShortcutName'"
                    Write-Log "Created Fabric inventory shortcut '$inventoryShortcutName' -> '$blobEndpoint/$inventoryContainerName'." 'INFO'
                } catch {
                    $errorMessage = $_.Exception.Message
                    # Check for 409 conflict (shortcut already exists)
                    if ($errorMessage -match '409|EntityConflict|ShorcutsOperationNotAllowed|shortcut.*already exists') {
                        Write-Log "Shortcut conflict detected for '$inventoryShortcutName' at '$inventoryShortcutPath'." 'WARN'
                        $resolution = Resolve-ShortcutConflict -Endpoint $FabricEndpoint -AccessToken $FabricAccessToken -WorkspaceId $WorkspaceId -LakehouseId $LakehouseId -ShortcutName $inventoryShortcutName -ShortcutPath $inventoryShortcutPath
                        if ($resolution -eq 'Replace') {
                            $retryCreate = $true
                        }
                        # If 'Keep', we just continue without retrying
                    } else {
                        Write-Log "Failed to create inventory shortcut '$inventoryShortcutName': $errorMessage" 'ERROR'
                        throw
                    }
                }
            }
        }
    }
}

function New-FabricInventoryShortcuts {
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

    $segments = Resolve-LakehouseSegments -WorkspaceId $WorkspaceId -LakehouseId $LakehouseId
    $operationsSegments = Get-LakehousePathSegments -FullPath $OperationsPath
    New-LakehouseDirectoryPath -Endpoint $OneLakeEndpoint -WorkspaceSegment $segments.Workspace -LakehouseSegment $segments.Lakehouse -PathSegments $operationsSegments -AccessToken $OneLakeAccessToken

    $shortcutPath = $OperationsPath.TrimStart('/')
    if ([string]::IsNullOrWhiteSpace($shortcutPath)) {
        Write-Log 'Lakehouse shortcut path resolved to an empty string; skipping shortcut creation.' 'WARN'
        return
    }

    foreach ($definition in $StmoDefinitions) {
        $operationsContainer = $definition.ContainerName
        $displayName = "$InventoryStorageAccountName-$operationsContainer-workspace-mi"
        $storageLocation = "https://$InventoryStorageAccountName.dfs.core.windows.net"
        $containerSubpath = "/$operationsContainer"

        $connectionId = New-FabricAdlsConnection -Endpoint $FabricEndpoint -WorkspaceId $WorkspaceId -AccessToken $FabricAccessToken -DisplayName $displayName -StorageLocation $storageLocation -ContainerSubpath $containerSubpath

        $shortcutName = $operationsContainer
        $existingShortcut = Get-FabricShortcutByName -Endpoint $FabricEndpoint -AccessToken $FabricAccessToken -WorkspaceId $WorkspaceId -LakehouseId $LakehouseId -ShortcutName $shortcutName -ShortcutPath $shortcutPath

        if ($existingShortcut) {
            $message = "Shortcut '$shortcutName' already exists at '$shortcutPath'."
            Write-Log $message 'INFO'
            continue
        }

        $body = @{
            path = $shortcutPath
            name = $shortcutName
            target = @{
                adlsGen2 = @{
                    location = $storageLocation
                    subpath  = $containerSubpath
                    connectionId = $connectionId
                }
            }
        }

        $headers = Get-FabricApiHeaders -AccessToken $FabricAccessToken
        $workspaceIdEncoded = [Uri]::EscapeDataString($WorkspaceId)
        $lakehouseIdEncoded = [Uri]::EscapeDataString($LakehouseId)
        $uri = "$($FabricEndpoint.TrimEnd('/'))/v1/workspaces/$workspaceIdEncoded/items/$lakehouseIdEncoded/shortcuts?shortcutConflictPolicy=Abort"

        $retryCreate = $true
        while ($retryCreate) {
            $retryCreate = $false
            try {
                Invoke-FabricApiRequest -Method 'Post' -Uri $uri -Headers $headers -Body $body -Description "Create shortcut '$shortcutName'"
                $successMessage = "Created Fabric shortcut '$shortcutName' -> '$storageLocation$containerSubpath'."
                Write-Log $successMessage 'INFO'
            } catch {
                $errorMessage = $_.Exception.Message
                # Check for 409 conflict (shortcut already exists)
                if ($errorMessage -match '409|EntityConflict|ShorcutsOperationNotAllowed|shortcut.*already exists') {
                    Write-Log "Shortcut conflict detected for '$shortcutName' at '$shortcutPath'." 'WARN'
                    $resolution = Resolve-ShortcutConflict -Endpoint $FabricEndpoint -AccessToken $FabricAccessToken -WorkspaceId $WorkspaceId -LakehouseId $LakehouseId -ShortcutName $shortcutName -ShortcutPath $shortcutPath
                    if ($resolution -eq 'Replace') {
                        $retryCreate = $true
                    }
                    # If 'Keep', we just continue without retrying
                } else {
                    Write-Log "Failed to create shortcut '$shortcutName': $errorMessage" 'ERROR'
                    throw
                }
            }
        }
    }
}

Write-Log 'Starting HDS DICOM infrastructure orchestration.' 'INFO'

$moduleNames = @('Az.Accounts', 'Az.Resources', 'Az.Storage')
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

# Validate and normalize storage account names from parameters
$imageBlobAccountName = $ImagesStorageAccountName.ToLowerInvariant().Trim()
$imageOperationsAccountName = $FHIROpsStorageAccountName.ToLowerInvariant().Trim()

# Validate storage account names meet Azure requirements
if ($imageBlobAccountName.Length -lt 3 -or $imageBlobAccountName.Length -gt 24) {
    throw "Images storage account name '$imageBlobAccountName' must be between 3 and 24 characters."
}
if ($imageOperationsAccountName.Length -lt 3 -or $imageOperationsAccountName.Length -gt 24) {
    throw "FHIR Ops storage account name '$imageOperationsAccountName' must be between 3 and 24 characters."
}
if ($imageBlobAccountName -notmatch '^[a-z0-9]+$') {
    throw "Images storage account name '$imageBlobAccountName' must contain only lowercase letters and numbers."
}
if ($imageOperationsAccountName -notmatch '^[a-z0-9]+$') {
    throw "FHIR Ops storage account name '$imageOperationsAccountName' must contain only lowercase letters and numbers."
}

if ($imageBlobAccountName -eq $imageOperationsAccountName) {
    throw "Blob and operations storage account names are identical ('$imageBlobAccountName'). These must be different storage accounts."
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

# Handle storage account provisioning and configuration
# Check if storage accounts already exist
$blobAccountExists = $null -ne (Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $imageBlobAccountName -ErrorAction SilentlyContinue)
$opsAccountExists = $null -ne (Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $imageOperationsAccountName -ErrorAction SilentlyContinue)

if (-not $SkipStorageDeployment) {
    # Run Bicep deployment to create or ensure consistency of storage accounts, containers, and policies
    # Bicep is idempotent - it will create missing resources or update existing ones to match desired state
    if ($blobAccountExists -and $opsAccountExists) {
        Write-Log "Both storage accounts already exist. Running Bicep deployment to ensure container and inventory policy consistency..." 'INFO'
    } elseif ($blobAccountExists -or $opsAccountExists) {
        Write-Log "One storage account exists but not the other. Running Bicep deployment to create/update both." 'INFO'
    } else {
        Write-Log "Storage accounts do not exist. Running Bicep deployment to create them." 'INFO'
    }
    
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
        allowSharedKeyAccess            = $true
        globalTags                      = $GlobalTags
        # Role assignments are handled separately by PowerShell with idempotent logic
        # Setting these to false/empty to avoid Bicep "RoleAssignmentExists" errors on re-runs
        assignTrustedWorkspaceIdentity  = $true
        trustedWorkspacePrincipalId     = ''
        trustedWorkspacePrincipalType   = $TrustedWorkspacePrincipalType
        dicomAdminSecurityGroupId       = ''
    }

    Invoke-StorageDeployment -DeploymentName $DeploymentName -ResourceGroup $ResourceGroupName -TemplatePath $stoBicepTemplatePath -TemplateParameters $templateParameters
    
    Write-Log 'Storage accounts and configurations deployed/validated successfully via Bicep.' 'INFO'
} else {
    # -SkipStorageDeployment was specified - verify storage accounts exist
    if (-not $blobAccountExists -and -not $opsAccountExists) {
        throw "Both storage accounts ('$imageBlobAccountName' and '$imageOperationsAccountName') do not exist and -SkipStorageDeployment was specified. Cannot proceed."
    } elseif (-not $blobAccountExists) {
        throw "Blob storage account '$imageBlobAccountName' does not exist and -SkipStorageDeployment was specified. Cannot proceed."
    } elseif (-not $opsAccountExists) {
        throw "Operations storage account '$imageOperationsAccountName' does not exist and -SkipStorageDeployment was specified. Cannot proceed."
    } else {
        Write-Log "Storage deployment skipped by user request. Both storage accounts exist but container/policy consistency is NOT guaranteed." 'WARN'
    }
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

    New-FabricImageShortcuts -OneLakeEndpoint $FabricApiEndpoint -FabricEndpoint $FabricManagementEndpoint -WorkspaceId $FabricWorkspaceId -LakehouseId $HdsBronzeLakehouse -OneLakeAccessToken $oneLakeAccessToken -FabricAccessToken $fabricApiAccessToken -StmoDefinitions $stmoDefinitions -BlobStorageAccountName $imageBlobAccountName -BlobConnectionDisplayName $blobConnectionDisplayName -InventoryStorageAccountName $imageOperationsAccountName

    New-FabricInventoryShortcuts -OneLakeEndpoint $FabricApiEndpoint -FabricEndpoint $FabricManagementEndpoint -WorkspaceId $FabricWorkspaceId -LakehouseId $HdsBronzeLakehouse -OneLakeAccessToken $oneLakeAccessToken -FabricAccessToken $fabricApiAccessToken -StmoDefinitions $stmoDefinitions -OperationsPath $LakehouseOperationsPath -InventoryStorageAccountName $imageOperationsAccountName
    Write-Log 'Fabric image and operations shortcuts created or verified successfully.' 'INFO'
} else {
    Write-Log 'Fabric shortcut creation skipped by user request.' 'WARN'
}

Write-Log 'HDS DICOM infrastructure orchestration completed.' 'INFO'
