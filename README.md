# HDS DICOM Infrastructure Automation

This repository contains a PowerShell automation script and supporting Bicep templates that provision Azure storage resources per facility and prepare Microsoft Fabric lakehouse folders for imaging workloads.

## Overview

The solution orchestrates four responsibilities:

1. **Azure authentication** – Verifies an interactive Azure session is already established and halts with guidance if not.
2. **Facility storage provisioning** – Reads facility and study locations from a CSV file, then deploys storage accounts and blob containers using the `infra/storageAccounts.bicep` template. For every study (STMO) entry, two containers are created: the primary data container and a twin container with an `-inv` suffix that stores that study's blob inventory output.
3. **Blob inventory governance** – Each study receives a dedicated blob inventory policy that scans block blobs daily, captures all available metadata fields in Apache Parquet format, and writes the results into its associated `-inv` container using a `<primary-container>/` prefix filter.
4. **Trusted workspace identity** – Automatically assigns the Fabric workspace's managed identity the Storage Blob Data Contributor role on each provisioned storage account.
4. **Fabric OneLake folder scaffolding** – Creates standardized folder structures in the target Fabric lakehouse via the OneLake REST interface so that each study location has an `InventoryFiles` drop location.

## Prerequisites

- PowerShell 7.2 or later.
- Azure PowerShell modules `Az.Accounts` and `Az.Resources` (the script imports them automatically when available).
- Run `Connect-AzAccount` (or equivalent interactive login) before executing the script. The current Azure context must target the tenant and subscription specified by the parameters.
- The signed-in identity must have Contributor (or higher) permissions on the target subscription/resource group for deploying storage resources and on the Fabric workspace for folder creation.
- CSV file with at least the following headers: `facilityLocation`, `studyLocation`.
- Bicep CLI/runtime available on the executing machine (installed with the latest Az PowerShell module or separately).

## Usage

Run the script from the repository root. The example below shows the minimum parameter set; adjust to your environment.

```powershell
Connect-AzAccount
pwsh ./hds-dicom-infra.ps1 `
    -TenantId "<tenant-guid>" `
    -SubscriptionId "<subscription-guid>" `
    -ResourceGroupName "rg-hds-prod" `
    -FacilityCsvPath ".\data\facilityLocations.csv" `
    -FabricWorkspaceId "<fabric-workspace-guid>" `
    -HdsBronzeLakehouse "<lakehouse-guid>" `
    -DicomAdmSecGrpId "<security-group-object-id>"
```

### Full example with all parameters

```powershell
Connect-AzAccount

.\hds-dicom-infra.ps1 `
    -FacilityCsvPath .\example-stmos.csv `
    -TenantId 8d038e6a-9b7d-4cb8-bbcf-e84dff156478 `
    -location westus3 `
    -SubscriptionId 9bbee190-dc61-4c58-ab47-1275cb04018f `
    -ResourceGroupName rg-DICOM `
    -hdsWorkspaceName DICOM-Integration `
    -PrefixName sa `
    -LocationSuffix wu3 `
    -stoBicepTemplatePath '.\infra\storageAccounts.bicep' `
    -DeploymentName hds-storage-provisioning `
    -StorageAccountSkuName Standard_LRS `
    -StorageAccountKind StorageV2 `
    -FabricWorkspaceId 93acd72f-a23e-4b93-968d-c139600891e7 `
    -HdsBronzeLakehouse 74f52728-9f52-456f-aeb0-a9e250371087 `
    -DicomAdmSecGrpId 425d706b-afd7-4044-8110-f5fc4663f5bc `
    -Debug
```

### Partial execution examples

Skip storage deployment (Fabric operations only):

```powershell
.\hds-dicom-infra.ps1 `
    -FacilityCsvPath .\example-stmos.csv `
    -TenantId "<tenant-guid>" `
    -SubscriptionId "<subscription-guid>" `
    -ResourceGroupName rg-DICOM `
    -hdsWorkspaceName DICOM-Integration `
    -FabricWorkspaceId "<fabric-workspace-guid>" `
    -HdsBronzeLakehouse "<lakehouse-guid>" `
    -DicomAdmSecGrpId "<security-group-object-id>" `
    -SkipStorageDeployment
```

Skip Fabric folder and shortcut creation (Azure storage only):

```powershell
.\hds-dicom-infra.ps1 `
    -FacilityCsvPath .\example-stmos.csv `
    -TenantId "<tenant-guid>" `
    -SubscriptionId "<subscription-guid>" `
    -ResourceGroupName rg-DICOM `
    -hdsWorkspaceName DICOM-Integration `
    -FabricWorkspaceId "<fabric-workspace-guid>" `
    -HdsBronzeLakehouse "<lakehouse-guid>" `
    -DicomAdmSecGrpId "<security-group-object-id>" `
    -SkipFabricFolders `
    -SkipFabricShortcuts
```

Key optional switches:

- `-PrefixName` / `-LocationSuffix`: override the storage account naming convention (default `sa` and `wu3`).
- `-GlobalTags @{ Environment = 'prod'; Workstream = 'dicom' }` : merge custom tags into every storage account.
- `-TrustedWorkspacePrincipalType`: change the principal type used when assigning the Fabric workspace's managed identity (defaults to `ServicePrincipal`).
- `-SkipStorageDeployment` or `-SkipFabricFolders`: execute only parts of the workflow.
- `-WhatIf`: preview the Bicep deployment without applying changes.

## CSV expectations

Each row must map a facility to one study location. Duplicate rows per facility are allowed and deduplicated per study. Study locations are sanitized to meet Azure Storage naming requirements (lowercase, no spaces). Facilities are truncated as needed to honor the 24-character storage account limit with the configured prefix/suffix.

## File structure

- `hds-dicom-infra.ps1` – Main PowerShell orchestration script.
- `infra/storageAccounts.bicep` – Resource group–scoped Bicep template that provisions storage accounts and blob containers.
- `infra/modules/containers.bicep` – Child module invoked by the main template to create blob containers per facility.

## Required Permissions

The executing identity must hold the following roles and permissions to run the complete script.

### Azure RBAC

| Role | Scope | Purpose |
|------|-------|---------|
| **Contributor** | Resource Group | Deploy storage accounts, containers, and blob services via Bicep |
| **User Access Administrator** | Resource Group | Create role assignments for the Fabric workspace identity and DICOM admin security group |

> **Tip:** The **Owner** role at the Resource Group level includes both Contributor and User Access Administrator.

### Microsoft Entra ID

| Permission | Purpose |
|------------|---------|
| `Directory.Read.All` or **Directory Readers** role | Required for `Get-AzADServicePrincipal` to resolve the Fabric workspace managed identity by display name |

### Microsoft Fabric

| Role / Permission | Scope | Purpose |
|-------------------|-------|---------|
| **Workspace Admin** or **Member** | Target Fabric Workspace | Create connections, shortcuts, and directories in the Lakehouse |
| `Connection.ReadWrite.All` | Tenant (delegated) | Create new Fabric connections for Azure Blob Storage and ADLS Gen2 |
| `Connection.Read.All` | Tenant (delegated) | Query existing connections to avoid duplicates |

### API Token Scopes

The script acquires delegated access tokens for the following resources:

| Resource | Purpose |
|----------|---------|
| `https://api.fabric.microsoft.com/.default` | Fabric management API calls (connections, shortcuts, metadata) |
| `https://storage.azure.com/.default` | OneLake directory operations via the DFS endpoint |

### Roles Assigned by the Script

These roles are created during deployment and do **not** need to be held by the executing user:

| Role | Assigned To | Scope |
|------|-------------|-------|
| **Storage Blob Data Contributor** | Fabric Workspace Managed Identity | Both storage accounts |
| **Storage Blob Data Contributor** | DICOM Admin Security Group | Both storage accounts |

### Summary

| Category | Required Role / Permission | Scope |
|----------|----------------------------|-------|
| Azure RBAC | Owner **or** (Contributor + User Access Administrator) | Resource Group |
| Entra ID | Directory Readers **or** `Directory.Read.All` | Tenant |
| Fabric | Workspace Admin or Member | Target Workspace |
| Fabric API | `Connection.ReadWrite.All`, `Connection.Read.All` | Tenant (delegated auth) |

## References

- Azure Storage account naming rules: <https://learn.microsoft.com/azure/storage/common/storage-account-overview#storage-account-names>
- OneLake REST directory creation (API parity with ADLS): <https://learn.microsoft.com/fabric/onelake/onelake-api-parity>
- Fabric folder REST API (preview): <https://learn.microsoft.com/rest/api/fabric/core/folders/create-folder>

These references guided the authentication, storage, and OneLake integration strategies used in the solution.
