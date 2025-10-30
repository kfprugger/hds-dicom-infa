# HDS DICOM Infrastructure Automation

This repository contains automation for provisioning Azure storage resources and configuring Microsoft Fabric OneLake shortcuts that support the HDS DICOM imaging ingestion pipeline. The primary entry point is the PowerShell script `hds-dicom-infra.ps1`, which orchestrates resource deployment, folder setup, and shortcut wiring from a single run.

## Repository Layout

| Path | Purpose |
| --- | --- |
| `hds-dicom-infra.ps1` | Main orchestration script for storage deployment, Fabric folder creation, and shortcut management. |
| `infra/storageAccounts.bicep` | Bicep template invoked by the script to provision blob and ADLS Gen2 accounts, containers, and RBAC assignments. |
| `infra/modules/containers.bicep` | Helper module that creates the ingest blob containers defined in the CSV input. |
| `infra/modules/keyVault.bicep` | Reserved module for future secrets integration (not currently referenced by the script). |
| `example-fmos-stmos.csv` | Sample study definition CSV consumed by the script to derive container names. |
| `create-fabric-lh-folders.ps1` | Placeholder for earlier manual operations (the orchestration logic supersedes it). |

## How the Pieces Fit Together

1. **CSV-driven definitions** – The script reads the facility CSV, sanitizes study names, and derives both ingest and inventory container identifiers used across storage and Fabric.
2. **Infrastructure as code** – Sanitized definitions are passed into `infra/storageAccounts.bicep`, which provisions the two storage accounts, creates the ingest and operations containers, and applies RBAC to the Fabric workspace identity and DICOM admin group.
3. **Fabric API orchestration** – Using OneLake and Fabric REST APIs, the script ensures the lakehouse directory structure exists, reuses or creates Fabric connections, and builds shortcuts into the storage accounts created earlier.
4. **Idempotent reruns** – Shortcut indexing, connection lookups, and conflict handling mean the script can be rerun safely to reconcile state without creating duplicates.

## Script Workflow

1. **Parameter validation and logging setup**
   - Binds required identifiers such as tenant, subscription, Fabric workspace, and lakehouse IDs.
   - Establishes logging helpers and strict error handling.
2. **Study metadata ingestion**
   - `Import-StmoDefinitions` parses the CSV, sanitizes container names, generates inventory suffixes, and produces ordered study objects.
3. **Storage account name generation**
   - `Get-SharedStorageAccountName` creates unique blob and operations account names using the provided prefix and location suffix, flagging any trims.
4. **Azure authentication check**
   - `Confirm-AzLogin` verifies an existing Az session before continuing; the script then selects the target subscription.
5. **Resource deployment (optional)**
   - Unless `-SkipStorageDeployment` is set, `Invoke-StorageDeployment` runs the Bicep template with the study definitions, provisioning:
     - `imageBlobAccount` (ingest blob storage) plus per-study containers via `modules/containers.bicep`.
     - `imageOperationsAccount` (ADLS Gen2) with matching containers.
     - Role assignments for the Fabric workspace managed identity and DICOM admin group.
6. **OneLake folder preparation (optional)**
   - If not skipped, `New-FabricInventoryFolders` ensures each study has `/Files/Ingest/Imaging/DICOM/<stmo>/InventoryFiles` directories in the target lakehouse.
7. **Token acquisition**
   - `Get-OneLakeAccessToken` retrieves a Storage audience token; `Get-FabricApiAccessToken` retrieves the Fabric management token when shortcuts are managed.
8. **Inventory shortcuts (blob storage)**
   - `New-FabricImageShortcuts` reuses or creates a Fabric blob connection to the ingest storage account and generates shortcuts named `<stmo>-inv` pointing to each inventory container under `/Files/Ingest/Imaging/DICOM/<stmo>/InventoryFiles`.
9. **Operations shortcuts (ADLS Gen2)**
   - `New-FabricOperationsShortcuts` validates or creates an ADLS Gen2 connection and guarantees a shortcut per container within `/Files/External/Imaging/DICOM/Operations`, verifying the target points to the operations storage account.
10. **Completion and logging**
    - The script surfaces detailed INFO/WARN/ERROR entries throughout and ends with a summary notice when orchestration finishes.

## Running the Script

```pwsh
pwsh ./hds-dicom-infra.ps1 \
  -TenantId <tenant-guid> \
  -SubscriptionId <subscription-guid> \
  -ResourceGroupName <resource-group> \
  -FacilityCsvPath .\example-fmos-stmos.csv \
  -hdsWorkspaceName <fabric-workspace-name> \
  -DicomAdmSecGrpId <aad-group-object-id> \
  -FabricWorkspaceId <fabric-workspace-guid> \
  -HdsBronzeLakehouse <lakehouse-item-guid>
```

### Prerequisites
- `Az.Accounts` and `Az.Resources` modules installed and authenticated (`Connect-AzAccount`).
- Fabric workspace managed identity already provisioned.
- CSV providing study identifiers aligned with the expected format.

### Optional Switches
- `-SkipStorageDeployment` – Skip the Bicep deployment and reuse existing storage accounts.
- `-SkipFabricFolders` – Skip creation of OneLake directory structure.
- `-SkipFabricShortcuts` – Skip shortcut creation; useful for infrastructure-only runs.

## Extending the Automation

- **Additional infrastructure**: Expand `infra/storageAccounts.bicep` or its modules with new resources (Key Vault, diagnostic settings) and pass the parameters through `Invoke-StorageDeployment`.
- **New shortcut targets**: Follow the pattern in `New-FabricImageShortcuts` when adding more data sources; ensure connection reuse logic mirrors the existing helpers (`Get-FabricBlobConnectionId`, `Get-FabricAdlsConnectionId`).
- **Observability**: Logging is centralized through `Write-Log`; extend it to integrate with external telemetry if desired.

Use this README as the single reference for understanding how the PowerShell automation, Bicep templates, and Fabric API interactions come together to provision and wire the DICOM ingestion environment.
