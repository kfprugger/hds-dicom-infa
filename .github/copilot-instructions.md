# HDS DICOM Infrastructure — Agent Instructions

This repo provisions Azure storage + Microsoft Fabric lakehouse integration for DICOM imaging workloads via PowerShell and Bicep.

## Repository layout

- `hds-dicom-infra.ps1` — Main orchestration script. Single-file, large (~2800 lines). All Fabric API / OneLake / storage logic lives here.
- `infra/storageAccounts.bicep` — Bicep template for the two storage accounts (image blob + operations ADLS Gen2), containers, and blob inventory policies.
- `infra/modules/` — `containers.bicep`, `keyVault.bicep` supporting modules.
- `example-stmos.csv` — Sample STMO (study location) input. One container per row is created per storage account.
- `storage-access-trusted-workspace.ps1` — Standalone helper for trusted-workspace access grants.
- `README.md` — Architecture, usage, parameters.

## Core domain concepts

- **STMO** = study location identifier. Each STMO gets a primary container and a `-inv` inventory container on the blob account, plus a container on the ADLS Gen2 ops account.
- **Two storage accounts**: `Images` (blob, for DICOM + inventory output) and `FHIROps` (ADLS Gen2, HNS-enabled, required for Fabric ops shortcuts).
- **Fabric workspace managed identity** is resolved by display name (`-hdsWorkspaceName`) via `Get-AzADServicePrincipal` and granted `Storage Blob Data Contributor` on both accounts.
- **Lakehouse layout** (bronze lakehouse):
  - `/Files/Inventory/Imaging/DICOM/{stmo}` — image shortcut to blob container
  - `/Files/Inventory/Imaging/DICOM/{stmo}/InventoryFiles/{stmo}-inventory` — shortcut to `{stmo}-inv` blob container
  - `/Files/Ingest/Imaging/OPERATIONS/` — ADLS Gen2 ops shortcuts
- **Fabric connections** are created per STMO container using `WorkspaceIdentity` credentials, `ShareableCloud` connectivity, `Organizational` privacy.

## Conventions when editing `hds-dicom-infra.ps1`

- **PowerShell style**: `Set-StrictMode -Version Latest`, `$ErrorActionPreference = 'Stop'`. Use approved verbs. Use `[CmdletBinding(SupportsShouldProcess)]` patterns already in place.
- **Logging**: Always use the `Write-Log` helper with levels `INFO`/`WARN`/`ERROR`/`DEBUG`. Do not use raw `Write-Host` for diagnostic output (only used for the final deployment banner and interactive prompts).
- **Idempotency is required**. Every resource operation (containers, ACLs, inventory rules, role assignments, Fabric folders, connections, shortcuts) must check for existence before creating, and re-running the script must be safe. Fabric drift is handled by `Get-FabricConnectionDriftReasons` → delete + recreate.
- **Fabric REST pagination**: `GET /v1/connections` (and other list endpoints) return `continuationUri` / `continuationToken`. Always use `Get-AllFabricConnections` (or an equivalent paginated helper) — do not assume a single page. A prior bug caused 409 `DuplicateConnectionName` errors because a single-page lookup missed existing connections.
- **Fabric API calls** go through `Invoke-FabricApiRequest` for consistent logging, status handling, and 4xx/5xx parsing. Don't call `Invoke-WebRequest`/`Invoke-RestMethod` against `api.fabric.microsoft.com` directly.
- **OneLake directory creation**: Use `New-LakehouseDirectoryPath` (which walks segments and calls `Test-OneLakeDirectoryExists` + `New-OneLakeDirectory`). HEAD requests must NOT include `?resource=directory`; only PUT (create) does.
- **Access tokens**: OneLake uses `Get-AzAccessToken -ResourceTypeName Storage`; Fabric control plane uses `Get-AzAccessToken -ResourceUrl https://api.fabric.microsoft.com`. Both are wrapped by `Get-OneLakeAccessToken` / `Get-FabricApiAccessToken` — reuse those.
- **Container name sanitization**: Always go through `Get-SanitizedContainerName` / `Get-InventoryContainerName` / `Get-InventoryRuleName` for the 3–63 char lowercase rules.
- **ADLS Gen2 ACLs**: Applied via `Set-AdlsContainerAcl` with both access and default ACL entries; service principals use `user` accessor type in ACL entries.
- **Skip switches**: `-SkipStorageDeployment`, `-SkipFabricFolders`, `-SkipFabricShortcuts` must remain independently usable. RBAC/ACL/inventory enforcement (`Confirm-ExistingStorageAccounts`) always runs — it closes gaps the Bicep template cannot (ACLs) and is safe to re-run.

## Conventions when editing Bicep

- Keep the template idempotent — it is invoked on every run unless `-SkipStorageDeployment` is set. Do not introduce parameters that force re-creation of existing resources.
- Accept empty principal IDs gracefully (the PS script intentionally passes empty strings for RBAC to avoid `RoleAssignmentExists` errors; the script then does RBAC itself).

## Things to avoid

- Do not add new top-level script files for logic that belongs in `hds-dicom-infra.ps1` — keep the orchestration in one place.
- Do not introduce new authentication flows (device code, SP secrets, etc.) — the script requires a pre-existing `Connect-AzAccount` session and uses the context's token for both Azure Resource Manager and Fabric.
- Do not bypass `Ensure-FabricConnection` by POSTing connections directly — the drift-detection + delete-recreate flow is required to keep connections consistent across reruns.
- Do not hardcode GUIDs, tenant IDs, subscription IDs, or storage account names in code. They come from parameters or CSV.

## Testing / validation

There is no automated test suite. Validate changes by:
1. Running `pwsh` with `-WhatIf` where supported.
2. Running the full script against a non-prod subscription with a small CSV (1–2 STMOs).
3. Re-running to confirm idempotency (zero changes on second run except where drift is intentional).
