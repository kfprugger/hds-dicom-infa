targetScope = 'resourceGroup'

@description('Sanitized study location definitions containing ingest container metadata.')
param stmoDefinitions array

@description('Name of the shared blob storage account that ingests imaging data.')
param imageBlobAccountName string

@description('Name of the shared operations storage account that holds inventory and downstream data.')
param imageOperationsAccountName string

@description('SKU to apply to each storage account.')
param storageAccountSkuName string = 'Standard_LRS'

@description('Storage account kind applied to both storage accounts.')
param storageAccountKind string = 'StorageV2'

@description('Determines whether shared key access remains enabled on the storage accounts.')
param allowSharedKeyAccess bool = false

@description('Tags applied to both storage accounts.')
param globalTags object = {}

@description('When true, assigns the trusted workspace identity to Storage Blob Data Contributor on each storage account.')
param assignTrustedWorkspaceIdentity bool = false

@description('Principal ID of the trusted workspace identity to assign. Required when assignTrustedWorkspaceIdentity is true.')
param trustedWorkspacePrincipalId string = ''

@description('Principal type of the trusted workspace identity used for role assignment.')
@allowed([
  'ServicePrincipal'
  'Group'
  'User'
  'Application'
  'Device'
  'ForeignGroup'
])
param trustedWorkspacePrincipalType string = 'ServicePrincipal'

@description('Object ID of the DICOM administrators security group to assign Storage Blob Data Contributor on each storage account.')
param dicomAdminSecurityGroupId string = ''

var ingestionContainerDefinitions = [for definition in stmoDefinitions: {
  primaryContainerName: definition.containerName
  inventoryContainerName: definition.inventoryContainerName
  ruleName: definition.ruleName
  prefixMatch: definition.prefixMatch
}]

resource imageBlobAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: imageBlobAccountName
  location: resourceGroup().location
  sku: {
    name: storageAccountSkuName
  }
  kind: storageAccountKind
  properties: {
    allowBlobPublicAccess: false
    allowSharedKeyAccess: allowSharedKeyAccess
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    isHnsEnabled: false
    encryption: {
      keySource: 'Microsoft.Storage'
      services: {
        blob: {
          enabled: true
        }
      }
    }
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Allow'
    }
  }
  tags: globalTags
}

module ingestionContainers 'modules/containers.bicep' = if (length(ingestionContainerDefinitions) > 0) {
  name: 'image-blob-containers'
  params: {
    storageAccountName: imageBlobAccount.name
    containerDefinitions: ingestionContainerDefinitions
  }
}

resource imageOperationsAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: imageOperationsAccountName
  location: resourceGroup().location
  sku: {
    name: storageAccountSkuName
  }
  kind: storageAccountKind
  properties: {
    allowBlobPublicAccess: false
    allowSharedKeyAccess: allowSharedKeyAccess
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    isHnsEnabled: true
    encryption: {
      keySource: 'Microsoft.Storage'
      services: {
        blob: {
          enabled: true
        }
      }
    }
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Allow'
    }
  }
  tags: globalTags
}

resource operationsBlobService 'Microsoft.Storage/storageAccounts/blobServices@2022-09-01' existing = {
  name: 'default'
  parent: imageOperationsAccount
}

resource operationsContainers 'Microsoft.Storage/storageAccounts/blobServices/containers@2022-09-01' = [for definition in stmoDefinitions: {
  name: definition.containerName
  parent: operationsBlobService
  properties: {
    publicAccess: 'None'
  }
}]

resource trustedWorkspaceRoleAssignmentsBlob 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (assignTrustedWorkspaceIdentity && !empty(trustedWorkspacePrincipalId)) {
  name: guid(imageBlobAccount.id, trustedWorkspacePrincipalId, 'workspace-storage-blob-contributor')
  scope: imageBlobAccount
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
    principalId: trustedWorkspacePrincipalId
    principalType: trustedWorkspacePrincipalType
  }
}

resource trustedWorkspaceRoleAssignmentsOperations 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (assignTrustedWorkspaceIdentity && !empty(trustedWorkspacePrincipalId)) {
  name: guid(imageOperationsAccount.id, trustedWorkspacePrincipalId, 'workspace-ops-storage-blob-contributor')
  scope: imageOperationsAccount
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
    principalId: trustedWorkspacePrincipalId
    principalType: trustedWorkspacePrincipalType
  }
}

resource dicomAdminRoleAssignmentsBlob 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(dicomAdminSecurityGroupId)) {
  name: guid(imageBlobAccount.id, dicomAdminSecurityGroupId, 'dicom-admin-blob-contributor')
  scope: imageBlobAccount
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
    principalId: dicomAdminSecurityGroupId
    principalType: 'Group'
  }
}

resource dicomAdminRoleAssignmentsOperations 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(dicomAdminSecurityGroupId)) {
  name: guid(imageOperationsAccount.id, dicomAdminSecurityGroupId, 'dicom-admin-ops-blob-contributor')
  scope: imageOperationsAccount
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
    principalId: dicomAdminSecurityGroupId
    principalType: 'Group'
  }
}

output provisionedStorageAccounts array = [
  {
    name: imageBlobAccount.name
    id: imageBlobAccount.id
  }
  {
    name: imageOperationsAccount.name
    id: imageOperationsAccount.id
  }
]
