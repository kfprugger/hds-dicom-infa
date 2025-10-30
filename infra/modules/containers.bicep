@description('Name of the storage account that owns the containers.')
param storageAccountName string

@description('Study container definitions containing primary and inventory container names along with inventory rule metadata.')
param containerDefinitions array

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' existing = {
  name: storageAccountName
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2022-09-01' existing = {
  name: 'default'
  parent: storageAccount
}

var primaryContainers = [for definition in containerDefinitions: definition.primaryContainerName]
var inventoryContainers = [for definition in containerDefinitions: definition.inventoryContainerName]
var allContainers = union(primaryContainers, inventoryContainers)

resource blobContainers 'Microsoft.Storage/storageAccounts/blobServices/containers@2022-09-01' = [for containerName in allContainers: {
  name: containerName
  parent: blobService
  properties: {
    publicAccess: 'None'
  }
}]

var inventorySchemaFields = [
  'Name'
  'Creation-Time'
  'Last-Modified'
  'ETag'
  'Content-Length'
  'Content-Type'
  'Content-Encoding'
  'Content-Language'
  'Content-CRC64'
  'Content-MD5'
  'Cache-Control'
  'Content-Disposition'
  'BlobType'
  'AccessTier'
  'AccessTierChangeTime'
  'AccessTierInferred'
  'Metadata'
  'LastAccessTime'
  'LeaseStatus'
  'LeaseState'
  'LeaseDuration'
  'ServerEncrypted'
  'CustomerProvidedKeySha256'
  'RehydratePriority'
  'ArchiveStatus'
  'EncryptionScope'
  'CopyId'
  'CopyStatus'
  'CopySource'
  'CopyProgress'
  'CopyCompletionTime'
  'CopyStatusDescription'
  'ImmutabilityPolicyUntilDate'
  'ImmutabilityPolicyMode'
  'LegalHold'
  'Tags'
  'TagCount'
]

resource inventoryPolicy 'Microsoft.Storage/storageAccounts/inventoryPolicies@2023-05-01' = if (length(containerDefinitions) > 0) {
  name: 'default'
  parent: storageAccount
  properties: {
    policy: {
      enabled: true
      type: 'Inventory'
      rules: [for definition in containerDefinitions: {
        enabled: true
        name: definition.ruleName
        destination: definition.inventoryContainerName
        definition: {
          objectType: 'Blob'
          format: 'Parquet'
          schedule: 'Weekly'
          schemaFields: inventorySchemaFields
          filters: {
            blobTypes: [
              'blockBlob'
            ]
            prefixMatch: [
              definition.prefixMatch
            ]
          }
        }
      }]
    }
  }
  dependsOn: [
    for container in blobContainers: container
  ]
}
