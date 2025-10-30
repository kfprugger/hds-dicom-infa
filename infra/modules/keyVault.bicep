targetScope = 'resourceGroup'

@description('Name of the Key Vault to ensure exists.')
param keyVaultName string

@description('Azure region used when creating the Key Vault.')
param location string

@description('Microsoft Entra tenant ID associated with the Key Vault.')
param tenantId string

@description('Key Vault SKU name.')
@allowed([
  'standard'
  'premium'
])
param skuName string = 'standard'

@description('Indicates whether the Key Vault already exists. When true, no changes are applied to the existing vault.')
param keyVaultExists bool = false

@description('Access policies applied when creating a new Key Vault. Existing vaults remain unchanged.')
param accessPolicies array = []

@description('Tags applied when creating a new Key Vault.')
param tags object = {}

@description('Soft delete retention period (days) to apply when creating the Key Vault.')
@minValue(7)
@maxValue(90)
param softDeleteRetentionInDays int = 90

@description('Determines whether purge protection is enabled when creating the Key Vault.')
param enablePurgeProtection bool = false

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = if (!keyVaultExists) {
  name: keyVaultName
  location: location
  tags: tags
  properties: {
    tenantId: tenantId
    sku: {
      family: 'A'
      name: skuName
    }
    accessPolicies: [for policy in accessPolicies: {
      tenantId: policy.tenantId == null ? tenantId : policy.tenantId
      objectId: policy.objectId
      permissions: policy.permissions
    }]
    publicNetworkAccess: 'Enabled'
    softDeleteRetentionInDays: softDeleteRetentionInDays
    enablePurgeProtection: enablePurgeProtection
  }
}

resource existingKeyVault 'Microsoft.KeyVault/vaults@2023-07-01' existing = if (keyVaultExists) {
  name: keyVaultName
}

var targetVault = keyVaultExists ? existingKeyVault : keyVault

output keyVaultId string = targetVault.id
output keyVaultName string = keyVaultName
