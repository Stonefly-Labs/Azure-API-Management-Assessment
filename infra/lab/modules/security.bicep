targetScope = 'resourceGroup'

@description('Azure region for security, registry, and storage resources.')
param location string = resourceGroup().location

@description('Unique suffix for globally unique ACR, Storage, and Key Vault names.')
param uniqueSuffix string = substring(uniqueString(subscription().id, resourceGroup().id), 0, 6)

@description('Principal ID of the read-only assessment identity for Blob upload RBAC.')
param assessPrincipalId string = ''

@description('Principal ID of the deploy identity for ACR push/pull and Key Vault RBAC.')
param deployPrincipalId string = ''

@description('Optional Application Insights instrumentation key stored in Key Vault for APIM logger bindings.')
@secure()
param appInsightsInstrumentationKey string = ''

@description('Standard resource tags including MCAPS sandbox exemption.')
param tags object = {
  SecurityControl: 'Ignore'
  project: 'apim-assess'
  environment: 'validation-lab'
  managedBy: 'bicep'
}

var acrName = 'acrapvlab${uniqueSuffix}'
var storageName = 'stapvlab${uniqueSuffix}'
var keyVaultName = 'kv-apv-lab-${uniqueSuffix}'
var workloadIdentityName = 'id-apv-workload-wus3-001'

module workloadIdentity 'br/public:avm/res/managed-identity/user-assigned-identity:0.5.0' = {
  name: 'avm-${workloadIdentityName}'
  params: {
    name: workloadIdentityName
    location: location
    tags: tags
  }
}

var acrRoles = concat(
  [
    {
      principalId: workloadIdentity.outputs.principalId
      principalType: 'ServicePrincipal'
      roleDefinitionIdOrName: 'AcrPull'
    }
  ],
  !empty(deployPrincipalId)
    ? [
        {
          principalId: deployPrincipalId
          principalType: 'ServicePrincipal'
          roleDefinitionIdOrName: 'AcrPush'
        }
      ]
    : []
)

module registry 'br/public:avm/res/container-registry/registry:0.9.3' = {
  name: 'avm-${acrName}'
  params: {
    name: acrName
    location: location
    tags: tags
    acrSku: 'Basic'
    acrAdminUserEnabled: false
    publicNetworkAccess: 'Enabled'
    roleAssignments: acrRoles
  }
}

var storageRoles = concat(
  !empty(assessPrincipalId)
    ? [
        {
          principalId: assessPrincipalId
          principalType: 'ServicePrincipal'
          roleDefinitionIdOrName: 'Storage Blob Data Contributor'
        }
      ]
    : [],
  !empty(deployPrincipalId)
    ? [
        {
          principalId: deployPrincipalId
          principalType: 'ServicePrincipal'
          roleDefinitionIdOrName: 'Storage Blob Data Contributor'
        }
      ]
    : []
)

module storage 'br/public:avm/res/storage/storage-account:0.9.1' = {
  name: 'avm-${storageName}'
  params: {
    name: storageName
    location: location
    tags: tags
    skuName: 'Standard_LRS'
    kind: 'StorageV2'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    minimumTlsVersion: 'TLS1_2'
    publicNetworkAccess: 'Enabled'
    supportsHttpsTrafficOnly: true
    blobServices: {
      containerDeleteRetentionPolicyEnabled: false
      deleteRetentionPolicyEnabled: false
      containers: [
        {
          name: 'assessment-runs'
          publicAccess: 'None'
        }
      ]
    }
    roleAssignments: storageRoles
  }
}

var kvRoles = !empty(deployPrincipalId)
  ? [
      {
        principalId: deployPrincipalId
        principalType: 'ServicePrincipal'
        roleDefinitionIdOrName: 'Key Vault Secrets Officer'
      }
    ]
  : []

// Purge protection is explicitly false and softDeleteRetentionInDays=7 so
// scripts/lab/destroy.py can purge the vault cleanly during teardown.
module keyVault 'br/public:avm/res/key-vault/vault:0.9.0' = {
  name: 'avm-${keyVaultName}'
  params: {
    name: keyVaultName
    location: location
    tags: tags
    sku: 'standard'
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    enablePurgeProtection: false
    publicNetworkAccess: 'Enabled'
    roleAssignments: kvRoles
    secrets: [
      {
        name: 'backend-api-shared-secret'
        value: 'kv-backed-lab-validation-placeholder-value'
      }
      {
        name: 'ai-gateway-partner-token'
        value: 'kv-backed-ai-gateway-placeholder-value'
      }
      {
        name: 'appinsights-instrumentation-key'
        value: !empty(appInsightsInstrumentationKey)
          ? appInsightsInstrumentationKey
          : '00000000-0000-0000-0000-000000000000'
      }
    ]
  }
}

output workloadIdentityResourceId string = workloadIdentity.outputs.resourceId
output workloadIdentityClientId string = workloadIdentity.outputs.clientId
output workloadIdentityPrincipalId string = workloadIdentity.outputs.principalId

output acrResourceId string = registry.outputs.resourceId
output acrName string = registry.outputs.name
output acrLoginServer string = registry.outputs.loginServer

output storageAccountResourceId string = storage.outputs.resourceId
output storageAccountName string = storage.outputs.name
output storageBlobEndpoint string = storage.outputs.primaryBlobEndpoint

output keyVaultResourceId string = keyVault.outputs.resourceId
output keyVaultName string = keyVault.outputs.name
output keyVaultUri string = keyVault.outputs.uri
output keyVaultBackendSecretUri string = '${keyVault.outputs.uri}secrets/backend-api-shared-secret'
output keyVaultAppInsightsKeySecretUri string = '${keyVault.outputs.uri}secrets/appinsights-instrumentation-key'
