targetScope = 'resourceGroup'

@description('Azure region for the public Basic v2 APIM instance.')
param location string = resourceGroup().location

@description('Name of the public Basic v2 APIM instance.')
param apimName string = 'apim-apv-bv2-wus3-001'

@description('Resource ID of the Log Analytics workspace for GatewayLogs and AllMetrics.')
param workspaceResourceId string

@description('Resource ID of the Key Vault to grant Key Vault Secrets User to BasicV2 APIM.')
param keyVaultName string = ''

@description('Publisher email for the APIM instance.')
param publisherEmail string = 'apim-lab@contoso.com'

@description('Publisher name for the APIM instance.')
param publisherName string = 'Contoso Validation Lab'

@description('Standard resource tags including MCAPS sandbox exemption.')
param tags object = {
  SecurityControl: 'Ignore'
  project: 'apim-assess'
  environment: 'validation-lab'
  managedBy: 'bicep'
}

// Healthy comparison posture on BasicV2 APIM:
// - BasicV2 SKU with 2 scale units -> passes APIM-REL-001 & APIM-REL-003
// - SystemAssigned managed identity -> passes APIM-SEC-011
// - minApiVersion 2021-08-01 -> passes APIM-SEC-010
// - customProperties empty ({}) because BasicV2 does not support classic cipher customProperties
//   and disables legacy SSL 3.0 / TLS 1.0 / TLS 1.1 by platform default
// - diagnosticSettings shipping GatewayLogs/AllMetrics to Log Analytics -> passes APIM-OPS-001
module apimBv2 'br/public:avm/res/api-management/service:0.9.1' = {
  name: 'avm-${apimName}'
  params: {
    name: apimName
    location: location
    tags: tags
    sku: 'BasicV2'
    skuCapacity: 2
    publisherEmail: publisherEmail
    publisherName: publisherName
    virtualNetworkType: 'None'
    minApiVersion: '2021-08-01'
    enableDeveloperPortal: true
    managedIdentities: {
      systemAssigned: true
    }
    customProperties: {}
    diagnosticSettings: [
      {
        name: 'diag-apv-apim-bv2'
        workspaceResourceId: workspaceResourceId
        logAnalyticsDestinationType: 'Dedicated'
        logCategoriesAndGroups: [
          {
            categoryGroup: 'allLogs'
            enabled: true
          }
        ]
        metricCategories: [
          {
            category: 'AllMetrics'
            enabled: true
          }
        ]
      }
    ]
  }
}

resource existingApimBv2 'Microsoft.ApiManagement/service@2024-05-01' existing = {
  name: apimName
  dependsOn: [
    apimBv2
  ]
}

resource existingKeyVault 'Microsoft.KeyVault/vaults@2023-07-01' existing = if (!empty(keyVaultName)) {
  name: keyVaultName
}

// Key Vault Secrets User role assignment so BasicV2 APIM can resolve Key Vault-backed named values
var keyVaultSecretsUserRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '4633458b-17de-408a-b874-0445c86b69e6'
)

resource bv2KvRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(keyVaultName)) {
  name: guid(resourceGroup().id, keyVaultName, apimName, keyVaultSecretsUserRoleId)
  scope: existingKeyVault
  properties: {
    principalId: apimBv2.outputs.?systemAssignedMIPrincipalId ?? ''
    principalType: 'ServicePrincipal'
    roleDefinitionId: keyVaultSecretsUserRoleId
  }
}

output apimResourceId string = apimBv2.outputs.resourceId
output apimName string = apimBv2.outputs.name
output principalId string = apimBv2.outputs.?systemAssignedMIPrincipalId ?? ''
output gatewayUrl string = existingApimBv2.properties.?gatewayUrl ?? 'https://${apimName}.azure-api.net'
