targetScope = 'resourceGroup'

@description('Azure region for Microsoft Foundry resources.')
param location string = resourceGroup().location

@description('Unique suffix for globally unique Foundry account subdomain.')
param uniqueSuffix string = substring(uniqueString(subscription().id, resourceGroup().id), 0, 6)

@description('Resource ID of the Log Analytics workspace for Foundry diagnostics.')
param workspaceResourceId string

@description('Primary Responses model deployment name.')
param primaryModelName string = 'gpt-5.6-sol'

@description('Primary Responses model version.')
param primaryModelVersion string = '2026-07-09'

@description('Secondary Responses model deployment name.')
param secondaryModelName string = 'gpt-5.4-mini'

@description('Secondary Responses model version.')
param secondaryModelVersion string = '2026-03-17'

@description('Embeddings model deployment name.')
param embeddingModelName string = 'text-embedding-3-small'

@description('Embeddings model version.')
param embeddingModelVersion string = '1'

@description('Principal IDs (such as APIM system-assigned managed identities) granted Cognitive Services OpenAI User.')
param openAiUserPrincipalIds array = []

@description('Standard resource tags including MCAPS sandbox exemption.')
param tags object = {
  SecurityControl: 'Ignore'
  project: 'apim-assess'
  environment: 'validation-lab'
  managedBy: 'bicep'
}

var accountName = 'ais-apv-lab-${uniqueSuffix}'
var projectName = 'proj-apv-lab-wus3-001'

var roleAssignments = [
  for pid in openAiUserPrincipalIds: {
    principalId: pid
    principalType: 'ServicePrincipal'
    roleDefinitionIdOrName: 'Cognitive Services OpenAI User'
  }
]

// Use AVM cognitive-services/account for the Foundry AIServices resource and
// sequential GlobalStandard model deployments.
module foundryAccount 'br/public:avm/res/cognitive-services/account:0.9.2' = {
  name: 'avm-${accountName}'
  params: {
    name: accountName
    location: location
    tags: tags
    kind: 'AIServices'
    sku: 'S0'
    customSubDomainName: accountName
    publicNetworkAccess: 'Enabled'
    disableLocalAuth: false
    managedIdentities: {
      systemAssigned: true
    }
    diagnosticSettings: [
      {
        name: 'diag-apv-foundry'
        workspaceResourceId: workspaceResourceId
      }
    ]
    roleAssignments: roleAssignments
    deployments: [
      {
        name: primaryModelName
        model: {
          format: 'OpenAI'
          name: primaryModelName
          version: primaryModelVersion
        }
        sku: {
          name: 'GlobalStandard'
          capacity: 10
        }
      }
      {
        name: secondaryModelName
        model: {
          format: 'OpenAI'
          name: secondaryModelName
          version: secondaryModelVersion
        }
        sku: {
          name: 'GlobalStandard'
          capacity: 10
        }
      }
      {
        name: embeddingModelName
        model: {
          format: 'OpenAI'
          name: embeddingModelName
          version: embeddingModelVersion
        }
        sku: {
          name: 'GlobalStandard'
          capacity: 10
        }
      }
    ]
  }
}

// Enable allowProjectManagement on the Foundry account and provision the child
// Foundry project (Microsoft.CognitiveServices/accounts/projects@2025-04-01-preview,
// which is not yet exposed by the AVM cognitive-services/account module).
resource existingFoundryAccount 'Microsoft.CognitiveServices/accounts@2025-04-01-preview' existing = {
  name: accountName
}

resource foundryProject 'Microsoft.CognitiveServices/accounts/projects@2025-04-01-preview' = {
  parent: existingFoundryAccount
  name: projectName
  location: location
  tags: tags
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    displayName: 'APIM Validation Lab Foundry Project'
    description: 'Microsoft Foundry project backing the apim-assess AI Gateway validation lab.'
  }
  dependsOn: [
    foundryAccount
  ]
}

output foundryAccountResourceId string = foundryAccount.outputs.resourceId
output foundryAccountName string = foundryAccount.outputs.name
output foundryEndpoint string = foundryAccount.outputs.endpoint
output foundryProjectResourceId string = foundryProject.id
output foundryProjectName string = foundryProject.name
output primaryDeploymentName string = primaryModelName
output secondaryDeploymentName string = secondaryModelName
output embeddingDeploymentName string = embeddingModelName
