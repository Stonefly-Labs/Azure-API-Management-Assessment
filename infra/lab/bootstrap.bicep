targetScope = 'resourceGroup'

@description('Azure region for bootstrap identity resources.')
param location string = resourceGroup().location

@description('GitHub repository in owner/name format.')
param githubRepository string = 'Stonefly-Labs/Azure-API-Management-Assessment'

@description('GitHub Actions environment name bound to federated credentials.')
param githubEnvironment string = 'azure-lab'

@description('Name of the deploy user-assigned managed identity.')
param deployIdentityName string = 'id-apv-gh-deploy-wus3-001'

@description('Name of the read-only assess user-assigned managed identity.')
param assessIdentityName string = 'id-apv-gh-assess-wus3-001'

@description('Standard resource tags including MCAPS sandbox exemption.')
param tags object = {
  SecurityControl: 'Ignore'
  project: 'apim-assess'
  environment: 'validation-lab'
  managedBy: 'bicep'
}

var oidcIssuer = 'https://token.actions.githubusercontent.com'
var oidcSubject = 'repo:${githubRepository}:environment:${githubEnvironment}'
var oidcImmutableSubject = 'repo:Stonefly-Labs@279819657/Azure-API-Management-Assessment@1452795381:environment:${githubEnvironment}'
var oidcAudiences = [
  'api://AzureADTokenExchange'
]

module deployIdentity 'br/public:avm/res/managed-identity/user-assigned-identity:0.5.0' = {
  name: 'avm-${deployIdentityName}'
  params: {
    name: deployIdentityName
    location: location
    tags: tags
  }
}

resource existingDeployIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = {
  name: deployIdentityName
  dependsOn: [
    deployIdentity
  ]
}

resource deployFic 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials@2023-01-31' = {
  parent: existingDeployIdentity
  name: 'fic-gh-azure-lab-deploy'
  properties: {
    issuer: oidcIssuer
    subject: oidcSubject
    audiences: oidcAudiences
  }
}

resource deployFicImmutable 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials@2023-01-31' = {
  parent: existingDeployIdentity
  name: 'fic-gh-azure-lab-deploy-id'
  properties: {
    issuer: oidcIssuer
    subject: oidcImmutableSubject
    audiences: oidcAudiences
  }
}

module assessIdentity 'br/public:avm/res/managed-identity/user-assigned-identity:0.5.0' = {
  name: 'avm-${assessIdentityName}'
  params: {
    name: assessIdentityName
    location: location
    tags: tags
  }
}

resource existingAssessIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = {
  name: assessIdentityName
  dependsOn: [
    assessIdentity
  ]
}

resource assessFic 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials@2023-01-31' = {
  parent: existingAssessIdentity
  name: 'fic-gh-azure-lab-assess'
  properties: {
    issuer: oidcIssuer
    subject: oidcSubject
    audiences: oidcAudiences
  }
}

resource assessFicImmutable 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials@2023-01-31' = {
  parent: existingAssessIdentity
  name: 'fic-gh-azure-lab-assess-id'
  properties: {
    issuer: oidcIssuer
    subject: oidcImmutableSubject
    audiences: oidcAudiences
  }
}

output deployIdentityResourceId string = deployIdentity.outputs.resourceId
output deployIdentityClientId string = deployIdentity.outputs.clientId
output deployIdentityPrincipalId string = deployIdentity.outputs.principalId

output assessIdentityResourceId string = assessIdentity.outputs.resourceId
output assessIdentityClientId string = assessIdentity.outputs.clientId
output assessIdentityPrincipalId string = assessIdentity.outputs.principalId
output oidcSubjectClaim string = oidcSubject
