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
var oidcAudiences = [
  'api://AzureADTokenExchange'
]

module deployIdentity 'br/public:avm/res/managed-identity/user-assigned-identity:0.5.0' = {
  name: 'avm-${deployIdentityName}'
  params: {
    name: deployIdentityName
    location: location
    tags: tags
    federatedIdentityCredentials: [
      {
        name: 'fic-gh-azure-lab-deploy'
        issuer: oidcIssuer
        subject: oidcSubject
        audiences: oidcAudiences
      }
    ]
  }
}

module assessIdentity 'br/public:avm/res/managed-identity/user-assigned-identity:0.5.0' = {
  name: 'avm-${assessIdentityName}'
  params: {
    name: assessIdentityName
    location: location
    tags: tags
    federatedIdentityCredentials: [
      {
        name: 'fic-gh-azure-lab-assess'
        issuer: oidcIssuer
        subject: oidcSubject
        audiences: oidcAudiences
      }
    ]
  }
}

output deployIdentityResourceId string = deployIdentity.outputs.resourceId
output deployIdentityClientId string = deployIdentity.outputs.clientId
output deployIdentityPrincipalId string = deployIdentity.outputs.principalId

output assessIdentityResourceId string = assessIdentity.outputs.resourceId
output assessIdentityClientId string = assessIdentity.outputs.clientId
output assessIdentityPrincipalId string = assessIdentity.outputs.principalId
output oidcSubjectClaim string = oidcSubject
