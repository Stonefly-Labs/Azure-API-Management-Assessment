targetScope = 'resourceGroup'

@description('Azure region for all validation lab resources.')
param location string = resourceGroup().location

@description('Deterministic suffix for globally unique resource names.')
param uniqueSuffix string = substring(uniqueString(subscription().id, resourceGroup().id), 0, 6)

@description('Deployment phase: "foundation" provisions ACR, Storage, Key Vault, VNet, Observability, and Foundry; "full" adds Container Apps, APIM instances, Private DNS, and APIM configuration.')
@allowed([
  'foundation'
  'full'
])
param deploymentPhase string = 'full'

@description('Microsoft Entra tenant ID.')
param tenantId string = subscription().tenantId

@description('Entra client ID for the APIM gateway audience app registration.')
param apimGatewayAppClientId string = '00000000-0000-0000-0000-000000000001'

@description('Entra client ID for the MCP backend app registration.')
param mcpBackendAppClientId string = '00000000-0000-0000-0000-000000000002'

@description('Entra client ID for the A2A backend app registration.')
param a2aBackendAppClientId string = '00000000-0000-0000-0000-000000000003'

@description('Entra client ID for the smoke-test client app registration.')
param smokeClientAppClientId string = '00000000-0000-0000-0000-000000000004'

@description('Entra audience URI for the MCP API app registration.')
param mcpAudience string = 'api://${mcpBackendAppClientId}'

@description('Entra audience URI for the A2A API app registration.')
param a2aAudience string = 'api://${a2aBackendAppClientId}'

@description('Resource ID of the persistent deploy user-assigned managed identity.')
param deployIdentityResourceId string = ''

@description('Client ID of the persistent deploy user-assigned managed identity.')
param deployIdentityClientId string = ''

@description('Principal ID of the persistent deploy user-assigned managed identity.')
param deployIdentityPrincipalId string = ''

@description('Resource ID of the persistent read-only assessment user-assigned managed identity.')
param assessIdentityResourceId string = ''

@description('Client ID of the persistent read-only assessment user-assigned managed identity.')
param assessIdentityClientId string = ''

@description('Principal ID of the persistent read-only assessment user-assigned managed identity.')
param assessIdentityPrincipalId string = ''

@description('Container image tag in ACR for the Python lab workloads (REST, MCP, A2A).')
param workloadImage string = 'mcr.microsoft.com/azuredocs/containerapps-helloworld:latest'

@description('Container image tag in ACR for the apim-assess and smoke runner jobs.')
param assessImage string = 'mcr.microsoft.com/azuredocs/containerapps-helloworld:latest'

@description('Name of the Internal VNet Developer APIM instance.')
param apimDevName string = 'apim-apv-dev-wus3-001'

@description('Name of the Public BasicV2 APIM instance.')
param apimBv2Name string = 'apim-apv-bv2-wus3-001'

@description('Optional resolved public IPv4 of the BasicV2 APIM instance for VNet Private DNS resolution.')
param apimBv2PublicIp string = ''

@description('Optional resolved public IPv4 of regional Cognitive Services (cognitiveusw3prod.azure-api.net) for VNet Private DNS resolution.')
param foundryPublicIp string = ''

@description('Optional Key Vault secret URI containing the ACME wildcard certificate for Application Gateway and BasicV2 APIM.')
param wildcardCertKeyVaultSecretUri string = ''

@description('Public hostname for the BasicV2 APIM listener on Application Gateway.')
param agwBv2HostName string = 'agw-bv2.christopher-house.com'

@description('Public hostname for the Developer APIM listener on Application Gateway.')
param agwDevHostName string = 'agw-dev.christopher-house.com'

@description('Optional custom Proxy domain hostname for BasicV2 APIM (APIM-SEC-014 pass).')
param bv2CustomDomainHostName string = 'api-bv2.christopher-house.com'

@description('Optional custom Proxy domain hostname for Developer APIM (APIM-SEC-014 fail).')
param devCustomDomainHostName string = 'api-dev.christopher-house.com'

@description('Optional base64-encoded short-lived custom PFX certificate for Developer APIM (APIM-SEC-014 fail).')
@secure()
param devCustomDomainEncodedCertificate string = ''

@description('Optional password for the short-lived custom PFX certificate on Developer APIM.')
@secure()
param devCustomDomainCertificatePassword string = ''

@description('When true, skip re-running the Developer APIM service deployment if already converged.')
param skipApimDevServiceUpdate bool = false

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

@description('Standard resource tags including MCAPS sandbox exemption.')
param tags object = {
  SecurityControl: 'Ignore'
  project: 'apim-assess'
  environment: 'validation-lab'
  managedBy: 'bicep'
}

// ============================================================================
// 1. Network Foundation (AVM VNet + Hardened Subnet NSGs)
// ============================================================================

module network 'modules/network.bicep' = {
  name: 'lab-network'
  params: {
    location: location
    tags: tags
  }
}

// ============================================================================
// 2. Observability Foundation (AVM Log Analytics + App Insights)
// ============================================================================

module observability 'modules/observability.bicep' = {
  name: 'lab-observability'
  params: {
    location: location
    assessPrincipalId: assessIdentityPrincipalId
    tags: tags
  }
}

// ============================================================================
// 3. Security, Registry, Storage, and Key Vault Foundation (AVM)
// ============================================================================

module security 'modules/security.bicep' = {
  name: 'lab-security'
  params: {
    location: location
    uniqueSuffix: uniqueSuffix
    assessPrincipalId: assessIdentityPrincipalId
    deployPrincipalId: deployIdentityPrincipalId
    appInsightsInstrumentationKey: observability.outputs.appInsightsInstrumentationKey
    tags: tags
  }
}

// ============================================================================
// 4. Paired APIM Instances (AVM API Management + Public IP)
// ============================================================================

module apimDev 'modules/apim-dev.bicep' = if (deploymentPhase == 'full') {
  name: 'lab-apim-dev'
  params: {
    location: location
    apimName: apimDevName
    subnetResourceId: network.outputs.apimSubnetResourceId
    customDomainHostName: devCustomDomainHostName
    customDomainEncodedCertificate: devCustomDomainEncodedCertificate
    customDomainCertificatePassword: devCustomDomainCertificatePassword
    skipServiceUpdate: skipApimDevServiceUpdate
    tags: tags
  }
}

module apimBv2 'modules/apim-bv2.bicep' = if (deploymentPhase == 'full') {
  name: 'lab-apim-bv2'
  params: {
    location: location
    apimName: apimBv2Name
    workspaceResourceId: observability.outputs.workspaceResourceId
    keyVaultName: security.outputs.keyVaultName
    customDomainHostName: bv2CustomDomainHostName
    customDomainKeyVaultSecretUri: wildcardCertKeyVaultSecretUri
    certIdentityResourceId: security.outputs.appGwIdentityResourceId
    certIdentityClientId: security.outputs.appGwIdentityClientId
    tags: tags
  }
}

// ============================================================================
// 5. Scoped Private DNS for Internal Developer APIM (AVM Private DNS Zone)
// ============================================================================

module privateDns 'modules/private-dns.bicep' = if (deploymentPhase == 'full') {
  name: 'lab-private-dns'
  params: {
    vnetResourceId: network.outputs.vnetResourceId
    devApimName: apimDevName
    devApimPrivateIp: apimDev!.outputs.privateIpAddress
    bv2ApimName: apimBv2Name
    bv2ApimPublicIp: !empty(apimBv2PublicIp) ? apimBv2PublicIp : apimBv2!.outputs.publicIpAddress
    foundryPublicIp: foundryPublicIp
    tags: tags
  }
}

// ============================================================================
// 5b. Application Gateway WAF_v2 Ingress (AVM Application Gateway + WAF Policies)
// ============================================================================

module appGw 'modules/appgw.bicep' = if (deploymentPhase == 'full' && !empty(wildcardCertKeyVaultSecretUri)) {
  name: 'lab-appgw'
  params: {
    location: location
    appGwSubnetResourceId: network.outputs.appGwSubnetResourceId
    appGwIdentityResourceId: security.outputs.appGwIdentityResourceId
    wildcardCertKeyVaultSecretUri: wildcardCertKeyVaultSecretUri
    agwBv2HostName: agwBv2HostName
    agwDevHostName: agwDevHostName
    apimBv2Name: apimBv2Name
    apimDevName: apimDevName
    workspaceResourceId: observability.outputs.workspaceResourceId
    tags: tags
  }
}

// ============================================================================
// 6. Microsoft Foundry Account, Project & Model Deployments (AVM)
// ============================================================================

var foundryOpenAiUsers = deploymentPhase == 'full'
  ? [
      apimDev!.outputs.principalId
      apimBv2!.outputs.principalId
    ]
  : []

module foundry 'modules/foundry.bicep' = {
  name: 'lab-foundry'
  params: {
    location: location
    uniqueSuffix: uniqueSuffix
    workspaceResourceId: observability.outputs.workspaceResourceId
    primaryModelName: primaryModelName
    primaryModelVersion: primaryModelVersion
    secondaryModelName: secondaryModelName
    secondaryModelVersion: secondaryModelVersion
    embeddingModelName: embeddingModelName
    embeddingModelVersion: embeddingModelVersion
    openAiUserPrincipalIds: foundryOpenAiUsers
    tags: tags
  }
}

// ============================================================================
// 7. Container Apps Managed Environment, Apps, and Jobs (AVM)
// ============================================================================

module containerApps 'modules/container-apps.bicep' = if (deploymentPhase == 'full') {
  name: 'lab-container-apps'
  params: {
    location: location
    acaSubnetResourceId: network.outputs.acaSubnetResourceId
    workspaceResourceId: observability.outputs.workspaceResourceId
    appInsightsConnectionString: observability.outputs.appInsightsConnectionString
    acrLoginServer: security.outputs.acrLoginServer
    workloadImage: workloadImage
    assessImage: assessImage
    workloadIdentityResourceId: security.outputs.workloadIdentityResourceId
    workloadIdentityClientId: security.outputs.workloadIdentityClientId
    assessIdentityResourceId: assessIdentityResourceId
    assessIdentityClientId: assessIdentityClientId
    deployIdentityResourceId: deployIdentityResourceId
    deployIdentityClientId: deployIdentityClientId
    tenantId: tenantId
    mcpAudience: mcpAudience
    a2aAudience: a2aAudience
    storageAccountName: security.outputs.storageAccountName
    devGatewayUrl: 'https://${apimDevName}.azure-api.net'
    bv2GatewayUrl: 'https://${apimBv2Name}.azure-api.net'
    tags: tags
  }
}

// ============================================================================
// 8. APIM Sub-Resources & Rule Coverage Configuration (Dev vs BasicV2)
// ============================================================================

module apimConfig 'modules/apim-config.bicep' = if (deploymentPhase == 'full') {
  name: 'lab-apim-config'
  params: {
    apimDevName: apimDev!.outputs.apimName
    apimBv2Name: apimBv2!.outputs.apimName
    tenantId: tenantId
    apimGatewayAppClientId: apimGatewayAppClientId
    mcpBackendAppClientId: mcpBackendAppClientId
    a2aBackendAppClientId: a2aBackendAppClientId
    smokeClientAppClientId: smokeClientAppClientId
    restAppUrl: containerApps!.outputs.restAppUrl
    mcpAppUrl: containerApps!.outputs.mcpAppUrl
    a2aAppUrl: containerApps!.outputs.a2aAppUrl
    foundryAccountName: foundry.outputs.foundryAccountName
    appInsightsResourceId: observability.outputs.appInsightsResourceId
    appInsightsInstrumentationKey: observability.outputs.appInsightsInstrumentationKey
    keyVaultSecretUri: security.outputs.keyVaultBackendSecretUri
    keyVaultAppInsightsKeySecretUri: security.outputs.keyVaultAppInsightsKeySecretUri
  }
  dependsOn: [
    privateDns
  ]
}

// ============================================================================
// Outputs
// ============================================================================

output acrName string = security.outputs.acrName
output acrLoginServer string = security.outputs.acrLoginServer
output storageAccountName string = security.outputs.storageAccountName
output keyVaultName string = security.outputs.keyVaultName
output foundryAccountName string = foundry.outputs.foundryAccountName
output foundryEndpoint string = foundry.outputs.foundryEndpoint
output workspaceResourceId string = observability.outputs.workspaceResourceId
output appInsightsResourceId string = observability.outputs.appInsightsResourceId

output apimDevName string = apimDevName
output apimBv2Name string = apimBv2Name
output apimDevGatewayUrl string = deploymentPhase == 'full' ? apimDev!.outputs.gatewayUrl : 'https://${apimDevName}.azure-api.net'
output apimBv2GatewayUrl string = deploymentPhase == 'full' ? apimBv2!.outputs.gatewayUrl : 'https://${apimBv2Name}.azure-api.net'
output apimDevPrivateIp string = deploymentPhase == 'full' ? apimDev!.outputs.privateIpAddress : ''
output appGwName string = deploymentPhase == 'full' && !empty(wildcardCertKeyVaultSecretUri) ? appGw!.outputs.appGwName : 'agw-apv-lab-wus3-001'
output appGwPublicIpAddress string = deploymentPhase == 'full' && !empty(wildcardCertKeyVaultSecretUri) ? appGw!.outputs.appGwPublicIpAddress : ''
output restAppUrl string = deploymentPhase == 'full' ? containerApps!.outputs.restAppUrl : ''
output mcpAppUrl string = deploymentPhase == 'full' ? containerApps!.outputs.mcpAppUrl : ''
output a2aAppUrl string = deploymentPhase == 'full' ? containerApps!.outputs.a2aAppUrl : ''
output smokeJobName string = deploymentPhase == 'full' ? containerApps!.outputs.smokeJobName : 'caj-apv-smoke-wus3-001'
output assessJobName string = deploymentPhase == 'full' ? containerApps!.outputs.assessJobName : 'caj-apv-assess-wus3-001'
