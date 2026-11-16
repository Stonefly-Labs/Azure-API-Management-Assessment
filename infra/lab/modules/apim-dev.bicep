targetScope = 'resourceGroup'

@description('Azure region for the Internal VNet Developer APIM instance.')
param location string = resourceGroup().location

@description('Name of the Internal VNet Developer APIM instance.')
param apimName string = 'apim-apv-dev-wus3-001'

@description('Name of the dedicated Standard Public IP required by stv2 Internal VNet APIM.')
param publicIpName string = 'pip-apim-apv-dev-wus3-001'

@description('Resource ID of the VNet subnet (snet-apim-dev) for Internal VNet injection.')
param subnetResourceId string

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

module publicIp 'br/public:avm/res/network/public-ip-address:0.9.0' = {
  name: 'avm-${publicIpName}'
  params: {
    name: publicIpName
    location: location
    tags: tags
    skuName: 'Standard'
    skuTier: 'Regional'
    publicIPAllocationMethod: 'Static'
    publicIPAddressVersion: 'IPv4'
    dnsSettings: {
      domainNameLabel: apimName
    }
  }
}

// Intentional negative posture on Developer APIM:
// - Developer SKU (1 unit) in prod -> fails APIM-REL-001 & APIM-REL-003
// - Internal VNet injection with hardened subnet NSG -> passes APIM-SEC-001 & APIM-SEC-003
// - Enables TLS 1.0/1.1 and weak cipher -> fails APIM-SEC-006 & APIM-SEC-007
// - Sets minApiVersion to 2018-01-01 -> fails APIM-SEC-010
// - Omits diagnosticSettings -> fails APIM-OPS-001
module apimDev 'br/public:avm/res/api-management/service:0.9.1' = {
  name: 'avm-${apimName}'
  params: {
    name: apimName
    location: location
    tags: tags
    sku: 'Developer'
    skuCapacity: 1
    publisherEmail: publisherEmail
    publisherName: publisherName
    virtualNetworkType: 'Internal'
    subnetResourceId: subnetResourceId
    publicIpAddressResourceId: publicIp.outputs.resourceId
    minApiVersion: '2018-01-01'
    enableDeveloperPortal: true
    managedIdentities: {
      systemAssigned: true
    }
    customProperties: {
      'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls10': 'True'
      'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls11': 'True'
      'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Tls10': 'True'
      'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Tls11': 'True'
      'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Ciphers.TripleDes168': 'True'
      'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Ciphers.TLS_RSA_WITH_AES_128_CBC_SHA': 'True'
    }
  }
}

resource existingApimDev 'Microsoft.ApiManagement/service@2024-05-01' existing = {
  name: apimName
  dependsOn: [
    apimDev
  ]
}

output apimResourceId string = apimDev.outputs.resourceId
output apimName string = apimDev.outputs.name
output principalId string = apimDev.outputs.?systemAssignedMIPrincipalId ?? ''
output gatewayUrl string = existingApimDev.properties.?gatewayUrl ?? 'https://${apimName}.azure-api.net'
output privateIpAddress string = existingApimDev.properties.?privateIPAddresses[0] ?? '10.240.1.5'
