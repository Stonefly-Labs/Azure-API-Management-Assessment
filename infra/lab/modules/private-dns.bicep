targetScope = 'resourceGroup'

@description('Resource ID of the lab virtual network to link.')
param vnetResourceId string

@description('Name of the internal Developer APIM instance.')
param devApimName string

@description('Private IPv4 address of the internal Developer APIM gateway.')
param devApimPrivateIp string

@description('Standard resource tags including MCAPS sandbox exemption.')
param tags object = {
  SecurityControl: 'Ignore'
  project: 'apim-assess'
  environment: 'validation-lab'
  managedBy: 'bicep'
}

// Scoped Private DNS zone for azure-api.net with an exact record only for the
// internal Developer APIM instance (never a wildcard record) so public Basic v2
// APIM and other azure-api.net endpoints continue resolving normally.
module privateDns 'br/public:avm/res/network/private-dns-zone:0.8.1' = {
  name: 'avm-pdns-azure-api-net'
  params: {
    name: 'azure-api.net'
    tags: tags
    virtualNetworkLinks: [
      {
        name: 'link-apv-lab-vnet'
        virtualNetworkResourceId: vnetResourceId
        registrationEnabled: false
      }
    ]
    a: [
      {
        name: devApimName
        ttl: 300
        aRecords: [
          {
            ipv4Address: devApimPrivateIp
          }
        ]
      }
    ]
  }
}

output privateDnsZoneResourceId string = privateDns.outputs.resourceId
