targetScope = 'resourceGroup'

@description('Azure region for network resources.')
param location string = resourceGroup().location

@description('Name of the lab virtual network.')
param vnetName string = 'vnet-apv-lab-wus3-001'

@description('Name of the NSG attached to the Developer APIM subnet.')
param apimNsgName string = 'nsg-apv-apim-dev-wus3-001'

@description('Name of the NSG attached to the Container Apps subnet.')
param acaNsgName string = 'nsg-apv-aca-wus3-001'

@description('Standard resource tags including MCAPS sandbox exemption.')
param tags object = {
  SecurityControl: 'Ignore'
  project: 'apim-assess'
  environment: 'validation-lab'
  managedBy: 'bicep'
}

// NSG for the VNet-injected Developer APIM subnet (snet-apim-dev).
// Specifically satisfies APIM-SEC-003 (subnet_nsg in adjacent_checks.py):
//   - Allows inbound ApiManagement on TCP 3443
//   - Allows inbound AzureLoadBalancer on TCP 6390
//   - Allows inbound VirtualNetwork on TCP 443 for internal VNet gateway callers
//   - Explicitly denies inbound Internet on TCP 80 and 443
module apimNsg 'br/public:avm/res/network/network-security-group:0.5.4' = {
  name: 'avm-${apimNsgName}'
  params: {
    name: apimNsgName
    location: location
    tags: tags
    securityRules: [
      {
        name: 'Allow-Apim-ControlPlane-3443'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: 'ApiManagement'
          sourcePortRange: '*'
          destinationAddressPrefix: 'VirtualNetwork'
          destinationPortRange: '3443'
          description: 'Allow Azure API Management control plane traffic on port 3443.'
        }
      }
      {
        name: 'Allow-AzureLoadBalancer-6390'
        properties: {
          priority: 110
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: 'AzureLoadBalancer'
          sourcePortRange: '*'
          destinationAddressPrefix: 'VirtualNetwork'
          destinationPortRange: '6390'
          description: 'Allow Azure Load Balancer health probes on port 6390.'
        }
      }
      {
        name: 'Allow-VNet-Internal-Gateway-443'
        properties: {
          priority: 120
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: 'VirtualNetwork'
          sourcePortRange: '*'
          destinationAddressPrefix: 'VirtualNetwork'
          destinationPortRange: '443'
          description: 'Allow internal VNet callers (Container Apps Jobs) to reach the internal APIM gateway.'
        }
      }
      {
        name: 'Deny-Internet-Gateway-Http-Https'
        properties: {
          priority: 200
          direction: 'Inbound'
          access: 'Deny'
          protocol: 'Tcp'
          sourceAddressPrefix: 'Internet'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRanges: [
            '80'
            '443'
          ]
          description: 'Explicitly block direct public Internet traffic to internal VNet gateway ports.'
        }
      }
      {
        name: 'Allow-Outbound-Storage-443'
        properties: {
          priority: 100
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: 'VirtualNetwork'
          sourcePortRange: '*'
          destinationAddressPrefix: 'Storage'
          destinationPortRange: '443'
          description: 'Allow APIM outbound dependency to Azure Storage.'
        }
      }
      {
        name: 'Allow-Outbound-Sql-1433'
        properties: {
          priority: 110
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: 'VirtualNetwork'
          sourcePortRange: '*'
          destinationAddressPrefix: 'Sql'
          destinationPortRange: '1433'
          description: 'Allow APIM outbound dependency to Azure SQL.'
        }
      }
      {
        name: 'Allow-Outbound-KeyVault-443'
        properties: {
          priority: 120
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: 'VirtualNetwork'
          sourcePortRange: '*'
          destinationAddressPrefix: 'AzureKeyVault'
          destinationPortRange: '443'
          description: 'Allow APIM outbound dependency to Azure Key Vault.'
        }
      }
      {
        name: 'Allow-Outbound-Monitor-443'
        properties: {
          priority: 130
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: 'VirtualNetwork'
          sourcePortRange: '*'
          destinationAddressPrefix: 'AzureMonitor'
          destinationPortRanges: [
            '443'
            '1886'
          ]
          description: 'Allow APIM outbound dependency to Azure Monitor.'
        }
      }
    ]
  }
}

module acaNsg 'br/public:avm/res/network/network-security-group:0.5.4' = {
  name: 'avm-${acaNsgName}'
  params: {
    name: acaNsgName
    location: location
    tags: tags
    securityRules: []
  }
}

module vnet 'br/public:avm/res/network/virtual-network:0.9.0' = {
  name: 'avm-${vnetName}'
  params: {
    name: vnetName
    location: location
    tags: tags
    addressPrefixes: [
      '10.240.0.0/16'
    ]
    subnets: [
      {
        name: 'snet-apim-dev'
        addressPrefix: '10.240.1.0/26'
        networkSecurityGroupResourceId: apimNsg.outputs.resourceId
        serviceEndpoints: [
          'Microsoft.Storage'
          'Microsoft.Sql'
          'Microsoft.EventHub'
          'Microsoft.KeyVault'
        ]
      }
      {
        name: 'snet-aca'
        addressPrefix: '10.240.4.0/23'
        networkSecurityGroupResourceId: acaNsg.outputs.resourceId
        delegation: 'Microsoft.App/environments'
      }
    ]
  }
}

output vnetResourceId string = vnet.outputs.resourceId
output vnetName string = vnet.outputs.name
output apimSubnetResourceId string = vnet.outputs.subnetResourceIds[0]
output acaSubnetResourceId string = vnet.outputs.subnetResourceIds[1]
output apimNsgResourceId string = apimNsg.outputs.resourceId
