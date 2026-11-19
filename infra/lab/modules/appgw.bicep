targetScope = 'resourceGroup'

@description('Azure region for the Application Gateway WAF_v2 resources.')
param location string = resourceGroup().location

@description('Name of the Application Gateway WAF_v2 instance.')
param appGwName string = 'agw-apv-lab-wus3-001'

@description('Name of the Standard Public IP for the Application Gateway frontend.')
param publicIpName string = 'pip-agw-apv-lab-wus3-001'

@description('Name of the Prevention WAF Policy attached to the BasicV2 APIM listener (APIM-SEC-004 pass).')
param wafPolicyBv2Name string = 'wafp-apv-bv2-wus3-001'

@description('Name of the Detection WAF Policy attached to the Developer APIM listener (APIM-SEC-004 fail).')
param wafPolicyDevName string = 'wafp-apv-dev-wus3-001'

@description('Resource ID of the dedicated Application Gateway subnet (snet-appgw).')
param appGwSubnetResourceId string

@description('Resource ID of the user-assigned managed identity with Key Vault Secrets User permission.')
param appGwIdentityResourceId string

@description('Unversioned Key Vault secret URI containing the ACME wildcard PFX certificate.')
param wildcardCertKeyVaultSecretUri string

@description('Public hostname for the BasicV2 APIM listener on Application Gateway.')
param agwBv2HostName string = 'agw-bv2.christopher-house.com'

@description('Public hostname for the Developer APIM listener on Application Gateway.')
param agwDevHostName string = 'agw-dev.christopher-house.com'

@description('Name of the BasicV2 APIM instance.')
param apimBv2Name string = 'apim-apv-bv2-wus3-001'

@description('Name of the Internal VNet Developer APIM instance.')
param apimDevName string = 'apim-apv-dev-wus3-001'

@description('Resource ID of the Log Analytics workspace for Application Gateway diagnostics.')
param workspaceResourceId string

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
  }
}

// Healthy WAF Policy for BasicV2 APIM route:
// - state: Enabled, mode: Prevention, OWASP 3.2 managed rule set -> passes APIM-SEC-004
module wafPolicyBv2 'br/public:avm/res/network/application-gateway-web-application-firewall-policy:0.3.0' = {
  name: 'avm-${wafPolicyBv2Name}'
  params: {
    name: wafPolicyBv2Name
    location: location
    tags: tags
    policySettings: {
      state: 'Enabled'
      mode: 'Prevention'
      requestBodyCheck: true
      maxRequestBodySizeInKb: 128
      fileUploadLimitInMb: 100
    }
    managedRules: {
      managedRuleSets: [
        {
          ruleSetType: 'OWASP'
          ruleSetVersion: '3.2'
        }
      ]
    }
  }
}

// Intentional negative WAF Policy for Developer APIM route:
// - state: Enabled, mode: Detection (not Prevention) -> fails APIM-SEC-004
module wafPolicyDev 'br/public:avm/res/network/application-gateway-web-application-firewall-policy:0.3.0' = {
  name: 'avm-${wafPolicyDevName}'
  params: {
    name: wafPolicyDevName
    location: location
    tags: tags
    policySettings: {
      state: 'Enabled'
      mode: 'Detection'
      requestBodyCheck: true
      maxRequestBodySizeInKb: 128
      fileUploadLimitInMb: 100
    }
    managedRules: {
      managedRuleSets: [
        {
          ruleSetType: 'OWASP'
          ruleSetVersion: '3.2'
        }
      ]
    }
  }
}

module appGw 'br/public:avm/res/network/application-gateway:0.10.0' = {
  name: 'avm-${appGwName}'
  params: {
    name: appGwName
    location: location
    tags: tags
    sku: 'WAF_v2'
    capacity: 1
    managedIdentities: {
      userAssignedResourceIds: [
        appGwIdentityResourceId
      ]
    }
    firewallPolicyResourceId: wafPolicyDev.outputs.resourceId
    gatewayIPConfigurations: [
      {
        name: 'appgw-ip-config'
        properties: {
          subnet: {
            id: appGwSubnetResourceId
          }
        }
      }
    ]
    frontendIPConfigurations: [
      {
        name: 'appgw-fe-ip'
        properties: {
          publicIPAddress: {
            id: publicIp.outputs.resourceId
          }
        }
      }
    ]
    frontendPorts: [
      {
        name: 'port-443'
        properties: {
          port: 443
        }
      }
    ]
    sslCertificates: [
      {
        name: 'cert-wildcard-christopher-house'
        properties: {
          keyVaultSecretId: wildcardCertKeyVaultSecretUri
        }
      }
    ]
    backendAddressPools: [
      {
        name: 'bp-apim-bv2'
        properties: {
          backendAddresses: [
            {
              fqdn: '${apimBv2Name}.azure-api.net'
            }
          ]
        }
      }
      {
        name: 'bp-apim-dev'
        properties: {
          backendAddresses: [
            {
              fqdn: '${apimDevName}.azure-api.net'
            }
          ]
        }
      }
    ]
    probes: [
      {
        name: 'probe-apim-bv2'
        properties: {
          protocol: 'Https'
          path: '/status-0123456789abcdef'
          interval: 30
          timeout: 30
          unhealthyThreshold: 3
          pickHostNameFromBackendHttpSettings: true
          minServers: 0
          match: {
            statusCodes: [
              '200-399'
            ]
          }
        }
      }
      {
        name: 'probe-apim-dev'
        properties: {
          protocol: 'Https'
          path: '/status-0123456789abcdef'
          interval: 30
          timeout: 30
          unhealthyThreshold: 3
          pickHostNameFromBackendHttpSettings: true
          minServers: 0
          match: {
            statusCodes: [
              '200-399'
            ]
          }
        }
      }
    ]
    backendHttpSettingsCollection: [
      {
        name: 'bhs-apim-bv2-https'
        properties: {
          port: 443
          protocol: 'Https'
          cookieBasedAffinity: 'Disabled'
          pickHostNameFromBackendAddress: true
          requestTimeout: 30
          probe: {
            id: resourceId('Microsoft.Network/applicationGateways/probes', appGwName, 'probe-apim-bv2')
          }
        }
      }
      {
        name: 'bhs-apim-dev-https'
        properties: {
          port: 443
          protocol: 'Https'
          cookieBasedAffinity: 'Disabled'
          pickHostNameFromBackendAddress: true
          requestTimeout: 30
          probe: {
            id: resourceId('Microsoft.Network/applicationGateways/probes', appGwName, 'probe-apim-dev')
          }
        }
      }
    ]
    httpListeners: [
      {
        name: 'listener-bv2-https'
        properties: {
          frontendIPConfiguration: {
            id: resourceId('Microsoft.Network/applicationGateways/frontendIPConfigurations', appGwName, 'appgw-fe-ip')
          }
          frontendPort: {
            id: resourceId('Microsoft.Network/applicationGateways/frontendPorts', appGwName, 'port-443')
          }
          protocol: 'Https'
          sslCertificate: {
            id: resourceId(
              'Microsoft.Network/applicationGateways/sslCertificates',
              appGwName,
              'cert-wildcard-christopher-house'
            )
          }
          hostName: agwBv2HostName
          requireServerNameIndication: true
          firewallPolicy: {
            id: wafPolicyBv2.outputs.resourceId
          }
        }
      }
      {
        name: 'listener-dev-https'
        properties: {
          frontendIPConfiguration: {
            id: resourceId('Microsoft.Network/applicationGateways/frontendIPConfigurations', appGwName, 'appgw-fe-ip')
          }
          frontendPort: {
            id: resourceId('Microsoft.Network/applicationGateways/frontendPorts', appGwName, 'port-443')
          }
          protocol: 'Https'
          sslCertificate: {
            id: resourceId(
              'Microsoft.Network/applicationGateways/sslCertificates',
              appGwName,
              'cert-wildcard-christopher-house'
            )
          }
          hostName: agwDevHostName
          requireServerNameIndication: true
          firewallPolicy: {
            id: wafPolicyDev.outputs.resourceId
          }
        }
      }
    ]
    requestRoutingRules: [
      {
        name: 'rule-bv2-https'
        properties: {
          ruleType: 'Basic'
          priority: 100
          httpListener: {
            id: resourceId('Microsoft.Network/applicationGateways/httpListeners', appGwName, 'listener-bv2-https')
          }
          backendAddressPool: {
            id: resourceId('Microsoft.Network/applicationGateways/backendAddressPools', appGwName, 'bp-apim-bv2')
          }
          backendHttpSettings: {
            id: resourceId(
              'Microsoft.Network/applicationGateways/backendHttpSettingsCollection',
              appGwName,
              'bhs-apim-bv2-https'
            )
          }
        }
      }
      {
        name: 'rule-dev-https'
        properties: {
          ruleType: 'Basic'
          priority: 110
          httpListener: {
            id: resourceId('Microsoft.Network/applicationGateways/httpListeners', appGwName, 'listener-dev-https')
          }
          backendAddressPool: {
            id: resourceId('Microsoft.Network/applicationGateways/backendAddressPools', appGwName, 'bp-apim-dev')
          }
          backendHttpSettings: {
            id: resourceId(
              'Microsoft.Network/applicationGateways/backendHttpSettingsCollection',
              appGwName,
              'bhs-apim-dev-https'
            )
          }
        }
      }
    ]
    diagnosticSettings: [
      {
        name: 'diag-apv-appgw'
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

resource existingPublicIp 'Microsoft.Network/publicIPAddresses@2024-05-01' existing = {
  name: publicIpName
  dependsOn: [
    publicIp
  ]
}

output appGwResourceId string = appGw.outputs.resourceId
output appGwName string = appGw.outputs.name
output appGwPublicIpAddress string = existingPublicIp.properties.?ipAddress ?? publicIp.outputs.ipAddress
