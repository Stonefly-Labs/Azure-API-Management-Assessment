targetScope = 'resourceGroup'

@description('Azure region for Container Apps resources.')
param location string = resourceGroup().location

@description('Resource ID of the Container Apps delegated subnet (snet-aca).')
param acaSubnetResourceId string

@description('Resource ID of the Log Analytics workspace.')
param workspaceResourceId string

@description('Application Insights connection string.')
param appInsightsConnectionString string

@description('ACR login server (for example acrapvlabxxxx.azurecr.io).')
param acrLoginServer string

@description('Container image for the lab Python workloads (REST, MCP, A2A, Smoke).')
param workloadImage string

@description('Container image for the apim-assess runner job.')
param assessImage string

@description('Resource ID of the workload user-assigned managed identity (AcrPull).')
param workloadIdentityResourceId string

@description('Client ID of the workload user-assigned managed identity.')
param workloadIdentityClientId string

@description('Resource ID of the read-only assessment user-assigned managed identity.')
param assessIdentityResourceId string

@description('Client ID of the read-only assessment user-assigned managed identity.')
param assessIdentityClientId string

@description('Resource ID of the deploy user-assigned managed identity (used by smoke job to acquire Entra tokens).')
param deployIdentityResourceId string

@description('Client ID of the deploy user-assigned managed identity.')
param deployIdentityClientId string

@description('Entra Tenant ID.')
param tenantId string

@description('Entra audience URI for the MCP API app registration.')
param mcpAudience string

@description('Entra audience URI for the A2A API app registration.')
param a2aAudience string

@description('Storage account name where the assess job uploads sanitized artifacts.')
param storageAccountName string

@description('Internal Developer APIM gateway URL.')
param devGatewayUrl string = 'https://apim-apv-dev-wus3-001.azure-api.net'

@description('Public BasicV2 APIM gateway URL.')
param bv2GatewayUrl string = 'https://apim-apv-bv2-wus3-001.azure-api.net'

@description('Standard resource tags including MCAPS sandbox exemption.')
param tags object = {
  SecurityControl: 'Ignore'
  project: 'apim-assess'
  environment: 'validation-lab'
  managedBy: 'bicep'
}

var envName = 'cae-apv-lab-wus3-001'
var restAppName = 'ca-apv-rest-wus3-001'
var mcpAppName = 'ca-apv-mcp-wus3-001'
var a2aAppName = 'ca-apv-a2a-wus3-001'
var smokeJobName = 'caj-apv-smoke-wus3-001'
var assessJobName = 'caj-apv-assess-wus3-001'

module managedEnv 'br/public:avm/res/app/managed-environment:0.9.1' = {
  name: 'avm-${envName}'
  params: {
    name: envName
    location: location
    tags: tags
    logAnalyticsWorkspaceResourceId: workspaceResourceId
    appInsightsConnectionString: appInsightsConnectionString
    infrastructureSubnetId: acaSubnetResourceId
    internal: false
    zoneRedundant: false
    workloadProfiles: [
      {
        name: 'Consumption'
        workloadProfileType: 'Consumption'
      }
    ]
  }
}

module restApp 'br/public:avm/res/app/container-app:0.9.0' = {
  name: 'avm-${restAppName}'
  params: {
    name: restAppName
    location: location
    tags: tags
    environmentResourceId: managedEnv.outputs.resourceId
    workloadProfileName: 'Consumption'
    ingressExternal: true
    ingressTargetPort: 8080
    ingressTransport: 'auto'
    scaleMinReplicas: 1
    scaleMaxReplicas: 2
    managedIdentities: {
      userAssignedResourceIds: [
        workloadIdentityResourceId
      ]
    }
    registries: [
      {
        server: acrLoginServer
        identity: workloadIdentityResourceId
      }
    ]
    containers: [
      {
        name: 'orders-rest'
        image: workloadImage
        resources: {
          cpu: json('0.25')
          memory: '0.5Gi'
        }
        env: [
          {
            name: 'LAB_APP_MODULE'
            value: 'samples.validation_lab.rest_app:app'
          }
          {
            name: 'PORT'
            value: '8080'
          }
        ]
        probes: [
          {
            type: 'Liveness'
            httpGet: {
              path: '/healthz'
              port: 8080
              scheme: 'HTTP'
            }
            initialDelaySeconds: 5
            periodSeconds: 15
          }
        ]
      }
    ]
  }
}

module mcpApp 'br/public:avm/res/app/container-app:0.9.0' = {
  name: 'avm-${mcpAppName}'
  params: {
    name: mcpAppName
    location: location
    tags: tags
    environmentResourceId: managedEnv.outputs.resourceId
    workloadProfileName: 'Consumption'
    ingressExternal: true
    ingressTargetPort: 8080
    ingressTransport: 'auto'
    scaleMinReplicas: 1
    scaleMaxReplicas: 2
    managedIdentities: {
      userAssignedResourceIds: [
        workloadIdentityResourceId
      ]
    }
    registries: [
      {
        server: acrLoginServer
        identity: workloadIdentityResourceId
      }
    ]
    containers: [
      {
        name: 'mcp-server'
        image: workloadImage
        resources: {
          cpu: json('0.25')
          memory: '0.5Gi'
        }
        env: [
          {
            name: 'LAB_APP_MODULE'
            value: 'samples.validation_lab.mcp_app:app'
          }
          {
            name: 'PORT'
            value: '8080'
          }
          {
            name: 'LAB_ENTRA_TENANT_ID'
            value: tenantId
          }
          {
            name: 'LAB_ENTRA_AUDIENCE'
            value: mcpAudience
          }
          {
            name: 'LAB_ENTRA_REQUIRED_ROLE'
            value: 'Mcp.Tool.Invoke'
          }
        ]
        probes: [
          {
            type: 'Liveness'
            httpGet: {
              path: '/healthz'
              port: 8080
              scheme: 'HTTP'
            }
            initialDelaySeconds: 5
            periodSeconds: 15
          }
        ]
      }
    ]
  }
}

module a2aApp 'br/public:avm/res/app/container-app:0.9.0' = {
  name: 'avm-${a2aAppName}'
  params: {
    name: a2aAppName
    location: location
    tags: tags
    environmentResourceId: managedEnv.outputs.resourceId
    workloadProfileName: 'Consumption'
    ingressExternal: true
    ingressTargetPort: 8080
    ingressTransport: 'auto'
    scaleMinReplicas: 1
    scaleMaxReplicas: 2
    managedIdentities: {
      userAssignedResourceIds: [
        workloadIdentityResourceId
      ]
    }
    registries: [
      {
        server: acrLoginServer
        identity: workloadIdentityResourceId
      }
    ]
    containers: [
      {
        name: 'a2a-agent'
        image: workloadImage
        resources: {
          cpu: json('0.25')
          memory: '0.5Gi'
        }
        env: [
          {
            name: 'LAB_APP_MODULE'
            value: 'samples.validation_lab.a2a_app:app'
          }
          {
            name: 'PORT'
            value: '8080'
          }
          {
            name: 'LAB_ENTRA_TENANT_ID'
            value: tenantId
          }
          {
            name: 'LAB_ENTRA_AUDIENCE'
            value: a2aAudience
          }
          {
            name: 'LAB_ENTRA_REQUIRED_ROLE'
            value: 'A2A.Agent.Invoke'
          }
        ]
        probes: [
          {
            type: 'Liveness'
            httpGet: {
              path: '/healthz'
              port: 8080
              scheme: 'HTTP'
            }
            initialDelaySeconds: 5
            periodSeconds: 15
          }
        ]
      }
    ]
  }
}

var smokeJobIdentities = !empty(deployIdentityResourceId)
  ? [
      workloadIdentityResourceId
      deployIdentityResourceId
    ]
  : [
      workloadIdentityResourceId
    ]

module smokeJob 'br/public:avm/res/app/job:0.7.2' = {
  name: 'avm-${smokeJobName}'
  params: {
    name: smokeJobName
    location: location
    tags: tags
    environmentResourceId: managedEnv.outputs.resourceId
    workloadProfileName: 'Consumption'
    triggerType: 'Manual'
    replicaTimeout: 600
    replicaRetryLimit: 1
    manualTriggerConfig: {
      parallelism: 1
      replicaCompletionCount: 1
    }
    managedIdentities: {
      userAssignedResourceIds: smokeJobIdentities
    }
    registries: [
      {
        server: acrLoginServer
        identity: workloadIdentityResourceId
      }
    ]
    containers: [
      {
        name: 'smoke-runner'
        image: assessImage
        command: [
          'python'
          '-m'
          'scripts.lab.run_smoke_in_job'
        ]
        resources: {
          cpu: '0.5'
          memory: '1Gi'
        }
        env: [
          {
            name: 'AZURE_CLIENT_ID'
            value: !empty(deployIdentityClientId) ? deployIdentityClientId : workloadIdentityClientId
          }
          {
            name: 'LAB_ENTRA_TENANT_ID'
            value: tenantId
          }
          {
            name: 'LAB_ENTRA_MCP_AUDIENCE'
            value: mcpAudience
          }
          {
            name: 'LAB_ENTRA_A2A_AUDIENCE'
            value: a2aAudience
          }
          {
            name: 'LAB_DEV_GATEWAY_URL'
            value: devGatewayUrl
          }
          {
            name: 'LAB_BV2_GATEWAY_URL'
            value: bv2GatewayUrl
          }
          {
            name: 'LAB_STORAGE_ACCOUNT_NAME'
            value: storageAccountName
          }
        ]
      }
    ]
  }
}

var assessJobIdentities = !empty(assessIdentityResourceId)
  ? [
      workloadIdentityResourceId
      assessIdentityResourceId
    ]
  : [
      workloadIdentityResourceId
    ]

module assessJob 'br/public:avm/res/app/job:0.7.2' = {
  name: 'avm-${assessJobName}'
  params: {
    name: assessJobName
    location: location
    tags: tags
    environmentResourceId: managedEnv.outputs.resourceId
    workloadProfileName: 'Consumption'
    triggerType: 'Manual'
    replicaTimeout: 900
    replicaRetryLimit: 1
    manualTriggerConfig: {
      parallelism: 1
      replicaCompletionCount: 1
    }
    managedIdentities: {
      userAssignedResourceIds: assessJobIdentities
    }
    registries: [
      {
        server: acrLoginServer
        identity: workloadIdentityResourceId
      }
    ]
    containers: [
      {
        name: 'assess-runner'
        image: assessImage
        command: [
          'python'
          '-m'
          'scripts.lab.run_assess_in_job'
        ]
        resources: {
          cpu: '0.5'
          memory: '1Gi'
        }
        env: [
          {
            name: 'AZURE_CLIENT_ID'
            value: !empty(assessIdentityClientId) ? assessIdentityClientId : workloadIdentityClientId
          }
          {
            name: 'AZURE_SUBSCRIPTION_ID'
            value: subscription().subscriptionId
          }
          {
            name: 'AZURE_LAB_RESOURCE_GROUP'
            value: resourceGroup().name
          }
          {
            name: 'LAB_STORAGE_ACCOUNT_NAME'
            value: storageAccountName
          }
        ]
      }
    ]
  }
}

output managedEnvironmentResourceId string = managedEnv.outputs.resourceId
output restAppFqdn string = restApp.outputs.fqdn
output restAppUrl string = 'https://${restApp.outputs.fqdn}'
output mcpAppFqdn string = mcpApp.outputs.fqdn
output mcpAppUrl string = 'https://${mcpApp.outputs.fqdn}'
output a2aAppFqdn string = a2aApp.outputs.fqdn
output a2aAppUrl string = 'https://${a2aApp.outputs.fqdn}'
output smokeJobName string = smokeJob.outputs.name
output assessJobName string = assessJob.outputs.name
