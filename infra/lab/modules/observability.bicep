targetScope = 'resourceGroup'

@description('Azure region for observability resources.')
param location string = resourceGroup().location

@description('Name of the Log Analytics workspace.')
param logAnalyticsName string = 'law-apv-lab-wus3-001'

@description('Name of the Application Insights component.')
param appInsightsName string = 'appi-apv-lab-wus3-001'

@description('Principal ID of the read-only assessment identity for Log Analytics Reader RBAC.')
param assessPrincipalId string = ''

@description('Standard resource tags including MCAPS sandbox exemption.')
param tags object = {
  SecurityControl: 'Ignore'
  project: 'apim-assess'
  environment: 'validation-lab'
  managedBy: 'bicep'
}

module workspace 'br/public:avm/res/operational-insights/workspace:0.9.1' = {
  name: 'avm-${logAnalyticsName}'
  params: {
    name: logAnalyticsName
    location: location
    tags: tags
    skuName: 'PerGB2018'
    dataRetention: 30
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
    roleAssignments: !empty(assessPrincipalId)
      ? [
          {
            principalId: assessPrincipalId
            principalType: 'ServicePrincipal'
            roleDefinitionIdOrName: 'Log Analytics Reader'
          }
        ]
      : []
  }
}

module appInsights 'br/public:avm/res/insights/component:0.8.0' = {
  name: 'avm-${appInsightsName}'
  params: {
    name: appInsightsName
    location: location
    tags: tags
    workspaceResourceId: workspace.outputs.resourceId
    applicationType: 'web'
    kind: 'web'
    retentionInDays: 30
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

output workspaceResourceId string = workspace.outputs.resourceId
output workspaceName string = workspace.outputs.name
output workspaceCustomerId string = workspace.outputs.logAnalyticsWorkspaceId
output appInsightsResourceId string = appInsights.outputs.resourceId
output appInsightsName string = appInsights.outputs.name
output appInsightsInstrumentationKey string = appInsights.outputs.instrumentationKey
output appInsightsConnectionString string = appInsights.outputs.connectionString
