@description('Name of the Developer APIM instance (intentional negative profile)')
param apimDevName string

@description('Name of the BasicV2 APIM instance (healthy comparison profile)')
param apimBv2Name string

@description('Microsoft Entra tenant ID')
param tenantId string

@description('Entra client ID for the APIM gateway audience app registration')
param apimGatewayAppClientId string

@description('Entra client ID for the MCP backend app registration')
param mcpBackendAppClientId string

@description('Entra client ID for the A2A backend app registration')
param a2aBackendAppClientId string

@description('Entra client ID for the smoke-test client app registration')
param smokeClientAppClientId string

@description('Base HTTPS URL of the Orders REST Container App')
param restAppUrl string

@description('Base HTTPS URL of the MCP Container App')
param mcpAppUrl string

@description('Base HTTPS URL of the A2A Container App')
param a2aAppUrl string

@description('Foundry AIServices account name')
param foundryAccountName string

@description('Application Insights resource ID')
param appInsightsResourceId string

@description('Application Insights instrumentation key')
@secure()
param appInsightsInstrumentationKey string

@description('Key Vault secret URI for the sample backend secret')
param keyVaultSecretUri string

var foundryOpenAiEndpoint = 'https://${foundryAccountName}.openai.azure.com/openai'
var openApiJson = loadTextContent('../openapi/orders-api.openapi.json')

// ============================================================================
// Existing APIM Services
// ============================================================================

resource apimDev 'Microsoft.ApiManagement/service@2024-05-01' existing = {
  name: apimDevName
}

resource apimBv2 'Microsoft.ApiManagement/service@2024-05-01' existing = {
  name: apimBv2Name
}

resource apimDevPreview 'Microsoft.ApiManagement/service@2025-09-01-preview' existing = {
  name: apimDevName
}

resource apimBv2Preview 'Microsoft.ApiManagement/service@2025-09-01-preview' existing = {
  name: apimBv2Name
}

// ============================================================================
// 1. Developer APIM Subresources (Intentional Negative Profile)
// ============================================================================

// APIM-SEC-009: fail (Direct management API access enabled)
resource devTenantAccess 'Microsoft.ApiManagement/service/tenant@2024-05-01' = {
  parent: apimDev
  name: 'access'
  properties: {
    enabled: true
  }
}

// APIM-SEC-022: fail (Developer portal allows anonymous access and open signup)
resource devPortalConfig 'Microsoft.ApiManagement/service/portalconfigs@2024-05-01' = {
  parent: apimDev
  name: 'default'
  properties: {
    enableBasicAuth: true
    signin: {
      require: false
    }
    signup: {
      termsOfService: {
        requireConsent: false
        text: 'Validation lab terms'
      }
    }
  }
}

resource devPortalSignup 'Microsoft.ApiManagement/service/portalsettings@2024-05-01' = {
  parent: apimDev
  name: 'signup'
  properties: {
    enabled: true
    termsOfService: {
      enabled: false
      consentRequired: false
      text: 'Validation lab terms'
    }
  }
}

// APIM-SEC-012: fail (Secret named value stored inline without Key Vault)
resource devNamedValueInlineSecret 'Microsoft.ApiManagement/service/namedValues@2024-05-01' = {
  parent: apimDev
  name: 'nv-dev-inline-secret'
  properties: {
    displayName: 'nv-dev-inline-secret'
    secret: true
    value: 'placeholder-inline-secret-for-lab'
  }
}

// APIM-SEC-013: pass (Non-secret named value stored as plain value)
resource devNamedValueEnv 'Microsoft.ApiManagement/service/namedValues@2024-05-01' = {
  parent: apimDev
  name: 'nv-dev-env'
  properties: {
    displayName: 'nv-dev-env'
    secret: false
    value: 'dev-negative-profile'
  }
}

// APIM-PERF-002: fail (Application Insights logger with 100% sampling and 8192 body bytes)
resource devAppInsightsLogger 'Microsoft.ApiManagement/service/loggers@2024-05-01' = {
  parent: apimDev
  name: 'appinsights'
  properties: {
    loggerType: 'applicationInsights'
    description: 'Application Insights logger for Developer APIM'
    resourceId: appInsightsResourceId
    credentials: {
      instrumentationKey: appInsightsInstrumentationKey
    }
  }
}

resource devAppInsightsDiagnostic 'Microsoft.ApiManagement/service/diagnostics@2024-05-01' = {
  parent: apimDev
  name: 'applicationinsights'
  properties: {
    loggerId: devAppInsightsLogger.id
    alwaysLog: 'allErrors'
    sampling: {
      samplingType: 'fixed'
      percentage: 100
    }
    frontend: {
      request: {
        body: {
          bytes: 8192
        }
      }
    }
  }
}

// Products: prod-orders (with APIs) and prod-empty (0 APIs -> APIM-COST-005 fail)
resource devProductOrders 'Microsoft.ApiManagement/service/products@2024-05-01' = {
  parent: apimDev
  name: 'prod-orders'
  properties: {
    displayName: 'Orders Product (Dev)'
    description: 'Orders product for Developer APIM'
    subscriptionRequired: true
    approvalRequired: false
    state: 'published'
  }
}

resource devProductEmpty 'Microsoft.ApiManagement/service/products@2024-05-01' = {
  parent: apimDev
  name: 'prod-empty'
  properties: {
    displayName: 'Empty Product (Dev)'
    description: 'Intentional empty product to exercise APIM-COST-005'
    subscriptionRequired: true
    approvalRequired: false
    state: 'published'
  }
}

// APIM-SEC-016: fail (All-APIs subscription scope)
resource devAllApisSubscription 'Microsoft.ApiManagement/service/subscriptions@2024-05-01' = {
  parent: apimDev
  name: 'sub-dev-all-apis'
  properties: {
    displayName: 'Dev All APIs Subscription'
    scope: '${apimDev.id}/apis'
    state: 'active'
  }
}

// Backends on Dev:
// APIM-SEC-021: fail (validateCertificateChain/Name = false)
// APIM-REL-007: fail (no circuitBreaker rules)
resource devBackendRest 'Microsoft.ApiManagement/service/backends@2024-05-01' = {
  parent: apimDev
  name: 'backend-rest'
  properties: {
    url: restAppUrl
    protocol: 'http'
    tls: {
      validateCertificateChain: false
      validateCertificateName: false
    }
  }
}

resource devBackendMcp 'Microsoft.ApiManagement/service/backends@2024-05-01' = {
  parent: apimDev
  name: 'backend-mcp'
  properties: {
    url: '${mcpAppUrl}/mcp'
    protocol: 'http'
    tls: {
      validateCertificateChain: true
      validateCertificateName: true
    }
  }
}

resource devBackendA2a 'Microsoft.ApiManagement/service/backends@2024-05-01' = {
  parent: apimDev
  name: 'backend-a2a'
  properties: {
    url: a2aAppUrl
    protocol: 'http'
    tls: {
      validateCertificateChain: true
      validateCertificateName: true
    }
  }
}

resource devBackendFoundry 'Microsoft.ApiManagement/service/backends@2024-05-01' = {
  parent: apimDev
  name: 'backend-foundry-primary'
  properties: {
    url: foundryOpenAiEndpoint
    protocol: 'http'
    tls: {
      validateCertificateChain: true
      validateCertificateName: true
    }
  }
}

// APIM-REL-008: fail (Backend pool with only 1 member)
resource devBackendPoolSingle 'Microsoft.ApiManagement/service/backends@2024-05-01' = {
  parent: apimDev
  name: 'backend-pool-single'
  properties: {
    type: 'Pool'
    pool: {
      services: [
        {
          id: '/subscriptions/${subscription().subscriptionId}/resourceGroups/${resourceGroup().name}/providers/Microsoft.ApiManagement/service/${apimDevName}/backends/${devBackendRest.name}'
          priority: 1
          weight: 100
        }
      ]
    }
  }
}

// Global policy on Dev (minimal pass-through)
resource devGlobalPolicy 'Microsoft.ApiManagement/service/policies@2024-05-01' = {
  parent: apimDev
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: '''
<policies>
  <inbound />
  <backend>
    <forward-request />
  </backend>
  <outbound />
  <on-error />
</policies>
'''
  }
}

// 1A. Dev REST API: orders-api (imported from OpenAPI spec)
// Exercises:
// - APIM-SEC-008: fail (protocols includes 'http')
// - APIM-SEC-017: fail (subscriptionRequired: false and no caller auth)
// - APIM-SEC-019: fail (outbound omits <base />)
// - APIM-SEC-020: fail (wildcard CORS <origin>*</origin>)
// - APIM-SEC-015: fail (inline secret literal in set-header)
// - APIM-REL-008: fail (routes to 1-member backend-pool-single)
// - APIM-REL-009: fail (no on-error handling)
// - APIM-REL-010: fail (<retry> without condition and <forward-request /> without timeout)
// - APIM-COST-004: fail (no rate-limit-by-key)
// - APIM-SEC-024: fail (no outbound deletion of X-Powered-By / X-AspNet-Version)
// - APIM-PERF-003: fail (POST operation has no validate-content)
// - APIM-PERF-004: unknown (GET operations omit cache-lookup/cache-store)
// - APIM-OPS-003: fail (shares identical 3-node outbound block with orders-legacy-api)
resource devOrdersApi 'Microsoft.ApiManagement/service/apis@2024-05-01' = {
  parent: apimDev
  name: 'orders-api'
  properties: {
    format: 'openapi+json'
    value: openApiJson
    path: 'orders'
    protocols: [
      'http'
      'https'
    ]
    subscriptionRequired: false
  }
}

resource devProductOrdersLink 'Microsoft.ApiManagement/service/products/apis@2024-05-01' = {
  parent: devProductOrders
  name: devOrdersApi.name
}

resource devOrdersApiPolicy 'Microsoft.ApiManagement/service/apis/policies@2024-05-01' = {
  parent: devOrdersApi
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: '''
<policies>
  <inbound>
    <base />
    <cors>
      <allowed-origins>
        <origin>*</origin>
      </allowed-origins>
    </cors>
    <set-header name="x-api-key" exists-action="override">
      <value>sk-inline-lab-test-secret-1234567890abcdef</value>
    </set-header>
    <set-backend-service backend-id="backend-pool-single" />
  </inbound>
  <backend>
    <base />
    <retry count="3" interval="1">
      <forward-request />
    </retry>
  </backend>
  <outbound>
    <set-header name="x-powered-by" exists-action="delete" />
    <set-header name="x-aspnet-version" exists-action="delete" />
    <set-header name="server" exists-action="delete" />
  </outbound>
  <on-error>
    <base />
  </on-error>
</policies>
'''
  }
  dependsOn: [
    devBackendPoolSingle
  ]
}

// Re-override x-powered-by on getOrder operation so APIM-SEC-024 fails on Dev while
// orders-api outbound still shares the 3-node inspectable block for APIM-OPS-003,
// and add operation-scoped validate-jwt on getOrder to prove backing-operation JWT
// does NOT satisfy APIM-AIGW-006 on the MCP server.
resource devOrdersGetOrderOp 'Microsoft.ApiManagement/service/apis/operations@2024-05-01' existing = {
  parent: devOrdersApi
  name: 'getOrder'
}

resource devOrdersGetOrderPolicy 'Microsoft.ApiManagement/service/apis/operations/policies@2024-05-01' = {
  parent: devOrdersGetOrderOp
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: '''
<policies>
  <inbound>
    <base />
    <validate-jwt header-name="Authorization" require-signed-tokens="true" require-expiration-time="true">
      <openid-config url="https://idp.contoso.example/.well-known/openid-configuration" />
      <audiences>
        <audience>api://orders-dev</audience>
      </audiences>
    </validate-jwt>
  </inbound>
  <backend>
    <base />
  </backend>
  <outbound>
    <base />
    <set-header name="x-powered-by" exists-action="override">
      <value>apim-dev</value>
    </set-header>
  </outbound>
  <on-error>
    <base />
  </on-error>
</policies>
'''
  }
}

// 1B. Dev Duplicate Unversioned REST API: orders-legacy-api
// Exercises:
// - APIM-OPS-002: fail (literal serviceUrl + set-backend-service base-url)
// - APIM-OPS-003: fail (identical 3-node outbound block as orders-api)
// - APIM-OPS-004: fail (same route 'orders-dup' as orders-legacy-v2 without apiVersionSetId)
// - APIM-SEC-018: fail (subscriptionRequired: true without validate-jwt/validate-azure-ad-token)
resource devOrdersDupA 'Microsoft.ApiManagement/service/apis@2024-05-01' = {
  parent: apimDev
  name: 'orders-dup-a'
  properties: {
    displayName: 'orders-dup-a'
    path: 'orders-dup'
    serviceUrl: restAppUrl
    protocols: [
      'https'
    ]
    subscriptionRequired: true
  }
}

resource devOrdersDupAOp 'Microsoft.ApiManagement/service/apis/operations@2024-05-01' = {
  parent: devOrdersDupA
  name: 'health'
  properties: {
    displayName: 'Health'
    method: 'GET'
    urlTemplate: '/healthz'
  }
}

resource devOrdersDupAPolicy 'Microsoft.ApiManagement/service/apis/policies@2024-05-01' = {
  parent: devOrdersDupA
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: $'''
<policies>
  <inbound>
    <base />
    <set-backend-service base-url="${restAppUrl}" />
  </inbound>
  <backend>
    <base />
  </backend>
  <outbound>
    <base />
    <set-header name="x-powered-by" exists-action="delete" />
    <set-header name="x-aspnet-version" exists-action="delete" />
    <set-header name="server" exists-action="delete" />
  </outbound>
  <on-error>
    <base />
  </on-error>
</policies>
'''
  }
}

resource devOrdersDupB 'Microsoft.ApiManagement/service/apis@2024-05-01' = {
  parent: apimDev
  name: 'orders-dup-b'
  properties: {
    displayName: 'orders-dup-b'
    path: 'orders-dup'
    serviceUrl: restAppUrl
    protocols: [
      'https'
    ]
    subscriptionRequired: true
  }
}

resource devOrdersDupBOp 'Microsoft.ApiManagement/service/apis/operations@2024-05-01' = {
  parent: devOrdersDupB
  name: 'health'
  properties: {
    displayName: 'Health'
    method: 'GET'
    urlTemplate: '/healthz'
  }
}

resource devOrdersDupBPolicy 'Microsoft.ApiManagement/service/apis/policies@2024-05-01' = {
  parent: devOrdersDupB
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: '''
<policies>
  <inbound>
    <base />
    <set-backend-service backend-id="backend-rest" />
  </inbound>
  <backend>
    <base />
  </backend>
  <outbound>
    <base />
  </outbound>
  <on-error>
    <base />
  </on-error>
</policies>
'''
  }
  dependsOn: [
    devBackendRest
  ]
}

// Note: Dev GraphQL API to exercise APIM-AIGW-005 fail (omits validate-graphql-request)
resource devGraphqlApi 'Microsoft.ApiManagement/service/apis@2024-05-01' = {
  parent: apimDev
  name: 'orders-graphql'
  properties: {
    displayName: 'Orders GraphQL (Dev)'
    path: 'graphql'
    type: 'graphql'
    serviceUrl: '${restAppUrl}/graphql'
    protocols: [
      'https'
    ]
    subscriptionRequired: true
  }
}

resource devGraphqlPolicy 'Microsoft.ApiManagement/service/apis/policies@2024-05-01' = {
  parent: devGraphqlApi
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: '''
<policies>
  <inbound>
    <base />
    <set-backend-service backend-id="backend-rest" />
  </inbound>
  <backend>
    <base />
  </backend>
  <outbound>
    <base />
  </outbound>
  <on-error>
    <base />
  </on-error>
</policies>
'''
  }
  dependsOn: [
    devBackendRest
  ]
}

// 1C. Dev AI Gateway API: foundry-ai
// Exercises:
// - APIM-AIGW-001: fail (no llm-token-limit)
// - APIM-AIGW-002: fail (no authentication-managed-identity; uses api-key header)
// - APIM-AIGW-003: fail (routes to single backend-foundry-primary, not a 2-member pool with 429 breaker)
// - APIM-AIGW-004: fail (no llm-emit-token-metric)
resource devFoundryAiApi 'Microsoft.ApiManagement/service/apis@2024-05-01' = {
  parent: apimDev
  name: 'foundry-ai'
  properties: {
    displayName: 'Foundry Responses API (Dev)'
    description: 'AI Gateway route to Microsoft Foundry OpenAI Responses endpoint (Dev negative profile)'
    path: 'ai'
    serviceUrl: foundryOpenAiEndpoint
    protocols: [
      'https'
    ]
    subscriptionRequired: true
  }
}

resource devFoundryResponsesOp 'Microsoft.ApiManagement/service/apis/operations@2024-05-01' = {
  parent: devFoundryAiApi
  name: 'createResponse'
  properties: {
    displayName: 'Create Response'
    method: 'POST'
    urlTemplate: '/v1/responses'
  }
}

resource devFoundryEmbeddingsOp 'Microsoft.ApiManagement/service/apis/operations@2024-05-01' = {
  parent: devFoundryAiApi
  name: 'createEmbedding'
  properties: {
    displayName: 'Create Embedding'
    method: 'POST'
    urlTemplate: '/deployments/text-embedding-3-small/embeddings'
  }
}

resource devFoundryAiPolicy 'Microsoft.ApiManagement/service/apis/policies@2024-05-01' = {
  parent: devFoundryAiApi
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: '''
<policies>
  <inbound>
    <base />
    <authentication-managed-identity resource="https://cognitiveservices.azure.com" />
    <set-header name="api-key" exists-action="override">
      <value>{{nv-dev-inline-secret}}</value>
    </set-header>
    <set-backend-service backend-id="backend-foundry-primary" />
  </inbound>
  <backend>
    <base />
  </backend>
  <outbound>
    <base />
  </outbound>
  <on-error>
    <base />
  </on-error>
</policies>
'''
  }
  dependsOn: [
    devBackendFoundry
    devNamedValueInlineSecret
  ]
}

// 1D. Dev Native MCP API #1: orders-mcp (REST-backed MCP server projecting Orders API operations)
// Exercises APIM-AIGW-006: fail (no inbound validate-jwt / validate-azure-ad-token on MCP API)
resource devOrdersMcpApi 'Microsoft.ApiManagement/service/apis@2025-09-01-preview' = {
  parent: apimDevPreview
  name: 'orders-mcp'
  properties: {
    displayName: 'Orders MCP Server (Dev)'
    description: 'Native APIM MCP server projecting Orders REST operations'
    type: 'mcp'
    path: 'orders-mcp'
    protocols: [
      'https'
    ]
    subscriptionRequired: false
    #disable-next-line BCP037
    mcpTools: [
      {
        name: 'listOrders'
        description: 'List recent customer orders'
        operationId: '${apimDev.id}/apis/${devOrdersApi.name}/operations/listOrders'
      }
      {
        name: 'getOrder'
        description: 'Get a single customer order by ID'
        operationId: '${apimDev.id}/apis/${devOrdersApi.name}/operations/getOrder'
      }
    ]
  }
}

resource devOrdersMcpPolicy 'Microsoft.ApiManagement/service/apis/policies@2025-09-01-preview' = {
  parent: devOrdersMcpApi
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: '''
<policies>
  <inbound>
    <base />
  </inbound>
  <backend>
    <base />
  </backend>
  <outbound>
    <base />
  </outbound>
  <on-error>
    <base />
  </on-error>
</policies>
'''
  }
}

// 1E. Dev Native MCP API #2: container-mcp (Passthrough MCP server to MCP Container App)
// Exercises APIM-AIGW-006: fail (no inbound OAuth validation at APIM gateway; acquires backend token via MI)
resource devContainerMcpApi 'Microsoft.ApiManagement/service/apis@2025-09-01-preview' = {
  parent: apimDevPreview
  name: 'container-mcp'
  properties: {
    displayName: 'Fulfillment Container MCP Server (Dev)'
    description: 'Passthrough MCP server proxying to Container App MCP server'
    type: 'mcp'
    path: 'container-mcp'
    protocols: [
      'https'
    ]
    subscriptionRequired: false
    #disable-next-line BCP037
    backendId: devBackendMcp.name
    mcpProperties: {
      transportType: 'streamable'
    }
  }
}

resource devContainerMcpPolicy 'Microsoft.ApiManagement/service/apis/policies@2025-09-01-preview' = {
  parent: devContainerMcpApi
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: $'''
<policies>
  <inbound>
    <base />
    <authentication-managed-identity resource="api://${mcpBackendAppClientId}" />
  </inbound>
  <backend>
    <base />
  </backend>
  <outbound>
    <base />
  </outbound>
  <on-error>
    <base />
  </on-error>
</policies>
'''
  }
}

// 1F. Dev Native A2A API: concierge-a2a (Agent2Agent API proxying to A2A Container App)
resource devConciergeA2aApi 'Microsoft.ApiManagement/service/apis@2025-09-01-preview' = {
  parent: apimDevPreview
  name: 'concierge-a2a'
  properties: {
    displayName: 'Order Concierge A2A Agent (Dev)'
    description: 'Native A2A agent API backed by Container App A2A service'
    type: 'a2a'
    path: 'concierge-a2a'
    serviceUrl: a2aAppUrl
    protocols: [
      'https'
    ]
    subscriptionRequired: false
    #disable-next-line BCP037
    backendId: devBackendA2a.name
    #disable-next-line BCP037
    agent: {
      id: 'order-concierge-dev'
    }
    #disable-next-line BCP089
    a2aProperties: {
      agentCardBackendUrl: '${a2aAppUrl}/.well-known/agent-card.json'
      agentCardPath: '/.well-known/agent-card.json'
    }
    #disable-next-line BCP037
    jsonRpcProperties: {
      backendUrl: a2aAppUrl
      path: '/'
    }
  }
}

resource devConciergeA2aOp 'Microsoft.ApiManagement/service/apis/operations@2025-09-01-preview' = {
  parent: devConciergeA2aApi
  name: 'jsonrpc'
  properties: {
    displayName: 'JSON-RPC Endpoint'
    method: 'POST'
    urlTemplate: '/'
  }
}

resource devConciergeA2aPolicy 'Microsoft.ApiManagement/service/apis/policies@2025-09-01-preview' = {
  parent: devConciergeA2aApi
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: $'''
<policies>
  <inbound>
    <base />
    <authentication-managed-identity resource="api://${a2aBackendAppClientId}" />
    <set-backend-service backend-id="backend-a2a" />
  </inbound>
  <backend>
    <base />
  </backend>
  <outbound>
    <base />
  </outbound>
  <on-error>
    <base />
  </on-error>
</policies>
'''
  }
}

// ============================================================================
// 2. BasicV2 APIM Subresources (Healthy Comparison Profile)
// ============================================================================

// APIM-SEC-022: pass (Developer portal requires sign-in and disables open signup)
resource bv2PortalConfig 'Microsoft.ApiManagement/service/portalconfigs@2024-05-01' = {
  parent: apimBv2
  name: 'default'
  properties: {
    enableBasicAuth: false
    signin: {
      require: true
    }
    signup: {
      termsOfService: {
        requireConsent: true
        text: 'Authorized enterprise users only.'
      }
    }
  }
}

resource bv2PortalSignup 'Microsoft.ApiManagement/service/portalsettings@2024-05-01' = {
  parent: apimBv2
  name: 'signup'
  properties: {
    enabled: false
    termsOfService: {
      enabled: true
      consentRequired: true
      text: 'Authorized enterprise users only.'
    }
  }
}

// APIM-SEC-012: pass (Secret named value backed by Key Vault via SystemAssigned MI)
resource bv2NamedValueKvSecret 'Microsoft.ApiManagement/service/namedValues@2024-05-01' = {
  parent: apimBv2
  name: 'nv-bv2-kv-secret'
  properties: {
    displayName: 'nv-bv2-kv-secret'
    secret: true
    keyVault: {
      secretIdentifier: keyVaultSecretUri
    }
  }
}

// APIM-SEC-013: pass (Non-secret named value stored as plain value, not in Key Vault)
resource bv2NamedValueEnv 'Microsoft.ApiManagement/service/namedValues@2024-05-01' = {
  parent: apimBv2
  name: 'nv-bv2-env'
  properties: {
    displayName: 'nv-bv2-env'
    secret: false
    value: 'bv2-healthy-profile'
  }
}

// APIM-PERF-002 & APIM-AIGW-004: pass (Application Insights logger with 50% sampling and 0 body bytes)
resource bv2AppInsightsLogger 'Microsoft.ApiManagement/service/loggers@2024-05-01' = {
  parent: apimBv2
  name: 'appinsights'
  properties: {
    loggerType: 'applicationInsights'
    description: 'Application Insights logger for BasicV2 APIM'
    resourceId: appInsightsResourceId
    credentials: {
      instrumentationKey: appInsightsInstrumentationKey
    }
  }
}

resource bv2AppInsightsDiagnostic 'Microsoft.ApiManagement/service/diagnostics@2024-05-01' = {
  parent: apimBv2
  name: 'applicationinsights'
  properties: {
    loggerId: bv2AppInsightsLogger.id
    alwaysLog: 'allErrors'
    sampling: {
      samplingType: 'fixed'
      percentage: 50
    }
    frontend: {
      request: {
        body: {
          bytes: 0
        }
      }
      response: {
        body: {
          bytes: 0
        }
      }
    }
    backend: {
      request: {
        body: {
          bytes: 0
        }
      }
      response: {
        body: {
          bytes: 0
        }
      }
    }
  }
}

// Product on BasicV2 (linked to APIs -> no empty products)
resource bv2ProductEnterprise 'Microsoft.ApiManagement/service/products@2024-05-01' = {
  parent: apimBv2
  name: 'prod-enterprise'
  properties: {
    displayName: 'Enterprise APIs Product (BasicV2)'
    description: 'Scoped product for BasicV2 APIs'
    subscriptionRequired: true
    approvalRequired: false
    state: 'published'
  }
}

// APIM-SEC-016: pass (Product-scoped subscription)
resource bv2ProductSubscription 'Microsoft.ApiManagement/service/subscriptions@2024-05-01' = {
  parent: apimBv2
  name: 'sub-bv2-enterprise'
  properties: {
    displayName: 'BasicV2 Enterprise Product Subscription'
    scope: '${apimBv2.id}/products/${bv2ProductEnterprise.name}'
    state: 'active'
  }
}

// Backends on BasicV2:
// APIM-SEC-021: pass (validateCertificateChain: true, validateCertificateName: true)
// APIM-REL-007: pass (circuitBreaker rules on every non-pool backend)
// APIM-AIGW-003: pass (2-member pool across Foundry primary + secondary with 429 Retry-After breakers)
var standardCircuitBreakerRules = [
  {
    name: 'cb-429-5xx'
    failureCondition: {
      count: 3
      interval: 'PT1M'
      statusCodeRanges: [
        {
          min: 429
          max: 429
        }
        {
          min: 500
          max: 599
        }
      ]
    }
    tripDuration: 'PT1M'
    acceptRetryAfter: true
  }
]

resource bv2BackendRest 'Microsoft.ApiManagement/service/backends@2024-05-01' = {
  parent: apimBv2
  name: 'backend-rest'
  properties: {
    url: restAppUrl
    protocol: 'http'
    tls: {
      validateCertificateChain: true
      validateCertificateName: true
    }
    circuitBreaker: {
      rules: standardCircuitBreakerRules
    }
  }
}

resource bv2BackendMcp 'Microsoft.ApiManagement/service/backends@2024-05-01' = {
  parent: apimBv2
  name: 'backend-mcp'
  properties: {
    url: '${mcpAppUrl}/mcp'
    protocol: 'http'
    tls: {
      validateCertificateChain: true
      validateCertificateName: true
    }
    circuitBreaker: {
      rules: standardCircuitBreakerRules
    }
  }
}

resource bv2BackendA2a 'Microsoft.ApiManagement/service/backends@2024-05-01' = {
  parent: apimBv2
  name: 'backend-a2a'
  properties: {
    url: a2aAppUrl
    protocol: 'http'
    tls: {
      validateCertificateChain: true
      validateCertificateName: true
    }
    circuitBreaker: {
      rules: standardCircuitBreakerRules
    }
  }
}

resource bv2BackendFoundryPrimary 'Microsoft.ApiManagement/service/backends@2024-05-01' = {
  parent: apimBv2
  name: 'backend-foundry-primary'
  properties: {
    url: foundryOpenAiEndpoint
    protocol: 'http'
    tls: {
      validateCertificateChain: true
      validateCertificateName: true
    }
    circuitBreaker: {
      rules: standardCircuitBreakerRules
    }
  }
}

resource bv2BackendFoundrySecondary 'Microsoft.ApiManagement/service/backends@2024-05-01' = {
  parent: apimBv2
  name: 'backend-foundry-secondary'
  properties: {
    url: foundryOpenAiEndpoint
    protocol: 'http'
    tls: {
      validateCertificateChain: true
      validateCertificateName: true
    }
    circuitBreaker: {
      rules: standardCircuitBreakerRules
    }
  }
}

resource bv2BackendFoundryPool 'Microsoft.ApiManagement/service/backends@2024-05-01' = {
  parent: apimBv2
  name: 'backend-foundry-pool'
  properties: {
    type: 'Pool'
    pool: {
      services: [
        {
          id: '/subscriptions/${subscription().subscriptionId}/resourceGroups/${resourceGroup().name}/providers/Microsoft.ApiManagement/service/${apimBv2Name}/backends/${bv2BackendFoundryPrimary.name}'
          priority: 1
          weight: 50
        }
        {
          id: '/subscriptions/${subscription().subscriptionId}/resourceGroups/${resourceGroup().name}/providers/Microsoft.ApiManagement/service/${apimBv2Name}/backends/${bv2BackendFoundrySecondary.name}'
          priority: 1
          weight: 50
        }
      ]
    }
  }
}

// Policy Fragments on BasicV2 (APIM-OPS-003 pass: shared reusable fragments)
resource bv2FragInboundCommon 'Microsoft.ApiManagement/service/policyFragments@2024-05-01' = {
  parent: apimBv2
  name: 'frag-inbound-common'
  properties: {
    description: 'Shared inbound CORS, Entra JWT validation, and rate limiting'
    format: 'rawxml'
    value: $'''
<fragment>
  <cors allow-credentials="false">
    <allowed-origins>
      <origin>https://portal.contoso.example</origin>
    </allowed-origins>
    <allowed-methods>
      <method>GET</method>
      <method>POST</method>
    </allowed-methods>
  </cors>
  <validate-azure-ad-token tenant-id="${tenantId}" header-name="Authorization" failed-validation-httpcode="401">
    <audiences>
      <audience>api://${apimGatewayAppClientId}</audience>
      <audience>${apimGatewayAppClientId}</audience>
    </audiences>
    <client-application-ids>
      <application-id>${smokeClientAppClientId}</application-id>
    </client-application-ids>
  </validate-azure-ad-token>
  <rate-limit-by-key calls="120" renewal-period="60" counter-key="@(context.Request.IpAddress)" />
</fragment>
'''
  }
}

resource bv2FragOutboundHardening 'Microsoft.ApiManagement/service/policyFragments@2024-05-01' = {
  parent: apimBv2
  name: 'frag-outbound-hardening'
  properties: {
    description: 'Shared outbound implementation header removal'
    format: 'rawxml'
    value: '''
<fragment>
  <set-header name="x-powered-by" exists-action="delete" />
  <set-header name="x-aspnet-version" exists-action="delete" />
</fragment>
'''
  }
}

// Global policy on BasicV2:
// - Includes shared fragments for inbound auth/CORS/rate-limit and outbound header deletion
// - Configures <forward-request timeout="30" /> in backend (APIM-REL-010 pass)
// - Configures <trace> in on-error (APIM-REL-009 pass)
resource bv2GlobalPolicy 'Microsoft.ApiManagement/service/policies@2024-05-01' = {
  parent: apimBv2
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: '''
<policies>
  <inbound>
    <include-fragment fragment-id="frag-inbound-common" />
  </inbound>
  <backend>
    <forward-request timeout="30" />
  </backend>
  <outbound>
    <include-fragment fragment-id="frag-outbound-hardening" />
  </outbound>
  <on-error>
    <trace source="apim-bv2-global-error" severity="error">
      <message>Gateway execution error recorded</message>
    </trace>
  </on-error>
</policies>
'''
  }
  dependsOn: [
    bv2FragInboundCommon
    bv2FragOutboundHardening
  ]
}

// API Version Set on BasicV2 (APIM-OPS-004 pass)
resource bv2OrdersVersionSet 'Microsoft.ApiManagement/service/apiVersionSets@2024-05-01' = {
  parent: apimBv2
  name: 'vs-orders'
  properties: {
    displayName: 'Orders API Version Set'
    versioningScheme: 'Segment'
  }
}

// 2A. BasicV2 REST API: orders-api
// Uses dynamic serviceUrl via Named Value so serviceUrl is not flagged as a literal hardcoded URL (APIM-OPS-002 pass)
resource bv2NamedValueRestUrl 'Microsoft.ApiManagement/service/namedValues@2024-05-01' = {
  parent: apimBv2
  name: 'nv-bv2-rest-url'
  properties: {
    displayName: 'nv-bv2-rest-url'
    secret: false
    value: restAppUrl
  }
}

resource bv2OrdersApi 'Microsoft.ApiManagement/service/apis@2024-05-01' = {
  parent: apimBv2
  name: 'orders-api'
  properties: {
    format: 'openapi+json'
    value: replace(openApiJson, restAppUrl, '{{nv-bv2-rest-url}}')
    path: 'orders'
    protocols: [
      'https'
    ]
    subscriptionRequired: true
    apiVersion: 'v1'
    apiVersionSetId: bv2OrdersVersionSet.id
  }
  dependsOn: [
    bv2NamedValueRestUrl
  ]
}

resource bv2ProductOrdersLink 'Microsoft.ApiManagement/service/products/apis@2024-05-01' = {
  parent: bv2ProductEnterprise
  name: bv2OrdersApi.name
}

// Override serviceUrl via policy backend entity + validate-content + cache-lookup/store
resource bv2OrdersApiPolicy 'Microsoft.ApiManagement/service/apis/policies@2024-05-01' = {
  parent: bv2OrdersApi
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: '''
<policies>
  <inbound>
    <base />
    <validate-content unspecified-content-type-action="prevent" max-size="65536" size-exceeded-action="prevent" />
    <cache-lookup vary-by-developer="false" vary-by-developer-groups="false" downstream-caching-type="none" />
    <set-backend-service backend-id="backend-rest" />
  </inbound>
  <backend>
    <base />
  </backend>
  <outbound>
    <base />
    <cache-store duration="60" />
  </outbound>
  <on-error>
    <base />
  </on-error>
</policies>
'''
  }
  dependsOn: [
    bv2BackendRest
    bv2GlobalPolicy
  ]
}

// 2B. BasicV2 GraphQL API: orders-graphql (APIM-AIGW-005 pass)
resource bv2GraphqlVersionSet 'Microsoft.ApiManagement/service/apiVersionSets@2024-05-01' = {
  parent: apimBv2
  name: 'vs-graphql'
  properties: {
    displayName: 'Orders GraphQL Version Set'
    versioningScheme: 'Segment'
  }
}

resource bv2GraphqlApi 'Microsoft.ApiManagement/service/apis@2024-05-01' = {
  parent: apimBv2
  name: 'orders-graphql'
  properties: {
    displayName: 'Orders GraphQL API (BasicV2)'
    description: 'Healthy GraphQL API with size and depth validation'
    path: 'graphql'
    type: 'graphql'
    serviceUrl: '{{nv-bv2-rest-url}}/graphql'
    protocols: [
      'https'
    ]
    subscriptionRequired: true
    apiVersion: 'v1'
    apiVersionSetId: bv2GraphqlVersionSet.id
  }
  dependsOn: [
    bv2NamedValueRestUrl
  ]
}

resource bv2ProductGraphqlLink 'Microsoft.ApiManagement/service/products/apis@2024-05-01' = {
  parent: bv2ProductEnterprise
  name: bv2GraphqlApi.name
}

resource bv2GraphqlPolicy 'Microsoft.ApiManagement/service/apis/policies@2024-05-01' = {
  parent: bv2GraphqlApi
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: '''
<policies>
  <inbound>
    <base />
    <validate-graphql-request max-size="65536" max-depth="6" />
    <set-backend-service backend-id="backend-rest" />
  </inbound>
  <backend>
    <base />
  </backend>
  <outbound>
    <base />
  </outbound>
  <on-error>
    <base />
  </on-error>
</policies>
'''
  }
  dependsOn: [
    bv2BackendRest
    bv2GlobalPolicy
  ]
}

// 2C. BasicV2 AI Gateway API: foundry-ai
// Exercises:
// - APIM-AIGW-001: pass (llm-token-limit with tokens-per-minute, estimate-prompt-tokens, counter-key)
// - APIM-AIGW-002: pass (authentication-managed-identity for https://cognitiveservices.azure.com, no api-key header)
// - APIM-AIGW-003: pass (routes to 2-member backend-foundry-pool with 429 Retry-After breakers)
// - APIM-AIGW-004: pass (llm-emit-token-metric with namespace + Application Insights logger)
// - APIM-PERF-003: pass (validate-content max-size=65536 size-exceeded-action=prevent on POST operations)
resource bv2AiVersionSet 'Microsoft.ApiManagement/service/apiVersionSets@2024-05-01' = {
  parent: apimBv2
  name: 'vs-ai'
  properties: {
    displayName: 'Foundry AI API Version Set'
    versioningScheme: 'Segment'
  }
}

resource bv2FoundryAiApi 'Microsoft.ApiManagement/service/apis@2024-05-01' = {
  parent: apimBv2
  name: 'foundry-ai'
  properties: {
    displayName: 'Foundry Responses API (BasicV2)'
    description: 'Healthy AI Gateway route to Microsoft Foundry OpenAI Responses and Embeddings endpoints'
    path: 'ai'
    protocols: [
      'https'
    ]
    subscriptionRequired: true
    apiVersion: 'v1'
    apiVersionSetId: bv2AiVersionSet.id
  }
}

resource bv2ProductAiLink 'Microsoft.ApiManagement/service/products/apis@2024-05-01' = {
  parent: bv2ProductEnterprise
  name: bv2FoundryAiApi.name
}

resource bv2FoundryResponsesOp 'Microsoft.ApiManagement/service/apis/operations@2024-05-01' = {
  parent: bv2FoundryAiApi
  name: 'createResponse'
  properties: {
    displayName: 'Create Response'
    method: 'POST'
    urlTemplate: '/v1/responses'
  }
}

resource bv2FoundryEmbeddingsOp 'Microsoft.ApiManagement/service/apis/operations@2024-05-01' = {
  parent: bv2FoundryAiApi
  name: 'createEmbedding'
  properties: {
    displayName: 'Create Embedding'
    method: 'POST'
    urlTemplate: '/deployments/text-embedding-3-small/embeddings'
  }
}

resource bv2FoundryAiPolicy 'Microsoft.ApiManagement/service/apis/policies@2024-05-01' = {
  parent: bv2FoundryAiApi
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: '''
<policies>
  <inbound>
    <base />
    <validate-content unspecified-content-type-action="prevent" max-size="65536" size-exceeded-action="prevent" />
    <llm-token-limit counter-key="@(context.Request.IpAddress)" tokens-per-minute="10000" estimate-prompt-tokens="true" />
    <llm-emit-token-metric namespace="foundry-ai">
      <dimension name="API ID" value="@(context.Api.Id)" />
    </llm-emit-token-metric>
    <authentication-managed-identity resource="https://cognitiveservices.azure.com" />
    <set-backend-service backend-id="backend-foundry-pool" />
  </inbound>
  <backend>
    <base />
  </backend>
  <outbound>
    <base />
  </outbound>
  <on-error>
    <base />
  </on-error>
</policies>
'''
  }
  dependsOn: [
    bv2BackendFoundryPool
    bv2AppInsightsLogger
    bv2GlobalPolicy
  ]
}

// 2D. BasicV2 Native MCP API #1: orders-mcp (REST-backed MCP server)
// Exercises APIM-AIGW-006: pass (inherits frag-inbound-common with validate-azure-ad-token and no auth-mutating policy)
resource bv2OrdersMcpApi 'Microsoft.ApiManagement/service/apis@2025-09-01-preview' = {
  parent: apimBv2Preview
  name: 'orders-mcp'
  properties: {
    displayName: 'Orders MCP Server (BasicV2)'
    description: 'Healthy REST-backed MCP server secured with Entra OAuth token validation'
    type: 'mcp'
    path: 'orders-mcp'
    protocols: [
      'https'
    ]
    subscriptionRequired: false
    #disable-next-line BCP037
    mcpTools: [
      {
        name: 'listOrders'
        description: 'List recent customer orders'
        operationId: '${apimBv2.id}/apis/${bv2OrdersApi.name}/operations/listOrders'
      }
      {
        name: 'getOrder'
        description: 'Get a single customer order by ID'
        operationId: '${apimBv2.id}/apis/${bv2OrdersApi.name}/operations/getOrder'
      }
    ]
  }
}

resource bv2OrdersMcpPolicy 'Microsoft.ApiManagement/service/apis/policies@2025-09-01-preview' = {
  parent: bv2OrdersMcpApi
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: '''
<policies>
  <inbound>
    <base />
    <set-backend-service backend-id="backend-rest" />
  </inbound>
  <backend>
    <base />
  </backend>
  <outbound>
    <base />
  </outbound>
  <on-error>
    <base />
  </on-error>
</policies>
'''
  }
  dependsOn: [
    bv2BackendRest
    bv2GlobalPolicy
  ]
}

// 2E. BasicV2 Native MCP API #2: container-mcp (Passthrough MCP server to MCP Container App)
// Exercises APIM-AIGW-006: pass (validates caller Entra JWT at APIM via inherited frag-inbound-common,
// and forwards caller Bearer token directly to the MCP Container App without mutating headers)
resource bv2ContainerMcpApi 'Microsoft.ApiManagement/service/apis@2025-09-01-preview' = {
  parent: apimBv2Preview
  name: 'container-mcp'
  properties: {
    displayName: 'Fulfillment Container MCP Server (BasicV2)'
    description: 'Healthy passthrough MCP server secured with Entra OAuth token validation'
    type: 'mcp'
    path: 'container-mcp'
    protocols: [
      'https'
    ]
    subscriptionRequired: false
    #disable-next-line BCP037
    backendId: bv2BackendMcp.name
    mcpProperties: {
      transportType: 'streamable'
    }
  }
}

resource bv2ContainerMcpPolicy 'Microsoft.ApiManagement/service/apis/policies@2025-09-01-preview' = {
  parent: bv2ContainerMcpApi
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: '''
<policies>
  <inbound>
    <base />
    <set-backend-service backend-id="backend-mcp" />
  </inbound>
  <backend>
    <base />
  </backend>
  <outbound>
    <base />
  </outbound>
  <on-error>
    <base />
  </on-error>
</policies>
'''
  }
  dependsOn: [
    bv2GlobalPolicy
  ]
}

// 2F. BasicV2 Native A2A API: concierge-a2a (Agent2Agent API proxying to A2A Container App)
resource bv2ConciergeA2aApi 'Microsoft.ApiManagement/service/apis@2025-09-01-preview' = {
  parent: apimBv2Preview
  name: 'concierge-a2a'
  properties: {
    displayName: 'Order Concierge A2A Agent (BasicV2)'
    description: 'Healthy native A2A agent API secured with Entra OAuth token validation'
    type: 'a2a'
    path: 'concierge-a2a'
    protocols: [
      'https'
    ]
    subscriptionRequired: false
    #disable-next-line BCP037
    backendId: bv2BackendA2a.name
    #disable-next-line BCP037
    agent: {
      id: 'order-concierge-bv2'
    }
    #disable-next-line BCP089
    a2aProperties: {
      agentCardBackendUrl: '{{nv-bv2-a2a-url}}/.well-known/agent-card.json'
      agentCardPath: '/.well-known/agent-card.json'
    }
    #disable-next-line BCP037
    jsonRpcProperties: {
      backendUrl: '{{nv-bv2-a2a-url}}'
      path: '/'
    }
  }
  dependsOn: [
    bv2NamedValueA2aUrl
  ]
}

resource bv2NamedValueA2aUrl 'Microsoft.ApiManagement/service/namedValues@2024-05-01' = {
  parent: apimBv2
  name: 'nv-bv2-a2a-url'
  properties: {
    displayName: 'nv-bv2-a2a-url'
    secret: false
    value: a2aAppUrl
  }
}

resource bv2ConciergeA2aOp 'Microsoft.ApiManagement/service/apis/operations@2025-09-01-preview' = {
  parent: bv2ConciergeA2aApi
  name: 'jsonrpc'
  properties: {
    displayName: 'JSON-RPC Endpoint'
    method: 'POST'
    urlTemplate: '/'
  }
}

resource bv2ConciergeA2aPolicy 'Microsoft.ApiManagement/service/apis/policies@2025-09-01-preview' = {
  parent: bv2ConciergeA2aApi
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: '''
<policies>
  <inbound>
    <base />
    <set-backend-service backend-id="backend-a2a" />
  </inbound>
  <backend>
    <base />
  </backend>
  <outbound>
    <base />
  </outbound>
  <on-error>
    <base />
  </on-error>
</policies>
'''
  }
  dependsOn: [
    bv2GlobalPolicy
  ]
}

output devOrdersApiId string = devOrdersApi.id
output bv2OrdersApiId string = bv2OrdersApi.id
output bv2EnterpriseSubscriptionName string = bv2ProductSubscription.name
