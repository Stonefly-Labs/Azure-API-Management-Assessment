import asyncio
import hashlib
import json
from unittest.mock import AsyncMock

import httpx
import pytest
from azure.core.credentials import AccessToken
from pydantic import ValidationError
from typer.testing import CliRunner

from apim_assess.analyzer.ai_narrator import NarrativeError, enrich, public_summary
from apim_assess.analyzer.engine import ITERATION_5_IDS, analyze, mcsb_coverage, mcsb_score, scores
from apim_assess.artifacts import digest
from apim_assess.cli import app
from apim_assess.collector.apim_core import collect
from apim_assess.collector.client import ArmReader, AzureReadError
from apim_assess.collector.sanitizer import ai_backend_kind, reference_id, sanitize_policy
from apim_assess.collector.subresources import _metadata
from apim_assess.collector.upstream import aliases, host, restricted_rules, waf_configuration
from apim_assess.collector.upstream_afd import collect_afd
from apim_assess.collector.upstream_appgw import collect_appgw
from apim_assess.config import AiEnrichment, AssessmentConfig, UpstreamModule
from apim_assess.models.findings import Narrative, PortfolioAssessment, RuleSettings, Waiver
from apim_assess.models.policy import (
    MODERN_METADATA_FIELDS,
    CollectionCoverage,
    Inventory,
    ResourceMetadata,
    SubResource,
)
from apim_assess.models.snapshot import Snapshot
from apim_assess.models.upstream import Upstream, UpstreamProbe, UpstreamRoute
from apim_assess.reporting.generator import render, roadmap

FDID = "00000000-0000-0000-0000-000000000022"
SECRET = "SYNTHETIC_PRIVATE_SENTINEL_NOT_A_REAL_SECRET"
TOKEN = (
    '<llm-token-limit counter-key="@(context.Subscription.Id)" '
    'tokens-per-minute="1000" estimate-prompt-tokens="false"/>'
)
IDENTITY = '<authentication-managed-identity resource="https://cognitiveservices.azure.com"/>'
METRIC = '<llm-emit-token-metric namespace="synthetic"/>'


def add(snapshot, path, kind, **metadata):
    instance = snapshot.instances[0]
    item = SubResource(
        resource_id=instance.resource_id + "/" + path,
        path=path,
        name=path.rsplit("/", 1)[-1],
        kind=kind,
        metadata=ResourceMetadata(**metadata),
    )
    instance.inventory.resources.append(item)
    return item


def put(snapshot, inbound="", *, path="", backend=""):
    instance = snapshot.instances[0]
    base = "<base/>" if path else ""
    instance.inventory.policies[path] = sanitize_policy(
        instance.resource_id + "/" + path + "/policies/policy",
        f"<policies><inbound>{base}{inbound}</inbound>"
        f"<backend>{base}{backend}</backend><outbound>{base}</outbound>"
        f"<on-error>{base}</on-error></policies>",
    )


@pytest.fixture
def modern(full_snapshot):
    full_snapshot.schema_version = "1.4"
    instance = full_snapshot.instances[0]
    instance.virtual_network_type = "External"
    instance.public_network_access = "Enabled"
    instance.identity_type = "SystemAssigned"
    instance.inventory = Inventory(
        collections={
            name: CollectionCoverage(status="complete")
            for name in (
                "apis",
                "products",
                "workspaces",
                "backends",
                "loggers",
                "policyFragments",
                "apis/model/operations",
            )
        }
    )
    add(
        full_snapshot,
        "apis/model",
        "api",
        api_type="http",
        protocols=["https"],
        service_url_kind="literal",
        ai_backend="azure_openai",
        api_key_credential=False,
        subscription_required=True,
    )
    put(full_snapshot, backend="<forward-request/>")
    put(full_snapshot, path="apis/model")
    return full_snapshot


def finding(snapshot, identifier, settings=None):
    return next(item for item in analyze(snapshot, settings).findings if item.rule.id == identifier)


@pytest.mark.parametrize(
    ("policy", "outcome"),
    [
        ("", "fail"),
        (TOKEN, "pass"),
        (TOKEN.replace("1000", "@(1000)"), "unknown"),
        (TOKEN.replace('estimate-prompt-tokens="false"', ""), "unknown"),
        ('<choose><when condition="@(true)">' + TOKEN + "</when></choose>", "unknown"),
        (
            '<llm-token-limit counter-key="shared" token-quota="4000" '
            'token-quota-period="Daily" estimate-prompt-tokens="true"/>',
            "pass",
        ),
    ],
)
def test_llm_token_decisions_use_catalog_and_effective_paths(modern, policy, outcome):
    put(modern, policy, path="apis/model")
    assert finding(modern, "APIM-AIGW-001").result.outcome == outcome


def test_ai_inheritance_fragments_and_final_routing(modern):
    instance = modern.instances[0]
    put(modern, TOKEN)
    assert finding(modern, "APIM-AIGW-001").result.outcome == "pass"
    instance.inventory.policies["apis/model"] = sanitize_policy(
        "synthetic", "<policies><inbound/><backend><base/></backend></policies>"
    )
    assert finding(modern, "APIM-AIGW-001").result.outcome == "fail"
    fragment = reference_id("budget")
    instance.inventory.fragments["policyFragments/" + fragment] = sanitize_policy(
        "synthetic-fragment", "<fragment>" + TOKEN + "</fragment>", fragment=True
    )
    put(modern, '<include-fragment fragment-id="budget"/>', path="apis/model")
    assert finding(modern, "APIM-AIGW-001").result.outcome == "pass"
    put(modern, '<set-backend-service base-url="https://model.openai.azure.com"/>')
    instance.inventory.resources[0].metadata.ai_backend = "other"
    put(modern, TOKEN, path="apis/model")
    assert finding(modern, "APIM-AIGW-001").result.outcome == "pass"
    put(
        modern, '<set-backend-service base-url="https://example.test/ordinary"/>', path="apis/model"
    )
    assert finding(modern, "APIM-AIGW-001").result.outcome == "not_applicable"


@pytest.mark.parametrize(
    ("policy", "outcome"),
    [
        ("", "fail"),
        (IDENTITY, "pass"),
        (IDENTITY.replace("/>", ' ignore-error="true"/>'), "unknown"),
        (IDENTITY + '<set-header name="Authorization" exists-action="delete"/>', "unknown"),
        (
            IDENTITY + '<set-query-parameter name="api-key"><value>synthetic</value>'
            "</set-query-parameter>",
            "unknown",
        ),
        (
            IDENTITY.replace("https://cognitiveservices.azure.com", "https://example.test"),
            "unknown",
        ),
        (
            IDENTITY + '<set-header name="Authorization"><value>private</value></set-header>',
            "unknown",
        ),
        ('<choose><when condition="@(true)">' + IDENTITY + "</when></choose>", "unknown"),
    ],
)
def test_azure_openai_identity_is_not_caller_auth_or_a_tag(modern, policy, outcome):
    put(modern, policy, path="apis/model")
    assert finding(modern, "APIM-AIGW-002").result.outcome == outcome
    assert finding(modern, "APIM-SEC-018").result.outcome != "pass"


def pool(modern):
    a = add(
        modern,
        "backends/a",
        "backend",
        ai_backend="azure_openai",
        backend_pool=False,
        breaker_429=True,
        breaker_retry_after=True,
        api_key_credential=False,
    )
    b = add(
        modern,
        "backends/b",
        "backend",
        ai_backend="azure_openai",
        backend_pool=False,
        breaker_429=True,
        breaker_retry_after=True,
        api_key_credential=False,
    )
    p = add(
        modern,
        "backends/pool",
        "backend",
        backend_pool=True,
        pool_member_count=2,
        pool_member_references=[
            reference_id(a.resource_id.casefold()),
            reference_id(b.resource_id.casefold()),
        ],
    )
    put(modern, '<set-backend-service backend-id="pool"/>', path="apis/model")
    return a, b, p


def test_ai_pools_require_actual_routed_distinct_members_and_429_breakers(modern):
    assert finding(modern, "APIM-AIGW-003").result.outcome == "fail"
    a, b, p = pool(modern)
    assert finding(modern, "APIM-AIGW-003").result.outcome == "pass"
    b.metadata.breaker_429 = False
    assert finding(modern, "APIM-AIGW-003").result.outcome == "fail"
    b.metadata.breaker_429 = None
    assert finding(modern, "APIM-AIGW-003").result.outcome == "unknown"
    p.metadata.pool_member_references = [reference_id(a.resource_id.casefold())] * 2
    assert finding(modern, "APIM-AIGW-003").result.outcome == "fail"
    p.metadata.pool_member_references = [reference_id(p.resource_id.casefold())]
    assert finding(modern, "APIM-AIGW-001").result.outcome == "unknown"


def test_ai_mixed_pool_and_literal_routes_do_not_pass(modern):
    pool(modern)
    put(
        modern,
        '<choose><when condition="@(true)"><set-backend-service backend-id="pool"/></when>'
        '<otherwise><set-backend-service base-url="https://another.openai.azure.com"/>'
        "</otherwise></choose>",
        path="apis/model",
    )
    assert finding(modern, "APIM-AIGW-003").result.outcome == "fail"


def test_static_backend_key_does_not_pass_managed_identity(modern):
    backend = add(
        modern,
        "backends/a",
        "backend",
        ai_backend="azure_openai",
        backend_pool=False,
        api_key_credential=True,
    )
    put(modern, IDENTITY + '<set-backend-service backend-id="a"/>', path="apis/model")
    assert finding(modern, "APIM-AIGW-002").result.outcome == "fail"
    backend.metadata.api_key_credential = False
    assert finding(modern, "APIM-AIGW-002").result.outcome == "pass"


def test_ai_metrics_logger_unknowns_consumption_and_waivers(modern):
    assert finding(modern, "APIM-AIGW-004").result.outcome == "fail"
    put(modern, METRIC, path="apis/model")
    assert finding(modern, "APIM-AIGW-004").result.outcome == "unknown"
    add(modern, "loggers/appinsights", "logger", application_insights=True)
    assert finding(modern, "APIM-AIGW-004").result.outcome == "pass"
    instance = modern.instances[0]
    instance.sku.name = "Consumption"
    assert finding(modern, "APIM-AIGW-001").result.outcome == "unsupported"
    assert finding(modern, "APIM-AIGW-003").result.outcome == "unsupported"
    instance.environment = "non-prod"
    settings = RuleSettings(waivers=[Waiver(rule_id="APIM-AIGW-001", justification="Approved")])
    item = finding(modern, "APIM-AIGW-001", settings)
    assert item.severity == "Medium" and item.waiver_justification == "Approved"
    instance.inventory.collections["backends"].status = "partial"
    assert finding(modern, "APIM-AIGW-004").result.outcome == "unknown"
    instance.inventory.resources[0].metadata.ai_backend = "llm"
    assert finding(modern, "APIM-AIGW-002").result.outcome in {"unknown", "not_applicable"}


def test_ai_identity_cannot_pass_missing_identity_or_static_key_on_pool_member(modern):
    a, _, _ = pool(modern)
    put(modern, IDENTITY + '<set-backend-service backend-id="pool"/>', path="apis/model")
    assert finding(modern, "APIM-AIGW-002").result.outcome == "pass"
    a.metadata.api_key_credential = True
    assert finding(modern, "APIM-AIGW-002").result.outcome == "fail"
    a.metadata.api_key_credential = False
    modern.instances[0].identity_type = None
    assert finding(modern, "APIM-AIGW-002").result.outcome == "unknown"


def test_ai_identity_cannot_pass_url_embedded_credentials(modern):
    api = modern.instances[0].inventory.resources[0]
    api.metadata = _metadata(
        "api",
        {
            "type": "http",
            "protocols": ["https"],
            "serviceUrl": "https://synthetic.openai.azure.com/?%61pi-key=" + SECRET,
        },
    )
    put(modern, IDENTITY, path="apis/model")
    assert finding(modern, "APIM-AIGW-002").result.outcome == "fail"
    assert SECRET not in modern.model_dump_json()
    api.metadata.api_key_credential = False
    put(
        modern,
        IDENTITY + '<set-backend-service base-url="https://synthetic.openai.azure.com'
        "/?api-key=" + SECRET + '"/>',
        path="apis/model",
    )
    assert finding(modern, "APIM-AIGW-002").result.outcome == "unknown"
    assert SECRET not in modern.model_dump_json()
    backend = _metadata("backend", {"url": "https://synthetic.openai.azure.com/?api-key=" + SECRET})
    assert backend.api_key_credential is True


@pytest.mark.parametrize(
    ("policy", "outcome"),
    [
        ("", "fail"),
        ('<validate-graphql-request max-size="102400" max-depth="6"/>', "pass"),
        ('<validate-graphql-request max-size="102400"/>', "pass"),
        ('<validate-graphql-request max-size="@(100)" max-depth="6"/>', "unknown"),
        ('<validate-graphql-request max-size="102400" max-depth="0"/>', "unknown"),
    ],
)
def test_graphql_uses_resolved_api_policy_not_http_coverage(modern, policy, outcome):
    modern.instances[0].inventory.resources[0].metadata.api_type = "graphql"
    put(modern, policy, path="apis/model")
    assert finding(modern, "APIM-AIGW-005").result.outcome == outcome
    assert finding(modern, "APIM-SEC-018").result.outcome == "unsupported"


@pytest.mark.parametrize(
    ("url", "kind"),
    [
        ("https://synthetic.openai.azure.com/openai", "azure_openai"),
        ("https://api.openai.com/v1", "llm"),
        ("https://synthetic.services.ai.azure.com/models", "llm"),
        ("https://api.anthropic.com/v1", "llm"),
        ("https://example.test/openai.azure.com", "other"),
        ("https://example.test/?api-key=" + SECRET, "other"),
        ("{{backend}}", "unknown"),
        (None, "unknown"),
    ],
)
def test_endpoint_classification_is_secret_free_and_host_bound(url, kind):
    assert ai_backend_kind(url) == kind


def test_safe_backend_projection_records_real_pool_and_breaker_metadata(modern):
    raw = {
        "type": "Pool",
        "url": "https://synthetic.openai.azure.com",
        "pool": {"services": [{"id": modern.instances[0].resource_id + "/backends/a"}]},
        "credentials": {"header": {"api-key": [SECRET]}},
        "circuitBreaker": {
            "rules": [
                {
                    "failureCondition": {
                        "count": 1,
                        "interval": "PT1M",
                        "statusCodeRanges": [{"min": 429, "max": 429}],
                    },
                    "tripDuration": "PT1M",
                    "acceptRetryAfter": True,
                }
            ]
        },
    }
    metadata = _metadata("backend", raw)
    assert metadata.breaker_429 and metadata.breaker_retry_after
    assert metadata.api_key_credential and metadata.pool_member_count == 1
    assert SECRET not in metadata.model_dump_json()
    assert "synthetic.openai.azure.com" not in metadata.model_dump_json()
    raw["circuitBreaker"]["rules"][0]["failureCondition"]["interval"] = "PT0M"
    assert not _metadata("backend", raw).breaker_429


def reader_run(handler, work):
    async def run():
        credential = AsyncMock()
        credential.get_token.return_value = AccessToken("synthetic-token", 9999999999)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await work(ArmReader(credential, client))

    return asyncio.run(run())


def paths(modern):
    prefix = modern.instances[0].resource_id.partition("/providers/")[0]
    return {
        "afd": prefix + "/providers/Microsoft.Cdn/profiles/edge",
        "appgw": prefix + "/providers/Microsoft.Network/applicationGateways/gateway",
        "waf": prefix + "/providers/Microsoft.Network/frontDoorWebApplicationFirewallPolicies/waf",
        "agwaf": prefix
        + "/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/waf",
        "subnet": prefix + "/providers/Microsoft.Network/virtualNetworks/vnet/subnets/apim",
        "nsg": prefix + "/providers/Microsoft.Network/networkSecurityGroups/nsg",
    }


def waf(identifier, *, afd=True, mode="Prevention"):
    return {
        "id": identifier,
        "properties": {
            "policySettings": {"enabledState" if afd else "state": "Enabled", "mode": mode},
            "managedRules": {
                "managedRuleSets": [
                    {"ruleSetType": "Microsoft_DefaultRuleSet", "ruleSetVersion": "2.1"}
                ]
            },
            "customRules": {"rules": []} if afd else [],
            "private": SECRET,
        },
    }


def afd_bodies(modern):
    p = paths(modern)
    identifier = p["afd"]
    group = identifier + "/originGroups/group"
    endpoint = identifier + "/afdEndpoints/endpoint"
    return {
        identifier: {
            "id": identifier,
            "sku": {"name": "Premium_AzureFrontDoor"},
            "properties": {"frontDoorId": FDID},
        },
        identifier + "/originGroups": {
            "value": [
                {
                    "id": group,
                    "properties": {
                        "healthProbeSettings": {
                            "protocol": "Https",
                            "requestType": "HEAD",
                            "path": "/health",
                        }
                    },
                }
            ]
        },
        group + "/origins": {
            "value": [
                {
                    "id": group + "/origins/apim",
                    "properties": {"enabledState": "Enabled", "hostName": "gateway.example.test"},
                }
            ]
        },
        identifier + "/afdEndpoints": {
            "value": [
                {
                    "id": endpoint,
                    "properties": {"enabledState": "Enabled"},
                }
            ]
        },
        endpoint + "/routes": {
            "value": [
                {
                    "id": endpoint + "/routes/api",
                    "properties": {
                        "enabledState": "Enabled",
                        "originGroup": {"id": group},
                        "customDomains": [],
                        "linkToDefaultDomain": "Enabled",
                        "forwardingProtocol": "HttpsOnly",
                    },
                }
            ]
        },
        identifier + "/securityPolicies": {
            "value": [
                {
                    "id": identifier + "/securityPolicies/default",
                    "properties": {
                        "parameters": {
                            "type": "WebApplicationFirewall",
                            "wafPolicy": {"id": p["waf"]},
                            "associations": [
                                {"domains": [{"id": endpoint}], "patternsToMatch": ["/*"]}
                            ],
                        }
                    },
                }
            ]
        },
        p["waf"]: waf(p["waf"]),
    }


def raw_service(modern):
    return {
        "properties": {
            "gatewayUrl": "https://gateway.example.test",
            "additionalLocations": [],
            "hostnameConfigurations": [],
            "privateIPAddresses": [],
            "publicIPAddresses": [],
        }
    }


def collect_edge(modern, bodies, *, afd=True, auto=False):
    instance = modern.instances[0]
    warnings = []
    requests = []
    identifier = paths(modern)["afd" if afd else "appgw"]
    module = UpstreamModule(enabled=True, auto_discover=auto, resource_ids=[identifier])

    def handler(request):
        requests.append(request)
        assert request.method == "GET"
        body = bodies.get(request.url.path)
        if body is None:
            return httpx.Response(403, json={"error": {"message": SECRET}})
        return httpx.Response(200, json=body)

    async def work(reader):
        return await (collect_afd if afd else collect_appgw)(
            reader,
            instance,
            raw_service(modern),
            module,
            [instance.resource_id.split("/")[2]],
            warnings,
        )

    return reader_run(handler, work), warnings, requests


def test_afd_association_projection_and_waf_rule_are_read_only_and_sanitized(modern):
    probe, warnings, requests = collect_edge(modern, afd_bodies(modern))
    assert probe.status == "complete" and len(probe.routes) == 1
    assert probe.routes[0].waf.prevention and probe.routes[0].https_only
    assert not warnings and requests
    assert SECRET not in probe.model_dump_json()
    assert "gateway.example.test" not in probe.model_dump_json()
    modern.instances[0].upstream = Upstream(afd=probe, appgw=UpstreamProbe(status="disabled"))
    assert finding(modern, "APIM-SEC-004").result.outcome == "pass"
    probe.routes[0].waf.prevention = False
    assert finding(modern, "APIM-SEC-004").result.outcome == "fail"
    probe.routes[0].waf.prevention = None
    assert finding(modern, "APIM-SEC-004").result.outcome == "unknown"


def test_afd_other_domain_or_partial_path_does_not_establish_protection(modern):
    bodies = afd_bodies(modern)
    policy = bodies[paths(modern)["afd"] + "/securityPolicies"]["value"][0]
    policy["properties"]["parameters"]["associations"][0]["patternsToMatch"] = ["/not-all/*"]
    probe, _, _ = collect_edge(modern, bodies)
    assert probe.routes[0].waf is None
    modern.instances[0].upstream = Upstream(afd=probe, appgw=UpstreamProbe(status="disabled"))
    assert finding(modern, "APIM-SEC-004").result.outcome == "unknown"
    policy["properties"]["parameters"]["associations"][0]["patternsToMatch"] = ["/*"]
    policy["properties"]["parameters"]["associations"][0]["domains"] = [{"id": "unrelated"}]
    probe, _, _ = collect_edge(modern, bodies)
    assert probe.routes[0].waf.enabled is False


def test_upstream_permission_gaps_no_match_and_disabled_are_not_passes(modern):
    probe, warnings, _ = collect_edge(modern, {})
    assert probe.status == "partial" and warnings
    assert SECRET not in "".join(w.model_dump_json() for w in warnings)
    modern.instances[0].upstream = Upstream(afd=probe, appgw=UpstreamProbe(status="disabled"))
    assert finding(modern, "APIM-SEC-004").result.outcome == "unknown"
    bodies = afd_bodies(modern)
    group = paths(modern)["afd"] + "/originGroups/group/origins"
    bodies[group]["value"][0]["properties"]["hostName"] = "not-the-gateway.example.test"
    probe, _, _ = collect_edge(modern, bodies)
    assert probe.status == "complete" and not probe.routes

    async def disabled(reader):
        return await collect_afd(reader, modern.instances[0], None, UpstreamModule(), [], [])

    assert (
        reader_run(lambda r: pytest.fail("disabled module requested Azure"), disabled).status
        == "disabled"
    )


def appgw_bodies(modern):
    p = paths(modern)
    identifier = p["appgw"]
    pool_id = identifier + "/backendAddressPools/apim"
    setting = identifier + "/backendHttpSettingsCollection/https"
    listener = identifier + "/httpListeners/https"
    return {
        identifier: {
            "id": identifier,
            "properties": {
                "operationalState": "Running",
                "backendAddressPools": [
                    {
                        "id": pool_id,
                        "properties": {
                            "backendAddresses": [{"fqdn": "gateway.example.test"}],
                        },
                    }
                ],
                "httpListeners": [{"id": listener, "properties": {"protocol": "Https"}}],
                "backendHttpSettingsCollection": [
                    {"id": setting, "properties": {"protocol": "Https"}}
                ],
                "probes": [],
                "urlPathMaps": [],
                "gatewayIPConfigurations": [],
                "firewallPolicy": {"id": p["agwaf"]},
                "requestRoutingRules": [
                    {
                        "id": identifier + "/requestRoutingRules/basic",
                        "properties": {
                            "ruleType": "Basic",
                            "httpListener": {"id": listener},
                            "backendAddressPool": {"id": pool_id},
                            "backendHttpSettings": {"id": setting},
                        },
                    }
                ],
            },
        },
        p["agwaf"]: waf(p["agwaf"], afd=False),
    }


def test_application_gateway_effective_listener_policy_overrides_global(modern):
    bodies = appgw_bodies(modern)
    identifier = paths(modern)["appgw"]
    props = bodies[identifier]["properties"]
    override = paths(modern)["agwaf"] + "-override"
    props["httpListeners"][0]["properties"]["firewallPolicy"] = {"id": override}
    bodies[override] = waf(override, afd=False, mode="Detection")
    probe, warnings, _ = collect_edge(modern, bodies, afd=False)
    assert probe.status == "complete" and not warnings
    assert len(probe.routes) == 1 and probe.routes[0].waf.prevention is False
    assert probe.routes[0].https_only
    assert SECRET not in probe.model_dump_json()
    modern.instances[0].upstream = Upstream(appgw=probe, afd=UpstreamProbe(status="disabled"))
    assert finding(modern, "APIM-SEC-004").result.outcome == "fail"


def test_application_gateway_path_policy_overrides_listener_and_default(modern):
    bodies = appgw_bodies(modern)
    identifier = paths(modern)["appgw"]
    props = bodies[identifier]["properties"]
    rule = props["requestRoutingRules"][0]["properties"]
    pathmap = identifier + "/urlPathMaps/map"
    override = paths(modern)["agwaf"] + "-path"
    props["urlPathMaps"] = [
        {
            "id": pathmap,
            "properties": {
                "defaultBackendAddressPool": rule["backendAddressPool"],
                "defaultBackendHttpSettings": rule["backendHttpSettings"],
                "pathRules": [
                    {
                        "id": pathmap + "/pathRules/api",
                        "properties": {
                            "paths": ["/api/*"],
                            "backendAddressPool": rule["backendAddressPool"],
                            "backendHttpSettings": rule["backendHttpSettings"],
                            "firewallPolicy": {"id": override},
                        },
                    }
                ],
            },
        }
    ]
    rule["ruleType"] = "PathBasedRouting"
    rule["urlPathMap"] = {"id": pathmap}
    bodies[override] = waf(override, afd=False, mode="Detection")
    probe, warnings, _ = collect_edge(modern, bodies, afd=False)
    assert probe.status == "complete" and not warnings and len(probe.routes) == 2
    assert {route.waf.prevention for route in probe.routes} == {True, False}


def test_waf_exclusions_and_unknown_rewrite_routing_do_not_pass(modern):
    body = waf(paths(modern)["waf"])
    body["properties"]["managedRules"]["managedRuleSets"][0]["exclusions"] = [{"private": SECRET}]
    assert waf_configuration(body, afd=True).managed_rules is None
    bodies = afd_bodies(modern)
    route = next(value["value"][0] for key, value in bodies.items() if key.endswith("/routes"))
    route["properties"]["ruleSets"] = [{"id": paths(modern)["afd"] + "/ruleSets/rewrite"}]
    probe, warnings, _ = collect_edge(modern, bodies)
    assert probe.status == "partial" and warnings
    modern.instances[0].upstream = Upstream(afd=probe, appgw=UpstreamProbe(status="disabled"))
    assert finding(modern, "APIM-SEC-004").result.outcome == "unknown"


def test_ipv6_origin_matching_is_exact_not_just_the_first_component():
    assert host("2001:db8::1") != host("2001:db8::2")
    assert host("[2001:db8::1]") == host("https://[2001:db8::1]")
    assert host("https://[2001:0db8::1]") == host("2001:db8::1")


def test_nullable_live_matching_lists_preserve_gateway_and_regional_aliases():
    body = {
        "properties": {
            "gatewayUrl": "https://gateway.example.test",
            "additionalLocations": None,
            "publicIPAddresses": [],
            "privateIPAddresses": None,
            "gatewayRegionalUrl": "https://regional.example.test",
            "hostnameConfigurations": [],
        }
    }
    assert aliases(body) == {"gateway.example.test", "regional.example.test"}


def nsg_rule(priority, source, access="Allow", port="*", **extra):
    return {
        "properties": {
            "priority": priority,
            "direction": "Inbound",
            "protocol": "Tcp",
            "sourceAddressPrefix": source,
            "sourcePortRange": "*",
            "destinationAddressPrefix": "*",
            "destinationPortRange": port,
            "access": access,
            **extra,
        }
    }


@pytest.mark.parametrize(
    ("rules", "outcome"),
    [
        ([nsg_rule(100, "AzureFrontDoor.Backend", port="443"), nsg_rule(200, "*", "Deny")], True),
        ([nsg_rule(100, "*", port="443"), nsg_rule(200, "*", "Deny")], False),
        ([nsg_rule(100, "AzureFrontDoor.Backend", port="443")], None),
        ([nsg_rule(100, "*", "Deny"), nsg_rule(200, "AzureFrontDoor.Backend", port="443")], None),
        ([nsg_rule(100, "AzureFrontDoor.Backend", port="443", sourcePortRange="80")], None),
        ([nsg_rule(100, "AzureFrontDoor.Backend"), nsg_rule(100, "*", "Deny")], None),
        (
            [
                nsg_rule(100, "*", port="invalid"),
                nsg_rule(200, "AzureFrontDoor.Backend"),
                nsg_rule(300, "*", "Deny"),
            ],
            None,
        ),
        (
            [
                nsg_rule(100, "AzureFrontDoor.Backend"),
                nsg_rule(200, "*", "Deny"),
                nsg_rule(100, "*", direction="Outbound"),
            ],
            True,
        ),
    ],
)
def test_origin_network_restriction_honors_priority_and_both_web_ports(rules, outcome):
    assert restricted_rules(rules, set(), afd=True) is outcome


def test_afd_lockdown_requires_matching_effective_header_and_network(modern):
    route = UpstreamRoute(
        reference="synthetic",
        provider="afd",
        front_door_id=reference_id(FDID),
        network_restricted=True,
    )
    modern.instances[0].upstream = Upstream(
        afd=UpstreamProbe(status="complete", routes=[route]), appgw=UpstreamProbe(status="disabled")
    )
    assert finding(modern, "APIM-SEC-005").result.outcome == "fail"
    header = (
        '<check-header name="X-Azure-FDID" failed-check-httpcode="403">'
        f"<value>{FDID}</value></check-header>"
    )
    put(modern, header)
    assert finding(modern, "APIM-SEC-005").result.outcome == "pass"
    assert FDID not in modern.model_dump_json()
    route.network_restricted = False
    assert finding(modern, "APIM-SEC-005").result.outcome == "fail"
    route.network_restricted = None
    assert finding(modern, "APIM-SEC-005").result.outcome == "unknown"
    route.network_restricted = True
    put(modern, header.replace(FDID, "{{fdid}}"))
    assert finding(modern, "APIM-SEC-005").result.outcome == "unknown"
    modern.instances[0].public_network_access = "Disabled"
    assert finding(modern, "APIM-SEC-005").result.outcome == "not_applicable"


def test_unproven_origin_alternatives_and_header_rewrites_do_not_become_passes(modern):
    route = UpstreamRoute(
        reference="synthetic",
        provider="afd",
        front_door_id=reference_id(FDID),
        network_restricted=False,
    )
    modern.instances[0].upstream = Upstream(
        afd=UpstreamProbe(status="complete", routes=[route]), appgw=UpstreamProbe(status="disabled")
    )
    put(modern, '<ip-filter action="allow"><address>192.0.2.1</address></ip-filter>')
    assert finding(modern, "APIM-SEC-005").result.outcome == "unknown"
    route.network_restricted = True
    put(
        modern,
        '<set-header name="X-Azure-FDID"><value>synthetic</value></set-header>'
        f'<check-header name="X-Azure-FDID" failed-check-httpcode="403"><value>{FDID}'
        "</value></check-header>",
    )
    assert finding(modern, "APIM-SEC-005").result.outcome == "unknown"


def test_resource_graph_queries_only_requested_scope_and_pages(modern):
    ids = paths(modern)
    requests = []

    def handler(request):
        assert request.method == "POST"
        assert request.url.path == "/providers/Microsoft.ResourceGraph/resources"
        payload = json.loads(request.content)
        assert payload["subscriptions"] == [modern.instances[0].resource_id.split("/")[2]]
        assert "project id" in payload["query"]
        requests.append(payload)
        return httpx.Response(
            200,
            json={
                "data": [{"id": ids["afd"]}],
                **({"$skipToken": "synthetic-next"} if len(requests) == 1 else {}),
            },
        )

    async def work(reader):
        return [
            identifier
            async for identifier in reader.graph_resources(
                [modern.instances[0].resource_id.split("/")[2]], "microsoft.cdn/profiles"
            )
        ]

    assert reader_run(handler, work) == [ids["afd"], ids["afd"]]
    assert requests[1]["options"]["$skipToken"] == "synthetic-next"


def test_graph_out_of_scope_response_is_rejected(modern):
    async def work(reader):
        return [
            identifier
            async for identifier in reader.graph_resources(
                [modern.instances[0].resource_id.split("/")[2]], "microsoft.cdn/profiles"
            )
        ]

    bad = paths(modern)["afd"].replace(
        modern.instances[0].resource_id.split("/")[2], "00000000-0000-0000-0000-000000000099"
    )
    with pytest.raises(AzureReadError, match="OUT_OF_SCOPE"):
        reader_run(lambda r: httpx.Response(200, json={"data": [{"id": bad}]}), work)


def test_schema_13_digest_and_historical_findings_remain_reportable(modern):
    instance = modern.instances[0]
    for item in instance.inventory.resources:
        for field in MODERN_METADATA_FIELDS:
            setattr(item.metadata, field, None)
    modern.schema_version = "1.3"
    payload = modern.model_dump_json(
        exclude={
            "instances": {
                "__all__": {
                    "upstream": True,
                    "inventory": {"resources": {"__all__": {"metadata": MODERN_METADATA_FIELDS}}},
                }
            }
        }
    )
    assert digest(modern) == hashlib.sha256(payload.encode()).hexdigest()
    assessment = analyze(modern)
    assessment.schema_version = "1.3"
    assessment.findings = [
        item for item in assessment.findings if item.rule.id not in ITERATION_5_IDS
    ]
    assessment.pillar_scores = scores(assessment.findings)
    assessment.mcsb_coverage = mcsb_coverage(assessment.findings)
    assessment.mcsb_assessed_score = mcsb_score(assessment.mcsb_coverage)
    assert "Iteration 4" in render(modern, assessment)
    instance.upstream = Upstream()
    with pytest.raises(ValidationError, match="require snapshot schema 1.4"):
        Snapshot.model_validate(modern.model_dump())


def test_roadmap_excludes_waivers_unknowns_and_is_stable(modern):
    assessment = analyze(
        modern,
        RuleSettings(
            waivers=[
                Waiver(rule_id="APIM-AIGW-001", justification="Approved"),
            ]
        ),
    )
    selected = [item for _, items in roadmap(assessment.findings) for item in items]
    assert selected and all(
        item.result.outcome == "fail" and not item.waiver_justification for item in selected
    )
    assert not any(item.rule.id == "APIM-AIGW-001" for item in selected)
    assert roadmap(assessment.findings) == roadmap(list(reversed(assessment.findings)))
    assessment.narrative = Narrative(status="complete", text='<img src=x onerror="bad">')
    html = render(modern, assessment)
    assert "30 / 60 / 90-day planning roadmap" in html
    assert "Upstream WAF &amp; AI gateway" in html
    assert '<img src=x onerror="bad">' not in html and "&lt;img" in html
    assert ".innerHTML" not in html


def test_ai_enrichment_transmits_only_aggregates_and_cannot_change_assessment(modern, monkeypatch):
    assessment = analyze(
        modern,
        RuleSettings(
            waivers=[
                Waiver(rule_id="APIM-AIGW-001", justification=SECRET),
            ]
        ),
    )
    before = assessment.model_dump_json()
    requests = []
    monkeypatch.setenv("APIM_ASSESS_AI_KEY", "synthetic-test-key")
    config = AiEnrichment(endpoint="https://synthetic.openai.azure.com", deployment="gpt-4o-mini")

    def handler(request):
        requests.append(request)
        assert request.url.params["api-version"] == "2024-10-21"
        payload = request.content.decode()
        assert SECRET not in payload and modern.instances[0].resource_id not in payload
        assert (
            "apis/model" not in payload
            and "policies" not in json.loads(payload)["messages"][1]["content"]
        )
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {
                            "content": '{"summary":"Review confirmed risks and coverage gaps."}'
                        },
                    }
                ]
            },
        )

    async def work():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await enrich(assessment, config, client)

    narrative = asyncio.run(work())
    assert narrative.status == "complete" and len(requests) == 1
    assert assessment.model_dump_json() == before
    assert SECRET not in json.dumps(public_summary(assessment))


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(429, json={"error": SECRET}),
        httpx.Response(200, json={"choices": []}),
        httpx.Response(200, json={"choices": [None]}),
        httpx.Response(
            200, json={"choices": [{"finish_reason": "length", "message": {"content": SECRET}}]}
        ),
        httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": '{"summary":"ok","findings":[]}'},
                    }
                ]
            },
        ),
    ],
)
def test_ai_provider_errors_are_safe_not_success_shaped(modern, monkeypatch, response):
    monkeypatch.setenv("APIM_ASSESS_AI_KEY", "synthetic-test-key")

    async def work():
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: response)) as client:
            return await enrich(
                analyze(modern),
                AiEnrichment(
                    endpoint="https://synthetic.openai.azure.com",
                    deployment="synthetic",
                ),
                client,
            )

    with pytest.raises(NarrativeError) as error:
        asyncio.run(work())
    assert SECRET not in str(error.value)


def test_cli_enrichment_failure_saves_deterministic_artifacts_and_exits_two(
    modern, tmp_path, monkeypatch
):
    async def collected(config):
        return modern

    async def failed(assessment, config):
        raise NarrativeError("HTTP_429")

    monkeypatch.setattr("apim_assess.cli.collect", collected)
    monkeypatch.setattr("apim_assess.cli.enrich", failed)
    config = tmp_path / "settings.yaml"
    config.write_text(
        "ai_enrichment:\n  endpoint: https://synthetic.openai.azure.com\n  deployment: synthetic\n"
    )
    result = CliRunner().invoke(
        app,
        [
            "assess",
            "--resource-id",
            modern.instances[0].resource_id,
            "--config",
            str(config),
            "--enrich-ai",
            "--output-dir",
            str(tmp_path / "out"),
        ],
    )
    assert result.exit_code == 2 and "AI enrichment failed" in result.output
    saved = PortfolioAssessment.model_validate_json(
        (tmp_path / "out" / "findings.json").read_text()
    )
    assert saved.narrative.status == "unavailable"
    assert saved.findings == analyze(modern).findings
    assert (tmp_path / "out" / "apim-assessment-report.html").exists()


def test_successful_enrichment_replays_report_offline_and_config_alone_never_calls(
    modern,
    tmp_path,
    monkeypatch,
):
    snapshot_path = tmp_path / "snapshot.json"
    snapshot_path.write_text(modern.model_dump_json())
    config = tmp_path / "settings.yaml"
    config.write_text(
        "ai_enrichment:\n  endpoint: https://synthetic.openai.azure.com\n  deployment: synthetic\n"
    )
    calls = []

    async def narrated(assessment, settings):
        calls.append(settings)
        return Narrative(status="complete", text="Review confirmed failures and missing coverage.")

    monkeypatch.setattr("apim_assess.cli.enrich", narrated)
    runner = CliRunner()
    findings = tmp_path / "findings.json"
    arguments = [
        "analyze",
        "--snapshot",
        str(snapshot_path),
        "--config",
        str(config),
        "--output",
        str(findings),
    ]
    assert runner.invoke(app, arguments).exit_code == 0 and not calls
    result = runner.invoke(app, [*arguments, "--enrich-ai"])
    assert result.exit_code == 0, result.output
    saved = PortfolioAssessment.model_validate_json(findings.read_text())
    assert len(calls) == 1 and saved.findings == analyze(modern).findings

    def forbidden(*args, **kwargs):
        pytest.fail("Offline report contacted a remote service")

    monkeypatch.setattr("httpx.AsyncClient", forbidden)
    monkeypatch.setattr("apim_assess.analyzer.ai_narrator.DefaultAzureCredential", forbidden)
    html = tmp_path / "report.html"
    result = runner.invoke(
        app,
        [
            "report",
            "--snapshot",
            str(snapshot_path),
            "--findings",
            str(findings),
            "--output",
            str(html),
        ],
    )
    assert result.exit_code == 0, result.output
    assert html.read_text() == render(modern, saved)


def test_mocked_multi_instance_modern_assess_and_offline_replay(modern, tmp_path, monkeypatch):
    identifiers = [modern.instances[0].resource_id, modern.instances[0].resource_id + "-two"]
    bodies = afd_bodies(modern)
    requests = []

    def handler(request):
        requests.append(request)
        assert request.method == "GET"
        path = request.url.path
        if path in bodies:
            return httpx.Response(200, json=bodies[path])
        identifier = next(
            (value for value in identifiers if path == value or path.startswith(value + "/")), None
        )
        if identifier is None:
            pytest.fail("Unscoped request")
        tail = path[len(identifier) :].lstrip("/")
        if not tail:
            return httpx.Response(
                200,
                json={
                    "id": identifier,
                    "location": "eastus",
                    "sku": {"name": "Premium", "capacity": 2},
                    "zones": ["1", "2"],
                    "identity": {"type": "SystemAssigned"},
                    "properties": {
                        **raw_service(modern)["properties"],
                        "virtualNetworkType": "None",
                        "privateEndpointConnections": [],
                        "publicNetworkAccess": "Enabled",
                    },
                },
            )
        if tail == "apis":
            return httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "id": identifier + "/apis/model",
                            "properties": {
                                "type": "http",
                                "protocols": ["https"],
                                "subscriptionRequired": True,
                                "serviceUrl": "https://synthetic.openai.azure.com",
                                "private": SECRET,
                            },
                        }
                    ]
                },
            )
        if tail == "loggers":
            return httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "id": identifier + "/loggers/ai",
                            "properties": {
                                "loggerType": "applicationInsights",
                                "credentials": {"private": SECRET},
                            },
                        }
                    ]
                },
            )
        if tail == "policies/policy":
            return httpx.Response(
                200,
                json={
                    "properties": {
                        "value": "<policies><inbound>"
                        + TOKEN
                        + IDENTITY
                        + METRIC
                        + "</inbound><backend><forward-request/></backend><outbound/><on-error/>"
                        + "</policies>",
                    }
                },
            )
        if tail.endswith("/policies/policy"):
            return httpx.Response(404)
        if tail in {"tenant/access", "portalsettings/signup"}:
            return httpx.Response(200, json={"properties": {"enabled": False}})
        if tail == "portalconfigs/default":
            return httpx.Response(200, json={"properties": {"signin": {"require": True}}})
        if tail == "apis/model":
            return httpx.Response(
                200,
                json={
                    "id": path,
                    "properties": {
                        "type": "http",
                        "protocols": ["https"],
                        "subscriptionRequired": True,
                        "serviceUrl": "https://synthetic.openai.azure.com",
                    },
                },
            )
        return httpx.Response(200, json={"value": []})

    async def collected(config):
        credential = AsyncMock()
        credential.get_token.return_value = AccessToken("synthetic-token", 9999999999)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await collect(config, ArmReader(credential, client))

    monkeypatch.setattr("apim_assess.cli.collect", collected)
    config = tmp_path / "settings.yaml"
    config.write_text(
        json.dumps(
            {
                "modules": {
                    "metrics": False,
                    "networking": False,
                    "defender_policy": False,
                    "afd": {
                        "enabled": True,
                        "auto_discover": False,
                        "resource_ids": [paths(modern)["afd"]],
                    },
                },
            }
        )
    )
    directory = tmp_path / "composed"
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "assess",
            "--resource-id",
            identifiers[0],
            "--resource-id",
            identifiers[1],
            "--config",
            str(config),
            "--output-dir",
            str(directory),
        ],
    )
    assert result.exit_code == 0, result.output
    saved = Snapshot.model_validate_json((directory / "snapshot.json").read_text())
    assessment = PortfolioAssessment.model_validate_json((directory / "findings.json").read_text())
    assert len(saved.instances) == 2 and len(assessment.findings) == 108
    assert SECRET not in saved.model_dump_json()
    for identifier in ("APIM-AIGW-001", "APIM-AIGW-002", "APIM-AIGW-004", "APIM-SEC-004"):
        assert all(
            item.result.outcome == "pass"
            for item in assessment.findings
            if item.rule.id == identifier
        ), [
            (item.rule.id, item.result)
            for item in assessment.findings
            if item.rule.id == identifier
        ]
    assert requests

    def forbidden(*args, **kwargs):
        pytest.fail("Offline pipeline used network or credentials")

    monkeypatch.setattr("httpx.AsyncClient", forbidden)
    monkeypatch.setattr("apim_assess.collector.apim_core.DefaultAzureCredential", forbidden)
    replay = tmp_path / "replay.json"
    result = runner.invoke(
        app,
        [
            "analyze",
            "--snapshot",
            str(directory / "snapshot.json"),
            "--output",
            str(replay),
        ],
    )
    assert result.exit_code == 0, result.output
    assert replay.read_bytes() == (directory / "findings.json").read_bytes()
    replay_html = tmp_path / "replay.html"
    result = runner.invoke(
        app,
        [
            "report",
            "--snapshot",
            str(directory / "snapshot.json"),
            "--findings",
            str(replay),
            "--output",
            str(replay_html),
        ],
    )
    assert result.exit_code == 0, result.output
    assert replay_html.read_bytes() == (directory / "apim-assessment-report.html").read_bytes()


@pytest.mark.parametrize(
    "data",
    [
        {"modules": {"afd": {"enabled": True, "auto_discover": False}}},
        {"modules": {"appgw": {"resource_ids": ["https://example.test"]}}},
        {"ai_enrichment": {"endpoint": "https://user:secret@example.test", "deployment": "model"}},
        {"ai_enrichment": {"endpoint": "https://example.test", "deployment": "model"}},
        {"ai_enrichment": {"endpoint": "http://synthetic.openai.azure.com", "deployment": "model"}},
    ],
)
def test_invalid_upstream_and_enrichment_configuration_is_rejected(data):
    with pytest.raises(ValidationError):
        AssessmentConfig.model_validate(data)
