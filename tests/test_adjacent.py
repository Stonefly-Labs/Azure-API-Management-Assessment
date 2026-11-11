import asyncio
import hashlib
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import httpx
import pytest
from azure.core.credentials import AccessToken
from pydantic import ValidationError
from typer.testing import CliRunner

from apim_assess.analyzer.engine import ITERATION_4_IDS, ITERATION_5_IDS, analyze, scores
from apim_assess.cli import app
from apim_assess.collector.apim_core import SAFE_CUSTOM_PROPERTIES, collect
from apim_assess.collector.client import ArmReader
from apim_assess.collector.governance import collect_governance
from apim_assess.collector.networking import collect_networking
from apim_assess.collector.sanitizer import reference_id
from apim_assess.collector.telemetry import collect_logs
from apim_assess.config import AssessmentConfig, Telemetry
from apim_assess.models.adjacent import (
    AutoscaleSetting,
    DiagnosticSetting,
    Governance,
    LogAggregate,
    LogAnalytics,
    Networking,
    NsgRule,
    PolicyState,
    ScaleProfile,
    SubnetEvidence,
    WorkspaceLogs,
)
from apim_assess.models.findings import PortfolioAssessment, RuleSettings, Thresholds, Waiver
from apim_assess.models.policy import (
    MODERN_METADATA_FIELDS,
    CollectionCoverage,
    Inventory,
    ResourceMetadata,
    SubResource,
)
from apim_assess.models.snapshot import Sku, Snapshot
from apim_assess.reporting.generator import render

SECRET = "PRIVATE_PAYLOAD_SENTINEL_NOT_A_REAL_SECRET"
WORKSPACE_GUID = "00000000-0000-0000-0000-000000000099"


@pytest.fixture
def adjacent_snapshot(full_snapshot):
    full_snapshot.schema_version = "1.3"
    instance = full_snapshot.instances[0]
    instance.inventory = Inventory(
        collections={
            name: CollectionCoverage(status="complete") for name in ("apis", "workspaces")
        },
        resources=[
            SubResource(
                resource_id=instance.resource_id + "/apis/orders",
                path="apis/orders",
                kind="api",
                name="orders",
                metadata=ResourceMetadata(api_type="http", protocols=["https"]),
            )
        ],
    )
    instance.virtual_network_type = "Internal"
    instance.governance = Governance()
    return full_snapshot


def finding(snapshot, identifier, settings=None):
    return next(item for item in analyze(snapshot, settings).findings if item.rule.id == identifier)


def rule(priority, access="Allow", sources=None, ports=None, destination="subnet"):
    return NsgRule(
        priority=priority,
        access=access,
        protocol="Tcp",
        sources=sources or ["any"],
        source_ports_any=True,
        destination=destination,
        ports=ports or [(0, 65535)],
    )


def network(snapshot, rules, **changes):
    snapshot.instances[0].networking = Networking(
        status="complete",
        subnets_status="complete",
        subnets=[
            SubnetEvidence(
                reference="subnet", status="complete", nsg_attached=True, rules=rules, **changes
            )
        ],
    )


def prerequisites():
    return [
        rule(100, sources=["apim"], ports=[(3443, 3443)]),
        rule(110, sources=["load_balancer"], ports=[(6390, 6390)]),
    ]


def test_nsg_priority_and_classic_prerequisites(adjacent_snapshot):
    network(adjacent_snapshot, prerequisites() + [rule(200, access="Deny")])
    assert finding(adjacent_snapshot, "APIM-SEC-003").result.outcome == "pass"
    rules = prerequisites() + [
        rule(120, ports=[(443, 443)]),
        rule(200, access="Deny"),
    ]
    network(adjacent_snapshot, rules)
    assert finding(adjacent_snapshot, "APIM-SEC-003").result.outcome == "fail"
    rules.insert(2, rule(115, access="Deny", ports=[(443, 443)]))
    network(adjacent_snapshot, rules)
    assert finding(adjacent_snapshot, "APIM-SEC-003").result.outcome == "pass"
    network(adjacent_snapshot, [rule(100, access="Deny"), *prerequisites()])
    assert finding(adjacent_snapshot, "APIM-SEC-003").result.outcome == "fail"


def test_nsg_specific_exceptions_and_collection_gaps_stay_unknown(adjacent_snapshot):
    network(
        adjacent_snapshot,
        prerequisites()
        + [
            rule(120, access="Deny", destination="specific"),
            rule(130),
        ],
    )
    assert finding(adjacent_snapshot, "APIM-SEC-003").result.outcome == "unknown"
    network(adjacent_snapshot, prerequisites() + [rule(200, access="Deny")])
    adjacent_snapshot.instances[0].networking.subnets_status = "partial"
    assert finding(adjacent_snapshot, "APIM-SEC-003").result.outcome == "unknown"
    adjacent_snapshot.instances[0].networking.subnets[0].nsg_attached = False
    assert finding(adjacent_snapshot, "APIM-SEC-003").result.outcome == "fail"


@pytest.mark.parametrize(
    ("sources", "destination"),
    [(["specific"], "subnet"), (["internet"], "specific")],
)
def test_specific_allow_before_broad_deny_cannot_establish_isolation(
    adjacent_snapshot, sources, destination
):
    network(
        adjacent_snapshot,
        prerequisites()
        + [
            rule(120, sources=sources, destination=destination, ports=[(443, 443)]),
            rule(200, access="Deny"),
        ],
    )
    assert finding(adjacent_snapshot, "APIM-SEC-003").result.outcome == "unknown"


def test_ipv4_deny_does_not_hide_ipv6_public_allowance(adjacent_snapshot):
    deny = rule(120, access="Deny", ports=[(443, 443)])
    deny.ip_versions = [4]
    allow = rule(130, ports=[(443, 443)])
    allow.ip_versions = [6]
    network(adjacent_snapshot, prerequisites() + [deny, allow, rule(200, access="Deny")])
    assert finding(adjacent_snapshot, "APIM-SEC-003").result.outcome == "fail"


def test_v2_nsg_semantics_do_not_require_classic_management_ports(adjacent_snapshot):
    instance = adjacent_snapshot.instances[0]
    instance.sku = Sku(name="PremiumV2", capacity=2)
    network(adjacent_snapshot, [rule(100, access="Deny")])
    assert finding(adjacent_snapshot, "APIM-SEC-003").result.outcome == "pass"
    instance.sku = Sku(name="StandardV2", capacity=2)
    instance.virtual_network_type = "External"
    assert finding(adjacent_snapshot, "APIM-SEC-003").result.outcome == "not_applicable"


@pytest.mark.parametrize(
    ("status", "enabled", "destination", "outcome"),
    [
        ("complete", True, True, "pass"),
        ("complete", True, False, "fail"),
        ("complete", False, True, "fail"),
        ("complete", None, True, "unknown"),
        ("partial", False, True, "unknown"),
        ("partial", True, True, "pass"),
    ],
)
def test_gateway_diagnostics(adjacent_snapshot, status, enabled, destination, outcome):
    governance = adjacent_snapshot.instances[0].governance
    governance.diagnostics_status = status
    governance.diagnostics = [
        DiagnosticSetting(
            reference="setting", gateway_logs=enabled, destination_configured=destination
        ),
    ]
    assert finding(adjacent_snapshot, "APIM-OPS-001").result.outcome == outcome


@pytest.mark.parametrize(
    ("increase", "decrease", "expected_out", "expected_in"),
    [(1, 1, "pass", "pass"), (0, 1, "fail", "pass"), (1, 0, "pass", "fail")],
)
def test_scale_profiles(adjacent_snapshot, increase, decrease, expected_out, expected_in):
    governance = adjacent_snapshot.instances[0].governance
    governance.autoscale_status = "complete"
    governance.autoscale = [
        AutoscaleSetting(
            reference="scale",
            enabled=True,
            profiles=[
                ScaleProfile(
                    minimum=1,
                    default=2,
                    maximum=4,
                    increase_rules=increase,
                    decrease_rules=decrease,
                )
            ],
        )
    ]
    assert finding(adjacent_snapshot, "APIM-REL-004").result.outcome == expected_out
    assert finding(adjacent_snapshot, "APIM-COST-003").result.outcome == expected_in
    governance.autoscale_status = "partial"
    assert finding(adjacent_snapshot, "APIM-REL-004").result.outcome == (
        "fail" if expected_out == "fail" else "unknown"
    )


def test_absent_disabled_and_fixed_autoscale_are_distinct(adjacent_snapshot):
    governance = adjacent_snapshot.instances[0].governance
    assert finding(adjacent_snapshot, "APIM-REL-004").result.outcome == "unknown"
    governance.autoscale_status = "complete"
    assert finding(adjacent_snapshot, "APIM-REL-004").result.outcome == "fail"
    assert finding(adjacent_snapshot, "APIM-COST-003").result.outcome == "not_applicable"
    governance.autoscale = [
        AutoscaleSetting(
            reference="scale",
            enabled=False,
            profiles=[
                ScaleProfile(minimum=1, default=1, maximum=4, increase_rules=1, decrease_rules=1)
            ],
        )
    ]
    assert finding(adjacent_snapshot, "APIM-REL-004").result.outcome == "fail"
    governance.autoscale[0].enabled = True
    governance.autoscale[0].profiles[0].maximum = 1
    assert finding(adjacent_snapshot, "APIM-COST-003").result.outcome == "not_applicable"
    adjacent_snapshot.instances[0].sku = Sku(name="Developer", capacity=1)
    assert finding(adjacent_snapshot, "APIM-REL-004").result.outcome == "unsupported"
    adjacent_snapshot.instances[0].sku = Sku(name="Consumption")
    assert finding(adjacent_snapshot, "APIM-REL-004").result.outcome == "not_applicable"


@pytest.mark.parametrize(
    ("state", "age", "outcome"),
    [
        ("NonCompliant", 1, "fail"),
        ("Compliant", 1, "pass"),
        ("Compliant", 3, "unknown"),
        ("NonCompliant", 3, "unknown"),
        ("Compliant", -1, "unknown"),
        ("Error", 1, "unknown"),
        ("Exempt", 1, "not_applicable"),
    ],
)
def test_policy_state_freshness(adjacent_snapshot, state, age, outcome):
    governance = adjacent_snapshot.instances[0].governance
    governance.policy_status = "complete"
    governance.policy_states = [
        PolicyState(
            assignment="assignment",
            definition="definition",
            state=state,
            timestamp=adjacent_snapshot.collected_at - timedelta(days=age),
        )
    ]
    assert finding(adjacent_snapshot, "APIM-OPS-005").result.outcome == outcome
    if age == 3 and state == "Compliant":
        settings = RuleSettings(thresholds=Thresholds(policy_max_age_days=4))
        assert finding(adjacent_snapshot, "APIM-OPS-005", settings).result.outcome == "pass"


def test_empty_policy_results_are_not_a_compliance_pass(adjacent_snapshot):
    adjacent_snapshot.instances[0].governance.policy_status = "complete"
    assert finding(adjacent_snapshot, "APIM-OPS-005").result.outcome == "unknown"


@pytest.mark.parametrize("states", [("Compliant", "NonCompliant"), ("NonCompliant", "Compliant")])
def test_tied_latest_policy_states_cannot_hide_noncompliance(adjacent_snapshot, states):
    governance = adjacent_snapshot.instances[0].governance
    governance.policy_status = "complete"
    governance.policy_states = [
        PolicyState(
            assignment="assignment",
            definition="definition",
            state=state,
            timestamp=adjacent_snapshot.collected_at,
        )
        for state in states
    ]
    assert finding(adjacent_snapshot, "APIM-OPS-005").result.outcome == "fail"


def test_defender_requires_plan_and_onboarding_and_supported_api_type(adjacent_snapshot):
    instance = adjacent_snapshot.instances[0]
    governance = instance.governance
    governance.defender_status = "complete"
    governance.defender_plan = "Free"
    assert finding(adjacent_snapshot, "APIM-SEC-025").result.outcome == "fail"
    governance.defender_plan = "Standard"
    assert finding(adjacent_snapshot, "APIM-SEC-025").result.outcome == "fail"
    governance.defender_api_paths = ["apis/orders"]
    assert finding(adjacent_snapshot, "APIM-SEC-025").result.outcome == "pass"
    instance.inventory.resources[0].metadata.api_type = None
    assert finding(adjacent_snapshot, "APIM-SEC-025").result.outcome == "unknown"
    instance.inventory.resources[0].metadata.api_type = "soap"
    assert finding(adjacent_snapshot, "APIM-SEC-025").result.outcome == "unsupported"
    instance.sku = Sku(name="StandardV2", capacity=2)
    assert finding(adjacent_snapshot, "APIM-SEC-025").result.outcome == "unsupported"


def aggregate(**changes):
    data = dict(
        requests=100,
        tls_known=100,
        weak_tls=0,
        response_known=100,
        gateway_5xx=1,
        backend_known=100,
        backend_5xx=1,
        latency_samples=100,
        backend_p95_ms=2000,
        cache_hits=0,
        cache_misses=100,
    )
    data.update(changes)
    return LogAggregate(**data)


def logs(snapshot, data, status="complete"):
    snapshot.instances[0].log_analytics = LogAnalytics(
        status=status,
        workspaces=[
            WorkspaceLogs(
                workspace="workspace",
                table="ApiManagementGatewayLogs",
                status="complete",
                aggregate=data,
            )
        ],
    )


def test_runtime_thresholds_and_missing_columns(adjacent_snapshot):
    logs(adjacent_snapshot, aggregate())
    assert finding(adjacent_snapshot, "APIM-PERF-005").result.outcome == "pass"
    logs(adjacent_snapshot, aggregate(backend_p95_ms=2001))
    assert finding(adjacent_snapshot, "APIM-PERF-005").result.outcome == "fail"
    logs(adjacent_snapshot, aggregate(gateway_5xx=2), status="partial")
    assert finding(adjacent_snapshot, "APIM-PERF-005").result.outcome == "fail"
    logs(adjacent_snapshot, aggregate(response_known=90))
    assert finding(adjacent_snapshot, "APIM-PERF-005").result.outcome == "unknown"
    logs(adjacent_snapshot, aggregate(), status="partial")
    assert finding(adjacent_snapshot, "APIM-PERF-005").result.outcome == "unknown"
    settings = RuleSettings(thresholds=Thresholds(backend_latency_ms=1500))
    assert finding(adjacent_snapshot, "APIM-PERF-005", settings).result.outcome == "fail"


def test_positive_legacy_tls_overrides_disabled_flags(adjacent_snapshot):
    instance = adjacent_snapshot.instances[0]
    instance.custom_properties = {
        key: False
        for key in SAFE_CUSTOM_PROPERTIES
        if "Protocols." in key and not key.endswith("Http2")
    }
    logs(adjacent_snapshot, aggregate(weak_tls=2), status="partial")
    assert finding(adjacent_snapshot, "APIM-SEC-006").result.outcome == "fail"
    logs(adjacent_snapshot, aggregate(tls_known=0))
    instance.custom_properties = {}
    assert finding(adjacent_snapshot, "APIM-SEC-006").result.outcome == "unknown"


def test_empty_logged_sample_cannot_establish_healthy_runtime(adjacent_snapshot):
    logs(
        adjacent_snapshot,
        aggregate(
            requests=0,
            tls_known=0,
            weak_tls=0,
            response_known=0,
            gateway_5xx=0,
            backend_known=0,
            backend_5xx=0,
            latency_samples=0,
            backend_p95_ms=None,
            cache_hits=0,
            cache_misses=0,
        ),
    )
    assert finding(adjacent_snapshot, "APIM-PERF-005").result.outcome == "unknown"


def test_new_rules_use_existing_waiver_and_scoring_contract(adjacent_snapshot):
    governance = adjacent_snapshot.instances[0].governance
    governance.autoscale_status = "complete"
    settings = RuleSettings(
        waivers=[Waiver(rule_id="APIM-REL-004", justification="Approved fixed capacity")],
        severity_overrides={"APIM-REL-004": "Low"},
    )
    selected = finding(adjacent_snapshot, "APIM-REL-004", settings)
    assert selected.result.outcome == "fail"
    assert selected.severity == "Low"
    assert selected.waiver_justification == "Approved fixed capacity"
    assert scores([selected])[0].score is None


def run_reader(handler, work):
    async def run():
        credential = AsyncMock()
        credential.get_token.return_value = AccessToken("synthetic-token", 9999999999)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await work(ArmReader(credential, client))

    return asyncio.run(run())


def linked_ids(instance):
    root = instance.resource_id.partition("/providers/")[0]
    return (
        root + "/providers/Microsoft.Network/virtualNetworks/vnet/subnets/gateway",
        root + "/providers/Microsoft.Network/networkSecurityGroups/nsg",
        root + "/providers/Microsoft.OperationalInsights/workspaces/logs",
    )


def raw_nsg_rule(priority, source="*", port="*", access="Allow", **changes):
    props = dict(
        priority=priority,
        sourceAddressPrefix=source,
        sourcePortRange="*",
        destinationAddressPrefix="*",
        destinationPortRange=port,
        access=access,
        protocol="Tcp",
        direction="Inbound",
    )
    props.update(changes)
    return {"properties": props}


def test_linked_network_projection_excludes_raw_addresses_and_payloads(adjacent_snapshot):
    instance = adjacent_snapshot.instances[0]
    subnet, nsg, _ = linked_ids(instance)
    public_ip = nsg.replace("networkSecurityGroups/nsg", "publicIPAddresses/ip")
    endpoint = nsg.replace("networkSecurityGroups/nsg", "privateEndpoints/pe")
    body = {
        "properties": {
            "virtualNetworkConfiguration": {"subnetResourceId": subnet},
            "additionalLocations": [],
            "publicIpAddressId": public_ip,
            "privateEndpointConnections": [{"properties": {"privateEndpoint": {"id": endpoint}}}],
        }
    }
    warnings = []
    requests = []

    def handler(request):
        requests.append(request)
        assert request.method == "GET"
        path = request.url.path
        if path == subnet:
            props = {"networkSecurityGroup": {"id": nsg}, "addressPrefix": "10.1.0.0/24"}
        elif path == nsg:
            props = {
                "securityRules": [
                    raw_nsg_rule(100, "ApiManagement", "3443"),
                    raw_nsg_rule(110, "AzureLoadBalancer", "6390"),
                    raw_nsg_rule(120, "0.0.0.0/0", "443"),
                ],
                "defaultSecurityRules": [raw_nsg_rule(65500, access="Deny")],
            }
        elif path == public_ip:
            props = {
                "ipAddress": SECRET,
                "ddosSettings": {"protectionMode": "VirtualNetworkInherited"},
            }
        elif path == subnet.rsplit("/", 2)[0]:
            props = {"enableDdosProtection": True}
        elif path == endpoint:
            props = {
                "subnet": {"id": subnet},
                "privateLinkServiceConnections": [
                    {
                        "properties": {
                            "privateLinkServiceId": instance.resource_id,
                            "privateLinkServiceConnectionState": {"status": "Approved"},
                        }
                    }
                ],
            }
        else:
            raise AssertionError(path)
        return httpx.Response(200, json={"properties": props, "privatePayload": SECRET})

    async def work(reader):
        return await collect_networking(reader, instance, body, warnings, enabled=True)

    result = run_reader(handler, work)
    assert not warnings
    assert result.status == result.subnets_status == "complete"
    assert result.public_ips[0].vnet_ddos_enabled is True
    assert result.private_endpoints[0].approved is True
    assert "10.1.0" not in result.model_dump_json()
    assert "0.0.0.0" not in result.model_dump_json()
    assert SECRET not in result.model_dump_json()
    assert all(request.url.host == "management.azure.com" for request in requests)
    instance.networking = result
    assert finding(adjacent_snapshot, "APIM-SEC-003").result.outcome == "fail"


@pytest.mark.parametrize(
    "response", [httpx.Response(403), httpx.Response(200, json={"properties": {}})]
)
def test_unreadable_or_omitted_nsg_link_is_not_a_confirmed_absence(adjacent_snapshot, response):
    instance = adjacent_snapshot.instances[0]
    subnet, _, _ = linked_ids(instance)
    warnings = []

    async def work(reader):
        return await collect_networking(
            reader,
            instance,
            {
                "properties": {
                    "virtualNetworkConfiguration": {"subnetResourceId": subnet},
                    "additionalLocations": [],
                }
            },
            warnings,
            enabled=True,
        )

    instance.networking = run_reader(lambda request: response, work)
    assert finding(adjacent_snapshot, "APIM-SEC-003").result.outcome == "unknown"
    assert warnings


def scale_body(instance, **changes):
    props = dict(
        targetResourceUri=instance.resource_id,
        enabled=True,
        notifications=[{"email": SECRET}],
        profiles=[
            {
                "name": SECRET,
                "capacity": {"minimum": "1", "default": "2", "maximum": "4"},
                "rules": [
                    {
                        "metricTrigger": {
                            "metricName": "Capacity",
                            "metricResourceUri": instance.resource_id,
                            "operator": "GreaterThan",
                            "threshold": 70,
                            "timeGrain": "PT1M",
                            "timeWindow": "PT5M",
                            "timeAggregation": "Average",
                            "statistic": "Average",
                        },
                        "scaleAction": {
                            "direction": direction,
                            "type": "ChangeCount",
                            "value": "1",
                        },
                    }
                    for direction in ("Increase", "Decrease")
                ],
            }
        ],
    )
    props.update(changes)
    return {"id": instance.resource_id + "-autoscale", "properties": props}


def governance_handler(instance, workspace, requests):
    def handler(request):
        requests.append(request)
        path = request.url.path
        if path.endswith("/diagnosticSettings"):
            return httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "id": instance.resource_id
                            + "/providers/Microsoft.Insights/diagnosticSettings/gateway",
                            "properties": {
                                "logs": [{"enabled": True, "categoryGroup": "allLogs"}],
                                "workspaceId": workspace,
                                "logAnalyticsDestinationType": "Dedicated",
                                "privatePayload": SECRET,
                            },
                        }
                    ]
                },
            )
        if path.endswith("/autoscalesettings"):
            return httpx.Response(
                200,
                json={
                    "value": [
                        scale_body(instance),
                        scale_body(instance, targetResourceUri=instance.resource_id + "-other"),
                    ]
                },
            )
        if path.endswith("/pricings/Api"):
            return httpx.Response(
                200, json={"properties": {"pricingTier": "Standard", "secret": SECRET}}
            )
        if path.endswith("/apiCollections"):
            return httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "id": instance.resource_id
                            + "/providers/Microsoft.Security/apiCollections/orders",
                            "name": "orders",
                            "properties": {
                                "displayName": SECRET,
                                "discoveredVia": SECRET,
                                "provisioningState": "Succeeded",
                            },
                        }
                    ]
                },
            )
        if path.endswith("/queryResults"):
            assert request.method == "POST"
            assert not request.content
            return httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "resourceId": instance.resource_id,
                            "complianceState": "Compliant",
                            "timestamp": "2026-01-15T00:00:00Z",
                            "policyAssignmentId": SECRET,
                            "policyDefinitionId": SECRET,
                        }
                    ]
                },
            )
        raise AssertionError(path)

    return handler


def test_governance_projects_scoped_paginated_metadata_and_readonly_query(adjacent_snapshot):
    instance = adjacent_snapshot.instances[0]
    _, _, workspace = linked_ids(instance)
    warnings, requests = [], []

    async def work(reader):
        return await collect_governance(reader, instance, warnings, enabled=True)

    result, links = run_reader(governance_handler(instance, workspace, requests), work)
    assert not warnings
    assert links == [(workspace, "ApiManagementGatewayLogs")]
    assert result.defender_api_paths == ["apis/orders"]
    assert len(result.autoscale) == 1
    assert result.autoscale[0].profiles[0].increase_rules == 1
    assert SECRET not in result.model_dump_json()
    assert all(
        request.method == "GET"
        or (
            request.method == "POST"
            and request.url.path.endswith("/policyStates/latest/queryResults")
        )
        for request in requests
    )


def test_policy_pagination_partial_and_host_escape_are_not_compliant(adjacent_snapshot):
    instance = adjacent_snapshot.instances[0]
    warnings, requests = [], []

    def handler(request):
        requests.append(request)
        if not request.url.path.endswith("/queryResults"):
            return httpx.Response(403, json={"error": SECRET})
        return httpx.Response(
            200,
            json={
                "value": [
                    {
                        "resourceId": instance.resource_id,
                        "complianceState": "Compliant",
                        "timestamp": adjacent_snapshot.collected_at.isoformat(),
                        "policyAssignmentId": "assignment",
                        "policyDefinitionId": "definition",
                    }
                ],
                "@odata.nextLink": "https://attacker.invalid" + request.url.path,
            },
        )

    async def work(reader):
        return await collect_governance(reader, instance, warnings, enabled=True)

    instance.governance, _ = run_reader(handler, work)
    assert instance.governance.policy_status == "partial"
    assert finding(adjacent_snapshot, "APIM-OPS-005").result.outcome == "unknown"
    assert all(request.url.host == "management.azure.com" for request in requests)
    assert any(warning.code == "UNSAFE_URL" for warning in warnings)
    assert SECRET not in instance.governance.model_dump_json()


def test_initiative_references_keep_independent_latest_policy_states(adjacent_snapshot):
    instance = adjacent_snapshot.instances[0]
    _, _, workspace = linked_ids(instance)
    original = governance_handler(instance, workspace, [])
    states = [
        {
            "resourceId": instance.resource_id,
            "complianceState": state,
            "timestamp": (adjacent_snapshot.collected_at - timedelta(hours=age)).isoformat(),
            "policyAssignmentId": "assignment",
            "policyDefinitionId": "definition",
            "policyDefinitionReferenceId": reference,
        }
        for state, age, reference in (
            ("NonCompliant", 1, SECRET),
            ("Compliant", 0, "another-reference"),
        )
    ]

    def handler(request):
        response = original(request)
        if request.url.path.endswith("/queryResults"):
            assert "policyDefinitionReferenceId" in request.url.params["$select"]
            return httpx.Response(200, json={"value": states})
        return response

    async def work(reader):
        return await collect_governance(reader, instance, [], enabled=True)

    instance.governance, _ = run_reader(handler, work)
    assert finding(adjacent_snapshot, "APIM-OPS-005").result.outcome == "fail"
    assert SECRET not in instance.governance.model_dump_json()
    states.append(
        {
            **states[0],
            "complianceState": "Compliant",
            "timestamp": adjacent_snapshot.collected_at.isoformat(),
        }
    )
    instance.governance, _ = run_reader(handler, work)
    assert finding(adjacent_snapshot, "APIM-OPS-005").result.outcome == "pass"


@pytest.mark.parametrize("state", ["Creating", "Failed", None])
def test_defender_onboarding_must_be_successfully_provisioned(adjacent_snapshot, state):
    instance = adjacent_snapshot.instances[0]
    _, _, workspace = linked_ids(instance)
    warnings = []
    original = governance_handler(instance, workspace, [])

    def handler(request):
        response = original(request)
        if request.url.path.endswith("/apiCollections"):
            body = response.json()
            body["value"][0]["properties"]["provisioningState"] = state
            return httpx.Response(200, json=body)
        return response

    async def work(reader):
        return await collect_governance(reader, instance, warnings, enabled=True)

    instance.governance, _ = run_reader(handler, work)
    assert instance.governance.defender_status == "partial"
    assert finding(adjacent_snapshot, "APIM-SEC-025").result.outcome == "unknown"
    assert warnings


@pytest.mark.parametrize(
    ("direction", "value", "identifier"),
    [
        ("Increase", "1", "APIM-REL-004"),
        ("Decrease", "4", "APIM-COST-003"),
    ],
)
def test_exact_capacity_action_must_change_an_elastic_profile(
    adjacent_snapshot, direction, value, identifier
):
    instance = adjacent_snapshot.instances[0]
    _, _, workspace = linked_ids(instance)
    original = governance_handler(instance, workspace, [])

    def handler(request):
        response = original(request)
        if request.url.path.endswith("/autoscalesettings"):
            body = response.json()
            for setting in body["value"]:
                for profile in setting["properties"]["profiles"]:
                    for rule in profile["rules"]:
                        if rule["scaleAction"]["direction"] == direction:
                            rule["scaleAction"].update(type="ExactCount", value=value)
            return httpx.Response(200, json=body)
        return response

    async def work(reader):
        return await collect_governance(reader, instance, [], enabled=True)

    instance.governance, _ = run_reader(handler, work)
    assert finding(adjacent_snapshot, identifier).result.outcome == "fail"


def log_response(**changes):
    data = aggregate(**changes).model_dump()
    return {
        "tables": [
            {
                "columns": [{"name": key, "type": "real"} for key in data],
                "rows": [list(data.values())],
            },
            {
                "columns": [
                    {"name": name, "type": "long"} for name in ("api", "gateway_5xx", "backend_5xx")
                ],
                "rows": [[SECRET, 1, 1]],
            },
        ]
    }


@pytest.mark.parametrize("table", ["ApiManagementGatewayLogs", "AzureDiagnostics"])
def test_opt_in_logs_are_scoped_aggregated_and_anonymized(adjacent_snapshot, table):
    instance = adjacent_snapshot.instances[0]
    instance.governance.diagnostics_status = "complete"
    _, _, workspace = linked_ids(instance)
    warnings, requests = [], []

    def handler(request):
        requests.append(request)
        if request.url.host == "management.azure.com":
            assert request.url.path.casefold() == workspace.casefold()
            return httpx.Response(200, json={"properties": {"customerId": WORKSPACE_GUID}})
        assert request.url.host == "api.loganalytics.azure.com"
        query = request.url.params["query"]
        assert f'where _ResourceId =~ "{instance.resource_id}"' in query
        assert "summarize requests=count()" in query
        assert "backend_p95_ms=percentile(" in query
        assert "take 5" in query
        assert "Authorization" not in query
        assert "CallerIpAddress" not in query and "BackendUrl" not in query
        if table == "AzureDiagnostics":
            assert 'Category == "GatewayLogs"' in query
            assert "AdditionalFields" in query
        return httpx.Response(200, json=log_response())

    async def work(reader):
        return await collect_logs(
            reader,
            instance,
            [(workspace, table), (workspace.swapcase(), table)],
            adjacent_snapshot.telemetry_start,
            adjacent_snapshot.telemetry_end,
            warnings,
            Telemetry(),
            enabled=True,
        )

    result = run_reader(handler, work)
    assert not warnings
    assert result.status == "complete"
    assert len(requests) == 2
    assert SECRET not in result.model_dump_json()
    assert result.workspaces[0].hotspots[0].api_reference == reference_id(SECRET.casefold())
    assert all(request.method == "GET" for request in requests)


@pytest.mark.parametrize(
    "body",
    [
        {"error": {"code": "PartialError", "message": SECRET}, "tables": []},
        {"tables": [{"columns": [{"name": "secret", "type": "string"}], "rows": [[SECRET]]}]},
    ],
)
def test_partial_or_malformed_logs_preserve_unknown(adjacent_snapshot, body):
    instance = adjacent_snapshot.instances[0]
    instance.governance.diagnostics_status = "complete"
    _, _, workspace = linked_ids(instance)
    warnings = []

    def handler(request):
        return httpx.Response(
            200,
            json=(
                {"properties": {"customerId": WORKSPACE_GUID}}
                if request.url.host == "management.azure.com"
                else body
            ),
        )

    async def work(reader):
        return await collect_logs(
            reader,
            instance,
            [(workspace, "ApiManagementGatewayLogs")],
            adjacent_snapshot.telemetry_start,
            adjacent_snapshot.telemetry_end,
            warnings,
            Telemetry(),
            enabled=True,
        )

    instance.log_analytics = run_reader(handler, work)
    assert finding(adjacent_snapshot, "APIM-PERF-005").result.outcome == "unknown"
    assert warnings
    assert SECRET not in instance.log_analytics.model_dump_json()
    assert SECRET not in "".join(warning.model_dump_json() for warning in warnings)


def test_disabled_adjacent_modules_issue_no_network_requests(adjacent_snapshot):
    instance = adjacent_snapshot.instances[0]
    warnings = []

    def forbidden(request):
        raise AssertionError("Disabled modules must not request Azure")

    async def work(reader):
        network = await collect_networking(reader, instance, None, warnings, enabled=False)
        governance, links = await collect_governance(reader, instance, warnings, enabled=False)
        log_data = await collect_logs(
            reader,
            instance,
            links,
            adjacent_snapshot.telemetry_start,
            adjacent_snapshot.telemetry_end,
            warnings,
            Telemetry(),
            enabled=False,
        )
        return network, governance, log_data

    network_data, governance, log_data = run_reader(forbidden, work)
    assert network_data.status == governance.policy_status == log_data.status == "disabled"
    assert all(warning.code == "DISABLED" for warning in warnings)


def test_invalid_kql_and_dependency_settings_are_rejected():
    for data in (
        {"modules": {"log_analytics_kql": True, "defender_policy": False}},
        {"telemetry": {"kql_max_rows": 0}},
        {"telemetry": {"kql_timeout_seconds": 181}},
    ):
        with pytest.raises(ValidationError):
            AssessmentConfig.model_validate(data)


def test_legacy_iteration_three_digest_and_report_remain_usable(adjacent_snapshot):
    from apim_assess.artifacts import digest

    instance = adjacent_snapshot.instances[0]
    instance.governance = None
    adjacent_snapshot.schema_version = "1.2"
    payload = adjacent_snapshot.model_dump_json(
        exclude={
            "instances": {
                "__all__": {
                    "networking": True,
                    "governance": True,
                    "log_analytics": True,
                    "upstream": True,
                    "inventory": {"resources": {"__all__": {"metadata": MODERN_METADATA_FIELDS}}},
                }
            },
        }
    )
    assert digest(adjacent_snapshot) == hashlib.sha256(payload.encode()).hexdigest()
    assessment = analyze(adjacent_snapshot)
    assessment.schema_version = "1.2"
    assessment.findings = [
        item
        for item in assessment.findings
        if item.rule.id not in ITERATION_4_IDS | ITERATION_5_IDS
    ]
    from apim_assess.analyzer.engine import mcsb_coverage, mcsb_score

    assessment.pillar_scores = scores(assessment.findings)
    assessment.mcsb_coverage = mcsb_coverage(assessment.findings)
    assessment.mcsb_assessed_score = mcsb_score(assessment.mcsb_coverage)
    assert "Iteration 3" in render(adjacent_snapshot, assessment)
    instance.governance = Governance()
    with pytest.raises(ValidationError, match="require snapshot schema 1.3"):
        Snapshot.model_validate(adjacent_snapshot.model_dump())


def test_mocked_multi_instance_adjacent_assess_replays_offline(
    adjacent_snapshot,
    tmp_path,
    monkeypatch,
):
    original = adjacent_snapshot.instances[0]
    instances = [original, original.model_copy(deep=True)]
    instances[1].resource_id += "-test"
    identifiers = [instance.resource_id for instance in instances]
    subnet, nsg, workspace = linked_ids(original)
    queries = []
    requests = []

    def handler(request):
        requests.append(request)
        path = request.url.path
        if request.url.host == "api.loganalytics.azure.com":
            queries.append(request.url.params["query"])
            return httpx.Response(200, json=log_response(weak_tls=2))
        if path.casefold() == workspace.casefold():
            return httpx.Response(200, json={"properties": {"customerId": WORKSPACE_GUID}})
        if path == subnet:
            return httpx.Response(
                200,
                json={
                    "properties": {
                        "addressPrefix": "10.1.0.0/24",
                        "networkSecurityGroup": {"id": nsg},
                    }
                },
            )
        if path == nsg:
            return httpx.Response(
                200,
                json={
                    "properties": {
                        "securityRules": [
                            raw_nsg_rule(100, "ApiManagement", "3443"),
                            raw_nsg_rule(110, "AzureLoadBalancer", "6390"),
                        ],
                        "defaultSecurityRules": [raw_nsg_rule(65500, access="Deny")],
                    }
                },
            )
        if path.endswith("/pricings/Api"):
            return httpx.Response(200, json={"properties": {"pricingTier": "Standard"}})
        if path.endswith("/autoscalesettings"):
            return httpx.Response(200, json={"value": [scale_body(item) for item in instances]})
        instance = next(
            item
            for item in instances
            if (path == item.resource_id or path.startswith(item.resource_id + "/"))
        )
        if path == instance.resource_id:
            return httpx.Response(
                200,
                json={
                    "id": instance.resource_id,
                    "location": "eastus",
                    "sku": {"name": "Premium", "capacity": 2},
                    "zones": ["1", "2"],
                    "properties": {
                        "additionalLocations": [],
                        "virtualNetworkType": "Internal",
                        "virtualNetworkConfiguration": {"subnetResourceId": subnet},
                        "privateEndpointConnections": [],
                        "publicNetworkAccess": "Disabled",
                        "hostnameConfigurations": [],
                        "developerPortalStatus": "Disabled",
                        "customProperties": {
                            key: False for key in SAFE_CUSTOM_PROPERTIES if "Protocols." in key
                        },
                    },
                },
            )
        if path.endswith("/queryResults"):
            assert request.method == "POST"
            return httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "resourceId": instance.resource_id,
                            "complianceState": "Compliant",
                            "timestamp": (datetime.now(UTC) - timedelta(hours=1)).isoformat(),
                            "policyAssignmentId": SECRET,
                            "policyDefinitionId": SECRET,
                        }
                    ]
                },
            )
        if path.endswith(("/diagnosticSettings", "/apiCollections")):
            return governance_handler(instance, workspace, [])(request)
        tail = path.removeprefix(instance.resource_id + "/")
        if tail == "apis" or tail == "apis/orders":
            api = {
                "id": instance.resource_id + "/apis/orders",
                "properties": {
                    "type": "http",
                    "protocols": ["https"],
                    "path": "orders",
                    "subscriptionRequired": True,
                },
            }
            return httpx.Response(200, json={"value": [api]} if tail == "apis" else api)
        if tail.endswith("/policies/policy") or tail == "policies/policy":
            return httpx.Response(404)
        if tail in {"tenant/access", "portalsettings/signup"}:
            return httpx.Response(200, json={"properties": {"enabled": False}})
        if tail == "portalconfigs/default":
            return httpx.Response(200, json={"properties": {"signin": {"require": True}}})
        return httpx.Response(200, json={"value": []})

    async def mocked(config):
        credential = AsyncMock()
        credential.get_token.return_value = AccessToken("synthetic-token", 9999999999)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await collect(config, ArmReader(credential, client))

    monkeypatch.setattr("apim_assess.cli.collect", mocked)
    config = tmp_path / "settings.yaml"
    config.write_text(
        "targets:\n  instances:\n"
        f"    - resource_id: {identifiers[0]}\n      env: prod\n"
        f"    - resource_id: {identifiers[1]}\n      env: non-prod\n"
        "modules:\n  metrics: false\n  log_analytics_kql: true\n"
        "telemetry:\n  lookback_days: 1\n",
    )
    output = tmp_path / "composed"
    runner = CliRunner()
    result = runner.invoke(app, ["assess", "--config", str(config), "--output-dir", str(output)])
    assert result.exit_code == 0, result.output
    saved = Snapshot.model_validate_json((output / "snapshot.json").read_text())
    assessment = PortfolioAssessment.model_validate_json((output / "findings.json").read_text())
    assert saved.schema_version == assessment.schema_version == "1.4"
    assert [item.environment for item in saved.instances] == ["prod", "non-prod"]
    assert len(assessment.findings) == 108
    assert len(queries) == 2 and all(
        any(identifier in query for query in queries) for identifier in identifiers
    )
    assert all(
        item.result.outcome == "pass"
        for item in assessment.findings
        if item.rule.id in ITERATION_4_IDS
    )
    assert all(
        item.result.outcome == "fail"
        for item in assessment.findings
        if item.rule.id == "APIM-SEC-006"
    )
    assert {item.severity for item in assessment.findings if item.rule.id == "APIM-REL-004"} == {
        "High",
        "Low",
    }

    def forbidden(*args, **kwargs):
        raise AssertionError("Offline replay must not contact Azure or create credentials")

    monkeypatch.setattr("apim_assess.collector.apim_core.DefaultAzureCredential", forbidden)
    monkeypatch.setattr("httpx.AsyncClient", forbidden)
    replay = tmp_path / "replay.json"
    result = runner.invoke(
        app,
        [
            "analyze",
            "--snapshot",
            str(output / "snapshot.json"),
            "--output",
            str(replay),
        ],
    )
    assert result.exit_code == 0, result.output
    assert replay.read_bytes() == (output / "findings.json").read_bytes()
    report = tmp_path / "replay.html"
    result = runner.invoke(
        app,
        [
            "report",
            "--snapshot",
            str(output / "snapshot.json"),
            "--findings",
            str(replay),
            "--output",
            str(report),
        ],
    )
    assert result.exit_code == 0, result.output
    assert report.read_bytes() == (output / "apim-assessment-report.html").read_bytes()
    assert "Cache hit ratio=0.0%" in report.read_text()
    assert all(
        SECRET not in path.read_text() for path in (output / "snapshot.json", replay, report)
    )
