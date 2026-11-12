import asyncio
import json

import httpx
import pytest
from test_subresources import ID, SECRET, Credential, entity
from test_subresources import handler as core_handler
from typer.testing import CliRunner

from apim_assess.analyzer.engine import analyze, mcsb_coverage, mcsb_score, scores
from apim_assess.artifacts import digest
from apim_assess.cli import app
from apim_assess.collector.apim_core import collect
from apim_assess.collector.client import ArmReader
from apim_assess.collector.sanitizer import reference_id, sanitize_policy
from apim_assess.collector.subresources import GATEWAY_VERSION, SubresourceCollector
from apim_assess.models.findings import PortfolioAssessment, RuleSettings, Waiver
from apim_assess.models.policy import (
    CollectionCoverage,
    GatewayMetadata,
    Inventory,
    PolicyDocument,
    ResourceMetadata,
    SubResource,
)
from apim_assess.models.snapshot import Sku, Snapshot
from apim_assess.reporting.generator import render

JWT = (
    '<validate-jwt header-name="Authorization"><openid-config '
    'url="https://login.example.test/.well-known/openid-configuration"/>'
    "<audiences><audience>synthetic-audience</audience></audiences></validate-jwt>"
)
ENTRA = (
    '<validate-azure-ad-token tenant-id="00000000-0000-0000-0000-000000000022">'
    "<client-application-ids><application-id>synthetic-client</application-id>"
    "</client-application-ids></validate-azure-ad-token>"
)


def put(instance, path="", inbound="", *, inherit=True):
    base = "<base/>" if path and inherit else ""
    instance.inventory.policies[path] = sanitize_policy(
        instance.resource_id + "/" + path + "/policies/policy",
        f"<policies><inbound>{base}{inbound}</inbound><backend>{base}</backend>"
        f"<outbound>{base}</outbound><on-error>{base}</on-error></policies>",
    )


def add(instance, path, kind="api", *, gateway=None, **metadata):
    item = SubResource(
        resource_id=instance.resource_id + "/" + path,
        path=path,
        name=path.rsplit("/", 1)[-1],
        kind=kind,
        metadata=ResourceMetadata(**metadata),
        gateway=gateway,
    )
    instance.inventory.resources.append(item)
    return item


@pytest.fixture
def gateway(full_snapshot):
    full_snapshot.schema_version = "1.5"
    instance = full_snapshot.instances[0]
    instance.sku = Sku(name="StandardV2", capacity=1)
    instance.inventory = Inventory(
        gateway_api_version=GATEWAY_VERSION,
        collections={
            name: CollectionCoverage(status="complete")
            for name in (
                "apis",
                "gateway_apis",
                "products",
                "workspaces",
                "backends",
                "policyFragments",
                "loggers",
                "apis/mcp/tools",
                "apis/orders/operations",
                "apis/agent/operations",
            )
        },
    )
    add(
        instance,
        "apis/mcp",
        api_type="mcp",
        protocols=["https"],
        subscription_required=True,
        gateway=GatewayMetadata(mode="rest_backed"),
    )
    add(
        instance,
        "apis/orders",
        api_type="http",
        protocols=["https"],
        subscription_required=True,
        ai_backend="other",
    )
    add(instance, "apis/orders/operations/get", "operation", method="GET")
    add(
        instance,
        "apis/mcp/tools/get",
        "mcp_tool",
        gateway=GatewayMetadata(backing_operation_path="apis/orders/operations/get"),
    )
    add(
        instance,
        "apis/agent",
        api_type="a2a",
        protocols=["https"],
        subscription_required=False,
        gateway=GatewayMetadata(
            transport="jsonrpc", agent_card_url_kind="literal", runtime_url_kind="literal"
        ),
    )
    add(instance, "apis/agent/operations/runtime", "operation", method="POST")
    for path in (
        "",
        "apis/mcp",
        "apis/orders",
        "apis/orders/operations/get",
        "apis/agent",
        "apis/agent/operations/runtime",
    ):
        put(instance, path, JWT if path == "apis/orders" else ENTRA if path == "apis/agent" else "")
    return Snapshot.model_validate(full_snapshot.model_dump())


def oauth(snapshot, settings=None):
    return next(
        finding
        for finding in analyze(snapshot, settings).findings
        if finding.rule.id == "APIM-AIGW-006"
    )


@pytest.mark.parametrize(
    ("policy", "expected"),
    [
        ("", "fail"),
        (JWT, "pass"),
        (ENTRA, "pass"),
        (
            ENTRA.replace(
                "<validate-azure-ad-token ",
                '<validate-azure-ad-token authentication-endpoint="'
                'https://login.microsoftonline.com" ',
            ),
            "pass",
        ),
        (
            ENTRA.replace(
                "<validate-azure-ad-token ",
                '<validate-azure-ad-token authentication-endpoint="{{unverified-authority}}" ',
            ),
            "unknown",
        ),
        (
            ENTRA.replace(
                "<validate-azure-ad-token ",
                '<validate-azure-ad-token authentication-endpoint="https://unverified.test" ',
            ),
            "unknown",
        ),
        ("<validate-jwt/>", "unknown"),
        (
            JWT.replace("<audiences><audience>synthetic-audience</audience></audiences>", ""),
            "unknown",
        ),
        (JWT.replace('header-name="Authorization"', 'header-name=""'), "unknown"),
        (
            JWT.replace(
                'header-name="Authorization"',
                'header-name="Authorization" require-signed-tokens="false"',
            ),
            "unknown",
        ),
        (
            JWT.replace(
                'header-name="Authorization"',
                'header-name="Authorization" require-expiration-time="false"',
            ),
            "unknown",
        ),
        (ENTRA.replace("00000000-0000-0000-0000-000000000022", "{{tenant}}"), "unknown"),
        (ENTRA.replace("00000000-0000-0000-0000-000000000022", " @(context.Variable)"), "unknown"),
        (
            JWT.replace("</audiences>", "<audience>{{unverified-audience}}</audience></audiences>"),
            "unknown",
        ),
        ('<validate-jwt oauth-validator-configured="true"/>', "unknown"),
        ('<authentication-managed-identity resource="https://example.test"/>', "fail"),
        (
            '<set-header name="Authorization"><value>'
            '@(context.Request.Headers["Authorization"])</value></set-header>',
            "fail",
        ),
        ('<choose><when condition="@(true)">' + JWT + "</when></choose>", "unknown"),
        (
            '<choose><when condition="@(true)">'
            + JWT
            + "</when><otherwise>"
            + ENTRA
            + "</otherwise></choose>",
            "pass",
        ),
        ('<set-header name="Authorization"><value>synthetic</value></set-header>' + JWT, "unknown"),
    ],
)
def test_mcp_oauth_requires_configured_effective_caller_validation(gateway, policy, expected):
    put(gateway.instances[0], "apis/mcp", policy)
    finding = oauth(gateway)
    assert finding.result.outcome == expected
    assert finding.rule.pillar == "SEC"
    assert all(item.api_path in {None, "apis/mcp"} for item in finding.result.evidence)
    if expected == "fail":
        assert "MCP should be secured using OAuth 2.0." in finding.result.summary


def test_inherited_fragments_base_and_unavailable_policy(gateway):
    instance = gateway.instances[0]
    put(instance, inbound=JWT)
    assert oauth(gateway).result.outcome == "pass"
    put(instance, "apis/mcp", inherit=False)
    assert oauth(gateway).result.outcome == "fail"
    key = "policyFragments/" + reference_id("auth")
    instance.inventory.fragments[key] = sanitize_policy(
        "synthetic-fragment", "<fragment>" + ENTRA + "</fragment>", fragment=True
    )
    put(instance, "apis/mcp", '<include-fragment fragment-id="auth"/>', inherit=False)
    assert oauth(gateway).result.outcome == "pass"
    instance.inventory.fragments.clear()
    assert oauth(gateway).result.outcome == "unknown"
    instance.inventory.policies["apis/mcp"] = PolicyDocument(
        source="synthetic", status="unavailable", error_code="HTTP_403"
    )
    assert oauth(gateway).result.outcome == "unknown"


def test_missing_inventory_unsupported_scopes_and_non_mcp(gateway):
    instance = gateway.instances[0]
    instance.inventory.collections["apis/mcp/tools"].status = "unavailable"
    assert oauth(gateway).result.outcome == "unknown"
    instance.inventory.collections["apis/mcp/tools"].status = "complete"
    instance.sku.name = "Consumption"
    assert oauth(gateway).result.outcome == "unsupported"
    instance.sku.name = "Developer"
    next(
        item for item in instance.inventory.resources if item.path == "apis/mcp"
    ).workspace = "workspaces/team"
    assert oauth(gateway).result.outcome == "unsupported"
    instance.inventory.resources = [
        item for item in instance.inventory.resources if not item.path.startswith("apis/mcp")
    ]
    assert oauth(gateway).result.outcome == "not_applicable"
    instance.inventory.gateway_api_version = None
    assert oauth(gateway).result.outcome == "unknown"


@pytest.mark.parametrize("collection_name", ["gateway_apis", "products"])
def test_incomplete_discovery_cannot_establish_mcp_oauth_absence_or_pass(gateway, collection_name):
    instance = gateway.instances[0]
    instance.inventory.collections[collection_name].status = "partial"
    assert oauth(gateway).result.outcome == "unknown"
    put(instance, "apis/mcp", JWT)
    assert oauth(gateway).result.outcome == "unknown"


def test_tools_do_not_inflate_scoring_and_waivers_preserve_evidence(gateway):
    instance = gateway.instances[0]
    for index in range(3):
        add(
            instance,
            f"apis/mcp/tools/tool{index}",
            "mcp_tool",
            gateway=GatewayMetadata(backing_operation_path="apis/orders/operations/get"),
        )
    instance.environment = "prod"
    assert oauth(gateway).severity == "High"
    instance.environment = "non-prod"
    assert oauth(gateway).severity == "Medium"
    assessment = analyze(
        gateway,
        RuleSettings(
            severity_overrides={"APIM-AIGW-006": "Critical"},
            waivers=[Waiver(rule_id="APIM-AIGW-006", justification="Synthetic exception")],
        ),
    )
    selected = [item for item in assessment.findings if item.rule.id == "APIM-AIGW-006"]
    assert len(selected) == 1 and selected[0].severity == "Critical"
    assert selected[0].result.outcome == "fail" and selected[0].waiver_justification
    assert "tools/tool2" in selected[0].result.evidence[0].detail


def test_a2a_policies_are_inspected_without_rest_body_assumptions(gateway):
    assessment = analyze(gateway)
    agent_rows = [row for row in assessment.policy_coverage if row.api_path == "apis/agent"]
    assert agent_rows and all(row.jwt == "present" for row in agent_rows)
    for identifier in ("APIM-AIGW-001", "APIM-AIGW-002", "APIM-AIGW-003", "APIM-AIGW-004"):
        finding = next(item for item in assessment.findings if item.rule.id == identifier)
        assert finding.result.outcome != "fail"
    payload = next(item for item in assessment.findings if item.rule.id == "APIM-PERF-003")
    assert any("REST body/cache/forwarding" in item.detail for item in payload.result.evidence)
    assert not any(
        row.operation_path and "/tools/" in row.operation_path for row in assessment.policy_coverage
    )


def test_a2a_operation_policy_is_collected_but_not_credited_as_entry_point_auth(gateway):
    instance = gateway.instances[0]
    put(instance, "apis/agent", "")
    put(instance, "apis/agent/operations/runtime", ENTRA)
    rows = [row for row in analyze(gateway).policy_coverage if row.api_path == "apis/agent"]
    assert rows and all(row.operation_path is None and row.jwt == "absent" for row in rows)


def test_native_resource_names_are_escaped_in_report(gateway):
    mcp = next(item for item in gateway.instances[0].inventory.resources if item.path == "apis/mcp")
    mcp.name = '<img src=x onerror="alert(1)">'
    html = render(gateway, analyze(gateway))
    assert mcp.name not in html and "&lt;img src=x onerror=" in html


def test_saved_protocol_report_and_offline_cli_replay(gateway, tmp_path):
    original = gateway.model_dump_json()
    assessment = analyze(gateway)
    html = render(gateway, assessment)
    assert "Native MCP servers &amp; A2A agent APIs" in html
    assert "1 MCP servers / 1 A2A APIs / 1 MCP tools observed" in html
    assert "apis/orders/operations/get" in html
    assert "MCP should be secured using OAuth 2.0." in html
    assert gateway.model_dump_json() == original
    snapshot_path = tmp_path / "snapshot.json"
    findings_path = tmp_path / "findings.json"
    report_path = tmp_path / "report.html"
    snapshot_path.write_text(original, encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(
        app, ["analyze", "--snapshot", str(snapshot_path), "--output", str(findings_path)]
    )
    assert result.exit_code == 0, result.output
    saved = PortfolioAssessment.model_validate_json(findings_path.read_text(encoding="utf-8"))
    assert saved.model_dump() == assessment.model_dump()
    result = runner.invoke(
        app,
        [
            "report",
            "--snapshot",
            str(snapshot_path),
            "--findings",
            str(findings_path),
            "--output",
            str(report_path),
        ],
    )
    assert result.exit_code == 0, result.output
    assert report_path.read_text(encoding="utf-8") == html


def test_historical_14_findings_and_digest_stay_replayable(snapshot):
    snapshot.schema_version = "1.4"
    old_json = snapshot.model_dump_json()
    expected_digest = digest(snapshot)
    assert "gateway_api_version" not in old_json and '"gateway":' not in old_json
    assessment = analyze(snapshot)
    assert oauth(snapshot).result.outcome == "unknown"
    assessment.schema_version = "1.4"
    assessment.findings = [item for item in assessment.findings if item.rule.id != "APIM-AIGW-006"]
    assessment.pillar_scores = scores(assessment.findings)
    assessment.mcsb_coverage = mcsb_coverage(assessment.findings)
    assessment.mcsb_assessed_score = mcsb_score(assessment.mcsb_coverage)
    html = render(Snapshot.model_validate_json(old_json), assessment)
    assert "MCP/A2A coverage was not collected" in html
    assert 'data-open="APIM-AIGW-006"' not in html
    assert digest(Snapshot.model_validate_json(old_json)) == expected_digest
    assert len(assessment.findings) == 162


def protocol_handler(request):
    assert request.method == "GET"
    path = request.url.path.removeprefix(ID + "/")
    assert "listSecrets" not in path
    if path == "apis":
        assert request.url.params["api-version"] == GATEWAY_VERSION
        return httpx.Response(
            200,
            json={
                "value": [
                    entity("apis/mcp", type="mcp", subscriptionRequired=True, protocols=["https"]),
                    entity(
                        "apis/orders", type="http", subscriptionRequired=True, protocols=["https"]
                    ),
                    entity(
                        "apis/agent", type="a2a", subscriptionRequired=False, protocols=["https"]
                    ),
                ]
            },
        )
    if path == "apis/mcp":
        return httpx.Response(200, json=entity(path, type="mcp", description=SECRET))
    if path == "apis/agent":
        return httpx.Response(
            200,
            json=entity(
                path,
                type="a2a",
                agent={"id": SECRET},
                a2aProperties={
                    "agentCardBackendUrl": "https://private.example.test/" + SECRET,
                    "agentCardPath": "/" + SECRET,
                },
                jsonRpcProperties={
                    "backendUrl": "https://private.example.test/" + SECRET,
                    "path": "/" + SECRET,
                },
            ),
        )
    if path == "apis/mcp/tools":
        return httpx.Response(
            200,
            json={
                "value": [
                    entity(
                        "apis/mcp/tools/get",
                        operationId=ID.upper() + "/apis/orders/operations/get",
                        description=SECRET,
                        schema=SECRET,
                    ),
                ]
            },
        )
    if path == "apis/orders/operations":
        return httpx.Response(200, json={"value": [entity(path + "/get", method="GET")]})
    if path == "apis/agent/operations":
        return httpx.Response(200, json={"value": [entity(path + "/runtime", method="POST")]})
    if path.endswith("/policies/policy") or path == "policies/policy":
        base = "" if path == "policies/policy" else "<base/>"
        policy = ENTRA if path == "apis/agent/policies/policy" else ""
        return httpx.Response(
            200,
            json={
                "properties": {
                    "format": "rawxml",
                    "value": f"<policies><inbound>{base}{policy}</inbound><backend>{base}</backend>"
                    f"<outbound>{base}</outbound><on-error>{base}</on-error></policies>",
                }
            },
        )
    assert path != "apis/mcp/operations"
    return httpx.Response(200, json={"value": []})


def collection(handler=protocol_handler):
    async def run():
        warnings = []
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            inventory = await SubresourceCollector(
                ArmReader(Credential(), client), ID, warnings
            ).collect()
        return inventory, warnings

    return asyncio.run(run())


def test_native_collection_preserves_types_bindings_and_safe_a2a_metadata():
    inventory, warnings = collection()
    assert not warnings
    mcp = next(item for item in inventory.resources if item.path == "apis/mcp")
    assert mcp.metadata.api_type == "mcp" and mcp.gateway.mode == "rest_backed"
    tool = next(item for item in inventory.resources if item.kind == "mcp_tool")
    assert tool.gateway.backing_operation_path == "apis/orders/operations/get"
    agent = next(item for item in inventory.resources if item.path == "apis/agent")
    assert agent.gateway.transport == "jsonrpc" and agent.gateway.agent_id_hash == reference_id(
        SECRET
    )
    assert agent.gateway.agent_card_url_kind == "literal"
    assert "apis/agent/operations/runtime" in inventory.policies
    assert SECRET not in inventory.model_dump_json()
    assert "private.example.test" not in inventory.model_dump_json()


@pytest.mark.parametrize(
    "failure", ["preview", "tools", "policy", "binding", "unknown_type", "malformed"]
)
def test_collection_gaps_remain_explicit(failure):
    def handler(request):
        path = request.url.path.removeprefix(ID + "/")
        if failure == "preview" and path == "apis":
            if request.url.params["api-version"] == GATEWAY_VERSION:
                return httpx.Response(403, json={"secret": SECRET})
            return httpx.Response(
                200,
                json={
                    "value": [
                        entity(
                            "apis/orders",
                            type="http",
                            subscriptionRequired=True,
                            protocols=["https"],
                        )
                    ]
                },
            )
        if failure == "tools" and path == "apis/mcp/tools":
            return httpx.Response(403, json={"secret": SECRET})
        if failure == "policy" and path == "apis/mcp/policies/policy":
            return httpx.Response(403, json={"secret": SECRET})
        if failure == "binding" and path == "apis/mcp/tools":
            return httpx.Response(
                200,
                json={
                    "value": [entity(path + "/bad", operationId="/apis/missing/operations/missing")]
                },
            )
        if failure == "unknown_type" and path == "apis":
            return httpx.Response(
                200,
                json={
                    "value": [
                        entity("apis/unknown", type="future-native-type", protocols=["https"])
                    ]
                },
            )
        if failure == "malformed" and path == "apis/mcp":
            return httpx.Response(200, json=entity(path, mcpProperties={"transportType": {}}))
        return protocol_handler(request)

    inventory, warnings = collection(handler)
    assert warnings and SECRET not in json.dumps([warning.model_dump() for warning in warnings])
    if failure in {"preview", "unknown_type"}:
        assert inventory.collections["gateway_apis"].status != "complete"
        assert any(item.kind == "api" for item in inventory.resources)
    if failure in {"tools", "binding"}:
        assert inventory.collections["apis/mcp/tools"].status != "complete"
    if failure == "policy":
        assert inventory.policies["apis/mcp"].status == "unavailable"


@pytest.mark.parametrize("transport", ["streamable", "sse"])
def test_passthrough_metadata_and_management_tools_remain_distinct(transport, gateway):
    def handler(request):
        path = request.url.path.removeprefix(ID + "/")
        if path == "apis/mcp":
            return httpx.Response(
                200,
                json=entity(
                    path,
                    type="mcp",
                    serviceUrl="https://private.example.test/" + SECRET,
                    mcpProperties={
                        "transportType": transport,
                        "endpoints": [
                            {"name": name, "uriTemplate": "/" + SECRET}
                            for name in (
                                ["message"] if transport == "streamable" else ["message", "sse"]
                            )
                        ],
                    },
                ),
            )
        if path == "apis/mcp/tools":
            return httpx.Response(200, json={"value": []})
        if path == "apis/mcp/policies/policy":
            return httpx.Response(
                200,
                json={
                    "properties": {
                        "value": "<policies><inbound>" + JWT + "</inbound>"
                        "<backend/><outbound/><on-error/></policies>"
                    }
                },
            )
        return protocol_handler(request)

    inventory, warnings = collection(handler)
    assert not warnings
    mcp = next(item for item in inventory.resources if item.path == "apis/mcp")
    assert mcp.gateway.mode == "passthrough" and mcp.gateway.transport == transport
    assert mcp.gateway.endpoint_count == (1 if transport == "streamable" else 2)
    assert not any(item.kind == "mcp_tool" for item in inventory.resources)
    assert SECRET not in inventory.model_dump_json()
    gateway.instances[0].inventory = inventory
    assert oauth(gateway).result.outcome == "pass"


@pytest.mark.parametrize("second_page", ["complete", "denied", "version_change"])
def test_preview_pagination_keeps_native_evidence_and_contract(second_page):
    def handler(request):
        path = request.url.path.removeprefix(ID + "/")
        if path == "apis":
            if request.url.params["api-version"] != GATEWAY_VERSION:
                return httpx.Response(
                    200,
                    json={
                        "value": [
                            entity(
                                "apis/orders",
                                type="http",
                                protocols=["https"],
                                subscriptionRequired=True,
                            )
                        ]
                    },
                )
            if request.url.params.get("page") == "2":
                if second_page == "denied":
                    return httpx.Response(403, json={"secret": SECRET})
                return httpx.Response(
                    200,
                    json={
                        "value": [
                            entity(
                                "apis/orders",
                                type="http",
                                protocols=["https"],
                                subscriptionRequired=True,
                            )
                        ]
                    },
                )
            version = "2024-05-01" if second_page == "version_change" else GATEWAY_VERSION
            return httpx.Response(
                200,
                json={
                    "value": [
                        entity(
                            "apis/mcp", type="mcp", protocols=["https"], subscriptionRequired=True
                        )
                    ],
                    "nextLink": "https://management.azure.com"
                    + ID
                    + "/apis?page=2&api-version="
                    + version,
                },
            )
        return protocol_handler(request)

    inventory, warnings = collection(handler)
    assert {item.path for item in inventory.resources if item.kind == "api"} == {
        "apis/mcp",
        "apis/orders",
    }
    assert inventory.collections["apis"].count == 2
    assert inventory.collections["gateway_apis"].status == (
        "complete" if second_page == "complete" else "partial"
    )
    assert bool(warnings) == (second_page != "complete")


def test_mixed_classic_v2_assess_and_offline_replay(tmp_path, monkeypatch):
    identifiers = [ID, ID + "-v2"]
    requests = []

    def handler(request):
        assert request.method == "GET"
        requests.append(str(request.url))
        modern = request.url.path.startswith(identifiers[1])
        normalized = httpx.Request("GET", str(request.url).replace(identifiers[1], ID))
        if normalized.url.path == ID:
            response = core_handler(normalized)
            body = response.json()
            body["sku"]["name"] = "StandardV2" if modern else "Developer"
        elif normalized.url.path.endswith("/tenant/access"):
            body = {"properties": {"enabled": False}}
        else:
            body = protocol_handler(normalized).json()
        return httpx.Response(
            200,
            json=json.loads(
                json.dumps(body)
                .replace(ID.upper(), (identifiers[1] if modern else ID).upper())
                .replace(ID, identifiers[1] if modern else ID)
            ),
        )

    async def collected(config):
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await collect(config, ArmReader(Credential(), client))

    monkeypatch.setattr("apim_assess.cli.collect", collected)
    config = tmp_path / "settings.yaml"
    config.write_text(
        json.dumps({"modules": {"metrics": False, "networking": False, "defender_policy": False}}),
        encoding="utf-8",
    )
    output = tmp_path / "composed"
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
            str(output),
        ],
    )
    assert result.exit_code == 0, result.output
    saved = Snapshot.model_validate_json((output / "snapshot.json").read_text(encoding="utf-8"))
    findings = PortfolioAssessment.model_validate_json(
        (output / "findings.json").read_text(encoding="utf-8")
    )
    assert len(saved.instances) == 2 and len(findings.findings) == 110
    assert {instance.sku.name for instance in saved.instances} == {"Developer", "StandardV2"}
    assert [
        item.result.outcome for item in findings.findings if item.rule.id == "APIM-AIGW-006"
    ] == ["fail", "fail"]
    assert SECRET not in saved.model_dump_json() and requests

    def forbidden(*args, **kwargs):
        pytest.fail("Offline stages used network or credentials")

    monkeypatch.setattr("httpx.AsyncClient", forbidden)
    monkeypatch.setattr("apim_assess.collector.apim_core.DefaultAzureCredential", forbidden)
    replay = tmp_path / "replay.json"
    result = runner.invoke(
        app, ["analyze", "--snapshot", str(output / "snapshot.json"), "--output", str(replay)]
    )
    assert result.exit_code == 0, result.output
    assert replay.read_bytes() == (output / "findings.json").read_bytes()
    html = tmp_path / "replay.html"
    result = runner.invoke(
        app,
        [
            "report",
            "--snapshot",
            str(output / "snapshot.json"),
            "--findings",
            str(replay),
            "--output",
            str(html),
        ],
    )
    assert result.exit_code == 0, result.output
    assert html.read_bytes() == (output / "apim-assessment-report.html").read_bytes()


def test_workspace_mcp_is_explicitly_unsupported(gateway):
    def handler(request):
        path = request.url.path.removeprefix(ID + "/")
        if path == "apis":
            return httpx.Response(200, json={"value": []})
        if path == "workspaces":
            return httpx.Response(200, json={"value": [entity("workspaces/team")]})
        if path == "workspaces/team/apis":
            return httpx.Response(
                200,
                json={
                    "value": [
                        entity(
                            path + "/mcp",
                            type="mcp",
                            subscriptionRequired=True,
                            protocols=["https"],
                        )
                    ]
                },
            )
        if path == "workspaces/team/apis/mcp":
            return httpx.Response(200, json=entity(path, type="mcp"))
        assert path != "workspaces/team/apis/mcp/tools"
        return protocol_handler(request)

    inventory, warnings = collection(handler)
    assert any(warning.code == "UNSUPPORTED_GATEWAY_SCOPE" for warning in warnings)
    gateway.instances[0].inventory = inventory
    assert oauth(gateway).result.outcome == "unsupported"
