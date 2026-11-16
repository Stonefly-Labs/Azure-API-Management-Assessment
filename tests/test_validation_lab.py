"""Focused unit tests for the Iteration 10 Azure Validation Lab.

Verifies:
1. Entra JWT validation (`samples.validation_lab.auth`) for missing header,
   expired token, wrong audience, missing app role, and valid token.
2. Orders REST app (`samples.validation_lab.rest_app`) and OpenAPI 3.0.3 export.
3. Microsoft Agent Framework MCP app (`samples.validation_lab.mcp_app`)
   streamable HTTP JSON-RPC (`tools/list`, `tools/call` for `@tool` functions
   and `agent.as_tool()`).
4. Microsoft Agent Framework A2A app (`samples.validation_lab.a2a_app`)
   agent card discovery (`/.well-known/agent-card.json`) and JSON-RPC
   `message/send` task execution.
5. Gateway smoke probe runner (`samples.validation_lab.smoke`) against mocked
   gateway transport.
6. 55-rule catalog contract (`samples/validation_lab/expectations.yaml`) and
   expectation validator (`scripts.lab.validate`) + teardown guardrails
   (`scripts.lab.destroy`).
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest

from apim_assess.analyzer.engine import load_rules
from apim_assess.config import load_analysis_config
from apim_assess.models.findings import (
    PILLARS,
    Evaluation,
    Evidence,
    Finding,
    PillarScore,
    PortfolioAssessment,
)
from samples.validation_lab.a2a_app import create_a2a_app
from samples.validation_lab.auth import AuthError, EntraJwtValidator, build_test_jwt
from samples.validation_lab.config import LabServiceSettings
from samples.validation_lab.mcp_app import create_mcp_app
from samples.validation_lab.openapi import build_orders_openapi_spec
from samples.validation_lab.rest_app import create_rest_app
from samples.validation_lab.smoke import run_gateway_probes
from scripts.lab.destroy import validate_destroy_scope
from scripts.lab.validate import (
    load_expectations,
    verify_contract_covers_catalog,
    verify_findings_against_expectations,
)

TEST_SECRET = "validation-lab-unit-test-secret-32-bytes!"
TEST_TENANT = "11111111-2222-3333-4444-555555555555"


def test_entra_jwt_validator_enforces_audience_tenant_and_roles() -> None:
    cfg = LabServiceSettings(
        service_name="mcp-test",
        port=8080,
        tenant_id=TEST_TENANT,
        audience="api://app-apv-mcp-api",
        required_role="Mcp.Tool.Invoke",
        jwks_json=None,
        allow_hs256_test_secret=TEST_SECRET,
    )
    validator = EntraJwtValidator(cfg)

    with pytest.raises(AuthError) as exc_info:
        validator.verify_authorization_header(None)
    assert exc_info.value.status_code == 401

    wrong_aud = build_test_jwt(
        secret=TEST_SECRET,
        tenant_id=TEST_TENANT,
        audience="api://wrong-audience",
        roles=["Mcp.Tool.Invoke"],
    )
    with pytest.raises(AuthError) as exc_info:
        validator.verify_authorization_header(f"Bearer {wrong_aud}")
    assert exc_info.value.status_code == 401

    missing_role = build_test_jwt(
        secret=TEST_SECRET,
        tenant_id=TEST_TENANT,
        audience="api://app-apv-mcp-api",
        roles=["Other.Role"],
    )
    with pytest.raises(AuthError) as exc_info:
        validator.verify_authorization_header(f"Bearer {missing_role}")
    assert exc_info.value.status_code == 403

    expired_payload = {
        "iss": f"https://login.microsoftonline.com/{TEST_TENANT}/v2.0",
        "aud": "api://app-apv-mcp-api",
        "sub": "expired-caller",
        "tid": TEST_TENANT,
        "roles": ["Mcp.Tool.Invoke"],
        "iat": 1000,
        "nbf": 1000,
        "exp": 1001,
    }
    expired_token = jwt.encode(expired_payload, TEST_SECRET, algorithm="HS256")
    with pytest.raises(AuthError) as exc_info:
        validator.verify_authorization_header(f"Bearer {expired_token}")
    assert exc_info.value.status_code == 401

    valid_token = build_test_jwt(
        secret=TEST_SECRET,
        tenant_id=TEST_TENANT,
        audience="api://app-apv-mcp-api",
        roles=["Mcp.Tool.Invoke"],
    )
    claims = validator.verify_authorization_header(f"Bearer {valid_token}")
    assert claims.subject == "lab-client-sp"
    assert "Mcp.Tool.Invoke" in claims.roles


def test_orders_rest_app_and_openapi_contract() -> None:
    spec = build_orders_openapi_spec()
    assert spec["openapi"] == "3.0.3"
    assert "/orders" in spec["paths"]
    assert "/orders/{orderId}" in spec["paths"]

    checked_in = Path("infra/lab/openapi/orders-api.openapi.json")
    assert checked_in.exists()

    async def _exercise_rest() -> None:
        app = create_rest_app()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            health = await client.get("/healthz")
            assert health.status_code == 200
            assert health.json()["status"] == "ok"

            orders = await client.get("/orders")
            assert orders.status_code == 200
            assert len(orders.json()["orders"]) >= 2

            single = await client.get("/orders/ord-1001")
            assert single.status_code == 200
            assert single.json()["id"] == "ord-1001"

            missing = await client.get("/orders/ord-9999")
            assert missing.status_code == 404

            created = await client.post(
                "/orders",
                json={
                    "customer": "Adventure Works",
                    "items": ["apim-sensor-01"],
                    "totalUsd": 89.0,
                },
            )
            assert created.status_code == 201
            assert created.json()["customer"] == "Adventure Works"

    asyncio.run(_exercise_rest())


def test_agent_framework_mcp_app_streamable_http_and_jwt_auth() -> None:
    cfg = LabServiceSettings(
        service_name="mcp-test",
        port=8080,
        tenant_id=TEST_TENANT,
        audience="api://app-apv-mcp-api",
        required_role="Mcp.Tool.Invoke",
        jwks_json=None,
        allow_hs256_test_secret=TEST_SECRET,
    )
    token = build_test_jwt(
        secret=TEST_SECRET,
        tenant_id=TEST_TENANT,
        audience="api://app-apv-mcp-api",
        roles=["Mcp.Tool.Invoke"],
    )

    async def _exercise_mcp() -> None:
        app = create_mcp_app(cfg)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            health = await client.get("/healthz")
            assert health.status_code == 200
            assert health.json()["framework"] == "microsoft-agent-framework"

            unauth = await client.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            )
            assert unauth.status_code == 401

            listed = await client.post(
                "/mcp",
                headers={"Authorization": f"Bearer {token}"},
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            )
            assert listed.status_code == 200
            tool_names = {t["name"] for t in listed.json()["result"]["tools"]}
            assert {
                "validation_lab_mcp_agent",
                "lookup_inventory_status",
                "verify_gateway_posture",
            } <= tool_names

            call_tool = await client.post(
                "/mcp",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "lookup_inventory_status",
                        "arguments": {"sku": "apim-sensor-01"},
                    },
                },
            )
            assert call_tool.status_code == 200
            assert "apim-sensor-01" in call_tool.json()["result"]["content"][0]["text"]

            call_agent = await client.post(
                "/mcp",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "validation_lab_mcp_agent",
                        "arguments": {"task": "Check westus3 gateway"},
                    },
                },
            )
            assert call_agent.status_code == 200
            assert (
                "Agent Framework MCP concierge" in call_agent.json()["result"]["content"][0]["text"]
            )

    asyncio.run(_exercise_mcp())


def test_agent_framework_a2a_app_card_and_message_send() -> None:
    cfg = LabServiceSettings(
        service_name="a2a-test",
        port=8080,
        tenant_id=TEST_TENANT,
        audience="api://app-apv-a2a-api",
        required_role="A2A.Agent.Invoke",
        jwks_json=None,
        allow_hs256_test_secret=TEST_SECRET,
    )
    token = build_test_jwt(
        secret=TEST_SECRET,
        tenant_id=TEST_TENANT,
        audience="api://app-apv-a2a-api",
        roles=["A2A.Agent.Invoke"],
    )

    async def _exercise_a2a() -> None:
        app = create_a2a_app(cfg)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            health = await client.get("/healthz")
            assert health.status_code == 200
            assert health.json()["framework"] == "microsoft-agent-framework"

            unauth = await client.post(
                "/a2a",
                json={"jsonrpc": "2.0", "id": "1", "method": "message/send", "params": {}},
            )
            assert unauth.status_code == 401

            card = await client.get(
                "/.well-known/agent-card.json",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert card.status_code == 200
            assert card.json()["framework"] == "microsoft-agent-framework"

            sent = await client.post(
                "/a2a",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "jsonrpc": "2.0",
                    "id": "a2a-1",
                    "method": "message/send",
                    "params": {
                        "id": "task-1",
                        "message": {
                            "role": "user",
                            "parts": [{"type": "text", "text": "check order ord-1001"}],
                        },
                    },
                },
            )
            assert sent.status_code == 200
            result = sent.json()["result"]
            assert result["status"]["state"] == "completed"
            assert "ord-1001" in result["artifacts"][0]["parts"][0]["text"]

    asyncio.run(_exercise_a2a())


def test_smoke_probe_runner_handles_both_gateways() -> None:
    def _mock_handler(request: httpx.Request) -> httpx.Response:
        has_bearer = request.headers.get("Authorization", "").startswith("Bearer ")
        if request.url.host == "bv2.example.test" and not has_bearer:
            return httpx.Response(401, json={"error": "missing bearer"})
        return httpx.Response(200, json={"ok": True})

    async def _exercise_smoke() -> None:
        transport = httpx.MockTransport(_mock_handler)
        report = await run_gateway_probes(
            dev_gateway_url="https://dev.example.test",
            bv2_gateway_url="https://bv2.example.test",
            bv2_subscription_key="sub-key",
            mcp_token="token-mcp",
            a2a_token="token-a2a",
            transport=transport,
        )
        assert report.passed
        assert len(report.results) == 11

    asyncio.run(_exercise_smoke())


def test_expectations_contract_covers_all_55_rules_and_validates_outcomes() -> None:
    contract = load_expectations()
    errors = verify_contract_covers_catalog(contract)
    assert errors == []

    lab_config = load_analysis_config(Path("samples/validation_lab/assessment.lab.yaml"))
    assert str(lab_config.env) == "prod"
    assert lab_config.modules.log_analytics_kql is True

    catalog = {rule.id: rule for rule in load_rules()}
    assert len(catalog) == 55

    findings: list[Finding] = []
    for inst_name, inst_spec in contract.instances.items():
        rid = (
            "/subscriptions/00000000-0000-0000-0000-000000000000"
            f"/resourceGroups/rg-apv-lab-wus3-001/providers/Microsoft.ApiManagement/service/{inst_name}"
        )
        for idx, (rule_id, rule_exp) in enumerate(inst_spec.expected_rules.items()):
            rule = catalog[rule_id]
            chosen_status = sorted(rule_exp.statuses)[0]
            outcome: Any = "fail" if chosen_status == "waived" else chosen_status
            waiver = (
                "Lab waiver for outcome diversity"
                if (inst_name == "apim-apv-dev-wus3-001" and idx == 0)
                else None
            )
            findings.append(
                Finding(
                    resource_id=rid,
                    environment="prod",
                    rule=rule,
                    severity=rule.severity,
                    result=Evaluation(
                        outcome=outcome,
                        summary=f"Synthetic {outcome} for {rule_id}",
                        evidence=[Evidence(source="lab-test", detail=rule_exp.rationale or "ok")],
                    ),
                    waiver_justification=waiver,
                )
            )

    assessment = PortfolioAssessment(
        schema_version="1.5",
        snapshot_digest="a" * 64,
        findings=findings,
        pillar_scores=[
            PillarScore(
                pillar=p,
                score=80.0,
                passed=1,
                failed=1,
                unknown=0,
                unsupported=0,
                not_applicable=0,
                waived=0,
            )
            for p in PILLARS
        ],
    )
    summary = verify_findings_against_expectations(assessment, contract)
    assert summary.passed, summary.to_dict()
    assert summary.total_rules_checked == 110


def test_destroy_guardrails_protect_bootstrap_and_unrelated_resource_groups() -> None:
    validate_destroy_scope("rg-apv-lab-wus3-001")
    with pytest.raises(ValueError, match="protected bootstrap"):
        validate_destroy_scope("rg-apv-ops-wus3-001")
    with pytest.raises(ValueError, match="protected bootstrap"):
        validate_destroy_scope("rg-apv-bootstrap-wus3-001")
    with pytest.raises(ValueError, match="outside the 'rg-apv-lab-\\*' prefix"):
        validate_destroy_scope("rg-production-shared-001")


def test_paired_lab_snapshot_evaluates_all_55_rules_against_expectations() -> None:
    from datetime import date, timedelta

    from apim_assess.analyzer.engine import analyze
    from apim_assess.collector.sanitizer import reference_id, sanitize_policy
    from apim_assess.collector.subresources import GATEWAY_VERSION
    from apim_assess.models.adjacent import (
        DiagnosticSetting,
        Governance,
        LogAggregate,
        LogAnalytics,
        Networking,
        NsgRule,
        PublicIpEvidence,
        SubnetEvidence,
        WorkspaceLogs,
    )
    from apim_assess.models.findings import RuleSettings, Waiver
    from apim_assess.models.policy import (
        CollectionCoverage,
        GatewayMetadata,
        Inventory,
        PolicyDocument,
        ResourceMetadata,
        SubResource,
    )
    from apim_assess.models.snapshot import (
        Instance,
        MetricPoint,
        MetricSeries,
        ServiceSettings,
        Sku,
        Snapshot,
    )
    from apim_assess.models.upstream import Upstream, UpstreamProbe

    sub_id = "00000000-0000-0000-0000-000000000000"
    rg = "rg-apv-lab-wus3-001"
    dev_id = (
        f"/subscriptions/{sub_id}/resourceGroups/{rg}"
        "/providers/Microsoft.ApiManagement/service/apim-apv-dev-wus3-001"
    )
    bv2_id = (
        f"/subscriptions/{sub_id}/resourceGroups/{rg}"
        "/providers/Microsoft.ApiManagement/service/apim-apv-bv2-wus3-001"
    )
    now = datetime(2026, 4, 19, 12, 0, tzinfo=UTC)
    start = now - timedelta(hours=5)
    end = now - timedelta(hours=1)

    def _pol(rid: str, scope: str, xml: str | None) -> PolicyDocument:
        source = f"{rid}/{scope}/policies/policy" if scope else f"{rid}/policies/policy"
        if xml is None:
            return PolicyDocument(source=source, status="absent")
        return sanitize_policy(source, xml)

    def _sub(
        rid: str,
        path: str,
        kind: str,
        *,
        gateway: GatewayMetadata | None = None,
        **meta: Any,
    ) -> SubResource:
        return SubResource(
            resource_id=f"{rid}/{path}",
            path=path,
            name=path.rsplit("/", 1)[-1],
            kind=kind,  # type: ignore[arg-type]
            metadata=ResourceMetadata(**meta),
            gateway=gateway,
        )

    def _metrics(*, classic: bool) -> list[MetricSeries]:
        hours = [start + timedelta(hours=h) for h in range(4)]
        series = [
            MetricSeries(
                name="Capacity" if classic else "CpuPercent_Gateway",
                location="westus3" if classic else None,
                dimensions={"Location": "westus3"} if classic else {},
                status="available",
                unit="Percent",
                points=[MetricPoint(timestamp=ts, average=22.0, maximum=35.0) for ts in hours],
            ),
            MetricSeries(
                name="Requests",
                location="westus3",
                dimensions={"Location": "westus3"},
                status="available",
                unit="Count",
                points=[MetricPoint(timestamp=ts, total=120.0) for ts in hours],
            ),
            MetricSeries(
                name="Requests",
                dimensions={"GatewayResponseCodeCategory": "2xx"},
                status="available",
                unit="Count",
                points=[MetricPoint(timestamp=ts, total=118.0) for ts in hours],
            ),
            MetricSeries(
                name="Requests",
                dimensions={"GatewayResponseCodeCategory": "5xx"},
                status="available",
                unit="Count",
                points=[MetricPoint(timestamp=ts, total=0.0) for ts in hours],
            ),
            MetricSeries(
                name="BackendDuration",
                dimensions={"ApiId": reference_id("orders-api")},
                status="available",
                unit="MilliSeconds",
                points=[MetricPoint(timestamp=ts, average=35.0, maximum=90.0) for ts in hours],
            ),
            MetricSeries(
                name="Duration",
                status="available",
                unit="MilliSeconds",
                points=[MetricPoint(timestamp=ts, average=45.0, maximum=110.0) for ts in hours],
            ),
        ]
        if not classic:
            series.append(
                MetricSeries(
                    name="MemoryPercent_Gateway",
                    status="available",
                    unit="Percent",
                    points=[MetricPoint(timestamp=ts, average=30.0, maximum=45.0) for ts in hours],
                )
            )
        return series

    base_collections = (
        "apis",
        "gateway_apis",
        "products",
        "workspaces",
        "backends",
        "namedValues",
        "loggers",
        "subscriptions",
        "policyFragments",
        "diagnostics",
        "identityProviders",
        "openIdConnectProviders",
        "authorizationServers",
        "tags",
        "apiVersionSets",
    )

    dev_collections = {
        name: CollectionCoverage(status="complete")
        for name in (
            *base_collections,
            "apis/orders-api/operations",
            "apis/orders-api/diagnostics",
            "apis/orders-api-copy/operations",
            "apis/orders-api-copy/diagnostics",
            "apis/foundry-ai-api/operations",
            "apis/foundry-ai-api/diagnostics",
            "apis/orders-graphql/operations",
            "apis/orders-graphql/diagnostics",
            "apis/orders-a2a/operations",
            "apis/orders-a2a/diagnostics",
            "apis/orders-mcp/tools",
            "apis/orders-mcp/diagnostics",
            "products/prod-open/apis",
            "products/prod-empty/apis",
        )
    }
    dev_repeated_outbound = """
  <outbound>
    <set-header name="x-powered-by" exists-action="delete" />
    <set-header name="x-aspnet-version" exists-action="delete" />
    <set-header name="server" exists-action="delete" />
  </outbound>"""
    dev_orders_policy = f"""
<policies>
  <inbound>
    <cors allow-credentials="true">
      <allowed-origins><origin>*</origin></allowed-origins>
      <allowed-methods><method>*</method></allowed-methods>
      <allowed-headers><header>*</header></allowed-headers>
    </cors>
    <set-header name="X-Debug-Authorization" exists-action="override">
      <value>Bearer secret-inline-lab-credential-value-do-not-use</value>
    </set-header>
    <set-backend-service backend-id="backend-pool-single" />
  </inbound>
  <backend><forward-request /></backend>
{dev_repeated_outbound}
  <on-error />
</policies>
"""
    dev_orders_copy_policy = f"""
<policies>
  <inbound>
    <cors allow-credentials="true">
      <allowed-origins><origin>*</origin></allowed-origins>
      <allowed-methods><method>*</method></allowed-methods>
      <allowed-headers><header>*</header></allowed-headers>
    </cors>
    <set-header name="X-Debug-Authorization" exists-action="override">
      <value>Bearer secret-inline-lab-credential-value-do-not-use</value>
    </set-header>
    <set-backend-service base-url="https://ca-apv-rest-wus3-001.example.azurecontainerapps.io" />
  </inbound>
  <backend><forward-request /></backend>
{dev_repeated_outbound}
  <on-error />
</policies>
"""
    dev_policies = {
        "": _pol(
            dev_id,
            "",
            (
                "<policies><inbound /><backend><forward-request /></backend>"
                "<outbound /><on-error /></policies>"
            ),
        ),
        "products/prod-open": _pol(dev_id, "products/prod-open", None),
        "products/prod-empty": _pol(dev_id, "products/prod-empty", None),
        "apis/orders-api": _pol(dev_id, "apis/orders-api", dev_orders_policy),
        "apis/orders-api/operations/get-orders": _pol(
            dev_id,
            "apis/orders-api/operations/get-orders",
            """
<policies>
  <inbound><base /></inbound>
  <backend><base /></backend>
  <outbound>
    <base />
    <set-header name="x-powered-by" exists-action="override">
      <value>apim-dev</value>
    </set-header>
  </outbound>
  <on-error><base /></on-error>
</policies>
""",
        ),
        "apis/orders-api/operations/create-order": _pol(
            dev_id, "apis/orders-api/operations/create-order", None
        ),
        "apis/orders-api-copy": _pol(dev_id, "apis/orders-api-copy", dev_orders_copy_policy),
        "apis/orders-api-copy/operations/get-orders-copy": _pol(
            dev_id, "apis/orders-api-copy/operations/get-orders-copy", None
        ),
        "apis/foundry-ai-api": _pol(
            dev_id,
            "apis/foundry-ai-api",
            """
<policies>
  <inbound>
    <set-header name="api-key" exists-action="override">
      <value>synthetic-openai-key-literal-0123456789</value>
    </set-header>
    <set-backend-service backend-id="backend-foundry-single" />
  </inbound>
  <backend><forward-request /></backend>
  <outbound />
  <on-error />
</policies>
""",
        ),
        "apis/foundry-ai-api/operations/chat-completions": _pol(
            dev_id, "apis/foundry-ai-api/operations/chat-completions", None
        ),
        "apis/orders-graphql": _pol(
            dev_id,
            "apis/orders-graphql",
            (
                "<policies><inbound /><backend><forward-request /></backend>"
                "<outbound /><on-error /></policies>"
            ),
        ),
        "apis/orders-mcp": _pol(
            dev_id,
            "apis/orders-mcp",
            (
                "<policies><inbound><base /></inbound><backend><base /></backend>"
                "<outbound><base /></outbound><on-error><base /></on-error></policies>"
            ),
        ),
        "apis/orders-a2a": _pol(
            dev_id,
            "apis/orders-a2a",
            (
                "<policies><inbound><base /></inbound><backend><base /></backend>"
                "<outbound><base /></outbound><on-error><base /></on-error></policies>"
            ),
        ),
        "apis/orders-a2a/operations/message-send": _pol(
            dev_id, "apis/orders-a2a/operations/message-send", None
        ),
    }
    dev_instance = Instance(
        resource_id=dev_id,
        name="apim-apv-dev-wus3-001",
        location="westus3",
        environment="prod",
        environment_source="tag",
        core_status="available",
        sku=Sku(name="Developer", capacity=1),
        zones=[],
        additional_locations=[],
        virtual_network_type="Internal",
        public_network_access="Enabled",
        private_endpoint_statuses=[],
        identity_type="SystemAssigned",
        custom_properties={
            "Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls10": True,
            "Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls11": True,
            "Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Ciphers.TripleDes168": True,
            "Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Tls10": True,
            "Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Tls11": True,
            "Microsoft.WindowsAzure.ApiManagement.Gateway.Protocols.Server.Http2": False,
        },
        service_settings=ServiceSettings(
            minimum_api_version=date(2018, 1, 1),
            certificates=[],
            portal_enabled=True,
            portal_signin_required=False,
            portal_signup_enabled=True,
            portal_entra_enabled=False,
            management_api_enabled=True,
        ),
        inventory=Inventory(
            gateway_api_version=GATEWAY_VERSION,
            collections=dev_collections,
            resources=[
                _sub(
                    dev_id,
                    "apis/orders-api",
                    "api",
                    api_type="http",
                    protocols=["http", "https"],
                    subscription_required=False,
                    version_set=False,
                    api_route_hash=reference_id("orders-dup"),
                    service_url_kind="literal",
                    ai_backend="other",
                ),
                _sub(dev_id, "apis/orders-api/operations/get-orders", "operation", method="GET"),
                _sub(dev_id, "apis/orders-api/operations/create-order", "operation", method="POST"),
                _sub(
                    dev_id,
                    "apis/orders-api-copy",
                    "api",
                    api_type="http",
                    protocols=["http", "https"],
                    subscription_required=True,
                    version_set=False,
                    api_route_hash=reference_id("orders-dup"),
                    service_url_kind="literal",
                    ai_backend="other",
                ),
                _sub(
                    dev_id,
                    "apis/orders-api-copy/operations/get-orders-copy",
                    "operation",
                    method="GET",
                ),
                _sub(
                    dev_id,
                    "apis/foundry-ai-api",
                    "api",
                    api_type="http",
                    protocols=["http", "https"],
                    subscription_required=False,
                    version_set=False,
                    api_route_hash=reference_id("foundry-ai-api"),
                    service_url_kind="literal",
                    ai_backend="azure_openai",
                ),
                _sub(
                    dev_id,
                    "apis/foundry-ai-api/operations/chat-completions",
                    "operation",
                    method="POST",
                ),
                _sub(
                    dev_id,
                    "apis/orders-graphql",
                    "api",
                    api_type="graphql",
                    protocols=["http", "https"],
                    subscription_required=False,
                    version_set=False,
                    api_route_hash=reference_id("orders-graphql"),
                    service_url_kind="literal",
                    ai_backend="other",
                ),
                _sub(
                    dev_id,
                    "apis/orders-mcp",
                    "api",
                    gateway=GatewayMetadata(mode="passthrough"),
                    api_type="mcp",
                    protocols=["https"],
                    subscription_required=False,
                    version_set=False,
                    api_route_hash=reference_id("orders-mcp"),
                ),
                _sub(
                    dev_id,
                    "apis/orders-a2a",
                    "api",
                    gateway=GatewayMetadata(
                        transport="jsonrpc",
                        agent_id_hash=reference_id("orders-specialist-dev"),
                        agent_card_url_kind="literal",
                        runtime_url_kind="literal",
                    ),
                    api_type="a2a",
                    protocols=["https"],
                    subscription_required=False,
                    version_set=False,
                    api_route_hash=reference_id("orders-a2a"),
                ),
                _sub(
                    dev_id,
                    "apis/orders-a2a/operations/message-send",
                    "operation",
                    method="POST",
                ),
                _sub(
                    dev_id,
                    "backends/backend-rest-insecure",
                    "backend",
                    validate_certificate_chain=False,
                    validate_certificate_name=False,
                    circuit_breaker_present=False,
                    backend_pool=False,
                    ai_backend="other",
                ),
                _sub(
                    dev_id,
                    "backends/backend-pool-single",
                    "backend",
                    validate_certificate_chain=True,
                    validate_certificate_name=True,
                    circuit_breaker_present=False,
                    backend_pool=True,
                    pool_member_count=1,
                    ai_backend="other",
                ),
                _sub(
                    dev_id,
                    "backends/backend-mcp",
                    "backend",
                    validate_certificate_chain=True,
                    validate_certificate_name=True,
                    circuit_breaker_present=False,
                    backend_pool=False,
                    ai_backend="other",
                ),
                _sub(
                    dev_id,
                    "backends/backend-foundry-single",
                    "backend",
                    validate_certificate_chain=False,
                    validate_certificate_name=False,
                    circuit_breaker_present=False,
                    backend_pool=False,
                    api_key_credential=True,
                    credentials_present=True,
                    ai_backend="azure_openai",
                ),
                _sub(
                    dev_id,
                    "namedValues/nv-plaintext-secret",
                    "named_value",
                    secret=False,
                    key_vault=False,
                ),
                _sub(
                    dev_id,
                    "namedValues/nv-inline-secret",
                    "named_value",
                    secret=True,
                    key_vault=False,
                ),
                _sub(
                    dev_id,
                    "loggers/appinsights",
                    "logger",
                    application_insights=True,
                ),
                _sub(
                    dev_id,
                    "diagnostics/applicationinsights",
                    "diagnostic",
                    sampling_percentage=100.0,
                    always_log_errors=True,
                    body_bytes=8192,
                    logger_reference_hash=reference_id("appinsights"),
                ),
                _sub(
                    dev_id,
                    "products/prod-open",
                    "product",
                    subscription_required=False,
                ),
                _sub(
                    dev_id,
                    "products/prod-empty",
                    "product",
                    subscription_required=True,
                ),
                _sub(
                    dev_id,
                    "subscriptions/sub-all-apis-dev",
                    "subscription",
                    subscription_scope="all_apis",
                    state="active",
                ),
            ],
            product_apis={
                "products/prod-open": [
                    "apis/orders-api",
                    "apis/orders-api-copy",
                    "apis/foundry-ai-api",
                    "apis/orders-graphql",
                ],
                "products/prod-empty": [],
            },
            policies=dev_policies,
        ),
        networking=Networking(
            status="complete",
            subnets_status="complete",
            subnets=[
                SubnetEvidence(
                    reference=reference_id("snet-apim-dev"),
                    status="complete",
                    nsg_attached=True,
                    ip_versions=[4],
                    rules=[
                        NsgRule(
                            priority=100,
                            access="Allow",
                            protocol="Tcp",
                            ip_versions=[4],
                            sources=["apim"],
                            source_ports_any=True,
                            destination="subnet",
                            ports=[(3443, 3443)],
                        ),
                        NsgRule(
                            priority=110,
                            access="Allow",
                            protocol="Tcp",
                            ip_versions=[4],
                            sources=["load_balancer"],
                            source_ports_any=True,
                            destination="subnet",
                            ports=[(6390, 6390)],
                        ),
                        NsgRule(
                            priority=200,
                            access="Deny",
                            protocol="Tcp",
                            ip_versions=[4],
                            sources=["internet"],
                            source_ports_any=True,
                            destination="subnet",
                            ports=[(80, 80), (443, 443)],
                        ),
                    ],
                )
            ],
            private_endpoints=[],
            public_ips=[
                PublicIpEvidence(
                    reference=reference_id("pip-apim-dev"),
                    status="complete",
                    ddos_mode="VirtualNetworkInherited",
                    vnet_ddos_enabled=False,
                )
            ],
        ),
        governance=Governance(
            diagnostics_status="complete",
            diagnostics=[],
            autoscale_status="complete",
            autoscale=[],
            defender_status="complete",
            defender_plan="Free",
            defender_api_paths=[],
            policy_status="complete",
            policy_states=[],
        ),
        log_analytics=LogAnalytics(status="not_applicable", workspaces=[]),
        upstream=Upstream(
            afd=UpstreamProbe(status="complete", routes=[]),
            appgw=UpstreamProbe(status="complete", routes=[]),
        ),
        metrics=_metrics(classic=True),
    )

    bv2_collections = {
        name: CollectionCoverage(status="complete")
        for name in (
            *base_collections,
            "apis/orders-api/operations",
            "apis/orders-api/diagnostics",
            "apis/foundry-ai-api/operations",
            "apis/foundry-ai-api/diagnostics",
            "apis/orders-graphql/operations",
            "apis/orders-graphql/diagnostics",
            "apis/orders-a2a/operations",
            "apis/orders-a2a/diagnostics",
            "apis/orders-mcp/tools",
            "apis/orders-mcp/diagnostics",
            "products/prod-enterprise/apis",
        )
    }
    frag_inbound_key = "policyFragments/" + reference_id("frag-inbound-common")
    frag_outbound_key = "policyFragments/" + reference_id("frag-outbound-hardening")
    bv2_fragments = {
        frag_inbound_key: sanitize_policy(
            f"{bv2_id}/policyFragments/frag-inbound-common",
            f"""
<fragment>
  <cors allow-credentials="false">
    <allowed-origins><origin>https://portal.contoso.example</origin></allowed-origins>
    <allowed-methods><method>GET</method><method>POST</method></allowed-methods>
  </cors>
  <validate-azure-ad-token tenant-id="{TEST_TENANT}" header-name="Authorization"
      failed-validation-httpcode="401">
    <audiences>
      <audience>api://app-apv-gateway</audience>
    </audiences>
    <client-application-ids>
      <application-id>11111111-1111-1111-1111-111111111111</application-id>
    </client-application-ids>
  </validate-azure-ad-token>
  <rate-limit-by-key calls="120" renewal-period="60" counter-key="@(context.Request.IpAddress)" />
</fragment>
""",
            fragment=True,
        ),
        frag_outbound_key: sanitize_policy(
            f"{bv2_id}/policyFragments/frag-outbound-hardening",
            """
<fragment>
  <set-header name="x-powered-by" exists-action="delete" />
  <set-header name="x-aspnet-version" exists-action="delete" />
</fragment>
""",
            fragment=True,
        ),
    }
    bv2_policies = {
        "": _pol(
            bv2_id,
            "",
            """
<policies>
  <inbound><include-fragment fragment-id="frag-inbound-common" /></inbound>
  <backend><forward-request timeout="30" /></backend>
  <outbound><include-fragment fragment-id="frag-outbound-hardening" /></outbound>
  <on-error>
    <trace source="apim-bv2-global-error" severity="error">
      <message>Gateway execution error recorded</message>
    </trace>
  </on-error>
</policies>
""",
        ),
        "products/prod-enterprise": _pol(bv2_id, "products/prod-enterprise", None),
        "apis/orders-api": _pol(
            bv2_id,
            "apis/orders-api",
            """
<policies>
  <inbound>
    <base />
    <validate-content unspecified-content-type-action="prevent" max-size="65536"
        size-exceeded-action="prevent" />
    <cache-lookup vary-by-developer="false" vary-by-developer-groups="false"
        downstream-caching-type="none" />
    <authentication-managed-identity resource="api://app-apv-rest-api" />
    <set-backend-service backend-id="backend-rest" />
  </inbound>
  <backend><base /></backend>
  <outbound>
    <base />
    <cache-store duration="60" />
  </outbound>
  <on-error><base /></on-error>
</policies>
""",
        ),
        "apis/orders-api/operations/get-orders": _pol(
            bv2_id, "apis/orders-api/operations/get-orders", None
        ),
        "apis/orders-api/operations/create-order": _pol(
            bv2_id, "apis/orders-api/operations/create-order", None
        ),
        "apis/foundry-ai-api": _pol(
            bv2_id,
            "apis/foundry-ai-api",
            """
<policies>
  <inbound>
    <base />
    <validate-content unspecified-content-type-action="prevent" max-size="65536"
        size-exceeded-action="prevent" />
    <llm-token-limit counter-key="@(context.Request.IpAddress)" tokens-per-minute="2000"
        token-quota="100000" token-quota-period="Daily" estimate-prompt-tokens="true" />
    <llm-emit-token-metric namespace="apim-lab-ai-metrics">
      <dimension name="API" value="@(context.Api.Id)" />
    </llm-emit-token-metric>
    <authentication-managed-identity resource="https://cognitiveservices.azure.com" />
    <set-backend-service backend-id="backend-foundry-pool" />
  </inbound>
  <backend><base /></backend>
  <outbound><base /></outbound>
  <on-error><base /></on-error>
</policies>
""",
        ),
        "apis/foundry-ai-api/operations/chat-completions": _pol(
            bv2_id, "apis/foundry-ai-api/operations/chat-completions", None
        ),
        "apis/orders-graphql": _pol(
            bv2_id,
            "apis/orders-graphql",
            """
<policies>
  <inbound>
    <base />
    <validate-graphql-request max-size="65536" max-depth="6" />
    <authentication-managed-identity resource="api://app-apv-rest-api" />
    <set-backend-service backend-id="backend-rest" />
  </inbound>
  <backend><base /></backend>
  <outbound><base /></outbound>
  <on-error><base /></on-error>
</policies>
""",
        ),
        "apis/orders-mcp": _pol(
            bv2_id,
            "apis/orders-mcp",
            f"""
<policies>
  <inbound>
    <base />
    <validate-azure-ad-token tenant-id="{TEST_TENANT}" header-name="Authorization"
        failed-validation-httpcode="401">
      <audiences>
        <audience>api://app-apv-mcp-api</audience>
      </audiences>
      <client-application-ids>
        <application-id>11111111-1111-1111-1111-111111111111</application-id>
      </client-application-ids>
    </validate-azure-ad-token>
    <set-backend-service backend-id="backend-mcp" />
  </inbound>
  <backend><base /></backend>
  <outbound><base /></outbound>
  <on-error><base /></on-error>
</policies>
""",
        ),
        "apis/orders-a2a": _pol(
            bv2_id,
            "apis/orders-a2a",
            f"""
<policies>
  <inbound>
    <base />
    <validate-azure-ad-token tenant-id="{TEST_TENANT}" header-name="Authorization"
        failed-validation-httpcode="401">
      <audiences>
        <audience>api://app-apv-a2a-api</audience>
      </audiences>
      <client-application-ids>
        <application-id>11111111-1111-1111-1111-111111111111</application-id>
      </client-application-ids>
    </validate-azure-ad-token>
    <set-backend-service backend-id="backend-a2a" />
  </inbound>
  <backend><base /></backend>
  <outbound><base /></outbound>
  <on-error><base /></on-error>
</policies>
""",
        ),
        "apis/orders-a2a/operations/message-send": _pol(
            bv2_id, "apis/orders-a2a/operations/message-send", None
        ),
    }
    bv2_instance = Instance(
        resource_id=bv2_id,
        name="apim-apv-bv2-wus3-001",
        location="westus3",
        environment="prod",
        environment_source="tag",
        core_status="available",
        sku=Sku(name="BasicV2", capacity=2),
        zones=[],
        additional_locations=[],
        virtual_network_type="None",
        public_network_access="Enabled",
        private_endpoint_statuses=[],
        identity_type="SystemAssigned, UserAssigned",
        custom_properties={
            "Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls10": False,
            "Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls11": False,
            "Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Ciphers.TripleDes168": False,
            "Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Tls10": False,
            "Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Tls11": False,
            "Microsoft.WindowsAzure.ApiManagement.Gateway.Protocols.Server.Http2": True,
        },
        service_settings=ServiceSettings(
            minimum_api_version=date(2022, 8, 1),
            certificates=[],
            portal_enabled=True,
            portal_signin_required=True,
            portal_signup_enabled=False,
            portal_entra_enabled=True,
            management_api_enabled=True,
        ),
        inventory=Inventory(
            gateway_api_version=GATEWAY_VERSION,
            collections=bv2_collections,
            resources=[
                _sub(
                    bv2_id,
                    "apis/orders-api",
                    "api",
                    api_type="http",
                    protocols=["https"],
                    subscription_required=True,
                    version_set=True,
                    service_url_kind="dynamic",
                    ai_backend="other",
                ),
                _sub(bv2_id, "apis/orders-api/operations/get-orders", "operation", method="GET"),
                _sub(bv2_id, "apis/orders-api/operations/create-order", "operation", method="POST"),
                _sub(
                    bv2_id,
                    "apis/foundry-ai-api",
                    "api",
                    api_type="http",
                    protocols=["https"],
                    subscription_required=True,
                    version_set=True,
                    service_url_kind="dynamic",
                    ai_backend="azure_openai",
                    api_key_credential=False,
                ),
                _sub(
                    bv2_id,
                    "apis/foundry-ai-api/operations/chat-completions",
                    "operation",
                    method="POST",
                ),
                _sub(
                    bv2_id,
                    "apis/orders-graphql",
                    "api",
                    api_type="graphql",
                    protocols=["https"],
                    subscription_required=True,
                    version_set=True,
                    service_url_kind="dynamic",
                    ai_backend="other",
                ),
                _sub(
                    bv2_id,
                    "apis/orders-mcp",
                    "api",
                    gateway=GatewayMetadata(mode="passthrough"),
                    api_type="mcp",
                    protocols=["https"],
                    subscription_required=False,
                    version_set=True,
                ),
                _sub(
                    bv2_id,
                    "apis/orders-a2a",
                    "api",
                    gateway=GatewayMetadata(
                        transport="jsonrpc",
                        agent_id_hash=reference_id("orders-specialist-bv2"),
                        agent_card_url_kind="literal",
                        runtime_url_kind="literal",
                    ),
                    api_type="a2a",
                    protocols=["https"],
                    subscription_required=False,
                    version_set=True,
                ),
                _sub(
                    bv2_id,
                    "apis/orders-a2a/operations/message-send",
                    "operation",
                    method="POST",
                ),
                _sub(
                    bv2_id,
                    "backends/backend-rest",
                    "backend",
                    validate_certificate_chain=True,
                    validate_certificate_name=True,
                    circuit_breaker_present=True,
                    backend_pool=False,
                    breaker_429=True,
                    breaker_retry_after=True,
                    api_key_credential=False,
                    ai_backend="other",
                ),
                _sub(
                    bv2_id,
                    "backends/backend-mcp",
                    "backend",
                    validate_certificate_chain=True,
                    validate_certificate_name=True,
                    circuit_breaker_present=True,
                    backend_pool=False,
                    breaker_429=True,
                    breaker_retry_after=True,
                    api_key_credential=False,
                    ai_backend="other",
                ),
                _sub(
                    bv2_id,
                    "backends/backend-a2a",
                    "backend",
                    validate_certificate_chain=True,
                    validate_certificate_name=True,
                    circuit_breaker_present=True,
                    backend_pool=False,
                    breaker_429=True,
                    breaker_retry_after=True,
                    api_key_credential=False,
                    ai_backend="other",
                ),
                _sub(
                    bv2_id,
                    "backends/backend-foundry-primary",
                    "backend",
                    validate_certificate_chain=True,
                    validate_certificate_name=True,
                    circuit_breaker_present=True,
                    backend_pool=False,
                    breaker_429=True,
                    breaker_retry_after=True,
                    api_key_credential=False,
                    ai_backend="azure_openai",
                ),
                _sub(
                    bv2_id,
                    "backends/backend-foundry-secondary",
                    "backend",
                    validate_certificate_chain=True,
                    validate_certificate_name=True,
                    circuit_breaker_present=True,
                    backend_pool=False,
                    breaker_429=True,
                    breaker_retry_after=True,
                    api_key_credential=False,
                    ai_backend="azure_openai",
                ),
                _sub(
                    bv2_id,
                    "backends/backend-foundry-pool",
                    "backend",
                    backend_pool=True,
                    pool_member_count=2,
                    pool_member_references=[
                        reference_id((bv2_id + "/backends/backend-foundry-primary").casefold()),
                        reference_id((bv2_id + "/backends/backend-foundry-secondary").casefold()),
                    ],
                    api_key_credential=False,
                ),
                _sub(
                    bv2_id,
                    "namedValues/nv-kv-secret",
                    "named_value",
                    secret=True,
                    key_vault=True,
                ),
                _sub(
                    bv2_id,
                    "namedValues/nv-bv2-rest-url",
                    "named_value",
                    secret=False,
                    key_vault=False,
                ),
                _sub(
                    bv2_id,
                    "loggers/logger-appinsights",
                    "logger",
                    application_insights=True,
                ),
                _sub(
                    bv2_id,
                    "diagnostics/applicationinsights",
                    "diagnostic",
                    sampling_percentage=25.0,
                    always_log_errors=True,
                    body_bytes=0,
                    logger_reference_hash=reference_id("logger-appinsights"),
                ),
                _sub(
                    bv2_id,
                    "products/prod-enterprise",
                    "product",
                    subscription_required=True,
                ),
                _sub(
                    bv2_id,
                    "subscriptions/sub-enterprise-bv2",
                    "subscription",
                    subscription_scope="product",
                    state="active",
                ),
            ],
            product_apis={
                "products/prod-enterprise": [
                    "apis/orders-api",
                    "apis/foundry-ai-api",
                    "apis/orders-graphql",
                ]
            },
            fragments=bv2_fragments,
            policies=bv2_policies,
        ),
        networking=Networking(
            status="complete",
            subnets_status="not_applicable",
            subnets=[],
            private_endpoints=[],
            public_ips=[],
        ),
        governance=Governance(
            diagnostics_status="complete",
            diagnostics=[
                DiagnosticSetting(
                    reference=reference_id("diag-apim-bv2"),
                    gateway_logs=True,
                    destination_configured=True,
                    workspace=reference_id("law-apv-wus3-001"),
                )
            ],
            autoscale_status="complete",
            autoscale=[],
            defender_status="unsupported",
            defender_plan=None,
            defender_api_paths=[],
            policy_status="complete",
            policy_states=[],
        ),
        log_analytics=LogAnalytics(
            status="complete",
            workspaces=[
                WorkspaceLogs(
                    workspace=reference_id("law-apv-wus3-001"),
                    table="ApiManagementGatewayLogs",
                    status="complete",
                    aggregate=LogAggregate(
                        requests=50,
                        response_known=50,
                        gateway_5xx=0,
                        backend_known=50,
                        backend_5xx=0,
                        latency_samples=50,
                        backend_p95_ms=42.0,
                        tls_known=50,
                        weak_tls=0,
                        cache_hits=10,
                        cache_misses=40,
                    ),
                    hotspots=[],
                )
            ],
        ),
        upstream=Upstream(
            afd=UpstreamProbe(status="complete", routes=[]),
            appgw=UpstreamProbe(status="complete", routes=[]),
        ),
        metrics=_metrics(classic=False),
    )

    snapshot = Snapshot(
        schema_version="1.5",
        collected_at=now,
        telemetry_start=start,
        telemetry_end=end,
        instances=[dev_instance, bv2_instance],
    )
    settings = RuleSettings(
        waivers=[
            Waiver(
                rule_id="APIM-REL-003",
                resource_id=dev_id,
                justification="Developer tier intentionally runs single-region in westus3.",
            )
        ]
    )
    assessment = analyze(snapshot, settings)
    contract = load_expectations()
    summary = verify_findings_against_expectations(assessment, contract)
    assert summary.passed, summary.to_dict()
    assert summary.total_rules_checked == 110
