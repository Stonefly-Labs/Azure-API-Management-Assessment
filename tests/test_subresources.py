import asyncio

import httpx
import pytest
from azure.core.credentials import AccessToken
from typer.testing import CliRunner

from apim_assess.analyzer.engine import analyze
from apim_assess.cli import app
from apim_assess.collector.apim_core import collect
from apim_assess.collector.client import ARM, ArmReader
from apim_assess.config import AssessmentConfig
from apim_assess.models.snapshot import Snapshot

ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000001"
    "/resourceGroups/synthetic/providers/Microsoft.ApiManagement/service/synthetic"
)
SECRET = "SENSITIVE_TEST_SENTINEL_NOT_A_REAL_SECRET"
INHERITED = (
    "<policies><inbound><base/></inbound><backend><base/></backend>"
    "<outbound><base/></outbound><on-error><base/></on-error></policies>"
)
GLOBAL = (
    '<policies><inbound><include-fragment fragment-id="auth"/>'
    '<rate-limit-by-key calls="10" renewal-period="60" counter-key="@(context.Request.IpAddress)"/>'
    f'<authentication-basic username="{SECRET}" password="{SECRET}"/>'
    f"<set-body>{SECRET}</set-body></inbound><backend>"
    '<set-backend-service backend-id="orders"/><forward-request/>'
    "</backend><outbound/><on-error/></policies>"
)
FRAGMENT = (
    '<fragment><validate-jwt header-name="Authorization"><openid-config '
    'url="https://login.example.test/.well-known/openid-configuration"/>'
    "</validate-jwt></fragment>"
)


class Credential:
    async def get_token(self, *scopes, **kwargs):
        return AccessToken("synthetic-token", 9999999999)

    async def close(self):
        pass


def entity(resource_path, **properties):
    return {"id": ID + "/" + resource_path, "properties": properties}


def handler(request):
    assert request.method == "GET"
    assert "listSecrets" not in request.url.path
    if request.url.path == ID:
        return httpx.Response(
            200,
            json={
                "id": ID,
                "location": "eastus",
                "sku": {"name": "Developer", "capacity": 1},
                "zones": [],
                "properties": {
                    "virtualNetworkType": "None",
                    "privateEndpointConnections": [],
                    "additionalLocations": [],
                    "publicNetworkAccess": "Enabled",
                    "apiVersionConstraint": {"minApiVersion": "2021-08-01"},
                    "developerPortalStatus": "Enabled",
                    "hostnameConfigurations": [
                        {
                            "type": "Proxy",
                            "certificateSource": "KeyVault",
                            "keyVaultId": SECRET,
                            "certificatePassword": SECRET,
                            "hostName": SECRET,
                            "certificate": {"expiry": "2030-01-01T00:00:00Z", "subject": SECRET},
                        }
                    ],
                },
            },
        )
    path = request.url.path.removeprefix(ID + "/")
    values = {
        "apis": [
            entity(
                "apis/orders",
                subscriptionRequired=True,
                type="http",
                protocols=["https"],
                serviceUrl=f"https://example.test/?api_key={SECRET}",
                path="orders",
            ),
        ],
        "apis/orders/operations": [
            entity("apis/orders/operations/get", method="GET", urlTemplate=f"/{SECRET}"),
        ],
        "apis/orders/diagnostics": [
            entity("apis/orders/diagnostics/appinsights", sampling={"percentage": 10}),
        ],
        "products": [
            entity("products/protected", state="published", subscriptionRequired=True),
        ],
        "products/protected/apis": [entity("apis/orders")],
        "subscriptions": [
            entity(
                "subscriptions/sub",
                state="active",
                primaryKey=SECRET,
                secondaryKey=SECRET,
                ownerId=SECRET,
                scope=ID + "/products/protected",
            ),
        ],
        "backends": [
            entity(
                "backends/orders",
                url=f"https://example.test/?api_key={SECRET}",
                credentials={"authorization": {"scheme": "Basic", "parameter": SECRET}},
                tls={"validateCertificateChain": True, "validateCertificateName": True},
            ),
        ],
        "namedValues": [
            entity(
                "namedValues/secret",
                secret=True,
                value=SECRET,
                keyVault={"secretIdentifier": SECRET},
            ),
            entity("namedValues/config", secret=False, value=SECRET),
        ],
        "certificates": [
            entity(
                "certificates/tls",
                data=SECRET,
                password=SECRET,
                expirationDate="2030-01-01T00:00:00Z",
            ),
        ],
        "diagnostics": [
            entity("diagnostics/appinsights", sampling={"percentage": 5}, secret=SECRET)
        ],
        "loggers": [
            entity("loggers/telemetry", loggerType="applicationInsights", credentials=SECRET)
        ],
        "gateways": [entity("gateways/self-hosted", credentials=SECRET)],
        "workspaces": [entity("workspaces/team", description=SECRET)],
        "workspaces/team/apis": [
            entity(
                "workspaces/team/apis/workspace",
                subscriptionRequired=False,
                type="http",
                serviceUrl="https://example.test",
                protocols=["https"],
            ),
        ],
        "workspaces/team/apis/workspace/operations": [
            entity("workspaces/team/apis/workspace/operations/get", method="GET"),
        ],
        "policyFragments": [entity("policyFragments/auth")],
    }
    if path == "apis" and request.url.params.get("page") == "2":
        return httpx.Response(
            200,
            json={
                "value": [
                    entity(
                        "apis/second",
                        subscriptionRequired=True,
                        type="http",
                        serviceUrl="https://example.test",
                        protocols=["https"],
                    ),
                ]
            },
        )
    if path == "apis":
        return httpx.Response(
            200,
            json={
                "value": values[path],
                "nextLink": ARM + ID + "/apis?api-version=2024-05-01&page=2",
            },
        )
    if path == "policies/policy":
        return httpx.Response(200, json={"properties": {"format": "rawxml", "value": GLOBAL}})
    if path == "tenant/access" or path == "portalsettings/signup":
        return httpx.Response(200, json={"properties": {"enabled": False, "secret": SECRET}})
    if path == "portalconfigs/default":
        return httpx.Response(
            200, json={"properties": {"signin": {"require": True}, "secret": SECRET}}
        )
    if path == "policyFragments/auth":
        return httpx.Response(200, json={"properties": {"format": "rawxml", "value": FRAGMENT}})
    if path.endswith("/policies/policy"):
        return httpx.Response(200, json={"properties": {"value": INHERITED}})
    return httpx.Response(200, json={"value": values.get(path, [])})


async def collection(route=handler):
    config = AssessmentConfig.model_validate(
        {
            "targets": {"instances": [{"resource_id": ID}]},
            "modules": {"metrics": False},
        }
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(route)) as client:
        return await collect(config, ArmReader(Credential(), client))


def test_paginated_all_kinds_workspace_policies_and_safe_metadata_projection():
    snapshot = asyncio.run(collection())
    inventory = snapshot.instances[0].inventory
    assert {item.kind for item in inventory.resources} == {
        "api",
        "operation",
        "product",
        "subscription",
        "backend",
        "named_value",
        "certificate",
        "diagnostic",
        "gateway",
        "workspace",
        "logger",
    }
    assert len([item for item in inventory.resources if item.kind == "api"]) == 3
    assert inventory.collections["apis"].count == 2
    assert all(coverage.status == "complete" for coverage in inventory.collections.values())
    assert set(warning.module for warning in snapshot.collection_warnings) == {"metrics"}
    assert SECRET not in snapshot.model_dump_json()
    assessment = analyze(snapshot)
    assert len(assessment.findings) == 40
    assert len(assessment.policy_coverage) == 4
    assert all(row.jwt == "present" for row in assessment.policy_coverage)
    assert any(item.metadata.key_vault for item in inventory.resources)
    assert any(item.metadata.credentials_present for item in inventory.resources)
    settings = snapshot.instances[0].service_settings
    assert str(settings.minimum_api_version) == "2021-08-01"
    assert settings.certificates[0].source == "KeyVault"
    assert settings.portal_signin_required is True
    assert settings.portal_signup_enabled is False
    assert settings.management_api_enabled is False
    assert (
        next(
            item for item in inventory.resources if item.kind == "subscription"
        ).metadata.subscription_scope
        == "product"
    )


@pytest.mark.parametrize(
    ("scope", "expected"),
    [
        (ID + "/apis", "all_apis"),
        ("/apis/orders", "api"),
        (ID + "/products/apis", "product"),
        ("/products/apis", "product"),
    ],
)
def test_subscription_scope_does_not_confuse_a_product_named_apis(scope, expected):
    def route(request):
        if request.url.path == ID + "/subscriptions":
            return httpx.Response(200, json={"value": [entity("subscriptions/sub", scope=scope)]})
        return handler(request)

    snapshot = asyncio.run(collection(route))
    subscription = next(
        item for item in snapshot.instances[0].inventory.resources if item.kind == "subscription"
    )
    assert subscription.metadata.subscription_scope == expected


@pytest.mark.parametrize(
    ("members", "expected"),
    [
        ([{"id": ID + "/backends/a"}, {"id": ID + "/backends/b"}], 2),
        ([{"id": ID + "/backends/a"}, {"id": (ID + "/backends/a").upper()}], 1),
        ([{"id": ID + "/backends/a"}, {"id": SECRET}], None),
        ([{"id": ID + "/backends/a"}, {}], None),
    ],
)
def test_backend_pool_counts_distinct_valid_members_without_saving_references(members, expected):
    def route(request):
        if request.url.path == ID + "/backends":
            return httpx.Response(
                200,
                json={
                    "value": [entity("backends/orders", type="Pool", pool={"services": members})]
                },
            )
        return handler(request)

    snapshot = asyncio.run(collection(route))
    inventory = snapshot.instances[0].inventory
    backend = next((item for item in inventory.resources if item.kind == "backend"), None)
    if expected is None:
        assert backend is None
        assert inventory.collections["backends"].status == "partial"
        assert any(warning.code == "INVALID_METADATA" for warning in snapshot.collection_warnings)
    else:
        assert backend.metadata.pool_member_count == expected
    assert SECRET not in snapshot.model_dump_json()
    assert ID + "/backends/a" not in snapshot.model_dump_json()


@pytest.mark.parametrize(
    ("path", "response", "code"),
    [
        ("apis/orders/operations", httpx.Response(403, json={"secret": SECRET}), "HTTP_403"),
        ("policyFragments/auth", httpx.Response(404), "HTTP_404"),
        (
            "apis/orders/policies/policy",
            httpx.Response(200, json={"properties": {"format": "xml-link", "value": SECRET}}),
            "INVALID_POLICY_RESPONSE",
        ),
    ],
)
def test_permission_missing_fragment_and_linked_policy_gaps_are_explicit(path, response, code):
    def route(request):
        if request.url.path == ID + "/" + path:
            return response
        return handler(request)

    snapshot = asyncio.run(collection(route))
    assert any(warning.code == code for warning in snapshot.collection_warnings)
    assert SECRET not in snapshot.model_dump_json()
    rows = [row for row in analyze(snapshot).policy_coverage if row.api_path == "apis/orders"]
    assert all(row.jwt == "unknown" for row in rows)


def test_local_policy_404_is_absence_not_permission_or_list_success():
    def route(request):
        if request.url.path == ID + "/apis/orders/policies/policy":
            return httpx.Response(404)
        if request.url.path == ID + "/workspaces":
            return httpx.Response(404)
        return handler(request)

    snapshot = asyncio.run(collection(route))
    inventory = snapshot.instances[0].inventory
    assert inventory.policies["apis/orders"].status == "absent"
    assert inventory.collections["workspaces"].status == "unavailable"
    assert any(warning.code == "HTTP_404" for warning in snapshot.collection_warnings)
    result = next(item for item in analyze(snapshot).findings if item.rule.id == "APIM-SEC-018")
    assert result.result.outcome == "unknown"


def test_arm_raw_xml_media_bom_and_product_scoped_memberships():
    def route(request):
        if request.url.path == ID + "/policies/policy":
            return httpx.Response(
                200,
                text="\ufeff" + GLOBAL,
                headers={
                    "content-type": "application/vnd.ms-azure-apim.policy.raw+xml; charset=utf-8"
                },
            )
        if request.url.path == ID + "/products/protected/apis":
            return httpx.Response(
                200,
                json={
                    "value": [
                        entity("products/protected/apis/orders"),
                    ]
                },
            )
        return handler(request)

    snapshot = asyncio.run(collection(route))
    inventory = snapshot.instances[0].inventory
    assert inventory.policies[""].status == "available"
    assert inventory.product_apis["products/protected"] == ["apis/orders"]
    assert inventory.collections["products/protected/apis"].status == "complete"
    assert SECRET not in snapshot.model_dump_json()


def test_invalid_list_scope_and_partial_pagination_preserve_observed_resources():
    def route(request):
        if request.url.path == ID + "/apis" and request.url.params.get("page") == "2":
            return httpx.Response(403, json={"private": SECRET})
        if request.url.path == ID + "/namedValues":
            return httpx.Response(200, json={"value": [{"id": ID + "/backends/wrong-kind"}]})
        return handler(request)

    snapshot = asyncio.run(collection(route))
    inventory = snapshot.instances[0].inventory
    assert inventory.collections["apis"].status == "partial"
    assert inventory.collections["apis"].count == 1
    assert inventory.collections["namedValues"].status == "unavailable"
    assert any(item.path == "apis/orders" for item in inventory.resources)
    assert {warning.code for warning in snapshot.collection_warnings} >= {
        "HTTP_403",
        "INVALID_RESOURCE_ID",
    }
    assert SECRET not in snapshot.model_dump_json()


def test_composed_policy_pipeline_and_offline_replay_agree(tmp_path, monkeypatch):
    async def mocked(config):
        return await collection()

    monkeypatch.setattr("apim_assess.cli.collect", mocked)
    runner = CliRunner()
    directory = tmp_path / "assessment"
    result = runner.invoke(
        app,
        [
            "assess",
            "--resource-id",
            ID,
            "--no-metrics",
            "--output-dir",
            str(directory),
        ],
    )
    assert result.exit_code == 0, result.output
    saved = Snapshot.model_validate_json((directory / "snapshot.json").read_text())
    assert saved.schema_version == "1.2"
    assert saved.instances[0].inventory

    def forbidden(*args, **kwargs):
        raise AssertionError("Offline replay attempted Azure access")

    monkeypatch.setattr("apim_assess.collector.apim_core.DefaultAzureCredential", forbidden)
    findings = tmp_path / "offline-findings.json"
    result = runner.invoke(
        app,
        [
            "analyze",
            "--snapshot",
            str(directory / "snapshot.json"),
            "--output",
            str(findings),
        ],
    )
    assert result.exit_code == 0, result.output
    assert findings.read_bytes() == (directory / "findings.json").read_bytes()
    report = tmp_path / "offline-report.html"
    result = runner.invoke(
        app,
        [
            "report",
            "--snapshot",
            str(directory / "snapshot.json"),
            "--findings",
            str(findings),
            "--output",
            str(report),
        ],
    )
    assert result.exit_code == 0, result.output
    assert report.read_bytes() == (directory / "apim-assessment-report.html").read_bytes()
    assert "Effective policy coverage" in report.read_text()
    assert all(SECRET not in file.read_text() for file in directory.iterdir())
