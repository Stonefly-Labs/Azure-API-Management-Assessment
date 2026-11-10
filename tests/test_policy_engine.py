import hashlib
import json

import pytest

from apim_assess.analyzer.engine import EVALUATORS, analyze, scores
from apim_assess.analyzer.policy_resolver import resolve
from apim_assess.artifacts import digest
from apim_assess.collector.sanitizer import (
    MAX_XML_BYTES,
    reference_id,
    sanitize_policy,
)
from apim_assess.models.policy import (
    CollectionCoverage,
    Inventory,
    PolicyDocument,
    ResourceMetadata,
    SubResource,
)
from apim_assess.reporting.generator import render

JWT = (
    '<validate-jwt header-name="Authorization"><openid-config '
    'url="https://login.example.test/.well-known/openid-configuration"/>'
    "</validate-jwt>"
)
RATE = (
    '<rate-limit-by-key calls="10" renewal-period="60" counter-key="@(context.Request.IpAddress)"/>'
)
CORS = (
    '<cors allow-credentials="false"><allowed-origins><origin>https://app.example.test'
    "</origin></allowed-origins></cors>"
)
BACKEND = '<set-backend-service backend-id="orders"/><forward-request/>'
POLICY_IDS = {
    "APIM-SEC-017",
    "APIM-SEC-018",
    "APIM-SEC-019",
    "APIM-SEC-020",
    "APIM-COST-004",
    "APIM-OPS-002",
}


def put(snapshot, path, inbound="", backend="", *, inherit=True, outbound=""):
    base = "<base/>" if path and inherit else ""
    xml = (
        f"<policies><inbound>{base}{inbound}</inbound><backend>{base}{backend}</backend>"
        f"<outbound>{base}{outbound}</outbound><on-error>{base}</on-error></policies>"
    )
    instance = snapshot.instances[0]
    source = instance.resource_id + ("/" + path if path else "") + "/policies/policy"
    instance.inventory.policies[path] = sanitize_policy(source, xml)


def add(snapshot, path, kind, **metadata):
    instance = snapshot.instances[0]
    item = SubResource(
        resource_id=instance.resource_id + "/" + path,
        path=path,
        name=path.rsplit("/", 1)[-1],
        kind=kind,
        metadata=ResourceMetadata(**metadata),
        workspace=path.split("/apis/")[0] if path.startswith("workspaces/") else None,
    )
    instance.inventory.resources.append(item)
    return item


@pytest.fixture
def policy_snapshot(full_snapshot):
    full_snapshot.schema_version = "1.1"
    instance = full_snapshot.instances[0]
    instance.inventory = Inventory(
        collections={
            name: CollectionCoverage(status="complete")
            for name in ("apis", "products", "workspaces", "backends", "apis/orders/operations")
        }
    )
    add(
        full_snapshot,
        "apis/orders",
        "api",
        subscription_required=False,
        service_url_kind="literal",
        api_type="http",
    )
    add(full_snapshot, "apis/orders/operations/get", "operation", method="GET")
    add(full_snapshot, "backends/orders", "backend")
    put(full_snapshot, "", JWT + RATE + CORS, BACKEND)
    put(full_snapshot, "apis/orders")
    put(full_snapshot, "apis/orders/operations/get")
    return full_snapshot


def outcomes(snapshot):
    return {
        finding.rule.id: finding.result.outcome
        for finding in analyze(snapshot).findings
        if finding.rule.id in POLICY_IDS
    }


@pytest.mark.parametrize("rule_id", sorted(POLICY_IDS))
def test_six_rules_dispatch_with_positive_effective_evidence(policy_snapshot, rule_id):
    if rule_id == "APIM-SEC-018":
        policy_snapshot.instances[0].inventory.resources[0].metadata.subscription_required = True
    assert outcomes(policy_snapshot)[rule_id] == "pass"


@pytest.mark.parametrize(
    ("rule_id", "inbound", "backend"),
    [
        ("APIM-SEC-017", RATE + CORS, BACKEND),
        ("APIM-SEC-018", RATE + CORS, BACKEND),
        ("APIM-COST-004", JWT + CORS, BACKEND),
        (
            "APIM-SEC-020",
            JWT + RATE + '<cors allow-credentials="true"><allowed-origins><origin>*'
            "</origin></allowed-origins></cors>",
            BACKEND,
        ),
        ("APIM-OPS-002", JWT + RATE + CORS, "<forward-request/>"),
    ],
)
def test_rule_failures_through_catalog(policy_snapshot, rule_id, inbound, backend):
    if rule_id == "APIM-SEC-018":
        policy_snapshot.instances[0].inventory.resources[0].metadata.subscription_required = True
    put(policy_snapshot, "", inbound, backend)
    assert outcomes(policy_snapshot)[rule_id] == "fail"


def test_omitted_base_discards_inherited_controls_and_reports_provenance(policy_snapshot):
    put(policy_snapshot, "apis/orders", inherit=False)
    results = outcomes(policy_snapshot)
    assert results["APIM-SEC-019"] == "fail"
    assert results["APIM-SEC-017"] == "fail"
    finding = next(
        item for item in analyze(policy_snapshot).findings if item.rule.id == "APIM-SEC-019"
    )
    assert "apis/orders/inbound" in finding.result.evidence[0].detail


def test_all_policy_rules_unknown_for_uncollected_inventory(policy_snapshot):
    policy_snapshot.instances[0].inventory = None
    assert set(outcomes(policy_snapshot).values()) == {"unknown"}


@pytest.mark.parametrize("status", ["unavailable", "partial"])
def test_incomplete_operation_inventory_cannot_establish_missing_or_healthy_controls(
    policy_snapshot, status
):
    inventory = policy_snapshot.instances[0].inventory
    inventory.collections["apis/orders/operations"].status = status
    results = outcomes(policy_snapshot)
    assert results["APIM-SEC-017"] == "unknown"
    assert results["APIM-COST-004"] == "unknown"
    assert results["APIM-OPS-002"] == "unknown"


def test_empty_inventory_is_not_applicable_only_when_enumeration_is_complete(policy_snapshot):
    inventory = policy_snapshot.instances[0].inventory
    inventory.resources = []
    assert set(outcomes(policy_snapshot).values()) == {"not_applicable"}
    inventory.collections["workspaces"].status = "unavailable"
    assert set(outcomes(policy_snapshot).values()) == {"unknown"}


def test_absent_local_policy_inherits_but_unavailable_policy_is_unknown(policy_snapshot):
    inventory = policy_snapshot.instances[0].inventory
    source = inventory.policies["apis/orders"].source
    inventory.policies["apis/orders"] = PolicyDocument(source=source, status="absent")
    assert outcomes(policy_snapshot)["APIM-SEC-017"] == "pass"
    inventory.policies["apis/orders"] = PolicyDocument(source=source, status="unavailable")
    assert outcomes(policy_snapshot)["APIM-SEC-017"] == "unknown"


def test_fragment_expansion_and_unresolved_references(policy_snapshot):
    inventory = policy_snapshot.instances[0].inventory
    key = "policyFragments/" + reference_id("auth")
    inventory.fragments[key] = sanitize_policy(
        policy_snapshot.instances[0].resource_id + "/policyFragments/auth",
        "<fragment>" + JWT + "</fragment>",
        fragment=True,
    )
    put(policy_snapshot, "", '<include-fragment fragment-id="auth"/>' + RATE + CORS, BACKEND)
    assert outcomes(policy_snapshot)["APIM-SEC-017"] == "pass"
    finding = next(
        item for item in analyze(policy_snapshot).findings if item.rule.id == "APIM-SEC-017"
    )
    assert inventory.fragments[key].source in finding.result.evidence[0].detail
    del inventory.fragments[key]
    assert outcomes(policy_snapshot)["APIM-SEC-017"] == "unknown"


def test_nested_and_cyclic_fragments_are_invalid_not_silently_expanded(policy_snapshot):
    inventory = policy_snapshot.instances[0].inventory
    for name, other in [("a", "b"), ("b", "a")]:
        inventory.fragments["policyFragments/" + reference_id(name)] = sanitize_policy(
            name, f'<fragment><include-fragment fragment-id="{other}"/></fragment>', fragment=True
        )
    put(policy_snapshot, "", '<include-fragment fragment-id="a"/>', BACKEND)
    assert outcomes(policy_snapshot)["APIM-SEC-017"] == "unknown"


def test_conditionals_require_protection_on_every_possible_branch(policy_snapshot):
    choose = f'<choose><when condition="@(true)">{JWT}</when></choose>'
    put(policy_snapshot, "", choose + RATE + CORS, BACKEND)
    assert outcomes(policy_snapshot)["APIM-SEC-017"] == "unknown"
    choose = f'<choose><when condition="@(true)">{JWT}</when><otherwise>{JWT}</otherwise></choose>'
    put(policy_snapshot, "", choose + RATE + CORS, BACKEND)
    assert outcomes(policy_snapshot)["APIM-SEC-017"] == "pass"


def test_return_before_validator_is_not_credited(policy_snapshot):
    put(policy_snapshot, "", "<return-response/>" + JWT + RATE + CORS, BACKEND)
    assert outcomes(policy_snapshot)["APIM-SEC-017"] == "fail"
    put(
        policy_snapshot,
        "",
        '<choose><when condition="@(true)"><return-response/></when></choose>' + JWT,
        BACKEND,
    )
    assert outcomes(policy_snapshot)["APIM-SEC-017"] == "unknown"


def test_oauth_portal_and_outbound_managed_identity_do_not_validate_callers(policy_snapshot):
    policy_snapshot.instances[0].inventory.resources[0].metadata.oauth_configured = True
    put(
        policy_snapshot,
        "",
        '<authentication-managed-identity resource="https://example.test"/>' + RATE + CORS,
        BACKEND,
    )
    assert outcomes(policy_snapshot)["APIM-SEC-017"] == "fail"


@pytest.mark.parametrize(
    ("policy", "expected"),
    [
        ("<validate-client-certificate/>", "pass"),
        ('<validate-client-certificate ignore-error="true"/>', "fail"),
        ('<validate-client-certificate validate-trust="false"/>', "unknown"),
        ('<validate-azure-ad-token tenant-id="00000000-0000-0000-0000-000000000001"/>', "pass"),
        ('<validate-jwt header-name="Authorization" require-signed-tokens="false"/>', "unknown"),
    ],
)
def test_authentication_configuration_boundaries(policy_snapshot, policy, expected):
    put(policy_snapshot, "", policy + RATE + CORS, BACKEND)
    assert outcomes(policy_snapshot)["APIM-SEC-017"] == expected


def test_certificate_authentication_is_not_mislabeled_as_subscription_keys_only(policy_snapshot):
    policy_snapshot.instances[0].inventory.resources[0].metadata.subscription_required = True
    put(policy_snapshot, "", "<validate-client-certificate/>" + RATE + CORS, BACKEND)
    assert outcomes(policy_snapshot)["APIM-SEC-018"] == "not_applicable"


def test_product_controls_are_not_union_applied_to_api_subscription_context(policy_snapshot):
    inventory = policy_snapshot.instances[0].inventory
    inventory.resources[0].metadata.subscription_required = True
    add(policy_snapshot, "products/protected", "product", subscription_required=True)
    inventory.product_apis["products/protected"] = ["apis/orders"]
    inventory.collections["products/protected/apis"] = CollectionCoverage(status="complete")
    put(policy_snapshot, "", RATE + CORS, BACKEND)
    put(policy_snapshot, "products/protected", JWT)
    assessment = analyze(policy_snapshot)
    assert len(assessment.policy_coverage) == 2
    assert {row.jwt for row in assessment.policy_coverage} == {"present", "absent"}
    assert outcomes(policy_snapshot)["APIM-SEC-018"] == "fail"
    assert len(assessment.findings) == 11  # Contexts do not inflate scores.


def test_open_product_creates_anonymous_context_even_when_api_requires_key(policy_snapshot):
    inventory = policy_snapshot.instances[0].inventory
    inventory.resources[0].metadata.subscription_required = True
    add(policy_snapshot, "products/open", "product", subscription_required=False)
    inventory.product_apis["products/open"] = ["apis/orders"]
    inventory.collections["products/open/apis"] = CollectionCoverage(status="complete")
    put(policy_snapshot, "", RATE + CORS, BACKEND)
    put(policy_snapshot, "products/open")
    assert outcomes(policy_snapshot)["APIM-SEC-017"] == "fail"
    row = next(row for row in analyze(policy_snapshot).policy_coverage if row.product_path)
    assert row.subscription_required is False
    put(policy_snapshot, "products/open", JWT)
    assert outcomes(policy_snapshot)["APIM-SEC-017"] == "pass"


def test_ignored_keys_do_not_apply_protected_product_policies_to_public_api(policy_snapshot):
    inventory = policy_snapshot.instances[0].inventory
    add(policy_snapshot, "products/protected", "product", subscription_required=True)
    inventory.product_apis["products/protected"] = ["apis/orders"]
    inventory.collections["products/protected/apis"] = CollectionCoverage(status="complete")
    put(policy_snapshot, "products/protected", JWT)
    assert len(resolve(policy_snapshot.instances[0])) == 1
    assert resolve(policy_snapshot.instances[0])[0].product_path is None


def test_first_cors_and_base_order_control_result(policy_snapshot):
    wildcard = (
        '<cors allow-credentials="true"><allowed-origins><origin>*'
        "</origin></allowed-origins></cors>"
    )
    put(policy_snapshot, "apis/orders", wildcard)
    assert outcomes(policy_snapshot)["APIM-SEC-020"] == "pass"  # Parent CORS executes first.
    document = policy_snapshot.instances[0].inventory.policies["apis/orders"]
    document.xml = document.xml.replace("<inbound><base />", "<inbound>").replace(
        "</cors></inbound>", "</cors><base /></inbound>"
    )
    assert outcomes(policy_snapshot)["APIM-SEC-020"] == "fail"
    put(
        policy_snapshot,
        "",
        JWT + '<cors><allowed-origins><origin>@(context.Request.Headers["Origin"])'
        "</origin></allowed-origins></cors>",
        BACKEND,
    )
    put(policy_snapshot, "apis/orders")
    assert outcomes(policy_snapshot)["APIM-SEC-020"] == "unknown"


def test_explicit_options_operation_prevents_cors_assurance(policy_snapshot):
    policy_snapshot.instances[0].inventory.resources[1].metadata.method = "OPTIONS"
    assert outcomes(policy_snapshot)["APIM-SEC-020"] == "unknown"


def test_concurrency_must_enclose_forwarding_and_consumption_by_key_is_unsupported(policy_snapshot):
    put(
        policy_snapshot,
        "",
        JWT + CORS,
        '<limit-concurrency key="shared" max-count="3"><forward-request/></limit-concurrency>',
    )
    assert outcomes(policy_snapshot)["APIM-COST-004"] == "pass"
    put(policy_snapshot, "", JWT + CORS + '<limit-concurrency key="x" max-count="3"/>', BACKEND)
    assert outcomes(policy_snapshot)["APIM-COST-004"] == "unknown"
    policy_snapshot.instances[0].sku.name = "Consumption"
    put(policy_snapshot, "", JWT + RATE + CORS, BACKEND)
    assert outcomes(policy_snapshot)["APIM-COST-004"] == "unsupported"


def test_dynamic_or_conditional_limits_cannot_establish_fixed_load_protection(policy_snapshot):
    put(policy_snapshot, "", JWT + RATE.replace('calls="10"', 'calls="@(10)"'), BACKEND)
    assert outcomes(policy_snapshot)["APIM-COST-004"] == "unknown"
    put(
        policy_snapshot,
        "",
        JWT + RATE.replace('calls="10"', 'calls="10" increment-condition="@(false)"'),
        BACKEND,
    )
    assert outcomes(policy_snapshot)["APIM-COST-004"] == "unknown"


def test_backend_resolution_honors_last_override_and_forwarding_order(policy_snapshot):
    put(
        policy_snapshot,
        "",
        JWT + RATE + CORS,
        '<set-backend-service base-url="https://first.example.test"/>'
        '<set-backend-service backend-id="orders"/><forward-request/>',
    )
    assert outcomes(policy_snapshot)["APIM-OPS-002"] == "pass"
    put(
        policy_snapshot,
        "",
        JWT + RATE + CORS,
        '<choose><when condition="@(true)"><forward-request/></when></choose>' + BACKEND,
    )
    assert outcomes(policy_snapshot)["APIM-OPS-002"] == "unknown"
    put(
        policy_snapshot,
        "",
        JWT + RATE + CORS,
        '<set-backend-service backend-id="{{dynamic-backend}}"/><forward-request/>',
    )
    assert outcomes(policy_snapshot)["APIM-OPS-002"] == "unknown"


def test_workspace_policy_and_fragment_do_not_leak_into_service_or_other_workspaces(
    policy_snapshot,
):
    inventory = policy_snapshot.instances[0].inventory
    api = inventory.resources[0]
    api.path = "workspaces/team/apis/orders"
    api.resource_id = policy_snapshot.instances[0].resource_id + "/" + api.path
    api.workspace = "workspaces/team"
    inventory.resources = [api]
    add(policy_snapshot, "workspaces/team", "workspace")
    for collection in ("apis", "products", "backends", "apis/orders/operations"):
        inventory.collections["workspaces/team/" + collection] = CollectionCoverage(
            status="complete"
        )
    put(policy_snapshot, "", RATE + CORS, "<forward-request/>")
    put(policy_snapshot, "workspaces/team", '<include-fragment fragment-id="auth"/>')
    put(policy_snapshot, api.path)
    inventory.fragments["policyFragments/" + reference_id("auth")] = sanitize_policy(
        "service-fragment", "<fragment>" + JWT + "</fragment>", fragment=True
    )
    assert outcomes(policy_snapshot)["APIM-SEC-017"] == "unknown"
    inventory.fragments["workspaces/team/policyFragments/" + reference_id("auth")] = (
        inventory.fragments["policyFragments/" + reference_id("auth")].model_copy()
    )
    assert outcomes(policy_snapshot)["APIM-SEC-017"] == "pass"


@pytest.mark.parametrize(
    "xml",
    [
        '<!DOCTYPE policies [<!ENTITY x "sensitive">]><policies><inbound>&x;</inbound></policies>',
        '<!DOCTYPE policies SYSTEM "file:///C:/sensitive"><policies/>',
        "<policies><inbound>",
        "<fragment/>",
        "<policies>" + "x" * MAX_XML_BYTES + "</policies>",
        "<policies><inbound>" + "<choose>" * 80 + "</choose>" * 80 + "</inbound></policies>",
    ],
)
def test_unsafe_malformed_or_oversized_xml_is_unavailable(xml):
    document = sanitize_policy("synthetic-policy", xml)
    assert document.status == "unavailable"
    assert document.xml is None
    assert document.error_code


def test_policy_redaction_covers_text_attributes_expressions_comments_and_signing_material():
    secret = "SENSITIVE_TEST_SENTINEL_NOT_A_REAL_SECRET"
    document = sanitize_policy(
        "synthetic-policy",
        f'<policies><!--{secret}--><inbound><authentication-basic username="{secret}" '
        f'password="{secret}"/><set-header name="Authorization"><value>Bearer {secret}'
        f'</value></set-header><set-body>{secret}</set-body><set-variable name="x" '
        f'value="@(&quot;{secret}&quot;)"/><validate-jwt token-value="{secret}">'
        f"<issuer-signing-keys><key>{secret}</key></issuer-signing-keys></validate-jwt>"
        f'<set-backend-service base-url="https://example.test/?api_key={secret}"/>'
        "</inbound></policies>",
    )
    assert document.status == "available"
    assert document.has_inline_secret_pattern
    assert secret not in document.model_dump_json()
    assert "REDACTED_SECRET" in document.xml


def test_policy_matrix_is_escaped_and_tampered_coverage_is_rejected(policy_snapshot):
    document = policy_snapshot.instances[0].inventory.policies[""]
    document.source += '<script>alert("x")</script>'
    assessment = analyze(policy_snapshot)
    html = render(policy_snapshot, assessment)
    assert "Effective policy coverage" in html
    assert '<script>alert("x")</script>' not in html
    assert "&lt;script&gt;" in html
    assert "pageCount" in html
    assessment.policy_coverage[0].jwt = "absent"
    with pytest.raises(ValueError, match="Policy coverage"):
        render(policy_snapshot, assessment)


def test_fragment_expansion_budget_cannot_be_bypassed_by_repeated_includes(
    policy_snapshot, monkeypatch
):
    monkeypatch.setattr(
        "apim_assess.analyzer.policy_resolver._ExpansionBudget",
        lambda: type("Budget", (), {"remaining": 12})(),
    )
    inventory = policy_snapshot.instances[0].inventory
    inventory.fragments["policyFragments/" + reference_id("auth")] = sanitize_policy(
        "synthetic-fragment", "<fragment>" + CORS + RATE + "</fragment>", fragment=True
    )
    put(
        policy_snapshot,
        "",
        '<include-fragment fragment-id="auth"/>' * 5 + JWT,
        BACKEND,
    )
    assert outcomes(policy_snapshot)["APIM-SEC-017"] == "unknown"


def test_subscription_rate_limit_requires_key_and_valid_scope(policy_snapshot):
    policy_snapshot.instances[0].inventory.resources[0].metadata.subscription_required = True
    rate = '<rate-limit calls="10" renewal-period="60"/>'
    put(policy_snapshot, "", JWT + CORS, BACKEND)
    put(policy_snapshot, "apis/orders", rate)
    assert outcomes(policy_snapshot)["APIM-COST-004"] == "pass"
    policy_snapshot.instances[0].inventory.resources[0].metadata.subscription_required = False
    assert outcomes(policy_snapshot)["APIM-COST-004"] == "unknown"
    policy_snapshot.instances[0].inventory.resources[0].metadata.subscription_required = True
    put(policy_snapshot, "apis/orders")
    put(policy_snapshot, "", JWT + CORS + rate, BACKEND)
    assert outcomes(policy_snapshot)["APIM-COST-004"] == "unknown"


def test_omitted_api_type_uses_explicit_http_transport_without_inventing_type(policy_snapshot):
    api = policy_snapshot.instances[0].inventory.resources[0]
    api.metadata.api_type = None
    api.metadata.protocols = ["https"]
    assert outcomes(policy_snapshot)["APIM-SEC-017"] == "pass"
    assert analyze(policy_snapshot).policy_coverage[0].http_gateway_only
    assert api.metadata.api_type is None
    api.metadata.protocols = None
    assert outcomes(policy_snapshot)["APIM-SEC-017"] == "unknown"
    api.metadata.protocols = ["wss"]
    assert outcomes(policy_snapshot)["APIM-SEC-017"] == "unknown"


def test_unknown_sku_cannot_establish_rate_by_key_support(policy_snapshot):
    policy_snapshot.instances[0].sku.name = "FutureSku"
    assert outcomes(policy_snapshot)["APIM-COST-004"] == "unknown"


def test_product_membership_applies_to_noncurrent_api_revisions(policy_snapshot):
    inventory = policy_snapshot.instances[0].inventory
    inventory.resources[0].metadata.subscription_required = True
    add(
        policy_snapshot,
        "apis/orders;rev=2",
        "api",
        subscription_required=True,
        service_url_kind="literal",
        api_type="http",
    )
    add(policy_snapshot, "apis/orders;rev=2/operations/get", "operation", method="GET")
    add(policy_snapshot, "products/protected", "product", subscription_required=True)
    inventory.product_apis["products/protected"] = ["apis/orders"]
    for path in ("products/protected/apis", "apis/orders;rev=2/operations"):
        inventory.collections[path] = CollectionCoverage(status="complete")
    put(policy_snapshot, "products/protected", JWT)
    put(policy_snapshot, "apis/orders;rev=2")
    put(policy_snapshot, "apis/orders;rev=2/operations/get")
    rows = analyze(policy_snapshot).policy_coverage
    assert {row.api_path for row in rows if row.product_path == "products/protected"} == {
        "apis/orders",
        "apis/orders;rev=2",
    }


def test_inherited_backend_reference_keeps_its_declaring_namespace(policy_snapshot):
    inventory = policy_snapshot.instances[0].inventory
    api = inventory.resources[0]
    api.path = "workspaces/team/apis/orders"
    api.resource_id = policy_snapshot.instances[0].resource_id + "/" + api.path
    api.workspace = "workspaces/team"
    service_backend = next(item for item in inventory.resources if item.kind == "backend")
    inventory.resources = [api, service_backend]
    add(policy_snapshot, "workspaces/team", "workspace")
    for collection in ("apis", "products", "backends", "apis/orders/operations"):
        inventory.collections["workspaces/team/" + collection] = CollectionCoverage(
            status="complete"
        )
    put(policy_snapshot, "workspaces/team")
    put(policy_snapshot, api.path)
    assert outcomes(policy_snapshot)["APIM-OPS-002"] == "pass"
    inventory.resources.remove(service_backend)
    scoped_backend = add(policy_snapshot, "workspaces/team/backends/orders", "backend")
    scoped_backend.workspace = "workspaces/team"
    assert outcomes(policy_snapshot)["APIM-OPS-002"] == "unknown"
    put(policy_snapshot, "workspaces/team", backend='<set-backend-service backend-id="orders"/>')
    assert outcomes(policy_snapshot)["APIM-OPS-002"] == "unknown"  # Parent forward ran first.


def test_legacy_digest_and_findings_still_render_without_reinterpreting_scores(snapshot):
    # Schema 1.0 serialized instances predate inventory. Their exact hash contract is retained.
    legacy_json = snapshot.model_dump_json(exclude={"instances": {"__all__": {"inventory"}}})
    expected = hashlib.sha256(legacy_json.encode()).hexdigest()
    assert digest(snapshot) == expected
    assessment = analyze(snapshot)
    assessment.schema_version = "1.0"
    assessment.findings = [
        item for item in assessment.findings if item.rule.evaluator in EVALUATORS
    ]
    assessment.pillar_scores = scores(assessment.findings)
    assert len(assessment.findings) == 15
    assert "Portfolio readout" in render(snapshot, assessment)
    data = json.loads(snapshot.model_dump_json())
    data["instances"][0]["inventory"] = {}
    with pytest.raises(ValueError, match="requires snapshot schema 1.1"):
        snapshot.model_validate(data)
