import hashlib
from datetime import date, timedelta

import pytest
from pydantic import ValidationError

from apim_assess.analyzer.engine import (
    ITERATION_2_IDS,
    analyze,
    load_rules,
    mcsb_coverage,
    mcsb_score,
    scores,
)
from apim_assess.artifacts import digest
from apim_assess.collector.apim_core import SAFE_CUSTOM_PROPERTIES
from apim_assess.collector.sanitizer import reference_id, sanitize_policy
from apim_assess.models.findings import RuleSettings, Thresholds, Waiver
from apim_assess.models.policy import (
    CATALOG_METADATA_FIELDS,
    CollectionCoverage,
    Inventory,
    ResourceMetadata,
    SubResource,
)
from apim_assess.models.snapshot import HostCertificate, Region, ServiceSettings, Sku
from apim_assess.reporting.generator import render


def add(snapshot, path, kind, **metadata):
    instance = snapshot.instances[0]
    item = SubResource(
        resource_id=instance.resource_id + "/" + path,
        path=path,
        name=path.rsplit("/", 1)[-1],
        kind=kind,
        workspace="/".join(path.split("/")[:2]) if path.startswith("workspaces/") else None,
        metadata=ResourceMetadata(**metadata),
    )
    instance.inventory.resources.append(item)
    return item


def put(snapshot, path="", *, inbound="", backend="", outbound="", on_error=""):
    base = "<base/>" if path else ""
    xml = (
        f"<policies><inbound>{base}{inbound}</inbound><backend>{base}{backend}</backend>"
        f"<outbound>{base}{outbound}</outbound><on-error>{base}{on_error}</on-error></policies>"
    )
    instance = snapshot.instances[0]
    source = instance.resource_id + "/" + (path + "/" if path else "") + "policies/policy"
    instance.inventory.policies[path] = sanitize_policy(source, xml)


@pytest.fixture
def catalog_snapshot(full_snapshot):
    full_snapshot.schema_version = "1.2"
    instance = full_snapshot.instances[0]
    instance.service_settings = ServiceSettings()
    instance.inventory = Inventory(
        collections={
            name: CollectionCoverage(status="complete")
            for name in (
                "apis",
                "products",
                "workspaces",
                "backends",
                "namedValues",
                "certificates",
                "subscriptions",
                "diagnostics",
                "loggers",
                "policyFragments",
                "apis/orders/operations",
                "apis/orders/diagnostics",
            )
        }
    )
    add(
        full_snapshot,
        "apis/orders",
        "api",
        api_type="http",
        protocols=["https"],
        subscription_required=True,
        version_set=False,
        api_route_hash=reference_id("orders"),
    )
    add(full_snapshot, "apis/orders/operations/get", "operation", method="GET")
    put(full_snapshot, backend="<forward-request/>")
    put(full_snapshot, "apis/orders")
    put(full_snapshot, "apis/orders/operations/get")
    return full_snapshot


def finding(snapshot, rule_id, settings=None):
    return next(item for item in analyze(snapshot, settings).findings if item.rule.id == rule_id)


@pytest.mark.parametrize(("capacity", "outcome"), [(1, "fail"), (2, "pass"), (None, "unknown")])
def test_scale_units(catalog_snapshot, capacity, outcome):
    catalog_snapshot.instances[0].sku.capacity = capacity
    assert finding(catalog_snapshot, "APIM-REL-003").result.outcome == outcome


def test_regions_capability_and_environment(catalog_snapshot):
    instance = catalog_snapshot.instances[0]
    assert finding(catalog_snapshot, "APIM-REL-006").result.outcome == "fail"
    instance.additional_locations = [Region(location="westus2", capacity=2)]
    assert finding(catalog_snapshot, "APIM-REL-006").result.outcome == "pass"
    instance.sku = Sku(name="StandardV2", capacity=2)
    assert finding(catalog_snapshot, "APIM-REL-006").result.outcome == "unsupported"
    instance.environment = "non-prod"
    assert finding(catalog_snapshot, "APIM-REL-006").result.outcome == "not_applicable"


@pytest.mark.parametrize(
    ("enabled", "outcome"), [(False, "fail"), (True, "pass"), (None, "unknown")]
)
def test_backend_breakers_and_partial_coverage(catalog_snapshot, enabled, outcome):
    add(catalog_snapshot, "backends/orders", "backend", circuit_breaker_present=enabled)
    assert finding(catalog_snapshot, "APIM-REL-007").result.outcome == outcome
    catalog_snapshot.instances[0].inventory.collections["backends"].status = "partial"
    assert finding(catalog_snapshot, "APIM-REL-007").result.outcome == (
        "fail" if enabled is False else "unknown"
    )
    catalog_snapshot.instances[0].sku = Sku(name="Consumption")
    assert finding(catalog_snapshot, "APIM-REL-007").result.outcome == "unsupported"


@pytest.mark.parametrize(
    ("rule_id", "pattern"),
    [
        ("APIM-SEC-006", "Protocols."),
        ("APIM-SEC-007", ".Ciphers."),
    ],
)
def test_explicit_transport_flags_do_not_invent_defaults(catalog_snapshot, rule_id, pattern):
    instance = catalog_snapshot.instances[0]
    keys = [key for key in SAFE_CUSTOM_PROPERTIES if pattern in key and not key.endswith("Http2")]
    instance.custom_properties = {key: False for key in keys}
    assert finding(catalog_snapshot, rule_id).result.outcome == "pass"
    instance.custom_properties[keys[0]] = True
    assert finding(catalog_snapshot, rule_id).result.outcome == "fail"
    instance.custom_properties = {}
    assert finding(catalog_snapshot, rule_id).result.outcome == "unknown"


@pytest.mark.parametrize(
    ("protocols", "outcome"),
    [
        (["http", "https"], "fail"),
        (["ws"], "fail"),
        (["https"], "pass"),
        (["wss"], "pass"),
        (None, "unknown"),
        ([], "unknown"),
    ],
)
def test_api_transport(catalog_snapshot, protocols, outcome):
    catalog_snapshot.instances[0].inventory.resources[0].metadata.protocols = protocols
    assert finding(catalog_snapshot, "APIM-SEC-008").result.outcome == outcome


@pytest.mark.parametrize(
    ("enabled", "outcome"), [(True, "fail"), (False, "pass"), (None, "unknown")]
)
def test_direct_management_is_only_configuration(catalog_snapshot, enabled, outcome):
    catalog_snapshot.instances[0].service_settings.management_api_enabled = enabled
    result = finding(catalog_snapshot, "APIM-SEC-009").result
    assert result.outcome == outcome
    assert "does not prove a reachable endpoint" in result.summary


@pytest.mark.parametrize(
    ("version", "outcome"),
    [
        (date(2019, 11, 1), "fail"),
        (date(2019, 12, 1), "pass"),
        (None, "unknown"),
    ],
)
def test_control_plane_version_floor(catalog_snapshot, version, outcome):
    catalog_snapshot.instances[0].service_settings.minimum_api_version = version
    assert finding(catalog_snapshot, "APIM-SEC-010").result.outcome == outcome


@pytest.mark.parametrize(
    ("identity", "outcome"),
    [
        ("None", "fail"),
        ("SystemAssigned", "pass"),
        ("UserAssigned", "pass"),
        (None, "unknown"),
    ],
)
def test_identity_configuration(catalog_snapshot, identity, outcome):
    catalog_snapshot.instances[0].identity_type = identity
    assert finding(catalog_snapshot, "APIM-SEC-011").result.outcome == outcome


@pytest.mark.parametrize(
    ("secret", "vault", "rule_id", "outcome"),
    [
        (True, False, "APIM-SEC-012", "fail"),
        (True, True, "APIM-SEC-012", "pass"),
        (True, None, "APIM-SEC-012", "unknown"),
        (False, True, "APIM-SEC-013", "fail"),
        (False, False, "APIM-SEC-013", "pass"),
        (None, True, "APIM-SEC-013", "unknown"),
    ],
)
def test_named_value_metadata(catalog_snapshot, secret, vault, rule_id, outcome):
    add(catalog_snapshot, "namedValues/config", "named_value", secret=secret, key_vault=vault)
    assert finding(catalog_snapshot, rule_id).result.outcome == outcome


@pytest.mark.parametrize(
    ("source", "days", "outcome"),
    [
        ("Custom", 90, "fail"),
        ("KeyVault", 30, "fail"),
        ("KeyVault", 31, "pass"),
        ("KeyVault", None, "unknown"),
        ("Managed", 90, "pass"),
        ("BuiltIn", None, "not_applicable"),
    ],
)
def test_certificate_rotation_expiry_and_boundary(catalog_snapshot, source, days, outcome):
    expiry = catalog_snapshot.collected_at + timedelta(days=days) if days is not None else None
    catalog_snapshot.instances[0].service_settings.certificates = [
        HostCertificate(endpoint="Proxy", source=source, expires_at=expiry)
    ]
    assert finding(catalog_snapshot, "APIM-SEC-014").result.outcome == outcome


def test_inline_secret_evidence_never_contains_literal(catalog_snapshot):
    put(
        catalog_snapshot,
        inbound='<set-header name="Authorization">'
        "<value>Bearer PRIVATE_SENTINEL</value></set-header>",
    )
    assessment = analyze(catalog_snapshot)
    assert (
        next(item for item in assessment.findings if item.rule.id == "APIM-SEC-015").result.outcome
        == "fail"
    )
    assert "PRIVATE_SENTINEL" not in catalog_snapshot.model_dump_json()
    assert "PRIVATE_SENTINEL" not in assessment.model_dump_json()
    put(catalog_snapshot)
    assert finding(catalog_snapshot, "APIM-SEC-015").result.outcome == "pass"
    catalog_snapshot.instances[0].inventory.policies[""].status = "unavailable"
    assert finding(catalog_snapshot, "APIM-SEC-015").result.outcome == "unknown"


@pytest.mark.parametrize(
    ("scope", "outcome"),
    [
        ("all_apis", "fail"),
        ("api", "pass"),
        ("product", "pass"),
        ("unknown", "unknown"),
    ],
)
def test_subscription_classification(catalog_snapshot, scope, outcome):
    add(catalog_snapshot, "subscriptions/key", "subscription", subscription_scope=scope)
    assert finding(catalog_snapshot, "APIM-SEC-016").result.outcome == outcome


@pytest.mark.parametrize(
    ("chain", "name", "outcome"),
    [
        (False, True, "fail"),
        (True, False, "fail"),
        (True, True, "pass"),
        (None, True, "unknown"),
    ],
)
def test_backend_tls_validation(catalog_snapshot, chain, name, outcome):
    add(
        catalog_snapshot,
        "backends/orders",
        "backend",
        validate_certificate_chain=chain,
        validate_certificate_name=name,
    )
    assert finding(catalog_snapshot, "APIM-SEC-021").result.outcome == outcome


@pytest.mark.parametrize(
    ("signin", "signup", "entra", "outcome"),
    [
        (False, False, True, "fail"),
        (True, True, False, "fail"),
        (True, False, None, "pass"),
        (True, True, True, "pass"),
        (None, False, True, "unknown"),
    ],
)
def test_developer_portal_configuration(catalog_snapshot, signin, signup, entra, outcome):
    settings = catalog_snapshot.instances[0].service_settings
    settings.portal_signin_required = signin
    settings.portal_signup_enabled = signup
    settings.portal_entra_enabled = entra
    assert finding(catalog_snapshot, "APIM-SEC-022").result.outcome == outcome
    settings.portal_enabled = False
    assert finding(catalog_snapshot, "APIM-SEC-022").result.outcome == "not_applicable"


def test_external_and_obsolete_signals_are_not_passes(catalog_snapshot):
    assert finding(catalog_snapshot, "APIM-REL-011").result.outcome == "unknown"
    assert finding(catalog_snapshot, "APIM-SEC-023").result.outcome == "unsupported"
    catalog_snapshot.instances[0].environment = "non-prod"
    assert finding(catalog_snapshot, "APIM-SEC-023").result.outcome == "not_applicable"


def test_nonprod_cost_profile_and_severity(catalog_snapshot):
    instance = catalog_snapshot.instances[0]
    assert finding(catalog_snapshot, "APIM-COST-002").result.outcome == "not_applicable"
    instance.environment = "non-prod"
    assert finding(catalog_snapshot, "APIM-COST-002").result.outcome == "fail"
    instance.sku = Sku(name="Basic", capacity=1)
    assert finding(catalog_snapshot, "APIM-COST-002").result.outcome == "pass"
    assert finding(catalog_snapshot, "APIM-REL-003").severity == "Advisory"


@pytest.mark.parametrize(
    ("percentage", "always", "body", "outcome"),
    [
        (50, False, None, "pass"),
        (50.1, False, None, "fail"),
        (None, False, 0, "unknown"),
        (10, True, 1024, "pass"),
        (10, True, 1025, "fail"),
        (10, True, None, "unknown"),
    ],
)
def test_diagnostic_sampling_and_body_budgets(catalog_snapshot, percentage, always, body, outcome):
    add(catalog_snapshot, "loggers/custom-name", "logger", application_insights=True)
    diagnostic = add(
        catalog_snapshot,
        "diagnostics/applicationinsights",
        "diagnostic",
        sampling_percentage=percentage,
        always_log_errors=always,
        body_bytes=body,
        logger_reference_hash=reference_id("custom-name"),
    )
    assert finding(catalog_snapshot, "APIM-PERF-002").result.outcome == outcome
    diagnostic.metadata.logger_reference_hash = reference_id("uncollected")
    assert finding(catalog_snapshot, "APIM-PERF-002").result.outcome == "unknown"


@pytest.mark.parametrize(
    ("backend", "on_error", "rel9", "rel10"),
    [
        ("<forward-request/>", "", "fail", "fail"),
        ('<forward-request timeout="20"/>', '<set-status code="502"/>', "pass", "pass"),
        (
            '<retry count="3" interval="2" condition="@(true)"><forward-request/></retry>',
            '<choose><when condition="@(true)"><set-status code="502"/></when></choose>',
            "unknown",
            "pass",
        ),
    ],
)
def test_inherited_resilience_and_conditional_paths(
    catalog_snapshot, backend, on_error, rel9, rel10
):
    put(catalog_snapshot, backend=backend, on_error=on_error)
    assert finding(catalog_snapshot, "APIM-REL-009").result.outcome == rel9
    assert finding(catalog_snapshot, "APIM-REL-010").result.outcome == rel10


def test_pool_routing_honors_forwarding_order(catalog_snapshot):
    add(catalog_snapshot, "backends/pool", "backend", backend_pool=True, pool_member_count=2)
    put(catalog_snapshot, backend='<set-backend-service backend-id="pool"/><forward-request/>')
    assert finding(catalog_snapshot, "APIM-REL-008").result.outcome == "pass"
    put(catalog_snapshot, backend='<forward-request/><set-backend-service backend-id="pool"/>')
    assert finding(catalog_snapshot, "APIM-REL-008").result.outcome != "pass"
    put(catalog_snapshot, backend='<set-backend-service backend-id="pool"/><forward-request/>')
    catalog_snapshot.instances[0].inventory.resources[-1].metadata.pool_member_count = 1
    assert finding(catalog_snapshot, "APIM-REL-008").result.outcome == "fail"


def test_header_suppression_uses_final_action_and_excludes_server(catalog_snapshot):
    headers = (
        '<set-header name="X-Powered-By" exists-action="delete"/>'
        '<set-header name="X-AspNet-Version" exists-action="delete"/>'
    )
    put(catalog_snapshot, outbound=headers)
    result = finding(catalog_snapshot, "APIM-SEC-024").result
    assert result.outcome == "pass"
    assert "cannot delete the Server" in result.summary
    put(
        catalog_snapshot,
        outbound=headers + '<set-header name="X-Powered-By"><value>value</value></set-header>',
    )
    assert finding(catalog_snapshot, "APIM-SEC-024").result.outcome == "fail"
    put(
        catalog_snapshot,
        outbound='<choose><when condition="@(true)">' + headers + "</when></choose>",
    )
    assert finding(catalog_snapshot, "APIM-SEC-024").result.outcome == "unknown"


@pytest.mark.parametrize(
    ("limit", "action", "outcome"),
    [
        (102400, "prevent", "pass"),
        (102401, "prevent", "fail"),
        (102400, "detect", "fail"),
        ("@(1024)", "prevent", "unknown"),
    ],
)
def test_payload_limits_are_preventing_and_threshold_aware(
    catalog_snapshot, limit, action, outcome
):
    catalog_snapshot.instances[0].inventory.resources[1].metadata.method = "POST"
    put(
        catalog_snapshot,
        inbound=f'<validate-content max-size="{limit}" size-exceeded-action="{action}"/>',
    )
    assert finding(catalog_snapshot, "APIM-PERF-003").result.outcome == outcome


def test_response_cache_does_not_assume_get_is_cacheable(catalog_snapshot):
    assert finding(catalog_snapshot, "APIM-PERF-004").result.outcome == "unknown"
    put(catalog_snapshot, inbound="<cache-lookup/>", outbound='<cache-store duration="60"/>')
    assert finding(catalog_snapshot, "APIM-PERF-004").result.outcome == "pass"
    catalog_snapshot.instances[0].sku = Sku(name="Consumption")
    assert finding(catalog_snapshot, "APIM-PERF-004").result.outcome == "unknown"
    put(
        catalog_snapshot,
        inbound='<cache-lookup caching-type="internal"/>',
        outbound='<cache-store duration="60"/>',
    )
    assert finding(catalog_snapshot, "APIM-PERF-004").result.outcome == "unsupported"


def test_empty_product_requires_complete_membership(catalog_snapshot):
    add(catalog_snapshot, "products/empty", "product")
    inventory = catalog_snapshot.instances[0].inventory
    inventory.product_apis["products/empty"] = []
    inventory.collections["products/empty/apis"] = CollectionCoverage(status="complete")
    assert finding(catalog_snapshot, "APIM-COST-005").result.outcome == "fail"
    inventory.collections["products/empty/apis"].status = "unavailable"
    assert finding(catalog_snapshot, "APIM-COST-005").result.outcome == "unknown"
    inventory.product_apis["products/empty"] = ["apis/orders"]
    inventory.collections["products/empty/apis"].status = "complete"
    assert finding(catalog_snapshot, "APIM-COST-005").result.outcome == "pass"


def test_route_families_do_not_confuse_revisions(catalog_snapshot):
    api = add(
        catalog_snapshot,
        "apis/orders;rev=2",
        "api",
        version_set=False,
        api_route_hash=reference_id("orders"),
    )
    assert finding(catalog_snapshot, "APIM-OPS-004").result.outcome == "pass"
    api.path = "apis/other"
    assert finding(catalog_snapshot, "APIM-OPS-004").result.outcome == "fail"
    api.metadata.version_set = True
    assert finding(catalog_snapshot, "APIM-OPS-004").result.outcome == "pass"
    api.metadata.api_route_hash = None
    api.metadata.version_set = None
    assert finding(catalog_snapshot, "APIM-OPS-004").result.outcome == "unknown"


def test_repeated_blocks_never_compare_redacted_literals_as_equal(catalog_snapshot):
    add(catalog_snapshot, "apis/other", "api", api_type="http", subscription_required=True)
    inventory = catalog_snapshot.instances[0].inventory
    inventory.collections["apis/other/operations"] = CollectionCoverage(status="complete")
    block = (
        '<set-header name="X-Powered-By" exists-action="delete"/>'
        '<set-header name="X-AspNet-Version" exists-action="delete"/>'
        '<set-header name="Server" exists-action="delete"/>'
    )
    put(catalog_snapshot, "apis/orders", outbound=block)
    put(catalog_snapshot, "apis/other", outbound=block)
    assert finding(catalog_snapshot, "APIM-OPS-003").result.outcome == "fail"
    for path in ("apis/orders", "apis/other"):
        put(catalog_snapshot, path, outbound=block + "<set-body>private literal</set-body>")
    assert finding(catalog_snapshot, "APIM-OPS-003").result.outcome == "unknown"


def test_waivers_preserve_failures_and_exclude_them_from_scores(catalog_snapshot):
    settings = RuleSettings(
        waivers=[Waiver(rule_id="APIM-REL-006", justification="Approved recovery tradeoff")],
        severity_overrides={"APIM-REL-006": "Low"},
    )
    assessment = analyze(catalog_snapshot, settings)
    waived = next(item for item in assessment.findings if item.rule.id == "APIM-REL-006")
    assert waived.result.outcome == "fail"
    assert waived.waiver_justification == "Approved recovery tradeoff"
    assert waived.severity == "Low"
    assert next(score for score in assessment.pillar_scores if score.pillar == "REL").waived == 1
    assert assessment.pillar_scores == scores(assessment.findings)
    assert "Approved recovery tradeoff" in render(catalog_snapshot, assessment)
    waived.waiver_justification = None
    assessment.pillar_scores = scores(assessment.findings)
    with pytest.raises(ValueError, match="grading"):
        render(catalog_snapshot, assessment)


def test_resource_waiver_precedence_and_no_cross_instance_suppression(catalog_snapshot):
    second = catalog_snapshot.instances[0].model_copy(deep=True)
    second.resource_id += "-second"
    second.inventory = None
    catalog_snapshot.instances.append(second)
    identifier = catalog_snapshot.instances[0].resource_id
    settings = RuleSettings(
        waivers=[
            Waiver(rule_id="APIM-REL-006", justification="Global"),
            Waiver(
                rule_id="APIM-REL-006", resource_id=identifier.upper(), justification="Specific"
            ),
            Waiver(rule_id="APIM-REL-003", resource_id=identifier, justification="One instance"),
        ]
    )
    findings = analyze(catalog_snapshot, settings).findings
    assert [item.waiver_justification for item in findings if item.rule.id == "APIM-REL-006"] == [
        "Specific",
        "Global",
    ]
    assert [item.waiver_justification for item in findings if item.rule.id == "APIM-REL-003"] == [
        "One instance",
        None,
    ]


@pytest.mark.parametrize(
    "data",
    [
        {"waivers": [{"rule_id": "APIM-REL-006", "justification": "  "}]},
        {"severity_overrides": {"APIM-REL-006": "not-a-severity"}},
        {"thresholds": {"capacity_warning_pct": 101}},
        {"thresholds": {"payload_max_bytes": 0}},
        {"thresholds": {"cert_expiry_days": float("nan")}},
        {"waivers": [{"rule_id": "APIM-REL-006", "justification": "one"}] * 2},
    ],
)
def test_invalid_rule_configuration_is_rejected(data):
    with pytest.raises(ValidationError):
        RuleSettings.model_validate(data)


def test_unknown_and_deferred_overrides_are_not_silently_ignored(catalog_snapshot):
    with pytest.raises(ValueError, match="deferred rule"):
        analyze(catalog_snapshot, RuleSettings(severity_overrides={"APIM-SEC-004": "Low"}))
    with pytest.raises(ValueError, match="does not match"):
        analyze(
            catalog_snapshot,
            RuleSettings(
                waivers=[
                    Waiver(
                        rule_id="APIM-REL-006",
                        justification="Wrong target",
                        resource_id=catalog_snapshot.instances[0].resource_id + "-absent",
                    )
                ]
            ),
        )


def test_custom_capacity_and_payload_thresholds_change_real_dispatch(catalog_snapshot):
    settings = RuleSettings(
        thresholds=Thresholds(
            capacity_low_pct=31, capacity_warning_pct=29, payload_max_bytes=204800
        )
    )
    assert finding(catalog_snapshot, "APIM-COST-001", settings).result.outcome == "fail"
    assert finding(catalog_snapshot, "APIM-PERF-001", settings).result.outcome == "fail"
    catalog_snapshot.instances[0].inventory.resources[1].metadata.method = "PUT"
    put(
        catalog_snapshot,
        inbound='<validate-content max-size="204800" size-exceeded-action="prevent"/>',
    )
    assert finding(catalog_snapshot, "APIM-PERF-003").result.outcome == "fail"
    assert finding(catalog_snapshot, "APIM-PERF-003", settings).result.outcome == "pass"


def test_control_rollups_never_promote_missing_or_waived_evidence(catalog_snapshot):
    all_findings = analyze(catalog_snapshot).findings
    selected = [item for item in all_findings if item.rule.id in {"APIM-SEC-008", "APIM-SEC-021"}]
    assert mcsb_coverage(selected)[0].status == "pass"  # No backend entities: not applicable.
    selected[-1].result.outcome = "unknown"
    assert mcsb_coverage(selected)[0].status == "warning"
    assert mcsb_score(mcsb_coverage(selected)) is None
    selected[-1].result.outcome = "fail"
    assert mcsb_coverage(selected)[0].status == "fail"
    selected[-1].waiver_justification = "Risk accepted"
    assert mcsb_coverage(selected)[0].status == "warning"


def test_new_catalog_rules_dispatch_missing_inventory_honestly(catalog_snapshot):
    catalog_snapshot.instances[0].inventory = None
    assessment = analyze(catalog_snapshot)
    for item in assessment.findings:
        if item.rule.evaluator in {
            "api_protocols",
            "circuit_breakers",
            "named_value_secrets",
            "backend_tls",
            "inline_secrets",
            "payload_limits",
            "implementation_headers",
            "api_version_sets",
        }:
            assert item.result.outcome == "unknown"
    assert len(assessment.findings) == len(load_rules())


def test_cache_hit_cannot_bypass_caller_authentication_and_still_pass(catalog_snapshot):
    catalog_snapshot.instances[0].inventory.resources[0].metadata.subscription_required = False
    jwt = (
        '<validate-jwt header-name="Authorization"><openid-config '
        'url="https://login.example.test/.well-known/openid-configuration"/></validate-jwt>'
    )
    put(catalog_snapshot, inbound="<cache-lookup/>" + jwt)
    assert finding(catalog_snapshot, "APIM-SEC-017").result.outcome == "unknown"
    put(catalog_snapshot, inbound=jwt + "<cache-lookup/>")
    assert finding(catalog_snapshot, "APIM-SEC-017").result.outcome == "pass"


def test_iteration_two_digest_and_findings_are_still_reportable(catalog_snapshot):
    put(catalog_snapshot, inbound="<cache-lookup/>", backend="<forward-request/>")
    instance = catalog_snapshot.instances[0]
    instance.service_settings = None
    for item in instance.inventory.resources:
        for field in CATALOG_METADATA_FIELDS:
            setattr(item.metadata, field, None)
    catalog_snapshot.schema_version = "1.1"
    legacy = catalog_snapshot.model_dump_json(
        exclude={
            "instances": {
                "__all__": {
                    "service_settings": True,
                    "networking": True,
                    "governance": True,
                    "log_analytics": True,
                    "inventory": {"resources": {"__all__": {"metadata": CATALOG_METADATA_FIELDS}}},
                }
            },
        }
    )
    assert digest(catalog_snapshot) == hashlib.sha256(legacy.encode()).hexdigest()
    assessment = analyze(catalog_snapshot)
    assert assessment.policy_coverage[0].authentication == "unknown"
    assessment.policy_coverage[0].authentication = "absent"
    with pytest.raises(ValueError, match="Policy coverage does not match"):
        render(catalog_snapshot, assessment)
    assessment.schema_version = "1.1"
    assessment.findings = [item for item in assessment.findings if item.rule.id in ITERATION_2_IDS]
    assessment.pillar_scores = scores(assessment.findings)
    assessment.mcsb_coverage = []
    assessment.mcsb_assessed_score = None
    assert "Historical policy interpretations are preserved" in render(catalog_snapshot, assessment)
    assessment.policy_coverage[0].api_path = "apis/not-collected"
    with pytest.raises(ValueError, match="Policy coverage does not match"):
        render(catalog_snapshot, assessment)
    instance.service_settings = ServiceSettings()
    with pytest.raises(ValidationError, match="requires snapshot schema 1.2"):
        catalog_snapshot.model_validate(catalog_snapshot.model_dump())
