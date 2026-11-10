from __future__ import annotations

from typing import Literal
from urllib.parse import quote

from pydantic import AwareDatetime, BaseModel, Field, ValidationError

from apim_assess.collector.client import ArmReader, AzureReadError, linked_resource
from apim_assess.collector.sanitizer import reference_id
from apim_assess.models.adjacent import (
    AutoscaleSetting,
    DiagnosticSetting,
    Governance,
    PolicyState,
    ScaleProfile,
)
from apim_assess.models.snapshot import CollectionWarning, Instance

DIAGNOSTIC_VERSION = "2021-05-01-preview"
AUTOSCALE_VERSION = "2022-10-01"
DEFENDER_VERSION = "2023-11-15"
WORKSPACE_TYPE = r"Microsoft\.OperationalInsights/workspaces/[\w.() -]+"
LogLink = tuple[str, Literal["ApiManagementGatewayLogs", "AzureDiagnostics"]]


class _Log(BaseModel):
    enabled: bool
    category: str | None = None
    categoryGroup: str | None = None


class _DiagnosticProps(BaseModel):
    logs: list[_Log]
    workspaceId: str | None = None
    storageAccountId: str | None = None
    eventHubAuthorizationRuleId: str | None = None
    marketplacePartnerId: str | None = None
    logAnalyticsDestinationType: Literal["Dedicated", "AzureDiagnostics"] | None = None


class _Diagnostic(BaseModel):
    id: str
    properties: _DiagnosticProps


class _Action(BaseModel):
    direction: Literal["Increase", "Decrease", "None"]
    type: Literal["ChangeCount", "PercentChangeCount", "ExactCount", "ServiceAllowedNextValue"]
    value: str


class _Trigger(BaseModel):
    metricName: str = Field(min_length=1)
    metricResourceUri: str = Field(min_length=1)
    operator: Literal[
        "Equals", "NotEquals", "GreaterThan", "GreaterThanOrEqual", "LessThan", "LessThanOrEqual"
    ]
    threshold: float = Field(allow_inf_nan=False)
    timeGrain: str = Field(pattern=r"^PT[1-9][0-9]*[MH]$")
    timeWindow: str = Field(pattern=r"^PT[1-9][0-9]*[MH]$")
    timeAggregation: Literal["Average", "Minimum", "Maximum", "Total", "Count", "Last"]
    statistic: Literal["Average", "Min", "Max", "Sum", "Count"]


class _Rule(BaseModel):
    scaleAction: _Action
    metricTrigger: _Trigger


class _Capacity(BaseModel):
    minimum: int = Field(ge=0)
    maximum: int = Field(ge=0)
    default: int = Field(ge=0)


class _Profile(BaseModel):
    capacity: _Capacity
    rules: list[_Rule]


class _AutoscaleProps(BaseModel):
    targetResourceUri: str
    enabled: bool
    profiles: list[_Profile]


class _Autoscale(BaseModel):
    id: str
    properties: _AutoscaleProps


class _PricingProps(BaseModel):
    pricingTier: Literal["Free", "Standard"]


class _Pricing(BaseModel):
    properties: _PricingProps


class _ApiCollectionProps(BaseModel):
    provisioningState: Literal[
        "Succeeded", "Creating", "Updating", "Deleting", "Failed", "Canceled", "InProgress"
    ]


class _ApiCollection(BaseModel):
    id: str
    name: str
    properties: _ApiCollectionProps


class _PolicyState(BaseModel):
    resourceId: str
    policyAssignmentId: str
    policyDefinitionId: str
    policyDefinitionReferenceId: str | None = None
    complianceState: Literal["Compliant", "NonCompliant", "Exempt", "Conflict", "Error", "Unknown"]
    timestamp: AwareDatetime


def warn(
    warnings: list[CollectionWarning],
    identifier: str,
    signal: str,
    error: AzureReadError | ValidationError | None = None,
) -> None:
    code = (
        str(error)
        if isinstance(error, AzureReadError)
        else ("INVALID_RESPONSE" if error is not None else "DISABLED")
    )
    warnings.append(
        CollectionWarning(
            module="governance",
            resource_id=identifier,
            code=code,
            message=(
                f"{signal} evidence is incomplete or disabled; no healthy default was substituted."
            ),
        )
    )


async def collect_governance(
    reader: ArmReader,
    instance: Instance,
    warnings: list[CollectionWarning],
    *,
    enabled: bool,
) -> tuple[Governance, list[LogLink]]:
    result = Governance()
    links: set[LogLink] = set()
    if not enabled:
        warn(warnings, instance.resource_id, "Governance")
        return Governance(
            diagnostics_status="disabled",
            autoscale_status="disabled",
            defender_status="disabled",
            policy_status="disabled",
        ), []
    path = quote(instance.resource_id, safe="/")
    subscription = "/subscriptions/" + instance.resource_id.split("/")[2]
    if instance.sku and instance.sku.name == "Consumption":
        result.diagnostics_status = "unsupported"
    else:
        try:
            async for body in reader.pages(
                path + "/providers/Microsoft.Insights/diagnosticSettings",
                DIAGNOSTIC_VERSION,
            ):
                setting = _Diagnostic.model_validate(body)
                if not setting.id.casefold().startswith(
                    instance.resource_id.casefold()
                    + "/providers/microsoft.insights/diagnosticsettings/"
                ):
                    raise AzureReadError("DIAGNOSTIC_SCOPE_MISMATCH")
                props = setting.properties
                gateway = any(
                    log.enabled
                    and (log.category == "GatewayLogs" or log.categoryGroup == "allLogs")
                    for log in props.logs
                )
                known = all(log.category or log.categoryGroup for log in props.logs)
                workspace = None
                if props.workspaceId:
                    workspace = linked_resource(props.workspaceId, WORKSPACE_TYPE)
                destination = any(
                    (
                        workspace,
                        props.storageAccountId,
                        props.eventHubAuthorizationRuleId,
                        props.marketplacePartnerId,
                    )
                )
                result.diagnostics.append(
                    DiagnosticSetting(
                        reference=reference_id(setting.id.casefold()),
                        gateway_logs=True if gateway else False if known else None,
                        destination_configured=destination,
                        workspace=reference_id(workspace.casefold()) if workspace else None,
                    )
                )
                if gateway and workspace:
                    links.add(
                        (
                            workspace,
                            "ApiManagementGatewayLogs"
                            if props.logAnalyticsDestinationType == "Dedicated"
                            else "AzureDiagnostics",
                        )
                    )
            result.diagnostics_status = "complete"
        except (AzureReadError, ValidationError) as exc:
            result.diagnostics_status = "partial" if result.diagnostics else "unavailable"
            warn(warnings, instance.resource_id, "Resource diagnostic settings", exc)
    try:
        async for body in reader.pages(
            subscription + "/providers/Microsoft.Insights/autoscalesettings",
            AUTOSCALE_VERSION,
        ):
            setting_scale = _Autoscale.model_validate(body)
            if setting_scale.properties.targetResourceUri.casefold().rstrip("/") != (
                instance.resource_id.casefold()
            ):
                continue
            profiles = []
            for profile in setting_scale.properties.profiles:
                actions = [
                    rule.scaleAction.direction
                    for rule in profile.rules
                    if rule.scaleAction.value.isdigit()
                    and int(rule.scaleAction.value) > 0
                    and (
                        rule.scaleAction.type != "ExactCount"
                        or (
                            profile.capacity.minimum
                            < int(rule.scaleAction.value)
                            <= profile.capacity.maximum
                            if rule.scaleAction.direction == "Increase"
                            else profile.capacity.minimum
                            <= int(rule.scaleAction.value)
                            < profile.capacity.maximum
                        )
                    )
                ]
                profiles.append(
                    ScaleProfile(
                        **profile.capacity.model_dump(),
                        increase_rules=actions.count("Increase"),
                        decrease_rules=actions.count("Decrease"),
                    )
                )
            result.autoscale.append(
                AutoscaleSetting(
                    reference=reference_id(setting_scale.id.casefold()),
                    enabled=setting_scale.properties.enabled,
                    profiles=profiles,
                )
            )
        result.autoscale_status = "complete"
    except (AzureReadError, ValidationError) as exc:
        result.autoscale_status = "partial" if result.autoscale else "unavailable"
        warn(warnings, instance.resource_id, "Autoscale settings", exc)
    if instance.sku and instance.sku.name not in {"Developer", "Basic", "Standard", "Premium"}:
        result.defender_status = "unsupported"
    else:
        try:
            pricing = _Pricing.model_validate(
                await reader.get(
                    subscription + "/providers/Microsoft.Security/pricings/Api",
                    {"api-version": "2024-01-01"},
                )
            )
            result.defender_plan = pricing.properties.pricingTier
            ready = True
            async for body in reader.pages(
                path + "/providers/Microsoft.Security/apiCollections",
                DEFENDER_VERSION,
            ):
                collection = _ApiCollection.model_validate(body)
                expected = instance.resource_id + "/providers/Microsoft.Security/apiCollections/"
                if collection.id.casefold() != (expected + collection.name).casefold():
                    raise AzureReadError("DEFENDER_SCOPE_MISMATCH")
                if collection.properties.provisioningState != "Succeeded":
                    ready = False
                    continue
                inventory = instance.inventory
                matches = (
                    [
                        item.path
                        for item in inventory.resources
                        if item.kind == "api"
                        and item.workspace is None
                        and item.name.casefold() == collection.name.casefold()
                    ]
                    if inventory
                    else []
                )
                result.defender_api_paths.extend(matches)
            result.defender_api_paths = sorted(set(result.defender_api_paths))
            result.defender_status = "complete" if ready else "partial"
            if not ready:
                warn(
                    warnings,
                    instance.resource_id,
                    "Defender onboarding readiness",
                    AzureReadError("INCOMPLETE_DEFENDER_ONBOARDING"),
                )
        except (AzureReadError, ValidationError) as exc:
            result.defender_status = "partial" if result.defender_plan else "unavailable"
            warn(warnings, instance.resource_id, "Defender for APIs", exc)
    try:
        async for body in reader.policy_states(instance.resource_id):
            state = _PolicyState.model_validate(body)
            if state.resourceId.casefold() != instance.resource_id.casefold():
                raise AzureReadError("POLICY_SCOPE_MISMATCH")
            result.policy_states.append(
                PolicyState(
                    assignment=reference_id(state.policyAssignmentId.casefold()),
                    definition=reference_id(state.policyDefinitionId.casefold()),
                    definition_reference=(
                        reference_id(state.policyDefinitionReferenceId)
                        if state.policyDefinitionReferenceId
                        else None
                    ),
                    state=state.complianceState,
                    timestamp=state.timestamp,
                )
            )
        result.policy_status = "complete"
    except (AzureReadError, ValidationError) as exc:
        result.policy_status = "partial" if result.policy_states else "unavailable"
        warn(warnings, instance.resource_id, "Azure Policy states", exc)
    return result, sorted(links)
