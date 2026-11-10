from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import Field, TypeAdapter, model_validator

from apim_assess.models.findings import RuleSettings
from apim_assess.models.snapshot import (
    Environment,
    Model,
    Profile,
    ResourceGroup,
    ResourceId,
    SubscriptionId,
)


class Target(Model):
    resource_id: ResourceId
    env: Environment | None = None


class Targets(Model):
    instances: list[Target] = Field(default_factory=list)
    subscriptions: list[SubscriptionId] = Field(default_factory=list)
    resource_groups: list[ResourceGroup] = Field(default_factory=list)


class Modules(Model):
    metrics: bool = True
    networking: bool = True
    defender_policy: bool = True
    log_analytics_kql: bool = False


class Telemetry(Model):
    lookback_days: int = Field(default=14, ge=1, le=30)
    kql_max_rows: int = Field(default=5, ge=1, le=100)
    kql_timeout_seconds: int = Field(default=30, ge=1, le=180)


class AssessmentConfig(Model):
    targets: Targets = Field(default_factory=Targets)
    env: Profile = "auto"
    modules: Modules = Field(default_factory=Modules)
    telemetry: Telemetry = Field(default_factory=Telemetry)
    rules: RuleSettings = Field(default_factory=RuleSettings)

    @model_validator(mode="after")
    def consistent_targets(self) -> AssessmentConfig:
        if self.modules.log_analytics_kql and not self.modules.defender_policy:
            raise ValueError("Log Analytics requires diagnostic linkage from defender_policy")
        seen: dict[str, Environment | None] = {}
        for target in self.targets.instances:
            key = target.resource_id.casefold()
            if key in seen and seen[key] != target.env:
                raise ValueError("Conflicting per-instance environments for the same resource ID")
            seen[key] = target.env
        if self.targets.resource_groups and not self.targets.subscriptions:
            raise ValueError("Resource group discovery requires explicit subscriptions")
        return self


def load_rule_settings(path: Path | None) -> RuleSettings:
    if path is None:
        return RuleSettings()
    data = TypeAdapter(dict[str, object]).validate_python(
        yaml.safe_load(path.read_text(encoding="utf-8"))
    )
    return AssessmentConfig.model_validate(data).rules


def load_config(
    path: Path | None,
    resource_ids: list[str],
    subscriptions: list[str],
    resource_groups: list[str],
    env: Profile | None,
    metrics: bool | None,
    lookback_days: int | None,
) -> AssessmentConfig:
    adapter = TypeAdapter(dict[str, object])
    data = adapter.validate_python(yaml.safe_load(path.read_text(encoding="utf-8"))) if path else {}
    targets = adapter.validate_python(data.get("targets", {}))
    modules = adapter.validate_python(data.get("modules", {}))
    telemetry = adapter.validate_python(data.get("telemetry", {}))
    # Explicit CLI lists replace their corresponding configured lists.
    if resource_ids:
        targets["instances"] = [{"resource_id": value} for value in resource_ids]
    if subscriptions:
        targets["subscriptions"] = subscriptions
    if resource_groups:
        targets["resource_groups"] = resource_groups
    if env is not None:
        data["env"] = env
    if metrics is not None:
        modules["metrics"] = metrics
    if lookback_days is not None:
        telemetry["lookback_days"] = lookback_days
    data.update(targets=targets, modules=modules, telemetry=telemetry)
    config = AssessmentConfig.model_validate(data)
    if not config.targets.instances and not config.targets.subscriptions:
        raise ValueError("Supply --resource-id, --subscriptions, or configured targets")
    return config
