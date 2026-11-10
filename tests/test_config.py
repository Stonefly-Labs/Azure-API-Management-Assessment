import pytest
from pydantic import ValidationError

from apim_assess.collector.apim_core import _Service, project_service
from apim_assess.config import AssessmentConfig, load_config
from apim_assess.models.snapshot import Snapshot

ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000001"
    "/resourceGroups/example/providers/Microsoft.ApiManagement/service/example"
)


def test_config_cli_precedence_and_per_instance_override(tmp_path):
    path = tmp_path / "assessment.yaml"
    path.write_text(
        f"env: non-prod\ntargets:\n  instances:\n    - resource_id: {ID}\n"
        "      env: prod\nmodules:\n  metrics: false\ntelemetry:\n  lookback_days: 7\n"
    )
    config = load_config(path, [], [], [], None, None, None)
    assert config.env == "non-prod"
    assert config.telemetry.lookback_days == 7
    assert config.modules.metrics is False
    assert project_service(ID, None, config).environment == "prod"
    override = load_config(path, [ID + "-other"], [], [], "prod", True, 14)
    assert override.targets.instances[0].resource_id == ID + "-other"
    assert override.targets.instances[0].env is None
    assert override.modules.metrics is True
    assert override.telemetry.lookback_days == 14
    assert override.env == "prod"


def test_cli_subscription_can_complete_configured_group_scope(tmp_path):
    path = tmp_path / "assessment.yaml"
    path.write_text("targets:\n  resource_groups: [example]\n")
    config = load_config(path, [], ["00000000-0000-0000-0000-000000000001"], [], None, None, None)
    assert config.targets.resource_groups == ["example"]
    with pytest.raises(ValidationError):
        load_config(path, [], ["00000000-0000-0000-0000-000000000001"], [".."], None, None, None)


@pytest.mark.parametrize(
    ("name", "sku", "tags", "expected"),
    [
        ("example", "Developer", {"ENV": "Production"}, "prod"),
        ("example-prod", "Developer", {}, "prod"),
        ("example-test", "Premium", {}, "non-prod"),
        ("example", "Developer", {}, "non-prod"),
        ("example", "Premium", {}, "prod"),
    ],
)
def test_auto_environment_heuristics_are_recorded(name, sku, tags, expected):
    identifier = ID.rsplit("/", 1)[0] + "/" + name
    service = _Service.model_validate(
        {"id": identifier, "sku": {"name": sku, "capacity": 1}, "tags": tags, "properties": {}}
    )
    instance = project_service(identifier, service, AssessmentConfig())
    assert instance.environment == expected
    assert instance.environment_source


def test_unimplemented_options_and_conflicting_targets_are_rejected():
    with pytest.raises(ValidationError):
        AssessmentConfig.model_validate({"modules": {"afd": True}})
    with pytest.raises(ValidationError):
        AssessmentConfig.model_validate(
            {
                "targets": {
                    "instances": [
                        {"resource_id": ID, "env": "prod"},
                        {"resource_id": ID.upper(), "env": "non-prod"},
                    ]
                }
            }
        )


def test_snapshot_rejects_duplicate_resources_and_invalid_telemetry(snapshot):
    data = snapshot.model_dump()
    data["instances"].append(data["instances"][0])
    with pytest.raises(ValidationError, match="Duplicate APIM"):
        Snapshot.model_validate(data)
    data = snapshot.model_dump()
    point = data["instances"][0]["metrics"][0]["points"][0]
    point["average"] = float("nan")
    with pytest.raises(ValidationError):
        Snapshot.model_validate(data)
    data = snapshot.model_dump()
    data["instances"][0]["metrics"][0]["points"][0]["timestamp"] = snapshot.telemetry_end
    with pytest.raises(ValidationError, match="inside"):
        Snapshot.model_validate(data)
