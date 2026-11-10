from urllib.parse import quote

from pydantic import BaseModel, ValidationError

from apim_assess.collector.client import ArmReader, AzureReadError
from apim_assess.config import AssessmentConfig
from apim_assess.models.snapshot import CollectionWarning, ResourceId

APIM_API_VERSION = "2024-05-01"


class DiscoveredService(BaseModel):
    id: ResourceId


async def discover(
    reader: ArmReader, config: AssessmentConfig, warnings: list[CollectionWarning]
) -> list[str]:
    ids = {target.resource_id.casefold(): target.resource_id for target in config.targets.instances}
    groups: list[str | None] = list(config.targets.resource_groups) or [None]
    for subscription in config.targets.subscriptions:
        for group in groups:
            scope = f"/subscriptions/{subscription}"
            if group:
                scope += f"/resourceGroups/{quote(group, safe='')}"
            path = scope + "/providers/Microsoft.ApiManagement/service"
            try:
                async for item in reader.pages(path, APIM_API_VERSION):
                    service = DiscoveredService.model_validate(item)
                    expected = f"/subscriptions/{subscription}/".casefold()
                    if not service.id.casefold().startswith(expected):
                        raise AzureReadError("OUT_OF_SCOPE_RESPONSE")
                    if group and service.id.split("/")[4].casefold() != group.casefold():
                        raise AzureReadError("OUT_OF_SCOPE_RESPONSE")
                    ids[service.id.casefold()] = service.id
            except (AzureReadError, ValidationError) as exc:
                warnings.append(
                    CollectionWarning(
                        module="discovery",
                        resource_id=scope,
                        code=str(exc) if isinstance(exc, AzureReadError) else "INVALID_RESPONSE",
                        message="APIM discovery was incomplete for this scope.",
                    )
                )
    return sorted(ids.values(), key=str.casefold)
