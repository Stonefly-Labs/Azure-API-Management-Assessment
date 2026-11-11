from __future__ import annotations

from typing import Literal

from pydantic import Field

from apim_assess.models.adjacent import CoverageStatus
from apim_assess.models.policy import PolicyModel


class WafConfiguration(PolicyModel):
    enabled: bool | None = None
    prevention: bool | None = None
    managed_rules: bool | None = None
    bot_protection: bool | None = None
    rate_limiting: bool | None = None


class UpstreamRoute(PolicyModel):
    reference: str
    provider: Literal["afd", "appgw"]
    waf: WafConfiguration | None = None
    https_only: bool | None = None
    health_probe: bool | None = None
    network_restricted: bool | None = None
    front_door_id: str | None = None


class UpstreamProbe(PolicyModel):
    status: CoverageStatus = "unavailable"
    candidates: int = Field(default=0, ge=0)
    routes: list[UpstreamRoute] = Field(default_factory=list)


class Upstream(PolicyModel):
    afd: UpstreamProbe = Field(default_factory=UpstreamProbe)
    appgw: UpstreamProbe = Field(default_factory=UpstreamProbe)
