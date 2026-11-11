from __future__ import annotations

from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

CATALOG_METADATA_FIELDS = {
    "subscription_scope",
    "version_set",
    "api_route_hash",
    "pool_member_count",
    "always_log_errors",
    "body_bytes",
    "application_insights",
    "logger_reference_hash",
}
MODERN_METADATA_FIELDS = {
    "ai_backend",
    "api_key_credential",
    "pool_member_references",
    "breaker_429",
    "breaker_retry_after",
}


class PolicyModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class PolicyDocument(PolicyModel):
    source: str
    status: Literal["available", "absent", "unavailable"]
    xml: str | None = None
    has_inline_secret_pattern: bool = False
    inline_secret_locations: list[str] = Field(default_factory=list)
    hardcoded_urls: list[str] = Field(default_factory=list)
    named_value_refs: list[str] = Field(default_factory=list)
    error_code: str | None = None


class CollectionCoverage(PolicyModel):
    status: Literal["complete", "partial", "unavailable"]
    count: int = Field(default=0, ge=0)


class ResourceMetadata(PolicyModel):
    subscription_required: bool | None = None
    service_url_kind: Literal["literal", "dynamic", "none", "unknown"] = "unknown"
    api_type: Literal["http", "soap", "websocket", "graphql", "odata", "grpc"] | None = None
    protocols: list[Literal["http", "https", "ws", "wss"]] | None = None
    method: (
        Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"]
        | None
    ) = None
    oauth_configured: bool | None = None
    secret: bool | None = None
    key_vault: bool | None = None
    credentials_present: bool | None = None
    circuit_breaker_present: bool | None = None
    backend_pool: bool | None = None
    validate_certificate_chain: bool | None = None
    validate_certificate_name: bool | None = None
    certificate_expiry: AwareDatetime | None = None
    sampling_percentage: float | None = Field(default=None, ge=0, le=100)
    subscription_scope: Literal["all_apis", "api", "product", "unknown"] | None = None
    version_set: bool | None = None
    api_route_hash: str | None = Field(default=None, pattern=r"^ref_[a-f0-9]{64}$")
    pool_member_count: int | None = Field(default=None, ge=0)
    always_log_errors: bool | None = None
    body_bytes: int | None = Field(default=None, ge=0)
    application_insights: bool | None = None
    logger_reference_hash: str | None = Field(default=None, pattern=r"^ref_[a-f0-9]{64}$")
    state: (
        Literal[
            "active",
            "suspended",
            "submitted",
            "rejected",
            "cancelled",
            "expired",
            "published",
            "notPublished",
        ]
        | None
    ) = None
    ai_backend: Literal["azure_openai", "llm", "other", "unknown"] | None = None
    api_key_credential: bool | None = None
    pool_member_references: list[str] | None = None
    breaker_429: bool | None = None
    breaker_retry_after: bool | None = None


class SubResource(PolicyModel):
    resource_id: str
    path: str
    name: str
    kind: Literal[
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
    ]
    workspace: str | None = None
    metadata: ResourceMetadata = Field(default_factory=ResourceMetadata)


class Inventory(PolicyModel):
    resources: list[SubResource] = Field(default_factory=list)
    collections: dict[str, CollectionCoverage] = Field(default_factory=dict)
    policies: dict[str, PolicyDocument] = Field(default_factory=dict)
    fragments: dict[str, PolicyDocument] = Field(default_factory=dict)
    product_apis: dict[str, list[str]] = Field(default_factory=dict)


class PolicyNode(PolicyModel):
    tag: str
    attributes: dict[str, str] = Field(default_factory=dict)
    text: str | None = None
    source: str
    scope: str = ""
    section: str = ""
    children: list[PolicyNode] = Field(default_factory=list)


class EffectivePolicy(PolicyModel):
    resource_id: str
    api_path: str
    operation_path: str | None = None
    workspace: str | None = None
    product_path: str | None = None
    subscription_required: bool | None = None
    service_url_kind: Literal["literal", "dynamic", "none", "unknown"] = "unknown"
    http_gateway_only: bool = False
    sections: dict[str, list[PolicyNode]] = Field(default_factory=dict)
    missing_base: list[str] = Field(default_factory=list)
    issues: list[str] = Field(default_factory=list)


ControlState = Literal["present", "absent", "unknown", "not_applicable"]


class PolicyCoverage(PolicyModel):
    resource_id: str
    api_path: str
    operation_path: str | None
    product_path: str | None
    subscription_required: bool | None
    http_gateway_only: bool = False
    authentication: ControlState
    jwt: ControlState
    rate_limit: ControlState
    inheritance: ControlState
    cors: ControlState
    backend: ControlState
    issues: list[str] = Field(default_factory=list)
