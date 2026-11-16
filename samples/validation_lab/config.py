from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class LabServiceSettings:
    tenant_id: str
    audience: str
    required_role: str
    jwks_json: str | None
    allow_hs256_test_secret: str | None
    service_name: str
    port: int


def load_service_settings(
    *,
    default_name: str,
    default_role: str,
    default_port: int = 8080,
) -> LabServiceSettings:
    tenant_id = os.environ.get(
        "LAB_ENTRA_TENANT_ID", "00000000-0000-0000-0000-000000000000"
    ).strip()
    audience = os.environ.get("LAB_ENTRA_AUDIENCE", f"api://{default_name}").strip()
    required_role = os.environ.get("LAB_ENTRA_REQUIRED_ROLE", default_role).strip()
    jwks_json = os.environ.get("LAB_ENTRA_JWKS_JSON")
    allow_hs256_test_secret = os.environ.get("LAB_TEST_JWT_SECRET")
    port = int(os.environ.get("PORT", str(default_port)))
    return LabServiceSettings(
        tenant_id=tenant_id,
        audience=audience,
        required_role=required_role,
        jwks_json=jwks_json,
        allow_hs256_test_secret=allow_hs256_test_secret,
        service_name=default_name,
        port=port,
    )
