from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

import httpx
import jwt
from jwt import PyJWK, PyJWKClient

from samples.validation_lab.config import LabServiceSettings


class AuthError(Exception):
    def __init__(self, message: str, status_code: int = 401) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


@dataclass(frozen=True)
class VerifiedClaims:
    subject: str
    issuer: str
    audiences: list[str]
    roles: list[str]
    tenant_id: str


class EntraJwtValidator:
    def __init__(self, settings: LabServiceSettings) -> None:
        self._settings = settings
        self._jwks_client: PyJWKClient | None = None
        if not settings.jwks_json and not settings.allow_hs256_test_secret:
            jwks_uri = f"https://login.microsoftonline.com/{settings.tenant_id}/discovery/v2.0/keys"
            self._jwks_client = PyJWKClient(jwks_uri, cache_keys=True)

    @property
    def valid_issuers(self) -> set[str]:
        tid = self._settings.tenant_id
        return {
            f"https://login.microsoftonline.com/{tid}/v2.0",
            f"https://sts.windows.net/{tid}/",
        }

    @property
    def valid_audiences(self) -> set[str]:
        aud = self._settings.audience
        candidates = {aud}
        if aud.startswith("api://"):
            candidates.add(aud.removeprefix("api://"))
        else:
            candidates.add(f"api://{aud}")
        return candidates

    def verify_authorization_header(self, authorization: str | None) -> VerifiedClaims:
        if not authorization:
            raise AuthError("Missing Authorization header", status_code=401)
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            raise AuthError("Authorization header must use Bearer token", status_code=401)
        return self.verify_token(token.strip())

    def verify_token(self, token: str) -> VerifiedClaims:
        try:
            key, algorithms = self._signing_key(token)
            payload: dict[str, Any] = jwt.decode(
                token,
                key=key,
                algorithms=algorithms,
                audience=list(self.valid_audiences),
                options={
                    "require": ["exp", "iss", "aud"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_aud": True,
                },
            )
        except jwt.PyJWTError as exc:
            raise AuthError(f"Invalid bearer token: {exc}", status_code=401) from exc

        issuer = str(payload.get("iss") or "")
        if issuer not in self.valid_issuers:
            raise AuthError("Token issuer is not authorized for this tenant", status_code=401)

        raw_aud = payload.get("aud")
        audiences = (
            [str(item) for item in raw_aud]
            if isinstance(raw_aud, list)
            else [str(raw_aud)]
            if raw_aud
            else []
        )
        raw_roles = payload.get("roles")
        roles = [str(item) for item in raw_roles] if isinstance(raw_roles, list) else []
        required_role = self._settings.required_role
        if required_role and required_role not in roles:
            raise AuthError(
                f"Caller does not possess required app role '{required_role}'",
                status_code=403,
            )

        return VerifiedClaims(
            subject=str(payload.get("sub") or payload.get("oid") or "service-principal"),
            issuer=issuer,
            audiences=audiences,
            roles=roles,
            tenant_id=str(payload.get("tid") or self._settings.tenant_id),
        )

    def _signing_key(self, token: str) -> tuple[Any, list[str]]:
        if self._settings.allow_hs256_test_secret:
            return self._settings.allow_hs256_test_secret, ["HS256"]
        if self._settings.jwks_json:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            jwks_data = json.loads(self._settings.jwks_json)
            for key_dict in jwks_data.get("keys", []):
                if not kid or key_dict.get("kid") == kid:
                    return PyJWK.from_dict(key_dict).key, ["RS256"]
            raise AuthError("Matching JWK kid not found", status_code=401)
        if self._jwks_client is None:
            raise AuthError("JWKS client is not initialized", status_code=401)
        signing_key = self._jwks_client.get_signing_key_from_jwt(token)
        return signing_key.key, ["RS256"]


async def fetch_openid_metadata(tenant_id: str) -> dict[str, Any]:
    url = f"https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(url)
        response.raise_for_status()
        result: dict[str, Any] = response.json()
        return result


def build_test_jwt(
    *,
    secret: str,
    tenant_id: str,
    audience: str,
    roles: list[str],
    expires_in_seconds: int = 600,
    issuer: str | None = None,
) -> str:
    now = int(time.time())
    payload: dict[str, Any] = {
        "iss": issuer or f"https://login.microsoftonline.com/{tenant_id}/v2.0",
        "aud": audience,
        "tid": tenant_id,
        "sub": "lab-client-sp",
        "oid": "00000000-0000-0000-0000-000000000001",
        "roles": roles,
        "iat": now - 5,
        "nbf": now - 5,
        "exp": now + expires_in_seconds,
    }
    return jwt.encode(payload, secret, algorithm="HS256")
