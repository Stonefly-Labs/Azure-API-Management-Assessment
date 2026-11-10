from __future__ import annotations

import asyncio
import re
import time
from collections.abc import AsyncIterator
from urllib.parse import quote, urlsplit
from uuid import UUID

import httpx
from azure.core.credentials import AccessToken
from azure.core.credentials_async import AsyncTokenCredential
from azure.core.exceptions import ClientAuthenticationError

ARM = "https://management.azure.com"
LOGS = "https://api.loganalytics.azure.com"


class AzureReadError(Exception):
    """A safe, stable error code; never contains response bodies or tokens."""


def linked_resource(value: str, resource_type: str) -> str:
    pattern = (
        r"/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[\w.() -]+/providers/" + resource_type
    )
    if not re.fullmatch(pattern, value, re.IGNORECASE):
        raise AzureReadError("INVALID_LINKED_RESOURCE")
    try:
        UUID(value.split("/")[2])
    except ValueError as exc:
        raise AzureReadError("INVALID_LINKED_RESOURCE") from exc
    return value


class ArmReader:
    def __init__(self, credential: AsyncTokenCredential, client: httpx.AsyncClient) -> None:
        self.credential = credential
        self.client = client
        self._token: AccessToken | None = None
        self._token_lock = asyncio.Lock()

    async def _access_token(self) -> AccessToken:
        async with self._token_lock:
            if self._token is None or self._token.expires_on <= time.time() + 120:
                self._token = await self.credential.get_token(ARM + "/.default")
            return self._token

    async def get(
        self, path: str, params: dict[str, str] | None = None, *, policy_xml: bool = False
    ) -> object:
        return await self._read("GET", path, params, policy_xml=policy_xml)

    async def _read(
        self,
        method: str,
        path: str,
        params: dict[str, str] | None,
        *,
        policy_xml: bool = False,
    ) -> object:
        url = ARM + path if path.startswith("/") else path
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or parsed.netloc.casefold() not in {"management.azure.com", "management.azure.com:443"}
            or parsed.fragment
            or not parsed.path.startswith("/subscriptions/")
        ):
            raise AzureReadError("UNSAFE_URL")
        try:
            token = await self._access_token()
            for attempt in range(3):
                response = await self.client.request(
                    method,
                    url,
                    params=params,
                    headers={"Authorization": f"Bearer {token.token}"},
                    follow_redirects=False,
                )
                if response.status_code in {429, 500, 502, 503, 504} and attempt < 2:
                    retry = response.headers.get("Retry-After", "")
                    await asyncio.sleep(min(int(retry), 5) if retry.isdigit() else 2**attempt)
                    continue
                if response.status_code != 200:
                    raise AzureReadError(f"HTTP_{response.status_code}")
                media = response.headers.get("content-type", "").split(";", 1)[0].lower()
                if policy_xml and (
                    media in {"text/xml", "application/xml"} or media.endswith("+xml")
                ):
                    return response.text
                try:
                    result: object = response.json()
                    return result
                except ValueError as exc:
                    raise AzureReadError("INVALID_JSON") from exc
        except ClientAuthenticationError as exc:
            raise AzureReadError("AUTHENTICATION_FAILED") from exc
        except httpx.HTTPError as exc:
            raise AzureReadError("TRANSPORT_ERROR") from exc
        raise AzureReadError("RETRY_EXHAUSTED")

    async def policy_states(self, identifier: str) -> AsyncIterator[object]:
        from apim_assess.models.snapshot import resource_id

        path = quote(resource_id(identifier), safe="/") + (
            "/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults"
        )
        next_url: str | None = ARM + path
        params: dict[str, str] | None = {
            "api-version": "2024-10-01",
            "$select": "resourceId,complianceState,timestamp,policyAssignmentId,"
            "policyDefinitionId,policyDefinitionReferenceId",
        }
        seen: set[str] = set()
        while next_url:
            if next_url in seen or urlsplit(next_url).path.casefold() != path.casefold():
                raise AzureReadError("INVALID_PAGINATION")
            seen.add(next_url)
            # POST is exclusively the documented read-only Policy Insights query operation.
            body = await self._read("POST", next_url, params)
            if not isinstance(body, dict) or not isinstance(body.get("value"), list):
                raise AzureReadError("INVALID_LIST_RESPONSE")
            for item in body["value"]:
                yield item
            link = body.get("@odata.nextLink")
            if link is not None and not isinstance(link, str):
                raise AzureReadError("INVALID_PAGINATION")
            next_url, params = link or None, None

    async def query_logs(
        self,
        workspace: str,
        query: str,
        timespan: str,
        timeout_seconds: int,
    ) -> object:
        try:
            workspace = str(UUID(workspace))
        except ValueError as exc:
            raise AzureReadError("INVALID_WORKSPACE_ID") from exc
        try:
            token = await self.credential.get_token("https://api.loganalytics.io/.default")
            response = await self.client.get(
                f"{LOGS}/v1/workspaces/{workspace}/query",
                params={"query": query, "timespan": timespan},
                headers={
                    "Authorization": f"Bearer {token.token}",
                    "Prefer": f"wait={timeout_seconds}",
                },
                timeout=timeout_seconds + 10,
                follow_redirects=False,
            )
            if response.status_code != 200:
                raise AzureReadError(f"HTTP_{response.status_code}")
            try:
                body: object = response.json()
            except ValueError as exc:
                raise AzureReadError("INVALID_JSON") from exc
            if not isinstance(body, dict) or body.get("error") is not None:
                raise AzureReadError("LOG_QUERY_PARTIAL_OR_FAILED")
            return body
        except ClientAuthenticationError as exc:
            raise AzureReadError("AUTHENTICATION_FAILED") from exc
        except httpx.HTTPError as exc:
            raise AzureReadError("TRANSPORT_ERROR") from exc

    async def pages(self, path: str, version: str) -> AsyncIterator[object]:
        next_url: str | None = ARM + path
        params: dict[str, str] | None = {"api-version": version}
        seen: set[str] = set()
        while next_url:
            if next_url in seen or urlsplit(next_url).path.casefold() != path.casefold():
                raise AzureReadError("INVALID_PAGINATION")
            seen.add(next_url)
            body = await self.get(next_url, params)
            if not isinstance(body, dict) or not isinstance(body.get("value"), list):
                raise AzureReadError("INVALID_LIST_RESPONSE")
            for item in body["value"]:
                yield item
            link = body.get("nextLink")
            if link is not None and not isinstance(link, str):
                raise AzureReadError("INVALID_PAGINATION")
            next_url = link or None
            params = None
