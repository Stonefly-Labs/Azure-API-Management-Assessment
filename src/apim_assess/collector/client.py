from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

import httpx
from azure.core.credentials import AccessToken
from azure.core.credentials_async import AsyncTokenCredential
from azure.core.exceptions import ClientAuthenticationError

ARM = "https://management.azure.com"


class AzureReadError(Exception):
    """A safe, stable error code; never contains response bodies or tokens."""


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
                response = await self.client.get(
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
