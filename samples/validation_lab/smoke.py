from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

import httpx
from azure.identity import DefaultAzureCredential


@dataclass
class ProbeResult:
    gateway: str
    route: str
    expected_status: int
    actual_status: int
    passed: bool
    detail: str


@dataclass
class SmokeReport:
    results: list[ProbeResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return bool(self.results) and all(item.passed for item in self.results)

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "total": len(self.results),
            "failed": sum(1 for item in self.results if not item.passed),
            "results": [
                {
                    "gateway": item.gateway,
                    "route": item.route,
                    "expected_status": item.expected_status,
                    "actual_status": item.actual_status,
                    "passed": item.passed,
                    "detail": item.detail,
                }
                for item in self.results
            ],
        }


def acquire_bearer_token(scope: str, credential: Any | None = None) -> str:
    cred = credential or DefaultAzureCredential()
    token = cred.get_token(scope)
    return str(token.token)


async def run_gateway_probes(
    *,
    dev_gateway_url: str,
    bv2_gateway_url: str,
    mcp_token: str,
    a2a_token: str,
    bv2_subscription_key: str,
    dev_subscription_key: str | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> SmokeReport:
    report = SmokeReport()
    dev_base = dev_gateway_url.rstrip("/")
    bv2_base = bv2_gateway_url.rstrip("/")
    dev_headers: dict[str, str] = {}
    if dev_subscription_key:
        dev_headers["Ocp-Apim-Subscription-Key"] = dev_subscription_key

    bv2_sub_headers = {"Ocp-Apim-Subscription-Key": bv2_subscription_key}
    bv2_mcp_headers = {
        **bv2_sub_headers,
        "Authorization": f"Bearer {mcp_token}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    bv2_a2a_headers = {
        **bv2_sub_headers,
        "Authorization": f"Bearer {a2a_token}",
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(timeout=30.0, verify=True, transport=transport) as client:
        # 1. BasicV2 REST Orders API: unauthenticated -> 401
        resp = await client.get(f"{bv2_base}/orders/orders", headers=bv2_sub_headers)
        report.results.append(
            ProbeResult(
                gateway="bv2",
                route="GET /orders/orders (no bearer)",
                expected_status=401,
                actual_status=resp.status_code,
                passed=resp.status_code == 401,
                detail="BasicV2 REST API enforces inbound validate-azure-ad-token",
            )
        )

        # 2. BasicV2 REST Orders API: valid token -> 200
        resp = await client.get(
            f"{bv2_base}/orders/orders",
            headers={**bv2_sub_headers, "Authorization": f"Bearer {mcp_token}"},
        )
        report.results.append(
            ProbeResult(
                gateway="bv2",
                route="GET /orders/orders (bearer)",
                expected_status=200,
                actual_status=resp.status_code,
                passed=resp.status_code == 200,
                detail="BasicV2 REST API returns order list with valid Entra token",
            )
        )

        # 3. BasicV2 Passthrough MCP API: unauthenticated -> 401
        resp = await client.post(
            f"{bv2_base}/container-mcp",
            headers={**bv2_sub_headers, "Accept": "application/json, text/event-stream"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        )
        report.results.append(
            ProbeResult(
                gateway="bv2",
                route="POST /container-mcp (no bearer)",
                expected_status=401,
                actual_status=resp.status_code,
                passed=resp.status_code == 401,
                detail="BasicV2 MCP server rejects unauthenticated calls",
            )
        )

        # 4. BasicV2 Passthrough MCP API: authenticated tools/list -> 200
        resp = await client.post(
            f"{bv2_base}/container-mcp",
            headers=bv2_mcp_headers,
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        )
        report.results.append(
            ProbeResult(
                gateway="bv2",
                route="POST /container-mcp (bearer tools/list)",
                expected_status=200,
                actual_status=resp.status_code,
                passed=resp.status_code == 200,
                detail="BasicV2 Agent Framework MCP server lists tools with Entra OAuth token",
            )
        )

        # 5. BasicV2 A2A API: unauthenticated -> 401
        resp = await client.post(
            f"{bv2_base}/concierge-a2a",
            headers=bv2_sub_headers,
            json={
                "jsonrpc": "2.0",
                "id": "a2a-1",
                "method": "message/send",
                "params": {
                    "id": "task-1",
                    "message": {
                        "messageId": "msg-1",
                        "role": "user",
                        "parts": [{"kind": "text", "text": "ping"}],
                    },
                },
            },
        )
        report.results.append(
            ProbeResult(
                gateway="bv2",
                route="POST /concierge-a2a (no bearer)",
                expected_status=401,
                actual_status=resp.status_code,
                passed=resp.status_code == 401,
                detail="BasicV2 A2A agent rejects unauthenticated calls",
            )
        )

        # 6. BasicV2 A2A API: authenticated message/send -> 200
        resp = await client.post(
            f"{bv2_base}/concierge-a2a",
            headers=bv2_a2a_headers,
            json={
                "jsonrpc": "2.0",
                "id": "a2a-2",
                "method": "message/send",
                "params": {
                    "id": "task-2",
                    "message": {
                        "messageId": "msg-2",
                        "role": "user",
                        "parts": [{"kind": "text", "text": "check order ord-1001"}],
                    },
                },
            },
        )
        report.results.append(
            ProbeResult(
                gateway="bv2",
                route="POST /concierge-a2a (bearer message/send)",
                expected_status=200,
                actual_status=resp.status_code,
                passed=resp.status_code == 200,
                detail=(
                    "BasicV2 Agent Framework A2A agent completes concierge task "
                    "with Entra OAuth token"
                ),
            )
        )

        # 7. BasicV2 Foundry Responses API: authenticated POST /ai/openai/v1/responses -> 200
        resp = await client.post(
            f"{bv2_base}/ai/openai/v1/responses",
            headers=bv2_mcp_headers,
            json={
                "model": os.environ.get("LAB_FOUNDRY_PRIMARY_MODEL", "gpt-5.4-mini"),
                "input": "Reply with the single word READY.",
                "max_output_tokens": 32,
            },
        )
        report.results.append(
            ProbeResult(
                gateway="bv2",
                route="POST /ai/openai/v1/responses",
                expected_status=200,
                actual_status=resp.status_code,
                passed=resp.status_code == 200,
                detail="BasicV2 Foundry Responses API succeeds through AI Gateway pool",
            )
        )

        # 8. Internal Developer APIM: REST Orders API (intentionally open / no bearer) -> 200
        resp = await client.get(f"{dev_base}/orders/orders", headers=dev_headers)
        report.results.append(
            ProbeResult(
                gateway="dev-internal",
                route="GET /orders/orders (internal VNet)",
                expected_status=200,
                actual_status=resp.status_code,
                passed=resp.status_code == 200,
                detail="Internal Developer APIM REST API reachable over private VNet DNS",
            )
        )

        # 9. Internal Developer APIM: Passthrough MCP API (gateway lacks validate-azure-ad-token,
        # so unauthenticated request reaches backend MCP container or passes with backend token)
        resp = await client.post(
            f"{dev_base}/container-mcp",
            headers={
                **dev_headers,
                "Authorization": f"Bearer {mcp_token}",
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
            },
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        report.results.append(
            ProbeResult(
                gateway="dev-internal",
                route="POST /container-mcp (internal VNet)",
                expected_status=200,
                actual_status=resp.status_code,
                passed=resp.status_code == 200,
                detail="Internal Developer APIM MCP route reachable over private VNet DNS",
            )
        )

        # 10. Internal Developer APIM: A2A API over private VNet DNS -> 200
        resp = await client.post(
            f"{dev_base}/concierge-a2a",
            headers={
                **dev_headers,
                "Authorization": f"Bearer {a2a_token}",
                "Content-Type": "application/json",
            },
            json={
                "jsonrpc": "2.0",
                "id": "a2a-dev-1",
                "method": "message/send",
                "params": {
                    "id": "task-dev-1",
                    "message": {
                        "messageId": "msg-dev-1",
                        "role": "user",
                        "parts": [{"kind": "text", "text": "internal ping"}],
                    },
                },
            },
        )
        report.results.append(
            ProbeResult(
                gateway="dev-internal",
                route="POST /concierge-a2a (internal VNet)",
                expected_status=200,
                actual_status=resp.status_code,
                passed=resp.status_code == 200,
                detail="Internal Developer APIM A2A route reachable over private VNet DNS",
            )
        )

        # 11. Internal Developer APIM: Foundry Responses API over private VNet DNS -> 200
        resp = await client.post(
            f"{dev_base}/ai/openai/v1/responses",
            headers={**dev_headers, "Content-Type": "application/json"},
            json={
                "model": os.environ.get("LAB_FOUNDRY_PRIMARY_MODEL", "gpt-5.4-mini"),
                "input": "Reply with the single word INTERNAL.",
                "max_output_tokens": 32,
            },
        )
        report.results.append(
            ProbeResult(
                gateway="dev-internal",
                route="POST /ai/openai/v1/responses (internal VNet)",
                expected_status=200,
                actual_status=resp.status_code,
                passed=resp.status_code == 200,
                detail=(
                    "Internal Developer APIM Foundry Responses route reachable "
                    "over private VNet DNS"
                ),
            )
        )

    return report
