from __future__ import annotations

from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from samples.validation_lab.openapi import build_orders_openapi_spec

SEED_ORDERS: dict[str, dict[str, Any]] = {
    "ord-1001": {
        "id": "ord-1001",
        "customer": "Contoso Retail",
        "status": "shipped",
        "totalUsd": 149.50,
        "items": ["apim-gateway-sensor", "telemetry-adapter"],
    },
    "ord-1002": {
        "id": "ord-1002",
        "customer": "Fabrikam Logistics",
        "status": "processing",
        "totalUsd": 420.00,
        "items": ["foundry-router-pack"],
    },
}


def create_rest_app() -> Starlette:
    orders: dict[str, dict[str, Any]] = {key: dict(val) for key, val in SEED_ORDERS.items()}

    async def healthz(_request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "service": "orders-rest-api"})

    async def openapi_doc(request: Request) -> JSONResponse:
        base_url = str(request.base_url).rstrip("/")
        return JSONResponse(build_orders_openapi_spec(server_url=base_url))

    async def list_orders(request: Request) -> JSONResponse:
        status_filter = request.query_params.get("status")
        items = list(orders.values())
        if status_filter:
            items = [item for item in items if item["status"] == status_filter]
        return JSONResponse({"orders": items, "count": len(items)})

    async def get_order(request: Request) -> JSONResponse:
        order_id = str(request.path_params.get("orderId") or "")
        order = orders.get(order_id)
        if order is None:
            return JSONResponse({"error": f"Order '{order_id}' not found"}, status_code=404)
        return JSONResponse(order)

    async def create_order(request: Request) -> JSONResponse:
        try:
            body: dict[str, Any] = await request.json()
        except Exception:
            return JSONResponse({"error": "Invalid JSON body"}, status_code=400)
        customer = str(body.get("customer") or "").strip()
        items = body.get("items")
        total_usd = body.get("totalUsd")
        if not customer or not isinstance(items, list) or not isinstance(total_usd, (int, float)):
            return JSONResponse(
                {"error": "customer, items (list), and totalUsd (number) are required"},
                status_code=400,
            )
        new_id = f"ord-{1000 + len(orders) + 1}"
        record: dict[str, Any] = {
            "id": new_id,
            "customer": customer,
            "status": "processing",
            "totalUsd": float(total_usd),
            "items": [str(item) for item in items],
        }
        orders[new_id] = record
        return JSONResponse(record, status_code=201)

    routes = [
        Route("/healthz", healthz, methods=["GET"]),
        Route("/openapi.json", openapi_doc, methods=["GET"]),
        Route("/orders", list_orders, methods=["GET"]),
        Route("/orders", create_order, methods=["POST"]),
        Route("/orders/{orderId}", get_order, methods=["GET"]),
    ]
    return Starlette(routes=routes)


app = create_rest_app()
