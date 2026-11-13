from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def build_orders_openapi_spec(
    server_url: str = "https://ca-apv-rest-wus3-001.internal",
) -> dict[str, Any]:
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "Validation Lab Orders API",
            "version": "1.0.0",
            "description": (
                "Deterministic Orders REST API used by the apim-assess validation lab "
                "for direct REST operations and REST-to-MCP tool projection."
            ),
        },
        "servers": [{"url": server_url}],
        "paths": {
            "/healthz": {
                "get": {
                    "operationId": "getHealth",
                    "summary": "Check service health",
                    "responses": {
                        "200": {
                            "description": "Service is healthy",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/HealthStatus"}
                                }
                            },
                        }
                    },
                }
            },
            "/orders": {
                "get": {
                    "operationId": "listOrders",
                    "summary": "List recent orders",
                    "parameters": [
                        {
                            "name": "status",
                            "in": "query",
                            "required": False,
                            "schema": {"type": "string"},
                            "description": "Optional status filter such as shipped or processing",
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "List of orders",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/OrderList"}
                                }
                            },
                        }
                    },
                },
                "post": {
                    "operationId": "createOrder",
                    "summary": "Create a new order",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/CreateOrderRequest"}
                            }
                        },
                    },
                    "responses": {
                        "201": {
                            "description": "Created order",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Order"}
                                }
                            },
                        }
                    },
                },
            },
            "/orders/{orderId}": {
                "get": {
                    "operationId": "getOrder",
                    "summary": "Get an order by identifier",
                    "parameters": [
                        {
                            "name": "orderId",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                            "description": "Order identifier such as ord-1001",
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Requested order",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Order"}
                                }
                            },
                        },
                        "404": {"description": "Order not found"},
                    },
                }
            },
        },
        "components": {
            "schemas": {
                "HealthStatus": {
                    "type": "object",
                    "required": ["status", "service"],
                    "properties": {
                        "status": {"type": "string", "example": "ok"},
                        "service": {"type": "string", "example": "orders-rest-api"},
                    },
                },
                "Order": {
                    "type": "object",
                    "required": ["id", "customer", "status", "totalUsd", "items"],
                    "properties": {
                        "id": {"type": "string", "example": "ord-1001"},
                        "customer": {"type": "string", "example": "Contoso Retail"},
                        "status": {"type": "string", "example": "shipped"},
                        "totalUsd": {"type": "number", "example": 149.5},
                        "items": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                    },
                },
                "OrderList": {
                    "type": "object",
                    "required": ["orders", "count"],
                    "properties": {
                        "orders": {
                            "type": "array",
                            "items": {"$ref": "#/components/schemas/Order"},
                        },
                        "count": {"type": "integer", "example": 2},
                    },
                },
                "CreateOrderRequest": {
                    "type": "object",
                    "required": ["customer", "items", "totalUsd"],
                    "properties": {
                        "customer": {"type": "string"},
                        "items": {"type": "array", "items": {"type": "string"}},
                        "totalUsd": {"type": "number"},
                    },
                },
            }
        },
    }


def export_orders_openapi_spec(
    output_path: Path, server_url: str = "https://ca-apv-rest-wus3-001.internal"
) -> Path:
    spec = build_orders_openapi_spec(server_url=server_url)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8")
    return output_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Export Orders REST OpenAPI 3.0 specification.")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("infra/lab/openapi/orders-api.openapi.json"),
        help="Destination path for OpenAPI JSON file.",
    )
    parser.add_argument(
        "--server-url",
        default="https://ca-apv-rest-wus3-001.internal",
        help="Default server URL in the exported OpenAPI spec.",
    )
    args = parser.parse_args()
    export_orders_openapi_spec(args.output, server_url=args.server_url)


if __name__ == "__main__":
    main()
