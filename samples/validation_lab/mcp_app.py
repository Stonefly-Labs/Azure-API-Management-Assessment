from __future__ import annotations

import contextlib
import contextvars
from collections.abc import AsyncIterable, AsyncIterator, Mapping, Sequence
from typing import Any

from agent_framework import (
    Agent,
    BaseChatClient,
    ChatResponse,
    ChatResponseUpdate,
    Content,
    FunctionInvocationLayer,
    FunctionTool,
    Message,
    ResponseStream,
    tool,
)
from mcp import types as mcp_types
from mcp.server import ServerRequestContext
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.shared.exceptions import MCPError
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from samples.validation_lab.auth import AuthError, EntraJwtValidator, VerifiedClaims
from samples.validation_lab.config import LabServiceSettings, load_service_settings

_CURRENT_CALLER: contextvars.ContextVar[VerifiedClaims | None] = contextvars.ContextVar(
    "mcp_current_caller",
    default=None,
)


@tool(
    name="lookup_inventory_status",
    description="Look up real-time warehouse inventory status for a SKU.",
)
def lookup_inventory_status(sku: str) -> str:
    """Look up real-time warehouse inventory status for a catalog SKU."""
    normalized = sku.strip() or "unknown-sku"
    return f"SKU {normalized} is in_stock (available=42, warehouse=westus3)"


@tool(
    name="verify_gateway_posture",
    description="Return synthetic posture summary for an API gateway.",
)
def verify_gateway_posture(gateway: str) -> str:
    """Return synthetic gateway posture summary for an API gateway."""
    caller = _CURRENT_CALLER.get()
    subject = caller.subject if caller is not None else "agent-framework"
    normalized = gateway.strip() or "default-gateway"
    return f"Gateway {normalized} verified by {subject}"


class ValidationLabAgentChatClient(FunctionInvocationLayer[Any], BaseChatClient[Any]):
    """Deterministic Microsoft Agent Framework chat client for the validation lab."""

    def _inner_get_response(
        self,
        *,
        messages: Sequence[Message],
        stream: bool,
        options: Mapping[str, Any],
        **kwargs: Any,
    ) -> Any:
        del options, kwargs
        last_text = messages[-1].text if messages else "status check"
        caller = _CURRENT_CALLER.get()
        subject = caller.subject if caller is not None else "agent-framework"
        reply = (
            f"Agent Framework MCP concierge processed '{last_text}' "
            f"for caller {subject} (warehouse=westus3)."
        )
        if stream:

            async def _stream() -> AsyncIterable[ChatResponseUpdate]:
                yield ChatResponseUpdate(
                    contents=[Content.from_text(reply)],
                    role="assistant",
                    model="agent-framework-lab-v1",
                )

            return ResponseStream(_stream(), finalizer=ChatResponse.from_updates)

        async def _complete() -> ChatResponse:
            return ChatResponse(
                messages=[Message("assistant", [reply])],
                model="agent-framework-lab-v1",
            )

        return _complete()


def build_mcp_agent() -> tuple[Agent[Any], dict[str, FunctionTool]]:
    """Build the Microsoft Agent Framework Agent and its FunctionTools for MCP hosting."""
    domain_tools: list[FunctionTool] = [lookup_inventory_status, verify_gateway_posture]
    agent = Agent(
        client=ValidationLabAgentChatClient(),
        name="validation_lab_mcp_agent",
        description=(
            "Validation lab MCP fulfillment & gateway posture agent "
            "built with Microsoft Agent Framework."
        ),
        instructions=(
            "You are the Validation Lab MCP agent. Answer inventory and API gateway posture "
            "questions deterministically."
        ),
        tools=domain_tools,
    )
    agent_tool = agent.as_tool(
        name="validation_lab_mcp_agent",
        description="Run the Microsoft Agent Framework MCP concierge agent on a task.",
        arg_name="task",
    )
    tool_registry: dict[str, FunctionTool] = {
        agent_tool.name: agent_tool,
        lookup_inventory_status.name: lookup_inventory_status,
        verify_gateway_posture.name: verify_gateway_posture,
    }
    return agent, tool_registry


def create_agent_framework_mcp_server(
    agent: Agent[Any],
    tool_registry: Mapping[str, FunctionTool],
) -> Server[Any]:
    """Create a native MCP server backed by a Microsoft Agent Framework Agent and FunctionTools."""
    base_server = agent.as_mcp_server(
        server_name="validation-lab-mcp",
        version="1.0.0",
        instructions="Microsoft Agent Framework MCP server for APIM validation lab.",
    )

    async def _list_tools(
        _ctx: ServerRequestContext[Any],
        _params: mcp_types.PaginatedRequestParams | None,
    ) -> mcp_types.ListToolsResult:
        tools = [
            mcp_types.Tool(
                name=fn_tool.name,
                description=fn_tool.description,
                input_schema=fn_tool.parameters(),
            )
            for fn_tool in tool_registry.values()
        ]
        return mcp_types.ListToolsResult(tools=tools)

    async def _call_tool(
        _ctx: ServerRequestContext[Any],
        params: mcp_types.CallToolRequestParams,
    ) -> mcp_types.CallToolResult:
        fn_tool = tool_registry.get(params.name)
        if fn_tool is None:
            raise MCPError(
                code=mcp_types.INVALID_PARAMS,
                message=f"Unknown tool '{params.name}'",
            )
        arguments = dict(params.arguments or {})
        try:
            args_instance: Any = (
                fn_tool.input_model(**arguments)
                if fn_tool.input_model is not None and not isinstance(fn_tool.input_model, dict)
                else arguments
            )
            result_items = await fn_tool.invoke(arguments=args_instance)
        except Exception as exc:
            raise MCPError(
                code=mcp_types.INVALID_PARAMS,
                message=f"Error calling tool '{params.name}': {exc}",
            ) from exc

        content_blocks: list[mcp_types.ContentBlock] = [
            mcp_types.TextContent(type="text", text=item.text)
            for item in result_items
            if getattr(item, "type", None) == "text" and isinstance(item.text, str) and item.text
        ]
        return mcp_types.CallToolResult(content=content_blocks, is_error=False)

    return Server(
        name=base_server.name,
        version=base_server.version or "1.0.0",
        instructions=base_server.instructions,
        on_list_tools=_list_tools,
        on_call_tool=_call_tool,
    )


class _AuthenticatedMcpAsgiApp:
    """ASGI wrapper enforcing Entra Bearer JWT auth before StreamableHTTPSessionManager."""

    def __init__(
        self,
        *,
        validator: EntraJwtValidator,
        mcp_server: Server[Any],
    ) -> None:
        self._validator = validator
        self._mcp_server = mcp_server
        self._session_manager: StreamableHTTPSessionManager | None = None

    @contextlib.asynccontextmanager
    async def lifespan_context(self) -> AsyncIterator[None]:
        manager = StreamableHTTPSessionManager(
            app=self._mcp_server,
            json_response=True,
            stateless=True,
        )
        self._session_manager = manager
        async with manager.run():
            try:
                yield
            finally:
                self._session_manager = None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return
        request = Request(scope, receive=receive)
        try:
            claims = self._validator.verify_authorization_header(
                request.headers.get("authorization")
            )
        except AuthError as exc:
            response = JSONResponse(
                {"error": exc.message},
                status_code=exc.status_code,
                headers={"WWW-Authenticate": 'Bearer realm="mcp"'},
            )
            await response(scope, receive, send)
            return

        if request.method == "GET" and "text/event-stream" not in (
            request.headers.get("accept") or ""
        ):
            info_response = JSONResponse(
                {
                    "protocol": "mcp-streamable-http",
                    "framework": "microsoft-agent-framework",
                    "serverInfo": {"name": "validation-lab-mcp", "version": "1.0.0"},
                    "authenticatedSubject": claims.subject,
                }
            )
            await info_response(scope, receive, send)
            return

        # Ensure Accept header includes application/json so stateless JSON-RPC callers succeed
        headers = list(scope.get("headers") or [])
        has_accept = any(k.lower() == b"accept" for k, _ in headers)
        if not has_accept:
            headers.append((b"accept", b"application/json, text/event-stream"))
        else:
            headers = [
                (
                    k,
                    b"application/json, text/event-stream"
                    if k.lower() == b"accept" and b"application/json" not in v.lower()
                    else v,
                )
                for k, v in headers
            ]
        patched_scope = dict(scope)
        patched_scope["headers"] = headers

        token = _CURRENT_CALLER.set(claims)
        try:
            if self._session_manager is not None:
                await self._session_manager.handle_request(patched_scope, receive, send)
            else:
                temp_manager = StreamableHTTPSessionManager(
                    app=self._mcp_server,
                    json_response=True,
                    stateless=True,
                )
                async with temp_manager.run():
                    await temp_manager.handle_request(patched_scope, receive, send)
        finally:
            _CURRENT_CALLER.reset(token)


def create_mcp_app(settings: LabServiceSettings | None = None) -> Starlette:
    cfg = settings or load_service_settings(
        default_name="app-apv-mcp-api",
        default_role="Mcp.Tool.Invoke",
    )
    validator = EntraJwtValidator(cfg)
    agent, tool_registry = build_mcp_agent()
    mcp_server = create_agent_framework_mcp_server(agent, tool_registry)
    mcp_asgi: ASGIApp = _AuthenticatedMcpAsgiApp(validator=validator, mcp_server=mcp_server)

    @contextlib.asynccontextmanager
    async def lifespan(_app: Starlette) -> AsyncIterator[None]:
        assert isinstance(mcp_asgi, _AuthenticatedMcpAsgiApp)
        async with mcp_asgi.lifespan_context():
            yield

    async def healthz(_request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "status": "ok",
                "service": cfg.service_name,
                "protocol": "mcp-streamable-http",
                "framework": "microsoft-agent-framework",
                "agent": agent.name,
            }
        )

    routes = [
        Route("/healthz", healthz, methods=["GET"]),
        Route("/mcp", endpoint=mcp_asgi, methods=["GET", "POST", "DELETE"]),
        Route("/mcp/{rest:path}", endpoint=mcp_asgi, methods=["GET", "POST", "DELETE"]),
    ]
    return Starlette(routes=routes, lifespan=lifespan)


app = create_mcp_app()
