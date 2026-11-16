from __future__ import annotations

import contextvars
import json
import uuid
from collections.abc import AsyncIterable, Mapping, Sequence
from typing import Any

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore, TaskUpdater
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentInterface,
    AgentSkill,
    Part,
    Task,
    TaskState,
    TaskStatus,
)
from agent_framework import (
    Agent,
    BaseChatClient,
    ChatResponse,
    ChatResponseUpdate,
    Content,
    FunctionInvocationLayer,
    Message,
    ResponseStream,
    tool,
)
from google.protobuf.json_format import MessageToDict  # type: ignore[import-untyped]
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from samples.validation_lab.auth import AuthError, EntraJwtValidator, VerifiedClaims
from samples.validation_lab.config import LabServiceSettings, load_service_settings

_CURRENT_A2A_CALLER: contextvars.ContextVar[VerifiedClaims | None] = contextvars.ContextVar(
    "a2a_current_caller",
    default=None,
)


@tool(
    name="summarize_order_fulfillment",
    description="Summarize order fulfillment and shipping status for an order ID.",
)
def summarize_order_fulfillment(order_id: str) -> str:
    """Summarize order fulfillment status for a customer order."""
    normalized = order_id.strip() or "ord-1001"
    return f"Order {normalized} is fulfilled and ready in westus3."


class ConciergeAgentChatClient(FunctionInvocationLayer[Any], BaseChatClient[Any]):
    """Deterministic Microsoft Agent Framework chat client for the A2A concierge agent."""

    def _inner_get_response(
        self,
        *,
        messages: Sequence[Message],
        stream: bool,
        options: Mapping[str, Any],
        **kwargs: Any,
    ) -> Any:
        del options, kwargs
        prompt_text = messages[-1].text if messages else "status check"
        caller = _CURRENT_A2A_CALLER.get()
        subject = caller.subject if caller is not None else "agent-framework"
        reply = f"A2A concierge processed '{prompt_text}' for caller {subject}."
        if stream:

            async def _stream() -> AsyncIterable[ChatResponseUpdate]:
                yield ChatResponseUpdate(
                    contents=[Content.from_text(reply)],
                    role="assistant",
                    model="agent-framework-a2a-v1",
                )

            return ResponseStream(_stream(), finalizer=ChatResponse.from_updates)

        async def _complete() -> ChatResponse:
            return ChatResponse(
                messages=[Message("assistant", [reply])],
                model="agent-framework-a2a-v1",
            )

        return _complete()


def build_a2a_agent() -> Agent[Any]:
    """Create the Microsoft Agent Framework Agent backing the A2A endpoint."""
    return Agent(
        client=ConciergeAgentChatClient(),
        name="validation_lab_order_concierge",
        description=(
            "A2A order concierge agent built with Microsoft Agent Framework "
            "and secured with Microsoft Entra OAuth 2.0."
        ),
        instructions=(
            "You are the Validation Lab Order Concierge Agent. Summarize order fulfillment "
            "and API gateway posture for authenticated A2A callers."
        ),
        tools=[summarize_order_fulfillment],
    )


class AgentFrameworkA2AExecutor(AgentExecutor):
    """A2A SDK AgentExecutor that delegates task execution to a Microsoft Agent Framework Agent."""

    def __init__(self, agent: Agent[Any]) -> None:
        self._agent = agent

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        if not context.task_id or not context.context_id or not context.message:
            return
        updater = TaskUpdater(event_queue, context.task_id, context.context_id)
        if not context.current_task:
            await event_queue.enqueue_event(
                Task(
                    id=context.task_id,
                    context_id=context.context_id,
                    status=TaskStatus(state=TaskState.TASK_STATE_SUBMITTED),
                    history=[context.message],
                )
            )
        await updater.start_work()
        prompt_text = context.get_user_input().strip() or "status check"
        response = await self._agent.run(prompt_text, stream=False)
        await updater.add_artifact(
            [Part(text=response.text)],
            name="concierge-response",
        )
        await updater.complete()

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        if context.task_id and context.context_id:
            await TaskUpdater(event_queue, context.task_id, context.context_id).cancel()


def build_agent_card_proto(base_url: str) -> AgentCard:
    normalized_base = base_url.rstrip("/")
    return AgentCard(
        name="Validation Lab Order Concierge Agent",
        description=(
            "A2A order concierge agent built with Microsoft Agent Framework "
            "and secured with Microsoft Entra OAuth 2.0."
        ),
        version="1.0.0",
        default_input_modes=["text", "text/plain", "application/json"],
        default_output_modes=["text", "text/plain", "application/json"],
        capabilities=AgentCapabilities(
            streaming=False,
            push_notifications=False,
        ),
        supported_interfaces=[
            AgentInterface(
                url=f"{normalized_base}/a2a",
                protocol_binding="JSONRPC",
                protocol_version="1.0",
            )
        ],
        skills=[
            AgentSkill(
                id="order-concierge",
                name="Order Triage & Status Concierge",
                description="Summarize order fulfillment and API gateway posture.",
                tags=["orders", "apim", "validation-lab", "agent-framework"],
            )
        ],
    )


def build_agent_card(base_url: str) -> dict[str, Any]:
    card_proto = build_agent_card_proto(base_url)
    card_dict: dict[str, Any] = MessageToDict(card_proto)
    card_dict["url"] = f"{base_url.rstrip('/')}/a2a"
    card_dict["protocolVersion"] = "1.0"
    card_dict["framework"] = "microsoft-agent-framework"
    return card_dict


def _normalize_a2a_jsonrpc_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize v0.3/custom A2A JSON-RPC payloads for a2a-sdk v0.3 & v1.0 handlers."""
    method = str(payload.get("method") or "message/send")
    normalized_method = "message/send" if method in {"tasks/send", "agent/invoke"} else method
    params = dict(payload.get("params") or {}) if isinstance(payload.get("params"), dict) else {}
    message = params.get("message")
    if isinstance(message, dict):
        msg_copy = dict(message)
        if not msg_copy.get("messageId"):
            msg_copy["messageId"] = str(params.get("id") or f"msg-{uuid.uuid4().hex[:8]}")
        raw_parts = msg_copy.get("parts")
        if isinstance(raw_parts, list):
            normalized_parts: list[dict[str, Any]] = []
            for part in raw_parts:
                if isinstance(part, dict):
                    part_copy = dict(part)
                    if normalized_method == "message/send":
                        part_type = part_copy.pop("type", None)
                        if "kind" not in part_copy and isinstance(part_type, str):
                            part_copy["kind"] = part_type
                        elif "kind" not in part_copy and "text" in part_copy:
                            part_copy["kind"] = "text"
                    normalized_parts.append(part_copy)
            msg_copy["parts"] = normalized_parts
        params["message"] = msg_copy
    return {
        **payload,
        "method": normalized_method,
        "params": params,
    }


def create_a2a_app(settings: LabServiceSettings | None = None) -> Starlette:
    cfg = settings or load_service_settings(
        default_name="app-apv-a2a-api",
        default_role="A2A.Agent.Invoke",
    )
    validator = EntraJwtValidator(cfg)
    agent = build_a2a_agent()
    default_card = build_agent_card_proto("http://localhost:8080")
    request_handler = DefaultRequestHandler(
        agent_executor=AgentFrameworkA2AExecutor(agent),
        task_store=InMemoryTaskStore(),
        agent_card=default_card,
    )
    jsonrpc_routes = create_jsonrpc_routes(
        request_handler=request_handler,
        rpc_url="/a2a",
        enable_v0_3_compat=True,
    )
    a2a_rpc_endpoint = jsonrpc_routes[0].endpoint

    async def healthz(_request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "status": "ok",
                "service": cfg.service_name,
                "protocol": "a2a-jsonrpc",
                "framework": "microsoft-agent-framework",
                "agent": agent.name,
            }
        )

    async def agent_card(request: Request) -> JSONResponse:
        try:
            validator.verify_authorization_header(request.headers.get("authorization"))
        except AuthError as exc:
            return JSONResponse(
                {"error": exc.message},
                status_code=exc.status_code,
                headers={"WWW-Authenticate": 'Bearer realm="a2a"'},
            )
        base_url = str(request.base_url).rstrip("/")
        return JSONResponse(build_agent_card(base_url))

    async def handle_a2a(request: Request) -> Response:
        try:
            claims = validator.verify_authorization_header(request.headers.get("authorization"))
        except AuthError as exc:
            return JSONResponse(
                {"error": exc.message},
                status_code=exc.status_code,
                headers={"WWW-Authenticate": 'Bearer realm="a2a"'},
            )

        if request.method == "GET":
            base_url = str(request.base_url).rstrip("/")
            return JSONResponse(build_agent_card(base_url))

        try:
            raw_payload: dict[str, Any] = await request.json()
        except Exception:
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "Parse error"},
                },
                status_code=400,
            )

        normalized_payload = _normalize_a2a_jsonrpc_payload(raw_payload)
        normalized_bytes = json.dumps(normalized_payload).encode("utf-8")

        async def _patched_receive() -> dict[str, Any]:
            return {"type": "http.request", "body": normalized_bytes, "more_body": False}

        patched_request = Request(request.scope, receive=_patched_receive)
        token = _CURRENT_A2A_CALLER.set(claims)
        try:
            response: Response = await a2a_rpc_endpoint(patched_request)
            return response
        finally:
            _CURRENT_A2A_CALLER.reset(token)

    routes = [
        Route("/healthz", healthz, methods=["GET"]),
        Route("/.well-known/agent.json", agent_card, methods=["GET"]),
        Route("/.well-known/agent-card.json", agent_card, methods=["GET"]),
        Route("/a2a", handle_a2a, methods=["GET", "POST"]),
        Route("/", handle_a2a, methods=["GET", "POST"]),
    ]
    return Starlette(routes=routes)


app = create_a2a_app()
