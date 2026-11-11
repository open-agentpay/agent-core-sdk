"""
OpenAI Agents & Function Calling Adapter for AgentPay.

Provides OpenAI tool definitions, tool-call execution handlers, and pre-execution guards.
Compatible with standard OpenAI Chat Completions API, OpenAI Assistants API,
and OpenAI Agents SDK.
"""

from __future__ import annotations

import json
from typing import Any

from agent_core.client.client import AgentPayClient, AsyncAgentPayClient
from agent_core.contracts import (
    AgentPayBudgetExceededError,
    AgentPayIntegrationError,
    AgentPayPolicyDeniedError,
    PaymentRequest,
    ResourceContext,
)

AGENTPAY_PAY_TOOL_DEFINITION: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "agentpay_pay",
        "description": (
            "Request payment authorization and execute payment for a declared paid resource or 402 challenge. "
            "Returns structured three-domain payment status (payment, settlement, fulfillment)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "resource_id": {
                    "type": "string",
                    "description": "The unique identifier of the target paid resource or registered route.",
                },
                "challenge_id": {
                    "type": "string",
                    "description": "Optional payment challenge identifier if received from an HTTP 402 response.",
                },
                "amount": {
                    "type": "string",
                    "description": "Optional payment amount as a decimal string (e.g. '0.20'). If omitted, route default is used.",
                },
                "asset": {
                    "type": "string",
                    "description": "Cryptocurrency or fiat asset code (e.g. 'USDC', 'USD'). Default is 'USDC'.",
                    "default": "USDC",
                },
                "network": {
                    "type": "string",
                    "description": "Blockchain or settlement network (e.g. 'base', 'ethereum', 'polygon').",
                },
                "idempotency_key": {
                    "type": "string",
                    "description": "Client-generated idempotency key to prevent double charging on retry.",
                },
            },
            "required": ["resource_id"],
        },
    },
}

AGENTPAY_GET_PAYMENT_TOOL_DEFINITION: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "agentpay_get_payment",
        "description": (
            "Query the current three-domain lifecycle status of an existing payment intent "
            "(payment_status, settlement_status, fulfillment_status). Useful for polling asynchronous settlements."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "payment_intent_id": {
                    "type": "string",
                    "description": "The unique payment intent identifier to check.",
                },
            },
            "required": ["payment_intent_id"],
        },
    },
}


def get_openai_tools() -> list[dict[str, Any]]:
    """Return the list of OpenAI function tool definitions for AgentPay."""
    return [AGENTPAY_PAY_TOOL_DEFINITION, AGENTPAY_GET_PAYMENT_TOOL_DEFINITION]


def _extract_tool_call_info(tool_call: Any) -> tuple[str, str, dict[str, Any]]:
    """Extract tool_call_id, function_name, and parsed arguments dict from tool_call."""
    if hasattr(tool_call, "id") and hasattr(tool_call, "function"):
        tool_call_id = tool_call.id
        fn_name = tool_call.function.name
        args_raw = tool_call.function.arguments
    elif isinstance(tool_call, dict):
        tool_call_id = tool_call.get("id", "")
        fn = tool_call.get("function", {})
        fn_name = fn.get("name", "")
        args_raw = fn.get("arguments", {})
    else:
        raise ValueError(f"Unsupported tool_call object type: {type(tool_call)}")

    if isinstance(args_raw, str):
        try:
            args = json.loads(args_raw)
        except json.JSONDecodeError:
            args = {}
    elif isinstance(args_raw, dict):
        args = args_raw
    else:
        args = {}

    return tool_call_id, fn_name, args


def handle_openai_tool_call(
    tool_call: Any,
    client: AgentPayClient,
) -> dict[str, Any]:
    """Execute an OpenAI tool call against AgentPay and format a tool message response.

    Returns an OpenAI tool message dict:
    {
        "tool_call_id": "<id>",
        "role": "tool",
        "name": "<name>",
        "content": "<json_result_or_error_string>"
    }
    """
    tool_call_id, fn_name, args = _extract_tool_call_info(tool_call)

    if fn_name == "agentpay_pay":
        resource_id = args.get("resource_id") or args.get("resourceId")
        if not resource_id:
            content = json.dumps({"error": "resource_id is required"})
        else:
            try:
                req = PaymentRequest(
                    resource=ResourceContext(
                        resource_id=resource_id,
                        challenge_id=args.get("challenge_id") or args.get("challengeId"),
                    ),
                    amount=args.get("amount"),
                    asset=args.get("asset", "USDC"),
                    network=args.get("network"),
                    idempotency_key=args.get("idempotency_key") or args.get("idempotencyKey"),
                )
                res = client.pay(req)
                content = json.dumps(res.model_dump())
            except AgentPayBudgetExceededError as exc:
                content = json.dumps({
                    "status": "REJECTED",
                    "error_code": exc.code,
                    "message": exc.message,
                    "next_action": exc.next_action or "REQUEST_BUDGET_APPROVAL",
                })
            except AgentPayPolicyDeniedError as exc:
                content = json.dumps({
                    "status": "DENIED",
                    "error_code": exc.code,
                    "message": exc.message,
                    "next_action": exc.next_action,
                })
            except AgentPayIntegrationError as exc:
                content = json.dumps({
                    "status": "ERROR",
                    "error_code": exc.code,
                    "message": exc.message,
                    "next_action": exc.next_action,
                })
            except Exception as exc:
                content = json.dumps({"status": "ERROR", "message": str(exc)})

    elif fn_name == "agentpay_get_payment":
        payment_intent_id = args.get("payment_intent_id") or args.get("paymentIntentId")
        if not payment_intent_id:
            content = json.dumps({"error": "payment_intent_id is required"})
        else:
            try:
                res = client.get_payment(payment_intent_id)
                content = json.dumps(res.model_dump())
            except Exception as exc:
                content = json.dumps({"status": "ERROR", "message": str(exc)})
    else:
        content = json.dumps({"error": f"Unknown tool name: {fn_name}"})

    return {
        "tool_call_id": tool_call_id,
        "role": "tool",
        "name": fn_name,
        "content": content,
    }


async def handle_async_openai_tool_call(
    tool_call: Any,
    client: AsyncAgentPayClient,
) -> dict[str, Any]:
    """Asynchronously execute an OpenAI tool call against AsyncAgentPayClient."""
    tool_call_id, fn_name, args = _extract_tool_call_info(tool_call)

    if fn_name == "agentpay_pay":
        resource_id = args.get("resource_id") or args.get("resourceId")
        if not resource_id:
            content = json.dumps({"error": "resource_id is required"})
        else:
            try:
                req = PaymentRequest(
                    resource=ResourceContext(
                        resource_id=resource_id,
                        challenge_id=args.get("challenge_id") or args.get("challengeId"),
                    ),
                    amount=args.get("amount"),
                    asset=args.get("asset", "USDC"),
                    network=args.get("network"),
                    idempotency_key=args.get("idempotency_key") or args.get("idempotencyKey"),
                )
                res = await client.pay(req)
                content = json.dumps(res.model_dump())
            except AgentPayBudgetExceededError as exc:
                content = json.dumps({
                    "status": "REJECTED",
                    "error_code": exc.code,
                    "message": exc.message,
                    "next_action": exc.next_action or "REQUEST_BUDGET_APPROVAL",
                })
            except AgentPayPolicyDeniedError as exc:
                content = json.dumps({
                    "status": "DENIED",
                    "error_code": exc.code,
                    "message": exc.message,
                    "next_action": exc.next_action,
                })
            except AgentPayIntegrationError as exc:
                content = json.dumps({
                    "status": "ERROR",
                    "error_code": exc.code,
                    "message": exc.message,
                    "next_action": exc.next_action,
                })
            except Exception as exc:
                content = json.dumps({"status": "ERROR", "message": str(exc)})

    elif fn_name == "agentpay_get_payment":
        payment_intent_id = args.get("payment_intent_id") or args.get("paymentIntentId")
        if not payment_intent_id:
            content = json.dumps({"error": "payment_intent_id is required"})
        else:
            try:
                res = await client.get_payment(payment_intent_id)
                content = json.dumps(res.model_dump())
            except Exception as exc:
                content = json.dumps({"status": "ERROR", "message": str(exc)})
    else:
        content = json.dumps({"error": f"Unknown tool name: {fn_name}"})

    return {
        "tool_call_id": tool_call_id,
        "role": "tool",
        "name": fn_name,
        "content": content,
    }


def protect_openai_function(
    resource_id: str,
    client: AgentPayClient,
    amount: str | None = None,
    asset: str = "USDC",
    fail_closed: bool = True,
):
    """Decorator for an OpenAI function implementation to guard execution with AgentPay policy dry-run."""

    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                req = PaymentRequest(
                    resource=ResourceContext(resource_id=resource_id),
                    amount=amount,
                    asset=asset,
                )
                decision = client.evaluate_policy(req)
                if decision.decision != "ALLOW":
                    raise AgentPayPolicyDeniedError(
                        message=f"AgentPay Policy Denied: [{decision.reason_code}] {decision.reason}",
                        code=decision.reason_code,
                    )
            except Exception as exc:
                if isinstance(exc, AgentPayPolicyDeniedError):
                    raise
                if fail_closed:
                    raise AgentPayPolicyDeniedError(
                        message=f"AgentPay Guard Fail-Closed: {exc}",
                        code="GUARD_FAIL_CLOSED",
                    ) from exc
            return func(*args, **kwargs)

        return wrapper

    return decorator
