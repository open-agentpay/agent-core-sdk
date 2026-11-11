"""
AgentPay LangChain Middleware / Guard.

Implements declarative pre-execution interception for payment-protected tools.
Enforces fail-closed security, preventing protected tools from executing
unless AgentPay policy explicitly permits it.
"""

from __future__ import annotations

import functools
import inspect
from typing import Any, Callable

from pydantic import BaseModel, ConfigDict, Field

try:
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.tools import BaseTool, StructuredTool, ToolException
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "The 'langchain-core' package is required to use agentpay.integrations.langchain.guard. "
        "Please install it via: pip install 'agentpay[langchain]' or pip install langchain-core"
    ) from exc

from agent_core.client.client import AgentPayClient, AsyncAgentPayClient
from agent_core.contracts import (
    AgentPayIntegrationError,
    AgentPayPolicyDeniedError,
    PaymentRequest,
    ResourceContext,
)


class PaymentDeclaration(BaseModel):
    """Declarative specification attaching AgentPay protection to a tool."""

    model_config = ConfigDict(frozen=True)

    required: bool = Field(default=True, description="Whether execution strictly requires AgentPay authorization.")
    provider: str = Field(default="agentpay", description="Payment provider identifier.")
    resource_id: str = Field(description="AgentPay route or paid resource identifier.")
    amount: str | None = Field(default=None, description="Estimated cost or limit for this tool invocation.")
    asset: str = Field(default="USDC", description="Currency symbol (e.g. 'USDC').")


def protect_tool(
    tool: BaseTool,
    *,
    resource_id: str,
    client: AgentPayClient | None = None,
    amount: str | None = None,
    asset: str = "USDC",
    fail_closed: bool = True,
) -> BaseTool:
    """
    Wrap an existing LangChain BaseTool with AgentPay pre-execution guardrails.

    Before the wrapped tool executes, AgentPay evaluates policy and budget limits.
    If rejected or unreachable, execution is blocked (fail-closed).
    """
    declaration = PaymentDeclaration(
        required=True,
        resource_id=resource_id,
        amount=amount,
        asset=asset,
    )

    original_run = tool._run
    original_arun = tool._arun

    @functools.wraps(original_run)
    def guarded_run(*args: Any, **kwargs: Any) -> Any:
        active_client = client or getattr(tool, "client", None)
        if active_client is None:
            if fail_closed:
                raise ToolException(f"AgentPay Guard Error: No AgentPayClient configured for protected tool {tool.name}")
            return original_run(*args, **kwargs)

        req = PaymentRequest(
            resource=ResourceContext(resource_id=declaration.resource_id),
            idempotency_key=f"guard_check_{tool.name}",
            amount=declaration.amount,
            asset=declaration.asset,
        )

        try:
            decision = active_client.evaluate_policy(req)
            if not decision.is_allowed:
                raise ToolException(
                    f"AgentPay Guard Blocked: [{decision.reason_code}] {decision.reason or 'Policy denied execution'}"
                )
        except ToolException:
            raise
        except AgentPayPolicyDeniedError as exc:
            raise ToolException(f"AgentPay Guard Blocked: [{exc.code}] {exc.message}") from exc
        except AgentPayIntegrationError as exc:
            if fail_closed:
                raise ToolException(f"AgentPay Guard Fail-Closed: [{exc.code}] {exc.message}") from exc
        except Exception as exc:
            if fail_closed:
                raise ToolException(f"AgentPay Guard Fail-Closed: policy check failed ({exc})") from exc

        return original_run(*args, **kwargs)

    @functools.wraps(original_arun)
    async def guarded_arun(*args: Any, **kwargs: Any) -> Any:
        active_client = client or getattr(tool, "client", None)
        if active_client is None:
            if fail_closed:
                raise ToolException(f"AgentPay Guard Error: No AgentPayClient configured for protected tool {tool.name}")
            return await original_arun(*args, **kwargs)

        async_c = getattr(active_client, "async_client", None)
        async_c = async_c() if callable(async_c) else active_client

        req = PaymentRequest(
            resource=ResourceContext(resource_id=declaration.resource_id),
            idempotency_key=f"guard_check_{tool.name}",
            amount=declaration.amount,
            asset=declaration.asset,
        )

        try:
            decision = await async_c.evaluate_policy(req)
            if not decision.is_allowed:
                raise ToolException(
                    f"AgentPay Guard Blocked: [{decision.reason_code}] {decision.reason or 'Policy denied execution'}"
                )
        except ToolException:
            raise
        except AgentPayPolicyDeniedError as exc:
            raise ToolException(f"AgentPay Guard Blocked: [{exc.code}] {exc.message}") from exc
        except AgentPayIntegrationError as exc:
            if fail_closed:
                raise ToolException(f"AgentPay Guard Fail-Closed: [{exc.code}] {exc.message}") from exc
        except Exception as exc:
            if fail_closed:
                raise ToolException(f"AgentPay Guard Fail-Closed: policy check failed ({exc})") from exc

        return await original_arun(*args, **kwargs)

    tool._run = guarded_run  # type: ignore[method-assign]
    tool._arun = guarded_arun  # type: ignore[method-assign]
    setattr(tool, "_agentpay_payment", declaration)
    return tool


class AgentPayGuardCallbackHandler(BaseCallbackHandler):
    """
    LangChain CallbackHandler to intercept protected tool invocations.

    When on_tool_start fires for a protected tool, verifies policy authorization.
    """

    def __init__(self, client: AgentPayClient, fail_closed: bool = True) -> None:
        super().__init__()
        self.client = client
        self.fail_closed = fail_closed

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> Any:
        """Inspect tool metadata before tool execution begins."""
        metadata = serialized.get("metadata") or kwargs.get("metadata") or {}
        payment_meta = metadata.get("payment")

        if not payment_meta or not payment_meta.get("required"):
            return

        resource_id = payment_meta.get("resource_id") or serialized.get("name")
        amount = payment_meta.get("amount")
        asset = payment_meta.get("asset", "USDC")

        req = PaymentRequest(
            resource=ResourceContext(resource_id=resource_id),
            idempotency_key=f"callback_guard_{resource_id}",
            amount=amount,
            asset=asset,
        )

        try:
            decision = self.client.evaluate_policy(req)
            if not decision.is_allowed:
                raise ToolException(
                    f"AgentPay Guard Blocked: [{decision.reason_code}] {decision.reason or 'Policy denied execution'}"
                )
        except ToolException:
            raise
        except Exception as exc:
            if self.fail_closed:
                raise ToolException(f"AgentPay Guard Callback Fail-Closed: {exc}") from exc
