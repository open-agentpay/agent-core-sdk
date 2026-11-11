"""
CrewAI Integration for AgentPay.

Enables CrewAI agents and crews to execute explicit payments and query settlement status.
"""

from __future__ import annotations

import json
from typing import Any, Type

from pydantic import BaseModel, Field

try:
    from crewai.tools import BaseTool as _BaseTool
except ImportError:
    try:
        from langchain_core.tools import BaseTool as _BaseTool
    except ImportError:  # pragma: no cover
        class _BaseTool(BaseModel):  # type: ignore
            name: str
            description: str
            def run(self, *args, **kwargs):
                return self._run(*args, **kwargs)

from agent_core.client.client import AgentPayClient
from agent_core.contracts import (
    AgentPayBudgetExceededError,
    AgentPayIntegrationError,
    AgentPayPolicyDeniedError,
    PaymentRequest,
    ResourceContext,
)


class CrewAIPayInput(BaseModel):
    """Input schema for CrewAI AgentPay pay tool."""
    resource_id: str = Field(..., description="Unique resource identifier or route ID.")
    challenge_id: str | None = Field(None, description="Optional HTTP 402 challenge ID.")
    amount: str | None = Field(None, description="Optional payment amount as a decimal string.")
    asset: str = Field("USDC", description="Asset ticker, default USDC.")
    network: str | None = Field(None, description="Settlement network.")
    idempotency_key: str | None = Field(None, description="Unique idempotency key.")


class CrewAIGetPaymentInput(BaseModel):
    """Input schema for CrewAI AgentPay get payment tool."""
    payment_intent_id: str = Field(..., description="Payment intent ID to query.")


class AgentPayCrewPayTool(_BaseTool):
    """CrewAI tool for executing payment for declared resources."""

    name: str = "agentpay_pay"
    description: str = (
        "Request payment authorization and execute payment for a declared paid resource or 402 challenge. "
        "Returns structured three-domain payment status."
    )
    args_schema: Type[BaseModel] = CrewAIPayInput
    client: Any = Field(default=None, exclude=True)

    def __init__(self, client: AgentPayClient, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        object.__setattr__(self, "client", client)

    def run(self, tool_input: Any = None, **kwargs: Any) -> str:
        merged = {}
        if isinstance(tool_input, dict):
            merged.update(tool_input)
        merged.update(kwargs)
        return self._run(**merged)

    def _run(
        self,
        resource_id: str,
        challenge_id: str | None = None,
        amount: str | None = None,
        asset: str = "USDC",
        network: str | None = None,
        idempotency_key: str | None = None,
        **kwargs: Any,
    ) -> str:
        try:
            req = PaymentRequest(
                resource=ResourceContext(resource_id=resource_id, challenge_id=challenge_id),
                amount=amount,
                asset=asset,
                network=network,
                idempotency_key=idempotency_key,
            )
            result = self.client.pay(req)
            return json.dumps(result.model_dump())
        except AgentPayBudgetExceededError as exc:
            return f"AgentPay Budget Exceeded: [{exc.code}] {exc.message}. Please request budget approval."
        except AgentPayPolicyDeniedError as exc:
            return f"AgentPay Policy Denied: [{exc.code}] {exc.message}."
        except AgentPayIntegrationError as exc:
            return f"AgentPay Integration Error: [{exc.code}] {exc.message}."
        except Exception as exc:
            return f"Payment execution failed: {exc}"


class AgentPayCrewGetPaymentTool(_BaseTool):
    """CrewAI tool for querying payment lifecycle status."""

    name: str = "agentpay_get_payment"
    description: str = (
        "Query current status of an existing payment intent across payment intent, "
        "settlement, and fulfillment domains."
    )
    args_schema: Type[BaseModel] = CrewAIGetPaymentInput
    client: Any = Field(default=None, exclude=True)

    def __init__(self, client: AgentPayClient, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        object.__setattr__(self, "client", client)

    def run(self, tool_input: Any = None, **kwargs: Any) -> str:
        merged = {}
        if isinstance(tool_input, dict):
            merged.update(tool_input)
        elif isinstance(tool_input, str):
            merged["payment_intent_id"] = tool_input
        merged.update(kwargs)
        return self._run(**merged)

    def _run(self, payment_intent_id: str, **kwargs: Any) -> str:
        try:
            result = self.client.get_payment(payment_intent_id)
            return json.dumps(result.model_dump())
        except Exception as exc:
            return f"AgentPay Query Failed: {exc}"


def get_crewai_tools(client: AgentPayClient) -> list[_BaseTool]:
    """Return all AgentPay tools configured for CrewAI."""
    return [AgentPayCrewPayTool(client=client), AgentPayCrewGetPaymentTool(client=client)]
