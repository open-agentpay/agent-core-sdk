"""
LangChain Explicit AgentPay Tools: AgentPayPayTool and AgentPayGetPaymentTool.

Enables LangChain agents to explicitly initiate payments for declared resources,
satisfy x402 challenges, and poll asynchronous settlement statuses.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

try:
    from langchain_core.tools import BaseTool, ToolException
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "The 'langchain-core' package is required to use agentpay.integrations.langchain.tools. "
        "Please install it via: pip install 'agentpay[langchain]' or pip install langchain-core"
    ) from exc

from agent_core.client.client import AgentPayClient, AsyncAgentPayClient
from agent_core.contracts import (
    AgentPayBudgetExceededError,
    AgentPayIntegrationError,
    AgentPayPolicyDeniedError,
    PaymentRequest,
    ResourceContext,
)


class AgentPayPayInput(BaseModel):
    """Schema for agentpay_pay tool invocation arguments."""

    model_config = ConfigDict(frozen=True)

    resource_id: str = Field(
        description="The unique identifier of the target paid resource or registered gateway route."
    )
    challenge_id: str | None = Field(
        default=None,
        description="Optional payment challenge identifier if received from an HTTP 402 challenge.",
    )
    amount: str | None = Field(
        default=None,
        description="Optional payment amount as a decimal string (e.g. '0.20'). If omitted, route default price is used.",
    )
    asset: str | None = Field(
        default="USDC",
        description="Currency or asset symbol (e.g. 'USDC', 'CNY'). Defaults to 'USDC'.",
    )
    network: str | None = Field(
        default=None,
        description="Target settlement network (e.g. 'base', 'ethereum').",
    )
    idempotency_key: str | None = Field(
        default=None,
        description="Unique client-generated idempotency key preventing duplicate charges. Auto-generated if omitted.",
    )


class AgentPayPayTool(BaseTool):
    """
    LangChain tool for executing payments against AgentPay Financial Control Layer.

    Authorizes payments, holds budget from virtual wallets, and initiates settlement.
    """

    name: str = "agentpay_pay"
    description: str = (
        "Request payment authorization and execute payment for a declared paid resource or 402 challenge. "
        "Returns structured three-domain payment status (payment, settlement, fulfillment). "
        "If budget is exceeded or policy is denied, returns a rejection explanation."
    )
    args_schema: type[BaseModel] = AgentPayPayInput
    client: AgentPayClient | None = None
    async_client: AsyncAgentPayClient | None = None
    handle_policy_violation: bool = True
    handle_tool_error: bool = True

    def _run(
        self,
        resource_id: str,
        challenge_id: str | None = None,
        amount: str | None = None,
        asset: str | None = "USDC",
        network: str | None = None,
        idempotency_key: str | None = None,
        **kwargs: Any,
    ) -> str:
        """Synchronously execute payment."""
        if self.client is None:
            raise ToolException("AgentPayPayTool requires a configured AgentPayClient instance.")

        req = PaymentRequest(
            resource=ResourceContext(resource_id=resource_id, challenge_id=challenge_id),
            idempotency_key=idempotency_key or "",
            amount=amount,
            asset=asset,
            network=network,
        )

        try:
            result = self.client.pay(req)
            return json.dumps(
                {
                    "payment_intent_id": result.payment_intent_id,
                    "decision": result.decision,
                    "payment_status": str(result.payment_status),
                    "settlement_status": str(result.settlement_status),
                    "fulfillment_status": str(result.fulfillment_status),
                    "amount": result.amount,
                    "asset": result.asset,
                    "idempotency_key": result.idempotency_key,
                    "next_action": result.next_action,
                },
                ensure_ascii=False,
            )
        except AgentPayBudgetExceededError as exc:
            if self.handle_policy_violation:
                return f"AgentPay Budget Exceeded: [{exc.code}] {exc.message}. Please request budget approval."
            raise ToolException(str(exc)) from exc
        except AgentPayPolicyDeniedError as exc:
            if self.handle_policy_violation:
                return f"AgentPay Firewall Rejected: [{exc.code}] {exc.message}."
            raise ToolException(str(exc)) from exc
        except AgentPayIntegrationError as exc:
            if self.handle_policy_violation:
                return f"AgentPay Integration Error: [{exc.code}] {exc.message}."
            raise ToolException(str(exc)) from exc
        except Exception as exc:
            raise ToolException(f"Payment execution failed: {exc}") from exc

    async def _arun(
        self,
        resource_id: str,
        challenge_id: str | None = None,
        amount: str | None = None,
        asset: str | None = "USDC",
        network: str | None = None,
        idempotency_key: str | None = None,
        **kwargs: Any,
    ) -> str:
        """Asynchronously execute payment."""
        client = self.async_client or (self.client.async_client() if self.client else None)
        if client is None:
            return self._run(
                resource_id=resource_id,
                challenge_id=challenge_id,
                amount=amount,
                asset=asset,
                network=network,
                idempotency_key=idempotency_key,
                **kwargs,
            )

        req = PaymentRequest(
            resource=ResourceContext(resource_id=resource_id, challenge_id=challenge_id),
            idempotency_key=idempotency_key or "",
            amount=amount,
            asset=asset,
            network=network,
        )

        try:
            result = await client.pay(req)
            return json.dumps(
                {
                    "payment_intent_id": result.payment_intent_id,
                    "decision": result.decision,
                    "payment_status": str(result.payment_status),
                    "settlement_status": str(result.settlement_status),
                    "fulfillment_status": str(result.fulfillment_status),
                    "amount": result.amount,
                    "asset": result.asset,
                    "idempotency_key": result.idempotency_key,
                    "next_action": result.next_action,
                },
                ensure_ascii=False,
            )
        except AgentPayBudgetExceededError as exc:
            if self.handle_policy_violation:
                return f"AgentPay Budget Exceeded: [{exc.code}] {exc.message}. Please request budget approval."
            raise ToolException(str(exc)) from exc
        except AgentPayPolicyDeniedError as exc:
            if self.handle_policy_violation:
                return f"AgentPay Firewall Rejected: [{exc.code}] {exc.message}."
            raise ToolException(str(exc)) from exc
        except AgentPayIntegrationError as exc:
            if self.handle_policy_violation:
                return f"AgentPay Integration Error: [{exc.code}] {exc.message}."
            raise ToolException(str(exc)) from exc
        except Exception as exc:
            raise ToolException(f"Payment execution failed: {exc}") from exc


class AgentPayGetPaymentInput(BaseModel):
    """Schema for agentpay_get_payment tool invocation arguments."""

    model_config = ConfigDict(frozen=True)

    payment_intent_id: str = Field(
        description="The unique payment intent identifier (e.g. 'pi_xxx') to query."
    )


class AgentPayGetPaymentTool(BaseTool):
    """
    LangChain tool for querying the three-domain lifecycle status of an existing payment intent.
    """

    name: str = "agentpay_get_payment"
    description: str = (
        "Query current status of an existing payment intent across payment intent, "
        "settlement, and fulfillment domains. Useful for polling asynchronous settlements."
    )
    args_schema: type[BaseModel] = AgentPayGetPaymentInput
    client: AgentPayClient | None = None
    async_client: AsyncAgentPayClient | None = None
    handle_tool_error: bool = True

    def _run(self, payment_intent_id: str, **kwargs: Any) -> str:
        """Synchronously query payment status."""
        if self.client is None:
            raise ToolException("AgentPayGetPaymentTool requires a configured AgentPayClient instance.")

        try:
            result = self.client.get_payment(payment_intent_id)
            return json.dumps(
                {
                    "payment_intent_id": result.payment_intent_id,
                    "decision": result.decision,
                    "payment_status": str(result.payment_status),
                    "settlement_status": str(result.settlement_status),
                    "fulfillment_status": str(result.fulfillment_status),
                    "amount": result.amount,
                    "asset": result.asset,
                    "transaction_hash": result.transaction_hash,
                    "next_action": result.next_action,
                },
                ensure_ascii=False,
            )
        except AgentPayIntegrationError as exc:
            return f"AgentPay Query Failed: [{exc.code}] {exc.message}"
        except Exception as exc:
            raise ToolException(f"Failed to query payment status: {exc}") from exc

    async def _arun(self, payment_intent_id: str, **kwargs: Any) -> str:
        """Asynchronously query payment status."""
        client = self.async_client or (self.client.async_client() if self.client else None)
        if client is None:
            return self._run(payment_intent_id=payment_intent_id, **kwargs)

        try:
            result = await client.get_payment(payment_intent_id)
            return json.dumps(
                {
                    "payment_intent_id": result.payment_intent_id,
                    "decision": result.decision,
                    "payment_status": str(result.payment_status),
                    "settlement_status": str(result.settlement_status),
                    "fulfillment_status": str(result.fulfillment_status),
                    "amount": result.amount,
                    "asset": result.asset,
                    "transaction_hash": result.transaction_hash,
                    "next_action": result.next_action,
                },
                ensure_ascii=False,
            )
        except AgentPayIntegrationError as exc:
            return f"AgentPay Query Failed: [{exc.code}] {exc.message}"
        except Exception as exc:
            raise ToolException(f"Failed to query payment status: {exc}") from exc


def get_agentpay_tools(client: AgentPayClient | None = None) -> list[BaseTool]:
    """
    Convenience factory to construct the standard AgentPay toolset for a LangChain agent.
    """
    return [
        AgentPayPayTool(client=client),
        AgentPayGetPaymentTool(client=client),
    ]
