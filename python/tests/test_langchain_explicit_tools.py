"""
Unit tests for LangChain Explicit AgentPay Tools and Guard Middleware.
"""

from __future__ import annotations

import json
import pytest
import httpx

from langchain_core.tools import StructuredTool, ToolException

from agent_core.client.client import AgentPayClient, AsyncAgentPayClient
from agent_core.integrations.langchain import (
    AgentPayGetPaymentTool,
    AgentPayPayTool,
    get_agentpay_tools,
    protect_tool,
)
from agent_core.policy.models import PolicyConfig
from agent_core.policy.sqlite_engine import SQLitePolicyEngine


def _create_test_policy() -> SQLitePolicyEngine:
    cfg = PolicyConfig(
        id="test_lc_policy",
        max_per_tx_base_units=1_000_000_000,
        rolling_budget_24h_base_units=10_000_000_000,
        whitelist_domains={"*"},
    )
    return SQLitePolicyEngine.create_in_memory(cfg)


def test_agentpay_pay_tool_run():
    """Verify AgentPayPayTool execution and error handling."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/integrations/payments":
            payload = json.loads(request.content)
            if payload.get("amount") == "999.00":
                return httpx.Response(
                    403,
                    json={
                        "error": {
                            "code": "BUDGET_EXCEEDED",
                            "message": "Quota limit reached",
                        }
                    },
                )
            return httpx.Response(
                200,
                json={
                    "payment_intent_id": "pi_tool_001",
                    "decision": "ALLOW",
                    "payment_status": "AUTHORIZED",
                    "settlement_status": "HELD",
                    "fulfillment_status": "NOT_STARTED",
                    "amount": "0.20",
                    "asset": "USDC",
                    "idempotency_key": payload.get("idempotency_key", "idem"),
                    "next_action": "POLL_STATUS",
                },
            )
        return httpx.Response(404)

    client = AgentPayClient(
        api_key="apk_tool_test",
        policy=_create_test_policy(),
        transport=httpx.MockTransport(handler),
    )

    pay_tool = AgentPayPayTool(client=client)
    res_str = pay_tool.run({"resource_id": "weather_api", "amount": "0.20"})
    res_data = json.loads(res_str)
    assert res_data["payment_intent_id"] == "pi_tool_001"
    assert res_data["payment_status"] == "AUTHORIZED"

    # Test Budget Exceeded friendly message
    denied_str = pay_tool.run({"resource_id": "expensive_api", "amount": "999.00"})
    assert "AgentPay Budget Exceeded" in denied_str


def test_agentpay_get_payment_tool_run():
    """Verify AgentPayGetPaymentTool querying."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/integrations/payments/pi_tool_001":
            return httpx.Response(
                200,
                json={
                    "payment_intent_id": "pi_tool_001",
                    "decision": "ALLOW",
                    "payment_status": "COMPLETED",
                    "settlement_status": "CONFIRMED",
                    "fulfillment_status": "DELIVERED",
                    "amount": "0.20",
                    "asset": "USDC",
                    "idempotency_key": "idem",
                    "next_action": "NONE",
                },
            )
        return httpx.Response(404)

    client = AgentPayClient(
        api_key="apk_tool_test",
        policy=_create_test_policy(),
        transport=httpx.MockTransport(handler),
    )

    query_tool = AgentPayGetPaymentTool(client=client)
    res_str = query_tool.run({"payment_intent_id": "pi_tool_001"})
    res_data = json.loads(res_str)
    assert res_data["payment_status"] == "COMPLETED"
    assert res_data["settlement_status"] == "CONFIRMED"
    assert res_data["fulfillment_status"] == "DELIVERED"


def test_get_agentpay_tools_factory():
    """Verify get_agentpay_tools convenience helper."""
    tools = get_agentpay_tools()
    assert len(tools) == 2
    tool_names = [t.name for t in tools]
    assert "agentpay_pay" in tool_names
    assert "agentpay_get_payment" in tool_names


def test_protect_tool_guard_interception():
    """Verify protect_tool pre-execution interception and fail-closed security."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/integrations/policies/evaluate":
            payload = json.loads(request.content)
            res_id = payload["resource"]["resource_id"]
            if res_id == "blocked_resource":
                return httpx.Response(
                    200,
                    json={
                        "decision": "DENY",
                        "decision_id": "pd_denied",
                        "reason_code": "ERR_MERCHANT_BLOCKED",
                        "reason": "Merchant route is blocked by policy",
                    },
                )
            return httpx.Response(
                200,
                json={
                    "decision": "ALLOW",
                    "decision_id": "pd_allow",
                    "reason_code": "POLICY_PASSED",
                    "reason": "passed",
                },
            )
        return httpx.Response(404)

    client = AgentPayClient(
        api_key="apk_tool_test",
        policy=_create_test_policy(),
        transport=httpx.MockTransport(handler),
    )

    was_called = False

    def raw_data_lookup(query: str) -> str:
        nonlocal was_called
        was_called = True
        return f"result for {query}"

    tool = StructuredTool.from_function(func=raw_data_lookup, name="data_lookup", description="Lookup data")

    # 1. Protect with allowed resource
    protected_allowed = protect_tool(tool, resource_id="allowed_resource", client=client)
    res = protected_allowed.run({"query": "apple"})
    assert res == "result for apple"
    assert was_called is True

    # 2. Protect with blocked resource
    was_called = False
    protected_blocked = protect_tool(tool, resource_id="blocked_resource", client=client)
    with pytest.raises(ToolException) as exc_info:
        protected_blocked.run({"query": "banana"})
    assert "AgentPay Guard Blocked" in str(exc_info.value)
    assert was_called is False  # Target function was blocked from executing!
