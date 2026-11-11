"""Tests for OpenAI and CrewAI adapters."""

import json
import httpx
import pytest

from agent_core.client.client import AgentPayClient, AsyncAgentPayClient
from agent_core.contracts import (
    AgentPayBudgetExceededError,
    AgentPayPolicyDeniedError,
    PaymentRequest,
    ResourceContext,
)
from agent_core.integrations.crewai import (
    AgentPayCrewGetPaymentTool,
    AgentPayCrewPayTool,
    get_crewai_tools,
)
from agent_core.integrations.openai import (
    get_openai_tools,
    handle_async_openai_tool_call,
    handle_openai_tool_call,
    protect_openai_function,
)
from agent_core.policy.sqlite_engine import SQLitePolicyEngine
from agent_core.policy.models import PolicyConfig


def _create_test_policy() -> SQLitePolicyEngine:
    cfg = PolicyConfig(
        id="adapter_test_policy",
        max_per_tx_base_units=1_000_000_000,
        rolling_budget_24h_base_units=10_000_000_000,
        whitelist_domains={"*"},
    )
    return SQLitePolicyEngine.create_in_memory(cfg)


def test_openai_tool_definitions():
    tools = get_openai_tools()
    assert len(tools) == 2
    names = {t["function"]["name"] for t in tools}
    assert "agentpay_pay" in names
    assert "agentpay_get_payment" in names


def test_openai_tool_call_handler_success():
    def mock_handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "/api/v1/integrations/payments" in url and request.method == "POST":
            return httpx.Response(
                200,
                json={
                    "payment_intent_id": "pi_oai_1",
                    "decision": "ALLOW",
                    "payment_status": "AUTHORIZED",
                    "settlement_status": "HELD",
                    "fulfillment_status": "NOT_STARTED",
                    "amount": "0.15",
                    "asset": "USDC",
                    "idempotency_key": "idem_oai",
                    "next_action": "POLL_STATUS",
                },
            )
        elif "/api/v1/integrations/payments/pi_oai_1" in url and request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "payment_intent_id": "pi_oai_1",
                    "decision": "ALLOW",
                    "payment_status": "COMPLETED",
                    "settlement_status": "CONFIRMED",
                    "fulfillment_status": "DELIVERED",
                    "amount": "0.15",
                    "asset": "USDC",
                    "idempotency_key": "idem_oai",
                    "next_action": "NONE",
                },
            )
        return httpx.Response(404)

    client = AgentPayClient(
        api_key="test_oai_key",
        policy=_create_test_policy(),
        transport=httpx.MockTransport(mock_handler),
    )

    # 1. Test agentpay_pay tool call
    tool_call = {
        "id": "call_123",
        "type": "function",
        "function": {
            "name": "agentpay_pay",
            "arguments": json.dumps({"resource_id": "web_search_premium", "amount": "0.15"}),
        },
    }
    resp = handle_openai_tool_call(tool_call, client)
    assert resp["tool_call_id"] == "call_123"
    assert resp["name"] == "agentpay_pay"
    data = json.loads(resp["content"])
    assert data["payment_intent_id"] == "pi_oai_1"
    assert data["payment_status"] == "AUTHORIZED"

    # 2. Test agentpay_get_payment tool call
    poll_call = {
        "id": "call_456",
        "type": "function",
        "function": {
            "name": "agentpay_get_payment",
            "arguments": json.dumps({"payment_intent_id": "pi_oai_1"}),
        },
    }
    resp2 = handle_openai_tool_call(poll_call, client)
    data2 = json.loads(resp2["content"])
    assert data2["payment_status"] == "COMPLETED"
    assert data2["fulfillment_status"] == "DELIVERED"


def test_openai_tool_call_budget_exceeded():
    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            json={
                "error": {
                    "code": "BUDGET_EXCEEDED",
                    "message": "Exceeded daily budget limit",
                    "next_action": "REQUEST_BUDGET_APPROVAL",
                }
            },
        )

    client = AgentPayClient(
        api_key="test_oai_key",
        policy=_create_test_policy(),
        transport=httpx.MockTransport(mock_handler),
    )

    tool_call = {
        "id": "call_789",
        "type": "function",
        "function": {
            "name": "agentpay_pay",
            "arguments": json.dumps({"resource_id": "super_gpu", "amount": "1000.00"}),
        },
    }
    resp = handle_openai_tool_call(tool_call, client)
    data = json.loads(resp["content"])
    assert data["status"] == "REJECTED"
    assert data["error_code"] == "BUDGET_EXCEEDED"


def test_openai_protect_function():
    policy_allowed = True

    def mock_handler(request: httpx.Request) -> httpx.Response:
        if "/api/v1/integrations/policies/evaluate" in str(request.url):
            return httpx.Response(
                200,
                json={
                    "decision": "ALLOW" if policy_allowed else "DENY",
                    "reason_code": "APPROVED" if policy_allowed else "DAILY_CAP_EXCEEDED",
                    "reason": "OK" if policy_allowed else "Exceeded",
                },
            )
        return httpx.Response(404)

    client = AgentPayClient(
        api_key="test_oai_key",
        policy=_create_test_policy(),
        transport=httpx.MockTransport(mock_handler),
    )

    executed = False

    @protect_openai_function(resource_id="db_query_premium", client=client, amount="0.05")
    def execute_expensive_query(sql: str) -> str:
        nonlocal executed
        executed = True
        return f"Results for: {sql}"

    # ALLOW branch
    res = execute_expensive_query("SELECT 1")
    assert res == "Results for: SELECT 1"
    assert executed is True

    # DENY branch
    policy_allowed = False
    executed = False
    with pytest.raises(AgentPayPolicyDeniedError) as exc_info:
        execute_expensive_query("SELECT 2")
    assert "DAILY_CAP_EXCEEDED" in str(exc_info.value)
    assert executed is False


def test_crewai_adapter_tools():
    def mock_handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "/api/v1/integrations/payments" in url and request.method == "POST":
            return httpx.Response(
                200,
                json={
                    "payment_intent_id": "pi_crew_1",
                    "decision": "ALLOW",
                    "payment_status": "AUTHORIZED",
                    "settlement_status": "HELD",
                    "fulfillment_status": "NOT_STARTED",
                    "amount": "0.50",
                    "asset": "USDC",
                    "idempotency_key": "idem_crew",
                    "next_action": "POLL_STATUS",
                },
            )
        elif "/api/v1/integrations/payments/pi_crew_1" in url and request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "payment_intent_id": "pi_crew_1",
                    "decision": "ALLOW",
                    "payment_status": "COMPLETED",
                    "settlement_status": "CONFIRMED",
                    "fulfillment_status": "DELIVERED",
                    "amount": "0.50",
                    "asset": "USDC",
                    "idempotency_key": "idem_crew",
                    "next_action": "NONE",
                },
            )
        return httpx.Response(404)

    client = AgentPayClient(
        api_key="test_crew_key",
        policy=_create_test_policy(),
        transport=httpx.MockTransport(mock_handler),
    )

    tools = get_crewai_tools(client)
    assert len(tools) == 2
    pay_tool, get_tool = tools[0], tools[1]

    # Test run pay tool
    res_str = pay_tool.run(resource_id="web_scraper_pro", amount="0.50")
    res_data = json.loads(res_str)
    assert res_data["payment_intent_id"] == "pi_crew_1"
    assert res_data["payment_status"] == "AUTHORIZED"

    # Test run get tool
    poll_str = get_tool.run(payment_intent_id="pi_crew_1")
    poll_data = json.loads(poll_str)
    assert poll_data["payment_status"] == "COMPLETED"
    assert poll_data["fulfillment_status"] == "DELIVERED"
