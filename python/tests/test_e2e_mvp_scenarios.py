"""
Comprehensive E2E Integration Test Suite for the 5 MVP Scenarios:
- Scenario A: Normal Purchase (402 -> Hold -> Settle -> Deliver)
- Scenario B: Budget Exceeded Interception (Single Tx / Rolling Budget Breach)
- Scenario C: Duplicate Request & Idempotency Protection
- Scenario D: Unknown Settlement Recovery & Non-Reissuing Polling
- Scenario E: Uncontrolled Loop & Circuit Breaker / Rate Limit
"""

import json
import httpx
import pytest

from agent_core.client.client import AgentPayClient
from agent_core.contracts import (
    AgentPayBudgetExceededError,
    AgentPayCircuitOpenError,
    AgentPayIdempotencyConflictError,
    AgentPayRateLimitedError,
    FulfillmentStatus,
    PaymentIntentStatus,
    PaymentRequest,
    PaymentResult,
    ResourceContext,
    SettlementStatus,
)
from agent_core.integrations.langchain import AgentPayPayTool, protect_tool
from agent_core.policy.models import PolicyConfig
from agent_core.policy.sqlite_engine import SQLitePolicyEngine


def _create_test_policy() -> SQLitePolicyEngine:
    cfg = PolicyConfig(
        id="mvp_e2e_policy",
        max_per_tx_base_units=1_000_000_000,
        rolling_budget_24h_base_units=10_000_000_000,
        whitelist_domains={"*"},
    )
    return SQLitePolicyEngine.create_in_memory(cfg)


# ==============================================================================
# Scenario A: Normal Purchase (402 -> Hold -> Settle -> Deliver)
# ==============================================================================
def test_scenario_a_normal_purchase_lifecycle():
    """Scenario A: Agent accesses paid resource, reserves hold, and settlements confirm."""
    poll_count = 0

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal poll_count
        url = str(request.url)

        if "/api/v1/integrations/payments" in url and request.method == "POST":
            return httpx.Response(
                200,
                json={
                    "payment_intent_id": "pi_mvp_scenario_a",
                    "decision": "ALLOW",
                    "payment_status": "AUTHORIZED",
                    "settlement_status": "HELD",
                    "fulfillment_status": "NOT_STARTED",
                    "amount": "0.50",
                    "asset": "USDC",
                    "idempotency_key": "idem_scenario_a",
                    "next_action": "POLL_STATUS",
                },
            )
        elif "/api/v1/integrations/payments/pi_mvp_scenario_a" in url and request.method == "GET":
            poll_count += 1
            if poll_count < 2:
                # Still in progress
                return httpx.Response(
                    200,
                    json={
                        "payment_intent_id": "pi_mvp_scenario_a",
                        "decision": "ALLOW",
                        "payment_status": "AUTHORIZED",
                        "settlement_status": "PENDING",
                        "fulfillment_status": "PROCESSING",
                        "amount": "0.50",
                        "asset": "USDC",
                        "idempotency_key": "idem_scenario_a",
                        "next_action": "POLL_STATUS",
                    },
                )
            else:
                # Fully settled and fulfilled
                return httpx.Response(
                    200,
                    json={
                        "payment_intent_id": "pi_mvp_scenario_a",
                        "decision": "ALLOW",
                        "payment_status": "COMPLETED",
                        "settlement_status": "CONFIRMED",
                        "fulfillment_status": "DELIVERED",
                        "amount": "0.50",
                        "asset": "USDC",
                        "idempotency_key": "idem_scenario_a",
                        "next_action": "NONE",
                    },
                )
        return httpx.Response(404)

    client = AgentPayClient(
        api_key="test_key_a",
        policy=_create_test_policy(),
        transport=httpx.MockTransport(mock_handler),
    )

    # Agent triggers payment via LangChain tool
    pay_tool = AgentPayPayTool(client=client)
    res_str = pay_tool.invoke({"resource_id": "financial_market_depth", "amount": "0.50"})
    res_json = json.loads(res_str)

    assert res_json["payment_intent_id"] == "pi_mvp_scenario_a"
    assert res_json["payment_status"] == PaymentIntentStatus.AUTHORIZED
    assert res_json["settlement_status"] == SettlementStatus.HELD

    # Polling resolves settlement
    final_result = client.poll_payment("pi_mvp_scenario_a", initial_interval=0.01)
    assert final_result.is_settled() is True
    assert final_result.is_delivered() is True
    assert final_result.payment_status == PaymentIntentStatus.COMPLETED


# ==============================================================================
# Scenario B: Budget Exceeded Interception
# ==============================================================================
def test_scenario_b_budget_exceeded_fail_closed():
    """Scenario B: Breaching budget returns DENY without financial deduction."""

    def mock_handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "/api/v1/integrations/policies/evaluate" in url:
            return httpx.Response(
                200,
                json={
                    "decision": "DENY",
                    "reason_code": "MAX_PER_TX_EXCEEDED",
                    "reason": "Requested amount 150.00 USDC exceeds per-tx cap 10.00 USDC",
                },
            )
        elif "/api/v1/integrations/payments" in url:
            return httpx.Response(
                403,
                json={
                    "error": {
                        "code": "BUDGET_EXCEEDED",
                        "message": "Requested amount 150.00 USDC exceeds per-tx cap 10.00 USDC",
                        "next_action": "REQUEST_BUDGET_APPROVAL",
                    }
                },
            )
        return httpx.Response(404)

    client = AgentPayClient(
        api_key="test_key_b",
        policy=_create_test_policy(),
        transport=httpx.MockTransport(mock_handler),
    )

    # 1. Test direct pay() raises AgentPayBudgetExceededError
    with pytest.raises(AgentPayBudgetExceededError) as exc_info:
        client.pay(resource_id="ultra_llm_finetune", amount="150.00")
    assert "BUDGET_EXCEEDED" in exc_info.value.code
    assert exc_info.value.next_action == "REQUEST_BUDGET_APPROVAL"

    # 2. Test guard on downstream tool prevents execution fail-closed
    downstream_called = False

    def expensive_calc(query: str) -> str:
        nonlocal downstream_called
        downstream_called = True
        return "Expensive Output"

    from langchain_core.tools import StructuredTool, ToolException

    tool = StructuredTool.from_function(
        func=expensive_calc,
        name="expensive_calc",
        description="Run expensive computation",
    )

    guarded_tool = protect_tool(
        tool,
        resource_id="ultra_llm_finetune",
        client=client,
        amount="150.00",
    )

    with pytest.raises(ToolException) as tool_exc:
        guarded_tool.run({"query": "train model"})

    assert "MAX_PER_TX_EXCEEDED" in str(tool_exc.value)
    assert downstream_called is False, "Downstream tool must NOT execute when budget check fails"


# ==============================================================================
# Scenario C: Duplicate Request & Idempotency Protection
# ==============================================================================
def test_scenario_c_idempotency_replay_protection():
    """Scenario C: Replaying request with same idempotency key returns cached intent without re-billing."""
    calls = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        payload = json.loads(request.content.decode("utf-8"))
        calls.append(payload["idempotency_key"])

        # Returns identical payment intent without duplicate hold
        return httpx.Response(
            200,
            json={
                "payment_intent_id": "pi_mvp_scenario_c",
                "decision": "ALLOW",
                "payment_status": "AUTHORIZED",
                "settlement_status": "HELD",
                "fulfillment_status": "NOT_STARTED",
                "amount": "1.00",
                "asset": "USDC",
                "idempotency_key": payload["idempotency_key"],
                "next_action": "POLL_STATUS",
            },
        )

    client = AgentPayClient(
        api_key="test_key_c",
        policy=_create_test_policy(),
        transport=httpx.MockTransport(mock_handler),
    )

    fixed_idem_key = "idem_stable_scenario_c_999"

    # First attempt
    res1 = client.pay(resource_id="satellite_image", amount="1.00", idempotency_key=fixed_idem_key)
    # Simulated retry after network timeout
    res2 = client.pay(resource_id="satellite_image", amount="1.00", idempotency_key=fixed_idem_key)

    assert res1.payment_intent_id == res2.payment_intent_id == "pi_mvp_scenario_c"
    assert res1.idempotency_key == res2.idempotency_key == fixed_idem_key
    assert len(calls) == 2
    assert calls[0] == calls[1] == fixed_idem_key


# ==============================================================================
# Scenario D: Unknown Settlement Recovery & Non-Reissuing Polling
# ==============================================================================
def test_scenario_d_unknown_settlement_recovery():
    """Scenario D: Network/chain uncertainty keeps state UNKNOWN without issuing new payment intent."""
    step = 0

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal step
        url = str(request.url)
        if "/api/v1/integrations/payments" in url and request.method == "POST":
            return httpx.Response(
                200,
                json={
                    "payment_intent_id": "pi_mvp_scenario_d",
                    "decision": "ALLOW",
                    "payment_status": "AUTHORIZED",
                    "settlement_status": "UNKNOWN",
                    "fulfillment_status": "PROCESSING",
                    "amount": "2.00",
                    "asset": "USDC",
                    "idempotency_key": "idem_scenario_d",
                    "next_action": "POLL_STATUS",
                },
            )
        elif "/api/v1/integrations/payments/pi_mvp_scenario_d" in url and request.method == "GET":
            step += 1
            if step == 1:
                return httpx.Response(
                    200,
                    json={
                        "payment_intent_id": "pi_mvp_scenario_d",
                        "decision": "ALLOW",
                        "payment_status": "AUTHORIZED",
                        "settlement_status": "UNKNOWN",
                        "fulfillment_status": "PROCESSING",
                        "amount": "2.00",
                        "asset": "USDC",
                        "idempotency_key": "idem_scenario_d",
                        "next_action": "POLL_STATUS",
                    },
                )
            else:
                return httpx.Response(
                    200,
                    json={
                        "payment_intent_id": "pi_mvp_scenario_d",
                        "decision": "ALLOW",
                        "payment_status": "COMPLETED",
                        "settlement_status": "CONFIRMED",
                        "fulfillment_status": "DELIVERED",
                        "amount": "2.00",
                        "asset": "USDC",
                        "idempotency_key": "idem_scenario_d",
                        "next_action": "NONE",
                    },
                )
        return httpx.Response(404)

    client = AgentPayClient(
        api_key="test_key_d",
        policy=_create_test_policy(),
        transport=httpx.MockTransport(mock_handler),
    )

    init_res = client.pay(resource_id="cross_chain_swap", amount="2.00")
    assert init_res.settlement_status == SettlementStatus.UNKNOWN
    assert init_res.requires_recovery() is True

    # Polling recovers the original intent without spawning a new intent ID
    recovered_res = client.poll_payment("pi_mvp_scenario_d", initial_interval=0.01)
    assert recovered_res.payment_intent_id == "pi_mvp_scenario_d"
    assert recovered_res.is_settled() is True
    assert recovered_res.is_delivered() is True


# ==============================================================================
# Scenario E: Uncontrolled Loop & Circuit Breaker / Rate Limit
# ==============================================================================
def test_scenario_e_circuit_breaker_tripped():
    """Scenario E: Uncontrolled agent loop trips rate limit and circuit breaker."""

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            503,
            json={
                "error": {
                    "code": "CIRCUIT_OPEN",
                    "message": "Circuit breaker OPEN: anomalous high-frequency calls detected (35 calls in 5s)",
                    "next_action": "STOP",
                }
            },
        )

    client = AgentPayClient(
        api_key="test_key_e",
        policy=_create_test_policy(),
        transport=httpx.MockTransport(mock_handler),
    )

    # Calling pay() during circuit open immediately trips AgentPayCircuitOpenError
    with pytest.raises(AgentPayCircuitOpenError) as exc_info:
        client.pay(resource_id="high_frequency_api", amount="0.01")

    assert exc_info.value.code == "CIRCUIT_OPEN"
    assert "Circuit breaker OPEN" in exc_info.value.message
    assert exc_info.value.next_action == "STOP"
