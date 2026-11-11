"""
Unit tests for AgentPay SDK Integration Contracts and Client Methods.
"""

from __future__ import annotations

import json
import pytest
import httpx

from agent_core.client.client import AgentPayClient, AsyncAgentPayClient
from agent_core.contracts import (
    AgentContext,
    AgentPayAuthenticationError,
    AgentPayBudgetExceededError,
    AgentPayIdempotencyConflictError,
    FulfillmentStatus,
    PaymentIntentStatus,
    PaymentRequest,
    PaymentResult,
    PolicyDecision,
    ResourceContext,
    SettlementStatus,
)
from agent_core.policy.models import PolicyConfig
from agent_core.policy.sqlite_engine import SQLitePolicyEngine


def _create_test_policy() -> SQLitePolicyEngine:
    cfg = PolicyConfig(
        id="test_integration_policy",
        max_per_tx_base_units=1_000_000_000,
        rolling_budget_24h_base_units=10_000_000_000,
        whitelist_domains={"*"},
    )
    return SQLitePolicyEngine.create_in_memory(cfg)


def test_contracts_data_models():
    """Verify contracts serialization, defaults and helper methods."""
    ctx = AgentContext(agent_id="test_agent", framework="langchain", environment="test")
    res = ResourceContext(resource_id="route_weather")
    req = PaymentRequest(resource=res, idempotency_key="idem_123", amount="0.20", context=ctx)

    data = req.model_dump(exclude_none=True)
    assert data["idempotency_key"] == "idem_123"
    assert data["resource"]["resource_id"] == "route_weather"
    assert data["context"]["agent_id"] == "test_agent"

    # Test PaymentResult helpers
    result = PaymentResult(
        payment_intent_id="pi_123",
        decision="ALLOW",
        payment_status=PaymentIntentStatus.AUTHORIZED,
        settlement_status=SettlementStatus.HELD,
        fulfillment_status=FulfillmentStatus.NOT_STARTED,
        amount="0.20",
        asset="USDC",
        idempotency_key="idem_123",
    )
    assert result.is_in_progress() is True
    assert result.is_settled() is False
    assert result.is_delivered() is False

    settled = PaymentResult(
        payment_intent_id="pi_123",
        decision="ALLOW",
        payment_status=PaymentIntentStatus.COMPLETED,
        settlement_status=SettlementStatus.CONFIRMED,
        fulfillment_status=FulfillmentStatus.DELIVERED,
        amount="0.20",
        asset="USDC",
        idempotency_key="idem_123",
    )
    assert settled.is_in_progress() is False
    assert settled.is_settled() is True
    assert settled.is_delivered() is True


def test_client_pay_success_and_query():
    """Test pay(), get_payment() and get_me() with mock HTTP transport."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/integrations/payments" and request.method == "POST":
            payload = json.loads(request.content)
            assert payload["resource"]["resource_id"] == "weather_api"
            return httpx.Response(
                200,
                json={
                    "payment_intent_id": "pi_mock_999",
                    "decision": "ALLOW",
                    "payment_status": "AUTHORIZED",
                    "settlement_status": "HELD",
                    "fulfillment_status": "NOT_STARTED",
                    "amount": "0.20",
                    "asset": "USDC",
                    "idempotency_key": payload["idempotency_key"],
                    "next_action": "POLL_STATUS",
                },
            )
        elif request.url.path == "/api/v1/integrations/payments/pi_mock_999":
            return httpx.Response(
                200,
                json={
                    "payment_intent_id": "pi_mock_999",
                    "decision": "ALLOW",
                    "payment_status": "COMPLETED",
                    "settlement_status": "CONFIRMED",
                    "fulfillment_status": "DELIVERED",
                    "amount": "0.20",
                    "asset": "USDC",
                    "idempotency_key": "idem_mock",
                    "next_action": "NONE",
                },
            )
        elif request.url.path == "/api/v1/integrations/agents/me":
            return httpx.Response(
                200,
                json={
                    "tenant_id": "ten_1",
                    "project_id": "prj_1",
                    "agent_id": "agent_1",
                    "wallet_id": "wlt_1",
                    "status": "active",
                },
            )
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    client = AgentPayClient(api_key="apk_test", policy=_create_test_policy(), transport=transport)

    # 1. Test pay()
    result = client.pay(resource_id="weather_api", amount="0.20")
    assert isinstance(result, PaymentResult)
    assert result.payment_intent_id == "pi_mock_999"
    assert result.payment_status == "AUTHORIZED"
    assert result.settlement_status == "HELD"

    # 2. Test get_payment()
    polled = client.get_payment("pi_mock_999")
    assert polled.is_settled() is True
    assert polled.is_delivered() is True

    # 3. Test get_me()
    me = client.get_me()
    assert me["agent_id"] == "agent_1"


def test_client_pay_error_mappings():
    """Test that gateway integration error payloads map to typed Python exceptions."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/integrations/payments":
            payload = json.loads(request.content)
            if payload.get("amount") == "9999.00":
                return httpx.Response(
                    403,
                    json={
                        "error": {
                            "code": "BUDGET_EXCEEDED",
                            "message": "insufficient wallet balance",
                            "next_action": "INCREASE_BUDGET",
                        }
                    },
                )
            elif payload.get("idempotency_key") == "conflict_key":
                return httpx.Response(
                    409,
                    json={
                        "error": {
                            "code": "IDEMPOTENCY_CONFLICT",
                            "message": "concurrent request in progress",
                            "next_action": "POLL_STATUS",
                        }
                    },
                )
        elif request.url.path == "/api/v1/integrations/agents/me":
            return httpx.Response(
                401,
                json={
                    "error": {
                        "code": "UNAUTHENTICATED",
                        "message": "invalid api key",
                        "next_action": "PROVIDE_API_KEY",
                    }
                },
            )
        return httpx.Response(404)

    client = AgentPayClient(api_key="apk_test", policy=_create_test_policy(), transport=httpx.MockTransport(handler))

    with pytest.raises(AgentPayBudgetExceededError) as exc_info:
        client.pay(resource_id="expensive_gpu", amount="9999.00")
    assert exc_info.value.code == "BUDGET_EXCEEDED"
    assert exc_info.value.next_action == "INCREASE_BUDGET"

    with pytest.raises(AgentPayIdempotencyConflictError) as exc_info:
        client.pay(resource_id="api", idempotency_key="conflict_key")
    assert exc_info.value.code == "IDEMPOTENCY_CONFLICT"

    with pytest.raises(AgentPayAuthenticationError) as exc_info:
        client.get_me()
    assert exc_info.value.code == "UNAUTHENTICATED"


@pytest.mark.anyio
async def test_async_client_pay_and_evaluate():
    """Test async client methods with MockTransport."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/integrations/policies/evaluate":
            return httpx.Response(
                200,
                json={
                    "decision": "ALLOW",
                    "decision_id": "pd_dry_run_01",
                    "reason_code": "POLICY_PASSED",
                    "reason": "dry run passed",
                },
            )
        elif request.url.path == "/api/v1/integrations/payments":
            return httpx.Response(
                200,
                json={
                    "payment_intent_id": "pi_async_01",
                    "decision": "ALLOW",
                    "payment_status": "AUTHORIZED",
                    "settlement_status": "HELD",
                    "fulfillment_status": "NOT_STARTED",
                    "amount": "0.10",
                    "asset": "USDC",
                    "idempotency_key": "idem_async",
                },
            )
        return httpx.Response(404)

    client = AsyncAgentPayClient(api_key="apk_async", policy=_create_test_policy(), transport=httpx.MockTransport(handler))
    try:
        dec = await client.evaluate_policy(resource_id="route_calc", amount="0.10")
        assert isinstance(dec, PolicyDecision)
        assert dec.is_allowed is True

        res = await client.pay(resource_id="route_calc", amount="0.10", idempotency_key="idem_async")
        assert isinstance(res, PaymentResult)
        assert res.payment_intent_id == "pi_async_01"
    finally:
        await client.aclose()
