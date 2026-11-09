import pytest
from agent_core.integrations.mcp import (
    McpPriceMetadata,
    ToolCallContext,
    ToolQuotaGuard,
    InMemoryToolQuotaGuard,
    mcp_price,
    get_tool_price_metadata,
    inject_tool_schema_pricing,
    PolicyViolationError,
)

def test_mcp_price_decorator_and_metadata_extraction():
    @mcp_price(amount=0.05, currency="CNY", hitl_required=False, vendor="open-agentpay")
    def sample_stock_tool(symbol: str) -> dict:
        return {"symbol": symbol, "price": 100.0}

    metadata = get_tool_price_metadata(sample_stock_tool)
    assert metadata is not None
    assert metadata.amount_cny == 0.05
    assert metadata.amount_base_units == 50000
    assert metadata.currency == "CNY"
    assert metadata.hitl_required is False
    assert metadata.vendor == "open-agentpay"

def test_inject_tool_schema_pricing():
    base_schema = {
        "name": "sample_stock_tool",
        "description": "Query stock quote",
        "inputSchema": {"type": "object", "properties": {"symbol": {"type": "string"}}}
    }
    pricing = McpPriceMetadata(amount_cny=0.05, currency="CNY", vendor="open-agentpay")
    enriched = inject_tool_schema_pricing(base_schema, pricing)

    assert "_agentpay" in enriched
    assert enriched["_agentpay"]["price_cny"] == 0.05
    assert enriched["_agentpay"]["price_base_units"] == 50000
    assert enriched["_agentpay"]["currency"] == "CNY"
    assert enriched["_agentpay"]["vendor"] == "open-agentpay"
    # Original schema keys preserved
    assert enriched["name"] == "sample_stock_tool"
    assert "inputSchema" in enriched

def test_in_memory_quota_guard_lifecycle():
    guard = InMemoryToolQuotaGuard(
        max_per_call_cny=1.00,
        rolling_budget_cny=10.00
    )

    ctx = ToolCallContext(
        agent_id="agent_quant_1",
        tool_name="fetch_stock_level2_quote",
        amount_cny=0.05,
        currency="CNY"
    )

    # 1. Evaluate
    assert guard.evaluate(ctx) is True

    # 2. Reserve
    hold_id = guard.reserve(ctx)
    assert hold_id.startswith("hold_")
    assert guard.get_active_hold_count() == 1
    assert guard.get_total_reserved_cny() == 0.05

    # 3. Commit
    guard.commit(hold_id, actual_cost_cny=0.05)
    assert guard.get_active_hold_count() == 0
    assert guard.get_total_spent_cny() == 0.05
    assert guard.get_remaining_budget_cny() == 9.95

def test_in_memory_quota_guard_rejections():
    guard = InMemoryToolQuotaGuard(
        max_per_call_cny=0.10,
        rolling_budget_cny=0.15
    )

    # Single call cap violation
    expensive_ctx = ToolCallContext(
        agent_id="agent_1",
        tool_name="expensive_model_tool",
        amount_cny=0.50
    )
    assert guard.evaluate(expensive_ctx) is False
    with pytest.raises(PolicyViolationError) as exc_info:
        guard.reserve(expensive_ctx)
    assert "SINGLE_TX_CAP_EXCEEDED" in str(exc_info.value)

    # Small call passes
    valid_ctx = ToolCallContext(
        agent_id="agent_1",
        tool_name="normal_tool",
        amount_cny=0.08
    )
    h1 = guard.reserve(valid_ctx)
    guard.commit(h1, 0.08)

    # Next call exceeds remaining rolling budget (0.15 - 0.08 = 0.07 remaining, request 0.08)
    another_ctx = ToolCallContext(
        agent_id="agent_1",
        tool_name="normal_tool",
        amount_cny=0.08
    )
    assert guard.evaluate(another_ctx) is False
    with pytest.raises(PolicyViolationError) as exc_info:
        guard.reserve(another_ctx)
    assert "BUDGET_CAP_EXCEEDED" in str(exc_info.value)

def test_in_memory_quota_guard_release():
    guard = InMemoryToolQuotaGuard(
        max_per_call_cny=1.00,
        rolling_budget_cny=10.00
    )
    ctx = ToolCallContext(agent_id="agent_1", tool_name="tool_fail", amount_cny=0.50)
    hold_id = guard.reserve(ctx)
    assert guard.get_remaining_budget_cny() == 9.50

    # Upstream failed, release hold
    guard.release(hold_id, reason="Upstream timeout")
    assert guard.get_active_hold_count() == 0
    assert guard.get_total_spent_cny() == 0.00
    assert guard.get_remaining_budget_cny() == 10.00
