import pytest
from agent_core.integrations.mcp import (
    McpPriceMetadata,
    InMemoryToolQuotaGuard,
    McpToolInterceptor,
    mcp_price,
    PolicyViolationError,
)

def test_interceptor_normal_call_and_settlement():
    guard = InMemoryToolQuotaGuard(max_per_call_cny=1.00, rolling_budget_cny=10.00)
    interceptor = McpToolInterceptor(
        guard=guard,
        pricing_registry={
            "fetch_stock": McpPriceMetadata(amount_cny=0.05, currency="CNY")
        }
    )

    call_count = 0
    def mock_executor(tool_name: str, args: dict) -> dict:
        nonlocal call_count
        call_count += 1
        return {"result": f"quote for {args.get('symbol')}"}

    res = interceptor.call_tool(
        tool_name="fetch_stock",
        arguments={"symbol": "600519"},
        execute_fn=mock_executor,
        agent_id="trader_bot"
    )

    assert call_count == 1
    assert res["content"][0]["text"] == '{"result": "quote for 600519"}'
    assert res["_agentpay"]["status"] == "SETTLED"
    assert res["_agentpay"]["cost_cny"] == 0.05
    assert guard.get_total_spent_cny() == 0.05
    assert guard.get_active_hold_count() == 0

def test_interceptor_blocks_exceeded_single_tx_cap():
    guard = InMemoryToolQuotaGuard(max_per_call_cny=0.10, rolling_budget_cny=10.00)
    interceptor = McpToolInterceptor(
        guard=guard,
        pricing_registry={
            "heavy_ml_tool": McpPriceMetadata(amount_cny=2.50, currency="CNY")
        },
        handle_violation=True
    )

    called = False
    def mock_executor(tool_name: str, args: dict):
        nonlocal called
        called = True
        return {"data": "should not run"}

    # Must return isError=True to inform LLM without running the tool
    res = interceptor.call_tool(
        tool_name="heavy_ml_tool",
        arguments={"input": "data"},
        execute_fn=mock_executor,
        agent_id="analyst_bot"
    )

    assert called is False  # Tool was NOT called, funds 100% saved!
    assert res.get("isError") is True
    assert "SINGLE_TX_CAP_EXCEEDED" in res["content"][0]["text"]
    assert res["_agentpay"]["action"] == "BLOCKED"
    assert guard.get_total_spent_cny() == 0.00
    assert guard.get_active_hold_count() == 0

def test_interceptor_blocks_when_budget_exhausted():
    guard = InMemoryToolQuotaGuard(max_per_call_cny=1.00, rolling_budget_cny=0.08)
    interceptor = McpToolInterceptor(
        guard=guard,
        pricing_registry={
            "api_tool": McpPriceMetadata(amount_cny=0.05, currency="CNY")
        }
    )

    def dummy_exec(t, a):
        return {"status": "ok"}

    # Call 1: 0.05 (budget remaining 0.08 - 0.05 = 0.03)
    res1 = interceptor.call_tool("api_tool", {}, dummy_exec)
    assert res1.get("isError") is not True
    assert guard.get_total_spent_cny() == 0.05

    # Call 2: 0.05 > 0.03 remaining -> blocked
    res2 = interceptor.call_tool("api_tool", {}, dummy_exec)
    assert res2.get("isError") is True
    assert "BUDGET_CAP_EXCEEDED" in res2["content"][0]["text"]
    assert guard.get_total_spent_cny() == 0.05

def test_interceptor_releases_hold_on_upstream_failure():
    guard = InMemoryToolQuotaGuard(max_per_call_cny=1.00, rolling_budget_cny=5.00)
    interceptor = McpToolInterceptor(
        guard=guard,
        pricing_registry={
            "failing_tool": McpPriceMetadata(amount_cny=0.50, currency="CNY")
        }
    )

    def crashing_exec(t, a):
        raise ConnectionError("Upstream API 504 Gateway Timeout")

    with pytest.raises(ConnectionError):
        interceptor.call_tool("failing_tool", {}, crashing_exec)

    # Hold was safely released upon exception! Zero loss!
    assert guard.get_active_hold_count() == 0
    assert guard.get_total_spent_cny() == 0.00
    assert guard.get_remaining_budget_cny() == 5.00

def test_interceptor_extracts_metadata_from_decorated_function():
    guard = InMemoryToolQuotaGuard(max_per_call_cny=1.00, rolling_budget_cny=5.00)
    interceptor = McpToolInterceptor(guard=guard)

    @mcp_price(amount=0.12, currency="CNY")
    def decorated_tool(query: str) -> str:
        return f"result for {query}"

    res = interceptor.call_tool(
        tool_name="decorated_tool",
        arguments={"query": "test"},
        execute_fn=decorated_tool
    )

    assert res["_agentpay"]["cost_cny"] == 0.12
    assert guard.get_total_spent_cny() == 0.12
