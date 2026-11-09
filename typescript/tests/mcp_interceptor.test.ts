import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  McpPriceMetadata,
  InMemoryToolQuotaGuard,
  McpToolInterceptor,
  withPrice,
  type McpToolResponse,
} from '../dist/integrations/mcp.js';

describe('TypeScript MCP Client Pre-Call Interceptor', () => {
  it('should intercept, reserve, and commit normal tool call', async () => {
    const guard = new InMemoryToolQuotaGuard({
      maxPerCallCny: 1.00,
      rollingBudgetCny: 10.00,
    });

    const interceptor = new McpToolInterceptor({
      guard,
      pricingRegistry: {
        fetch_stock: new McpPriceMetadata({ amountCny: 0.05, currency: 'CNY' }),
      },
    });

    let callCount = 0;
    const mockExecutor = async (_name: string, args: Record<string, unknown>) => {
      callCount++;
      return { symbol: args.symbol, price: 100 };
    };

    const res = await interceptor.callTool(
      {
        toolName: 'fetch_stock',
        arguments: { symbol: '600519' },
        agentId: 'trader_ts_bot',
      },
      mockExecutor
    );

    assert.strictEqual(callCount, 1);
    assert.ok((res as any).content);
    assert.strictEqual((res as any)._agentpay?.status, 'SETTLED');
    assert.strictEqual((res as any)._agentpay?.cost_cny, 0.05);
    assert.strictEqual(guard.getTotalSpentCny(), 0.05);
    assert.strictEqual(guard.getActiveHoldCount(), 0);
  });

  it('should block call when single tx cap is breached and return isError=true to LLM', async () => {
    const guard = new InMemoryToolQuotaGuard({
      maxPerCallCny: 0.10,
      rollingBudgetCny: 10.00,
    });

    const interceptor = new McpToolInterceptor({
      guard,
      pricingRegistry: {
        heavy_compute: new McpPriceMetadata({ amountCny: 2.50, currency: 'CNY' }),
      },
      handleViolation: true,
    });

    let called = false;
    const mockExecutor = async () => {
      called = true;
      return { status: 'executed' };
    };

    const res = (await interceptor.callTool(
      {
        toolName: 'heavy_compute',
        arguments: { data: 'test' },
      },
      mockExecutor
    )) as McpToolResponse;

    assert.strictEqual(called, false); // Blocked before calling upstream!
    assert.strictEqual(res.isError, true);
    assert.ok(res.content[0].text?.includes('SINGLE_TX_CAP_EXCEEDED'));
    assert.strictEqual((res as any)._agentpay?.action, 'BLOCKED');
    assert.strictEqual(guard.getTotalSpentCny(), 0.00);
    assert.strictEqual(guard.getActiveHoldCount(), 0);
  });

  it('should block call when rolling budget is exhausted', async () => {
    const guard = new InMemoryToolQuotaGuard({
      maxPerCallCny: 1.00,
      rollingBudgetCny: 0.08,
    });

    const interceptor = new McpToolInterceptor({
      guard,
      pricingRegistry: {
        api_tool: new McpPriceMetadata({ amountCny: 0.05, currency: 'CNY' }),
      },
    });

    const dummyExec = async () => ({ ok: true });

    // Call 1: 0.05 passes (remaining: 0.03)
    const res1 = (await interceptor.callTool({ toolName: 'api_tool' }, dummyExec)) as McpToolResponse;
    assert.strictEqual(res1.isError, undefined);
    assert.strictEqual(guard.getTotalSpentCny(), 0.05);

    // Call 2: 0.05 > 0.03 remaining -> blocked
    const res2 = (await interceptor.callTool({ toolName: 'api_tool' }, dummyExec)) as McpToolResponse;
    assert.strictEqual(res2.isError, true);
    assert.ok(res2.content[0].text?.includes('BUDGET_CAP_EXCEEDED'));
    assert.strictEqual(guard.getTotalSpentCny(), 0.05);
  });

  it('should safely release held quota when upstream tool execution crashes', async () => {
    const guard = new InMemoryToolQuotaGuard({
      maxPerCallCny: 1.00,
      rollingBudgetCny: 5.00,
    });

    const interceptor = new McpToolInterceptor({
      guard,
      pricingRegistry: {
        failing_tool: new McpPriceMetadata({ amountCny: 0.50, currency: 'CNY' }),
      },
    });

    const crashingExec = async () => {
      throw new Error('504 Gateway Timeout');
    };

    await assert.rejects(
      async () => {
        await interceptor.callTool({ toolName: 'failing_tool' }, crashingExec);
      },
      (err: any) => err.message.includes('504 Gateway Timeout')
    );

    // Held quota was zero-loss released
    assert.strictEqual(guard.getActiveHoldCount(), 0);
    assert.strictEqual(guard.getTotalSpentCny(), 0.00);
    assert.strictEqual(guard.getRemainingBudgetCny(), 5.00);
  });

  it('should automatically extract metadata from withPrice tool', async () => {
    const guard = new InMemoryToolQuotaGuard({
      maxPerCallCny: 1.00,
      rollingBudgetCny: 5.00,
    });
    const interceptor = new McpToolInterceptor({ guard });

    const pricedTool = withPrice(
      {
        name: 'priced_tool',
        description: 'Auto priced tool',
        execute: async (args: { q: string }) => `result_${args.q}`,
      },
      { amount: 0.15, currency: 'CNY' }
    );

    const res = await interceptor.callTool(
      {
        toolName: pricedTool.name,
        arguments: { q: 'hello' },
      },
      pricedTool.execute,
      pricedTool
    );

    assert.strictEqual((res as any)._agentpay?.cost_cny, 0.15);
    assert.strictEqual(guard.getTotalSpentCny(), 0.15);
  });
});
