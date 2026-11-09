import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  McpPriceMetadata,
  type ToolCallContext,
  InMemoryToolQuotaGuard,
  withPrice,
  getToolPrice,
  injectToolSchemaPricing
} from '../dist/integrations/mcp.js';
import { PolicyViolationError } from '../dist/policy/errors.js';

describe('TypeScript MCP Core Services & Pricing Interfaces', () => {
  it('should wrap MCP tool with withPrice and extract metadata correctly', () => {
    const rawTool = {
      name: 'fetch_stock_level2_quote',
      description: 'Get level 2 quotes',
      execute: async (args: { symbol: string }) => ({ symbol: args.symbol, price: 100 })
    };

    const pricedTool = withPrice(rawTool, {
      amount: 0.05,
      currency: 'CNY',
      hitlRequired: false,
      vendor: 'open-agentpay'
    });

    assert.strictEqual(pricedTool.name, 'fetch_stock_level2_quote');
    assert.ok(pricedTool._agentpay);
    assert.strictEqual(pricedTool._agentpay.amountCny, 0.05);
    assert.strictEqual(pricedTool._agentpay.amountBaseUnits, 50000n);
    assert.strictEqual(pricedTool._agentpay.currency, 'CNY');
    assert.strictEqual(pricedTool._agentpay.hitlRequired, false);

    const extracted = getToolPrice(pricedTool);
    assert.ok(extracted);
    assert.strictEqual(extracted.amountCny, 0.05);
    assert.strictEqual(extracted.amountBaseUnits, 50000n);
  });

  it('should inject pricing metadata into MCP Tool Definition schema', () => {
    const schema = {
      name: 'fetch_stock_level2_quote',
      description: 'Quote API',
      inputSchema: { type: 'object', properties: { symbol: { type: 'string' } } }
    };

    const pricing = new McpPriceMetadata({
      amountCny: 0.05,
      currency: 'CNY',
      vendor: 'open-agentpay'
    });

    const enriched = injectToolSchemaPricing(schema, pricing);
    assert.ok((enriched as any)._agentpay);
    assert.strictEqual((enriched as any)._agentpay.price_cny, 0.05);
    assert.strictEqual((enriched as any)._agentpay.price_base_units, 50000);
    assert.strictEqual((enriched as any)._agentpay.currency, 'CNY');
    assert.strictEqual((enriched as any)._agentpay.vendor, 'open-agentpay');
    assert.strictEqual((enriched as any).name, 'fetch_stock_level2_quote');
  });

  it('should handle InMemoryToolQuotaGuard lifecycle (evaluate, reserve, commit)', async () => {
    const guard = new InMemoryToolQuotaGuard({
      maxPerCallCny: 1.00,
      rollingBudgetCny: 10.00
    });

    const ctx: ToolCallContext = {
      agentId: 'agent_ts_1',
      toolName: 'fetch_stock_level2_quote',
      amountCny: 0.05,
      currency: 'CNY'
    };

    assert.strictEqual(await guard.evaluate(ctx), true);

    const holdId = await guard.reserve(ctx);
    assert.ok(holdId.startsWith('hold_'));
    assert.strictEqual(guard.getActiveHoldCount(), 1);
    assert.strictEqual(guard.getTotalReservedCny(), 0.05);

    await guard.commit(holdId, 0.05);
    assert.strictEqual(guard.getActiveHoldCount(), 0);
    assert.strictEqual(guard.getTotalSpentCny(), 0.05);
    assert.strictEqual(guard.getRemainingBudgetCny(), 9.95);
  });

  it('should reject single tx cap and budget exceeded in InMemoryToolQuotaGuard', async () => {
    const guard = new InMemoryToolQuotaGuard({
      maxPerCallCny: 0.10,
      rollingBudgetCny: 0.15
    });

    const expensiveCtx: ToolCallContext = {
      agentId: 'agent_ts_1',
      toolName: 'big_compute',
      amountCny: 0.50
    };

    assert.strictEqual(await guard.evaluate(expensiveCtx), false);
    await assert.rejects(
      async () => {
        await guard.reserve(expensiveCtx);
      },
      (err: any) => {
        return err instanceof PolicyViolationError && err.message.includes('SINGLE_TX_CAP_EXCEEDED');
      }
    );

    // Call 1: 0.08 passes
    const validCtx: ToolCallContext = {
      agentId: 'agent_ts_1',
      toolName: 'small_tool',
      amountCny: 0.08
    };
    const h1 = await guard.reserve(validCtx);
    await guard.commit(h1, 0.08);

    // Call 2: 0.08 -> remaining 0.07 -> rejected
    assert.strictEqual(await guard.evaluate(validCtx), false);
    await assert.rejects(
      async () => {
        await guard.reserve(validCtx);
      },
      (err: any) => {
        return err instanceof PolicyViolationError && err.message.includes('BUDGET_CAP_EXCEEDED');
      }
    );
  });

  it('should release held quota on failure without financial loss', async () => {
    const guard = new InMemoryToolQuotaGuard({
      maxPerCallCny: 1.00,
      rollingBudgetCny: 10.00
    });

    const ctx: ToolCallContext = {
      agentId: 'agent_ts_1',
      toolName: 'unstable_tool',
      amountCny: 0.50
    };

    const holdId = await guard.reserve(ctx);
    assert.strictEqual(guard.getRemainingBudgetCny(), 9.50);

    await guard.release(holdId, 'Network Timeout');
    assert.strictEqual(guard.getActiveHoldCount(), 0);
    assert.strictEqual(guard.getTotalSpentCny(), 0.00);
    assert.strictEqual(guard.getRemainingBudgetCny(), 10.00);
  });
});
