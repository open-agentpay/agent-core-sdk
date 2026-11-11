import { describe, it } from 'node:test';
import assert from 'node:assert';
import { AgentPayClient } from '../dist/client/client.js';
import { SQLitePolicyEngine } from '../dist/policy/sqlite-engine.js';
import { PolicyConfig } from '../dist/policy/models.js';
import {
  createAgentPayPayTool,
  createAgentPayGetPaymentTool,
  getAgentPayTools,
  protectTool,
  ToolException,
} from '../dist/integrations/langchain.js';

function createMockPolicy(): SQLitePolicyEngine {
  const cfg = new PolicyConfig({
    id: 'ts_test_policy',
    maxPerTxBaseUnits: 1_000_000_000n,
    rollingBudget24hBaseUnits: 10_000_000_000n,
    whitelistDomains: ['*'],
  });
  return SQLitePolicyEngine.createInMemory(cfg);
}

describe('TypeScript LangChain Explicit Tools & Guard', () => {
  it('should execute createAgentPayPayTool successfully', async () => {
    const mockFetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = String(input);
      if (url.includes('/api/v1/integrations/payments') && init?.method === 'POST') {
        return new Response(
          JSON.stringify({
            payment_intent_id: 'pi_langchain_1',
            decision: 'ALLOW',
            payment_status: 'AUTHORIZED',
            settlement_status: 'HELD',
            fulfillment_status: 'NOT_STARTED',
            amount: '0.10',
            asset: 'USDC',
            idempotency_key: 'idem_lc',
            next_action: 'POLL_STATUS',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      return new Response('{}', { status: 200 });
    };

    const client = new AgentPayClient({
      apiKey: 'test_key',
      policy: createMockPolicy(),
      baseFetch: mockFetch as any,
    });

    const payTool = createAgentPayPayTool(client);
    assert.strictEqual(payTool.name, 'agentpay_pay');

    const resultStr = await payTool.invoke({
      resource_id: 'financial_analyst_tool',
      amount: '0.10',
    });

    const result = JSON.parse(resultStr);
    assert.strictEqual(result.paymentIntentId, 'pi_langchain_1');
    assert.strictEqual(result.paymentStatus, 'AUTHORIZED');
    assert.strictEqual(result.settlementStatus, 'HELD');
  });

  it('should return budget error message in createAgentPayPayTool on 403 BUDGET_EXCEEDED', async () => {
    const mockFetch = async (): Promise<Response> => {
      return new Response(
        JSON.stringify({
          error_code: 'BUDGET_EXCEEDED',
          message: 'Rolling daily budget of 10.00 USDC exceeded',
          decision: 'DENY',
        }),
        { status: 403, headers: { 'Content-Type': 'application/json' } },
      );
    };

    const client = new AgentPayClient({
      apiKey: 'test_key',
      policy: createMockPolicy(),
      baseFetch: mockFetch as any,
    });

    const payTool = createAgentPayPayTool(client);
    const resultStr = await payTool.invoke({
      resource_id: 'expensive_model',
      amount: '500.00',
    });

    assert.ok(resultStr.includes('AgentPay Budget Exceeded'));
    assert.ok(resultStr.includes('BUDGET_EXCEEDED'));
  });

  it('should execute createAgentPayGetPaymentTool successfully', async () => {
    const mockFetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = String(input);
      if (url.includes('/api/v1/integrations/payments/pi_100') && init?.method === 'GET') {
        return new Response(
          JSON.stringify({
            payment_intent_id: 'pi_100',
            decision: 'ALLOW',
            payment_status: 'COMPLETED',
            settlement_status: 'CONFIRMED',
            fulfillment_status: 'DELIVERED',
            amount: '0.10',
            asset: 'USDC',
            idempotency_key: 'idem_100',
            next_action: 'NONE',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      return new Response('{}', { status: 200 });
    };

    const client = new AgentPayClient({
      apiKey: 'test_key',
      policy: createMockPolicy(),
      baseFetch: mockFetch as any,
    });

    const getPaymentTool = createAgentPayGetPaymentTool(client);
    const resStr = await getPaymentTool.invoke({ payment_intent_id: 'pi_100' });
    const res = JSON.parse(resStr);
    assert.strictEqual(res.paymentStatus, 'COMPLETED');
    assert.strictEqual(res.settlementStatus, 'CONFIRMED');
    assert.strictEqual(res.fulfillmentStatus, 'DELIVERED');

    const tools = getAgentPayTools(client);
    assert.strictEqual(tools.length, 2);
  });

  it('should protect downstream tool execution with protectTool guard', async () => {
    let policyApproved = true;
    const mockFetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = String(input);
      if (url.includes('/api/v1/integrations/policies/evaluate') && init?.method === 'POST') {
        return new Response(
          JSON.stringify({
            decision: policyApproved ? 'ALLOW' : 'DENY',
            reason_code: policyApproved ? 'APPROVED' : 'DAILY_BUDGET_EXCEEDED',
            reason: policyApproved ? 'Within limits' : 'Daily budget exceeded',
            estimated_cost: '0.05',
            asset: 'USDC',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      return new Response('{}', { status: 200 });
    };

    const client = new AgentPayClient({
      apiKey: 'test_key',
      policy: createMockPolicy(),
      baseFetch: mockFetch as any,
    });

    let downstreamCalled = false;
    const mockTool = {
      invoke: async (input: any) => {
        downstreamCalled = true;
        return `Hello ${input.name}`;
      },
    };

    const protectedTool = protectTool(mockTool, {
      resourceId: 'test_guard_tool',
      client,
      amount: '0.05',
    });

    // 1. Policy approves -> downstream tool executes
    const res = await protectedTool.invoke({ name: 'World' });
    assert.strictEqual(res, 'Hello World');
    assert.strictEqual(downstreamCalled, true);

    // 2. Policy denies -> throws ToolException fail-closed, downstream tool NOT executed
    policyApproved = false;
    downstreamCalled = false;

    await assert.rejects(
      async () => {
        await protectedTool.invoke({ name: 'ShouldFail' });
      },
      (err: any) => {
        assert.ok(err instanceof ToolException);
        assert.ok(err.message.includes('DAILY_BUDGET_EXCEEDED'));
        return true;
      },
    );
    assert.strictEqual(downstreamCalled, false);
  });
});
