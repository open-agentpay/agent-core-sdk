import { describe, it } from 'node:test';
import assert from 'node:assert';
import { AgentPayClient } from '../dist/client/client.js';
import { SQLitePolicyEngine } from '../dist/policy/sqlite-engine.js';
import { PolicyConfig } from '../dist/policy/models.js';
import {
  createAgentPayPayTool,
  protectTool,
  ToolException,
} from '../dist/integrations/langchain.js';
import {
  AgentPayBudgetExceededError,
  AgentPayCircuitOpenError,
} from '../dist/contracts/index.js';

function createMockPolicy(): SQLitePolicyEngine {
  const cfg = new PolicyConfig({
    id: 'ts_mvp_e2e_policy',
    maxPerTxBaseUnits: 1_000_000_000n,
    rollingBudget24hBaseUnits: 10_000_000_000n,
    whitelistDomains: ['*'],
  });
  return SQLitePolicyEngine.createInMemory(cfg);
}

describe('E2E Integration Test Suite for 5 MVP Scenarios (TypeScript)', () => {
  // ==============================================================================
  // Scenario A: Normal Purchase (402 -> Hold -> Settle -> Deliver)
  // ==============================================================================
  it('Scenario A: Normal Purchase Lifecycle (Hold -> Confirmed -> Delivered)', async () => {
    let pollCount = 0;
    const mockFetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = String(input);
      if (url.includes('/api/v1/integrations/payments') && init?.method === 'POST') {
        return new Response(
          JSON.stringify({
            payment_intent_id: 'pi_scenario_a_ts',
            decision: 'ALLOW',
            payment_status: 'AUTHORIZED',
            settlement_status: 'HELD',
            fulfillment_status: 'NOT_STARTED',
            amount: '0.50',
            asset: 'USDC',
            idempotency_key: 'idem_scenario_a_ts',
            next_action: 'POLL_STATUS',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      } else if (url.includes('/api/v1/integrations/payments/pi_scenario_a_ts') && init?.method === 'GET') {
        pollCount++;
        if (pollCount < 2) {
          return new Response(
            JSON.stringify({
              payment_intent_id: 'pi_scenario_a_ts',
              decision: 'ALLOW',
              payment_status: 'AUTHORIZED',
              settlement_status: 'PENDING',
              fulfillment_status: 'PROCESSING',
              amount: '0.50',
              asset: 'USDC',
              idempotency_key: 'idem_scenario_a_ts',
              next_action: 'POLL_STATUS',
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        } else {
          return new Response(
            JSON.stringify({
              payment_intent_id: 'pi_scenario_a_ts',
              decision: 'ALLOW',
              payment_status: 'COMPLETED',
              settlement_status: 'CONFIRMED',
              fulfillment_status: 'DELIVERED',
              amount: '0.50',
              asset: 'USDC',
              idempotency_key: 'idem_scenario_a_ts',
              next_action: 'NONE',
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
      }
      return new Response('{}', { status: 200 });
    };

    const client = new AgentPayClient({
      apiKey: 'test_key_a',
      policy: createMockPolicy(),
      baseFetch: mockFetch as any,
    });

    const payTool = createAgentPayPayTool(client);
    const resultStr = await payTool.invoke({
      resource_id: 'financial_depth',
      amount: '0.50',
    });
    const result = JSON.parse(resultStr);
    assert.strictEqual(result.paymentIntentId, 'pi_scenario_a_ts');
    assert.strictEqual(result.paymentStatus, 'AUTHORIZED');
    assert.strictEqual(result.settlementStatus, 'HELD');

    // Poll until confirmed
    const finalResult = await client.pollPayment('pi_scenario_a_ts', {
      initialIntervalMs: 10,
      maxAttempts: 5,
    });
    assert.strictEqual(finalResult.settlementStatus, 'CONFIRMED');
    assert.strictEqual(finalResult.fulfillmentStatus, 'DELIVERED');
    assert.strictEqual(finalResult.paymentStatus, 'COMPLETED');
  });

  // ==============================================================================
  // Scenario B: Budget Exceeded Interception
  // ==============================================================================
  it('Scenario B: Budget Exceeded Interception & Fail-Closed Guard', async () => {
    const mockFetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = String(input);
      if (url.includes('/api/v1/integrations/policies/evaluate')) {
        return new Response(
          JSON.stringify({
            decision: 'DENY',
            reason_code: 'MAX_PER_TX_EXCEEDED',
            reason: 'Requested amount 200.00 USDC exceeds per-tx cap 10.00 USDC',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      } else if (url.includes('/api/v1/integrations/payments')) {
        return new Response(
          JSON.stringify({
            error: {
              code: 'BUDGET_EXCEEDED',
              message: 'Requested amount 200.00 USDC exceeds per-tx cap 10.00 USDC',
              next_action: 'REQUEST_BUDGET_APPROVAL',
            },
          }),
          { status: 403, headers: { 'Content-Type': 'application/json' } },
        );
      }
      return new Response('{}', { status: 404 });
    };

    const client = new AgentPayClient({
      apiKey: 'test_key_b',
      policy: createMockPolicy(),
      baseFetch: mockFetch as any,
    });

    // 1. Direct pay() throws AgentPayBudgetExceededError
    await assert.rejects(
      async () => {
        await client.pay({ resourceId: 'super_cluster', amount: '200.00' });
      },
      (err: any) => {
        assert.ok(err instanceof AgentPayBudgetExceededError);
        assert.strictEqual(err.code, 'BUDGET_EXCEEDED');
        assert.strictEqual(err.nextAction, 'REQUEST_BUDGET_APPROVAL');
        return true;
      },
    );

    // 2. protectTool blocks downstream execution fail-closed
    let downstreamCalled = false;
    const guardedTool = protectTool(
      {
        invoke: async () => {
          downstreamCalled = true;
          return 'Dangerous Execution';
        },
      },
      {
        resourceId: 'super_cluster',
        client,
        amount: '200.00',
      },
    );

    await assert.rejects(
      async () => {
        await guardedTool.invoke();
      },
      (err: any) => {
        assert.ok(err instanceof ToolException);
        assert.ok(err.message.includes('MAX_PER_TX_EXCEEDED'));
        return true;
      },
    );
    assert.strictEqual(downstreamCalled, false);
  });

  // ==============================================================================
  // Scenario C: Duplicate Request & Idempotency Protection
  // ==============================================================================
  it('Scenario C: Duplicate Request & Idempotency Protection', async () => {
    const receivedKeys: string[] = [];

    const mockFetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const body = JSON.parse(Buffer.from(init?.body as any).toString('utf-8'));
      receivedKeys.push(body.idempotency_key);

      return new Response(
        JSON.stringify({
          payment_intent_id: 'pi_scenario_c_ts',
          decision: 'ALLOW',
          payment_status: 'AUTHORIZED',
          settlement_status: 'HELD',
          fulfillment_status: 'NOT_STARTED',
          amount: '1.00',
          asset: 'USDC',
          idempotency_key: body.idempotency_key,
          next_action: 'POLL_STATUS',
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    };

    const client = new AgentPayClient({
      apiKey: 'test_key_c',
      policy: createMockPolicy(),
      baseFetch: mockFetch as any,
    });

    const fixedKey = 'idem_stable_ts_999';
    const res1 = await client.pay({ resourceId: 'imagery_api', amount: '1.00', idempotencyKey: fixedKey });
    const res2 = await client.pay({ resourceId: 'imagery_api', amount: '1.00', idempotencyKey: fixedKey });

    assert.strictEqual(res1.paymentIntentId, 'pi_scenario_c_ts');
    assert.strictEqual(res2.paymentIntentId, 'pi_scenario_c_ts');
    assert.strictEqual(receivedKeys.length, 2);
    assert.strictEqual(receivedKeys[0], fixedKey);
    assert.strictEqual(receivedKeys[1], fixedKey);
  });

  // ==============================================================================
  // Scenario D: Unknown Settlement Recovery & Non-Reissuing Polling
  // ==============================================================================
  it('Scenario D: Unknown Settlement Recovery & Polling Without Reissuing', async () => {
    let step = 0;
    const mockFetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = String(input);
      if (url.includes('/api/v1/integrations/payments') && init?.method === 'POST') {
        return new Response(
          JSON.stringify({
            payment_intent_id: 'pi_scenario_d_ts',
            decision: 'ALLOW',
            payment_status: 'AUTHORIZED',
            settlement_status: 'UNKNOWN',
            fulfillment_status: 'PROCESSING',
            amount: '3.00',
            asset: 'USDC',
            idempotency_key: 'idem_d_ts',
            next_action: 'POLL_STATUS',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      } else if (url.includes('/api/v1/integrations/payments/pi_scenario_d_ts') && init?.method === 'GET') {
        step++;
        if (step === 1) {
          return new Response(
            JSON.stringify({
              payment_intent_id: 'pi_scenario_d_ts',
              decision: 'ALLOW',
              payment_status: 'AUTHORIZED',
              settlement_status: 'UNKNOWN',
              fulfillment_status: 'PROCESSING',
              amount: '3.00',
              asset: 'USDC',
              idempotency_key: 'idem_d_ts',
              next_action: 'POLL_STATUS',
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        } else {
          return new Response(
            JSON.stringify({
              payment_intent_id: 'pi_scenario_d_ts',
              decision: 'ALLOW',
              payment_status: 'COMPLETED',
              settlement_status: 'CONFIRMED',
              fulfillment_status: 'DELIVERED',
              amount: '3.00',
              asset: 'USDC',
              idempotency_key: 'idem_d_ts',
              next_action: 'NONE',
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
      }
      return new Response('{}', { status: 404 });
    };

    const client = new AgentPayClient({
      apiKey: 'test_key_d',
      policy: createMockPolicy(),
      baseFetch: mockFetch as any,
    });

    const initRes = await client.pay({ resourceId: 'bridge_swap', amount: '3.00' });
    assert.strictEqual(initRes.settlementStatus, 'UNKNOWN');

    const finalRes = await client.pollPayment('pi_scenario_d_ts', {
      initialIntervalMs: 10,
      maxAttempts: 5,
    });
    assert.strictEqual(finalRes.paymentIntentId, 'pi_scenario_d_ts');
    assert.strictEqual(finalRes.settlementStatus, 'CONFIRMED');
    assert.strictEqual(finalRes.fulfillmentStatus, 'DELIVERED');
  });

  // ==============================================================================
  // Scenario E: Uncontrolled Loop & Circuit Breaker / Rate Limit
  // ==============================================================================
  it('Scenario E: Circuit Breaker Trips on Anomaly', async () => {
    const mockFetch = async (): Promise<Response> => {
      return new Response(
        JSON.stringify({
          error: {
            code: 'CIRCUIT_OPEN',
            message: 'Circuit breaker tripped: 40 calls in 3s detected',
            next_action: 'STOP',
          },
        }),
        { status: 503, headers: { 'Content-Type': 'application/json' } },
      );
    };

    const client = new AgentPayClient({
      apiKey: 'test_key_e',
      policy: createMockPolicy(),
      baseFetch: mockFetch as any,
    });

    await assert.rejects(
      async () => {
        await client.pay({ resourceId: 'rapid_api', amount: '0.01' });
      },
      (err: any) => {
        assert.ok(err instanceof AgentPayCircuitOpenError);
        assert.strictEqual(err.code, 'CIRCUIT_OPEN');
        assert.ok(err.message.includes('Circuit breaker tripped'));
        assert.strictEqual(err.nextAction, 'STOP');
        return true;
      },
    );
  });
});
