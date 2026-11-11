import { describe, it } from 'node:test';
import assert from 'node:assert';
import { AgentPayClient } from '../dist/client/client.js';
import { SQLitePolicyEngine } from '../dist/policy/sqlite-engine.js';
import { PolicyConfig } from '../dist/policy/models.js';
import {
  AgentPayBudgetExceededError,
  AgentPayIdempotencyConflictError,
  AgentPayAuthenticationError,
} from '../dist/contracts/index.js';

function createMockPolicy(): SQLitePolicyEngine {
  const cfg = new PolicyConfig({
    id: 'ts_test_policy',
    maxPerTxBaseUnits: 1_000_000_000n,
    rollingBudget24hBaseUnits: 10_000_000_000n,
    whitelistDomains: ['*'],
  });
  return SQLitePolicyEngine.createInMemory(cfg);
}

describe('TypeScript Integration Contracts & Client Methods', () => {
  it('should successfully execute pay(), getPayment() and getMe()', async () => {
    const mockFetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = String(input);
      const readBody = () => {
        if (!init?.body) return {};
        if (typeof init.body === 'string') return JSON.parse(init.body);
        return JSON.parse(Buffer.from(init.body as any).toString('utf-8'));
      };

      if (url.includes('/api/v1/integrations/payments') && init?.method === 'POST') {
        const body = readBody();
        assert.strictEqual(body.resource.resource_id, 'weather_api');
        return new Response(
          JSON.stringify({
            payment_intent_id: 'pi_ts_123',
            decision: 'ALLOW',
            payment_status: 'AUTHORIZED',
            settlement_status: 'HELD',
            fulfillment_status: 'NOT_STARTED',
            amount: '0.20',
            asset: 'USDC',
            idempotency_key: body.idempotency_key,
            next_action: 'POLL_STATUS',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      } else if (url.includes('/api/v1/integrations/payments/pi_ts_123') && init?.method === 'GET') {
        return new Response(
          JSON.stringify({
            payment_intent_id: 'pi_ts_123',
            decision: 'ALLOW',
            payment_status: 'COMPLETED',
            settlement_status: 'CONFIRMED',
            fulfillment_status: 'DELIVERED',
            amount: '0.20',
            asset: 'USDC',
            idempotency_key: 'idem_ts',
            next_action: 'NONE',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      } else if (url.includes('/api/v1/integrations/agents/me') && init?.method === 'GET') {
        return new Response(
          JSON.stringify({
            tenant_id: 'ten_ts_1',
            agent_id: 'agent_ts_1',
            wallet_id: 'wlt_ts_1',
            status: 'active',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      return new Response('Not found', { status: 404 });
    };

    const client = new AgentPayClient({
      apiKey: 'apk_test_ts',
      policy: createMockPolicy(),
      baseFetch: mockFetch as any,
    });

    const res = await client.pay({
      resourceId: 'weather_api',
      amount: '0.20',
    });

    assert.strictEqual(res.paymentIntentId, 'pi_ts_123');
    assert.strictEqual(res.paymentStatus, 'AUTHORIZED');
    assert.strictEqual(res.settlementStatus, 'HELD');

    const polled = await client.getPayment('pi_ts_123');
    assert.strictEqual(polled.paymentStatus, 'COMPLETED');
    assert.strictEqual(polled.settlementStatus, 'CONFIRMED');
    assert.strictEqual(polled.fulfillmentStatus, 'DELIVERED');

    const me = await client.getMe();
    assert.strictEqual(me['agent_id'], 'agent_ts_1');
  });

  it('should map error responses to typed integration errors', async () => {
    const mockFetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = String(input);
      const readBody = () => {
        if (!init?.body) return {};
        if (typeof init.body === 'string') return JSON.parse(init.body);
        return JSON.parse(Buffer.from(init.body as any).toString('utf-8'));
      };

      if (url.includes('/api/v1/integrations/payments')) {
        const body = readBody();
        if (body.amount === '9999.00') {
          return new Response(
            JSON.stringify({
              error: {
                code: 'BUDGET_EXCEEDED',
                message: 'Budget exceeded limit',
                next_action: 'INCREASE_BUDGET',
              },
            }),
            { status: 403, headers: { 'Content-Type': 'application/json' } },
          );
        }
        if (body.idempotency_key === 'conflict_ts') {
          return new Response(
            JSON.stringify({
              error: {
                code: 'IDEMPOTENCY_CONFLICT',
                message: 'Concurrent request conflict',
                next_action: 'POLL_STATUS',
              },
            }),
            { status: 409, headers: { 'Content-Type': 'application/json' } },
          );
        }
      } else if (url.includes('/api/v1/integrations/agents/me')) {
        return new Response(
          JSON.stringify({
            error: {
              code: 'UNAUTHENTICATED',
              message: 'Invalid credentials',
            },
          }),
          { status: 401, headers: { 'Content-Type': 'application/json' } },
        );
      }
      return new Response('Not found', { status: 404 });
    };

    const client = new AgentPayClient({
      apiKey: 'apk_test_ts',
      policy: createMockPolicy(),
      baseFetch: mockFetch as any,
    });

    await assert.rejects(
      async () => {
        await client.pay({ resourceId: 'gpu', amount: '9999.00' });
      },
      (err: any) => {
        assert(err instanceof AgentPayBudgetExceededError);
        assert.strictEqual(err.code, 'BUDGET_EXCEEDED');
        return true;
      },
    );

    await assert.rejects(
      async () => {
        await client.pay({ resourceId: 'gpu', idempotencyKey: 'conflict_ts' });
      },
      (err: any) => {
        assert(err instanceof AgentPayIdempotencyConflictError);
        assert.strictEqual(err.code, 'IDEMPOTENCY_CONFLICT');
        return true;
      },
    );

    await assert.rejects(
      async () => {
        await client.getMe();
      },
      (err: any) => {
        assert(err instanceof AgentPayAuthenticationError);
        assert.strictEqual(err.code, 'UNAUTHENTICATED');
        return true;
      },
    );
  });
});
