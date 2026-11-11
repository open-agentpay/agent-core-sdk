import { describe, it } from 'node:test';
import assert from 'node:assert';
import { AgentPayClient } from '../dist/client/client.js';
import { SQLitePolicyEngine } from '../dist/policy/sqlite-engine.js';
import { PolicyConfig } from '../dist/policy/models.js';
import {
  getOpenAITools,
  handleOpenAIToolCall,
  protectOpenAIFunction,
} from '../dist/integrations/openai.js';
import { AgentPayPolicyDeniedError } from '../dist/contracts/index.js';

function createMockPolicy(): SQLitePolicyEngine {
  const cfg = new PolicyConfig({
    id: 'ts_test_policy',
    maxPerTxBaseUnits: 1_000_000_000n,
    rollingBudget24hBaseUnits: 10_000_000_000n,
    whitelistDomains: ['*'],
  });
  return SQLitePolicyEngine.createInMemory(cfg);
}

describe('TypeScript OpenAI Integration Adapter', () => {
  it('should return valid OpenAI tool definitions', () => {
    const tools = getOpenAITools();
    assert.strictEqual(tools.length, 2);
    const names = tools.map((t) => t.function.name);
    assert.ok(names.includes('agentpay_pay'));
    assert.ok(names.includes('agentpay_get_payment'));
  });

  it('should handle agentpay_pay and agentpay_get_payment tool calls', async () => {
    const mockFetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = String(input);
      if (url.includes('/api/v1/integrations/payments') && init?.method === 'POST') {
        return new Response(
          JSON.stringify({
            payment_intent_id: 'pi_oai_ts_1',
            decision: 'ALLOW',
            payment_status: 'AUTHORIZED',
            settlement_status: 'HELD',
            fulfillment_status: 'NOT_STARTED',
            amount: '0.25',
            asset: 'USDC',
            idempotency_key: 'idem_ts_oai',
            next_action: 'POLL_STATUS',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      } else if (url.includes('/api/v1/integrations/payments/pi_oai_ts_1') && init?.method === 'GET') {
        return new Response(
          JSON.stringify({
            payment_intent_id: 'pi_oai_ts_1',
            decision: 'ALLOW',
            payment_status: 'COMPLETED',
            settlement_status: 'CONFIRMED',
            fulfillment_status: 'DELIVERED',
            amount: '0.25',
            asset: 'USDC',
            idempotency_key: 'idem_ts_oai',
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

    // 1. Test agentpay_pay
    const toolCallPay = {
      id: 'call_oai_1',
      type: 'function',
      function: {
        name: 'agentpay_pay',
        arguments: JSON.stringify({ resource_id: 'web_search_ai', amount: '0.25' }),
      },
    };
    const payMsg = await handleOpenAIToolCall(toolCallPay, client);
    assert.strictEqual(payMsg.tool_call_id, 'call_oai_1');
    assert.strictEqual(payMsg.name, 'agentpay_pay');
    const payData = JSON.parse(payMsg.content);
    assert.strictEqual(payData.paymentIntentId, 'pi_oai_ts_1');
    assert.strictEqual(payData.paymentStatus, 'AUTHORIZED');

    // 2. Test agentpay_get_payment
    const toolCallGet = {
      id: 'call_oai_2',
      type: 'function',
      function: {
        name: 'agentpay_get_payment',
        arguments: JSON.stringify({ payment_intent_id: 'pi_oai_ts_1' }),
      },
    };
    const getMsg = await handleOpenAIToolCall(toolCallGet, client);
    assert.strictEqual(getMsg.tool_call_id, 'call_oai_2');
    const getData = JSON.parse(getMsg.content);
    assert.strictEqual(getData.paymentStatus, 'COMPLETED');
    assert.strictEqual(getData.settlementStatus, 'CONFIRMED');
    assert.strictEqual(getData.fulfillmentStatus, 'DELIVERED');
  });

  it('should handle BUDGET_EXCEEDED gracefully in OpenAI tool handler', async () => {
    const mockFetch = async (): Promise<Response> => {
      return new Response(
        JSON.stringify({
          error: {
            code: 'BUDGET_EXCEEDED',
            message: 'Monthly quota exhausted',
            next_action: 'REQUEST_BUDGET_APPROVAL',
          },
        }),
        { status: 403, headers: { 'Content-Type': 'application/json' } },
      );
    };

    const client = new AgentPayClient({
      apiKey: 'test_key',
      policy: createMockPolicy(),
      baseFetch: mockFetch as any,
    });

    const toolCall = {
      id: 'call_overbudget',
      function: {
        name: 'agentpay_pay',
        arguments: { resource_id: 'massive_model', amount: '500.00' },
      },
    };
    const msg = await handleOpenAIToolCall(toolCall, client);
    const data = JSON.parse(msg.content);
    assert.strictEqual(data.status, 'REJECTED');
    assert.strictEqual(data.error_code, 'BUDGET_EXCEEDED');
  });

  it('should protect function execution using protectOpenAIFunction', async () => {
    let policyApproved = true;
    const mockFetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = String(input);
      if (url.includes('/api/v1/integrations/policies/evaluate') && init?.method === 'POST') {
        return new Response(
          JSON.stringify({
            decision: policyApproved ? 'ALLOW' : 'DENY',
            reason_code: policyApproved ? 'APPROVED' : 'DAILY_BUDGET_EXCEEDED',
            reason: policyApproved ? 'Within limits' : 'Daily budget exceeded',
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

    let executed = false;
    const computeStats = protectOpenAIFunction(
      async (dataset: string) => {
        executed = true;
        return `Stats for ${dataset}`;
      },
      {
        resourceId: 'compute_node_1',
        client,
        amount: '0.10',
      },
    );

    // ALLOW branch
    const res = await computeStats('sales_data');
    assert.strictEqual(res, 'Stats for sales_data');
    assert.strictEqual(executed, true);

    // DENY branch
    policyApproved = false;
    executed = false;
    await assert.rejects(
      async () => {
        await computeStats('financial_data');
      },
      (err: any) => {
        assert.ok(err instanceof AgentPayPolicyDeniedError);
        assert.ok(err.message.includes('DAILY_BUDGET_EXCEEDED'));
        return true;
      },
    );
    assert.strictEqual(executed, false);
  });
});
