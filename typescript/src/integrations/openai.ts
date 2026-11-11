/**
 * OpenAI Agents SDK and Function Calling Integration for AgentPay.
 */

import type { AgentPayClient } from '../client/client.js';
import {
  AgentPayBudgetExceededError,
  AgentPayPolicyDeniedError,
  AgentPayIntegrationError,
} from '../contracts/index.js';

export const AGENTPAY_PAY_TOOL_DEFINITION = {
  type: 'function' as const,
  function: {
    name: 'agentpay_pay',
    description:
      'Request payment authorization and execute payment for a declared paid resource or 402 challenge. ' +
      'Returns structured three-domain payment status (payment, settlement, fulfillment).',
    parameters: {
      type: 'object',
      properties: {
        resource_id: {
          type: 'string',
          description: 'The unique identifier of the target paid resource or registered route.',
        },
        challenge_id: {
          type: 'string',
          description: 'Optional payment challenge identifier if received from an HTTP 402 response.',
        },
        amount: {
          type: 'string',
          description: "Optional payment amount as a decimal string (e.g. '0.20'). If omitted, route default is used.",
        },
        asset: {
          type: 'string',
          description: "Cryptocurrency or fiat asset code (e.g. 'USDC', 'USD'). Default is 'USDC'.",
          default: 'USDC',
        },
        network: {
          type: 'string',
          description: "Blockchain or settlement network (e.g. 'base', 'ethereum', 'polygon').",
        },
        idempotency_key: {
          type: 'string',
          description: 'Client-generated idempotency key to prevent double charging on retry.',
        },
      },
      required: ['resource_id'],
    },
  },
};

export const AGENTPAY_GET_PAYMENT_TOOL_DEFINITION = {
  type: 'function' as const,
  function: {
    name: 'agentpay_get_payment',
    description:
      'Query the current three-domain lifecycle status of an existing payment intent ' +
      '(payment_status, settlement_status, fulfillment_status). Useful for polling asynchronous settlements.',
    parameters: {
      type: 'object',
      properties: {
        payment_intent_id: {
          type: 'string',
          description: 'The unique payment intent identifier to check.',
        },
      },
      required: ['payment_intent_id'],
    },
  },
};

export function getOpenAITools() {
  return [AGENTPAY_PAY_TOOL_DEFINITION, AGENTPAY_GET_PAYMENT_TOOL_DEFINITION];
}

export interface OpenAIToolCallMessage {
  tool_call_id: string;
  role: 'tool';
  name: string;
  content: string;
}

export async function handleOpenAIToolCall(
  toolCall: any,
  client: AgentPayClient,
): Promise<OpenAIToolCallMessage> {
  const toolCallId: string = toolCall?.id ?? toolCall?.tool_call_id ?? '';
  const fnName: string = toolCall?.function?.name ?? toolCall?.name ?? '';
  let args: any = toolCall?.function?.arguments ?? toolCall?.arguments ?? {};

  if (typeof args === 'string') {
    try {
      args = JSON.parse(args);
    } catch {
      args = {};
    }
  }

  let content: string;

  if (fnName === 'agentpay_pay') {
    const resourceId = args.resource_id ?? args.resourceId;
    if (!resourceId) {
      content = JSON.stringify({ error: 'resource_id is required' });
    } else {
      try {
        const result = await client.pay({
          resourceId,
          challengeId: args.challenge_id ?? args.challengeId,
          amount: args.amount,
          asset: args.asset ?? 'USDC',
          network: args.network,
          idempotencyKey: args.idempotency_key ?? args.idempotencyKey,
        });
        content = JSON.stringify(result);
      } catch (err: any) {
        if (err instanceof AgentPayBudgetExceededError) {
          content = JSON.stringify({
            status: 'REJECTED',
            error_code: err.code,
            message: err.message,
            next_action: err.nextAction || 'REQUEST_BUDGET_APPROVAL',
          });
        } else if (err instanceof AgentPayPolicyDeniedError) {
          content = JSON.stringify({
            status: 'DENIED',
            error_code: err.code,
            message: err.message,
            next_action: err.nextAction,
          });
        } else if (err instanceof AgentPayIntegrationError) {
          content = JSON.stringify({
            status: 'ERROR',
            error_code: err.code,
            message: err.message,
            next_action: err.nextAction,
          });
        } else {
          content = JSON.stringify({ status: 'ERROR', message: err.message });
        }
      }
    }
  } else if (fnName === 'agentpay_get_payment') {
    const paymentIntentId = args.payment_intent_id ?? args.paymentIntentId;
    if (!paymentIntentId) {
      content = JSON.stringify({ error: 'payment_intent_id is required' });
    } else {
      try {
        const result = await client.getPayment(paymentIntentId);
        content = JSON.stringify(result);
      } catch (err: any) {
        content = JSON.stringify({ status: 'ERROR', message: err.message });
      }
    }
  } else {
    content = JSON.stringify({ error: `Unknown tool name: ${fnName}` });
  }

  return {
    tool_call_id: toolCallId,
    role: 'tool',
    name: fnName,
    content,
  };
}

export function protectOpenAIFunction<TArgs extends any[], TReturn>(
  fn: (...args: TArgs) => Promise<TReturn> | TReturn,
  options: {
    resourceId: string;
    client: AgentPayClient;
    amount?: string;
    asset?: string;
    failClosed?: boolean;
  },
): (...args: TArgs) => Promise<TReturn> {
  const failClosed = options.failClosed ?? true;

  return async (...args: TArgs): Promise<TReturn> => {
    try {
      const decision = await options.client.evaluatePolicy({
        resourceId: options.resourceId,
        amount: options.amount,
        asset: options.asset ?? 'USDC',
      });
      if (decision.decision !== 'ALLOW') {
        throw new AgentPayPolicyDeniedError(
          `AgentPay Policy Denied: [${decision.reasonCode}] ${decision.reason || 'Execution not allowed'}`,
          decision.reasonCode,
        );
      }
    } catch (err: any) {
      if (err instanceof AgentPayPolicyDeniedError) throw err;
      if (failClosed) {
        throw new AgentPayPolicyDeniedError(
          `AgentPay Guard Fail-Closed: ${err.message}`,
          'GUARD_FAIL_CLOSED',
        );
      }
    }
    return await fn(...args);
  };
}
