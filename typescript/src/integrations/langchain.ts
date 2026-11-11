/**
 * LangChain.js integration for AgentPay.
 *
 * Provides PaidStructuredTool and createPaidTool helper for wrapping
 * LangChain tools with autonomous 402 payment negotiation and financial firewall guardrails.
 */

import type { AgentPayClient } from '../client/client.js';
import { X402Error } from '../core/errors.js';
import { PolicyViolationError } from '../policy/errors.js';
import {
  AgentPayBudgetExceededError,
  AgentPayPolicyDeniedError,
  AgentPayIntegrationError,
} from '../contracts/index.js';

export class ToolException extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ToolException';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export interface CreatePaidToolOptions<TParams = any, TResult = any> {
  name: string;
  description: string;
  schema?: any;
  client?: AgentPayClient;
  handlePolicyViolation?: boolean;
  func?: (params: TParams, context?: { client?: AgentPayClient; [key: string]: any }) => Promise<TResult> | TResult;
  coroutine?: (params: TParams, context?: { client?: AgentPayClient; [key: string]: any }) => Promise<TResult>;
  [key: string]: any;
}

export class PaidStructuredTool<TParams = any, TResult = any> {
  readonly name: string;
  readonly description: string;
  readonly schema: any;
  readonly client?: AgentPayClient;
  readonly handlePolicyViolation: boolean;
  private readonly targetFn: (params: TParams, context?: any) => Promise<TResult> | TResult;

  constructor(options: CreatePaidToolOptions<TParams, TResult>) {
    this.name = options.name;
    this.description = options.description;
    this.schema = options.schema;
    this.client = options.client;
    this.handlePolicyViolation = options.handlePolicyViolation ?? true;

    const fn = options.func ?? options.coroutine;
    if (!fn) {
      throw new Error("Either 'func' or 'coroutine' must be provided to PaidStructuredTool");
    }
    this.targetFn = fn;
  }

  public async call(arg: TParams, ...extra: any[]): Promise<TResult> {
    return this.invoke(arg, ...extra);
  }

  public async _call(arg: TParams, ...extra: any[]): Promise<TResult> {
    return this.invoke(arg, ...extra);
  }

  public async invoke(arg: TParams, ...extra: any[]): Promise<TResult> {
    const context = {
      client: this.client,
      ...(extra[0] && typeof extra[0] === 'object' ? extra[0] : {}),
    };

    try {
      return await this.targetFn(arg, context);
    } catch (err) {
      if (err instanceof PolicyViolationError) {
        if (this.handlePolicyViolation) {
          throw new ToolException(
            `AgentPay Firewall Rejected: [${err.code}] ${err.detail || err.message}`,
          );
        }
        throw err;
      }
      if (err instanceof X402Error) {
        if (this.handlePolicyViolation) {
          throw new ToolException(`AgentPay x402 Protocol Error: ${err.message}`);
        }
        throw err;
      }
      throw err;
    }
  }
}

export function createPaidTool<TParams = any, TResult = any>(
  options: CreatePaidToolOptions<TParams, TResult>,
): PaidStructuredTool<TParams, TResult> {
  return new PaidStructuredTool<TParams, TResult>(options);
}

export interface AgentPayPayToolArgs {
  resource_id?: string;
  resourceId?: string;
  challenge_id?: string;
  challengeId?: string;
  amount?: string;
  asset?: string;
  network?: string;
  idempotency_key?: string;
  idempotencyKey?: string;
}

export function createAgentPayPayTool(client: AgentPayClient): PaidStructuredTool<AgentPayPayToolArgs, string> {
  return createPaidTool<AgentPayPayToolArgs, string>({
    name: 'agentpay_pay',
    description:
      'Request payment authorization and execute payment for a declared paid resource or 402 challenge. ' +
      'Returns structured three-domain payment status (payment, settlement, fulfillment).',
    client,
    func: async (args) => {
      const resourceId = args.resource_id ?? args.resourceId;
      if (!resourceId) {
        throw new ToolException('resource_id is required');
      }
      try {
        const result = await client.pay({
          resourceId,
          challengeId: args.challenge_id ?? args.challengeId,
          amount: args.amount,
          asset: args.asset ?? 'USDC',
          network: args.network,
          idempotencyKey: args.idempotency_key ?? args.idempotencyKey,
        });
        return JSON.stringify(result);
      } catch (err: any) {
        if (err instanceof AgentPayBudgetExceededError) {
          return `AgentPay Budget Exceeded: [${err.code}] ${err.message}. Please request budget approval.`;
        }
        if (err instanceof AgentPayPolicyDeniedError) {
          return `AgentPay Firewall Rejected: [${err.code}] ${err.message}.`;
        }
        if (err instanceof AgentPayIntegrationError) {
          return `AgentPay Integration Error: [${err.code}] ${err.message}.`;
        }
        throw new ToolException(`Payment execution failed: ${err.message}`);
      }
    },
  });
}

export interface AgentPayGetPaymentToolArgs {
  payment_intent_id?: string;
  paymentIntentId?: string;
}

export function createAgentPayGetPaymentTool(client: AgentPayClient): PaidStructuredTool<AgentPayGetPaymentToolArgs, string> {
  return createPaidTool<AgentPayGetPaymentToolArgs, string>({
    name: 'agentpay_get_payment',
    description:
      'Query current status of an existing payment intent across payment intent, ' +
      'settlement, and fulfillment domains. Useful for polling asynchronous settlements.',
    client,
    func: async (args) => {
      const intentId = args.payment_intent_id ?? args.paymentIntentId;
      if (!intentId) {
        throw new ToolException('payment_intent_id is required');
      }
      try {
        const result = await client.getPayment(intentId);
        return JSON.stringify(result);
      } catch (err: any) {
        return `AgentPay Query Failed: [${err.code ?? 'ERROR'}] ${err.message}`;
      }
    },
  });
}

export function getAgentPayTools(client: AgentPayClient): Array<PaidStructuredTool<any, string>> {
  return [createAgentPayPayTool(client), createAgentPayGetPaymentTool(client)];
}

export function protectTool<TTool extends { invoke: (...args: any[]) => Promise<any> }>(
  tool: TTool,
  options: {
    resourceId: string;
    client: AgentPayClient;
    amount?: string;
    asset?: string;
    failClosed?: boolean;
  },
): TTool {
  const failClosed = options.failClosed ?? true;
  const originalInvoke = tool.invoke.bind(tool);

  (tool as any).invoke = async (...args: any[]) => {
    try {
      const decision = await options.client.evaluatePolicy({
        resourceId: options.resourceId,
        amount: options.amount,
        asset: options.asset ?? 'USDC',
      });
      if (decision.decision !== 'ALLOW') {
        throw new ToolException(
          `AgentPay Guard Blocked: [${decision.reasonCode}] ${decision.reason || 'Policy denied execution'}`,
        );
      }
    } catch (err: any) {
      if (err instanceof ToolException) throw err;
      if (err instanceof AgentPayPolicyDeniedError) {
        throw new ToolException(`AgentPay Guard Blocked: [${err.code}] ${err.message}`);
      }
      if (failClosed) {
        throw new ToolException(`AgentPay Guard Fail-Closed: ${err.message}`);
      }
    }

    return await originalInvoke(...args);
  };

  return tool;
}
