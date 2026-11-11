/**
 * AgentPayClient: HTTP Client with automatic 402 payment negotiation and financial firewall.
 */

import type { IPolicyEngine } from '../policy/interfaces.js';
import type { ISigner } from './interfaces.js';
import { AgentPayTransport, type AgentPayClientOptions, type AgentPayRequestInit } from './transport.js';
import {
  type PaymentRequest,
  type PaymentResult,
  type PolicyDecision,
  mapIntegrationError,
} from '../contracts/index.js';

function toPaymentResult(data: any): PaymentResult {
  return {
    paymentIntentId: data.payment_intent_id ?? data.paymentIntentId ?? '',
    decision: data.decision ?? 'ALLOW',
    paymentStatus: data.payment_status ?? data.paymentStatus ?? 'AUTHORIZED',
    settlementStatus: data.settlement_status ?? data.settlementStatus ?? 'NOT_STARTED',
    fulfillmentStatus: data.fulfillment_status ?? data.fulfillmentStatus ?? 'NOT_STARTED',
    amount: String(data.amount ?? '0'),
    asset: data.asset ?? 'USDC',
    idempotencyKey: data.idempotency_key ?? data.idempotencyKey ?? '',
    network: data.network,
    transactionHash: data.transaction_hash ?? data.transactionHash,
    nextAction: data.next_action ?? data.nextAction ?? 'NONE',
  };
}

function toPolicyDecision(data: any): PolicyDecision {
  return {
    decision: data.decision ?? 'ALLOW',
    decisionId: data.decision_id ?? data.decisionId ?? '',
    reasonCode: data.reason_code ?? data.reasonCode ?? 'POLICY_PASSED',
    reason: data.reason,
    paymentIntentId: data.payment_intent_id ?? data.paymentIntentId,
    policyVersion: data.policy_version ?? data.policyVersion,
    budgetReservationId: data.budget_reservation_id ?? data.budgetReservationId,
    expiresAt: data.expires_at ?? data.expiresAt,
  };
}

function extractError(errData: any, fallbackCode: string, fallbackMessage: string): {
  code: string;
  message: string;
  nextAction?: string;
  details?: any;
} {
  const err = errData?.error && typeof errData.error === 'object' ? errData.error : errData;
  const code = err?.code ?? err?.error_code ?? fallbackCode;
  const message = err?.message ?? fallbackMessage;
  const nextAction = err?.next_action ?? err?.nextAction;
  return { code, message, nextAction, details: err };
}

function serializePaymentRequest(req: any): Record<string, unknown> {
  const resource = req.resource || {};
  const context = req.context || {};
  return {
    resource: {
      resource_id: resource.resource_id ?? resource.resourceId ?? req.resourceId,
      challenge_id: resource.challenge_id ?? resource.challengeId ?? req.challengeId,
    },
    idempotency_key: req.idempotency_key ?? req.idempotencyKey ?? `idem_${Math.random().toString(36).substring(2)}`,
    amount: req.amount,
    asset: req.asset,
    network: req.network,
    context: req.context
      ? {
          agent_id: context.agent_id ?? context.agentId,
          tenant_id: context.tenant_id ?? context.tenantId,
          run_id: context.run_id ?? context.runId,
          framework: context.framework,
          framework_version: context.framework_version ?? context.frameworkVersion,
          tool_name: context.tool_name ?? context.toolName,
          task_id: context.task_id ?? context.taskId,
        }
      : undefined,
    metadata: req.metadata,
  };
}

export class AgentPayClient {
  readonly signer?: ISigner;
  readonly apiKey?: string;
  readonly policy: IPolicyEngine;
  readonly transport: AgentPayTransport;

  constructor(options: AgentPayClientOptions) {
    this.signer = options.signer;
    this.apiKey = options.apiKey;
    this.policy = options.policy;
    this.transport = new AgentPayTransport(options);
  }

  /**
   * Return a fetch function bound to this client's payment interceptor.
   */
  public asFetch(): typeof globalThis.fetch {
    const fetchFn = (input: string | URL | Request, init?: AgentPayRequestInit) => this.transport.fetch(input, init);
    return fetchFn as unknown as typeof globalThis.fetch;
  }

  /**
   * Dispatch an HTTP request through the AgentPay interceptor.
   */
  public request(input: string | URL | Request, init?: AgentPayRequestInit): Promise<Response> {
    return this.transport.fetch(input, init);
  }

  /**
   * Dispatch a GET request.
   */
  public get(url: string | URL, init?: AgentPayRequestInit): Promise<Response> {
    return this.request(url, { ...init, method: 'GET' });
  }

  /**
   * Dispatch a POST request with automatic JSON body encoding.
   */
  public post(
    url: string | URL,
    body?: BodyInit | Record<string, unknown> | null,
    init?: AgentPayRequestInit,
  ): Promise<Response> {
    const { headers: initialHeaders, ...restInit } = init ?? {};
    const headers = new Headers(initialHeaders);
    let finalBody: BodyInit | undefined;

    if (body !== undefined && body !== null) {
      if (
        typeof body === 'object' &&
        !(body instanceof Uint8Array) &&
        !(body instanceof ArrayBuffer) &&
        !(body instanceof Blob) &&
        !(body instanceof FormData) &&
        !(body instanceof URLSearchParams)
      ) {
        finalBody = JSON.stringify(body);
        if (!headers.has('content-type')) {
          headers.set('content-type', 'application/json');
        }
      } else {
        finalBody = body as BodyInit;
      }
    }

    return this.request(url, { ...restInit, method: 'POST', headers, body: finalBody });
  }

  /**
   * Dispatch a PUT request with automatic JSON body encoding.
   */
  public put(
    url: string | URL,
    body?: BodyInit | Record<string, unknown> | null,
    init?: AgentPayRequestInit,
  ): Promise<Response> {
    const { headers: initialHeaders, ...restInit } = init ?? {};
    const headers = new Headers(initialHeaders);
    let finalBody: BodyInit | undefined;

    if (body !== undefined && body !== null) {
      if (
        typeof body === 'object' &&
        !(body instanceof Uint8Array) &&
        !(body instanceof ArrayBuffer) &&
        !(body instanceof Blob) &&
        !(body instanceof FormData) &&
        !(body instanceof URLSearchParams)
      ) {
        finalBody = JSON.stringify(body);
        if (!headers.has('content-type')) {
          headers.set('content-type', 'application/json');
        }
      } else {
        finalBody = body as BodyInit;
      }
    }

    return this.request(url, { ...restInit, method: 'PUT', headers, body: finalBody });
  }

  /**
   * Dispatch a DELETE request.
   */
  public delete(url: string | URL, init?: AgentPayRequestInit): Promise<Response> {
    return this.request(url, { ...init, method: 'DELETE' });
  }

  /**
   * Execute payment against AgentPay Integration API (/api/v1/integrations/payments).
   */
  public async pay(
    params: PaymentRequest | { resourceId?: string; challengeId?: string; idempotencyKey?: string; amount?: string; asset?: string; network?: string; context?: any; metadata?: Record<string, unknown> },
  ): Promise<PaymentResult> {
    const payload = serializePaymentRequest(params);
    const res = await this.post('/api/v1/integrations/payments', payload);

    if (res.ok) {
      const data = await res.json();
      return toPaymentResult(data);
    }

    let errData: any = {};
    try {
      errData = await res.json();
    } catch {
      // ignore
    }
    const err = extractError(errData, 'HTTP_ERROR', await res.text().catch(() => ''));
    throw mapIntegrationError(res.status, err.code, err.message, err.nextAction, err.details);
  }

  /**
   * Query current three-domain lifecycle status of a payment intent.
   */
  public async getPayment(paymentIntentId: string): Promise<PaymentResult> {
    const res = await this.get(`/api/v1/integrations/payments/${paymentIntentId}`);
    if (res.ok) {
      const data = await res.json();
      return toPaymentResult(data);
    }

    let errData: any = {};
    try {
      errData = await res.json();
    } catch {
      // ignore
    }
    const err = extractError(errData, 'NOT_FOUND', 'Payment intent not found');
    throw mapIntegrationError(res.status, err.code, err.message, err.nextAction, err.details);
  }

  /**
   * Poll payment intent status until settled or terminal state reached.
   */
  public async pollPayment(
    paymentIntentId: string,
    options: { maxAttempts?: number; initialIntervalMs?: number; backoffFactor?: number; maxIntervalMs?: number } = {},
  ): Promise<PaymentResult> {
    const maxAttempts = options.maxAttempts ?? 15;
    let interval = options.initialIntervalMs ?? 500;
    const backoff = options.backoffFactor ?? 1.5;
    const maxInterval = options.maxIntervalMs ?? 5000;

    let lastResult: PaymentResult | null = null;
    for (let i = 0; i < maxAttempts; i++) {
      lastResult = await this.getPayment(paymentIntentId);
      const isSettled = lastResult.settlementStatus === 'CONFIRMED';
      const isDelivered = lastResult.fulfillmentStatus === 'DELIVERED';
      const isPending =
        ['HELD', 'SUBMITTED', 'PENDING'].includes(lastResult.settlementStatus) ||
        lastResult.fulfillmentStatus === 'PROCESSING';

      if (isSettled || isDelivered || !isPending) {
        return lastResult;
      }

      await new Promise((resolve) => setTimeout(resolve, interval));
      interval = Math.min(interval * backoff, maxInterval);
    }

    if (lastResult) return lastResult;
    throw new Error(`Polling payment ${paymentIntentId} timed out after ${maxAttempts} attempts`);
  }

  /**
   * Execute dry-run policy evaluation via /api/v1/integrations/policies/evaluate.
   */
  public async evaluatePolicy(
    params: PaymentRequest | { resourceId?: string; challengeId?: string; amount?: string; asset?: string; context?: any },
  ): Promise<PolicyDecision> {
    const payload = serializePaymentRequest(params);
    const res = await this.post('/api/v1/integrations/policies/evaluate', payload);

    if (res.ok) {
      const data = await res.json();
      return toPolicyDecision(data);
    }

    let errData: any = {};
    try {
      errData = await res.json();
    } catch {
      // ignore
    }
    const err = extractError(errData, 'POLICY_ERROR', 'Policy evaluation failed');
    throw mapIntegrationError(res.status, err.code, err.message, err.nextAction, err.details);
  }

  /**
   * Query authenticated agent metadata and tenant binding from /api/v1/integrations/agents/me.
   */
  public async getMe(): Promise<Record<string, unknown>> {
    const res = await this.get('/api/v1/integrations/agents/me');
    if (res.ok) {
      return (await res.json()) as Record<string, unknown>;
    }

    let errData: any = {};
    try {
      errData = await res.json();
    } catch {
      // ignore
    }
    const err = extractError(errData, 'AUTH_ERROR', 'Failed to retrieve agent identity');
    throw mapIntegrationError(res.status, err.code, err.message, err.nextAction, err.details);
  }
}

export const AgentCoreClient = AgentPayClient;
export type { AgentPayClient as AgentCoreClientType };

