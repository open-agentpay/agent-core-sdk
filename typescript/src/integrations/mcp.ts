/**
 * Model Context Protocol (MCP) integration for AgentPay.
 *
 * Provides MCP server tool handlers, pricing annotations, quota guard interfaces,
 * and client fetch adapters for autonomous 402 payment negotiation.
 */

import { AgentPayClient } from '../client/client.js';
import { createAgentPayFetch, type AgentPayClientOptions } from '../client/transport.js';
import { X402Error } from '../core/errors.js';
import { PolicyErrorCode, PolicyViolationError } from '../policy/errors.js';

export interface McpContentItem {
  type: string;
  text?: string;
  data?: string;
  mimeType?: string;
  [key: string]: unknown;
}

export interface McpToolResponse {
  isError?: boolean;
  content: McpContentItem[];
  [key: string]: unknown;
}

export interface PaidMcpToolOptions {
  handlePolicyViolation?: boolean;
}

export type McpToolHandler<TArgs = Record<string, unknown>> = (
  args: TArgs,
  extra?: { client: AgentPayClient; [key: string]: unknown },
) => Promise<McpToolResponse | unknown>;

export function createPaidMcpToolHandler<TArgs = Record<string, unknown>>(
  client: AgentPayClient,
  handler: McpToolHandler<TArgs>,
  options?: PaidMcpToolOptions,
): (args: TArgs, extra?: any) => Promise<McpToolResponse> {
  const handlePolicyViolation = options?.handlePolicyViolation ?? true;

  return async (args: TArgs, extra?: any): Promise<McpToolResponse> => {
    const context = {
      client,
      ...(extra && typeof extra === 'object' ? extra : {}),
    };

    try {
      const result = await handler(args, context);
      if (
        result &&
        typeof result === 'object' &&
        'content' in result &&
        Array.isArray((result as McpToolResponse).content)
      ) {
        return result as McpToolResponse;
      }
      return {
        content: [
          {
            type: 'text',
            text: typeof result === 'string' ? result : JSON.stringify(result),
          },
        ],
      };
    } catch (err) {
      if (err instanceof PolicyViolationError) {
        if (handlePolicyViolation) {
          return {
            isError: true,
            content: [
              {
                type: 'text',
                text: `AgentPay Firewall Rejected: [${err.code}] ${err.detail || err.message}`,
              },
            ],
          };
        }
        throw err;
      }
      if (err instanceof X402Error) {
        if (handlePolicyViolation) {
          return {
            isError: true,
            content: [
              {
                type: 'text',
                text: `AgentPay x402 Protocol Error: ${err.message}`,
              },
            ],
          };
        }
        throw err;
      }
      throw err;
    }
  };
}

export function createPaidMcpFetch(
  clientOrOptions: AgentPayClient | AgentPayClientOptions,
): typeof globalThis.fetch {
  if (clientOrOptions instanceof AgentPayClient) {
    return clientOrOptions.asFetch();
  }
  return createAgentPayFetch(clientOrOptions);
}

// ----------------------------------------------------------------------------
// MCP Pricing Annotations & Standardized Quota Guard Interfaces
// ----------------------------------------------------------------------------

export interface McpPriceOptions {
  amount: number;
  currency?: 'CNY' | 'USD' | string;
  billingMode?: 'per_call' | 'per_token' | string;
  hitlRequired?: boolean;
  vendor?: string;
  description?: string;
}

export class McpPriceMetadata {
  readonly amountCny: number;
  readonly amountBaseUnits: bigint;
  readonly currency: string;
  readonly billingMode: string;
  readonly hitlRequired: boolean;
  readonly vendor?: string;
  readonly description?: string;

  constructor(options: {
    amountCny: number;
    amountBaseUnits?: bigint;
    currency?: string;
    billingMode?: string;
    hitlRequired?: boolean;
    vendor?: string;
    description?: string;
  }) {
    this.amountCny = options.amountCny;
    this.amountBaseUnits =
      options.amountBaseUnits ?? BigInt(Math.round(options.amountCny * 1_000_000));
    this.currency = options.currency ?? 'CNY';
    this.billingMode = options.billingMode ?? 'per_call';
    this.hitlRequired = options.hitlRequired ?? false;
    this.vendor = options.vendor;
    this.description = options.description;
  }

  toJSON(): Record<string, unknown> {
    const res: Record<string, unknown> = {
      price_cny: Number(this.amountCny.toFixed(2)),
      price_base_units: Number(this.amountBaseUnits),
      currency: this.currency,
      billing_mode: this.billingMode,
      hitl_required: this.hitlRequired,
    };
    if (this.vendor) res.vendor = this.vendor;
    if (this.description) res.description = this.description;
    return res;
  }
}

export interface ToolCallContext {
  agentId: string;
  toolName: string;
  amountCny: number;
  currency?: string;
  arguments?: Record<string, unknown>;
  callId?: string;
}

export interface ToolQuotaGuard {
  evaluate(ctx: ToolCallContext): Promise<boolean> | boolean;
  reserve(ctx: ToolCallContext): Promise<string> | string;
  commit(holdId: string, actualCostCny: number): Promise<void> | void;
  release(holdId: string, reason?: string): Promise<void> | void;
}

export interface InMemoryToolQuotaGuardOptions {
  maxPerCallCny?: number;
  rollingBudgetCny?: number;
}

export class InMemoryToolQuotaGuard implements ToolQuotaGuard {
  private readonly maxPerCallCny: number;
  private readonly rollingBudgetCny: number;
  private totalSpentCny = 0;
  private activeHolds = new Map<
    string,
    { ctx: ToolCallContext; amountCny: number; timestamp: number }
  >();

  constructor(options?: InMemoryToolQuotaGuardOptions) {
    this.maxPerCallCny = options?.maxPerCallCny ?? 50.0;
    this.rollingBudgetCny = options?.rollingBudgetCny ?? 500.0;
  }

  evaluate(ctx: ToolCallContext): boolean {
    if (ctx.amountCny > this.maxPerCallCny) return false;
    const totalReserved = this.getTotalReservedCny();
    if (this.totalSpentCny + totalReserved + ctx.amountCny > this.rollingBudgetCny) {
      return false;
    }
    return true;
  }

  reserve(ctx: ToolCallContext): string {
    if (ctx.amountCny > this.maxPerCallCny) {
      throw new PolicyViolationError(
        PolicyErrorCode.SINGLE_TX_CAP_EXCEEDED,
        `SINGLE_TX_CAP_EXCEEDED: Requested ¥${ctx.amountCny.toFixed(2)} exceeds cap ¥${this.maxPerCallCny.toFixed(2)}`,
      );
    }
    const totalReserved = this.getTotalReservedCny();
    if (this.totalSpentCny + totalReserved + ctx.amountCny > this.rollingBudgetCny) {
      throw new PolicyViolationError(
        PolicyErrorCode.DAILY_BUDGET_EXCEEDED,
        `BUDGET_CAP_EXCEEDED: Requested ¥${ctx.amountCny.toFixed(2)} exceeds budget limit ¥${this.rollingBudgetCny.toFixed(2)}`,
      );
    }

    const holdId = `hold_${Math.random().toString(36).substring(2, 10)}${Date.now().toString(36)}`;
    this.activeHolds.set(holdId, {
      ctx,
      amountCny: ctx.amountCny,
      timestamp: Date.now(),
    });
    return holdId;
  }

  commit(holdId: string, actualCostCny: number): void {
    if (this.activeHolds.has(holdId)) {
      this.activeHolds.delete(holdId);
      this.totalSpentCny += actualCostCny;
    }
  }

  release(holdId: string, _reason?: string): void {
    this.activeHolds.delete(holdId);
  }

  getActiveHoldCount(): number {
    return this.activeHolds.size;
  }

  getTotalReservedCny(): number {
    let sum = 0;
    for (const item of this.activeHolds.values()) {
      sum += item.amountCny;
    }
    return Number(sum.toFixed(2));
  }

  getTotalSpentCny(): number {
    return Number(this.totalSpentCny.toFixed(2));
  }

  getRemainingBudgetCny(): number {
    const remaining = this.rollingBudgetCny - (this.totalSpentCny + this.getTotalReservedCny());
    return Number(Math.max(0, remaining).toFixed(2));
  }
}

export function withPrice<T extends { name: string; [key: string]: any }>(
  tool: T,
  options: McpPriceOptions,
): T & { _agentpay: McpPriceMetadata } {
  const metadata = new McpPriceMetadata({
    amountCny: options.amount,
    currency: options.currency,
    billingMode: options.billingMode,
    hitlRequired: options.hitlRequired,
    vendor: options.vendor,
    description: options.description,
  });

  return Object.assign(tool, {
    _agentpay: metadata,
  });
}

export function getToolPrice(tool: unknown): McpPriceMetadata | undefined {
  if (!tool || typeof tool !== 'object') return undefined;
  if ('_agentpay' in tool && (tool as any)._agentpay instanceof McpPriceMetadata) {
    return (tool as any)._agentpay;
  }
  if ('_agentpay' in tool && typeof (tool as any)._agentpay === 'object') {
    const raw = (tool as any)._agentpay;
    return new McpPriceMetadata({
      amountCny: raw.price_cny ?? raw.amountCny ?? 0,
      amountBaseUnits: raw.price_base_units ? BigInt(raw.price_base_units) : undefined,
      currency: raw.currency,
      billingMode: raw.billing_mode ?? raw.billingMode,
      hitlRequired: raw.hitl_required ?? raw.hitlRequired,
      vendor: raw.vendor,
      description: raw.description,
    });
  }
  return undefined;
}

export function injectToolSchemaPricing<T extends Record<string, unknown>>(
  schema: T,
  pricing: McpPriceMetadata,
): T & { _agentpay: Record<string, unknown> } {
  return {
    ...schema,
    _agentpay: pricing.toJSON(),
  };
}
