/**
 * LangChain.js integration for AgentPay.
 *
 * Provides PaidStructuredTool and createPaidTool helper for wrapping
 * LangChain tools with autonomous 402 payment negotiation and financial firewall guardrails.
 */

import type { AgentPayClient } from '../client/client.js';
import { X402Error } from '../core/errors.js';
import { PolicyViolationError } from '../policy/errors.js';

export class ToolException extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ToolException';
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
