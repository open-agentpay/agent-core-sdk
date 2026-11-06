/**
 * Vercel AI SDK integration for AgentPay.
 *
 * Wraps tool definitions with autonomous AgentPayClient execution context,
 * intercepting financial policy rejections to return structured tool error responses.
 */

import type { AgentPayClient } from '../client/client.js';
import { X402Error } from '../core/errors.js';
import { PolicyViolationError } from '../policy/errors.js';

export interface PaidVercelToolOptions<TParams = any, TResult = any> {
  description?: string;
  parameters: any;
  client?: AgentPayClient;
  handlePolicyViolation?: boolean;
  execute: (args: TParams, context?: { client?: AgentPayClient; [key: string]: any }) => Promise<TResult>;
}

export interface PaidVercelToolError {
  error: true;
  code: string;
  message: string;
}

export interface PaidVercelTool<TParams = any, TResult = any> {
  description?: string;
  parameters: any;
  client?: AgentPayClient;
  execute: (args: TParams, context?: any) => Promise<TResult | PaidVercelToolError>;
}

export function paidVercelTool<TParams = any, TResult = any>(
  options: PaidVercelToolOptions<TParams, TResult>,
): PaidVercelTool<TParams, TResult> {
  const handlePolicyViolation = options.handlePolicyViolation ?? true;

  return {
    description: options.description,
    parameters: options.parameters,
    client: options.client,
    execute: async (args: TParams, context?: any) => {
      const execContext = {
        client: options.client,
        ...(context && typeof context === 'object' ? context : {}),
      };

      try {
        return await options.execute(args, execContext);
      } catch (err) {
        if (err instanceof PolicyViolationError) {
          if (handlePolicyViolation) {
            return {
              error: true,
              code: err.code,
              message: `AgentPay Firewall Rejected: [${err.code}] ${err.detail || err.message}`,
            };
          }
          throw err;
        }
        if (err instanceof X402Error) {
          if (handlePolicyViolation) {
            return {
              error: true,
              code: 'X402_ERROR',
              message: `AgentPay x402 Protocol Error: ${err.message}`,
            };
          }
          throw err;
        }
        throw err;
      }
    },
  };
}

export const createVercelPaidTool = paidVercelTool;
