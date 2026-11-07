/**
 * Model Context Protocol (MCP) integration for AgentPay.
 *
 * Provides MCP server tool handlers and client fetch adapters for autonomous 402 payment negotiation.
 */

import { AgentPayClient } from '../client/client.js';
import { createAgentPayFetch, type AgentPayClientOptions } from '../client/transport.js';
import { X402Error } from '../core/errors.js';
import { PolicyViolationError } from '../policy/errors.js';

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
