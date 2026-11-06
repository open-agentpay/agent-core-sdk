/**
 * AgentPayClient: HTTP Client with automatic 402 payment negotiation and financial firewall.
 */

import type { IPolicyEngine } from '../policy/interfaces.js';
import type { ISigner } from './interfaces.js';
import { AgentPayTransport, type AgentPayClientOptions, type AgentPayRequestInit } from './transport.js';

export class AgentPayClient {
  readonly signer: ISigner;
  readonly policy: IPolicyEngine;
  readonly transport: AgentPayTransport;

  constructor(options: AgentPayClientOptions) {
    this.signer = options.signer;
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
}
