/**
 * HTTP Fetch Interceptor and Transport for AgentPay.
 *
 * Implements transparent 402 Payment Required interception, policy evaluation,
 * Cryptographic payment authorization, agent-core-sdk-wallet authorization, and post-dispatch safety.
 */

import { createHash, randomUUID } from 'node:crypto';
import {
  extractChallengeFromHeaders,
  HEADER_PAYMENT_SIGNATURE,
  injectAuthorizationToHeaders,
  encodeWalletAuthorization,
} from '../core/codecs.js';
import { WalletAuthorization } from '../core/models.js';
import { PolicyErrorCode, PolicyViolationError } from '../policy/errors.js';
import type { Clock, IMeteredPolicyEngine, IPolicyEngine } from '../policy/interfaces.js';
import type { ISigner } from './interfaces.js';

export type CredentialMode = 'block' | 'meter' | 'allow';

export const ALLOW_UNMETERED_HEADER = 'x-agent-core-sdk-allow-unmetered';
export const ALLOW_UNMETERED_HEADER_LEGACY = 'x-agentpay-allow-unmetered';
export const DEFAULT_CREDENTIAL_HEADERS: readonly string[] = ['x-agent-key'];
export const DEFAULT_CREDENTIAL_VALUE_PREFIXES: readonly string[] = ['apk_'];

export interface AgentPayRequestInit extends RequestInit {
  params?: Record<string, string | number | boolean | undefined | null> | URLSearchParams;
}

export interface AgentPayClientOptions {
  apiKey?: string;
  signer?: ISigner;
  policy: IPolicyEngine;
  baseFetch?: typeof globalThis.fetch;
  baseUrl?: string;
  defaultHeaders?: Record<string, string>;
  autoRetryOn402?: boolean;
  raiseOnPolicyRejection?: boolean;
  clock?: Clock;
  unmeteredCredentialPolicy?: CredentialMode;
  credentialHeaders?: readonly string[];
  credentialValuePrefixes?: readonly string[];
  estimateCost?: (req: Request) => bigint | number;
  actualCost?: (res: Response) => bigint | number | null;
  credentialTtlSeconds?: number;
  walletChallengeMode?: boolean;
}

function safeRecordFailure(policy: IPolicyEngine, reason: string): void {
  const p = policy as unknown as { recordFailure?: (r?: string) => void };
  if (typeof p.recordFailure === 'function') {
    try {
      p.recordFailure(reason);
    } catch {
      // Avoid masking original error
    }
  }
}

function hasCredential(
  headers: Headers,
  credentialHeaders: readonly string[],
  credentialValuePrefixes: readonly string[],
): boolean {
  for (const name of credentialHeaders) {
    if (headers.has(name)) {
      return true;
    }
  }
  const auth = headers.get('authorization');
  if (auth && credentialValuePrefixes.length > 0) {
    let token = auth.trim();
    if (token.toLowerCase().startsWith('bearer ')) {
      token = token.slice(7).trim();
    }
    for (const prefix of credentialValuePrefixes) {
      if (token.startsWith(prefix)) {
        return true;
      }
    }
  }
  return false;
}

export function computeRequestBinding(method: string, urlStr: string, bodyBytes: Uint8Array | null): string {
  const url = new URL(urlStr);
  const path = url.pathname || '/';
  const query = url.search ? url.search.slice(1) : '';
  const bodyHash = createHash('sha256').update(bodyBytes ?? new Uint8Array(0)).digest('hex');
  const canonical = `${method.toUpperCase()}\n${path}\n${query}\n${bodyHash}`;
  const canonicalHash = createHash('sha256').update(Buffer.from(canonical, 'utf-8')).digest('hex');
  return `sha256:${canonicalHash}`;
}

export class AgentPayTransport {
  readonly options: Readonly<AgentPayClientOptions>;
  private readonly baseFetch: typeof globalThis.fetch;
  private readonly clock: Clock;
  private readonly credentialHeaders: readonly string[];
  private readonly credentialValuePrefixes: readonly string[];

  constructor(options: AgentPayClientOptions) {
    if (!options.apiKey && !options.signer) {
      throw new Error("Either 'apiKey' or 'signer' must be provided.");
    }

    const credMode = options.unmeteredCredentialPolicy ?? 'block';
    if (credMode !== 'block' && credMode !== 'meter' && credMode !== 'allow') {
      throw new Error(`unmeteredCredentialPolicy must be block/meter/allow, got '${credMode}'`);
    }

    if (credMode === 'meter') {
      if (typeof options.estimateCost !== 'function') {
        throw new Error('meter mode requires estimateCost callback');
      }
      const p = options.policy as unknown as IMeteredPolicyEngine;
      if (typeof p.reserveMetered !== 'function' || typeof p.settleMetered !== 'function') {
        throw new Error('meter mode requires a policy implementing IMeteredPolicyEngine');
      }
    }

    const defaultHeaders = { ...(options.defaultHeaders ?? {}) };
    let walletChallengeMode = options.walletChallengeMode;

    if (options.apiKey) {
      if (walletChallengeMode === undefined) {
        walletChallengeMode = true;
      }
      const hasKey = Object.keys(defaultHeaders).some(
        (k) => k.toLowerCase() === 'x-agent-key' || k.toLowerCase() === 'authorization'
      );
      if (!hasKey) {
        defaultHeaders['x-agent-key'] = options.apiKey;
      }
    } else if (walletChallengeMode === undefined) {
      walletChallengeMode = false;
    }

    this.options = {
      autoRetryOn402: true,
      raiseOnPolicyRejection: false,
      unmeteredCredentialPolicy: 'block',
      credentialTtlSeconds: 60,
      baseUrl: options.baseUrl ?? (typeof process !== 'undefined' ? process.env?.AGENTPAY_BASE_URL : undefined) ?? 'http://localhost:8000',
      ...options,
      defaultHeaders,
      walletChallengeMode,
    };

    this.baseFetch = options.baseFetch ?? globalThis.fetch.bind(globalThis);
    this.clock = options.clock ?? ((options.policy as unknown as { _clock?: Clock })._clock ?? (() => Math.floor(Date.now() / 1000)));
    this.credentialHeaders = (options.credentialHeaders ?? DEFAULT_CREDENTIAL_HEADERS).map((h) => h.toLowerCase());
    this.credentialValuePrefixes = options.credentialValuePrefixes ?? DEFAULT_CREDENTIAL_VALUE_PREFIXES;
  }

  public async fetch(input: string | URL | Request, init?: RequestInit): Promise<Response> {
    let urlStr: string;
    let reqMethod: string;

    if (input instanceof Request) {
      urlStr = input.url;
      reqMethod = (init?.method ?? input.method).toUpperCase();
    } else if (typeof input === 'string') {
      urlStr = input;
      reqMethod = (init?.method ?? 'GET').toUpperCase();
    } else {
      urlStr = input.toString();
      reqMethod = (init?.method ?? 'GET').toUpperCase();
    }

    if (this.options.baseUrl) {
      urlStr = new URL(urlStr, this.options.baseUrl).toString();
    }

    if (init && 'params' in init && (init as AgentPayRequestInit).params) {
      const p = (init as AgentPayRequestInit).params;
      try {
        const urlObj = new URL(urlStr);
        if (p instanceof URLSearchParams) {
          p.forEach((v, k) => urlObj.searchParams.append(k, v));
        } else if (typeof p === 'object') {
          for (const [k, v] of Object.entries(p)) {
            if (v !== undefined && v !== null) {
              urlObj.searchParams.append(k, String(v));
            }
          }
        }
        urlStr = urlObj.toString();
      } catch {
        // Leave urlStr as is if relative without baseUrl
      }
    }

    const headers = new Headers();
    if (this.options.defaultHeaders) {
      for (const [k, v] of Object.entries(this.options.defaultHeaders)) {
        headers.set(k, v);
      }
    }

    if (input instanceof Request) {
      input.headers.forEach((v, k) => headers.set(k, v));
    }

    if (init?.headers) {
      if (init.headers instanceof Headers) {
        init.headers.forEach((v, k) => headers.set(k, v));
      } else if (Array.isArray(init.headers)) {
        for (const [k, v] of init.headers) {
          headers.set(k, v);
        }
      } else {
        for (const [k, v] of Object.entries(init.headers)) {
          if (v !== undefined) {
            headers.set(k, String(v));
          }
        }
      }
    }

    let bodyBytes: Uint8Array | null = null;
    if (init?.body !== undefined && init?.body !== null) {
      if (typeof init.body === 'string') {
        bodyBytes = new TextEncoder().encode(init.body);
      } else if (init.body instanceof Uint8Array) {
        bodyBytes = init.body;
      } else if (init.body instanceof ArrayBuffer) {
        bodyBytes = new Uint8Array(init.body);
      } else {
        const arrayBuf = await new Response(init.body as unknown as BodyInit).arrayBuffer();
        bodyBytes = new Uint8Array(arrayBuf);
      }
    } else if (input instanceof Request && input.body) {
      const arrayBuf = await input.arrayBuffer();
      bodyBytes = new Uint8Array(arrayBuf);
    }

    const { method: _m, headers: _h, body: _b, ...restInit } = init ?? {};

    const allowUnmetered =
      headers.get(ALLOW_UNMETERED_HEADER) === 'true' ||
      headers.get(ALLOW_UNMETERED_HEADER_LEGACY) === 'true';
    const isCredential = !allowUnmetered && hasCredential(headers, this.credentialHeaders, this.credentialValuePrefixes);

    let meterIntentId: string | null = null;
    if (isCredential) {
      if (this.options.walletChallengeMode) {
        // First request is allowed through to obtain 402 challenge
      } else if (this.options.unmeteredCredentialPolicy === 'allow') {
        // opt-in bypass
      } else if (this.options.unmeteredCredentialPolicy === 'block') {
        throw new PolicyViolationError(
          PolicyErrorCode.UNMETERED_CREDENTIAL,
          'Request carries a gateway credential that can bypass the HTTP 402 flow; the local budget/RPM firewall cannot meter it. Blocked (fail-closed).',
        );
      } else if (this.options.unmeteredCredentialPolicy === 'meter') {
        const dummyReq = new Request(urlStr, {
          method: reqMethod,
          headers,
          body: bodyBytes ? new Uint8Array(bodyBytes) : undefined,
        });
        let estimate: bigint | number;
        try {
          estimate = this.options.estimateCost!(dummyReq);
        } catch {
          throw new PolicyViolationError(PolicyErrorCode.INVALID_AMOUNT_FORMAT, 'estimateCost callback failed');
        }

        const intentId = `cred_${randomUUID ? randomUUID().replace(/-/g, '') : Math.random().toString(16).slice(2)}`;
        let host: string | null = null;
        try {
          host = new URL(urlStr).hostname;
        } catch {
          host = null;
        }

        const meteredPolicy = this.options.policy as IMeteredPolicyEngine;
        const decision = meteredPolicy.reserveMetered(
          intentId,
          estimate,
          host,
          this.options.credentialTtlSeconds ?? 60,
        );

        if (!decision.approved) {
          const code = decision.errorCode ?? PolicyErrorCode.POLICY_SYSTEM_ERROR;
          throw new PolicyViolationError(code, `credential call rejected by policy: ${code}`);
        }
        meterIntentId = intentId;
      }
    }

    let response: Response;
    try {
      response = await this.baseFetch(urlStr, {
        ...restInit,
        method: reqMethod,
        headers,
        body: bodyBytes ? new Uint8Array(bodyBytes) : undefined,
      });
    } catch (err) {
      if (meterIntentId) {
        safeRecordFailure(this.options.policy, 'transport error on credential call');
      }
      throw err;
    }

    if (meterIntentId) {
      const code = response.status;
      const meteredPolicy = this.options.policy as IMeteredPolicyEngine;
      if (code >= 200 && code < 300) {
        let actual: bigint | number | null = null;
        if (this.options.actualCost) {
          try {
            actual = this.options.actualCost(response);
          } catch {
            // Keep estimate if callback fails
          }
        }
        meteredPolicy.settleMetered(meterIntentId, actual);
      } else if (code >= 500) {
        safeRecordFailure(this.options.policy, `upstream ${code} on credential call`);
      } else {
        try {
          this.options.policy.release(meterIntentId);
        } catch {
          // ignore
        }
      }
    }

    const pathname = (() => {
      try {
        return new URL(urlStr).pathname;
      } catch {
        return urlStr;
      }
    })();
    const isIntegrationApi = pathname.startsWith('/api/v1/integrations/');

    if (!isIntegrationApi && this.options.walletChallengeMode && isCredential && response.status >= 200 && response.status < 300) {
      throw new PolicyViolationError(
        PolicyErrorCode.UNMETERED_CREDENTIAL,
        'Wallet challenge mode expected a 402 price challenge; the gateway served the credential request directly.',
      );
    }

    if (response.status !== 402 || this.options.autoRetryOn402 === false) {
      return response;
    }

    const challenge = extractChallengeFromHeaders(response.headers);
    if (!challenge) {
      return response;
    }
    if (challenge.isExpired(this.clock())) {
      return response;
    }

    const isWallet = challenge.scheme === 'agent-core-sdk-wallet' || challenge.scheme === 'agentpay-wallet';
    if (!isWallet && !this.options.signer) {
      throw new PolicyViolationError(
        PolicyErrorCode.POLICY_SYSTEM_ERROR,
        `unsupported payment scheme: ${challenge.scheme}`,
      );
    }

    let domain: string | null = null;
    try {
      domain = new URL(urlStr).hostname;
    } catch {
      domain = null;
    }

    if (isWallet) {
      const expectedBinding = computeRequestBinding(reqMethod, urlStr, bodyBytes);
      const ext = challenge.extensions as Record<string, unknown> | undefined;
      if (ext?.['requestBinding'] !== expectedBinding) {
        throw new PolicyViolationError(PolicyErrorCode.POLICY_SYSTEM_ERROR, 'wallet challenge requestBinding mismatch');
      }
      if (!ext?.['routeId']) {
        throw new PolicyViolationError(PolicyErrorCode.POLICY_SYSTEM_ERROR, 'wallet challenge missing routeId');
      }
      const urlObj = new URL(urlStr);
      const path = urlObj.pathname || '/';
      if (challenge.resourceUri !== path) {
        throw new PolicyViolationError(PolicyErrorCode.POLICY_SYSTEM_ERROR, 'wallet challenge resourceUri mismatch');
      }
    }

    const paymentRequest = challenge.toPaymentRequest({ domain: domain ?? undefined });
    const decision = this.options.policy.reserve({
      intentId: paymentRequest.intentId,
      amount: paymentRequest.amount,
      payee: paymentRequest.payee,
      asset: paymentRequest.asset,
      network: paymentRequest.network,
      domain: paymentRequest.domain,
      ttlSeconds: paymentRequest.ttlSeconds,
    });

    if (!decision.approved) {
      if (this.options.raiseOnPolicyRejection) {
        const code = decision.errorCode ?? PolicyErrorCode.POLICY_SYSTEM_ERROR;
        throw new PolicyViolationError(code, `Payment policy rejected 402 challenge: ${code}`);
      }
      return response;
    }

    if (!decision.reservation) {
      throw new PolicyViolationError(PolicyErrorCode.POLICY_SYSTEM_ERROR, 'approved decision without reservation');
    }
    const reservation = decision.reservation;

    const retryHeaders = new Headers(headers);

    try {
      if (isWallet) {
        if (reservation.intentId !== challenge.challengeId || reservation.amount !== challenge.amountBaseUnits) {
          throw new PolicyViolationError(
            PolicyErrorCode.POLICY_SYSTEM_ERROR,
            'wallet reservation does not match challenge',
          );
        }
        if (reservation.expiresAt < challenge.validBefore) {
          throw new PolicyViolationError(
            PolicyErrorCode.POLICY_SYSTEM_ERROR,
            'wallet reservation expires before challenge',
          );
        }
        const ext = challenge.extensions as Record<string, unknown> | undefined;
        const requestBinding = ext?.['requestBinding'] as string | undefined;
        if (!requestBinding) {
          throw new PolicyViolationError(PolicyErrorCode.POLICY_SYSTEM_ERROR, 'wallet challenge missing requestBinding');
        }
        const nonceBytes = new Uint8Array(32);
        crypto.getRandomValues(nonceBytes);
        const nonce = `0x${Buffer.from(nonceBytes).toString('hex')}` as `0x${string}`;

        const walletAuth = new WalletAuthorization({
          challengeId: challenge.challengeId,
          nonce,
          validAfter: challenge.validAfter,
          validBefore: challenge.validBefore,
          amount: challenge.amount,
          resourceUri: challenge.resourceUri ?? '/',
          requestBinding,
        });
        retryHeaders.set(HEADER_PAYMENT_SIGNATURE, encodeWalletAuthorization(walletAuth));
      } else {
        if (!this.options.signer) {
          throw new PolicyViolationError(
            PolicyErrorCode.POLICY_SYSTEM_ERROR,
            'External settlement challenge requires a configured signer',
          );
        }
        const authorization = await this.options.signer.signPaymentAuthorization(challenge, reservation);
        injectAuthorizationToHeaders(retryHeaders, authorization);
      }
    } catch (err) {
      try {
        this.options.policy.release(reservation.intentId);
      } catch {
        // ignore
      }
      throw err;
    }

    let retryResponse: Response;
    try {
      retryResponse = await this.baseFetch(urlStr, {
        ...restInit,
        method: reqMethod,
        headers: retryHeaders,
        body: bodyBytes ? new Uint8Array(bodyBytes) : undefined,
      });
    } catch (err) {
      safeRecordFailure(this.options.policy, 'transport error after payment signature sent');
      throw err;
    }

    const statusCode = retryResponse.status;
    if (statusCode >= 200 && statusCode < 300) {
      this.options.policy.commit(reservation.intentId);
    } else if (isWallet && statusCode >= 400 && statusCode < 500) {
      this.options.policy.release(reservation.intentId);
    } else if (statusCode >= 500) {
      safeRecordFailure(this.options.policy, `upstream ${statusCode} after payment`);
    }

    return retryResponse;
  }
}

export function createAgentPayFetch(options: AgentPayClientOptions): typeof globalThis.fetch {
  const transport = new AgentPayTransport(options);
  const fetchFn = (input: string | URL | Request, init?: RequestInit) => transport.fetch(input, init);
  return fetchFn as unknown as typeof globalThis.fetch;
}

export const AgentCoreTransport = AgentPayTransport;
export const createAgentCoreFetch = createAgentPayFetch;

