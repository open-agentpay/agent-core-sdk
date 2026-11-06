/**
 * x402 V2 HTTP Header Codecs & Serialization Utilities.
 *
 * Implements Base64URL and standard JSON encoding/decoding for HTTP headers:
 *   - PAYMENT-REQUIRED  (Response from Seller)
 *   - PAYMENT-SIGNATURE (Request from Buyer)
 *
 * Adheres strictly to RFC 4648 Base64URL encoding and the x402 V2 specification.
 */

import { X402DecodeError, X402EncodeError, X402ErrorCode, X402ValidationError } from './errors.js';
import { PaymentAuthorization, PaymentChallenge, WalletAuthorization } from './models.js';

export const HEADER_PAYMENT_REQUIRED = 'PAYMENT-REQUIRED';
export const HEADER_PAYMENT_SIGNATURE = 'PAYMENT-SIGNATURE';

// ---------------------------------------------------------------------------
// Base64URL Helpers (RFC 4648 §5)
// ---------------------------------------------------------------------------

/** Encode bytes or string into unpadded Base64URL string. */
export function base64urlEncode(data: Uint8Array | Buffer | string): string {
  const buf = typeof data === 'string' ? Buffer.from(data, 'utf-8') : Buffer.from(data);
  return buf
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/** Decode Base64URL string (with or without padding) into raw bytes. */
export function base64urlDecode(s: string): Uint8Array {
  const clean = s.trim();
  if (!clean || !/^[A-Za-z0-9\-_]+=*$/.test(clean)) {
    throw new ValueError('Malformed Base64URL input');
  }
  const missingPadding = clean.length % 4;
  const padded = missingPadding ? clean + '='.repeat(4 - missingPadding) : clean;
  const b64 = padded.replace(/-/g, '+').replace(/_/g, '/');
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

class ValueError extends Error {}

function parseRawHeaderValue(headerValue: string): Record<string, unknown> {
  if (typeof headerValue !== 'string' || !headerValue.trim()) {
    throw new X402DecodeError('Header value cannot be empty.', X402ErrorCode.MALFORMED_HEADER);
  }

  const val = headerValue.trim();

  // Fast path: direct JSON string
  if (val.startsWith('{') && val.endsWith('}')) {
    try {
      const parsed: unknown = JSON.parse(val);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('Parsed JSON must be a JSON object');
      }
      return parsed as Record<string, unknown>;
    } catch (exc) {
      throw new X402DecodeError(
        `Failed to parse raw JSON header value: ${exc instanceof Error ? exc.message : String(exc)}`,
        X402ErrorCode.MALFORMED_HEADER,
      );
    }
  }

  // Attempt Base64URL decoding
  try {
    const rawBytes = base64urlDecode(val);
    const jsonStr = Buffer.from(rawBytes).toString('utf-8');
    const parsed: unknown = JSON.parse(jsonStr);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('Parsed Base64 payload must be a JSON object');
    }
    return parsed as Record<string, unknown>;
  } catch (exc) {
    throw new X402DecodeError(
      `Failed to decode Base64URL x402 header value: ${exc instanceof Error ? exc.message : String(exc)}`,
      X402ErrorCode.MALFORMED_HEADER,
    );
  }
}

// ---------------------------------------------------------------------------
// Challenge Codecs (PAYMENT-REQUIRED)
// ---------------------------------------------------------------------------

export function encodeChallenge(
  challenge: PaymentChallenge,
  options?: { base64Url?: boolean },
): string {
  const useBase64Url = options?.base64Url ?? true;
  try {
    const jsonStr = JSON.stringify(challenge.toJSON());
    return useBase64Url ? base64urlEncode(jsonStr) : jsonStr;
  } catch (exc) {
    throw new X402EncodeError(
      `Failed to encode challenge: ${exc instanceof Error ? exc.message : String(exc)}`,
      X402ErrorCode.MALFORMED_HEADER,
    );
  }
}

export function decodeChallenge(headerValue: string): PaymentChallenge {
  const payloadDict = parseRawHeaderValue(headerValue);
  try {
    return PaymentChallenge.modelValidate(payloadDict);
  } catch (exc) {
    if (exc instanceof X402ValidationError) {
      throw exc;
    }
    throw new X402ValidationError(
      `Invalid challenge payload: ${exc instanceof Error ? exc.message : String(exc)}`,
    );
  }
}

// ---------------------------------------------------------------------------
// Authorization Codecs (PAYMENT-SIGNATURE)
// ---------------------------------------------------------------------------

export function encodeAuthorization(
  authorization: PaymentAuthorization,
  options?: { base64Url?: boolean },
): string {
  const useBase64Url = options?.base64Url ?? true;
  try {
    const jsonStr = JSON.stringify(authorization.toJSON());
    return useBase64Url ? base64urlEncode(jsonStr) : jsonStr;
  } catch (exc) {
    throw new X402EncodeError(
      `Failed to encode authorization: ${exc instanceof Error ? exc.message : String(exc)}`,
      X402ErrorCode.MALFORMED_HEADER,
    );
  }
}

export function encodeWalletAuthorization(
  authorization: WalletAuthorization,
  options?: { base64Url?: boolean },
): string {
  const useBase64Url = options?.base64Url ?? true;
  try {
    const jsonStr = JSON.stringify(authorization.toJSON());
    return useBase64Url ? base64urlEncode(jsonStr) : jsonStr;
  } catch {
    throw new X402EncodeError('Failed to encode wallet authorization', X402ErrorCode.MALFORMED_HEADER);
  }
}

export function decodeAuthorization(headerValue: string): PaymentAuthorization {
  const payloadDict = parseRawHeaderValue(headerValue);
  try {
    return PaymentAuthorization.modelValidate(payloadDict);
  } catch (exc) {
    if (exc instanceof X402ValidationError) {
      throw exc;
    }
    throw new X402ValidationError(
      `Invalid authorization payload: ${exc instanceof Error ? exc.message : String(exc)}`,
    );
  }
}

// ---------------------------------------------------------------------------
// Header Extraction & Injection Utilities
// ---------------------------------------------------------------------------

export type HeadersLike = Headers | Record<string, string | undefined> | Map<string, string>;

function findHeaderCaseInsensitive(headers: HeadersLike, targetUpper: string): string | null {
  if (typeof Headers !== 'undefined' && headers instanceof Headers) {
    return headers.get(targetUpper);
  }
  if (headers instanceof Map) {
    for (const [k, v] of headers.entries()) {
      if (k.toUpperCase() === targetUpper) {
        return v;
      }
    }
    return null;
  }
  for (const [k, v] of Object.entries(headers)) {
    if (k.toUpperCase() === targetUpper && typeof v === 'string') {
      return v;
    }
  }
  return null;
}

export function extractChallengeFromHeaders(headers: HeadersLike): PaymentChallenge | null {
  const val = findHeaderCaseInsensitive(headers, HEADER_PAYMENT_REQUIRED);
  if (val === null) {
    return null;
  }
  return decodeChallenge(val);
}

export function extractAuthorizationFromHeaders(headers: HeadersLike): PaymentAuthorization | null {
  const val = findHeaderCaseInsensitive(headers, HEADER_PAYMENT_SIGNATURE);
  if (val === null) {
    return null;
  }
  return decodeAuthorization(val);
}

export function injectAuthorizationToHeaders(
  headers: Headers | Record<string, string> | Map<string, string>,
  authorization: PaymentAuthorization,
  options?: { base64Url?: boolean; headerName?: string },
): void {
  const headerName = options?.headerName ?? HEADER_PAYMENT_SIGNATURE;
  const encoded = encodeAuthorization(authorization, { base64Url: options?.base64Url });

  if (headers instanceof Headers) {
    headers.set(headerName, encoded);
  } else if (headers instanceof Map) {
    headers.set(headerName, encoded);
  } else {
    headers[headerName] = encoded;
  }
}
