/**
 * Core x402 V2 Protocol Models.
 *
 * Defines frozen, byte-conforming value objects for x402 V2
 * PaymentChallenge, PaymentAuthorization, WalletAuthorization, and SignatureData.
 */

import { X402ErrorCode, X402ValidationError } from './errors.js';

// ---------------------------------------------------------------------------
// Regex patterns & Constants
// ---------------------------------------------------------------------------

/** CAIP-2: namespace:reference (e.g. eip155:84532) */
const CAIP2_RE = /^[a-z0-9]+:[a-zA-Z0-9_-]+$/;

/** Canonical EVM address: 0x followed by 40 hex chars */
const EVM_ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

/** 32-byte hex nonce: 0x followed by 64 hex chars (or 64 hex chars without 0x) */
const NONCE_HEX_RE = /^(0x)?[0-9a-fA-F]{64}$/;

/** 32-byte r or s hex: 0x followed by 1 to 64 hex chars (canonicalized to 32 bytes) */
const BYTES32_HEX_RE = /^(0x)?[0-9a-fA-F]{1,64}$/;

/** AgentPay route identifier regex for internal virtual wallet */
const AGENTPAY_ROUTE_RE = /^agent-core-sdk:route:[A-Za-z0-9_-]+$/;

/** Maximum signed 64-bit integer for base units */
export const SQLITE_MAX_INT = 9_223_372_036_854_775_807n;

/** Supported fiat base currencies for AgentPay internal virtual wallet */
export const WALLET_FIAT_CURRENCIES = new Set(['CNY', 'USD', 'EUR']);

export function validateEvmAddress(value: unknown, fieldName: string): `0x${string}` {
  if (typeof value !== 'string' || !EVM_ADDRESS_RE.test(value)) {
    throw new X402ValidationError(
      `${fieldName}: invalid EVM address format: ${JSON.stringify(value)}. Must be 0x followed by 40 hexadecimal characters.`,
      X402ErrorCode.INVALID_ADDRESS,
    );
  }
  return value.toLowerCase() as `0x${string}`;
}

export function validateCaip2(value: unknown): string {
  if (typeof value !== 'string' || !CAIP2_RE.test(value)) {
    throw new X402ValidationError(
      `Invalid CAIP-2 network identifier: ${JSON.stringify(value)}. Expected format: namespace:reference (e.g. eip155:84532).`,
      X402ErrorCode.NETWORK_NOT_WHITELISTED,
    );
  }
  return value;
}

function validateUnixTimestamp(value: unknown, fieldName: string): number {
  if (value === undefined || value === null) {
    throw new X402ValidationError(
      `Missing required field '${fieldName}'`,
      X402ErrorCode.MISSING_REQUIRED_FIELD,
    );
  }
  if (typeof value === 'boolean' || (typeof value !== 'number' && typeof value !== 'string' && typeof value !== 'bigint')) {
    throw new X402ValidationError(
      `${fieldName} must be integer Unix seconds`,
      X402ErrorCode.INVALID_TIME_WINDOW,
    );
  }
  if (typeof value === 'number' && !Number.isInteger(value)) {
    throw new X402ValidationError(
      `${fieldName} must be integer Unix seconds, got float ${value}`,
      X402ErrorCode.INVALID_TIME_WINDOW,
    );
  }
  const parsed = typeof value === 'bigint' ? Number(value) : Number.parseInt(String(value), 10);
  if (Number.isNaN(parsed) || !Number.isSafeInteger(parsed) || String(parsed) !== String(value).trim()) {
    throw new X402ValidationError(
      `${fieldName} must be integer Unix seconds, got ${JSON.stringify(value)}`,
      X402ErrorCode.INVALID_TIME_WINDOW,
    );
  }
  if (parsed < 0) {
    throw new X402ValidationError(
      `${fieldName} cannot be negative, got ${parsed}`,
      X402ErrorCode.INVALID_TIME_WINDOW,
    );
  }
  return parsed;
}

// ---------------------------------------------------------------------------
// SignatureData
// ---------------------------------------------------------------------------

export interface SignatureDataInput {
  v: number;
  r: string;
  s: string;
  serialized?: string | null;
  compact?: string | null;
}

export class SignatureData {
  readonly v: number;
  readonly r: `0x${string}`;
  readonly s: `0x${string}`;
  readonly serialized: string;
  readonly compact: `0x${string}`;

  constructor(input: SignatureDataInput) {
    if (!input || typeof input !== 'object') {
      throw new X402ValidationError('Invalid SignatureData input', X402ErrorCode.INVALID_SIGNATURE);
    }
    if (typeof input.v !== 'number' || !Number.isInteger(input.v) || (![27, 28, 0, 1].includes(input.v) && input.v < 35)) {
      throw new X402ValidationError(
        `Invalid signature v value: ${String(input.v)}. Expected 27 or 28 (or 0/1).`,
        X402ErrorCode.INVALID_SIGNATURE,
      );
    }
    if (typeof input.r !== 'string' || !BYTES32_HEX_RE.test(input.r)) {
      throw new X402ValidationError(
        'Invalid signature r: must be a 32-byte hex string.',
        X402ErrorCode.INVALID_SIGNATURE,
      );
    }
    if (typeof input.s !== 'string' || !BYTES32_HEX_RE.test(input.s)) {
      throw new X402ValidationError(
        'Invalid signature s: must be a 32-byte hex string.',
        X402ErrorCode.INVALID_SIGNATURE,
      );
    }

    this.v = input.v;
    const rRaw = input.r.startsWith('0x') ? input.r.slice(2) : input.r;
    const sRaw = input.s.startsWith('0x') ? input.s.slice(2) : input.s;
    const rClean = rRaw.toLowerCase().padStart(64, '0');
    const sClean = sRaw.toLowerCase().padStart(64, '0');
    this.r = `0x${rClean}` as `0x${string}`;
    this.s = `0x${sClean}` as `0x${string}`;

    const vHex = this.v.toString(16).padStart(2, '0');
    const expectedRaw = `${rClean}${sClean}${vHex}`.toLowerCase();

    this.serialized = input.serialized != null ? input.serialized : expectedRaw;
    this.compact = (input.compact != null ? input.compact : `0x${expectedRaw}`) as `0x${string}`;

    Object.freeze(this);
  }

  static fromRawSignature(
    r: string | bigint,
    s: string | bigint,
    v: number,
    serialized?: string,
  ): SignatureData {
    const rStr = typeof r === 'bigint' ? `0x${r.toString(16).padStart(64, '0')}` : r.startsWith('0x') ? `0x${r.slice(2).padStart(64, '0')}` : `0x${r.padStart(64, '0')}`;
    const sStr = typeof s === 'bigint' ? `0x${s.toString(16).padStart(64, '0')}` : s.startsWith('0x') ? `0x${s.slice(2).padStart(64, '0')}` : `0x${s.padStart(64, '0')}`;
    return new SignatureData({ v, r: rStr, s: sStr, serialized });
  }

  toJSON(): Record<string, unknown> {
    return {
      v: this.v,
      r: this.r,
      s: this.s,
      serialized: this.serialized,
      compact: this.compact,
    };
  }
}

// ---------------------------------------------------------------------------
// PaymentRequestSummary (Core view returned by challenge.toPaymentRequest)
// ---------------------------------------------------------------------------

export interface ChallengePaymentRequest {
  readonly intentId: string;
  readonly amount: bigint;
  readonly payee: string;
  readonly asset: string;
  readonly network: string;
  readonly domain: string | null;
  readonly ttlSeconds: number;
  readonly isAgentpayWallet: boolean;
}

// ---------------------------------------------------------------------------
// PaymentChallenge (402 PAYMENT-REQUIRED payload)
// ---------------------------------------------------------------------------

export interface PaymentChallengeInput {
  version?: string;
  challengeId?: string;
  challenge_id?: string;
  scheme?: string;
  network?: string | null;
  asset?: string | null;
  assetSymbol?: string | null;
  asset_symbol?: string | null;
  decimals?: number;
  amount: string | bigint | number;
  payee?: string | null;
  validAfter?: number | string;
  valid_after?: number | string;
  validBefore?: number | string;
  valid_before?: number | string;
  facilitatorUrl?: string | null;
  facilitator_url?: string | null;
  resourceUri?: string | null;
  resource_uri?: string | null;
  extensions?: Record<string, unknown> | null;
  [key: string]: unknown;
}

export class PaymentChallenge {
  readonly version: string;
  readonly challengeId: string;
  readonly scheme: string;
  readonly network: string | null;
  readonly asset: string | null;
  readonly assetSymbol: string | null;
  readonly decimals: number;
  readonly amount: string;
  readonly payee: string | null;
  readonly validAfter: number;
  readonly validBefore: number;
  readonly facilitatorUrl: string | null;
  readonly resourceUri: string | null;
  readonly extensions: Record<string, unknown> | null;

  // Python snake_case aliases for seamless cross-language ergonomics
  get challenge_id(): string {
    return this.challengeId;
  }
  get asset_symbol(): string | null {
    return this.assetSymbol;
  }
  get valid_after(): number {
    return this.validAfter;
  }
  get valid_before(): number {
    return this.validBefore;
  }
  get facilitator_url(): string | null {
    return this.facilitatorUrl;
  }
  get resource_uri(): string | null {
    return this.resourceUri;
  }

  constructor(data: PaymentChallengeInput) {
    if (!data || typeof data !== 'object') {
      throw new X402ValidationError('Invalid PaymentChallenge payload', X402ErrorCode.MISSING_REQUIRED_FIELD);
    }

    const version = data.version ?? '2.0';
    if (version !== '2.0') {
      throw new X402ValidationError(
        `Unsupported protocol version: ${JSON.stringify(version)}. Expected '2.0'.`,
        X402ErrorCode.UNSUPPORTED_VERSION,
      );
    }
    this.version = version;

    const rawChallengeId = data.challengeId ?? data.challenge_id;
    if (typeof rawChallengeId !== 'string' || !rawChallengeId.trim()) {
      throw new X402ValidationError('challengeId cannot be empty.', X402ErrorCode.MISSING_REQUIRED_FIELD);
    }
    this.challengeId = rawChallengeId.trim();

    const scheme = data.scheme ?? 'EIP-3009';
    if (typeof scheme !== 'string' || !scheme.trim()) {
      throw new X402ValidationError('scheme is required', X402ErrorCode.INVALID_SCHEME);
    }
    this.scheme = scheme;

    // Network validation
    const rawNetwork = data.network ?? null;
    if (this.scheme === 'agent-core-sdk-wallet' && rawNetwork === 'agent-core-sdk:internal-ledger') {
      this.network = rawNetwork;
    } else if (rawNetwork === null || rawNetwork === undefined) {
      throw new X402ValidationError('network is required', X402ErrorCode.MISSING_REQUIRED_FIELD);
    } else {
      this.network = validateCaip2(rawNetwork);
    }

    // Asset validation
    const rawAsset = data.asset ?? null;
    if (this.scheme === 'agent-core-sdk-wallet' && typeof rawAsset === 'string' && WALLET_FIAT_CURRENCIES.has(rawAsset)) {
      this.asset = rawAsset;
    } else if (rawAsset === null || rawAsset === undefined) {
      throw new X402ValidationError('asset is required', X402ErrorCode.MISSING_REQUIRED_FIELD);
    } else {
      this.asset = validateEvmAddress(rawAsset, 'asset');
    }

    const rawSymbol = data.assetSymbol ?? data.asset_symbol ?? null;
    this.assetSymbol = typeof rawSymbol === 'string' ? rawSymbol : null;

    // Decimals validation
    const rawDecimals = data.decimals ?? 6;
    if (typeof rawDecimals !== 'number' || !Number.isInteger(rawDecimals) || rawDecimals < 0 || rawDecimals > 36) {
      throw new X402ValidationError(
        `decimals out of range or not integer: ${String(rawDecimals)}. Expected 0 to 36.`,
        X402ErrorCode.INVALID_AMOUNT_FORMAT,
      );
    }
    this.decimals = rawDecimals;

    // Amount validation (strictly integer base units, no float, no boolean)
    const rawAmount = data.amount;
    if (rawAmount === undefined || rawAmount === null) {
      throw new X402ValidationError('amount is a required field.', X402ErrorCode.MISSING_REQUIRED_FIELD);
    }
    if (typeof rawAmount === 'boolean') {
      throw new X402ValidationError('amount cannot be boolean.', X402ErrorCode.INVALID_AMOUNT_FORMAT);
    }
    if (typeof rawAmount === 'number') {
      if (!Number.isInteger(rawAmount) || !Number.isSafeInteger(rawAmount)) {
        throw new X402ValidationError(
          'amount cannot be float or unsafe number (precision loss risk). Use integer base units string or bigint.',
          X402ErrorCode.INVALID_AMOUNT_FORMAT,
        );
      }
    }
    let amountBig: bigint;
    try {
      const strVal = String(rawAmount).trim();
      if (!/^-?\d+$/.test(strVal)) {
        throw new Error('Not an integer string');
      }
      amountBig = BigInt(strVal);
    } catch {
      throw new X402ValidationError(
        `Invalid amount format: ${JSON.stringify(rawAmount)}. Must be a positive integer base units.`,
        X402ErrorCode.INVALID_AMOUNT_FORMAT,
      );
    }
    if (amountBig <= 0n) {
      throw new X402ValidationError(
        `amount must be strictly positive (> 0), got ${amountBig.toString()}.`,
        X402ErrorCode.INVALID_AMOUNT_FORMAT,
      );
    }
    if (amountBig > SQLITE_MAX_INT) {
      throw new X402ValidationError(
        `amount exceeds supported maximum int64 (${SQLITE_MAX_INT.toString()}).`,
        X402ErrorCode.INVALID_AMOUNT_FORMAT,
      );
    }
    this.amount = amountBig.toString();

    // Payee validation
    const rawPayee = data.payee ?? null;
    if (this.scheme === 'agent-core-sdk-wallet' && typeof rawPayee === 'string' && rawPayee.startsWith('agent-core-sdk:route:')) {
      this.payee = rawPayee;
    } else if (rawPayee === null || rawPayee === undefined) {
      throw new X402ValidationError('payee is required', X402ErrorCode.MISSING_REQUIRED_FIELD);
    } else {
      this.payee = validateEvmAddress(rawPayee, 'payee');
    }

    // Timestamps
    const rawValidAfter = data.validAfter ?? data.valid_after;
    const rawValidBefore = data.validBefore ?? data.valid_before;
    this.validAfter = validateUnixTimestamp(rawValidAfter, 'validAfter');
    this.validBefore = validateUnixTimestamp(rawValidBefore, 'validBefore');

    if (this.validBefore <= this.validAfter) {
      throw new X402ValidationError(
        `Invalid time window: validBefore (${this.validBefore}) must be strictly greater than validAfter (${this.validAfter}).`,
        X402ErrorCode.INVALID_TIME_WINDOW,
      );
    }

    const rawFacilitatorUrl = data.facilitatorUrl ?? data.facilitator_url ?? null;
    this.facilitatorUrl = typeof rawFacilitatorUrl === 'string' ? rawFacilitatorUrl : null;

    const rawResourceUri = data.resourceUri ?? data.resource_uri ?? null;
    this.resourceUri = typeof rawResourceUri === 'string' ? rawResourceUri : null;

    this.extensions = data.extensions && typeof data.extensions === 'object' ? { ...data.extensions } : null;

    // Scheme-specific cross-field checks
    if (this.scheme === 'agent-core-sdk-wallet') {
      if (
        this.network !== 'agent-core-sdk:internal-ledger' ||
        !this.asset ||
        !WALLET_FIAT_CURRENCIES.has(this.asset) ||
        !this.resourceUri
      ) {
        throw new X402ValidationError('invalid agent-core-sdk-wallet challenge fields', X402ErrorCode.INVALID_SCHEME);
      }
      if (this.facilitatorUrl) {
        throw new X402ValidationError(
          'agent-core-sdk-wallet challenge must not name an EIP-3009 facilitator',
          X402ErrorCode.INVALID_SCHEME,
        );
      }
    } else if (!this.network || !this.asset || !this.payee || !this.facilitatorUrl) {
      throw new X402ValidationError(
        'EIP-3009 challenge requires network, asset, payee, and facilitatorUrl',
        X402ErrorCode.MISSING_REQUIRED_FIELD,
      );
    }

    if (this.extensions) {
      Object.freeze(this.extensions);
    }
    Object.freeze(this);
  }

  static modelValidate(obj: unknown): PaymentChallenge {
    if (obj instanceof PaymentChallenge) {
      return obj;
    }
    return new PaymentChallenge(obj as PaymentChallengeInput);
  }

  get amountBaseUnits(): bigint {
    return BigInt(this.amount);
  }

  get amount_base_units(): bigint {
    return BigInt(this.amount);
  }

  isExpired(currentTimeSeconds: number): boolean {
    return currentTimeSeconds > this.validBefore;
  }

  is_expired(currentTimeSeconds: number): boolean {
    return this.isExpired(currentTimeSeconds);
  }

  toPaymentRequest(options?: {
    intentId?: string;
    domain?: string | null;
    ttlSeconds?: number;
  }): ChallengePaymentRequest {
    const intentId = options?.intentId ?? this.challengeId;
    const domain = options?.domain ? options.domain.trim().toLowerCase() : null;
    const ttlSeconds = options?.ttlSeconds ?? 360;
    const network = this.network ?? 'agent-core-sdk:internal-ledger';
    const asset = this.asset ?? 'USD';
    const payee = this.payee ?? 'agent-core-sdk:route:unknown';

    return Object.freeze({
      intentId,
      amount: this.amountBaseUnits,
      payee,
      asset,
      network,
      domain,
      ttlSeconds,
      isAgentpayWallet:
        network === 'agent-core-sdk:internal-ledger' &&
        WALLET_FIAT_CURRENCIES.has(asset) &&
        AGENTPAY_ROUTE_RE.test(payee),
    });
  }

  toJSON(): Record<string, unknown> {
    const out: Record<string, unknown> = {
      version: this.version,
      challengeId: this.challengeId,
      scheme: this.scheme,
    };
    if (this.network !== null) out.network = this.network;
    if (this.asset !== null) out.asset = this.asset;
    if (this.assetSymbol !== null) out.assetSymbol = this.assetSymbol;
    out.decimals = this.decimals;
    out.amount = this.amount;
    if (this.payee !== null) out.payee = this.payee;
    out.validAfter = this.validAfter;
    out.validBefore = this.validBefore;
    if (this.facilitatorUrl !== null) out.facilitatorUrl = this.facilitatorUrl;
    if (this.resourceUri !== null) out.resourceUri = this.resourceUri;
    if (this.extensions !== null) out.extensions = this.extensions;
    return out;
  }
}

// ---------------------------------------------------------------------------
// PaymentAuthorization (402 PAYMENT-SIGNATURE payload)
// ---------------------------------------------------------------------------

export interface PaymentAuthorizationInput {
  version?: string;
  challengeId?: string;
  challenge_id?: string;
  payer: string;
  scheme?: string;
  nonce: string;
  validAfter?: number | string;
  valid_after?: number | string;
  validBefore?: number | string;
  valid_before?: number | string;
  signature: SignatureData | SignatureDataInput | string;
}

export class PaymentAuthorization {
  readonly version: string;
  readonly challengeId: string;
  readonly payer: `0x${string}`;
  readonly scheme: string;
  readonly nonce: `0x${string}`;
  readonly validAfter: number;
  readonly validBefore: number;
  readonly signature: SignatureData | string;

  get challenge_id(): string {
    return this.challengeId;
  }
  get valid_after(): number {
    return this.validAfter;
  }
  get valid_before(): number {
    return this.validBefore;
  }

  constructor(data: PaymentAuthorizationInput) {
    if (!data || typeof data !== 'object') {
      throw new X402ValidationError('Invalid PaymentAuthorization payload', X402ErrorCode.MISSING_REQUIRED_FIELD);
    }

    const version = data.version ?? '2.0';
    if (version !== '2.0') {
      throw new X402ValidationError(
        `Unsupported protocol version: ${JSON.stringify(version)}. Expected '2.0'.`,
        X402ErrorCode.UNSUPPORTED_VERSION,
      );
    }
    this.version = version;

    const rawChallengeId = data.challengeId ?? data.challenge_id;
    if (typeof rawChallengeId !== 'string' || !rawChallengeId.trim()) {
      throw new X402ValidationError('challengeId is required', X402ErrorCode.MISSING_REQUIRED_FIELD);
    }
    this.challengeId = rawChallengeId.trim();

    if (data.payer === undefined || data.payer === null) {
      throw new X402ValidationError('payer is required', X402ErrorCode.MISSING_REQUIRED_FIELD);
    }
    this.payer = validateEvmAddress(data.payer, 'payer');

    this.scheme = data.scheme ?? 'EIP-3009';

    if (typeof data.nonce !== 'string' || !NONCE_HEX_RE.test(data.nonce)) {
      throw new X402ValidationError(
        `Invalid nonce: ${JSON.stringify(data.nonce)}. Must be a 32-byte hex string (64 hex characters).`,
        X402ErrorCode.INVALID_NONCE,
      );
    }
    this.nonce = (data.nonce.startsWith('0x') ? data.nonce.toLowerCase() : `0x${data.nonce.toLowerCase()}`) as `0x${string}`;

    const rawValidAfter = data.validAfter ?? data.valid_after;
    const rawValidBefore = data.validBefore ?? data.valid_before;
    this.validAfter = validateUnixTimestamp(rawValidAfter, 'validAfter');
    this.validBefore = validateUnixTimestamp(rawValidBefore, 'validBefore');

    if (this.validBefore <= this.validAfter) {
      throw new X402ValidationError(
        `Invalid time window: validBefore (${this.validBefore}) must be strictly greater than validAfter (${this.validAfter}).`,
        X402ErrorCode.INVALID_TIME_WINDOW,
      );
    }

    if (data.signature instanceof SignatureData) {
      this.signature = data.signature;
    } else if (typeof data.signature === 'string') {
      const clean = data.signature.trim();
      if (!clean) {
        throw new X402ValidationError('signature string cannot be empty.', X402ErrorCode.INVALID_SIGNATURE);
      }
      this.signature = clean;
    } else if (data.signature && typeof data.signature === 'object') {
      this.signature = new SignatureData(data.signature);
    } else {
      throw new X402ValidationError(
        'Invalid signature format: expected SignatureData object or hex string',
        X402ErrorCode.INVALID_SIGNATURE,
      );
    }

    Object.freeze(this);
  }

  static modelValidate(obj: unknown): PaymentAuthorization {
    if (obj instanceof PaymentAuthorization) {
      return obj;
    }
    return new PaymentAuthorization(obj as PaymentAuthorizationInput);
  }

  toJSON(): Record<string, unknown> {
    return {
      version: this.version,
      challengeId: this.challengeId,
      payer: this.payer,
      scheme: this.scheme,
      nonce: this.nonce,
      validAfter: this.validAfter,
      validBefore: this.validBefore,
      signature: this.signature instanceof SignatureData ? this.signature.toJSON() : this.signature,
    };
  }
}

// ---------------------------------------------------------------------------
// WalletAuthorization (AgentPay API-key wallet approval payload)
// ---------------------------------------------------------------------------

export interface WalletAuthorizationInput {
  version?: string;
  challengeId?: string;
  challenge_id?: string;
  scheme?: string;
  nonce: string;
  validAfter?: number;
  valid_after?: number;
  validBefore?: number;
  valid_before?: number;
  amount: string;
  resourceUri?: string;
  resource_uri?: string;
  requestBinding?: string;
  request_binding?: string;
}

export class WalletAuthorization {
  readonly version: string;
  readonly challengeId: string;
  readonly scheme: string;
  readonly nonce: `0x${string}`;
  readonly validAfter: number;
  readonly validBefore: number;
  readonly amount: string;
  readonly resourceUri: string;
  readonly requestBinding: string;

  constructor(data: WalletAuthorizationInput) {
    this.version = data.version ?? '2.0';
    this.scheme = data.scheme ?? 'agent-core-sdk-wallet';
    this.challengeId = (data.challengeId ?? data.challenge_id ?? '').trim();
    this.resourceUri = (data.resourceUri ?? data.resource_uri ?? '').trim();
    this.requestBinding = (data.requestBinding ?? data.request_binding ?? '').trim();

    if (typeof data.nonce !== 'string' || !/^0x[0-9a-f]{64}$/.test(data.nonce)) {
      throw new X402ValidationError(
        'wallet nonce must be 32 random bytes encoded as lowercase hex',
        X402ErrorCode.INVALID_NONCE,
      );
    }
    this.nonce = data.nonce as `0x${string}`;

    if (typeof data.amount !== 'string' || !/^\d+$/.test(data.amount)) {
      throw new X402ValidationError(
        'wallet amount must be a positive int64 decimal string',
        X402ErrorCode.INVALID_AMOUNT_FORMAT,
      );
    }
    const amtBig = BigInt(data.amount);
    if (amtBig <= 0n || amtBig > SQLITE_MAX_INT) {
      throw new X402ValidationError(
        'wallet amount must be a positive int64 decimal string',
        X402ErrorCode.INVALID_AMOUNT_FORMAT,
      );
    }
    this.amount = data.amount;

    this.validAfter = validateUnixTimestamp(data.validAfter ?? data.valid_after, 'validAfter');
    this.validBefore = validateUnixTimestamp(data.validBefore ?? data.valid_before, 'validBefore');

    if (this.version !== '2.0' || this.scheme !== 'agent-core-sdk-wallet' || this.validBefore <= this.validAfter) {
      throw new X402ValidationError('invalid agent-core-sdk-wallet authorization fields', X402ErrorCode.INVALID_SCHEME);
    }
    if (!this.challengeId || !this.resourceUri || !/^sha256:[0-9a-f]{64}$/.test(this.requestBinding)) {
      throw new X402ValidationError(
        'wallet authorization is missing challenge binding fields',
        X402ErrorCode.MISSING_REQUIRED_FIELD,
      );
    }

    Object.freeze(this);
  }

  toJSON(): Record<string, unknown> {
    return {
      version: this.version,
      challengeId: this.challengeId,
      scheme: this.scheme,
      nonce: this.nonce,
      validAfter: this.validAfter,
      validBefore: this.validBefore,
      amount: this.amount,
      resourceUri: this.resourceUri,
      requestBinding: this.requestBinding,
    };
  }
}
