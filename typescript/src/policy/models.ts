/**
 * Policy engine data models for AgentPay.
 *
 * All models are frozen value objects.
 * Amounts are strictly bigint base units; floats and booleans are rejected.
 * EVM addresses are auto-normalised to lowercase.
 * CAIP-2 network identifiers are validated on construction.
 */

import { SQLITE_MAX_INT } from '../core/models.js';
import { PolicyErrorCode } from './errors.js';

export { SQLITE_MAX_INT };

const CAIP2_RE = /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$/;
const EVM_ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const AGENTPAY_ROUTE_RE = /^agent-core-sdk:route:[A-Za-z0-9_-]+$/;
const AGENTPAY_INTERNAL_NETWORK = 'agent-core-sdk:internal-ledger';
const WALLET_FIAT_CURRENCIES = new Set(['CNY', 'USD', 'EUR']);

export function normalizeDomainHost(value: string): string {
  let v = value.trim().toLowerCase();
  if (v.includes('://')) {
    v = v.split('://')[1]!;
  }
  v = v.split('/')[0]!.split('?')[0]!.split('#')[0]!;
  if (v.includes(':')) {
    v = v.split(':')[0]!;
  }
  return v.replace(/\.+$/, '');
}

export function validatePositiveBigInt(value: unknown, fieldName: string): bigint {
  if (typeof value === 'boolean') {
    throw new TypeError(`${fieldName} must be an integer, got boolean`);
  }
  let big: bigint;
  if (typeof value === 'bigint') {
    big = value;
  } else if (typeof value === 'number') {
    if (!Number.isInteger(value) || !Number.isSafeInteger(value)) {
      throw new TypeError(`${fieldName} must be an integer, got ${value}`);
    }
    big = BigInt(value);
  } else if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!/^\d+$/.test(trimmed)) {
      throw new TypeError(`${fieldName} must be a positive integer string, got ${JSON.stringify(value)}`);
    }
    big = BigInt(trimmed);
  } else {
    throw new TypeError(`${fieldName} must be bigint, number, or string, got ${typeof value}`);
  }

  if (big <= 0n) {
    throw new RangeError(`${fieldName} must be > 0, got ${big.toString()}`);
  }
  if (big > SQLITE_MAX_INT) {
    throw new RangeError(`${fieldName} exceeds SQLite max signed 64-bit integer (${SQLITE_MAX_INT.toString()})`);
  }
  return big;
}

export enum BreakerState {
  CLOSED = 'CLOSED',
  OPEN = 'OPEN',
  HALF_OPEN = 'HALF_OPEN',
}

export enum WhitelistMode {
  STRICT = 'strict',
  SIMPLE = 'simple',
}

export enum LedgerEntryState {
  RESERVED = 'RESERVED',
  COMMITTED = 'COMMITTED',
  RELEASED = 'RELEASED',
}

export interface ReservationTokenInput {
  reservationId?: string;
  reservation_id?: string;
  intentId?: string;
  intent_id?: string;
  policyId?: string;
  policy_id?: string;
  amount: bigint | number | string;
  expiresAt?: number;
  expires_at?: number;
  createdAt?: number;
  created_at?: number;
}

export class ReservationToken {
  readonly reservationId: string;
  readonly intentId: string;
  readonly policyId: string;
  readonly amount: bigint;
  readonly expiresAt: number;
  readonly createdAt: number;

  get reservation_id(): string {
    return this.reservationId;
  }
  get intent_id(): string {
    return this.intentId;
  }
  get policy_id(): string {
    return this.policyId;
  }
  get expires_at(): number {
    return this.expiresAt;
  }
  get created_at(): number {
    return this.createdAt;
  }

  constructor(input: ReservationTokenInput) {
    const resId = input.reservationId ?? input.reservation_id;
    if (!resId || typeof resId !== 'string') {
      throw new TypeError('reservationId must be a non-empty string');
    }
    const intentId = input.intentId ?? input.intent_id;
    if (!intentId || typeof intentId !== 'string') {
      throw new TypeError('intentId must be a non-empty string');
    }
    const policyId = input.policyId ?? input.policy_id ?? 'default';
    if (typeof policyId !== 'string') {
      throw new TypeError('policyId must be a string');
    }

    const amountBig = validatePositiveBigInt(input.amount, 'amount');
    const expiresAt = input.expiresAt ?? input.expires_at ?? 0;
    const createdAt = input.createdAt ?? input.created_at ?? Math.floor(Date.now() / 1000);

    this.reservationId = resId;
    this.intentId = intentId;
    this.policyId = policyId;
    this.amount = amountBig;
    this.expiresAt = expiresAt;
    this.createdAt = createdAt;

    Object.freeze(this);
  }

  toJSON(): Record<string, unknown> {
    return {
      reservationId: this.reservationId,
      intentId: this.intentId,
      policyId: this.policyId,
      amount: this.amount.toString(),
      expiresAt: this.expiresAt,
      createdAt: this.createdAt,
    };
  }
}

export interface PolicyDecision {
  readonly approved: boolean;
  readonly errorCode?: PolicyErrorCode | null;
  readonly reservation?: ReservationToken | null;
  readonly availableAfter?: bigint | null;
}

export interface PaymentRequestInput {
  intentId?: string;
  intent_id?: string;
  amount: bigint | number | string;
  payee: string;
  asset: string;
  network: string;
  domain?: string | null;
  ttlSeconds?: number;
  ttl_seconds?: number;
}

export class PaymentRequest {
  readonly intentId: string;
  readonly amount: bigint;
  readonly payee: string;
  readonly asset: string;
  readonly network: string;
  readonly domain: string | null;
  readonly ttlSeconds: number;

  get intent_id(): string {
    return this.intentId;
  }
  get ttl_seconds(): number {
    return this.ttlSeconds;
  }
  get isAgentpayWallet(): boolean {
    return this.network === AGENTPAY_INTERNAL_NETWORK;
  }
  get is_internal_wallet(): boolean {
    return this.isAgentpayWallet;
  }

  constructor(input: PaymentRequestInput) {
    const intentId = input.intentId ?? input.intent_id;
    if (!intentId || typeof intentId !== 'string' || !intentId.trim()) {
      throw new TypeError('intentId must be a non-empty string');
    }

    const amountBig = validatePositiveBigInt(input.amount, 'amount');

    if (typeof input.payee !== 'string' || !input.payee.trim()) {
      throw new TypeError('payee must be a non-empty string');
    }
    const payeeClean = input.payee.trim();
    let normPayee: string;
    if (AGENTPAY_ROUTE_RE.test(payeeClean)) {
      normPayee = payeeClean;
    } else if (EVM_ADDRESS_RE.test(payeeClean)) {
      normPayee = payeeClean.toLowerCase();
    } else {
      throw new TypeError(`Invalid payee address: ${input.payee}`);
    }

    if (typeof input.asset !== 'string' || !input.asset.trim()) {
      throw new TypeError('asset must be a non-empty string');
    }
    const assetClean = input.asset.trim();
    let normAsset: string;
    if (WALLET_FIAT_CURRENCIES.has(assetClean.toUpperCase())) {
      normAsset = assetClean.toUpperCase();
    } else if (EVM_ADDRESS_RE.test(assetClean)) {
      normAsset = assetClean.toLowerCase();
    } else {
      throw new TypeError(`Invalid asset: ${input.asset}`);
    }

    if (typeof input.network !== 'string' || !input.network.trim()) {
      throw new TypeError('network must be a non-empty string');
    }
    const netClean = input.network.trim();
    if (netClean !== AGENTPAY_INTERNAL_NETWORK && !CAIP2_RE.test(netClean)) {
      throw new TypeError(`Invalid network identifier: ${input.network}`);
    }

    const isWallet = netClean === AGENTPAY_INTERNAL_NETWORK;
    const isWalletPayee = AGENTPAY_ROUTE_RE.test(normPayee);
    const isWalletAsset = WALLET_FIAT_CURRENCIES.has(normAsset);
    if ((isWallet || isWalletPayee || isWalletAsset) && !(isWallet && isWalletPayee && isWalletAsset)) {
      throw new TypeError(
        'AgentPay wallet requests require internal-ledger, supported fiat (CNY/USD/EUR), and agent-core-sdk:route payee',
      );
    }

    const domain = input.domain ? normalizeDomainHost(input.domain) : null;
    const rawTtl = input.ttlSeconds ?? input.ttl_seconds ?? 360;
    if (typeof rawTtl !== 'number' || !Number.isInteger(rawTtl) || rawTtl <= 0 || rawTtl > 86400) {
      throw new TypeError(`ttlSeconds must be an integer between 1 and 86400, got ${rawTtl}`);
    }

    this.intentId = intentId.trim();
    this.amount = amountBig;
    this.payee = normPayee;
    this.asset = normAsset;
    this.network = netClean;
    this.domain = domain;
    this.ttlSeconds = rawTtl;

    Object.freeze(this);
  }
}

export interface PolicyConfigInput {
  id: string;
  name?: string;
  walletAddress?: string;
  wallet_address?: string;
  maxPerTxBaseUnits?: bigint | number | string;
  max_per_tx_base_units?: bigint | number | string;
  rollingBudget24hBaseUnits?: bigint | number | string;
  rolling_budget_24h_base_units?: bigint | number | string;
  lifetimeBudgetBaseUnits?: bigint | number | string | null;
  lifetime_budget_base_units?: bigint | number | string | null;
  whitelistMode?: WhitelistMode | string;
  whitelist_mode?: WhitelistMode | string;
  whitelistPayees?: readonly string[];
  whitelist_payees?: readonly string[];
  whitelistAssets?: readonly string[];
  whitelist_assets?: readonly string[];
  whitelistNetworks?: readonly string[];
  whitelist_networks?: readonly string[];
  whitelistDomains?: readonly string[];
  whitelist_domains?: readonly string[];
  circuitMaxRpm?: number;
  circuit_max_rpm?: number;
  circuitConsecutiveFailures?: number;
  circuit_consecutive_failures?: number;
  circuitCooldownSeconds?: number;
  circuit_cooldown_seconds?: number;
  breakerState?: BreakerState | string;
  breaker_state?: BreakerState | string;
  trippedAt?: number | null;
  tripped_at?: number | null;
  isFrozen?: boolean;
  is_frozen?: boolean | number;
  createdAt?: number;
  created_at?: number;
  updatedAt?: number;
  updated_at?: number;
}

export class PolicyConfig {
  readonly id: string;
  readonly name: string;
  readonly walletAddress: `0x${string}`;
  readonly maxPerTxBaseUnits: bigint;
  readonly rollingBudget24hBaseUnits: bigint;
  readonly lifetimeBudgetBaseUnits: bigint | null;
  readonly whitelistMode: WhitelistMode;
  readonly whitelistPayees: ReadonlySet<string>;
  readonly whitelistAssets: ReadonlySet<string>;
  readonly whitelistNetworks: ReadonlySet<string>;
  readonly whitelistDomains: ReadonlySet<string>;
  readonly circuitMaxRpm: number;
  readonly circuitConsecutiveFailures: number;
  readonly circuitCooldownSeconds: number;
  readonly breakerState: BreakerState;
  readonly trippedAt: number | null;
  readonly isFrozen: boolean;
  readonly createdAt: number;
  readonly updatedAt: number;

  get wallet_address(): `0x${string}` {
    return this.walletAddress;
  }
  get max_per_tx_base_units(): bigint {
    return this.maxPerTxBaseUnits;
  }
  get rolling_budget_24h_base_units(): bigint {
    return this.rollingBudget24hBaseUnits;
  }
  get lifetime_budget_base_units(): bigint | null {
    return this.lifetimeBudgetBaseUnits;
  }
  get whitelist_mode(): WhitelistMode {
    return this.whitelistMode;
  }
  get circuit_max_rpm(): number {
    return this.circuitMaxRpm;
  }
  get circuit_consecutive_failures(): number {
    return this.circuitConsecutiveFailures;
  }
  get circuit_cooldown_seconds(): number {
    return this.circuitCooldownSeconds;
  }
  get breaker_state(): BreakerState {
    return this.breakerState;
  }
  get tripped_at(): number | null {
    return this.trippedAt;
  }
  get is_frozen(): boolean {
    return this.isFrozen;
  }
  get created_at(): number {
    return this.createdAt;
  }
  get updated_at(): number {
    return this.updatedAt;
  }

  constructor(input: PolicyConfigInput) {
    if (!input.id || typeof input.id !== 'string') {
      throw new TypeError('id must be a non-empty string');
    }
    this.id = input.id;
    this.name = input.name || input.id;

    const rawAddr = input.walletAddress ?? input.wallet_address;
    if (!rawAddr || typeof rawAddr !== 'string' || !EVM_ADDRESS_RE.test(rawAddr)) {
      throw new TypeError(`walletAddress must be a valid EVM address, got ${rawAddr}`);
    }
    this.walletAddress = rawAddr.toLowerCase() as `0x${string}`;

    const rawMaxPerTx = input.maxPerTxBaseUnits ?? input.max_per_tx_base_units;
    if (rawMaxPerTx === undefined || rawMaxPerTx === null) {
      throw new TypeError('maxPerTxBaseUnits is required');
    }
    this.maxPerTxBaseUnits = validatePositiveBigInt(rawMaxPerTx, 'maxPerTxBaseUnits');

    const rawRolling = input.rollingBudget24hBaseUnits ?? input.rolling_budget_24h_base_units;
    if (rawRolling === undefined || rawRolling === null) {
      throw new TypeError('rollingBudget24hBaseUnits is required');
    }
    this.rollingBudget24hBaseUnits = validatePositiveBigInt(rawRolling, 'rollingBudget24hBaseUnits');

    const rawLifetime = input.lifetimeBudgetBaseUnits ?? input.lifetime_budget_base_units;
    this.lifetimeBudgetBaseUnits =
      rawLifetime !== undefined && rawLifetime !== null
        ? validatePositiveBigInt(rawLifetime, 'lifetimeBudgetBaseUnits')
        : null;

    const rawMode = input.whitelistMode ?? input.whitelist_mode ?? WhitelistMode.SIMPLE;
    this.whitelistMode = rawMode === WhitelistMode.STRICT || rawMode === 'strict' ? WhitelistMode.STRICT : WhitelistMode.SIMPLE;

    const payees = input.whitelistPayees ?? input.whitelist_payees ?? [];
    const normPayees = new Set<string>();
    for (const p of payees) {
      if (typeof p !== 'string') throw new TypeError('whitelist payees must be strings');
      if (AGENTPAY_ROUTE_RE.test(p)) {
        normPayees.add(p);
      } else if (EVM_ADDRESS_RE.test(p)) {
        normPayees.add(p.toLowerCase());
      } else {
        throw new TypeError(`Invalid payee in whitelist: ${p}`);
      }
    }
    this.whitelistPayees = Object.freeze(normPayees);

    const assets = input.whitelistAssets ?? input.whitelist_assets ?? [];
    const normAssets = new Set<string>();
    for (const a of assets) {
      if (typeof a !== 'string') throw new TypeError('whitelist assets must be strings');
      if (WALLET_FIAT_CURRENCIES.has(a.toUpperCase())) {
        normAssets.add(a.toUpperCase());
      } else if (EVM_ADDRESS_RE.test(a)) {
        normAssets.add(a.toLowerCase());
      } else {
        throw new TypeError(`Invalid asset in whitelist: ${a}`);
      }
    }
    this.whitelistAssets = Object.freeze(normAssets);

    const networks = input.whitelistNetworks ?? input.whitelist_networks ?? [];
    const normNetworks = new Set<string>();
    for (const n of networks) {
      if (typeof n !== 'string' || (n !== AGENTPAY_INTERNAL_NETWORK && !CAIP2_RE.test(n))) {
        throw new TypeError(`Invalid network in whitelist: ${n}`);
      }
      normNetworks.add(n);
    }
    this.whitelistNetworks = Object.freeze(normNetworks);

    const domains = input.whitelistDomains ?? input.whitelist_domains ?? [];
    const normDomains = new Set<string>();
    for (const d of domains) {
      if (typeof d !== 'string') throw new TypeError('whitelist domains must be strings');
      normDomains.add(normalizeDomainHost(d));
    }
    this.whitelistDomains = Object.freeze(normDomains);

    this.circuitMaxRpm = input.circuitMaxRpm ?? input.circuit_max_rpm ?? 15;
    this.circuitConsecutiveFailures = input.circuitConsecutiveFailures ?? input.circuit_consecutive_failures ?? 5;
    this.circuitCooldownSeconds = input.circuitCooldownSeconds ?? input.circuit_cooldown_seconds ?? 300;

    const rawBreaker = input.breakerState ?? input.breaker_state ?? BreakerState.CLOSED;
    this.breakerState =
      rawBreaker === BreakerState.OPEN || rawBreaker === 'OPEN'
        ? BreakerState.OPEN
        : rawBreaker === BreakerState.HALF_OPEN || rawBreaker === 'HALF_OPEN'
          ? BreakerState.HALF_OPEN
          : BreakerState.CLOSED;

    this.trippedAt = input.trippedAt ?? input.tripped_at ?? null;

    const rawFrozen = input.isFrozen ?? input.is_frozen ?? false;
    this.isFrozen = rawFrozen === true || rawFrozen === 1;

    const now = Math.floor(Date.now() / 1000);
    this.createdAt = input.createdAt ?? input.created_at ?? now;
    this.updatedAt = input.updatedAt ?? input.updated_at ?? now;

    Object.freeze(this);
  }
}

export function loadPolicyConfig(data: Record<string, any>): PolicyConfig {
  const norm: Record<string, any> = {};

  if ('policyId' in data) norm.id = data.policyId;
  else if ('id' in data) norm.id = data.id;

  if ('name' in data) norm.name = data.name;

  if ('walletAddress' in data) norm.walletAddress = data.walletAddress;
  else if ('wallet_address' in data) norm.walletAddress = data.wallet_address;

  if ('max_per_tx_base_units' in data) norm.maxPerTxBaseUnits = data.max_per_tx_base_units;
  else if ('maxPerTxBaseUnits' in data) norm.maxPerTxBaseUnits = data.maxPerTxBaseUnits;

  if ('rolling_budget_24h_base_units' in data) norm.rollingBudget24hBaseUnits = data.rolling_budget_24h_base_units;
  else if ('rollingBudget24hBaseUnits' in data) norm.rollingBudget24hBaseUnits = data.rollingBudget24hBaseUnits;

  if ('lifetime_budget_base_units' in data) norm.lifetimeBudgetBaseUnits = data.lifetime_budget_base_units;
  else if ('lifetimeBudgetBaseUnits' in data) norm.lifetimeBudgetBaseUnits = data.lifetimeBudgetBaseUnits;

  if ('whitelistMode' in data) norm.whitelistMode = data.whitelistMode;
  else if ('whitelist_mode' in data) norm.whitelistMode = data.whitelist_mode;

  if ('whitelist' in data && typeof data.whitelist === 'object' && data.whitelist !== null) {
    const wl = data.whitelist;
    if ('mode' in wl && !norm.whitelistMode) norm.whitelistMode = wl.mode;
    norm.whitelistPayees = wl.payees ?? [];
    norm.whitelistAssets = wl.assets ?? [];
    norm.whitelistNetworks = wl.networks ?? [];
    norm.whitelistDomains = wl.domains ?? [];
  } else {
    if ('whitelist_payees' in data) norm.whitelistPayees = data.whitelist_payees;
    else if ('whitelistPayees' in data) norm.whitelistPayees = data.whitelistPayees;

    if ('whitelist_assets' in data) norm.whitelistAssets = data.whitelist_assets;
    else if ('whitelistAssets' in data) norm.whitelistAssets = data.whitelistAssets;

    if ('whitelist_networks' in data) norm.whitelistNetworks = data.whitelist_networks;
    else if ('whitelistNetworks' in data) norm.whitelistNetworks = data.whitelistNetworks;

    if ('whitelist_domains' in data) norm.whitelistDomains = data.whitelist_domains;
    else if ('whitelistDomains' in data) norm.whitelistDomains = data.whitelistDomains;
  }

  for (const field of [
    'circuit_max_rpm',
    'circuitMaxRpm',
    'circuit_consecutive_failures',
    'circuitConsecutiveFailures',
    'circuit_cooldown_seconds',
    'circuitCooldownSeconds',
    'breaker_state',
    'breakerState',
    'tripped_at',
    'trippedAt',
    'is_frozen',
    'isFrozen',
    'created_at',
    'createdAt',
    'updated_at',
    'updatedAt',
  ]) {
    if (field in data) {
      norm[field] = data[field];
    }
  }

  return new PolicyConfig(norm as PolicyConfigInput);
}
