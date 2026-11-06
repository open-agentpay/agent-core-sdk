/**
 * Static rule evaluation logic for AgentPay Policy Engine.
 *
 * Evaluates deterministic static guardrails according to specs/policy-engine-spec.md §3:
 *   1. Administrative lock (is_frozen) -> POLICY_FROZEN
 *   2. Request format -> INVALID_AMOUNT_FORMAT (for amount) / INVALID_REQUEST (for other fields)
 *   3. Whitelist matrix (Order: Network -> Asset -> Payee -> Domain)
 *   4. Single-Transaction Cap -> SINGLE_TX_CAP_EXCEEDED
 *   5. Lifetime Budget Ceiling -> LIFETIME_BUDGET_EXCEEDED
 *
 * Pure in-memory rule validation without external database calls.
 */

import { PolicyErrorCode } from './errors.js';
import {
  PaymentRequest,
  PolicyConfig,
  SQLITE_MAX_INT,
  WhitelistMode,
  normalizeDomainHost,
} from './models.js';

export interface StaticEvaluationResult {
  readonly passed: boolean;
  readonly errorCode?: PolicyErrorCode | null;
  readonly reason?: string | null;
}

export function evaluateStaticRules(
  config: PolicyConfig,
  request: PaymentRequest,
  lifetimeSpent = 0n,
): StaticEvaluationResult {
  // 1. Administrative lock (is_frozen)
  if (config.isFrozen) {
    return {
      passed: false,
      errorCode: PolicyErrorCode.POLICY_FROZEN,
      reason: `Policy ${config.id} is administratively frozen`,
    };
  }

  // 2. Format validation (Amount must be strictly positive bigint within SQLite 64-bit bounds)
  if (typeof request.amount !== 'bigint' || request.amount <= 0n || request.amount > SQLITE_MAX_INT) {
    return {
      passed: false,
      errorCode: PolicyErrorCode.INVALID_AMOUNT_FORMAT,
      reason: `Invalid payment amount: ${String(request.amount)}`,
    };
  }

  if (
    typeof request.intentId !== 'string' ||
    !request.intentId.trim() ||
    typeof request.ttlSeconds !== 'number' ||
    !Number.isInteger(request.ttlSeconds) ||
    request.ttlSeconds <= 0 ||
    request.ttlSeconds > 86400
  ) {
    return {
      passed: false,
      errorCode: PolicyErrorCode.INVALID_REQUEST,
      reason: 'Invalid payment request parameters',
    };
  }

  // 3. Whitelist Matrix (EVM only). AgentPay internal wallet ledger uses required gateway domain.
  const isStrict = config.whitelistMode === WhitelistMode.STRICT;

  if (!request.isAgentpayWallet) {
    if ((isStrict || config.whitelistNetworks.size > 0) && !config.whitelistNetworks.has(request.network)) {
      return {
        passed: false,
        errorCode: PolicyErrorCode.NETWORK_NOT_WHITELISTED,
        reason: `Network ${request.network} is not in whitelisted networks`,
      };
    }

    if ((isStrict || config.whitelistAssets.size > 0) && !config.whitelistAssets.has(request.asset)) {
      return {
        passed: false,
        errorCode: PolicyErrorCode.ASSET_NOT_WHITELISTED,
        reason: `Asset ${request.asset} is not in whitelisted assets`,
      };
    }

    if ((isStrict || config.whitelistPayees.size > 0) && !config.whitelistPayees.has(request.payee)) {
      return {
        passed: false,
        errorCode: PolicyErrorCode.PAYEE_NOT_WHITELISTED,
        reason: `Payee ${request.payee} is not in whitelisted payees`,
      };
    }
  }

  if (request.isAgentpayWallet && request.domain === null) {
    return {
      passed: false,
      errorCode: PolicyErrorCode.DOMAIN_NOT_WHITELISTED,
      reason: 'AgentPay wallet requests require a whitelisted gateway domain',
    };
  }

  if (request.domain !== null) {
    const enforceDomain = request.isAgentpayWallet || isStrict || config.whitelistDomains.size > 0;
    if (enforceDomain && !config.whitelistDomains.has(request.domain)) {
      return {
        passed: false,
        errorCode: PolicyErrorCode.DOMAIN_NOT_WHITELISTED,
        reason: `Domain ${request.domain} is not in whitelisted domains`,
      };
    }
  }

  // 4. Single-Transaction Cap
  if (request.amount > config.maxPerTxBaseUnits) {
    return {
      passed: false,
      errorCode: PolicyErrorCode.SINGLE_TX_CAP_EXCEEDED,
      reason: `Amount ${request.amount.toString()} exceeds single transaction cap of ${config.maxPerTxBaseUnits.toString()}`,
    };
  }

  // 5. Lifetime Budget Ceiling (if configured)
  if (
    config.lifetimeBudgetBaseUnits !== null &&
    lifetimeSpent + request.amount > config.lifetimeBudgetBaseUnits
  ) {
    return {
      passed: false,
      errorCode: PolicyErrorCode.LIFETIME_BUDGET_EXCEEDED,
      reason: `Lifetime spend (${lifetimeSpent.toString()} + ${request.amount.toString()}) exceeds limit of ${config.lifetimeBudgetBaseUnits.toString()}`,
    };
  }

  return { passed: true };
}

export function evaluateMeteredRules(
  config: PolicyConfig,
  amount: bigint,
  domain: string | null | undefined,
  lifetimeSpent = 0n,
): StaticEvaluationResult {
  if (config.isFrozen) {
    return {
      passed: false,
      errorCode: PolicyErrorCode.POLICY_FROZEN,
      reason: `Policy ${config.id} is administratively frozen`,
    };
  }

  if (typeof amount !== 'bigint' || amount <= 0n || amount > SQLITE_MAX_INT) {
    return {
      passed: false,
      errorCode: PolicyErrorCode.INVALID_AMOUNT_FORMAT,
      reason: `Invalid estimated amount: ${String(amount)}`,
    };
  }

  if (domain !== undefined && domain !== null && typeof domain !== 'string') {
    return {
      passed: false,
      errorCode: PolicyErrorCode.INVALID_REQUEST,
      reason: `Invalid domain type: ${typeof domain}`,
    };
  }

  const host = typeof domain === 'string' ? normalizeDomainHost(domain) : '';
  if (!host || !config.whitelistDomains.has(host)) {
    return {
      passed: false,
      errorCode: PolicyErrorCode.DOMAIN_NOT_WHITELISTED,
      reason: `Domain ${JSON.stringify(domain)} is not in whitelisted domains`,
    };
  }

  if (amount > config.maxPerTxBaseUnits) {
    return {
      passed: false,
      errorCode: PolicyErrorCode.SINGLE_TX_CAP_EXCEEDED,
      reason: `Amount ${amount.toString()} exceeds single transaction cap of ${config.maxPerTxBaseUnits.toString()}`,
    };
  }

  if (
    config.lifetimeBudgetBaseUnits !== null &&
    lifetimeSpent + amount > config.lifetimeBudgetBaseUnits
  ) {
    return {
      passed: false,
      errorCode: PolicyErrorCode.LIFETIME_BUDGET_EXCEEDED,
      reason: `Lifetime spend (${lifetimeSpent.toString()} + ${amount.toString()}) exceeds limit of ${config.lifetimeBudgetBaseUnits.toString()}`,
    };
  }

  return { passed: true };
}
