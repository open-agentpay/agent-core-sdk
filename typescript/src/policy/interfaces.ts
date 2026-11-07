/**
 * Policy engine interfaces for AgentPay.
 *
 * Defines the two-phase reservation protocol and metering extensions.
 */

import type { BreakerState, PolicyDecision } from './models.js';

export type Clock = () => number;

export interface ReserveParams {
  intentId: string;
  amount: bigint | number | string;
  payee: string;
  asset: string;
  network: string;
  domain?: string | null;
  ttlSeconds?: number;
}

export interface IPolicyEngine {
  /**
   * Atomically evaluate all precedence rules and lock quota.
   */
  reserve(params: ReserveParams): PolicyDecision;

  /**
   * Transition a reservation from RESERVED to COMMITTED.
   * Idempotent: subsequent calls for the same intentId are no-ops.
   */
  commit(intentId: string): void;

  /**
   * Transition a reservation from RESERVED to RELEASED, returning quota.
   * Guarded: if the intent was already COMMITTED, throws RESERVATION_ALREADY_FINALIZED.
   */
  release(intentId: string, reason?: string): void;
}

export interface IMeteredPolicyEngine extends IPolicyEngine {
  /**
   * Reserve quota for a credential-mode (non-402) call before wire dispatch.
   */
  reserveMetered(
    intentId: string,
    estimatedAmount: bigint | number | string,
    domain?: string | null,
    ttlSeconds?: number,
  ): PolicyDecision;

  /**
   * Settle a metered call by transitioning from RESERVED to COMMITTED.
   */
  settleMetered(intentId: string, actualAmount?: bigint | number | null): void;

  /**
   * Return the current available rolling budget in base units.
   */
  getAvailableRollingBudget(): bigint;

  /**
   * Return the current live circuit breaker state.
   */
  getBreakerState(): BreakerState;

  /**
   * Record a transaction or upstream delivery failure.
   */
  recordFailure(reason?: string): void;

  /**
   * Reset the circuit breaker to CLOSED.
   */
  resetBreaker(): void;
}
