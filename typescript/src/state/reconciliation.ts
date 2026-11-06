/**
 * Reconciliation Engine for AgentPay State Coordination.
 *
 * Adheres strictly to:
 *   - CLAUDE.md §6: Nonce verification, fail-closed reconciliation, and validBefore window safety
 *   - P0-6 Invariant: Quota release permitted ONLY if nonce is proven unspent after (validBefore + safeBuffer)
 *   - Anti-Rollback Invariant: Upstream delivery failure never rolls back valid settlement
 */

import {
  BudgetLedgerState,
  PaymentIntentState,
  SettlementState,
} from '../core/state.js';
import type { Clock } from '../policy/interfaces.js';
import type { BuyerStateCoordinator } from './buyer-coordinator.js';

export enum NonceStatus {
  UNUSED = 'UNUSED',
  USED = 'USED',
  CANCELED = 'CANCELED',
  UNKNOWN = 'UNKNOWN',
}

export interface NonceProbeResult {
  readonly status: NonceStatus;
  readonly txHash?: string | null;
  readonly detail?: string | null;
}

export interface SettlementProbeResult {
  readonly status: SettlementState;
  readonly txHash?: string | null;
  readonly error?: string | null;
}

export interface ISettlementProbe {
  probeSettlement(settlementId: string): Promise<SettlementProbeResult> | SettlementProbeResult;
  probeNonce(
    networkId: string,
    assetAddress: string,
    payerAddress: string,
    nonce: string,
  ): Promise<NonceProbeResult> | NonceProbeResult;
}

export class MockSettlementProbe implements ISettlementProbe {
  readonly #settlements = new Map<string, SettlementProbeResult>();
  readonly #nonces = new Map<string, NonceProbeResult>();
  raiseOnProbe = false;

  setSettlement(
    settlementId: string,
    status: SettlementState,
    options?: { txHash?: string | null; error?: string | null },
  ): void {
    this.#settlements.set(settlementId, {
      status,
      txHash: options?.txHash ?? null,
      error: options?.error ?? null,
    });
  }

  setNonce(
    networkId: string,
    assetAddress: string,
    payerAddress: string,
    nonce: string,
    status: NonceStatus,
    options?: { txHash?: string | null; detail?: string | null },
  ): void {
    const key = `${networkId.toLowerCase()}:${assetAddress.toLowerCase()}:${payerAddress.toLowerCase()}:${nonce.toLowerCase()}`;
    this.#nonces.set(key, {
      status,
      txHash: options?.txHash ?? null,
      detail: options?.detail ?? null,
    });
  }

  probeSettlement(settlementId: string): SettlementProbeResult {
    if (this.raiseOnProbe) {
      return {
        status: SettlementState.UNKNOWN,
        error: 'Simulated network failure in probe',
      };
    }
    return (
      this.#settlements.get(settlementId) ?? {
        status: SettlementState.FAILED,
        error: 'Settlement not found',
      }
    );
  }

  probeNonce(
    networkId: string,
    assetAddress: string,
    payerAddress: string,
    nonce: string,
  ): NonceProbeResult {
    if (this.raiseOnProbe) {
      return {
        status: NonceStatus.UNKNOWN,
        detail: 'Simulated network failure in probe',
      };
    }
    const key = `${networkId.toLowerCase()}:${assetAddress.toLowerCase()}:${payerAddress.toLowerCase()}:${nonce.toLowerCase()}`;
    return this.#nonces.get(key) ?? { status: NonceStatus.UNUSED };
  }
}

export interface FacilitatorClientLike {
  getSettlement?(settlementId: string): Promise<{ status: SettlementState | string; txHash?: string | null; error?: string | null }>;
  isNonceUsed?(params: { network: string; asset: string; payer: string; nonce: string }): Promise<boolean>;
}

export interface FacilitatorSettlementProbeOptions {
  client?: FacilitatorClientLike;
  baseUrl?: string;
  fetch?: typeof globalThis.fetch;
}

export class FacilitatorSettlementProbe implements ISettlementProbe {
  readonly #client?: FacilitatorClientLike;
  readonly #baseUrl?: string;
  readonly #fetch: typeof globalThis.fetch;

  constructor(options?: FacilitatorSettlementProbeOptions) {
    this.#client = options?.client;
    this.#baseUrl = options?.baseUrl?.replace(/\/+$/, '');
    this.#fetch = options?.fetch ?? globalThis.fetch;
  }

  async probeSettlement(settlementId: string): Promise<SettlementProbeResult> {
    if (this.#client?.getSettlement) {
      try {
        const res = await this.#client.getSettlement(settlementId);
        return {
          status: (res.status as SettlementState) || SettlementState.UNKNOWN,
          txHash: res.txHash ?? null,
          error: res.error ?? null,
        };
      } catch (err: any) {
        if (err?.status === 404 || String(err?.message).includes('not found')) {
          return { status: SettlementState.FAILED, error: 'Settlement not found' };
        }
        return { status: SettlementState.UNKNOWN, error: String(err?.message || err) };
      }
    }

    if (this.#baseUrl) {
      try {
        const resp = await this.#fetch(`${this.#baseUrl}/v1/settlements/${encodeURIComponent(settlementId)}`);
        if (resp.status === 404) {
          return { status: SettlementState.FAILED, error: 'Settlement not found' };
        }
        if (!resp.ok) {
          return { status: SettlementState.UNKNOWN, error: `HTTP ${resp.status}` };
        }
        const data = (await resp.json()) as any;
        return {
          status: (data.status as SettlementState) || SettlementState.UNKNOWN,
          txHash: data.txHash || data.tx_hash || null,
          error: data.error || null,
        };
      } catch (err: any) {
        return { status: SettlementState.UNKNOWN, error: String(err?.message || err) };
      }
    }

    return { status: SettlementState.UNKNOWN, error: 'No client or baseUrl configured for Facilitator probe' };
  }

  async probeNonce(
    networkId: string,
    assetAddress: string,
    payerAddress: string,
    nonce: string,
  ): Promise<NonceProbeResult> {
    if (this.#client?.isNonceUsed) {
      try {
        const isUsed = await this.#client.isNonceUsed({
          network: networkId,
          asset: assetAddress,
          payer: payerAddress,
          nonce,
        });
        return { status: isUsed ? NonceStatus.USED : NonceStatus.UNUSED };
      } catch (err: any) {
        return { status: NonceStatus.UNKNOWN, detail: String(err?.message || err) };
      }
    }

    if (this.#baseUrl) {
      try {
        const query = new URLSearchParams({
          network: networkId,
          asset: assetAddress,
          payer: payerAddress,
          nonce,
        });
        const resp = await this.#fetch(`${this.#baseUrl}/v1/nonces/status?${query.toString()}`);
        if (!resp.ok) {
          return { status: NonceStatus.UNKNOWN, detail: `HTTP ${resp.status}` };
        }
        const data = (await resp.json()) as any;
        const status = data.used || data.status === 'USED' ? NonceStatus.USED : NonceStatus.UNUSED;
        return { status, txHash: data.txHash || data.tx_hash || null };
      } catch (err: any) {
        return { status: NonceStatus.UNKNOWN, detail: String(err?.message || err) };
      }
    }

    return { status: NonceStatus.UNKNOWN, detail: 'No client or baseUrl configured for Facilitator probe' };
  }
}

export enum BuyerReconciliationOutcome {
  COMMITTED = 'COMMITTED',
  RELEASED = 'RELEASED',
  HELD = 'HELD',
  SKIPPED_UNKNOWN = 'SKIPPED_UNKNOWN',
}

export class BuyerReconciliationReport {
  readonly intentId: string;
  readonly previousIntentStatus: PaymentIntentState;
  readonly newIntentStatus: PaymentIntentState;
  readonly ledgerState: BudgetLedgerState;
  readonly outcome: BuyerReconciliationOutcome;
  readonly reason: string;

  constructor(data: {
    intentId: string;
    previousIntentStatus: PaymentIntentState;
    newIntentStatus: PaymentIntentState;
    ledgerState: BudgetLedgerState;
    outcome: BuyerReconciliationOutcome;
    reason: string;
  }) {
    this.intentId = data.intentId;
    this.previousIntentStatus = data.previousIntentStatus;
    this.newIntentStatus = data.newIntentStatus;
    this.ledgerState = data.ledgerState;
    this.outcome = data.outcome;
    this.reason = data.reason;
    Object.freeze(this);
  }
}

export class BuyerReconciler {
  readonly #coordinator: BuyerStateCoordinator;
  readonly #probe: ISettlementProbe;
  readonly #clock: Clock;
  readonly safeBufferSeconds: number;
  readonly inFlightTimeoutSeconds: number;

  constructor(
    coordinator: BuyerStateCoordinator,
    probe: ISettlementProbe,
    options?: {
      clock?: Clock;
      safeBufferSeconds?: number;
      inFlightTimeoutSeconds?: number;
    },
  ) {
    this.#coordinator = coordinator;
    this.#probe = probe;
    this.#clock = options?.clock ?? (() => coordinator.getTime());
    this.safeBufferSeconds = options?.safeBufferSeconds ?? 60;
    this.inFlightTimeoutSeconds = options?.inFlightTimeoutSeconds ?? 30;
  }

  getTime(): number {
    return this.#clock();
  }

  async reconcileIntent(intentId: string): Promise<BuyerReconciliationReport> {
    const now = this.getTime();
    let record = this.#coordinator.getIntent(intentId);
    if (!record) {
      throw new Error(`Buyer intent '${intentId}' not found.`);
    }

    let prevStatus = record.status;
    const ledgerState = this.#coordinator.getLedgerState(intentId) || BudgetLedgerState.RELEASED;

    // Pre-check: If intent is still in SIGNATURE_SENT but timed out, transition to RECOVERY_HOLD
    if (prevStatus === PaymentIntentState.SIGNATURE_SENT) {
      if (now - record.updatedAt >= this.inFlightTimeoutSeconds) {
        this.#coordinator.holdIntent(intentId);
        record = this.#coordinator.getIntent(intentId)!;
        prevStatus = record.status;
      } else {
        return new BuyerReconciliationReport({
          intentId,
          previousIntentStatus: prevStatus,
          newIntentStatus: prevStatus,
          ledgerState,
          outcome: BuyerReconciliationOutcome.HELD,
          reason: 'In-flight dispatch still active; waiting for response',
        });
      }
    }

    if (record.status !== PaymentIntentState.RECOVERY_HOLD) {
      return new BuyerReconciliationReport({
        intentId,
        previousIntentStatus: prevStatus,
        newIntentStatus: record.status,
        ledgerState,
        outcome: BuyerReconciliationOutcome.HELD,
        reason: `Intent status '${record.status}' is not held for recovery`,
      });
    }

    if (!record.nonce) {
      return new BuyerReconciliationReport({
        intentId,
        previousIntentStatus: prevStatus,
        newIntentStatus: record.status,
        ledgerState,
        outcome: BuyerReconciliationOutcome.SKIPPED_UNKNOWN,
        reason: 'Intent has no recorded nonce',
      });
    }

    const probeRes = await this.#probe.probeNonce(
      record.networkId,
      record.assetAddress,
      record.payerAddress,
      record.nonce,
    );

    // Case 1: Nonce was confirmed used on-chain / Facilitator
    if (probeRes.status === NonceStatus.USED) {
      this.#coordinator.completeIntent(intentId);
      const updatedIntent = this.#coordinator.getIntent(intentId)!;
      const updatedLedger = this.#coordinator.getLedgerState(intentId) || BudgetLedgerState.COMMITTED;
      return new BuyerReconciliationReport({
        intentId,
        previousIntentStatus: prevStatus,
        newIntentStatus: updatedIntent.status,
        ledgerState: updatedLedger,
        outcome: BuyerReconciliationOutcome.COMMITTED,
        reason: 'Nonce was settled on-chain; quota permanently committed',
      });
    }

    // Case 2: Nonce is UNUSED (or CANCELED)
    if (probeRes.status === NonceStatus.UNUSED || probeRes.status === NonceStatus.CANCELED) {
      const validBefore = record.validBefore || 0;
      const safeExpiry = validBefore + this.safeBufferSeconds;

      if (now > safeExpiry) {
        // Authorization window safely expired and nonce unspent -> safe to release!
        this.#coordinator.reconcileRelease(
          intentId,
          `Nonce confirmed unspent and validBefore expired (${now} > ${safeExpiry})`,
        );
        const updatedIntent = this.#coordinator.getIntent(intentId)!;
        const updatedLedger = this.#coordinator.getLedgerState(intentId) || BudgetLedgerState.RELEASED;
        return new BuyerReconciliationReport({
          intentId,
          previousIntentStatus: prevStatus,
          newIntentStatus: updatedIntent.status,
          ledgerState: updatedLedger,
          outcome: BuyerReconciliationOutcome.RELEASED,
          reason: `Authorization expired (${now} > ${safeExpiry}) with unspent nonce; quota released`,
        });
      }

      // Anti-Double-Spend Guard: validBefore has NOT expired yet!
      return new BuyerReconciliationReport({
        intentId,
        previousIntentStatus: prevStatus,
        newIntentStatus: record.status,
        ledgerState,
        outcome: BuyerReconciliationOutcome.HELD,
        reason: `Authorization still within validBefore window (${now} <= ${safeExpiry}); preserving RESERVED`,
      });
    }

    // Case 3: Probe status is UNKNOWN (network error, timeout, RPC split) -> fail-closed
    return new BuyerReconciliationReport({
      intentId,
      previousIntentStatus: prevStatus,
      newIntentStatus: record.status,
      ledgerState,
      outcome: BuyerReconciliationOutcome.SKIPPED_UNKNOWN,
      reason: `Probe returned UNKNOWN (${probeRes.detail || 'no detail'}); fail-closed preserve RESERVED`,
    });
  }

  async reconcileAllHeld(): Promise<BuyerReconciliationReport[]> {
    const intents = this.#coordinator.listIntents([
      PaymentIntentState.RECOVERY_HOLD,
      PaymentIntentState.SIGNATURE_SENT,
    ]);
    const reports: BuyerReconciliationReport[] = [];
    for (const it of intents) {
      const rep = await this.reconcileIntent(it.intentId);
      reports.push(rep);
    }
    return reports;
  }
}
