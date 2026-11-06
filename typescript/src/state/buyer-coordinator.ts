/**
 * Buyer State Coordinator for AgentPay.
 *
 * Coordinates SQLite atomic transactions between:
 *   - Buyer Payment Intent (ap_buyer_intent)
 *   - Budget Reservation Ledger (ap_budget_ledger)
 *
 * Enforces:
 *   - Atomic two-phase reservation & commitment
 *   - CLAUDE.md Invariant: No release once signature is dispatched
 *   - Deterministic time injection via clock parameter
 */

import { randomUUID } from 'node:crypto';
import type { Database as DatabaseInstance } from 'better-sqlite3';
import {
  BudgetLedgerState,
  BuyerIntentRecord,
  PaymentIntentState,
} from '../core/state.js';
import type { Clock } from '../policy/interfaces.js';
import {
  IllegalStateTransitionError,
  SignatureSentReleaseForbiddenError,
} from './errors.js';
import {
  validateIntentTransition,
  validateLedgerTransition,
} from './guards.js';

export class BuyerStateCoordinator {
  readonly #db: DatabaseInstance;
  readonly #clock: Clock;

  constructor(db: DatabaseInstance, options?: { clock?: Clock }) {
    this.#db = db;
    this.#clock = options?.clock ?? (() => Math.floor(Date.now() / 1000));
  }

  getTime(): number {
    return this.#clock();
  }

  #rollbackQuietly(): void {
    try {
      if (this.#db.inTransaction) {
        this.#db.exec('ROLLBACK;');
      }
    } catch {
      // Ignore rollback errors
    }
  }

  createIntent(record: BuyerIntentRecord): void {
    const now = this.getTime();
    this.#db
      .prepare(`
        INSERT INTO ap_buyer_intent (
          intent_id, policy_id, idempotency_key, payer_address, payee_address,
          asset_address, network_id, amount_base_units, status, nonce,
          valid_after, valid_before, raw_signature, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
      `)
      .run(
        record.intentId,
        record.policyId,
        record.idempotencyKey,
        record.payerAddress.toLowerCase(),
        record.payeeAddress.toLowerCase(),
        record.assetAddress.toLowerCase(),
        record.networkId,
        record.amountBaseUnits,
        record.status,
        record.nonce,
        record.validAfter,
        record.validBefore,
        record.rawSignature,
        record.createdAt || now,
        record.updatedAt || now,
      );
  }

  reserveIntent(
    intentId: string,
    policyId: string,
    walletAddress: string,
    amountBaseUnits: bigint | number,
    ttlSeconds = 360,
  ): string {
    const now = this.getTime();
    const expiresAt = now + ttlSeconds;
    const reservationId = `res_${randomUUID().replace(/-/g, '')}`;

    this.#db.exec('BEGIN IMMEDIATE;');
    try {
      const row = this.#db
        .prepare('SELECT status FROM ap_buyer_intent WHERE intent_id = ?;')
        .get(intentId) as { status?: string } | undefined;

      if (!row || !row.status) {
        this.#db.exec('ROLLBACK;');
        throw new Error(`Buyer intent '${intentId}' not found.`);
      }

      const currentStatus = row.status as PaymentIntentState;
      validateIntentTransition(currentStatus, PaymentIntentState.PROCESSING, { intentId });

      this.#db
        .prepare(`
          INSERT INTO ap_budget_ledger (
            id, policy_id, wallet_address, intent_id, amount_base_units, state, created_at, expires_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, 'RESERVED', ?, ?, ?);
        `)
        .run(
          reservationId,
          policyId,
          walletAddress.toLowerCase(),
          intentId,
          typeof amountBaseUnits === 'bigint' ? amountBaseUnits : BigInt(amountBaseUnits),
          now,
          expiresAt,
          now,
        );

      this.#db
        .prepare(`
          UPDATE ap_buyer_intent
          SET status = 'PROCESSING', updated_at = ?
          WHERE intent_id = ?;
        `)
        .run(now, intentId);

      this.#db.exec('COMMIT;');
      return reservationId;
    } catch (exc) {
      this.#rollbackQuietly();
      throw exc;
    }
  }

  recordDispatch(
    intentId: string,
    rawSignature = '0xdefault_sig',
    nonce: string | null = null,
  ): void {
    const now = this.getTime();
    this.#db.exec('BEGIN IMMEDIATE;');
    try {
      const row = this.#db
        .prepare('SELECT status FROM ap_buyer_intent WHERE intent_id = ?;')
        .get(intentId) as { status?: string } | undefined;

      if (!row || !row.status) {
        this.#db.exec('ROLLBACK;');
        throw new Error(`Buyer intent '${intentId}' not found.`);
      }

      const currentStatus = row.status as PaymentIntentState;
      validateIntentTransition(currentStatus, PaymentIntentState.SIGNATURE_SENT, { intentId });

      const ledgerRow = this.#db
        .prepare('SELECT state FROM ap_budget_ledger WHERE intent_id = ?;')
        .get(intentId) as { state?: string } | undefined;

      if (!ledgerRow || ledgerRow.state !== BudgetLedgerState.RESERVED) {
        this.#db.exec('ROLLBACK;');
        throw new IllegalStateTransitionError(
          'BudgetLedger',
          ledgerRow?.state ?? 'NONE',
          BudgetLedgerState.RESERVED,
          'Cannot dispatch request without an active RESERVED quota.',
        );
      }

      this.#db
        .prepare(`
          UPDATE ap_buyer_intent
          SET status = 'SIGNATURE_SENT',
              raw_signature = COALESCE(?, raw_signature),
              nonce = COALESCE(?, nonce),
              updated_at = ?
          WHERE intent_id = ?;
        `)
        .run(rawSignature, nonce, now, intentId);

      this.#db.exec('COMMIT;');
    } catch (exc) {
      this.#rollbackQuietly();
      throw exc;
    }
  }

  completeIntent(intentId: string): void {
    const now = this.getTime();
    this.#db.exec('BEGIN IMMEDIATE;');
    try {
      const row = this.#db
        .prepare('SELECT status FROM ap_buyer_intent WHERE intent_id = ?;')
        .get(intentId) as { status?: string } | undefined;

      if (!row || !row.status) {
        this.#db.exec('ROLLBACK;');
        throw new Error(`Buyer intent '${intentId}' not found.`);
      }

      const currentStatus = row.status as PaymentIntentState;
      validateIntentTransition(currentStatus, PaymentIntentState.SUCCEEDED, { intentId });

      const ledgerRow = this.#db
        .prepare('SELECT state FROM ap_budget_ledger WHERE intent_id = ?;')
        .get(intentId) as { state?: string } | undefined;

      if (!ledgerRow || !ledgerRow.state) {
        this.#db.exec('ROLLBACK;');
        throw new Error(`Ledger entry for intent '${intentId}' not found.`);
      }

      const currentLedger = ledgerRow.state as BudgetLedgerState;
      validateLedgerTransition(currentLedger, BudgetLedgerState.COMMITTED);

      this.#db
        .prepare(`
          UPDATE ap_budget_ledger
          SET state = 'COMMITTED', updated_at = ?
          WHERE intent_id = ?;
        `)
        .run(now, intentId);

      this.#db
        .prepare(`
          UPDATE ap_buyer_intent
          SET status = 'SUCCEEDED', updated_at = ?
          WHERE intent_id = ?;
        `)
        .run(now, intentId);

      this.#db.exec('COMMIT;');
    } catch (exc) {
      this.#rollbackQuietly();
      throw exc;
    }
  }

  holdIntent(intentId: string, errorMessage?: string | null): void {
    const now = this.getTime();
    this.#db.exec('BEGIN IMMEDIATE;');
    try {
      const row = this.#db
        .prepare('SELECT status FROM ap_buyer_intent WHERE intent_id = ?;')
        .get(intentId) as { status?: string } | undefined;

      if (!row || !row.status) {
        this.#db.exec('ROLLBACK;');
        throw new Error(`Buyer intent '${intentId}' not found.`);
      }

      const currentStatus = row.status as PaymentIntentState;
      validateIntentTransition(currentStatus, PaymentIntentState.RECOVERY_HOLD, { intentId });

      const ledgerRow = this.#db
        .prepare('SELECT state FROM ap_budget_ledger WHERE intent_id = ?;')
        .get(intentId) as { state?: string } | undefined;

      if (ledgerRow && ledgerRow.state !== BudgetLedgerState.RESERVED) {
        this.#db.exec('ROLLBACK;');
        throw new IllegalStateTransitionError(
          'BudgetLedger',
          ledgerRow.state ?? 'NONE',
          BudgetLedgerState.RESERVED,
          'Ledger must remain RESERVED when intent enters RECOVERY_HOLD.',
        );
      }

      this.#db
        .prepare(`
          UPDATE ap_buyer_intent
          SET status = 'RECOVERY_HOLD', updated_at = ?
          WHERE intent_id = ?;
        `)
        .run(now, intentId);

      this.#db.exec('COMMIT;');
    } catch (exc) {
      this.#rollbackQuietly();
      throw exc;
    }
  }

  cancelIntent(intentId: string, reason = ''): void {
    const now = this.getTime();
    this.#db.exec('BEGIN IMMEDIATE;');
    try {
      const row = this.#db
        .prepare('SELECT status FROM ap_buyer_intent WHERE intent_id = ?;')
        .get(intentId) as { status?: string } | undefined;

      if (!row || !row.status) {
        this.#db.exec('ROLLBACK;');
        throw new Error(`Buyer intent '${intentId}' not found.`);
      }

      const currentStatus = row.status as PaymentIntentState;

      // Safety Guard: Once SIGNATURE_SENT or RECOVERY_HOLD, cannot cancel!
      if (
        currentStatus === PaymentIntentState.SIGNATURE_SENT ||
        currentStatus === PaymentIntentState.RECOVERY_HOLD
      ) {
        this.#db.exec('ROLLBACK;');
        throw new SignatureSentReleaseForbiddenError(intentId, currentStatus);
      }

      validateIntentTransition(currentStatus, PaymentIntentState.CANCELLED, { intentId });

      const ledgerRow = this.#db
        .prepare('SELECT state FROM ap_budget_ledger WHERE intent_id = ?;')
        .get(intentId) as { state?: string } | undefined;

      if (ledgerRow?.state) {
        const currentLedger = ledgerRow.state as BudgetLedgerState;
        validateLedgerTransition(currentLedger, BudgetLedgerState.RELEASED);
        this.#db
          .prepare(`
            UPDATE ap_budget_ledger
            SET state = 'RELEASED', updated_at = ?
            WHERE intent_id = ?;
          `)
          .run(now, intentId);
      }

      this.#db
        .prepare(`
          UPDATE ap_buyer_intent
          SET status = 'CANCELLED', updated_at = ?
          WHERE intent_id = ?;
        `)
        .run(now, intentId);

      this.#db.exec('COMMIT;');
    } catch (exc) {
      this.#rollbackQuietly();
      throw exc;
    }
  }

  reconcileRelease(intentId: string, reason = ''): void {
    const now = this.getTime();
    this.#db.exec('BEGIN IMMEDIATE;');
    try {
      const row = this.#db
        .prepare('SELECT status FROM ap_buyer_intent WHERE intent_id = ?;')
        .get(intentId) as { status?: string } | undefined;

      if (!row || !row.status) {
        this.#db.exec('ROLLBACK;');
        throw new Error(`Buyer intent '${intentId}' not found.`);
      }

      const currentStatus = row.status as PaymentIntentState;
      validateIntentTransition(currentStatus, PaymentIntentState.REJECTED, { intentId });

      this.#db
        .prepare(`
          UPDATE ap_budget_ledger
          SET state = 'RELEASED', updated_at = ?
          WHERE intent_id = ? AND state = 'RESERVED';
        `)
        .run(now, intentId);

      this.#db
        .prepare(`
          UPDATE ap_buyer_intent
          SET status = 'REJECTED', updated_at = ?
          WHERE intent_id = ?;
        `)
        .run(now, intentId);

      this.#db.exec('COMMIT;');
    } catch (exc) {
      this.#rollbackQuietly();
      throw exc;
    }
  }

  getIntent(intentId: string): BuyerIntentRecord | null {
    const row = this.#db
      .prepare(`
        SELECT intent_id, policy_id, idempotency_key, payer_address, payee_address,
               asset_address, network_id, amount_base_units, status, nonce,
               valid_after, valid_before, raw_signature, created_at, updated_at
        FROM ap_buyer_intent
        WHERE intent_id = ?;
      `)
      .get(intentId) as {
        intent_id: string;
        policy_id: string;
        idempotency_key: string;
        payer_address: string;
        payee_address: string;
        asset_address: string;
        network_id: string;
        amount_base_units: bigint | number;
        status: string;
        nonce?: string | null;
        valid_after?: bigint | number | null;
        valid_before?: bigint | number | null;
        raw_signature?: string | null;
        created_at: bigint | number;
        updated_at: bigint | number;
      } | undefined;

    if (!row) {
      return null;
    }

    return new BuyerIntentRecord({
      intentId: row.intent_id,
      policyId: row.policy_id,
      idempotencyKey: row.idempotency_key,
      payerAddress: row.payer_address,
      payeeAddress: row.payee_address,
      assetAddress: row.asset_address,
      networkId: row.network_id,
      amountBaseUnits: row.amount_base_units,
      status: row.status as PaymentIntentState,
      nonce: row.nonce,
      validAfter: row.valid_after != null ? Number(row.valid_after) : null,
      validBefore: row.valid_before != null ? Number(row.valid_before) : null,
      rawSignature: row.raw_signature,
      createdAt: Number(row.created_at),
      updatedAt: Number(row.updated_at),
    });
  }

  getLedgerState(intentId: string): BudgetLedgerState | null {
    const row = this.#db
      .prepare('SELECT state FROM ap_budget_ledger WHERE intent_id = ?;')
      .get(intentId) as { state?: string } | undefined;

    return row?.state ? (row.state as BudgetLedgerState) : null;
  }

  listIntents(states?: PaymentIntentState[]): BuyerIntentRecord[] {
    let rows: any[];
    if (states && states.length > 0) {
      const placeholders = states.map(() => '?').join(',');
      rows = this.#db
        .prepare(`
          SELECT intent_id, policy_id, idempotency_key, payer_address, payee_address,
                 asset_address, network_id, amount_base_units, status, nonce,
                 valid_after, valid_before, raw_signature, created_at, updated_at
          FROM ap_buyer_intent
          WHERE status IN (${placeholders})
          ORDER BY created_at ASC;
        `)
        .all(...states);
    } else {
      rows = this.#db
        .prepare(`
          SELECT intent_id, policy_id, idempotency_key, payer_address, payee_address,
                 asset_address, network_id, amount_base_units, status, nonce,
                 valid_after, valid_before, raw_signature, created_at, updated_at
          FROM ap_buyer_intent
          ORDER BY created_at ASC;
        `)
        .all();
    }

    return rows.map(
      (row) =>
        new BuyerIntentRecord({
          intentId: row.intent_id,
          policyId: row.policy_id,
          idempotencyKey: row.idempotency_key,
          payerAddress: row.payer_address,
          payeeAddress: row.payee_address,
          assetAddress: row.asset_address,
          networkId: row.network_id,
          amountBaseUnits: row.amount_base_units,
          status: row.status as PaymentIntentState,
          nonce: row.nonce,
          validAfter: row.valid_after != null ? Number(row.valid_after) : null,
          validBefore: row.valid_before != null ? Number(row.valid_before) : null,
          rawSignature: row.raw_signature,
          createdAt: Number(row.created_at),
          updatedAt: Number(row.updated_at),
        }),
    );
  }
}
