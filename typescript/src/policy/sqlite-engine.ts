/**
 * SQLite-backed Policy Engine implementation.
 *
 * Enforces 24-hour true rolling budget, atomic slot reservation, lifetime limits,
 * circuit breaker (RPM rate limiting, consecutive failures, half-open test probes),
 * and strict two-phase commit/release protocol within BEGIN IMMEDIATE transactions.
 */

import { randomUUID } from 'node:crypto';
import type { Database as DatabaseInstance } from 'better-sqlite3';
import { createBuyerConnection, initBuyerDatabase } from './db.js';
import { PolicyErrorCode, PolicyViolationError } from './errors.js';
import { evaluateMeteredRules, evaluateStaticRules } from './evaluator.js';
import type { Clock, IMeteredPolicyEngine, ReserveParams } from './interfaces.js';
import {
  BreakerState,
  PaymentRequest,
  type PolicyConfig,
  type PolicyDecision,
  ReservationToken,
  SQLITE_MAX_INT,
  validatePositiveBigInt,
} from './models.js';

export class SQLitePolicyEngine implements IMeteredPolicyEngine {
  readonly #db: DatabaseInstance;
  readonly #config: PolicyConfig;
  readonly #clock: Clock;
  #consecutiveFailures = 0;

  constructor(db: DatabaseInstance, config: PolicyConfig, clock?: Clock) {
    this.#db = db;
    this.#config = config;
    this.#clock = clock ?? (() => Math.floor(Date.now() / 1000));
    this.#syncPolicyRecord();
  }

  /**
   * Create an in-memory SQLitePolicyEngine with the buyer schema initialized.
   */
  static createInMemory(config: PolicyConfig, clock?: Clock): SQLitePolicyEngine {
    const db = createBuyerConnection(':memory:');
    initBuyerDatabase(db);
    return new SQLitePolicyEngine(db, config, clock);
  }

  #syncPolicyRecord(): void {
    const now = this.#clock();
    const cfg = this.#config;

    const insertStmt = this.#db.prepare(`
      INSERT INTO ap_policy (
        id, name, wallet_address, max_per_tx_base_units,
        rolling_budget_24h_base_units, lifetime_budget_base_units,
        whitelist_mode,
        whitelist_payees_json, whitelist_assets_json,
        whitelist_networks_json, whitelist_domains_json,
        circuit_max_rpm, circuit_consecutive_failures,
        circuit_cooldown_seconds, consecutive_failures, breaker_state, tripped_at,
        is_frozen, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        name = excluded.name,
        wallet_address = excluded.wallet_address,
        max_per_tx_base_units = excluded.max_per_tx_base_units,
        rolling_budget_24h_base_units = excluded.rolling_budget_24h_base_units,
        lifetime_budget_base_units = excluded.lifetime_budget_base_units,
        whitelist_mode = excluded.whitelist_mode,
        whitelist_payees_json = excluded.whitelist_payees_json,
        whitelist_assets_json = excluded.whitelist_assets_json,
        whitelist_networks_json = excluded.whitelist_networks_json,
        whitelist_domains_json = excluded.whitelist_domains_json,
        circuit_max_rpm = excluded.circuit_max_rpm,
        circuit_consecutive_failures = excluded.circuit_consecutive_failures,
        circuit_cooldown_seconds = excluded.circuit_cooldown_seconds,
        is_frozen = MAX(ap_policy.is_frozen, excluded.is_frozen),
        updated_at = excluded.updated_at;
    `);

    insertStmt.run(
      cfg.id,
      cfg.name,
      cfg.walletAddress,
      cfg.maxPerTxBaseUnits,
      cfg.rollingBudget24hBaseUnits,
      cfg.lifetimeBudgetBaseUnits,
      cfg.whitelistMode,
      JSON.stringify(Array.from(cfg.whitelistPayees).sort()),
      JSON.stringify(Array.from(cfg.whitelistAssets).sort()),
      JSON.stringify(Array.from(cfg.whitelistNetworks).sort()),
      JSON.stringify(Array.from(cfg.whitelistDomains).sort()),
      cfg.circuitMaxRpm,
      cfg.circuitConsecutiveFailures,
      cfg.circuitCooldownSeconds,
      cfg.breakerState,
      cfg.trippedAt,
      cfg.isFrozen ? 1 : 0,
      cfg.createdAt || now,
      now,
    );

    const row = this.#db.prepare('SELECT consecutive_failures FROM ap_policy WHERE id = ?').get(cfg.id) as {
      consecutive_failures?: bigint | number;
    } | undefined;
    if (row?.consecutive_failures !== undefined) {
      this.#consecutiveFailures = Number(row.consecutive_failures);
    }
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

  #queryLifetimeSpent(nowSeconds: number): bigint {
    const row = this.#db
      .prepare(`
        SELECT COALESCE(SUM(amount_base_units), 0) AS val
        FROM ap_budget_ledger
        WHERE policy_id = ?
          AND (
            state = 'COMMITTED'
            OR
            (state = 'RESERVED' AND expires_at >= ?)
          );
      `)
      .get(this.#config.id, nowSeconds) as { val?: bigint | number } | undefined;
    return row?.val !== undefined ? BigInt(row.val) : 0n;
  }

  #queryRollingUsage(nowSeconds: number): bigint {
    const row = this.#db
      .prepare(`
        SELECT COALESCE(SUM(amount_base_units), 0) AS val
        FROM ap_budget_ledger
        WHERE policy_id = ?
          AND (
            (state = 'COMMITTED' AND created_at >= ? - 86400)
            OR
            (state = 'RESERVED' AND expires_at >= ?)
          );
      `)
      .get(this.#config.id, nowSeconds, nowSeconds) as { val?: bigint | number } | undefined;
    return row?.val !== undefined ? BigInt(row.val) : 0n;
  }

  #queryRequestsInLast60s(nowSeconds: number): number {
    const row = this.#db
      .prepare(`
        SELECT COUNT(*) AS count
        FROM ap_budget_ledger
        WHERE policy_id = ? AND created_at >= ? - 60;
      `)
      .get(this.#config.id, nowSeconds) as { count?: bigint | number } | undefined;
    return row?.count !== undefined ? Number(row.count) : 0;
  }

  #queryActiveProbeCount(nowSeconds: number): number {
    const row = this.#db
      .prepare(`
        SELECT COUNT(*) AS count
        FROM ap_budget_ledger
        WHERE policy_id = ? AND state = 'RESERVED' AND expires_at >= ?;
      `)
      .get(this.#config.id, nowSeconds) as { count?: bigint | number } | undefined;
    return row?.count !== undefined ? Number(row.count) : 0;
  }

  #gate(now: number): PolicyErrorCode | null {
    const row = this.#db
      .prepare('SELECT is_frozen, breaker_state, tripped_at FROM ap_policy WHERE id = ?;')
      .get(this.#config.id) as {
        is_frozen?: bigint | number;
        breaker_state?: string;
        tripped_at?: bigint | number | null;
      } | undefined;

    const isFrozen = row ? Number(row.is_frozen) === 1 : this.#config.isFrozen;
    if (isFrozen) {
      return PolicyErrorCode.POLICY_FROZEN;
    }

    let state = (row?.breaker_state as BreakerState) || BreakerState.CLOSED;
    const trippedAt = row?.tripped_at != null ? Number(row.tripped_at) : null;

    if (
      state === BreakerState.OPEN &&
      trippedAt !== null &&
      now >= trippedAt + this.#config.circuitCooldownSeconds
    ) {
      state = BreakerState.HALF_OPEN;
      this.#db
        .prepare("UPDATE ap_policy SET breaker_state = 'HALF_OPEN', updated_at = ? WHERE id = ?;")
        .run(now, this.#config.id);
    }

    if (state === BreakerState.OPEN) {
      return PolicyErrorCode.CIRCUIT_BREAKER_OPEN;
    }
    if (state === BreakerState.HALF_OPEN && this.#queryActiveProbeCount(now) >= 1) {
      return PolicyErrorCode.CIRCUIT_BREAKER_OPEN;
    }

    if (this.#queryRequestsInLast60s(now) >= this.#config.circuitMaxRpm) {
      this.#db
        .prepare("UPDATE ap_policy SET breaker_state = 'OPEN', tripped_at = ?, updated_at = ? WHERE id = ?;")
        .run(now, now, this.#config.id);
      return PolicyErrorCode.CIRCUIT_BREAKER_OPEN;
    }

    return null;
  }

  getAvailableRollingBudget(): bigint {
    const now = this.#clock();
    const usage = this.#queryRollingUsage(now);
    const diff = this.#config.rollingBudget24hBaseUnits - usage;
    return diff > 0n ? diff : 0n;
  }

  getBreakerState(): BreakerState {
    const now = this.#clock();
    const row = this.#db
      .prepare('SELECT breaker_state, tripped_at FROM ap_policy WHERE id = ?;')
      .get(this.#config.id) as {
        breaker_state?: string;
        tripped_at?: bigint | number | null;
      } | undefined;

    if (!row) {
      return BreakerState.CLOSED;
    }

    const current = (row.breaker_state as BreakerState) || BreakerState.CLOSED;
    const trippedAt = row.tripped_at != null ? Number(row.tripped_at) : null;

    if (
      current === BreakerState.OPEN &&
      trippedAt !== null &&
      now >= trippedAt + this.#config.circuitCooldownSeconds
    ) {
      this.#db
        .prepare("UPDATE ap_policy SET breaker_state = 'HALF_OPEN', updated_at = ? WHERE id = ?;")
        .run(now, this.#config.id);
      return BreakerState.HALF_OPEN;
    }

    return current;
  }

  recordFailure(reason = ''): void {
    const now = this.#clock();
    const current = this.getBreakerState();

    const row = this.#db
      .prepare('SELECT consecutive_failures, circuit_consecutive_failures FROM ap_policy WHERE id = ?;')
      .get(this.#config.id) as {
        consecutive_failures?: bigint | number;
        circuit_consecutive_failures?: bigint | number;
      } | undefined;

    const currFails = row?.consecutive_failures != null ? Number(row.consecutive_failures) : this.#consecutiveFailures;
    const threshold =
      row?.circuit_consecutive_failures != null
        ? Number(row.circuit_consecutive_failures)
        : this.#config.circuitConsecutiveFailures;

    const newFails = currFails + 1;
    this.#consecutiveFailures = newFails;

    const shouldTrip = current === BreakerState.HALF_OPEN || newFails >= threshold;
    if (shouldTrip) {
      this.#db
        .prepare(
          "UPDATE ap_policy SET consecutive_failures = ?, breaker_state = 'OPEN', tripped_at = ?, updated_at = ? WHERE id = ?;",
        )
        .run(newFails, now, now, this.#config.id);
    } else {
      this.#db
        .prepare('UPDATE ap_policy SET consecutive_failures = ?, updated_at = ? WHERE id = ?;')
        .run(newFails, now, this.#config.id);
    }
  }

  resetBreaker(): void {
    const now = this.#clock();
    this.#consecutiveFailures = 0;
    this.#db
      .prepare(
        "UPDATE ap_policy SET breaker_state = 'CLOSED', consecutive_failures = 0, tripped_at = NULL, updated_at = ? WHERE id = ?;",
      )
      .run(now, this.#config.id);
  }

  reserve(params: ReserveParams): PolicyDecision {
    const now = this.#clock();

    try {
      this.#db.exec('BEGIN IMMEDIATE;');

      // 1. Gate check (POLICY_FROZEN -> CIRCUIT_BREAKER_OPEN)
      const gateErr = this.#gate(now);
      if (gateErr) {
        this.#db.exec('COMMIT;');
        return { approved: false, errorCode: gateErr };
      }

      // 2. Amount format validation
      let amountBig: bigint;
      try {
        amountBig = validatePositiveBigInt(params.amount, 'amount');
      } catch {
        this.#db.exec('COMMIT;');
        return { approved: false, errorCode: PolicyErrorCode.INVALID_AMOUNT_FORMAT };
      }

      // 3. Request parameters validation
      let req: PaymentRequest;
      try {
        req = new PaymentRequest({
          intentId: params.intentId,
          amount: amountBig,
          payee: params.payee,
          asset: params.asset,
          network: params.network,
          domain: params.domain,
          ttlSeconds: params.ttlSeconds,
        });
      } catch {
        this.#db.exec('COMMIT;');
        return { approved: false, errorCode: PolicyErrorCode.INVALID_REQUEST };
      }

      // 4-6. Static rules (Whitelist -> Single Cap -> Lifetime)
      const lifetimeSpent = this.#queryLifetimeSpent(now);
      const staticRes = evaluateStaticRules(this.#config, req, lifetimeSpent);
      if (!staticRes.passed) {
        this.#db.exec('COMMIT;');
        return { approved: false, errorCode: staticRes.errorCode };
      }

      // 7. 24h Rolling Budget
      const rollingUsage = this.#queryRollingUsage(now);
      const available = this.#config.rollingBudget24hBaseUnits - rollingUsage;
      if (available < req.amount) {
        this.#db.exec('COMMIT;');
        return { approved: false, errorCode: PolicyErrorCode.DAILY_BUDGET_EXCEEDED };
      }

      // 8. Insert reservation slot
      const reservationId = `res_${randomUUID().replace(/-/g, '')}`;
      const expiresAt = now + req.ttlSeconds;

      this.#db
        .prepare(`
          INSERT INTO ap_budget_ledger (
            id, policy_id, wallet_address, intent_id,
            amount_base_units, state, created_at, expires_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, 'RESERVED', ?, ?, ?);
        `)
        .run(
          reservationId,
          this.#config.id,
          this.#config.walletAddress,
          req.intentId,
          req.amount,
          now,
          expiresAt,
          now,
        );

      this.#db.exec('COMMIT;');

      const token = new ReservationToken({
        reservationId,
        intentId: req.intentId,
        policyId: this.#config.id,
        amount: req.amount,
        expiresAt,
        createdAt: now,
      });

      return {
        approved: true,
        reservation: token,
        availableAfter: available - req.amount,
      };
    } catch (exc: any) {
      this.#rollbackQuietly();
      if (exc?.code === 'SQLITE_CONSTRAINT' || String(exc?.message).includes('UNIQUE')) {
        return { approved: false, errorCode: PolicyErrorCode.DUPLICATE_INTENT };
      }
      return { approved: false, errorCode: PolicyErrorCode.POLICY_SYSTEM_ERROR };
    }
  }

  commit(intentId: string): void {
    const now = this.#clock();
    this.#db.exec('BEGIN IMMEDIATE;');

    try {
      const row = this.#db
        .prepare('SELECT state, expires_at FROM ap_budget_ledger WHERE intent_id = ?;')
        .get(intentId) as { state?: string; expires_at?: bigint | number } | undefined;

      if (!row) {
        this.#db.exec('ROLLBACK;');
        return;
      }

      const state = row.state;
      const expiresAt = row.expires_at != null ? Number(row.expires_at) : 0;

      if (state === 'COMMITTED') {
        this.#db.exec('ROLLBACK;');
        return;
      }

      if (now > expiresAt) {
        this.#db.exec('ROLLBACK;');
        throw new PolicyViolationError(
          PolicyErrorCode.RESERVATION_EXPIRED,
          `Reservation for intent ${intentId} expired at ${expiresAt} (current: ${now})`,
        );
      }

      this.#db
        .prepare(`
          UPDATE ap_budget_ledger
          SET state = 'COMMITTED', updated_at = ?
          WHERE intent_id = ? AND state = 'RESERVED';
        `)
        .run(now, intentId);

      this.#consecutiveFailures = 0;
      this.#db
        .prepare(`
          UPDATE ap_policy
          SET consecutive_failures = 0,
              breaker_state = CASE WHEN breaker_state = 'HALF_OPEN' THEN 'CLOSED' ELSE breaker_state END,
              tripped_at = CASE WHEN breaker_state = 'HALF_OPEN' THEN NULL ELSE tripped_at END,
              updated_at = ?
          WHERE id = ?;
        `)
        .run(now, this.#config.id);

      this.#db.exec('COMMIT;');
    } catch (exc) {
      this.#rollbackQuietly();
      throw exc;
    }
  }

  release(intentId: string, reason?: string): void {
    const now = this.#clock();
    this.#db.exec('BEGIN IMMEDIATE;');

    try {
      const row = this.#db
        .prepare('SELECT state FROM ap_budget_ledger WHERE intent_id = ?;')
        .get(intentId) as { state?: string } | undefined;

      if (!row) {
        this.#db.exec('ROLLBACK;');
        return;
      }

      if (row.state === 'COMMITTED') {
        this.#db.exec('ROLLBACK;');
        throw new PolicyViolationError(
          PolicyErrorCode.RESERVATION_ALREADY_FINALIZED,
          `Cannot release intent ${intentId}: already COMMITTED`,
        );
      }

      if (row.state === 'RELEASED') {
        this.#db.exec('ROLLBACK;');
        return;
      }

      this.#db
        .prepare(`
          UPDATE ap_budget_ledger
          SET state = 'RELEASED', updated_at = ?
          WHERE intent_id = ? AND state = 'RESERVED';
        `)
        .run(now, intentId);

      this.#db.exec('COMMIT;');
    } catch (exc) {
      this.#rollbackQuietly();
      throw exc;
    }
  }

  reserveMetered(
    intentId: string,
    estimatedAmount: bigint | number | string,
    domain?: string | null,
    ttlSeconds = 60,
  ): PolicyDecision {
    const now = this.#clock();

    try {
      this.#db.exec('BEGIN IMMEDIATE;');

      let err = this.#gate(now);
      let amountBig: bigint = 0n;

      if (!err) {
        try {
          amountBig = validatePositiveBigInt(estimatedAmount, 'estimatedAmount');
        } catch {
          err = PolicyErrorCode.INVALID_AMOUNT_FORMAT;
        }
      }

      if (!err) {
        if (
          !intentId ||
          typeof intentId !== 'string' ||
          !intentId.trim() ||
          typeof ttlSeconds !== 'number' ||
          !Number.isInteger(ttlSeconds) ||
          ttlSeconds <= 0 ||
          ttlSeconds > 86400 ||
          (domain !== undefined && domain !== null && typeof domain !== 'string')
        ) {
          err = PolicyErrorCode.INVALID_REQUEST;
        }
      }

      if (!err) {
        const lifetimeSpent = this.#queryLifetimeSpent(now);
        const res = evaluateMeteredRules(this.#config, amountBig, domain, lifetimeSpent);
        if (!res.passed) {
          err = res.errorCode ?? PolicyErrorCode.POLICY_SYSTEM_ERROR;
        }
      }

      let available = 0n;
      if (!err) {
        const rollingUsage = this.#queryRollingUsage(now);
        available = this.#config.rollingBudget24hBaseUnits - rollingUsage;
        if (available < amountBig) {
          err = PolicyErrorCode.DAILY_BUDGET_EXCEEDED;
        }
      }

      if (err) {
        this.#db.exec('COMMIT;');
        return { approved: false, errorCode: err };
      }

      const reservationId = `res_${randomUUID().replace(/-/g, '')}`;
      const expiresAt = now + ttlSeconds;

      this.#db
        .prepare(`
          INSERT INTO ap_budget_ledger (
            id, policy_id, wallet_address, intent_id,
            amount_base_units, state, created_at, expires_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, 'RESERVED', ?, ?, ?);
        `)
        .run(
          reservationId,
          this.#config.id,
          this.#config.walletAddress,
          intentId,
          amountBig,
          now,
          expiresAt,
          now,
        );

      this.#db.exec('COMMIT;');

      return {
        approved: true,
        reservation: new ReservationToken({
          reservationId,
          intentId,
          policyId: this.#config.id,
          amount: amountBig,
          expiresAt,
          createdAt: now,
        }),
        availableAfter: available - amountBig,
      };
    } catch (exc: any) {
      this.#rollbackQuietly();
      if (exc?.code === 'SQLITE_CONSTRAINT' || String(exc?.message).includes('UNIQUE')) {
        return { approved: false, errorCode: PolicyErrorCode.DUPLICATE_INTENT };
      }
      return { approved: false, errorCode: PolicyErrorCode.POLICY_SYSTEM_ERROR };
    }
  }

  settleMetered(intentId: string, actualAmount?: bigint | number | null): void {
    let normActual: bigint | null = null;
    if (actualAmount !== undefined && actualAmount !== null) {
      try {
        normActual = validatePositiveBigInt(actualAmount, 'actualAmount');
      } catch {
        normActual = null;
      }
    }

    const now = this.#clock();
    this.#db.exec('BEGIN IMMEDIATE;');

    try {
      const info = this.#db
        .prepare(`
          UPDATE ap_budget_ledger
          SET state = 'COMMITTED',
              amount_base_units = COALESCE(?, amount_base_units),
              updated_at = ?
          WHERE intent_id = ? AND state = 'RESERVED';
        `)
        .run(normActual, now, intentId);

      if (info.changes > 0) {
        this.#consecutiveFailures = 0;
        this.#db
          .prepare(`
            UPDATE ap_policy
            SET consecutive_failures = 0,
                breaker_state = CASE WHEN breaker_state = 'HALF_OPEN' THEN 'CLOSED' ELSE breaker_state END,
                tripped_at = CASE WHEN breaker_state = 'HALF_OPEN' THEN NULL ELSE tripped_at END,
                updated_at = ?
            WHERE id = ?;
          `)
          .run(now, this.#config.id);
      }

      this.#db.exec('COMMIT;');
    } catch (exc) {
      this.#rollbackQuietly();
      throw exc;
    }
  }
}
