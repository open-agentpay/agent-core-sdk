/**
 * Database connection utilities and connection factory for AgentPay.
 *
 * Enforces:
 * - Foreign key constraint enforcement on EVERY connection (PRAGMA foreign_keys = ON)
 * - WAL journal mode for concurrent read/write isolation (PRAGMA journal_mode = WAL)
 * - Busy timeout configuration to wait during concurrent write contention
 * - Canonical buyer schema initialization helper
 * - defaultSafeIntegers(true) for 64-bit BigInt precision
 */

import Database, { type Database as DatabaseInstance } from 'better-sqlite3';

export function createBuyerConnection(
  dbPath: string,
  busyTimeoutMs = 5000,
): DatabaseInstance {
  const db = new Database(dbPath, {
    timeout: busyTimeoutMs,
  });

  db.defaultSafeIntegers(true);
  db.pragma('foreign_keys = ON');
  db.pragma(`busy_timeout = ${busyTimeoutMs}`);

  if (dbPath !== ':memory:') {
    db.pragma('journal_mode = WAL');
  }

  return db;
}

export function initBuyerDatabase(db: DatabaseInstance): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS ap_policy (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        wallet_address TEXT NOT NULL,
        max_per_tx_base_units INTEGER NOT NULL CHECK (max_per_tx_base_units > 0),
        rolling_budget_24h_base_units INTEGER NOT NULL CHECK (rolling_budget_24h_base_units > 0),
        lifetime_budget_base_units INTEGER CHECK (lifetime_budget_base_units > 0),
        whitelist_mode TEXT NOT NULL DEFAULT 'simple' CHECK (whitelist_mode IN ('strict', 'simple')),
        whitelist_payees_json TEXT NOT NULL DEFAULT '[]',
        whitelist_assets_json TEXT NOT NULL DEFAULT '[]',
        whitelist_networks_json TEXT NOT NULL DEFAULT '[]',
        whitelist_domains_json TEXT NOT NULL DEFAULT '[]',
        circuit_max_rpm INTEGER NOT NULL DEFAULT 15,
        circuit_consecutive_failures INTEGER NOT NULL DEFAULT 5,
        circuit_cooldown_seconds INTEGER NOT NULL DEFAULT 300,
        consecutive_failures INTEGER NOT NULL DEFAULT 0,
        breaker_state TEXT NOT NULL DEFAULT 'CLOSED' CHECK (breaker_state IN ('CLOSED', 'OPEN', 'HALF_OPEN')),
        tripped_at INTEGER,
        is_frozen INTEGER NOT NULL DEFAULT 0 CHECK (is_frozen IN (0, 1)),
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS ap_budget_ledger (
        id TEXT PRIMARY KEY,
        policy_id TEXT NOT NULL REFERENCES ap_policy(id),
        wallet_address TEXT NOT NULL,
        intent_id TEXT NOT NULL UNIQUE,
        amount_base_units INTEGER NOT NULL CHECK (amount_base_units > 0 AND typeof(amount_base_units) = 'integer'),
        state TEXT NOT NULL CHECK (state IN ('RESERVED', 'COMMITTED', 'RELEASED')),
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS ap_buyer_intent (
        intent_id TEXT PRIMARY KEY,
        policy_id TEXT NOT NULL REFERENCES ap_policy(id),
        idempotency_key TEXT NOT NULL,
        payer_address TEXT NOT NULL,
        payee_address TEXT NOT NULL,
        asset_address TEXT NOT NULL,
        network_id TEXT NOT NULL,
        amount_base_units INTEGER NOT NULL CHECK (amount_base_units > 0 AND typeof(amount_base_units) = 'integer'),
        status TEXT NOT NULL CHECK (status IN ('CREATED', 'AUTHORIZED', 'PROCESSING', 'SIGNATURE_SENT', 'COMPLETED', 'SUCCEEDED', 'REJECTED', 'EXPIRED', 'CANCELLED', 'RECOVERY_HOLD')),
        nonce TEXT,
        valid_after INTEGER,
        valid_before INTEGER,
        raw_signature TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_budget_rolling_sum 
    ON ap_budget_ledger (policy_id, state, created_at, expires_at);

    CREATE UNIQUE INDEX IF NOT EXISTS uq_buyer_intent_idempotency 
    ON ap_buyer_intent (payer_address, idempotency_key);
  `);
}
