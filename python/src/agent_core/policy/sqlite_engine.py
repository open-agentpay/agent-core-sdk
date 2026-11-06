"""
SQLite-backed Policy Engine implementation.

Enforces 24-hour true rolling budget, atomic slot reservation, lifetime limits,
circuit breaker (RPM rate limiting, consecutive failures, half-open test probes),
and strict two-phase commit/release protocol within BEGIN IMMEDIATE transactions.

References:
    - specs/policy-engine-spec.md §3, §4.1, §4.2, §5 (Precedence, Reservation, Circuit Breaker)
    - specs/domain-model.md §2.1 (Mathematical Invariant P0-6)
    - infra/sqlite/buyer-schema.sql (ap_policy, ap_budget_ledger)
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
import uuid
from collections.abc import Callable

from pydantic import ValidationError

from agent_core.policy.db import create_buyer_connection, init_buyer_database
from agent_core.policy.errors import PolicyErrorCode, PolicyViolationError
from agent_core.policy.evaluator import evaluate_metered_rules, evaluate_static_rules
from agent_core.policy.interfaces import IPolicyEngine
from agent_core.policy.models import (
    SQLITE_MAX_INT,
    BreakerState,
    PaymentRequest,
    PolicyConfig,
    PolicyDecision,
    ReservationToken,
    _validate_positive_int,
)


class SQLitePolicyEngine(IPolicyEngine):
    """
    SQLite-backed financial firewall, budget reservation, and circuit breaker engine.

    All reservations execute under ``BEGIN IMMEDIATE`` transactions to guarantee
    process-level exclusivity and prevent concurrent overspend races.
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        config: PolicyConfig,
        clock: Callable[[], int] | None = None,
    ) -> None:
        """
        Initialize the SQLite policy engine.

        Args:
            conn: An open SQLite connection with schema initialized.
            config: The policy configuration instance.
            clock: Optional clock callable returning Unix seconds (defaults to time.time).
        """
        self._conn = conn
        self._config = config
        self._clock = clock if clock is not None else (lambda: int(time.time()))
        self._consecutive_failures = 0
        self._sync_policy_record()

    @classmethod
    def create_in_memory(
        cls,
        config: PolicyConfig,
        clock: Callable[[], int] | None = None,
    ) -> SQLitePolicyEngine:
        """
        Create an in-memory SQLitePolicyEngine with the buyer schema initialized.

        Args:
            config: The policy configuration instance.
            clock: Optional clock callable returning Unix seconds (defaults to time.time).

        Returns:
            Initialized in-memory SQLitePolicyEngine instance.
        """
        conn = create_buyer_connection(":memory:")
        init_buyer_database(conn)
        return cls(conn=conn, config=config, clock=clock)

    def _sync_policy_record(self) -> None:
        """
        Upsert the policy configuration into the ap_policy table.
        Preserves existing is_frozen, breaker_state, and tripped_at from DB
        so a restart does not overwrite operator actions (P1-2, P1-3).
        """
        now = self._clock()
        cfg = self._config
        with self._conn:
            cursor = self._conn.cursor()
            cursor.execute("PRAGMA table_info(ap_policy);")
            cols = {row[1] for row in cursor.fetchall()}
            if "consecutive_failures" not in cols:
                try:
                    cursor.execute("ALTER TABLE ap_policy ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0;")
                except sqlite3.OperationalError:
                    # Column already added by concurrent thread or schema init
                    pass
            if "whitelist_mode" not in cols:
                try:
                    cursor.execute(
                        "ALTER TABLE ap_policy ADD COLUMN whitelist_mode TEXT NOT NULL DEFAULT 'simple' "
                        "CHECK (whitelist_mode IN ('strict', 'simple'));"
                    )
                except sqlite3.OperationalError:
                    pass
            self._conn.execute(
                """
                INSERT INTO ap_policy (
                    id, name, wallet_address, max_per_tx_base_units,
                    rolling_budget_24h_base_units, lifetime_budget_base_units,
                    whitelist_mode,
                    whitelist_payees_json, whitelist_assets_json,
                    whitelist_networks_json, whitelist_domains_json,
                    circuit_max_rpm, circuit_consecutive_failures,
                    circuit_cooldown_seconds, breaker_state, tripped_at,
                    is_frozen, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    -- If DB already has is_frozen=1 or custom breaker state, preserve it (P1-2)
                    is_frozen = MAX(ap_policy.is_frozen, excluded.is_frozen),
                    updated_at = excluded.updated_at;
                """,
                (
                    cfg.id,
                    cfg.name,
                    cfg.wallet_address,
                    cfg.max_per_tx_base_units,
                    cfg.rolling_budget_24h_base_units,
                    cfg.lifetime_budget_base_units,
                    cfg.whitelist_mode.value,
                    json.dumps(sorted(cfg.whitelist_payees)),
                    json.dumps(sorted(cfg.whitelist_assets)),
                    json.dumps(sorted(cfg.whitelist_networks)),
                    json.dumps(sorted(cfg.whitelist_domains)),
                    cfg.circuit_max_rpm,
                    cfg.circuit_consecutive_failures,
                    cfg.circuit_cooldown_seconds,
                    cfg.breaker_state.value,
                    cfg.tripped_at,
                    1 if cfg.is_frozen else 0,
                    cfg.created_at or now,
                    now,
                ),
            )
            cursor.execute("SELECT consecutive_failures FROM ap_policy WHERE id = ?;", (cfg.id,))
            row = cursor.fetchone()
            if row:
                self._consecutive_failures = row[0]

    def _query_lifetime_spent(self, cursor: sqlite3.Cursor, now_seconds: int) -> int:
        """
        Calculate total lifetime commitment under this policy:
        Sum of all COMMITTED amounts + active RESERVED where expires_at >= now_seconds.
        Ensures concurrent reservations cannot break the lifetime budget ceiling (P0-1).
        """
        cursor.execute(
            """
            SELECT COALESCE(SUM(amount_base_units), 0)
            FROM ap_budget_ledger
            WHERE policy_id = ?
              AND (
                  state = 'COMMITTED'
                  OR
                  (state = 'RESERVED' AND expires_at >= ?)
              );
            """,
            (self._config.id, now_seconds),
        )
        row = cursor.fetchone()
        return int(row[0]) if row and row[0] is not None else 0

    def _query_rolling_usage(self, cursor: sqlite3.Cursor, now_seconds: int) -> int:
        """
        Calculate current rolling usage per P0-6:
        COMMITTED in [now - 86400, now] + active RESERVED where expires_at >= now.
        Unifies expiration boundary with commit() at now == expires_at (P0-2).
        """
        cursor.execute(
            """
            SELECT COALESCE(SUM(amount_base_units), 0)
            FROM ap_budget_ledger
            WHERE policy_id = ?
              AND (
                  (state = 'COMMITTED' AND created_at >= ? - 86400)
                  OR
                  (state = 'RESERVED' AND expires_at >= ?)
              );
            """,
            (self._config.id, now_seconds, now_seconds),
        )
        row = cursor.fetchone()
        return int(row[0]) if row and row[0] is not None else 0

    def _query_requests_in_last_60s(self, cursor: sqlite3.Cursor, now_seconds: int) -> int:
        """Count reservations initiated in the last 60 seconds."""
        cursor.execute(
            """
            SELECT COUNT(*)
            FROM ap_budget_ledger
            WHERE policy_id = ? AND created_at >= ? - 60;
            """,
            (self._config.id, now_seconds),
        )
        row = cursor.fetchone()
        return int(row[0]) if row else 0

    def _query_active_probe_count(self, cursor: sqlite3.Cursor, now_seconds: int) -> int:
        """Count in-flight active reservations."""
        cursor.execute(
            """
            SELECT COUNT(*)
            FROM ap_budget_ledger
            WHERE policy_id = ? AND state = 'RESERVED' AND expires_at >= ?;
            """,
            (self._config.id, now_seconds),
        )
        row = cursor.fetchone()
        return int(row[0]) if row else 0

    def get_available_rolling_budget(self) -> int:
        """Return the current available rolling budget in base units."""
        now = self._clock()
        cursor = self._conn.cursor()
        usage = self._query_rolling_usage(cursor, now)
        return max(0, self._config.rolling_budget_24h_base_units - usage)

    def get_breaker_state(self) -> BreakerState:
        """
        Get the current circuit breaker state, evaluating cooldown transition
        from OPEN -> HALF_OPEN if elapsed.
        """
        now = self._clock()
        cursor = self._conn.cursor()
        cursor.execute(
            "SELECT breaker_state, tripped_at FROM ap_policy WHERE id = ?;",
            (self._config.id,),
        )
        row = cursor.fetchone()
        if not row:
            return BreakerState.CLOSED

        current_state = BreakerState(row[0])
        tripped_at = row[1]

        if (
            current_state == BreakerState.OPEN
            and tripped_at is not None
            and now >= tripped_at + self._config.circuit_cooldown_seconds
        ):
            # Transition to HALF_OPEN
            with self._conn:
                self._conn.execute(
                    """
                    UPDATE ap_policy
                    SET breaker_state = 'HALF_OPEN', updated_at = ?
                    WHERE id = ?;
                    """,
                    (now, self._config.id),
                )
            return BreakerState.HALF_OPEN

        return current_state

    def record_failure(self, reason: str = "") -> None:
        """
        Record a transaction or upstream delivery failure.

        Increments consecutive failures in ap_policy (persisted across instances)
        and trips breaker to OPEN if threshold reached or if in HALF_OPEN (test probe failed) (P1-3).
        """
        now = self._clock()
        current_state = self.get_breaker_state()
        with self._conn:
            cursor = self._conn.cursor()
            cursor.execute(
                """
                SELECT consecutive_failures, circuit_consecutive_failures
                FROM ap_policy
                WHERE id = ?;
                """,
                (self._config.id,),
            )
            row = cursor.fetchone()
            curr_fails = row[0] if row else self._consecutive_failures
            threshold = row[1] if (row and row[1]) else self._config.circuit_consecutive_failures

            new_failures = curr_fails + 1
            self._consecutive_failures = new_failures

            should_trip = current_state == BreakerState.HALF_OPEN or new_failures >= threshold

            if should_trip:
                cursor.execute(
                    """
                    UPDATE ap_policy
                    SET consecutive_failures = ?, breaker_state = 'OPEN', tripped_at = ?, updated_at = ?
                    WHERE id = ?;
                    """,
                    (new_failures, now, now, self._config.id),
                )
            else:
                cursor.execute(
                    """
                    UPDATE ap_policy
                    SET consecutive_failures = ?, updated_at = ?
                    WHERE id = ?;
                    """,
                    (new_failures, now, self._config.id),
                )

    def reset_breaker(self) -> None:
        """Explicitly reset the circuit breaker to CLOSED (operator unfreeze)."""
        now = self._clock()
        self._consecutive_failures = 0
        with self._conn:
            self._conn.execute(
                """
                UPDATE ap_policy
                SET breaker_state = 'CLOSED', consecutive_failures = 0, tripped_at = NULL, updated_at = ?
                WHERE id = ?;
                """,
                (now, self._config.id),
            )

    def reserve(
        self,
        intent_id: str,
        amount: int,
        payee: str,
        asset: str,
        network: str,
        domain: str | None = None,
        ttl_seconds: int = 360,
    ) -> PolicyDecision:
        """
        Atomically evaluate all precedence rules and lock quota in ap_budget_ledger.
        Fails-closed on any database error.

        Precedence order (specs/policy-engine-spec.md §3, P2-2):
          1. Freeze check (POLICY_FROZEN)
          2. Circuit breaker & RPM check (CIRCUIT_BREAKER_OPEN)
          3. Request format validation (INVALID_AMOUNT_FORMAT / INVALID_REQUEST)
          4. Whitelist matrix (NETWORK / ASSET / PAYEE / DOMAIN)
          5. Single-transaction cap (SINGLE_TX_CAP_EXCEEDED)
          6. Lifetime budget ceiling (LIFETIME_BUDGET_EXCEEDED)
          7. 24h rolling budget (DAILY_BUDGET_EXCEEDED)
        """
        now = self._clock()
        cursor = self._conn.cursor()
        try:
            # SECURITY-REVIEW: BEGIN IMMEDIATE acquires exclusive write lock immediately
            cursor.execute("BEGIN IMMEDIATE;")

            # Step 1 & 2: Policy Administrative Lock (is_frozen) -> Circuit Breaker & RPM Check (P1-2, P2-2)
            # SECURITY-REVIEW: Freeze and Circuit Breaker must precede request format validation (TV-ORD-01).
            gate_err = self._gate(cursor, now)
            if gate_err is not None:
                self._conn.commit()  # persist breaker transitions written by _gate
                return PolicyDecision(
                    approved=False,
                    error_code=gate_err,
                )

            # Step 3: Validate PaymentRequest format (amount -> INVALID_AMOUNT_FORMAT, other fields -> INVALID_REQUEST)
            try:
                _validate_positive_int(amount, "amount")
            except (ValueError, TypeError):
                self._conn.commit()
                return PolicyDecision(
                    approved=False,
                    error_code=PolicyErrorCode.INVALID_AMOUNT_FORMAT,
                )

            try:
                req = PaymentRequest(
                    intent_id=intent_id,
                    amount=amount,
                    payee=payee,
                    asset=asset,
                    network=network,
                    domain=domain,
                    ttl_seconds=ttl_seconds,
                )
            except (ValueError, TypeError, ValidationError):
                self._conn.commit()
                return PolicyDecision(
                    approved=False,
                    error_code=PolicyErrorCode.INVALID_REQUEST,
                )

            # Step 4-6: Evaluate static rules (Whitelist, Single-Tx Cap, Lifetime)
            lifetime_spent = self._query_lifetime_spent(cursor, now)
            static_res = evaluate_static_rules(
                config=self._config,
                request=req,
                lifetime_spent=lifetime_spent,
            )
            if not static_res.passed:
                self._conn.commit()
                return PolicyDecision(
                    approved=False,
                    error_code=static_res.error_code,
                )

            # Step 7: 24h Rolling Budget Check (P0-6)
            rolling_usage = self._query_rolling_usage(cursor, now)
            available = self._config.rolling_budget_24h_base_units - rolling_usage
            if available < req.amount:
                self._conn.commit()
                return PolicyDecision(
                    approved=False,
                    error_code=PolicyErrorCode.DAILY_BUDGET_EXCEEDED,
                )

            # Step 8: Insert Reservation Slot
            reservation_id = f"res_{uuid.uuid4().hex}"
            expires_at = now + req.ttl_seconds
            cursor.execute(
                """
                INSERT INTO ap_budget_ledger (
                    id, policy_id, wallet_address, intent_id,
                    amount_base_units, state, created_at, expires_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'RESERVED', ?, ?, ?);
                """,
                (
                    reservation_id,
                    self._config.id,
                    self._config.wallet_address,
                    req.intent_id,
                    req.amount,
                    now,
                    expires_at,
                    now,
                ),
            )
            self._conn.commit()

            new_available = available - req.amount
            token = ReservationToken(
                reservation_id=reservation_id,
                intent_id=req.intent_id,
                policy_id=self._config.id,
                amount=req.amount,
                expires_at=expires_at,
                created_at=now,
            )
            return PolicyDecision(
                approved=True,
                reservation=token,
                available_after=new_available,
            )
        except sqlite3.IntegrityError:
            self._rollback_quietly(cursor)
            # Duplicate intent_id or unique constraint violation -> fail closed (P2-1)
            return PolicyDecision(
                approved=False,
                error_code=PolicyErrorCode.DUPLICATE_INTENT,
            )
        except Exception:  # noqa: BLE001
            self._rollback_quietly(cursor)
            # Fail closed on any other unexpected DB or system errors (P2-1)
            return PolicyDecision(
                approved=False,
                error_code=PolicyErrorCode.POLICY_SYSTEM_ERROR,
            )

    def commit(self, intent_id: str) -> None:
        """
        Transition reservation from RESERVED to COMMITTED.
        Idempotent: Subsequent calls for already COMMITTED intent are no-ops.
        Resets consecutive failures to 0 and transitions HALF_OPEN to CLOSED.
        """
        now = self._clock()
        cursor = self._conn.cursor()
        cursor.execute("BEGIN IMMEDIATE;")
        try:
            cursor.execute(
                """
                SELECT state, expires_at
                FROM ap_budget_ledger
                WHERE intent_id = ?;
                """,
                (intent_id,),
            )
            row = cursor.fetchone()
            if not row:
                cursor.execute("ROLLBACK;")
                return

            state, expires_at = row[0], row[1]
            if state == "COMMITTED":
                cursor.execute("ROLLBACK;")
                return  # Idempotent no-op

            if now > expires_at:
                cursor.execute("ROLLBACK;")
                raise PolicyViolationError(
                    PolicyErrorCode.RESERVATION_EXPIRED,
                    f"Reservation for intent {intent_id} expired at {expires_at} (current: {now})",
                )

            cursor.execute(
                """
                UPDATE ap_budget_ledger
                SET state = 'COMMITTED', updated_at = ?
                WHERE intent_id = ? AND state = 'RESERVED';
                """,
                (now, intent_id),
            )

            # Success resets consecutive failure count & closes breaker if HALF_OPEN (P1-3)
            self._consecutive_failures = 0
            cursor.execute(
                """
                UPDATE ap_policy
                SET consecutive_failures = 0,
                    breaker_state = CASE WHEN breaker_state = 'HALF_OPEN' THEN 'CLOSED' ELSE breaker_state END,
                    tripped_at = CASE WHEN breaker_state = 'HALF_OPEN' THEN NULL ELSE tripped_at END,
                    updated_at = ?
                WHERE id = ?;
                """,
                (now, self._config.id),
            )
            self._conn.commit()
        except PolicyViolationError:
            raise
        except Exception:
            try:
                if self._conn.in_transaction:
                    cursor.execute("ROLLBACK;")
            except sqlite3.OperationalError:
                pass
            raise

    def release(self, intent_id: str, reason: str | None = None) -> None:
        """
        Transition reservation from RESERVED to RELEASED.
        Guarded: If intent was already COMMITTED, raises RESERVATION_ALREADY_FINALIZED.
        Idempotent: Subsequent releases on already RELEASED intent are no-ops.
        """
        now = self._clock()
        cursor = self._conn.cursor()
        cursor.execute("BEGIN IMMEDIATE;")
        try:
            cursor.execute(
                """
                SELECT state
                FROM ap_budget_ledger
                WHERE intent_id = ?;
                """,
                (intent_id,),
            )
            row = cursor.fetchone()
            if not row:
                cursor.execute("ROLLBACK;")
                return

            state = row[0]
            if state == "COMMITTED":
                cursor.execute("ROLLBACK;")
                raise PolicyViolationError(
                    PolicyErrorCode.RESERVATION_ALREADY_FINALIZED,
                    f"Cannot release intent {intent_id}: already COMMITTED",
                )

            if state == "RELEASED":
                cursor.execute("ROLLBACK;")
                return  # Idempotent no-op

            cursor.execute(
                """
                UPDATE ap_budget_ledger
                SET state = 'RELEASED', updated_at = ?
                WHERE intent_id = ? AND state = 'RESERVED';
                """,
                (now, intent_id),
            )
            self._conn.commit()
        except PolicyViolationError:
            raise
        except Exception:
            try:
                if self._conn.in_transaction:
                    cursor.execute("ROLLBACK;")
            except sqlite3.OperationalError:
                pass
            raise

    # ------------------------------------------------------------------
    # Credential-mode (non-402) metering  [agentpay-metering-patch]
    # ------------------------------------------------------------------

    def _rollback_quietly(self, cursor: sqlite3.Cursor) -> None:
        try:
            if self._conn.in_transaction:
                cursor.execute("ROLLBACK;")
        except sqlite3.OperationalError:
            pass

    def _gate(self, cursor: sqlite3.Cursor, now: int) -> PolicyErrorCode | None:
        """frozen / circuit-breaker / RPM gate. Caller must already hold BEGIN IMMEDIATE."""
        cursor.execute(
            "SELECT is_frozen, breaker_state, tripped_at FROM ap_policy WHERE id = ?;",
            (self._config.id,),
        )
        row = cursor.fetchone()
        is_frozen = (row[0] == 1) if row else self._config.is_frozen
        if is_frozen:
            return PolicyErrorCode.POLICY_FROZEN

        state = BreakerState(row[1]) if row and row[1] else BreakerState.CLOSED
        tripped_at = row[2] if row else None
        if (
            state == BreakerState.OPEN
            and tripped_at is not None
            and now >= tripped_at + self._config.circuit_cooldown_seconds
        ):
            state = BreakerState.HALF_OPEN
            cursor.execute(
                "UPDATE ap_policy SET breaker_state = 'HALF_OPEN', updated_at = ? WHERE id = ?;",
                (now, self._config.id),
            )
        if state == BreakerState.OPEN:
            return PolicyErrorCode.CIRCUIT_BREAKER_OPEN
        if state == BreakerState.HALF_OPEN and self._query_active_probe_count(cursor, now) >= 1:
            return PolicyErrorCode.CIRCUIT_BREAKER_OPEN

        if self._query_requests_in_last_60s(cursor, now) >= self._config.circuit_max_rpm:
            cursor.execute(
                "UPDATE ap_policy SET breaker_state = 'OPEN', tripped_at = ?, updated_at = ? WHERE id = ?;",
                (now, now, self._config.id),
            )
            return PolicyErrorCode.CIRCUIT_BREAKER_OPEN
        return None

    def reserve_metered(
        self,
        intent_id: str,
        estimated_amount: int,
        domain: str | None,
        ttl_seconds: int = 60,
    ) -> PolicyDecision:
        """
        Reserve quota for a credential-mode (non-402) call BEFORE it is sent.

        Applies frozen/breaker/RPM, request format, domain whitelist, single-tx cap,
        lifetime and 24h rolling budget against ``estimated_amount``. Fails closed.
        """
        now = self._clock()
        cursor = self._conn.cursor()
        try:
            # SECURITY-REVIEW: Freeze and Circuit Breaker precede format validation (P2-2, TV-ORD-01).
            cursor.execute("BEGIN IMMEDIATE;")

            err = self._gate(cursor, now)
            if err is None:
                if (
                    isinstance(estimated_amount, bool)
                    or not isinstance(estimated_amount, int)
                    or not (0 < estimated_amount <= SQLITE_MAX_INT)
                ):
                    err = PolicyErrorCode.INVALID_AMOUNT_FORMAT
                elif (
                    not isinstance(intent_id, str)
                    or not intent_id.strip()
                    or isinstance(ttl_seconds, bool)
                    or not isinstance(ttl_seconds, int)
                    or not (0 < ttl_seconds <= 86400)
                    or (domain is not None and not isinstance(domain, str))
                ):
                    err = PolicyErrorCode.INVALID_REQUEST

            if err is None:
                res = evaluate_metered_rules(
                    self._config,
                    estimated_amount,
                    domain,
                    self._query_lifetime_spent(cursor, now),
                )
                if not res.passed:
                    err = res.error_code or PolicyErrorCode.POLICY_SYSTEM_ERROR

            available = 0
            if err is None:
                available = self._config.rolling_budget_24h_base_units - self._query_rolling_usage(cursor, now)
                if available < estimated_amount:
                    err = PolicyErrorCode.DAILY_BUDGET_EXCEEDED

            if err is not None:
                self._conn.commit()  # persist breaker transitions written by _gate
                return PolicyDecision(approved=False, error_code=err)

            reservation_id = f"res_{uuid.uuid4().hex}"
            expires_at = now + ttl_seconds
            cursor.execute(
                """
                INSERT INTO ap_budget_ledger (
                    id, policy_id, wallet_address, intent_id,
                    amount_base_units, state, created_at, expires_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'RESERVED', ?, ?, ?);
                """,
                (
                    reservation_id,
                    self._config.id,
                    self._config.wallet_address,
                    intent_id,
                    estimated_amount,
                    now,
                    expires_at,
                    now,
                ),
            )
            self._conn.commit()
            return PolicyDecision(
                approved=True,
                reservation=ReservationToken(
                    reservation_id=reservation_id,
                    intent_id=intent_id,
                    policy_id=self._config.id,
                    amount=estimated_amount,
                    expires_at=expires_at,
                    created_at=now,
                ),
                available_after=available - estimated_amount,
            )
        except sqlite3.IntegrityError:
            self._rollback_quietly(cursor)
            return PolicyDecision(approved=False, error_code=PolicyErrorCode.DUPLICATE_INTENT)
        except Exception:  # noqa: BLE001
            logging.exception("policy reserve_metered failed; failing closed")
            self._rollback_quietly(cursor)
            return PolicyDecision(approved=False, error_code=PolicyErrorCode.POLICY_SYSTEM_ERROR)

    def settle_metered(self, intent_id: str, actual_amount: int | None = None) -> None:
        """
        RESERVED -> COMMITTED for a credential-mode call.

        ``actual_amount`` replaces the estimate when it is a valid positive int; anything else
        (None, negative, bool, too large) keeps the reserved estimate so a faulty callback can
        never reduce recorded spend. Never raises on expiry: the call already happened.
        """
        if actual_amount is not None and (
            isinstance(actual_amount, bool)
            or not isinstance(actual_amount, int)
            or not (0 < actual_amount <= SQLITE_MAX_INT)
        ):
            logging.warning("invalid actual_amount %r for %s; keeping reserved estimate", actual_amount, intent_id)
            actual_amount = None

        now = self._clock()
        cursor = self._conn.cursor()
        cursor.execute("BEGIN IMMEDIATE;")
        try:
            cursor.execute(
                """
                UPDATE ap_budget_ledger
                SET state = 'COMMITTED',
                    amount_base_units = COALESCE(?, amount_base_units),
                    updated_at = ?
                WHERE intent_id = ? AND state = 'RESERVED';
                """,
                (actual_amount, now, intent_id),
            )
            if cursor.rowcount:
                self._consecutive_failures = 0
                cursor.execute(
                    """
                    UPDATE ap_policy
                    SET consecutive_failures = 0,
                        breaker_state = CASE WHEN breaker_state = 'HALF_OPEN' THEN 'CLOSED' ELSE breaker_state END,
                        tripped_at = CASE WHEN breaker_state = 'HALF_OPEN' THEN NULL ELSE tripped_at END,
                        updated_at = ?
                    WHERE id = ?;
                    """,
                    (now, self._config.id),
                )
            else:
                logging.warning("settle_metered: no RESERVED row for intent %s", intent_id)
            self._conn.commit()
        except Exception:
            self._rollback_quietly(cursor)
            raise
