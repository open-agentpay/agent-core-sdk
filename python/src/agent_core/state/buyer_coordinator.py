"""
Buyer State Coordinator for AgentCore.

Coordinates SQLite atomic transactions between:
  - Buyer Payment Intent (ap_buyer_intent)
  - Budget Reservation Ledger (ap_budget_ledger)

Enforces:
  - Atomic two-phase reservation & commitment
  - CLAUDE.md Invariant: No release once signature is dispatched
  - Deterministic time injection via clock parameter
"""

from __future__ import annotations

import sqlite3
import time
import uuid
from collections.abc import Callable

from agent_core.core.state import (
    BudgetLedgerState,
    BuyerIntentRecord,
    PaymentIntentState,
)
from agent_core.state.errors import (
    IllegalStateTransitionError,
    SignatureSentReleaseForbiddenError,
)
from agent_core.state.guards import (
    validate_intent_transition,
    validate_ledger_transition,
)


class BuyerStateCoordinator:
    """
    Coordinates state mutations and SQLite transactions for the Buyer domain.
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._conn = conn
        self._clock = clock or (lambda: int(time.time()))

    def get_time(self) -> int:
        return self._clock()

    def create_intent(self, record: BuyerIntentRecord) -> None:
        """Insert a newly parsed payment intent into ap_buyer_intent."""
        now = self.get_time()
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO ap_buyer_intent (
                    intent_id, policy_id, idempotency_key, payer_address, payee_address,
                    asset_address, network_id, amount_base_units, status, nonce,
                    valid_after, valid_before, raw_signature, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    record.intent_id,
                    record.policy_id,
                    record.idempotency_key,
                    record.payer_address.lower(),
                    record.payee_address.lower(),
                    record.asset_address.lower(),
                    record.network_id,
                    record.amount_base_units,
                    record.status.value,
                    record.nonce,
                    record.valid_after,
                    record.valid_before,
                    record.raw_signature,
                    record.created_at or now,
                    record.updated_at or now,
                ),
            )

    def reserve_intent(
        self,
        intent_id: str,
        policy_id: str,
        wallet_address: str,
        amount_base_units: int,
        ttl_seconds: int = 360,
    ) -> str:
        """
        Atomically transition intent to PROCESSING / AUTHORIZED and lock quota in ap_budget_ledger.

        Returns:
            reservation_id (UUIDv7 string)
        """
        now = self.get_time()
        expires_at = now + ttl_seconds
        reservation_id = f"res_{uuid.uuid4().hex}"

        cursor = self._conn.cursor()
        cursor.execute("BEGIN IMMEDIATE;")
        try:
            # Check current intent state
            cursor.execute(
                "SELECT status FROM ap_buyer_intent WHERE intent_id = ?;",
                (intent_id,),
            )
            row = cursor.fetchone()
            if not row:
                cursor.execute("ROLLBACK;")
                raise ValueError(f"Buyer intent '{intent_id}' not found.")

            current_status = PaymentIntentState(row[0])
            validate_intent_transition(
                current_status,
                PaymentIntentState.PROCESSING,
                intent_id=intent_id,
            )

            # Insert budget reservation
            cursor.execute(
                """
                INSERT INTO ap_budget_ledger (
                    id, policy_id, wallet_address, intent_id, amount_base_units, state, created_at, expires_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'RESERVED', ?, ?, ?);
                """,
                (
                    reservation_id,
                    policy_id,
                    wallet_address.lower(),
                    intent_id,
                    amount_base_units,
                    now,
                    expires_at,
                    now,
                ),
            )

            # Update intent status
            cursor.execute(
                """
                UPDATE ap_buyer_intent
                SET status = 'PROCESSING', updated_at = ?
                WHERE intent_id = ?;
                """,
                (now, intent_id),
            )
            self._conn.commit()
            return reservation_id
        except Exception:
            if self._conn.in_transaction:
                cursor.execute("ROLLBACK;")
            raise

    def record_dispatch(
        self,
        intent_id: str,
        raw_signature: str = "default_sig",
        nonce: str | None = None,
    ) -> None:
        """
        Record that the HTTP request was dispatched on the wire with PAYMENT-SIGNATURE.
        Transitions intent to SIGNATURE_SENT. Ledger must be RESERVED.
        """
        now = self.get_time()
        cursor = self._conn.cursor()
        cursor.execute("BEGIN IMMEDIATE;")
        try:
            cursor.execute(
                "SELECT status FROM ap_buyer_intent WHERE intent_id = ?;",
                (intent_id,),
            )
            row = cursor.fetchone()
            if not row:
                cursor.execute("ROLLBACK;")
                raise ValueError(f"Buyer intent '{intent_id}' not found.")

            current_status = PaymentIntentState(row[0])
            validate_intent_transition(
                current_status,
                PaymentIntentState.SIGNATURE_SENT,
                intent_id=intent_id,
            )

            # Verify ledger is in RESERVED state
            cursor.execute(
                "SELECT state FROM ap_budget_ledger WHERE intent_id = ?;",
                (intent_id,),
            )
            ledger_row = cursor.fetchone()
            if not ledger_row or ledger_row[0] != BudgetLedgerState.RESERVED.value:
                cursor.execute("ROLLBACK;")
                raise IllegalStateTransitionError(
                    "BudgetLedger",
                    ledger_row[0] if ledger_row else "NONE",
                    BudgetLedgerState.RESERVED.value,
                    "Cannot dispatch request without an active RESERVED quota.",
                )

            cursor.execute(
                """
                UPDATE ap_buyer_intent
                SET status = 'SIGNATURE_SENT',
                    raw_signature = COALESCE(?, raw_signature),
                    nonce = COALESCE(?, nonce),
                    updated_at = ?
                WHERE intent_id = ?;
                """,
                (raw_signature, nonce, now, intent_id),
            )
            self._conn.commit()
        except Exception:
            if self._conn.in_transaction:
                cursor.execute("ROLLBACK;")
            raise

    def complete_intent(self, intent_id: str) -> None:
        """
        Finalize transaction after receiving HTTP 200 OK.
        Atomically sets intent to SUCCEEDED and ledger quota to COMMITTED.
        """
        now = self.get_time()
        cursor = self._conn.cursor()
        cursor.execute("BEGIN IMMEDIATE;")
        try:
            cursor.execute(
                "SELECT status FROM ap_buyer_intent WHERE intent_id = ?;",
                (intent_id,),
            )
            row = cursor.fetchone()
            if not row:
                cursor.execute("ROLLBACK;")
                raise ValueError(f"Buyer intent '{intent_id}' not found.")

            current_status = PaymentIntentState(row[0])
            validate_intent_transition(
                current_status,
                PaymentIntentState.SUCCEEDED,
                intent_id=intent_id,
            )

            cursor.execute(
                "SELECT state FROM ap_budget_ledger WHERE intent_id = ?;",
                (intent_id,),
            )
            ledger_row = cursor.fetchone()
            if not ledger_row:
                cursor.execute("ROLLBACK;")
                raise ValueError(f"Ledger entry for intent '{intent_id}' not found.")

            current_ledger = BudgetLedgerState(ledger_row[0])
            validate_ledger_transition(current_ledger, BudgetLedgerState.COMMITTED)

            cursor.execute(
                """
                UPDATE ap_budget_ledger
                SET state = 'COMMITTED', updated_at = ?
                WHERE intent_id = ?;
                """,
                (now, intent_id),
            )
            cursor.execute(
                """
                UPDATE ap_buyer_intent
                SET status = 'SUCCEEDED', updated_at = ?
                WHERE intent_id = ?;
                """,
                (now, intent_id),
            )
            self._conn.commit()
        except Exception:
            if self._conn.in_transaction:
                cursor.execute("ROLLBACK;")
            raise

    def hold_intent(self, intent_id: str, error_message: str | None = None) -> None:
        """
        Transition intent to RECOVERY_HOLD (e.g. upon upstream 500 or timeout).
        PRESERVES ledger in RESERVED state (never auto-release).
        """
        now = self.get_time()
        cursor = self._conn.cursor()
        cursor.execute("BEGIN IMMEDIATE;")
        try:
            cursor.execute(
                "SELECT status FROM ap_buyer_intent WHERE intent_id = ?;",
                (intent_id,),
            )
            row = cursor.fetchone()
            if not row:
                cursor.execute("ROLLBACK;")
                raise ValueError(f"Buyer intent '{intent_id}' not found.")

            current_status = PaymentIntentState(row[0])
            validate_intent_transition(
                current_status,
                PaymentIntentState.RECOVERY_HOLD,
                intent_id=intent_id,
            )

            # Ensure ledger is preserved in RESERVED state
            cursor.execute(
                "SELECT state FROM ap_budget_ledger WHERE intent_id = ?;",
                (intent_id,),
            )
            ledger_row = cursor.fetchone()
            if ledger_row and ledger_row[0] != BudgetLedgerState.RESERVED.value:
                cursor.execute("ROLLBACK;")
                raise IllegalStateTransitionError(
                    "BudgetLedger",
                    ledger_row[0],
                    BudgetLedgerState.RESERVED.value,
                    "Ledger must remain RESERVED when intent enters RECOVERY_HOLD.",
                )

            cursor.execute(
                """
                UPDATE ap_buyer_intent
                SET status = 'RECOVERY_HOLD', updated_at = ?
                WHERE intent_id = ?;
                """,
                (now, intent_id),
            )
            self._conn.commit()
        except Exception:
            if self._conn.in_transaction:
                cursor.execute("ROLLBACK;")
            raise

    def cancel_intent(self, intent_id: str, reason: str = "") -> None:
        """
        Cancel an intent before cryptographic signature was sent on the wire.
        Safely releases ledger quota (RESERVED -> RELEASED).

        Raises:
            SignatureSentReleaseForbiddenError: If signature was already sent on the wire.
        """
        now = self.get_time()
        cursor = self._conn.cursor()
        cursor.execute("BEGIN IMMEDIATE;")
        try:
            cursor.execute(
                "SELECT status FROM ap_buyer_intent WHERE intent_id = ?;",
                (intent_id,),
            )
            row = cursor.fetchone()
            if not row:
                cursor.execute("ROLLBACK;")
                raise ValueError(f"Buyer intent '{intent_id}' not found.")

            current_status = PaymentIntentState(row[0])

            # Safety Guard: If signature was sent, cannot cancel!
            if current_status in (
                PaymentIntentState.SIGNATURE_SENT,
                PaymentIntentState.RECOVERY_HOLD,
            ):
                cursor.execute("ROLLBACK;")
                raise SignatureSentReleaseForbiddenError(intent_id, current_status.value)

            validate_intent_transition(
                current_status,
                PaymentIntentState.CANCELLED,
                intent_id=intent_id,
            )

            # If ledger exists, release quota
            cursor.execute(
                "SELECT state FROM ap_budget_ledger WHERE intent_id = ?;",
                (intent_id,),
            )
            ledger_row = cursor.fetchone()
            if ledger_row:
                current_ledger = BudgetLedgerState(ledger_row[0])
                validate_ledger_transition(current_ledger, BudgetLedgerState.RELEASED)
                cursor.execute(
                    """
                    UPDATE ap_budget_ledger
                    SET state = 'RELEASED', updated_at = ?
                    WHERE intent_id = ?;
                    """,
                    (now, intent_id),
                )

            cursor.execute(
                """
                UPDATE ap_buyer_intent
                SET status = 'CANCELLED', updated_at = ?
                WHERE intent_id = ?;
                """,
                (now, intent_id),
            )
            self._conn.commit()
        except Exception:
            if self._conn.in_transaction:
                cursor.execute("ROLLBACK;")
            raise

    def reconcile_release(self, intent_id: str, reason: str = "") -> None:
        """
        Release quota for a RECOVERY_HOLD intent after reconciliation worker
        definitively proves nonce was never spent on-chain.
        """
        now = self.get_time()
        cursor = self._conn.cursor()
        cursor.execute("BEGIN IMMEDIATE;")
        try:
            cursor.execute(
                "SELECT status FROM ap_buyer_intent WHERE intent_id = ?;",
                (intent_id,),
            )
            row = cursor.fetchone()
            if not row:
                cursor.execute("ROLLBACK;")
                raise ValueError(f"Buyer intent '{intent_id}' not found.")

            current_status = PaymentIntentState(row[0])
            validate_intent_transition(
                current_status,
                PaymentIntentState.REJECTED,
                intent_id=intent_id,
            )

            cursor.execute(
                """
                UPDATE ap_budget_ledger
                SET state = 'RELEASED', updated_at = ?
                WHERE intent_id = ? AND state = 'RESERVED';
                """,
                (now, intent_id),
            )
            cursor.execute(
                """
                UPDATE ap_buyer_intent
                SET status = 'REJECTED', updated_at = ?
                WHERE intent_id = ?;
                """,
                (now, intent_id),
            )
            self._conn.commit()
        except Exception:
            if self._conn.in_transaction:
                cursor.execute("ROLLBACK;")
            raise

    def get_intent(self, intent_id: str) -> BuyerIntentRecord | None:
        """Fetch a BuyerIntentRecord by intent_id."""
        cursor = self._conn.cursor()
        cursor.execute(
            """
            SELECT intent_id, policy_id, idempotency_key, payer_address, payee_address,
                   asset_address, network_id, amount_base_units, status, nonce,
                   valid_after, valid_before, raw_signature, created_at, updated_at
            FROM ap_buyer_intent
            WHERE intent_id = ?;
            """,
            (intent_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return BuyerIntentRecord(
            intentId=row[0],
            policyId=row[1],
            idempotencyKey=row[2],
            payerAddress=row[3],
            payeeAddress=row[4],
            assetAddress=row[5],
            networkId=row[6],
            amountBaseUnits=row[7],
            status=PaymentIntentState(row[8]),
            nonce=row[9],
            validAfter=row[10],
            validBefore=row[11],
            rawSignature=row[12],
            createdAt=row[13],
            updatedAt=row[14],
        )

    def get_ledger_state(self, intent_id: str) -> BudgetLedgerState | None:
        """Fetch current BudgetLedgerState for an intent."""
        cursor = self._conn.cursor()
        cursor.execute(
            "SELECT state FROM ap_budget_ledger WHERE intent_id = ?;",
            (intent_id,),
        )
        row = cursor.fetchone()
        return BudgetLedgerState(row[0]) if row else None

    def list_intents(self, states: list[PaymentIntentState] | None = None) -> list[BuyerIntentRecord]:
        """Fetch BuyerIntentRecords filtered optionally by state."""
        cursor = self._conn.cursor()
        if states:
            placeholders = ",".join("?" for _ in states)
            sql = f"""
            SELECT intent_id, policy_id, idempotency_key, payer_address, payee_address,
                   asset_address, network_id, amount_base_units, status, nonce,
                   valid_after, valid_before, raw_signature, created_at, updated_at
            FROM ap_buyer_intent
            WHERE status IN ({placeholders})
            ORDER BY created_at ASC;
            """
            cursor.execute(sql, tuple(s.value for s in states))
        else:
            sql = """
            SELECT intent_id, policy_id, idempotency_key, payer_address, payee_address,
                   asset_address, network_id, amount_base_units, status, nonce,
                   valid_after, valid_before, raw_signature, created_at, updated_at
            FROM ap_buyer_intent
            ORDER BY created_at ASC;
            """
            cursor.execute(sql)

        records: list[BuyerIntentRecord] = []
        for row in cursor.fetchall():
            records.append(
                BuyerIntentRecord(
                    intentId=row[0],
                    policyId=row[1],
                    idempotencyKey=row[2],
                    payerAddress=row[3],
                    payeeAddress=row[4],
                    assetAddress=row[5],
                    networkId=row[6],
                    amountBaseUnits=row[7],
                    status=PaymentIntentState(row[8]),
                    nonce=row[9],
                    validAfter=row[10],
                    validBefore=row[11],
                    rawSignature=row[12],
                    createdAt=row[13],
                    updatedAt=row[14],
                )
            )
        return records
