"""
State Transition Guards and Multi-Entity Validation Rules for AgentCore.

Enforces:
  - Transition guard matrices for Intent, Settlement, Fulfillment, and Ledger
  - Strict Anti-Overspend invariant: SIGNATURE_SENT/RECOVERY_HOLD cannot release
  - Strict Anti-Rollback invariant: Upstream 5xx cannot void Settlement
  - Legal composite state whitelist
"""

from __future__ import annotations

from agent_core.core.state import (
    BudgetLedgerState,
    FulfillmentState,
    PaymentIntentState,
    SettlementState,
)
from agent_core.state.errors import (
    IllegalStateTransitionError,
    InvalidCompositeStateError,
    OrphanedSettlementRollbackForbiddenError,
    SignatureSentReleaseForbiddenError,
)

# ---------------------------------------------------------------------------
# 1. Individual Entity Transition Matrices
# ---------------------------------------------------------------------------

LEGAL_INTENT_TRANSITIONS: dict[PaymentIntentState, set[PaymentIntentState]] = {
    PaymentIntentState.CREATED: {
        PaymentIntentState.PROCESSING,
        PaymentIntentState.AUTHORIZED,
        PaymentIntentState.REJECTED,
        PaymentIntentState.EXPIRED,
        PaymentIntentState.CANCELLED,
    },
    PaymentIntentState.AUTHORIZED: {
        PaymentIntentState.PROCESSING,
        PaymentIntentState.SIGNATURE_SENT,
        PaymentIntentState.CANCELLED,
    },
    PaymentIntentState.PROCESSING: {
        PaymentIntentState.SIGNATURE_SENT,
        PaymentIntentState.SUCCEEDED,
        PaymentIntentState.COMPLETED,
        PaymentIntentState.RECOVERY_HOLD,
        PaymentIntentState.CANCELLED,
    },
    PaymentIntentState.SIGNATURE_SENT: {
        PaymentIntentState.SUCCEEDED,
        PaymentIntentState.COMPLETED,
        PaymentIntentState.RECOVERY_HOLD,
    },
    PaymentIntentState.RECOVERY_HOLD: {
        PaymentIntentState.SUCCEEDED,
        PaymentIntentState.COMPLETED,
        PaymentIntentState.REJECTED,  # Permitted ONLY after reconciler proves nonce unspent
    },
    # Terminal states
    PaymentIntentState.COMPLETED: set(),
    PaymentIntentState.SUCCEEDED: set(),
    PaymentIntentState.REJECTED: set(),
    PaymentIntentState.EXPIRED: set(),
    PaymentIntentState.CANCELLED: set(),
}

LEGAL_SETTLEMENT_TRANSITIONS: dict[SettlementState, set[SettlementState]] = {
    SettlementState.NOT_STARTED: {
        SettlementState.SUBMITTED,
        SettlementState.PENDING,
        SettlementState.FAILED,
    },
    SettlementState.NOT_SUBMITTED: {
        SettlementState.SUBMITTED,
        SettlementState.PENDING,
        SettlementState.FAILED,
    },
    SettlementState.SUBMITTED: {
        SettlementState.PENDING,
        SettlementState.CONFIRMED,
        SettlementState.SUCCESS,
        SettlementState.FAILED,
        SettlementState.UNKNOWN,
    },
    SettlementState.PENDING: {
        SettlementState.CONFIRMED,
        SettlementState.SUCCESS,
        SettlementState.FAILED,
        SettlementState.REORGED,
        SettlementState.UNKNOWN,
    },
    SettlementState.REORGED: {
        SettlementState.SUBMITTED,
        SettlementState.FAILED,
    },
    SettlementState.UNKNOWN: {
        SettlementState.CONFIRMED,
        SettlementState.SUCCESS,
        SettlementState.PENDING,
        SettlementState.FAILED,
    },
    # Terminal states
    SettlementState.CONFIRMED: set(),
    SettlementState.SUCCESS: set(),
    SettlementState.FAILED: set(),
}

LEGAL_FULFILLMENT_TRANSITIONS: dict[FulfillmentState, set[FulfillmentState]] = {
    FulfillmentState.NOT_STARTED: {
        FulfillmentState.PROCESSING,
        FulfillmentState.DELIVERING,
        FulfillmentState.FAILED,
    },
    FulfillmentState.NOT_DELIVERED: {
        FulfillmentState.PROCESSING,
        FulfillmentState.DELIVERING,
        FulfillmentState.FAILED,
    },
    FulfillmentState.PROCESSING: {
        FulfillmentState.DELIVERED,
        FulfillmentState.FAILED,
        FulfillmentState.RECOVERY_REQUIRED,
    },
    FulfillmentState.DELIVERING: {
        FulfillmentState.DELIVERED,
        FulfillmentState.FAILED,
        FulfillmentState.RECOVERY_REQUIRED,
    },
    FulfillmentState.RECOVERY_REQUIRED: {
        # Allows idempotent re-delivery attempts without new charges
        FulfillmentState.PROCESSING,
        FulfillmentState.DELIVERING,
        FulfillmentState.DELIVERED,
        FulfillmentState.FAILED,
    },
    # Terminal states
    FulfillmentState.DELIVERED: set(),
    FulfillmentState.FAILED: set(),
}

LEGAL_LEDGER_TRANSITIONS: dict[BudgetLedgerState, set[BudgetLedgerState]] = {
    BudgetLedgerState.RESERVED: {
        BudgetLedgerState.COMMITTED,
        BudgetLedgerState.RELEASED,
    },
    # Terminal states
    BudgetLedgerState.COMMITTED: set(),
    BudgetLedgerState.RELEASED: set(),
}


# ---------------------------------------------------------------------------
# 2. Guard Functions
# ---------------------------------------------------------------------------


def validate_intent_transition(
    from_state: PaymentIntentState,
    to_state: PaymentIntentState,
    *,
    intent_id: str = "",
) -> None:
    """
    Validate that an intent transition is legal.

    Raises:
        SignatureSentReleaseForbiddenError: If attempting to abort after signature dispatch.
        IllegalStateTransitionError: If the transition is not in LEGAL_INTENT_TRANSITIONS.
    """
    if from_state == to_state:
        return  # Idempotent no-op

    # Guardrail: Once SIGNATURE_SENT or RECOVERY_HOLD, never transition to CANCELLED
    if (
        from_state
        in (
            PaymentIntentState.SIGNATURE_SENT,
            PaymentIntentState.RECOVERY_HOLD,
        )
        and to_state == PaymentIntentState.CANCELLED
    ):
        raise SignatureSentReleaseForbiddenError(intent_id, from_state.value)

    allowed = LEGAL_INTENT_TRANSITIONS.get(from_state, set())
    if to_state not in allowed:
        raise IllegalStateTransitionError(
            entity_type="PaymentIntent",
            from_state=from_state.value,
            to_state=to_state.value,
            detail=f"Allowed transitions from '{from_state.value}': {[s.value for s in allowed]}",
        )


def validate_settlement_transition(
    from_state: SettlementState,
    to_state: SettlementState,
    *,
    settlement_id: str = "",
) -> None:
    """
    Validate that a settlement transition is legal.

    Raises:
        OrphanedSettlementRollbackForbiddenError: If attempting to rollback an active settlement.
        IllegalStateTransitionError: If the transition is not in LEGAL_SETTLEMENT_TRANSITIONS.
    """
    if from_state == to_state:
        return  # Idempotent no-op

    # Guardrail: Active settlements (SUBMITTED, PENDING, CONFIRMED/SUCCESS) cannot be reset to NOT_STARTED
    if from_state in (
        SettlementState.SUBMITTED,
        SettlementState.PENDING,
        SettlementState.CONFIRMED,
        SettlementState.SUCCESS,
    ) and to_state in (SettlementState.NOT_STARTED, SettlementState.NOT_SUBMITTED):
        raise OrphanedSettlementRollbackForbiddenError(settlement_id, from_state.value)

    allowed = LEGAL_SETTLEMENT_TRANSITIONS.get(from_state, set())
    if to_state not in allowed:
        raise IllegalStateTransitionError(
            entity_type="Settlement",
            from_state=from_state.value,
            to_state=to_state.value,
            detail=f"Allowed transitions from '{from_state.value}': {[s.value for s in allowed]}",
        )


def validate_fulfillment_transition(
    from_state: FulfillmentState,
    to_state: FulfillmentState,
) -> None:
    """
    Validate that a fulfillment transition is legal.

    Raises:
        IllegalStateTransitionError: If the transition is not in LEGAL_FULFILLMENT_TRANSITIONS.
    """
    if from_state == to_state:
        return  # Idempotent no-op

    allowed = LEGAL_FULFILLMENT_TRANSITIONS.get(from_state, set())
    if to_state not in allowed:
        raise IllegalStateTransitionError(
            entity_type="Fulfillment",
            from_state=from_state.value,
            to_state=to_state.value,
            detail=f"Allowed transitions from '{from_state.value}': {[s.value for s in allowed]}",
        )


def validate_ledger_transition(
    from_state: BudgetLedgerState,
    to_state: BudgetLedgerState,
) -> None:
    """
    Validate that a budget ledger quota transition is legal.

    Raises:
        IllegalStateTransitionError: If already finalized (COMMITTED or RELEASED).
    """
    if from_state == to_state:
        return  # Idempotent no-op

    allowed = LEGAL_LEDGER_TRANSITIONS.get(from_state, set())
    if to_state not in allowed:
        raise IllegalStateTransitionError(
            entity_type="BudgetLedger",
            from_state=from_state.value,
            to_state=to_state.value,
            detail=f"Ledger entry is already finalized in '{from_state.value}'.",
        )


# ---------------------------------------------------------------------------
# 3. Composite State Whitelist Validation
# ---------------------------------------------------------------------------


def validate_composite_state(
    intent_state: PaymentIntentState,
    settlement_state: SettlementState,
    fulfillment_state: FulfillmentState,
    ledger_state: BudgetLedgerState | None = None,
) -> None:
    """
    Validate the combined state across all four entities against specs §4.

    Enforces:
      - Successful intent (SUCCEEDED/COMPLETED) requires DELIVERED and COMMITTED.
      - RECOVERY_HOLD must NEVER pair with RELEASED ledger.
      - Orphaned settlement (RECOVERY_HOLD + SUCCESS + RECOVERY_REQUIRED) must keep RESERVED.
    """
    # Invariant 1: Anti-Overspend Rule
    if (
        intent_state
        in (
            PaymentIntentState.SIGNATURE_SENT,
            PaymentIntentState.RECOVERY_HOLD,
        )
        and ledger_state == BudgetLedgerState.RELEASED
    ):
        raise InvalidCompositeStateError(
            intent_state.value,
            settlement_state.value,
            fulfillment_state.value,
            ledger_state.value if ledger_state else None,
            "Anti-Overspend Violation: Budget cannot be RELEASED while intent is in-flight or held.",
        )

    # Invariant 2: Success Alignment Rule
    if intent_state in (PaymentIntentState.SUCCEEDED, PaymentIntentState.COMPLETED):
        if fulfillment_state not in (FulfillmentState.DELIVERED,):
            raise InvalidCompositeStateError(
                intent_state.value,
                settlement_state.value,
                fulfillment_state.value,
                ledger_state.value if ledger_state else None,
                "Intent cannot be SUCCEEDED if resource was not DELIVERED.",
            )
        if ledger_state is not None and ledger_state != BudgetLedgerState.COMMITTED:
            raise InvalidCompositeStateError(
                intent_state.value,
                settlement_state.value,
                fulfillment_state.value,
                ledger_state.value,
                "Intent cannot be SUCCEEDED unless budget quota is COMMITTED.",
            )

    # Invariant 3: Delivered Resource Settlement Requirement
    if fulfillment_state == FulfillmentState.DELIVERED and settlement_state not in (
        SettlementState.SUBMITTED,
        SettlementState.PENDING,
        SettlementState.CONFIRMED,
        SettlementState.SUCCESS,
    ):
        raise InvalidCompositeStateError(
            intent_state.value,
            settlement_state.value,
            fulfillment_state.value,
            ledger_state.value if ledger_state else None,
            "Fulfillment cannot be DELIVERED if settlement was never submitted or succeeded.",
        )
