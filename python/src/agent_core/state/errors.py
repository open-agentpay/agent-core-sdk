"""
State transition and coordination exceptions for AgentCore.

Defines standardized error types for illegal lifecycle mutations and safety violations:
  - IllegalStateTransitionError
  - SignatureSentReleaseForbiddenError
  - OrphanedSettlementRollbackForbiddenError
  - InvalidCompositeStateError
  - IdempotencyLockConflictError
"""

from __future__ import annotations


class StateCoordinationError(Exception):
    """Base exception for all state machine and coordination errors."""


class IllegalStateTransitionError(StateCoordinationError):
    """Raised when an entity attempts a state transition forbidden by transition guards."""

    def __init__(
        self,
        entity_type: str,
        from_state: str,
        to_state: str,
        detail: str = "",
    ) -> None:
        self.entity_type = entity_type
        self.from_state = from_state
        self.to_state = to_state
        self.detail = detail
        msg = f"Illegal {entity_type} state transition from '{from_state}' to '{to_state}'"
        if detail:
            msg += f": {detail}"
        super().__init__(msg)


class SignatureSentReleaseForbiddenError(StateCoordinationError):
    """
    CLAUDE.md Invariant Guardrail:
    Raised when an attempt is made to cancel or release budget quota for an intent
    that has already crossed the network boundary (SIGNATURE_SENT or RECOVERY_HOLD).
    """

    def __init__(self, intent_id: str, current_state: str) -> None:
        self.intent_id = intent_id
        self.current_state = current_state
        super().__init__(
            f"Cannot release or cancel intent '{intent_id}' in state '{current_state}': "
            "Cryptographic signature has already been transmitted on the wire. "
            "Quota must remain RESERVED until reconciliation or successful retry."
        )


class OrphanedSettlementRollbackForbiddenError(StateCoordinationError):
    """
    Raised when an attempt is made to rollback or void a settlement that has already
    been verified or enqueued (SUBMITTED, PENDING, or SUCCESS) due to an upstream service error.
    """

    def __init__(self, settlement_id: str, settlement_state: str) -> None:
        self.settlement_id = settlement_id
        self.settlement_state = settlement_state
        super().__init__(
            f"Cannot void settlement '{settlement_id}' in state '{settlement_state}': "
            "Payment verification succeeded and funds transfer is active. "
            "Upstream fulfillment failures must not rollback settlement."
        )


class InvalidCompositeStateError(StateCoordinationError):
    """Raised when the multi-system composite state combination violates legal invariants."""

    def __init__(
        self,
        intent_state: str,
        settlement_state: str,
        fulfillment_state: str,
        ledger_state: str | None,
        reason: str,
    ) -> None:
        self.intent_state = intent_state
        self.settlement_state = settlement_state
        self.fulfillment_state = fulfillment_state
        self.ledger_state = ledger_state
        self.reason = reason
        super().__init__(
            f"Invalid composite state (Intent={intent_state}, Settlement={settlement_state}, "
            f"Fulfillment={fulfillment_state}, Ledger={ledger_state}): {reason}"
        )


class IdempotencyLockConflictError(StateCoordinationError):
    """Raised when a concurrent request attempts to acquire an active idempotency lease."""

    def __init__(self, payer_address: str, idempotency_key: str, locked_until: int) -> None:
        self.payer_address = payer_address
        self.idempotency_key = idempotency_key
        self.locked_until = locked_until
        super().__init__(
            f"Concurrent request in-flight for ({payer_address}, {idempotency_key}). "
            f"Lease locked until Unix timestamp {locked_until}."
        )
