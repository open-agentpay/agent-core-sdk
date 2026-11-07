"""
Reconciliation Engine for AgentCore State Coordination.

Adheres strictly to:
  - CLAUDE.md §6: Nonce verification, fail-closed reconciliation, and validBefore window safety
  - specs/payment-state-machine.md §3, §4, §6: Decoupled Intent, Settlement, Fulfillment, and Ledger
  - P0-6 Invariant: Quota release permitted ONLY if nonce is proven unspent after (validBefore + safe_buffer)
  - Anti-Rollback Invariant: Upstream delivery failure never rolls back valid settlement
"""

from __future__ import annotations

import enum
from collections.abc import Callable
from typing import Any, Protocol

import httpx
from pydantic import BaseModel, ConfigDict, Field

from agent_core.core.state import (
    BudgetLedgerState,
    PaymentIntentState,
    SettlementState,
)

try:
    from agentpay_gateway.facilitator.client import FacilitatorClient
    from agentpay_gateway.facilitator.errors import (
        FacilitatorConnectionError,
        SettlementNotFoundError,
    )
except ImportError:  # pragma: no cover

    class FacilitatorConnectionError(Exception):  # type: ignore[no-redef]
        pass

    class SettlementNotFoundError(Exception):  # type: ignore[no-redef]
        pass

    FacilitatorClient = Any  # type: ignore[misc,assignment]

from agent_core.state.buyer_coordinator import BuyerStateCoordinator

# ---------------------------------------------------------------------------
# 1. Probe Interface and Data Models
# ---------------------------------------------------------------------------


class NonceStatus(str, enum.Enum):
    """Status of an EVM authorization nonce on-chain or at the Facilitator."""

    UNUSED = "UNUSED"
    USED = "USED"
    CANCELED = "CANCELED"
    UNKNOWN = "UNKNOWN"


class NonceProbeResult(BaseModel):
    """Result of querying a nonce state."""

    model_config = ConfigDict(frozen=True)

    status: NonceStatus
    tx_hash: str | None = None
    detail: str | None = None


class SettlementProbeResult(BaseModel):
    """Result of querying a settlement state."""

    model_config = ConfigDict(frozen=True)

    status: SettlementState
    tx_hash: str | None = None
    error: str | None = None


class ISettlementProbe(Protocol):
    """Protocol for probing blockchain and Facilitator settlement and nonce states."""

    def probe_settlement(self, settlement_id: str) -> SettlementProbeResult:
        """Query status of a settlement submission."""
        ...

    def probe_nonce(
        self,
        network_id: str,
        asset_address: str,
        payer_address: str,
        nonce: str,
    ) -> NonceProbeResult:
        """Query whether an authorization nonce has been spent on-chain or queued."""
        ...


class FacilitatorSettlementProbe:
    """Default probe backed by FacilitatorClient HTTP endpoints."""

    def __init__(self, client: FacilitatorClient) -> None:
        self.client = client

    def probe_settlement(self, settlement_id: str) -> SettlementProbeResult:
        try:
            status = self.client.get_settlement(settlement_id)
            core_state = SettlementState(status.status.value)
            return SettlementProbeResult(
                status=core_state,
                tx_hash=status.tx_hash,
                error=status.error,
            )
        except SettlementNotFoundError:
            return SettlementProbeResult(
                status=SettlementState.FAILED,
                error="Settlement not found on facilitator",
            )
        except (FacilitatorConnectionError, httpx.HTTPError) as exc:
            return SettlementProbeResult(
                status=SettlementState.UNKNOWN,
                error=f"Facilitator connection error: {exc}",
            )

    def probe_nonce(
        self,
        network_id: str,
        asset_address: str,
        payer_address: str,
        nonce: str,
    ) -> NonceProbeResult:
        try:
            is_used = self.client.is_nonce_used(
                network=network_id,
                asset=asset_address,
                payer=payer_address,
                nonce=nonce,
            )
            return NonceProbeResult(
                status=NonceStatus.USED if is_used else NonceStatus.UNUSED,
            )
        except (FacilitatorConnectionError, httpx.HTTPError) as exc:
            return NonceProbeResult(
                status=NonceStatus.UNKNOWN,
                detail=f"Facilitator connection error: {exc}",
            )


class MockSettlementProbe:
    """Configurable in-memory probe for testing reconciliation edges."""

    def __init__(self) -> None:
        self._settlements: dict[str, SettlementProbeResult] = {}
        self._nonces: dict[tuple[str, str, str, str], NonceProbeResult] = {}
        self.raise_on_probe: bool = False

    def set_settlement(
        self,
        settlement_id: str,
        status: SettlementState,
        *,
        tx_hash: str | None = None,
        error: str | None = None,
    ) -> None:
        self._settlements[settlement_id] = SettlementProbeResult(
            status=status,
            tx_hash=tx_hash,
            error=error,
        )

    def set_nonce(
        self,
        network_id: str,
        asset_address: str,
        payer_address: str,
        nonce: str,
        status: NonceStatus,
        *,
        tx_hash: str | None = None,
        detail: str | None = None,
    ) -> None:
        key = (
            network_id.lower(),
            asset_address.lower(),
            payer_address.lower(),
            nonce.lower(),
        )
        self._nonces[key] = NonceProbeResult(
            status=status,
            tx_hash=tx_hash,
            detail=detail,
        )

    def probe_settlement(self, settlement_id: str) -> SettlementProbeResult:
        if self.raise_on_probe:
            return SettlementProbeResult(
                status=SettlementState.UNKNOWN,
                error="Simulated network failure in probe",
            )
        if settlement_id not in self._settlements:
            return SettlementProbeResult(
                status=SettlementState.FAILED,
                error="Settlement not found",
            )
        return self._settlements[settlement_id]

    def probe_nonce(
        self,
        network_id: str,
        asset_address: str,
        payer_address: str,
        nonce: str,
    ) -> NonceProbeResult:
        if self.raise_on_probe:
            return NonceProbeResult(
                status=NonceStatus.UNKNOWN,
                detail="Simulated network failure in probe",
            )
        key = (
            network_id.lower(),
            asset_address.lower(),
            payer_address.lower(),
            nonce.lower(),
        )
        return self._nonces.get(
            key,
            NonceProbeResult(status=NonceStatus.UNUSED),
        )


# ---------------------------------------------------------------------------
# 2. Buyer Reconciliation Engine
# ---------------------------------------------------------------------------


class BuyerReconciliationOutcome(str, enum.Enum):
    """Outcome of reconciling a held buyer intent."""

    COMMITTED = "COMMITTED"
    RELEASED = "RELEASED"
    HELD = "HELD"
    SKIPPED_UNKNOWN = "SKIPPED_UNKNOWN"


class BuyerReconciliationReport(BaseModel):
    """Audit report for an individual buyer intent reconciliation attempt."""

    model_config = ConfigDict(frozen=True)

    intent_id: str = Field(..., alias="intentId")
    previous_intent_status: PaymentIntentState = Field(..., alias="previousIntentStatus")
    new_intent_status: PaymentIntentState = Field(..., alias="newIntentStatus")
    ledger_state: BudgetLedgerState = Field(..., alias="ledgerState")
    outcome: BuyerReconciliationOutcome
    reason: str


class BuyerReconciler:
    """
    Reconciliation worker for Buyer agents.

    Scans payment intents in RECOVERY_HOLD (or stuck SIGNATURE_SENT) and audits
    blockchain/Facilitator state to safely commit or release the local budget quota.

    Enforces CLAUDE.md Invariant:
      Quota release is strictly forbidden unless:
        1. Nonce is proven UNSPENT on-chain, AND
        2. current_time > validBefore + safe_buffer_seconds
    """

    def __init__(
        self,
        coordinator: BuyerStateCoordinator,
        probe: ISettlementProbe,
        *,
        clock: Callable[[], int] | None = None,
        safe_buffer_seconds: int = 60,
        in_flight_timeout_seconds: int = 30,
    ) -> None:
        self.coordinator = coordinator
        self.probe = probe
        self._clock = clock or coordinator.get_time
        self.safe_buffer_seconds = safe_buffer_seconds
        self.in_flight_timeout_seconds = in_flight_timeout_seconds

    def get_time(self) -> int:
        return self._clock()

    def reconcile_intent(self, intent_id: str) -> BuyerReconciliationReport:
        """
        Reconcile a single intent by ID.

        Returns:
            BuyerReconciliationReport with final statuses and outcome.
        """
        now = self.get_time()
        record = self.coordinator.get_intent(intent_id)
        if not record:
            raise ValueError(f"Buyer intent '{intent_id}' not found.")

        prev_status = record.status
        ledger_state = self.coordinator.get_ledger_state(intent_id) or BudgetLedgerState.RELEASED

        # Pre-check: If intent is still in SIGNATURE_SENT but timed out, transition to RECOVERY_HOLD
        if prev_status == PaymentIntentState.SIGNATURE_SENT:
            if now - record.updated_at >= self.in_flight_timeout_seconds:
                self.coordinator.hold_intent(intent_id)
                record = self.coordinator.get_intent(intent_id)
                assert record is not None
                prev_status = record.status
            else:
                # Still within in-flight timeout, leave untouched
                return BuyerReconciliationReport(
                    intentId=intent_id,
                    previousIntentStatus=prev_status,
                    newIntentStatus=prev_status,
                    ledgerState=ledger_state,
                    outcome=BuyerReconciliationOutcome.HELD,
                    reason="In-flight dispatch still active; waiting for response",
                )

        # Only intents in RECOVERY_HOLD are reconciled
        if record.status != PaymentIntentState.RECOVERY_HOLD:
            return BuyerReconciliationReport(
                intentId=intent_id,
                previousIntentStatus=prev_status,
                newIntentStatus=record.status,
                ledgerState=ledger_state,
                outcome=BuyerReconciliationOutcome.HELD,
                reason=f"Intent status '{record.status.value}' is not held for recovery",
            )

        if not record.nonce:
            # Without a nonce, no signature was ever generated
            return BuyerReconciliationReport(
                intentId=intent_id,
                previousIntentStatus=prev_status,
                newIntentStatus=record.status,
                ledgerState=ledger_state,
                outcome=BuyerReconciliationOutcome.SKIPPED_UNKNOWN,
                reason="Intent has no recorded nonce",
            )

        # Probe nonce state on Facilitator / blockchain
        probe_res = self.probe.probe_nonce(
            network_id=record.network_id,
            asset_address=record.asset_address,
            payer_address=record.payer_address,
            nonce=record.nonce,
        )

        # Case 1: Nonce was confirmed used on-chain / Facilitator
        if probe_res.status == NonceStatus.USED:
            self.coordinator.complete_intent(intent_id)
            updated_intent = self.coordinator.get_intent(intent_id)
            assert updated_intent is not None
            updated_ledger = self.coordinator.get_ledger_state(intent_id) or BudgetLedgerState.COMMITTED
            return BuyerReconciliationReport(
                intentId=intent_id,
                previousIntentStatus=prev_status,
                newIntentStatus=updated_intent.status,
                ledgerState=updated_ledger,
                outcome=BuyerReconciliationOutcome.COMMITTED,
                reason="Nonce was settled on-chain; quota permanently committed",
            )

        # Case 2: Nonce is UNUSED (or CANCELED)
        if probe_res.status in (NonceStatus.UNUSED, NonceStatus.CANCELED):
            valid_before = record.valid_before or 0
            safe_expiry = valid_before + self.safe_buffer_seconds

            if now > safe_expiry:
                # Authorization window has safely expired and nonce was unspent!
                # It is 100% mathematically impossible for funds to be debited. Safe to release!
                self.coordinator.reconcile_release(
                    intent_id,
                    reason=f"Nonce confirmed unspent and validBefore expired ({now} > {safe_expiry})",
                )
                updated_intent = self.coordinator.get_intent(intent_id)
                assert updated_intent is not None
                updated_ledger = self.coordinator.get_ledger_state(intent_id) or BudgetLedgerState.RELEASED
                return BuyerReconciliationReport(
                    intentId=intent_id,
                    previousIntentStatus=prev_status,
                    newIntentStatus=updated_intent.status,
                    ledgerState=updated_ledger,
                    outcome=BuyerReconciliationOutcome.RELEASED,
                    reason=f"Authorization expired ({now} > {safe_expiry}) with unspent nonce; quota released",
                )
            else:
                # Anti-Double-Spend Guard: validBefore has NOT expired yet!
                # Even if probe currently says UNUSED, a tx could still be in mempool or miner queue.
                return BuyerReconciliationReport(
                    intentId=intent_id,
                    previousIntentStatus=prev_status,
                    newIntentStatus=record.status,
                    ledgerState=ledger_state,
                    outcome=BuyerReconciliationOutcome.HELD,
                    reason=f"Authorization still within validBefore window ({now} <= {safe_expiry}); preserving RESERVED",
                )

        # Case 3: Probe status is UNKNOWN (network error, timeout, RPC split)
        # Fail-closed: Must keep quota locked in RESERVED
        return BuyerReconciliationReport(
            intentId=intent_id,
            previousIntentStatus=prev_status,
            newIntentStatus=record.status,
            ledgerState=ledger_state,
            outcome=BuyerReconciliationOutcome.SKIPPED_UNKNOWN,
            reason=f"Probe returned UNKNOWN ({probe_res.detail or 'no detail'}); fail-closed preserve RESERVED",
        )

    def reconcile_all_held(self) -> list[BuyerReconciliationReport]:
        """Scan and reconcile all intents currently in RECOVERY_HOLD or timed-out SIGNATURE_SENT."""
        intents = self.coordinator.list_intents(
            [
                PaymentIntentState.RECOVERY_HOLD,
                PaymentIntentState.SIGNATURE_SENT,
            ]
        )
        reports: list[BuyerReconciliationReport] = []
        for it in intents:
            rep = self.reconcile_intent(it.intent_id)
            reports.append(rep)
        return reports
