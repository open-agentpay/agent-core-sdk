"""
AgentPay Three-Domain Payment Result & Lifecycle Status Contracts.
"""

from __future__ import annotations

from enum import Enum
from pydantic import BaseModel, ConfigDict, Field


class PaymentIntentStatus(str, Enum):
    """Business payment intent state."""

    CREATED = "CREATED"
    CHALLENGED = "CHALLENGED"
    AUTHORIZED = "AUTHORIZED"
    VERIFIED = "VERIFIED"
    COMPLETED = "COMPLETED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    NEEDS_REVIEW = "NEEDS_REVIEW"


class SettlementStatus(str, Enum):
    """Financial fund movement and blockchain settlement state."""

    NOT_STARTED = "NOT_STARTED"
    HELD = "HELD"
    SUBMITTED = "SUBMITTED"
    PENDING = "PENDING"
    CONFIRMED = "CONFIRMED"
    RELEASED = "RELEASED"
    FAILED = "FAILED"
    REORGED = "REORGED"
    UNKNOWN = "UNKNOWN"


class FulfillmentStatus(str, Enum):
    """Upstream API or tool delivery state."""

    NOT_STARTED = "NOT_STARTED"
    PROCESSING = "PROCESSING"
    DELIVERED = "DELIVERED"
    FAILED = "FAILED"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"


class PaymentResult(BaseModel):
    """
    Standard three-domain payment execution result contract.
    Decouples payment authorization, financial settlement, and upstream fulfillment.
    """

    model_config = ConfigDict(frozen=True, extra="allow")

    payment_intent_id: str = Field(description="Unique business payment intent identifier.")
    decision: str = Field(description="Policy decision (ALLOW, DENY, etc.).")
    payment_status: PaymentIntentStatus | str = Field(description="High-level payment intent status.")
    settlement_status: SettlementStatus | str = Field(description="Financial ledger or blockchain settlement status.")
    fulfillment_status: FulfillmentStatus | str = Field(description="Target resource fulfillment delivery status.")
    amount: str = Field(description="Total transacted amount formatted as decimal string.")
    asset: str = Field(description="Currency or asset symbol (e.g. 'USDC', 'CNY').")
    idempotency_key: str = Field(description="Client-provided idempotency key.")
    network: str | None = Field(default=None, description="Settlement network name.")
    transaction_hash: str | None = Field(default=None, description="Onchain transaction hash if applicable.")
    next_action: str | None = Field(default="NONE", description="Recommended next action (NONE, POLL_STATUS, WAIT_APPROVAL).")

    def is_settled(self) -> bool:
        """Returns True if financial settlement has reached terminal confirmation."""
        return self.settlement_status in (SettlementStatus.CONFIRMED, "CONFIRMED")

    def is_delivered(self) -> bool:
        """Returns True if upstream resource was successfully fulfilled."""
        return self.fulfillment_status in (FulfillmentStatus.DELIVERED, "DELIVERED")

    def is_in_progress(self) -> bool:
        """Returns True if settlement or fulfillment is still processing asynchronously."""
        pending_settlement = self.settlement_status in (
            SettlementStatus.HELD,
            SettlementStatus.SUBMITTED,
            SettlementStatus.PENDING,
            "HELD",
            "SUBMITTED",
            "PENDING",
        )
        processing_fulfillment = self.fulfillment_status in (
            FulfillmentStatus.PROCESSING,
            "PROCESSING",
        )
        return pending_settlement or processing_fulfillment

    def requires_recovery(self) -> bool:
        """Returns True if fulfillment failed or entered an uncertain state requiring manual review/recovery."""
        return (
            self.settlement_status in (SettlementStatus.UNKNOWN, "UNKNOWN")
            or self.fulfillment_status in (FulfillmentStatus.RECOVERY_REQUIRED, "RECOVERY_REQUIRED")
        )
