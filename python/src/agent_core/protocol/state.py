"""
Core Multi-Dimensional State Enums and Entity Models for AgentCore.

Defines the four orthogonal state objects adhering to specs/payment-state-machine.md:
  1. PaymentIntentState  (Buyer request lifecycle)
  2. SettlementState     (Blockchain / clearing funds transfer)
  3. FulfillmentState    (Upstream API / resource payload delivery)
  4. BudgetLedgerState   (Buyer firewall local quota reservation)
"""

from __future__ import annotations

import enum

from pydantic import BaseModel, ConfigDict, Field


class PaymentIntentState(str, enum.Enum):
    """
    State of the Buyer's high-level business purchase request.
    Tracks the lifecycle from initial 402 challenge to final receipt.
    """

    CREATED = "CREATED"  # Challenge received and parsed
    AUTHORIZED = "AUTHORIZED"  # Policy firewall approved and quota reserved
    PROCESSING = "PROCESSING"  # In-flight (signing or dispatched to network)
    SIGNATURE_SENT = "SIGNATURE_SENT"  # Request dispatched with PAYMENT-SIGNATURE
    COMPLETED = "COMPLETED"  # Delivered successfully with 2xx
    SUCCEEDED = "SUCCEEDED"  # Alias for COMPLETED
    REJECTED = "REJECTED"  # Policy denied or expired unspent
    EXPIRED = "EXPIRED"  # Challenge expired before processing
    CANCELLED = "CANCELLED"  # Pre-flight abort before network dispatch
    RECOVERY_HOLD = "RECOVERY_HOLD"  # In-flight ambiguity / 5xx error; held for retry


class SettlementState(str, enum.Enum):
    """
    State of financial settlement and blockchain clearing.
    Managed by Seller Gateway and Facilitator clearing nodes.
    """

    NOT_STARTED = "NOT_STARTED"  # Initial state; verified but not submitted
    NOT_SUBMITTED = "NOT_SUBMITTED"  # Alias for NOT_STARTED
    SUBMITTED = "SUBMITTED"  # Enqueued to Facilitator clearing queue
    PENDING = "PENDING"  # Broadcasted to mempool, awaiting confirmations
    CONFIRMED = "CONFIRMED"  # Confirmed on-chain with sufficient blocks
    SUCCESS = "SUCCESS"  # Alias for CONFIRMED
    FAILED = "FAILED"  # Definitive settlement rejection or revert
    REORGED = "REORGED"  # Block re-org evicted tx; requires resubmission
    UNKNOWN = "UNKNOWN"  # RPC timeout / latency spike during polling


class FulfillmentState(str, enum.Enum):
    """
    State of upstream API resource payload delivery to the client.
    Tracks whether the client actually received the paid service.
    """

    NOT_STARTED = "NOT_STARTED"  # Initial state; payment verified, not yet dispatched
    NOT_DELIVERED = "NOT_DELIVERED"  # Alias for NOT_STARTED
    PROCESSING = "PROCESSING"  # Request in-flight to upstream business target
    DELIVERING = "DELIVERING"  # Alias for PROCESSING
    DELIVERED = "DELIVERED"  # Upstream returned 2xx; payload delivered to client
    FAILED = "FAILED"  # Terminal delivery failure
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"  # Upstream 5xx/timeout; payment kept, ready for free retry


class BudgetLedgerState(str, enum.Enum):
    """
    State of the Buyer's local financial firewall quota reservation.
    Strict three-state mathematical invariant (P0-6).
    """

    RESERVED = "RESERVED"  # Atomically locked; counts toward usage ceiling
    COMMITTED = "COMMITTED"  # Permanently finalized after successful delivery
    RELEASED = "RELEASED"  # Safely restored to available budget pool


# ---------------------------------------------------------------------------
# Entity Models (matching SQLite Schema rows)
# ---------------------------------------------------------------------------


class BuyerIntentRecord(BaseModel):
    """Represents a row in ap_buyer_intent table."""

    model_config = ConfigDict(frozen=True, populate_by_name=True)

    intent_id: str = Field(..., alias="intentId")
    policy_id: str = Field(..., alias="policyId")
    idempotency_key: str = Field(..., alias="idempotencyKey")
    payer_address: str = Field(..., alias="payerAddress")
    payee_address: str = Field(..., alias="payeeAddress")
    asset_address: str = Field(..., alias="assetAddress")
    network_id: str = Field(..., alias="networkId")
    amount_base_units: int = Field(..., alias="amountBaseUnits")
    status: PaymentIntentState = PaymentIntentState.CREATED
    nonce: str | None = None
    valid_after: int | None = Field(default=None, alias="validAfter")
    valid_before: int | None = Field(default=None, alias="validBefore")
    raw_signature: str | None = Field(default=None, alias="rawSignature")
    created_at: int = Field(default=0, alias="createdAt")
    updated_at: int = Field(default=0, alias="updatedAt")


class GatewaySettlementRecord(BaseModel):
    """Represents a row in ap_gateway_settlement table."""

    model_config = ConfigDict(frozen=True, populate_by_name=True)

    settlement_id: str = Field(..., alias="settlementId")
    idempotency_key: str = Field(..., alias="idempotencyKey")
    payer_address: str = Field(..., alias="payerAddress")
    payee_address: str = Field(..., alias="payeeAddress")
    asset_address: str = Field(..., alias="assetAddress")
    network_id: str = Field(..., alias="networkId")
    amount_base_units: int = Field(..., alias="amountBaseUnits")
    nonce: str
    valid_after: int = Field(..., alias="validAfter")
    valid_before: int = Field(..., alias="validBefore")
    raw_signature: str = Field(..., alias="rawSignature")
    status: SettlementState = SettlementState.NOT_STARTED
    tx_hash: str | None = Field(default=None, alias="txHash")
    block_number: int | None = Field(default=None, alias="blockNumber")
    error_message: str | None = Field(default=None, alias="errorMessage")
    created_at: int = Field(default=0, alias="createdAt")
    updated_at: int = Field(default=0, alias="updatedAt")


class GatewayFulfillmentRecord(BaseModel):
    """Represents a row in ap_gateway_fulfillment table."""

    model_config = ConfigDict(frozen=True, populate_by_name=True)

    fulfillment_id: str = Field(..., alias="fulfillmentId")
    settlement_id: str = Field(..., alias="settlementId")
    status: FulfillmentState = FulfillmentState.NOT_STARTED
    upstream_status_code: int | None = Field(default=None, alias="upstreamStatusCode")
    response_hash: str | None = Field(default=None, alias="responseHash")
    retry_count: int = Field(default=0, alias="retryCount")
    delivered_at: int | None = Field(default=None, alias="deliveredAt")
    created_at: int = Field(default=0, alias="createdAt")
    updated_at: int = Field(default=0, alias="updatedAt")


class IdempotencyRecord(BaseModel):
    """Represents a row in ap_idempotency_cache table."""

    model_config = ConfigDict(frozen=True, populate_by_name=True)

    payer_address: str = Field(..., alias="payerAddress")
    idempotency_key: str = Field(..., alias="idempotencyKey")
    settlement_id: str | None = Field(default=None, alias="settlementId")
    status: str = "IN_FLIGHT"  # IN_FLIGHT, COMPLETED, FAILED
    request_hash: str = Field(..., alias="requestHash")
    response_status_code: int | None = Field(default=None, alias="responseStatusCode")
    response_headers_json: str | None = Field(default=None, alias="responseHeadersJson")
    response_body_blob: bytes | None = Field(default=None, alias="responseBodyBlob")
    locked_until: int = Field(..., alias="lockedUntil")
    expires_at: int = Field(..., alias="expiresAt")
    created_at: int = Field(default=0, alias="createdAt")
