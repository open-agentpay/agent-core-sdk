"""
Core x402 V2 Protocol Models.

Defines frozen, byte-conforming Pydantic v2 value objects for x402 V2
PaymentChallenge and PaymentAuthorization protocols.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from agent_core.core.errors import (
    X402ErrorCode,
    X402ValidationError,
    map_pydantic_error_to_x402,
)

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# CAIP-2: namespace:reference  (e.g. eip155:84532)
# Strictly adheres to CAIP-2 specification and test vector regex
_CAIP2_RE = re.compile(r"^[a-z0-9]+:[a-zA-Z0-9_-]+$")

# Canonical 20-byte hex address: 0x followed by exactly 40 hex chars
_HEX_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

# 32-byte hex nonce: 0x followed by 64 hex chars (or 64 hex chars without 0x)
_NONCE_HEX_RE = re.compile(r"^(0x)?[0-9a-fA-F]{64}$")

# 32-byte r or s hex: 0x followed by 64 hex chars (or 64 hex chars without 0x)
_BYTES32_HEX_RE = re.compile(r"^(0x)?[0-9a-fA-F]{64}$")

# Maximum signed 64-bit integer for base units
SQLITE_MAX_INT = 9_223_372_036_854_775_807

# Supported fiat base currencies for AgentCore internal virtual wallet
WALLET_FIAT_CURRENCIES = frozenset({"CNY", "USD", "EUR"})


def _validate_hex_address(value: str, field_name: str) -> str:
    """Validate hex address format and normalise to lowercase."""
    if not isinstance(value, str) or not _HEX_ADDRESS_RE.match(value):
        raise X402ValidationError(
            f"{field_name}: invalid address format: {value!r}. Must be 0x followed by 40 hexadecimal characters.",
            code=X402ErrorCode.INVALID_ADDRESS,
        )
    return value.lower()


def _validate_caip2(value: str) -> str:
    """Validate CAIP-2 chain identifier format."""
    if not isinstance(value, str) or not _CAIP2_RE.match(value):
        raise X402ValidationError(
            f"Invalid CAIP-2 network identifier: {value!r}. Expected format: namespace:reference (e.g. eip155:84532).",
            code=X402ErrorCode.NETWORK_NOT_WHITELISTED,
        )
    return value


# ---------------------------------------------------------------------------
# PaymentChallenge (402 PAYMENT-REQUIRED payload)
# ---------------------------------------------------------------------------


class PaymentChallenge(BaseModel):
    """
    x402 V2 payment challenge payload emitted by a seller in an HTTP 402 response.
    Corresponds to the PAYMENT-REQUIRED header.
    """

    model_config = ConfigDict(frozen=True, populate_by_name=True, extra="allow")

    version: str = Field(default="2.0", description="Protocol version, fixed to 2.0")
    challenge_id: str = Field(..., alias="challengeId", description="Globally unique challenge ID")
    scheme: str = Field(default="agentpay-wallet", description="Payment authorization scheme")
    network: str | None = Field(default=None, description="CAIP-2 network or AgentCore internal ledger")
    asset: str | None = Field(default=None, description="Payment asset identifier")
    asset_symbol: str | None = Field(default=None, alias="assetSymbol", description="Token symbol")
    decimals: int = Field(default=6, description="Token decimals")
    amount: str = Field(..., description="Payment amount in integer base units as string")
    payee: str | None = Field(default=None, description="Recipient identifier or AgentCore route resource")
    valid_after: int = Field(..., alias="validAfter", description="Unix timestamp valid after (seconds)")
    valid_before: int = Field(..., alias="validBefore", description="Unix timestamp valid before (seconds)")
    facilitator_url: str | None = Field(
        default=None, alias="facilitatorUrl", description="Facilitator clearing endpoint URL"
    )
    resource_uri: str | None = Field(default=None, alias="resourceUri", description="Protected resource path")
    extensions: dict[str, Any] | None = None

    @model_validator(mode="before")
    @classmethod
    def _default_scheme(cls, data: Any) -> Any:
        if isinstance(data, dict) and "scheme" not in data:
            net = data.get("network")
            if net == "agentpay:internal-ledger" or data.get("asset") in WALLET_FIAT_CURRENCIES:
                data["scheme"] = "agentpay-wallet"
            elif net or data.get("facilitatorUrl") or data.get("facilitator_url"):
                data["scheme"] = "transfer-authorization"
        return data

    def __init__(self, /, **data: Any) -> None:
        try:
            super().__init__(**data)
        except X402ValidationError:
            raise
        except ValidationError as exc:
            raise map_pydantic_error_to_x402(exc) from exc

    @classmethod
    def model_validate(
        cls,
        obj: Any,
        *,
        strict: bool | None = None,
        from_attributes: bool | None = None,
        context: Any | None = None,
        by_alias: bool | None = None,
        by_name: bool | None = None,
    ) -> PaymentChallenge:
        try:
            return super().model_validate(
                obj,
                strict=strict,
                from_attributes=from_attributes,
                context=context,
                by_alias=by_alias,
                by_name=by_name,
            )
        except X402ValidationError:
            raise
        except ValidationError as exc:
            raise map_pydantic_error_to_x402(exc) from exc

    @field_validator("version")
    @classmethod
    def _validate_version(cls, v: str) -> str:
        if v != "2.0":
            raise X402ValidationError(
                f"Unsupported protocol version: {v!r}. Expected '2.0'.",
                code=X402ErrorCode.UNSUPPORTED_VERSION,
            )
        return v

    @field_validator("challenge_id")
    @classmethod
    def _validate_challenge_id(cls, v: str) -> str:
        if not v or not v.strip():
            raise X402ValidationError(
                "challengeId cannot be empty.",
                code=X402ErrorCode.MISSING_REQUIRED_FIELD,
            )
        return v.strip()

    @field_validator("network")
    @classmethod
    def _validate_network(cls, v: str | None, info: Any) -> str | None:
        if v is None:
            return None
        clean = v.strip()
        if clean.startswith("agentpay:") or clean.startswith("agent-core-sdk:"):
            return clean
        return _validate_caip2(clean)

    @field_validator("asset")
    @classmethod
    def _validate_asset(cls, v: str | None, info: Any) -> str | None:
        if v is None:
            return None
        clean = v.strip()
        if clean.startswith("0x"):
            return _validate_hex_address(clean, "asset")
        return clean

    @field_validator("payee")
    @classmethod
    def _validate_payee(cls, v: str | None, info: Any) -> str | None:
        if v is None:
            return None
        clean = v.strip()
        if clean.startswith("0x"):
            return _validate_hex_address(clean, "payee")
        return clean

    @field_validator("decimals")
    @classmethod
    def _validate_decimals(cls, v: int) -> int:
        if isinstance(v, bool) or not isinstance(v, int):
            raise X402ValidationError(
                f"decimals must be an integer, got {type(v).__name__}",
                code=X402ErrorCode.INVALID_AMOUNT_FORMAT,
            )
        if v < 0 or v > 36:
            raise X402ValidationError(
                f"decimals out of range: {v}. Expected 0 to 36.",
                code=X402ErrorCode.INVALID_AMOUNT_FORMAT,
            )
        return v

    @field_validator("amount", mode="before")
    @classmethod
    def _validate_amount(cls, v: Any) -> str:
        if v is None:
            raise X402ValidationError(
                "amount is a required field.",
                code=X402ErrorCode.MISSING_REQUIRED_FIELD,
            )
        if isinstance(v, bool):
            raise X402ValidationError(
                "amount cannot be boolean.",
                code=X402ErrorCode.INVALID_AMOUNT_FORMAT,
            )
        if isinstance(v, float):
            raise X402ValidationError(
                "amount cannot be float (precision loss risk). Use integer base units string.",
                code=X402ErrorCode.INVALID_AMOUNT_FORMAT,
            )
        try:
            val_int = int(v)
        except (ValueError, TypeError) as exc:
            raise X402ValidationError(
                f"Invalid amount format: {v!r}. Must be a positive integer base units.",
                code=X402ErrorCode.INVALID_AMOUNT_FORMAT,
            ) from exc

        if val_int <= 0:
            raise X402ValidationError(
                f"amount must be strictly positive (> 0), got {val_int}.",
                code=X402ErrorCode.INVALID_AMOUNT_FORMAT,
            )
        if val_int > SQLITE_MAX_INT:
            raise X402ValidationError(
                f"amount exceeds supported maximum int64 ({SQLITE_MAX_INT}).",
                code=X402ErrorCode.INVALID_AMOUNT_FORMAT,
            )
        return str(val_int)

    @field_validator("valid_after", "valid_before", mode="before")
    @classmethod
    def _validate_timestamp(cls, v: Any, info: Any) -> int:
        if isinstance(v, bool) or not isinstance(v, (int, str)):
            raise X402ValidationError(
                f"{info.field_name} must be integer Unix seconds, got {type(v).__name__}",
                code=X402ErrorCode.INVALID_TIME_WINDOW,
            )
        try:
            val = int(v)
        except ValueError as exc:
            raise X402ValidationError(
                f"{info.field_name} must be integer Unix seconds, got {v!r}",
                code=X402ErrorCode.INVALID_TIME_WINDOW,
            ) from exc
        if val < 0:
            raise X402ValidationError(
                f"{info.field_name} cannot be negative, got {val}",
                code=X402ErrorCode.INVALID_TIME_WINDOW,
            )
        return val

    @model_validator(mode="after")
    def _validate_time_window(self) -> PaymentChallenge:
        if self.valid_before <= self.valid_after:
            raise X402ValidationError(
                f"Invalid time window: validBefore ({self.valid_before}) must be strictly "
                f"greater than validAfter ({self.valid_after}).",
                code=X402ErrorCode.INVALID_TIME_WINDOW,
            )
        return self

    @model_validator(mode="after")
    def _validate_scheme_fields(self) -> PaymentChallenge:
        if self.scheme == "agentpay-wallet":
            if (
                self.network != "agentpay:internal-ledger"
                or self.asset not in WALLET_FIAT_CURRENCIES
                or not self.resource_uri
            ):
                raise X402ValidationError("invalid agentpay-wallet challenge fields", code=X402ErrorCode.INVALID_SCHEME)
        elif not self.network or not self.asset or not self.payee:
            raise X402ValidationError(
                f"{self.scheme} challenge requires network, asset, and payee",
                code=X402ErrorCode.MISSING_REQUIRED_FIELD,
            )
        return self

    @property
    def amount_base_units(self) -> int:
        """Payment amount parsed into integer base units."""
        return int(self.amount)

    def is_expired(self, current_time: int) -> bool:
        """Check if challenge expiration deadline has passed."""
        return current_time > self.valid_before

    def to_payment_request(
        self,
        *,
        intent_id: str | None = None,
        domain: str | None = None,
        ttl_seconds: int = 360,
    ) -> Any:
        """
        Convert this x402 challenge into an AgentCore policy PaymentRequest
        for evaluation and atomic reservation against the local financial firewall.
        """
        # Lazy import to avoid circular dependency
        from agent_core.policy.models import PaymentRequest

        return PaymentRequest(
            intent_id=intent_id or self.challenge_id,
            amount=self.amount_base_units,
            payee=self.payee or "agentpay:route:unknown",
            asset=self.asset or "USD",
            network=self.network or "agentpay:internal-ledger",
            domain=domain,
            ttl_seconds=ttl_seconds,
        )


# ---------------------------------------------------------------------------
# PaymentAuthorization (402 PAYMENT-SIGNATURE payload)
# ---------------------------------------------------------------------------


class PaymentAuthorization(BaseModel):
    """
    x402 V2 payment authorization payload generated by a client after policy approval.
    Replayed in the PAYMENT-SIGNATURE request header.
    """

    model_config = ConfigDict(frozen=True, populate_by_name=True)

    version: str = Field(default="2.0", description="Protocol version, fixed to 2.0")
    challenge_id: str = Field(..., alias="challengeId", description="Challenge ID being satisfied")
    payer: str = Field(..., description="Payer address or identity identifier")
    scheme: str = Field(default="agentpay-wallet", description="Payment authorization scheme")
    nonce: str = Field(..., description="Unique payment nonce")
    valid_after: int = Field(..., alias="validAfter", description="Unix timestamp valid after (seconds)")
    valid_before: int = Field(..., alias="validBefore", description="Unix timestamp valid before (seconds)")
    signature: Any = Field(..., description="Cryptographic signature or authorization proof")

    _signature_factory: Any = None

    @classmethod
    def register_signature_factory(cls, factory: Any) -> None:
        """Register pluggable signature factory for downstream Web3/EVM signature decoding."""
        cls._signature_factory = factory

    def __init__(self, /, **data: Any) -> None:
        try:
            super().__init__(**data)
        except X402ValidationError:
            raise
        except ValidationError as exc:
            raise map_pydantic_error_to_x402(exc) from exc

    @classmethod
    def model_validate(
        cls,
        obj: Any,
        *,
        strict: bool | None = None,
        from_attributes: bool | None = None,
        context: Any | None = None,
        by_alias: bool | None = None,
        by_name: bool | None = None,
    ) -> PaymentAuthorization:
        try:
            return super().model_validate(
                obj,
                strict=strict,
                from_attributes=from_attributes,
                context=context,
                by_alias=by_alias,
                by_name=by_name,
            )
        except X402ValidationError:
            raise
        except ValidationError as exc:
            raise map_pydantic_error_to_x402(exc) from exc

    @field_validator("version")
    @classmethod
    def _validate_version(cls, v: str) -> str:
        if v != "2.0":
            raise X402ValidationError(
                f"Unsupported protocol version: {v!r}. Expected '2.0'.",
                code=X402ErrorCode.UNSUPPORTED_VERSION,
            )
        return v

    @field_validator("payer")
    @classmethod
    def _validate_payer(cls, v: str) -> str:
        clean = str(v).strip()
        if not clean:
            raise X402ValidationError("payer is required", code=X402ErrorCode.MISSING_REQUIRED_FIELD)
        if clean.startswith("0x"):
            return _validate_hex_address(clean, "payer")
        return clean

    @field_validator("nonce")
    @classmethod
    def _validate_nonce(cls, v: str) -> str:
        if not isinstance(v, str) or not v.strip():
            raise X402ValidationError(
                f"Invalid nonce: {v!r}. Must be a non-empty string.",
                code=X402ErrorCode.INVALID_NONCE,
            )
        clean = v.strip()
        if clean.startswith("0x"):
            if not _NONCE_HEX_RE.match(clean):
                raise X402ValidationError(
                    f"Invalid nonce format: {clean}",
                    code=X402ErrorCode.INVALID_NONCE,
                )
            return clean.lower()
        return clean

    @field_validator("signature", mode="before")
    @classmethod
    def _validate_signature(cls, v: Any) -> Any:
        if isinstance(v, str):
            clean_str = v.strip()
            if not clean_str:
                raise X402ValidationError(
                    "signature string cannot be empty.",
                    code=X402ErrorCode.INVALID_SIGNATURE,
                )
            return clean_str
        if isinstance(v, Mapping):
            if cls._signature_factory is not None:
                return cls._signature_factory(v)
            return dict(v)
        if v is not None:
            return v
        raise X402ValidationError(
            f"Invalid signature format: expected dict or hex string, got {type(v).__name__}",
            code=X402ErrorCode.INVALID_SIGNATURE,
        )

    @model_validator(mode="after")
    def _validate_time_window(self) -> PaymentAuthorization:
        if self.valid_before <= self.valid_after:
            raise X402ValidationError(
                f"Invalid time window: validBefore ({self.valid_before}) must be strictly "
                f"greater than validAfter ({self.valid_after}).",
                code=X402ErrorCode.INVALID_TIME_WINDOW,
            )
        return self


class WalletAuthorization(BaseModel):
    """AgentCore's API-key-authenticated wallet approval payload (not a cryptographic signature)."""

    model_config = ConfigDict(frozen=True, populate_by_name=True)

    version: str = "2.0"
    challenge_id: str = Field(..., alias="challengeId")
    scheme: str = "agentpay-wallet"
    nonce: str
    valid_after: int = Field(..., alias="validAfter")
    valid_before: int = Field(..., alias="validBefore")
    amount: str
    resource_uri: str = Field(..., alias="resourceUri")
    request_binding: str = Field(..., alias="requestBinding")

    @field_validator("nonce")
    @classmethod
    def _validate_wallet_nonce(cls, value: str) -> str:
        if not re.fullmatch(r"0x[0-9a-f]{64}", value):
            raise X402ValidationError(
                "wallet nonce must be 32 random bytes encoded as lowercase hex", code=X402ErrorCode.INVALID_NONCE
            )
        return value

    @field_validator("amount")
    @classmethod
    def _validate_wallet_amount(cls, value: str) -> str:
        if not value.isdecimal() or int(value) <= 0 or int(value) > SQLITE_MAX_INT:
            raise X402ValidationError(
                "wallet amount must be a positive int64 decimal string", code=X402ErrorCode.INVALID_AMOUNT_FORMAT
            )
        return value

    @model_validator(mode="after")
    def _validate_wallet_fields(self) -> WalletAuthorization:
        if self.version != "2.0" or self.scheme != "agentpay-wallet" or self.valid_before <= self.valid_after:
            raise X402ValidationError("invalid agentpay-wallet authorization fields", code=X402ErrorCode.INVALID_SCHEME)
        if (
            not self.challenge_id
            or not self.resource_uri
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", self.request_binding)
        ):
            raise X402ValidationError(
                "wallet authorization is missing challenge binding fields", code=X402ErrorCode.MISSING_REQUIRED_FIELD
            )
        return self
