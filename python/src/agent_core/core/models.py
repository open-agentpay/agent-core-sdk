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

# Canonical EVM address: 0x followed by exactly 40 hex chars
_EVM_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

# 32-byte hex nonce: 0x followed by 64 hex chars (or 64 hex chars without 0x)
_NONCE_HEX_RE = re.compile(r"^(0x)?[0-9a-fA-F]{64}$")

# 32-byte r or s hex: 0x followed by 64 hex chars (or 64 hex chars without 0x)
_BYTES32_HEX_RE = re.compile(r"^(0x)?[0-9a-fA-F]{64}$")

# Maximum signed 64-bit integer for base units
SQLITE_MAX_INT = 9_223_372_036_854_775_807

# Supported fiat base currencies for AgentCore internal virtual wallet
WALLET_FIAT_CURRENCIES = frozenset({"CNY", "USD", "EUR"})


def _validate_evm_address(value: str, field_name: str) -> str:
    """Validate EVM address format and normalise to lowercase."""
    if not isinstance(value, str) or not _EVM_ADDRESS_RE.match(value):
        raise X402ValidationError(
            f"{field_name}: invalid EVM address format: {value!r}. Must be 0x followed by 40 hexadecimal characters.",
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
# SignatureData
# ---------------------------------------------------------------------------


class SignatureData(BaseModel):
    """
    Structured EIP-712/3009 cryptographic signature components.
    Supports individual (v, r, s) tuples as well as concatenated compact/serialized formats.
    """

    model_config = ConfigDict(frozen=True, populate_by_name=True)

    v: int
    r: str
    s: str
    serialized: str | None = None
    compact: str | None = None

    @field_validator("v")
    @classmethod
    def _validate_v(cls, v: int) -> int:
        if v not in (27, 28, 0, 1) and v < 35:
            # Allow common v ranges (including EIP-155 if applicable)
            raise X402ValidationError(
                f"Invalid signature v value: {v}. Expected 27 or 28 (or 0/1).",
                code=X402ErrorCode.INVALID_SIGNATURE,
            )
        return v

    @field_validator("r", "s")
    @classmethod
    def _validate_bytes32_hex(cls, v: str, info: Any) -> str:
        if not isinstance(v, str) or not _BYTES32_HEX_RE.match(v):
            raise X402ValidationError(
                f"Invalid signature {info.field_name}: must be a 32-byte hex string.",
                code=X402ErrorCode.INVALID_SIGNATURE,
            )
        if not v.startswith("0x"):
            return "0x" + v.lower()
        return v.lower()

    @model_validator(mode="after")
    def _populate_serialized(self) -> SignatureData:
        # Build raw serialized hex without 0x: r (64 hex) + s (64 hex) + v (2 hex)
        r_clean = self.r.removeprefix("0x")
        s_clean = self.s.removeprefix("0x")
        v_hex = f"{self.v:02x}"
        expected_raw = f"{r_clean}{s_clean}{v_hex}".lower()

        # If serialized was not provided, default to expected_raw
        ser = self.serialized if self.serialized is not None else expected_raw
        comp = self.compact if self.compact is not None else ("0x" + expected_raw)

        if ser != self.serialized or comp != self.compact:
            object.__setattr__(self, "serialized", ser)
            object.__setattr__(self, "compact", comp)

        return self

    @classmethod
    def from_raw_signature(cls, r: str | int, s: str | int, v: int, serialized: str | None = None) -> SignatureData:
        """Construct SignatureData from integers or hex components."""
        r_str = f"0x{r:064x}" if isinstance(r, int) else (r if r.startswith("0x") else f"0x{r}")
        s_str = f"0x{s:064x}" if isinstance(s, int) else (s if s.startswith("0x") else f"0x{s}")
        return cls(v=v, r=r_str, s=s_str, serialized=serialized)


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
    scheme: str = Field(default="EIP-3009", description="Payment authorization scheme")
    network: str | None = Field(default=None, description="CAIP-2 network or AgentCore internal ledger")
    asset: str | None = Field(default=None, description="Payment asset identifier")
    asset_symbol: str | None = Field(default=None, alias="assetSymbol", description="Token symbol")
    decimals: int = Field(default=6, description="Token decimals")
    amount: str = Field(..., description="Payment amount in integer base units as string")
    payee: str | None = Field(default=None, description="Chain recipient or AgentCore route resource")
    valid_after: int = Field(..., alias="validAfter", description="Unix timestamp valid after (seconds)")
    valid_before: int = Field(..., alias="validBefore", description="Unix timestamp valid before (seconds)")
    facilitator_url: str | None = Field(
        default=None, alias="facilitatorUrl", description="Facilitator clearing endpoint URL"
    )
    resource_uri: str | None = Field(default=None, alias="resourceUri", description="Protected resource path")
    extensions: dict[str, Any] | None = None

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
        if info.data.get("scheme") == "agentpay-wallet" and v == "agentpay:internal-ledger":
            return v
        if v is None:
            raise X402ValidationError("network is required", code=X402ErrorCode.MISSING_REQUIRED_FIELD)
        return _validate_caip2(v)

    @field_validator("asset")
    @classmethod
    def _validate_asset(cls, v: str | None, info: Any) -> str | None:
        if info.data.get("scheme") == "agentpay-wallet" and v in WALLET_FIAT_CURRENCIES:
            return v
        if v is None:
            raise X402ValidationError("asset is required", code=X402ErrorCode.MISSING_REQUIRED_FIELD)
        return _validate_evm_address(v, "asset")

    @field_validator("payee")
    @classmethod
    def _validate_payee(cls, v: str | None, info: Any) -> str | None:
        if info.data.get("scheme") == "agentpay-wallet" and v and v.startswith("agentpay:route:"):
            return v
        if v is None:
            raise X402ValidationError("payee is required", code=X402ErrorCode.MISSING_REQUIRED_FIELD)
        return _validate_evm_address(v, "payee")

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
            if self.facilitator_url:
                raise X402ValidationError(
                    "agentpay-wallet challenge must not name an EIP-3009 facilitator", code=X402ErrorCode.INVALID_SCHEME
                )
        elif not self.network or not self.asset or not self.payee or not self.facilitator_url:
            raise X402ValidationError(
                "EIP-3009 challenge requires network, asset, payee, and facilitatorUrl",
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
    payer: str = Field(..., description="Payer address on-chain (EVM 0x format)")
    scheme: str = Field(default="EIP-3009", description="Payment authorization scheme")
    nonce: str = Field(..., description="Unique 32-byte hex nonce")
    valid_after: int = Field(..., alias="validAfter", description="Unix timestamp valid after (seconds)")
    valid_before: int = Field(..., alias="validBefore", description="Unix timestamp valid before (seconds)")
    signature: SignatureData | str = Field(..., description="Cryptographic signature")

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
        return _validate_evm_address(v, "payer")

    @field_validator("nonce")
    @classmethod
    def _validate_nonce(cls, v: str) -> str:
        if not isinstance(v, str) or not _NONCE_HEX_RE.match(v):
            raise X402ValidationError(
                f"Invalid nonce: {v!r}. Must be a 32-byte hex string (64 hex characters).",
                code=X402ErrorCode.INVALID_NONCE,
            )
        if not v.startswith("0x"):
            return "0x" + v.lower()
        return v.lower()

    @field_validator("signature", mode="before")
    @classmethod
    def _validate_signature(cls, v: Any) -> SignatureData | str:
        if isinstance(v, Mapping):
            return SignatureData(**v)
        if isinstance(v, str):
            clean_str = v.strip()
            if not clean_str:
                raise X402ValidationError(
                    "signature string cannot be empty.",
                    code=X402ErrorCode.INVALID_SIGNATURE,
                )
            return clean_str
        if isinstance(v, SignatureData):
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
