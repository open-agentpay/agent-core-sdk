"""
x402 V2 HTTP Header Codecs & Serialization Utilities.

Implements Base64URL and standard JSON encoding/decoding for HTTP headers:
  - PAYMENT-REQUIRED  (Response from Seller)
  - PAYMENT-SIGNATURE (Request from Buyer)

Adheres strictly to RFC 4648 Base64URL encoding and the x402 V2 specification.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping, MutableMapping
from typing import Any

from pydantic import ValidationError

from agent_core.core.errors import (
    X402DecodeError,
    X402EncodeError,
    X402ErrorCode,
    X402ValidationError,
)
from agent_core.core.models import PaymentAuthorization, PaymentChallenge, WalletAuthorization

# Standard HTTP Header Constants (RFC-compliant uppercase default)
HEADER_PAYMENT_REQUIRED = "PAYMENT-REQUIRED"
HEADER_PAYMENT_SIGNATURE = "PAYMENT-SIGNATURE"


# ---------------------------------------------------------------------------
# Base64URL Helpers (RFC 4648 §5)
# ---------------------------------------------------------------------------


def base64url_encode(data: bytes) -> str:
    """Encode bytes into unpadded Base64URL string."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def base64url_decode(s: str) -> bytes:
    """
    Decode Base64URL string (with or without padding) into raw bytes.
    Raises ValueError on malformed inputs.
    """
    clean = s.strip()
    # Add padding characters back if missing
    missing_padding = len(clean) % 4
    if missing_padding:
        clean += "=" * (4 - missing_padding)
    return base64.urlsafe_b64decode(clean.encode("ascii"))


def _parse_raw_header_value(header_value: str) -> dict[str, Any]:
    """
    Parse a raw HTTP header value into a dictionary.
    Supports either Base64URL encoded JSON or direct JSON string.
    """
    if not isinstance(header_value, str) or not header_value.strip():
        raise X402DecodeError(
            "Header value cannot be empty.",
            code=X402ErrorCode.MALFORMED_HEADER,
        )

    val = header_value.strip()

    # Fast path: direct JSON string
    if val.startswith("{") and val.endswith("}"):
        try:
            parsed = json.loads(val)
            if not isinstance(parsed, dict):
                raise TypeError("Parsed JSON must be a JSON object (dict)")
            return parsed
        except Exception as exc:
            raise X402DecodeError(
                f"Failed to parse raw JSON header value: {exc}",
                code=X402ErrorCode.MALFORMED_HEADER,
            ) from exc

    # Attempt Base64URL decoding
    try:
        raw_bytes = base64url_decode(val)
        json_str = raw_bytes.decode("utf-8")
        parsed = json.loads(json_str)
        if not isinstance(parsed, dict):
            raise TypeError("Parsed Base64 payload must be a JSON object (dict)")
        return parsed
    except Exception as exc:
        raise X402DecodeError(
            f"Failed to decode Base64URL x402 header value: {exc}",
            code=X402ErrorCode.MALFORMED_HEADER,
        ) from exc


def _map_pydantic_error_to_x402(exc: ValidationError) -> X402ValidationError:
    """Map standard Pydantic validation error into an explicit X402ValidationError with error code."""
    first_err = exc.errors()[0] if exc.errors() else {}
    err_type = first_err.get("type", "")
    loc = ".".join(str(x) for x in first_err.get("loc", []))
    msg = first_err.get("msg", "Validation error")

    if "missing" in err_type:
        return X402ValidationError(
            f"Missing required field {loc!r}: {msg}",
            code=X402ErrorCode.MISSING_REQUIRED_FIELD,
        )
    return X402ValidationError(f"Invalid field {loc!r}: {msg}")


# ---------------------------------------------------------------------------
# Challenge Codecs (PAYMENT-REQUIRED)
# ---------------------------------------------------------------------------


def encode_challenge(challenge: PaymentChallenge, *, base64_url: bool = True) -> str:
    """
    Encode a PaymentChallenge into an HTTP header string.

    Args:
        challenge: The PaymentChallenge model instance.
        base64_url: If True (default), produces unpadded Base64URL. If False, produces JSON string.
    """
    try:
        json_str = challenge.model_dump_json(by_alias=True, exclude_none=True)
        if not base64_url:
            return json_str
        return base64url_encode(json_str.encode("utf-8"))
    except Exception as exc:
        raise X402EncodeError(
            f"Failed to encode challenge: {exc}",
            code=X402ErrorCode.MALFORMED_HEADER,
        ) from exc


def decode_challenge(header_value: str) -> PaymentChallenge:
    """
    Decode an HTTP PAYMENT-REQUIRED header value (Base64URL or raw JSON) into a PaymentChallenge model.

    Raises:
        X402DecodeError: If header cannot be decoded or deserialized.
        X402ValidationError: If schema constraints or domain validations fail.
    """
    payload_dict = _parse_raw_header_value(header_value)
    try:
        return PaymentChallenge.model_validate(payload_dict)
    except X402ValidationError:
        raise
    except ValidationError as exc:
        raise _map_pydantic_error_to_x402(exc) from exc


# ---------------------------------------------------------------------------
# Authorization Codecs (PAYMENT-SIGNATURE)
# ---------------------------------------------------------------------------


def encode_authorization(authorization: PaymentAuthorization, *, base64_url: bool = True) -> str:
    """
    Encode a PaymentAuthorization into an HTTP header string.

    Args:
        authorization: The PaymentAuthorization model instance.
        base64_url: If True (default), produces unpadded Base64URL. If False, produces JSON string.
    """
    try:
        json_str = authorization.model_dump_json(by_alias=True, exclude_none=True)
        if not base64_url:
            return json_str
        return base64url_encode(json_str.encode("utf-8"))
    except Exception as exc:
        raise X402EncodeError(
            f"Failed to encode authorization: {exc}",
            code=X402ErrorCode.MALFORMED_HEADER,
        ) from exc


def encode_wallet_authorization(authorization: WalletAuthorization, *, base64_url: bool = True) -> str:
    """Encode AgentCore's wallet authorization in PAYMENT-SIGNATURE."""
    try:
        payload = authorization.model_dump_json(by_alias=True, exclude_none=True)
        return base64url_encode(payload.encode("utf-8")) if base64_url else payload
    except Exception as exc:  # noqa: BLE001
        raise X402EncodeError("Failed to encode wallet authorization", code=X402ErrorCode.MALFORMED_HEADER) from exc


def decode_authorization(header_value: str) -> PaymentAuthorization:
    """
    Decode an HTTP PAYMENT-SIGNATURE header value (Base64URL or raw JSON) into a PaymentAuthorization model.

    Raises:
        X402DecodeError: If header cannot be decoded or deserialized.
        X402ValidationError: If schema constraints or domain validations fail.
    """
    payload_dict = _parse_raw_header_value(header_value)
    try:
        return PaymentAuthorization.model_validate(payload_dict)
    except X402ValidationError:
        raise
    except ValidationError as exc:
        raise _map_pydantic_error_to_x402(exc) from exc


# ---------------------------------------------------------------------------
# Header Extraction & Injection Utilities
# ---------------------------------------------------------------------------


def extract_challenge_from_headers(
    headers: Mapping[str, str],
) -> PaymentChallenge | None:
    """
    Case-insensitively search for the PAYMENT-REQUIRED header and decode it.
    Returns None if the header is not present.
    """
    for key, value in headers.items():
        if key.upper() == HEADER_PAYMENT_REQUIRED:
            return decode_challenge(value)
    return None


def extract_authorization_from_headers(
    headers: Mapping[str, str],
) -> PaymentAuthorization | None:
    """
    Case-insensitively search for the PAYMENT-SIGNATURE header and decode it.
    Returns None if the header is not present.
    """
    for key, value in headers.items():
        if key.upper() == HEADER_PAYMENT_SIGNATURE:
            return decode_authorization(value)
    return None


def inject_authorization_to_headers(
    headers: MutableMapping[str, str],
    authorization: PaymentAuthorization,
    *,
    base64_url: bool = True,
    header_name: str = HEADER_PAYMENT_SIGNATURE,
) -> None:
    """
    Encode authorization and set the PAYMENT-SIGNATURE header into a mutable headers mapping.
    """
    headers[header_name] = encode_authorization(authorization, base64_url=base64_url)
