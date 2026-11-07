"""
x402 V2 Protocol Errors & Error Codes.

Adheres strictly to the x402 V2 specification and conformance test suite.
"""

from __future__ import annotations

import enum


class X402ErrorCode(str, enum.Enum):
    """
    Standard error codes for x402 V2 validation and decoding errors.
    Matches test vectors and protocol specs.
    """

    MISSING_REQUIRED_FIELD = "MISSING_REQUIRED_FIELD"
    NETWORK_NOT_WHITELISTED = "NETWORK_NOT_WHITELISTED"
    INVALID_CAIP2_NETWORK = "INVALID_CAIP2_NETWORK"
    INVALID_ADDRESS = "INVALID_ADDRESS"
    INVALID_AMOUNT_FORMAT = "INVALID_AMOUNT_FORMAT"
    INVALID_TIME_WINDOW = "INVALID_TIME_WINDOW"
    INVALID_SCHEME = "INVALID_SCHEME"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    INVALID_NONCE = "INVALID_NONCE"
    MALFORMED_HEADER = "MALFORMED_HEADER"
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
    CHALLENGE_EXPIRED = "CHALLENGE_EXPIRED"


class X402Error(Exception):
    """Base exception for all x402 V2 protocol operations."""

    def __init__(self, message: str, code: X402ErrorCode | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.code = code


class X402ValidationError(X402Error):
    """Raised when a challenge or authorization payload violates schema constraints."""


class X402DecodeError(X402Error):
    """Raised when decoding a challenge or authorization header fails."""


class X402EncodeError(X402Error):
    """Raised when encoding a challenge or authorization header fails."""


def map_pydantic_error_to_x402(exc: Exception) -> X402ValidationError:
    """Map standard Pydantic validation error into an explicit X402ValidationError with error code."""
    # Check if exc has .errors() method (like pydantic.ValidationError)
    errors = getattr(exc, "errors", None)
    if callable(errors):
        err_list = errors()
        if err_list:
            first_err = err_list[0]
            err_type = first_err.get("type", "")
            loc = ".".join(str(x) for x in first_err.get("loc", []))
            msg = first_err.get("msg", "Validation error")

            if "missing" in err_type:
                return X402ValidationError(
                    f"Missing required field {loc!r}: {msg}",
                    code=X402ErrorCode.MISSING_REQUIRED_FIELD,
                )
    return X402ValidationError(f"Validation error: {exc}")
