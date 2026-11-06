"""
x402 Upstream Interoperability Module (ADR-001 §3.3).

Provides optional adapter functions between AgentCore native models and the official
third-party `x402` SDK objects (if installed).
"""

from __future__ import annotations

from typing import Any

from agent_core.core.models import PaymentAuthorization, PaymentChallenge


def is_official_x402_available() -> bool:
    """Check whether official `x402` package is installed in the current environment."""
    try:
        import x402  # noqa: F401

        return True
    except ImportError:
        return False


def to_official_challenge(challenge: PaymentChallenge) -> Any:
    """
    Convert an AgentCore PaymentChallenge into an official x402 library object or dict.
    Raises RuntimeError if official x402 is not installed and object conversion is requested.
    """
    data = challenge.model_dump(by_alias=True, exclude_none=True)
    if not is_official_x402_available():
        # Fall back to standard dict representation
        return data

    import x402

    if hasattr(x402, "PaymentChallenge"):
        return x402.PaymentChallenge(**data)
    return data


def from_official_challenge(obj: Any) -> PaymentChallenge:
    """
    Convert an official x402 library challenge object (or dict) into an AgentCore native PaymentChallenge.
    """
    if isinstance(obj, PaymentChallenge):
        return obj
    if isinstance(obj, dict):
        return PaymentChallenge.model_validate(obj)
    if hasattr(obj, "to_dict"):
        return PaymentChallenge.model_validate(obj.to_dict())
    if hasattr(obj, "__dict__"):
        return PaymentChallenge.model_validate(obj.__dict__)
    raise TypeError(f"Cannot convert object of type {type(obj)} to PaymentChallenge")


def from_official_authorization(obj: Any) -> PaymentAuthorization:
    """
    Convert an official x402 library authorization object (or dict) into an AgentCore native PaymentAuthorization.
    """
    if isinstance(obj, PaymentAuthorization):
        return obj
    if isinstance(obj, dict):
        return PaymentAuthorization.model_validate(obj)
    if hasattr(obj, "to_dict"):
        return PaymentAuthorization.model_validate(obj.to_dict())
    if hasattr(obj, "__dict__"):
        return PaymentAuthorization.model_validate(obj.__dict__)
    raise TypeError(f"Cannot convert object of type {type(obj)} to PaymentAuthorization")
