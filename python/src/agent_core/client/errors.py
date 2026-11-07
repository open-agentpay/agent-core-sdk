"""
Signer and Client Exceptions for AgentCore.
"""

from __future__ import annotations


class ClientError(Exception):
    """Base exception for all AgentCore client and signer operations."""


class SignerError(ClientError):
    """Base exception for cryptographic signing errors."""


class InvalidPrivateKeyError(SignerError):
    """Raised when an invalid EVM private key is provided."""


class UnsupportedNetworkError(SignerError):
    """Raised when a challenge specifies a network unsupported by the signer (e.g. non-EIP155)."""


class ReservationMismatchError(SignerError):
    """
    Raised when an approved ReservationToken does not match the PaymentChallenge.
    Critical financial firewall guardrail violation.
    """
