"""
Signer interface protocols for AgentCore.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from agent_core.core.models import PaymentAuthorization, PaymentChallenge
from agent_core.policy.models import ReservationToken


@runtime_checkable
class ISigner(Protocol):
    """
    Protocol for signing agents and cryptographic keystores.
    Enforces firewall reservation binding before signing.
    """

    @property
    def address(self) -> str:
        """The canonical address or identity of the signer."""
        ...

    def sign_payment_authorization(
        self,
        challenge: PaymentChallenge,
        reservation: ReservationToken,
        *,
        nonce: str | None = None,
        token_name: str | None = None,
        token_version: str = "2",
    ) -> PaymentAuthorization:
        """
        Sign a payment authorization for the given challenge.

        MUST verify that the reservation matches the challenge before signing.

        Args:
            challenge: The PaymentChallenge from the 402 PAYMENT-REQUIRED header.
            reservation: The Approved ReservationToken from the policy engine.
            nonce: Optional nonce. If omitted, a random nonce is generated.
            token_name: Optional token or currency name.
            token_version: Token domain version.

        Returns:
            PaymentAuthorization populated with cryptographic signature.

        Raises:
            ReservationMismatchError: If the reservation does not match the challenge.
            SignerError: If cryptographic signing fails.
        """
        ...
