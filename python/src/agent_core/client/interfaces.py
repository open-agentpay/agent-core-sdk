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
        """The canonical lowercase EVM address of the signing wallet."""
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
        Sign an EIP-712/3009 transfer authorization for the given challenge.

        MUST verify that the reservation matches the challenge before signing.

        Args:
            challenge: The PaymentChallenge from the 402 PAYMENT-REQUIRED header.
            reservation: The Approved ReservationToken from the policy engine.
            nonce: Optional 32-byte hex nonce. If omitted, a random nonce is generated.
            token_name: Optional EIP-712 domain token name (e.g. 'USD Coin').
            token_version: EIP-712 domain version (default '2').

        Returns:
            PaymentAuthorization populated with cryptographic signature.

        Raises:
            ReservationMismatchError: If the reservation does not match the challenge.
            SignerError: If cryptographic signing fails.
        """
        ...
