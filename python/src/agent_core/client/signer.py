"""
EIP-712 & EIP-3009 LocalSigner implementation for AgentCore.

Uses eth-account for all cryptographic operations.
Enforces firewall reservation binding and secret redaction.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Mapping
from typing import Any

from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_account.signers.local import LocalAccount

from agent_core.client.errors import (
    InvalidPrivateKeyError,
    ReservationMismatchError,
    SignerError,
    UnsupportedNetworkError,
)
from agent_core.client.interfaces import ISigner
from agent_core.core.models import (
    PaymentAuthorization,
    PaymentChallenge,
    SignatureData,
)
from agent_core.policy.models import ReservationToken

# CAIP-2 parsing regex for eip155 namespace: eip155:<chain_id>
_CAIP2_EIP155_RE = re.compile(r"^eip155:([0-9]+)$")

# Standard EIP-3009 message type definition for TransferWithAuthorization
EIP3009_MESSAGE_TYPES = {
    "TransferWithAuthorization": [
        {"name": "from", "type": "address"},
        {"name": "to", "type": "address"},
        {"name": "value", "type": "uint256"},
        {"name": "validAfter", "type": "uint256"},
        {"name": "validBefore", "type": "uint256"},
        {"name": "nonce", "type": "bytes32"},
    ]
}

# Standard token names for major stablecoins
DEFAULT_TOKEN_NAMES = {
    "usdc": "USD Coin",
    "eurc": "Euro Coin",
}


def generate_nonce() -> str:
    """Generate a cryptographically secure 32-byte hex nonce with 0x prefix."""
    return "0x" + secrets.token_bytes(32).hex()


def parse_caip2_chain_id(network: str) -> int:
    """
    Extract the integer chain ID from a CAIP-2 network string.

    Args:
        network: CAIP-2 network identifier (e.g. 'eip155:84532').

    Returns:
        Integer chain ID.

    Raises:
        UnsupportedNetworkError: If the network is not an eip155 EVM chain.
    """
    match = _CAIP2_EIP155_RE.match(network.strip())
    if not match:
        raise UnsupportedNetworkError(
            f"Unsupported network identifier: {network!r}. "
            "LocalSigner only supports EVM chains conforming to 'eip155:<chainId>'."
        )
    return int(match.group(1))


class LocalSigner(ISigner):
    """
    Local private key signer for AgentCore clients.

    - Adheres to EIP-712 and EIP-3009 specifications.
    - Uses eth-account strictly; implements zero custom cryptography.
    - Enforces mandatory policy reservation verification before signing.
    - Redacts private key in __repr__ and __str__ for financial safety.
    """

    def __init__(
        self,
        private_key: str | bytes,
        *,
        token_name_map: Mapping[str, str] | None = None,
    ) -> None:
        """
        Initialize LocalSigner with an EVM private key.

        Args:
            private_key: Hex string (with or without 0x) or 32 raw bytes.
            token_name_map: Optional mapping of contract address or symbol to EIP-712 domain name.
        """
        try:
            if isinstance(private_key, str):
                clean_key = private_key.strip()
                if not clean_key.startswith("0x"):
                    clean_key = "0x" + clean_key
                self._account: LocalAccount = Account.from_key(clean_key)
            elif isinstance(private_key, (bytes, bytearray)):
                self._account = Account.from_key(private_key)
            else:
                raise TypeError(f"private_key must be str or bytes, got {type(private_key).__name__}")
        except Exception as exc:
            raise InvalidPrivateKeyError(f"Failed to load EVM private key: {exc}") from exc

        self._address = self._account.address.lower()
        self._token_name_map: dict[str, str] = dict(token_name_map) if token_name_map else {}

    @property
    def address(self) -> str:
        """Canonical lowercase EVM address of the signing wallet."""
        return self._address

    def __repr__(self) -> str:
        # Redact private key strictly
        return f"<LocalSigner address={self._address}>"

    def __str__(self) -> str:
        # Redact private key strictly
        return f"LocalSigner(address={self._address})"

    @classmethod
    def generate(cls) -> LocalSigner:
        """Generate a new random LocalSigner using cryptographically secure randomness."""
        random_key = "0x" + secrets.token_bytes(32).hex()
        return cls(random_key)

    def resolve_token_name(self, challenge: PaymentChallenge, explicit_name: str | None = None) -> str:
        """Resolve the EIP-712 domain token name for a payment challenge."""
        if explicit_name:
            return explicit_name
        # Check custom token_name_map by contract address
        if challenge.asset in self._token_name_map:
            return self._token_name_map[challenge.asset]
        # Check by symbol
        if challenge.asset_symbol and challenge.asset_symbol.lower() in self._token_name_map:
            return self._token_name_map[challenge.asset_symbol.lower()]
        # Check default stablecoin mappings
        if challenge.asset_symbol and challenge.asset_symbol.lower() in DEFAULT_TOKEN_NAMES:
            return DEFAULT_TOKEN_NAMES[challenge.asset_symbol.lower()]
        # Fallback to symbol or USD Coin
        return challenge.asset_symbol or "USD Coin"

    def build_eip712_data(
        self,
        challenge: PaymentChallenge,
        nonce: str,
        *,
        token_name: str | None = None,
        token_version: str = "2",
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        """
        Build EIP-712 domain, types, and message dictionaries conforming to EIP-3009.
        """
        chain_id = parse_caip2_chain_id(challenge.network)
        domain_name = self.resolve_token_name(challenge, token_name)

        domain_data = {
            "name": domain_name,
            "version": token_version,
            "chainId": chain_id,
            "verifyingContract": challenge.asset,
        }

        types_data = EIP3009_MESSAGE_TYPES

        # Nonce format: ensure 0x prefix and lowercase
        norm_nonce = nonce if nonce.startswith("0x") else ("0x" + nonce)

        message_data = {
            "from": self.address,
            "to": challenge.payee,
            "value": challenge.amount_base_units,
            "validAfter": challenge.valid_after,
            "validBefore": challenge.valid_before,
            "nonce": norm_nonce,
        }

        return domain_data, types_data, message_data

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
        Sign an EIP-712/3009 transfer authorization after verifying the policy reservation.

        Safety Guardrails:
          1. Verifies reservation.intent_id == challenge.challenge_id
          2. Verifies reservation.amount == challenge.amount_base_units
          3. Verifies reservation.expires_at >= challenge.valid_before

        Returns:
            PaymentAuthorization with cryptographic signature.
        """
        # Guardrail 1: Policy intent binding
        if reservation.intent_id != challenge.challenge_id:
            raise ReservationMismatchError(
                f"Reservation intent_id ({reservation.intent_id!r}) does not match "
                f"challenge_id ({challenge.challenge_id!r}). Refusing to sign."
            )

        # Guardrail 2: Amount exact match
        if reservation.amount != challenge.amount_base_units:
            raise ReservationMismatchError(
                f"Reservation amount ({reservation.amount}) does not match "
                f"challenge amount ({challenge.amount_base_units}). Refusing to sign."
            )

        # Guardrail 3: Expiration safety window
        if reservation.expires_at < challenge.valid_before:
            raise ReservationMismatchError(
                f"Reservation expires_at ({reservation.expires_at}) does not cover "
                f"challenge valid_before ({challenge.valid_before}). Refusing to sign."
            )

        # Determine nonce
        sign_nonce = nonce if nonce is not None else generate_nonce()

        # Build EIP-712 data
        domain_data, types_data, message_data = self.build_eip712_data(
            challenge,
            sign_nonce,
            token_name=token_name,
            token_version=token_version,
        )

        try:
            encoded = encode_typed_data(
                domain_data=domain_data,
                message_types=types_data,
                message_data=message_data,
            )
            signed = self._account.sign_message(encoded)
        except Exception as exc:
            raise SignerError(f"Cryptographic signing failed: {exc}") from exc

        r_hex = f"0x{signed.r:064x}"
        s_hex = f"0x{signed.s:064x}"
        v_val = signed.v

        # Serialized hex: 65 bytes (r 32B + s 32B + v 1B)
        serialized_hex = f"{signed.r:064x}{signed.s:064x}{v_val:02x}"

        sig_data = SignatureData(
            v=v_val,
            r=r_hex,
            s=s_hex,
            serialized=serialized_hex,
            compact="0x" + serialized_hex,
        )

        return PaymentAuthorization(
            version="2.0",
            challenge_id=challenge.challenge_id,
            payer=self.address,
            scheme=challenge.scheme,
            nonce=sign_nonce,
            valid_after=challenge.valid_after,
            valid_before=challenge.valid_before,
            signature=sig_data,
        )

    @classmethod
    def verify_authorization(
        cls,
        authorization: PaymentAuthorization,
        challenge: PaymentChallenge,
        *,
        expected_payer: str | None = None,
        token_name: str | None = None,
        token_version: str = "2",
    ) -> bool:
        """
        Verify that a PaymentAuthorization cryptographically matches the PaymentChallenge
        and was signed by the expected payer.

        Returns:
            True if signature is valid and signer matches expected payer; False otherwise.
        """
        target_payer = (expected_payer or authorization.payer).lower()
        chain_id = parse_caip2_chain_id(challenge.network)
        d_name = token_name or (
            DEFAULT_TOKEN_NAMES.get((challenge.asset_symbol or "").lower()) or challenge.asset_symbol or "USD Coin"
        )

        domain_data = {
            "name": d_name,
            "version": token_version,
            "chainId": chain_id,
            "verifyingContract": challenge.asset,
        }

        types_data = EIP3009_MESSAGE_TYPES

        message_data = {
            "from": authorization.payer,
            "to": challenge.payee,
            "value": challenge.amount_base_units,
            "validAfter": authorization.valid_after,
            "validBefore": authorization.valid_before,
            "nonce": authorization.nonce,
        }

        try:
            encoded = encode_typed_data(
                domain_data=domain_data,
                message_types=types_data,
                message_data=message_data,
            )
            # Obtain serialized signature bytes
            if isinstance(authorization.signature, SignatureData):
                sig_bytes = bytes.fromhex(authorization.signature.serialized or "")
            elif isinstance(authorization.signature, str):
                sig_clean = authorization.signature.removeprefix("0x")
                sig_bytes = bytes.fromhex(sig_clean)
            else:
                return False

            recovered = Account.recover_message(encoded, signature=sig_bytes).lower()
            return recovered == target_payer
        except (ValueError, TypeError, KeyError):
            return False
