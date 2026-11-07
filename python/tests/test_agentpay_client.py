"""
Unit tests for AgentPayClient (dual-mode authentication and cross-language unified API).
"""

from __future__ import annotations

import pytest

from agent_core import (
    AgentCoreClient,
    AgentPayClient,
    AsyncAgentCoreClient,
    AsyncAgentPayClient,
    PolicyConfig,
    SQLitePolicyEngine,
)
from agent_core.client.interfaces import ISigner
from agent_core.core.models import PaymentAuthorization, PaymentChallenge
from agent_core.policy.models import ReservationToken
import agentpay_core


class DummySigner:
    @property
    def address(self) -> str:
        return "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"

    def sign_payment_authorization(
        self,
        challenge: PaymentChallenge,
        reservation: ReservationToken,
        *,
        nonce: str | None = None,
        token_name: str | None = None,
        token_version: str = "2",
    ) -> PaymentAuthorization:
        return PaymentAuthorization(
            challengeId=challenge.challenge_id,
            payer=self.address,
            scheme=challenge.scheme,
            nonce=nonce or "0x" + "11" * 32,
            validAfter=challenge.valid_after,
            validBefore=challenge.valid_before,
            signature="mock_sig",
        )


def test_top_level_reexports():
    """Verify that agentpay_core and agent_core expose the unified client and aliases."""
    assert agentpay_core.AgentPayClient is AgentPayClient
    assert agentpay_core.AgentCoreClient is AgentCoreClient
    assert AgentCoreClient is AgentPayClient
    assert AsyncAgentCoreClient is AsyncAgentPayClient


def test_policy_config_default_wallet_address():
    """PolicyConfig should not require an explicit EVM address for virtual-wallet scenarios."""
    config = PolicyConfig(
        id="test_policy",
        max_per_tx_base_units=1000,
        rolling_budget_24h_base_units=10000,
        whitelist_domains={"gate.aipmedia.cn"},
    )
    assert config.wallet_address == "0x0000000000000000000000000000000000000000"
    engine = SQLitePolicyEngine.create_in_memory(config)
    assert engine._config.id == "test_policy"


def test_agentpay_client_api_key_mode():
    """AgentPayClient with api_key should auto-enable wallet_challenge_mode and set headers."""
    config = PolicyConfig(
        id="agent_wallet_policy",
        max_per_tx_base_units=250000,
        rolling_budget_24h_base_units=5000000,
        whitelist_domains={"gate.aipmedia.cn"},
    )
    policy = SQLitePolicyEngine.create_in_memory(config)

    client = AgentPayClient(api_key="apk_test_123456", policy=policy)
    assert client.signer is None
    assert client.api_key == "apk_test_123456"
    assert client._agentpay_options["wallet_challenge_mode"] is True
    assert client.headers.get("x-agent-key") == "apk_test_123456"

    # Async child client should inherit api_key and wallet_challenge_mode
    async_client = client.async_client()
    assert isinstance(async_client, AsyncAgentPayClient)
    assert async_client.signer is None
    assert async_client.api_key == "apk_test_123456"
    assert async_client._agentpay_options["wallet_challenge_mode"] is True
    assert async_client.headers.get("x-agent-key") == "apk_test_123456"


def test_agentpay_client_signer_mode():
    """AgentPayClient with signer should preserve on-chain mode and wallet_challenge_mode=False."""
    config = PolicyConfig(
        id="signer_policy",
        max_per_tx_base_units=250000,
        rolling_budget_24h_base_units=5000000,
    )
    policy = SQLitePolicyEngine.create_in_memory(config)
    signer = DummySigner()

    client = AgentCoreClient(signer=signer, policy=policy)
    assert client.signer == signer
    assert client.api_key is None
    assert client._agentpay_options["wallet_challenge_mode"] is False
    assert "x-agent-key" not in client.headers


def test_agentpay_client_validation_errors():
    """AgentPayClient should fail fast when required parameters are missing."""
    config = PolicyConfig(
        id="test_policy",
        max_per_tx_base_units=1000,
        rolling_budget_24h_base_units=10000,
    )
    policy = SQLitePolicyEngine.create_in_memory(config)

    # Missing both api_key and signer
    with pytest.raises(ValueError, match="Either 'api_key' or 'signer' must be provided"):
        AgentPayClient(policy=policy)

    # Missing policy
    with pytest.raises(TypeError, match="A policy engine instance must be provided"):
        AgentPayClient(api_key="apk_test")
