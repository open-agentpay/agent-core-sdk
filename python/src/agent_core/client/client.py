"""
AgentCoreClient: Drop-in httpx.Client with automatic 402 payment negotiation.

Wraps the financial firewall and EIP-712 cryptographic signer to automatically
satisfy HTTP 402 Payment Required challenges.

Note on ``transport=``: unlike a plain httpx.Client, the transport you pass here is the
INNER transport. It is always wrapped by AgentCoreTransport so every request passes the firewall.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx

from agent_core.client.interfaces import ISigner
from agent_core.client.transport import (
    DEFAULT_CREDENTIAL_HEADERS,
    DEFAULT_CREDENTIAL_VALUE_PREFIXES,
    AgentCoreTransport,
    AsyncAgentCoreTransport,
    CredentialMode,
)
from agent_core.policy.interfaces import IPolicyEngine

# Client kwargs that configure the default network transport. httpx only applies them when it builds
# the transport itself; since we always inject ours, they must be forwarded to the inner transport.
_INNER_PASSTHROUGH = ("verify", "cert", "http1", "http2", "limits", "trust_env")


def _inner_transport_kwargs(kwargs: dict[str, Any]) -> dict[str, Any]:
    """Collect inner-transport settings from client kwargs (mutates ``kwargs``: removes ``proxy``)."""
    if "mounts" in kwargs or "proxies" in kwargs:
        # httpx routes matching URLs to mounted transports BEFORE the default transport,
        # which would skip the payment firewall entirely.
        raise TypeError(
            "AgentCoreClient does not support 'mounts'/'proxies': they bypass the payment firewall. "
            "Pass a pre-configured inner transport via transport=... or use proxy=..."
        )
    out = {k: kwargs[k] for k in _INNER_PASSTHROUGH if k in kwargs}
    if "proxy" in kwargs:
        # Left in kwargs, httpx would create a proxy mount that bypasses AgentCoreTransport.
        out["proxy"] = kwargs.pop("proxy")
    return out


class AgentCoreClient(httpx.Client):
    """
    HTTP client for autonomous AI agents with integrated financial firewall.

    Inherits from httpx.Client: fully compatible with LangChain, LlamaIndex,
    and standard Python HTTP toolchains. Set ``wallet_challenge_mode=True`` when
    sending AgentCore Gateway API-key requests so the first request can receive
    a price challenge before any wallet hold is placed.
    """

    def __init__(
        self,
        signer: ISigner,
        policy: IPolicyEngine,
        *,
        transport: httpx.BaseTransport | None = None,
        auto_retry_on_402: bool = True,
        raise_on_policy_rejection: bool = False,
        clock: Callable[[], int] | None = None,
        unmetered_credential_policy: CredentialMode = "block",
        credential_headers: tuple[str, ...] = DEFAULT_CREDENTIAL_HEADERS,
        credential_value_prefixes: tuple[str, ...] = DEFAULT_CREDENTIAL_VALUE_PREFIXES,
        estimate_cost: Callable[[httpx.Request], int] | None = None,
        actual_cost: Callable[[httpx.Response], int | None] | None = None,
        credential_ttl_seconds: int = 60,
        wallet_challenge_mode: bool = False,
        **kwargs: Any,
    ) -> None:
        inner_kwargs = _inner_transport_kwargs(kwargs)

        self.signer = signer
        self.policy = policy
        self.auto_retry_on_402 = auto_retry_on_402
        self.raise_on_policy_rejection = raise_on_policy_rejection
        self._clock = clock
        self.unmetered_credential_policy = unmetered_credential_policy
        # Single source of truth, reused by async_client() so both clients behave identically.
        self._agentpay_options: dict[str, Any] = {
            "auto_retry_on_402": auto_retry_on_402,
            "raise_on_policy_rejection": raise_on_policy_rejection,
            "clock": clock,
            "unmetered_credential_policy": unmetered_credential_policy,
            "credential_headers": credential_headers,
            "credential_value_prefixes": credential_value_prefixes,
            "estimate_cost": estimate_cost,
            "actual_cost": actual_cost,
            "credential_ttl_seconds": credential_ttl_seconds,
            "wallet_challenge_mode": wallet_challenge_mode,
        }

        inner = transport if transport is not None else httpx.HTTPTransport(**inner_kwargs)
        agent_transport = AgentCoreTransport(inner, signer, policy, **self._agentpay_options)
        super().__init__(transport=agent_transport, **kwargs)

    def async_client(
        self,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        **kwargs: Any,
    ) -> AsyncAgentCoreClient:
        """Create an AsyncAgentCoreClient sharing the same signer, policy and firewall options."""
        options = {**self._agentpay_options, **{k: v for k, v in kwargs.items() if k in self._agentpay_options}}
        client_kwargs = {k: v for k, v in kwargs.items() if k not in self._agentpay_options}
        return AsyncAgentCoreClient(
            signer=self.signer,
            policy=self.policy,
            transport=transport,
            **options,
            **client_kwargs,
        )


class AsyncAgentCoreClient(httpx.AsyncClient):
    """
    Asynchronous HTTP client for autonomous AI agents with integrated financial firewall.

    Inherits from httpx.AsyncClient. Use ``wallet_challenge_mode=True`` for
    AgentCore Gateway API-key requests that must be priced before wallet payment.
    """

    def __init__(
        self,
        signer: ISigner,
        policy: IPolicyEngine,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        auto_retry_on_402: bool = True,
        raise_on_policy_rejection: bool = False,
        clock: Callable[[], int] | None = None,
        unmetered_credential_policy: CredentialMode = "block",
        credential_headers: tuple[str, ...] = DEFAULT_CREDENTIAL_HEADERS,
        credential_value_prefixes: tuple[str, ...] = DEFAULT_CREDENTIAL_VALUE_PREFIXES,
        estimate_cost: Callable[[httpx.Request], int] | None = None,
        actual_cost: Callable[[httpx.Response], int | None] | None = None,
        credential_ttl_seconds: int = 60,
        wallet_challenge_mode: bool = False,
        **kwargs: Any,
    ) -> None:
        inner_kwargs = _inner_transport_kwargs(kwargs)

        self.signer = signer
        self.policy = policy
        self.auto_retry_on_402 = auto_retry_on_402
        self.raise_on_policy_rejection = raise_on_policy_rejection
        self._clock = clock
        self.unmetered_credential_policy = unmetered_credential_policy
        self._agentpay_options: dict[str, Any] = {
            "auto_retry_on_402": auto_retry_on_402,
            "raise_on_policy_rejection": raise_on_policy_rejection,
            "clock": clock,
            "unmetered_credential_policy": unmetered_credential_policy,
            "credential_headers": credential_headers,
            "credential_value_prefixes": credential_value_prefixes,
            "estimate_cost": estimate_cost,
            "actual_cost": actual_cost,
            "credential_ttl_seconds": credential_ttl_seconds,
            "wallet_challenge_mode": wallet_challenge_mode,
        }

        inner = transport if transport is not None else httpx.AsyncHTTPTransport(**inner_kwargs)
        agent_transport = AsyncAgentCoreTransport(inner, signer, policy, **self._agentpay_options)
        super().__init__(transport=agent_transport, **kwargs)
