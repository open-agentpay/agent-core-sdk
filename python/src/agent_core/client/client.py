"""
AgentPayClient: Drop-in httpx.Client with automatic 402 payment negotiation and financial firewall.

Supports both:
1. Virtual Wallet / API Key mode (zero Web3 setup, automatic gateway challenge negotiation)
2. Pluggable signer mode via ISigner implementation
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
import os
import random
import time
from typing import Any
import uuid

import httpx

from agent_core.client.interfaces import ISigner
from agent_core.client.transport import (
    DEFAULT_CREDENTIAL_HEADERS,
    DEFAULT_CREDENTIAL_VALUE_PREFIXES,
    AgentCoreTransport,
    AgentPayTransport,
    AsyncAgentCoreTransport,
    AsyncAgentPayTransport,
    CredentialMode,
)
from agent_core.contracts import (
    AgentContext,
    PaymentRequest,
    PaymentResult,
    PolicyDecision,
    ResourceContext,
    map_integration_error,
)
from agent_core.policy.interfaces import IPolicyEngine

_INNER_PASSTHROUGH = ("verify", "cert", "http1", "http2", "limits", "trust_env")


def _inner_transport_kwargs(kwargs: dict[str, Any]) -> dict[str, Any]:
    """Collect inner-transport settings from client kwargs (mutates ``kwargs``: removes ``proxy``)."""
    if "mounts" in kwargs or "proxies" in kwargs:
        raise TypeError(
            "AgentPayClient does not support 'mounts'/'proxies': they bypass the payment firewall. "
            "Pass a pre-configured inner transport via transport=... or use proxy=..."
        )
    out = {k: kwargs[k] for k in _INNER_PASSTHROUGH if k in kwargs}
    if "proxy" in kwargs:
        out["proxy"] = kwargs.pop("proxy")
    return out


def _resolve_client_auth_params(
    signer_or_policy: ISigner | IPolicyEngine | None,
    policy: IPolicyEngine | None,
    signer: ISigner | None,
    api_key: str | None,
    wallet_challenge_mode: bool | None,
    headers: Mapping[str, str] | None,
) -> tuple[ISigner | None, IPolicyEngine, bool, dict[str, str]]:
    """Resolve and validate signer, policy, api_key, wallet mode and headers."""
    resolved_signer = signer
    resolved_policy = policy

    if signer_or_policy is not None:
        if isinstance(signer_or_policy, ISigner):
            if resolved_signer is None:
                resolved_signer = signer_or_policy
        elif isinstance(signer_or_policy, IPolicyEngine):
            if resolved_policy is None:
                resolved_policy = signer_or_policy
        else:
            raise TypeError(
                f"First positional argument must be an ISigner or IPolicyEngine, got {type(signer_or_policy).__name__}"
            )

    if resolved_policy is None:
        raise TypeError("A policy engine instance must be provided via 'policy'.")

    if api_key is None and resolved_signer is None:
        raise ValueError("Either 'api_key' or 'signer' must be provided.")

    merged_headers = dict(headers or {})

    if api_key is not None:
        if wallet_challenge_mode is None:
            wallet_challenge_mode = True
        has_key_header = any(k.lower() == "x-agent-key" for k in merged_headers)
        has_auth_header = any(k.lower() == "authorization" for k in merged_headers)
        if not has_key_header and not has_auth_header:
            merged_headers["X-Agent-Key"] = api_key
    else:
        if wallet_challenge_mode is None:
            wallet_challenge_mode = False

    return resolved_signer, resolved_policy, wallet_challenge_mode, merged_headers


class AgentPayClient(httpx.Client):
    """
    HTTP client for autonomous AI agents with integrated financial firewall.

    Inherits from httpx.Client: fully compatible with LangChain, LlamaIndex,
    and standard Python HTTP toolchains.
    """

    def __init__(
        self,
        signer_or_policy: ISigner | IPolicyEngine | None = None,
        policy: IPolicyEngine | None = None,
        *,
        api_key: str | None = None,
        signer: ISigner | None = None,
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
        wallet_challenge_mode: bool | None = None,
        headers: Mapping[str, str] | None = None,
        **kwargs: Any,
    ) -> None:
        inner_kwargs = _inner_transport_kwargs(kwargs)
        resolved_signer, resolved_policy, resolved_wallet_mode, merged_headers = _resolve_client_auth_params(
            signer_or_policy=signer_or_policy,
            policy=policy,
            signer=signer,
            api_key=api_key,
            wallet_challenge_mode=wallet_challenge_mode,
            headers=headers,
        )

        self.signer = resolved_signer
        self.policy = resolved_policy
        self.api_key = api_key
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
            "wallet_challenge_mode": resolved_wallet_mode,
        }

        inner = transport if transport is not None else httpx.HTTPTransport(**inner_kwargs)
        agent_transport = AgentPayTransport(inner, resolved_signer, resolved_policy, **self._agentpay_options)
        base_url = kwargs.pop("base_url", None)
        if base_url is None:
            base_url = os.getenv("AGENTPAY_BASE_URL", "http://localhost:8000")
        super().__init__(transport=agent_transport, headers=merged_headers, base_url=base_url, **kwargs)

    def pay(
        self,
        request: PaymentRequest | dict[str, Any] | None = None,
        *,
        resource_id: str | None = None,
        challenge_id: str | None = None,
        idempotency_key: str | None = None,
        amount: str | None = None,
        asset: str | None = None,
        network: str | None = None,
        context: AgentContext | dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        timeout: float = 30.0,
    ) -> PaymentResult:
        """
        Execute payment against AgentPay Integration API (/api/v1/integrations/payments).

        Atomically verifies challenge/resource, checks policy, holds quota on virtual wallet,
        and returns three-domain PaymentResult.
        """
        if request is None:
            if idempotency_key is None:
                idempotency_key = f"idem_{uuid.uuid4().hex}"
            res_ctx = ResourceContext(resource_id=resource_id, challenge_id=challenge_id)
            agent_ctx = AgentContext(**context) if isinstance(context, dict) else context
            req = PaymentRequest(
                resource=res_ctx,
                idempotency_key=idempotency_key,
                context=agent_ctx,
                amount=amount,
                asset=asset,
                network=network,
                metadata=metadata,
            )
        elif isinstance(request, dict):
            req = PaymentRequest(**request)
        else:
            req = request

        response = self.post(
            "/api/v1/integrations/payments",
            json=req.model_dump(exclude_none=True),
            timeout=timeout,
        )

        if response.is_success:
            return PaymentResult(**response.json())

        data: dict[str, Any] = {}
        try:
            data = response.json()
        except Exception:
            pass

        err = data.get("error", {})
        raise map_integration_error(
            status_code=response.status_code,
            code=err.get("code", "HTTP_ERROR"),
            message=err.get("message", response.text),
            next_action=err.get("next_action", "STOP"),
            details=err,
        )

    def get_payment(
        self,
        payment_intent_id: str,
        *,
        timeout: float = 10.0,
    ) -> PaymentResult:
        """Query current three-domain lifecycle status of a payment intent."""
        response = self.get(
            f"/api/v1/integrations/payments/{payment_intent_id}",
            timeout=timeout,
        )
        if response.is_success:
            return PaymentResult(**response.json())

        data: dict[str, Any] = {}
        try:
            data = response.json()
        except Exception:
            pass
        err = data.get("error", {})
        raise map_integration_error(
            status_code=response.status_code,
            code=err.get("code", "NOT_FOUND"),
            message=err.get("message", response.text),
            next_action=err.get("next_action", "STOP"),
            details=err,
        )

    def poll_payment(
        self,
        payment_intent_id: str,
        *,
        max_attempts: int = 15,
        initial_interval: float = 0.5,
        backoff_factor: float = 1.5,
        max_interval: float = 5.0,
        stop_on_terminal: bool = True,
    ) -> PaymentResult:
        """
        Poll payment intent until settled, delivered, or terminal state reached.
        Uses exponential backoff with jitter to avoid load spikes.
        """
        interval = initial_interval
        last_result: PaymentResult | None = None

        for _ in range(max_attempts):
            last_result = self.get_payment(payment_intent_id)
            if stop_on_terminal and not last_result.is_in_progress():
                return last_result

            jitter = interval * random.uniform(-0.1, 0.1)
            sleep_sec = max(0.05, min(interval + jitter, max_interval))
            time.sleep(sleep_sec)
            interval = min(interval * backoff_factor, max_interval)

        if last_result is not None:
            return last_result
        raise TimeoutError(f"Polling payment {payment_intent_id} timed out after {max_attempts} attempts")

    def evaluate_policy(
        self,
        request: PaymentRequest | dict[str, Any] | None = None,
        *,
        resource_id: str | None = None,
        challenge_id: str | None = None,
        amount: str | None = None,
        asset: str | None = None,
        context: AgentContext | dict[str, Any] | None = None,
        timeout: float = 10.0,
    ) -> PolicyDecision:
        """
        Execute a dry-run policy evaluation via /api/v1/integrations/policies/evaluate
        without reserving funds or modifying wallet balances.
        """
        if request is None:
            res_ctx = ResourceContext(resource_id=resource_id, challenge_id=challenge_id)
            agent_ctx = AgentContext(**context) if isinstance(context, dict) else context
            req = PaymentRequest(
                resource=res_ctx,
                idempotency_key="dry_run_eval",
                context=agent_ctx,
                amount=amount,
                asset=asset,
            )
        elif isinstance(request, dict):
            req = PaymentRequest(**request)
        else:
            req = request

        response = self.post(
            "/api/v1/integrations/policies/evaluate",
            json=req.model_dump(exclude_none=True),
            timeout=timeout,
        )

        if response.is_success:
            return PolicyDecision(**response.json())

        data: dict[str, Any] = {}
        try:
            data = response.json()
        except Exception:
            pass
        err = data.get("error", {})
        raise map_integration_error(
            status_code=response.status_code,
            code=err.get("code", "POLICY_ERROR"),
            message=err.get("message", response.text),
            next_action=err.get("next_action", "STOP"),
            details=err,
        )

    def get_me(self, *, timeout: float = 10.0) -> dict[str, Any]:
        """Query authenticated agent identity and tenant details from /api/v1/integrations/agents/me."""
        response = self.get("/api/v1/integrations/agents/me", timeout=timeout)
        if response.is_success:
            return response.json()
        data: dict[str, Any] = {}
        try:
            data = response.json()
        except Exception:
            pass
        err = data.get("error", {})
        raise map_integration_error(
            status_code=response.status_code,
            code=err.get("code", "UNAUTHENTICATED"),
            message=err.get("message", response.text),
            next_action=err.get("next_action", "PROVIDE_API_KEY"),
            details=err,
        )

    def async_client(
        self,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        **kwargs: Any,
    ) -> AsyncAgentPayClient:
        """Create an AsyncAgentPayClient sharing the same credentials, policy and firewall options."""
        options = {**self._agentpay_options, **{k: v for k, v in kwargs.items() if k in self._agentpay_options}}
        client_kwargs = {k: v for k, v in kwargs.items() if k not in self._agentpay_options}
        return AsyncAgentPayClient(
            signer=self.signer,
            policy=self.policy,
            api_key=self.api_key,
            transport=transport,
            **options,
            **client_kwargs,
        )


class AsyncAgentPayClient(httpx.AsyncClient):
    """
    Asynchronous HTTP client for autonomous AI agents with integrated financial firewall.
    """

    def __init__(
        self,
        signer_or_policy: ISigner | IPolicyEngine | None = None,
        policy: IPolicyEngine | None = None,
        *,
        api_key: str | None = None,
        signer: ISigner | None = None,
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
        wallet_challenge_mode: bool | None = None,
        headers: Mapping[str, str] | None = None,
        **kwargs: Any,
    ) -> None:
        inner_kwargs = _inner_transport_kwargs(kwargs)
        resolved_signer, resolved_policy, resolved_wallet_mode, merged_headers = _resolve_client_auth_params(
            signer_or_policy=signer_or_policy,
            policy=policy,
            signer=signer,
            api_key=api_key,
            wallet_challenge_mode=wallet_challenge_mode,
            headers=headers,
        )

        self.signer = resolved_signer
        self.policy = resolved_policy
        self.api_key = api_key
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
            "wallet_challenge_mode": resolved_wallet_mode,
        }

        inner = transport if transport is not None else httpx.AsyncHTTPTransport(**inner_kwargs)
        agent_transport = AsyncAgentPayTransport(inner, resolved_signer, resolved_policy, **self._agentpay_options)
        base_url = kwargs.pop("base_url", None)
        if base_url is None:
            base_url = os.getenv("AGENTPAY_BASE_URL", "http://localhost:8000")
        super().__init__(transport=agent_transport, headers=merged_headers, base_url=base_url, **kwargs)

    async def pay(
        self,
        request: PaymentRequest | dict[str, Any] | None = None,
        *,
        resource_id: str | None = None,
        challenge_id: str | None = None,
        idempotency_key: str | None = None,
        amount: str | None = None,
        asset: str | None = None,
        network: str | None = None,
        context: AgentContext | dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        timeout: float = 30.0,
    ) -> PaymentResult:
        """
        Asynchronously execute payment against AgentPay Integration API.
        """
        if request is None:
            if idempotency_key is None:
                idempotency_key = f"idem_{uuid.uuid4().hex}"
            res_ctx = ResourceContext(resource_id=resource_id, challenge_id=challenge_id)
            agent_ctx = AgentContext(**context) if isinstance(context, dict) else context
            req = PaymentRequest(
                resource=res_ctx,
                idempotency_key=idempotency_key,
                context=agent_ctx,
                amount=amount,
                asset=asset,
                network=network,
                metadata=metadata,
            )
        elif isinstance(request, dict):
            req = PaymentRequest(**request)
        else:
            req = request

        response = await self.post(
            "/api/v1/integrations/payments",
            json=req.model_dump(exclude_none=True),
            timeout=timeout,
        )

        if response.is_success:
            return PaymentResult(**response.json())

        data: dict[str, Any] = {}
        try:
            data = response.json()
        except Exception:
            pass

        err = data.get("error", {})
        raise map_integration_error(
            status_code=response.status_code,
            code=err.get("code", "HTTP_ERROR"),
            message=err.get("message", response.text),
            next_action=err.get("next_action", "STOP"),
            details=err,
        )

    async def get_payment(
        self,
        payment_intent_id: str,
        *,
        timeout: float = 10.0,
    ) -> PaymentResult:
        """Asynchronously query current three-domain lifecycle status of a payment intent."""
        response = await self.get(
            f"/api/v1/integrations/payments/{payment_intent_id}",
            timeout=timeout,
        )
        if response.is_success:
            return PaymentResult(**response.json())

        data: dict[str, Any] = {}
        try:
            data = response.json()
        except Exception:
            pass
        err = data.get("error", {})
        raise map_integration_error(
            status_code=response.status_code,
            code=err.get("code", "NOT_FOUND"),
            message=err.get("message", response.text),
            next_action=err.get("next_action", "STOP"),
            details=err,
        )

    async def poll_payment(
        self,
        payment_intent_id: str,
        *,
        max_attempts: int = 15,
        initial_interval: float = 0.5,
        backoff_factor: float = 1.5,
        max_interval: float = 5.0,
        stop_on_terminal: bool = True,
    ) -> PaymentResult:
        """
        Asynchronously poll payment intent until settled, delivered, or terminal state reached.
        """
        interval = initial_interval
        last_result: PaymentResult | None = None

        for _ in range(max_attempts):
            last_result = await self.get_payment(payment_intent_id)
            if stop_on_terminal and not last_result.is_in_progress():
                return last_result

            jitter = interval * random.uniform(-0.1, 0.1)
            sleep_sec = max(0.05, min(interval + jitter, max_interval))
            await asyncio.sleep(sleep_sec)
            interval = min(interval * backoff_factor, max_interval)

        if last_result is not None:
            return last_result
        raise TimeoutError(f"Polling payment {payment_intent_id} timed out after {max_attempts} attempts")

    async def evaluate_policy(
        self,
        request: PaymentRequest | dict[str, Any] | None = None,
        *,
        resource_id: str | None = None,
        challenge_id: str | None = None,
        amount: str | None = None,
        asset: str | None = None,
        context: AgentContext | dict[str, Any] | None = None,
        timeout: float = 10.0,
    ) -> PolicyDecision:
        """Asynchronously execute dry-run policy evaluation."""
        if request is None:
            res_ctx = ResourceContext(resource_id=resource_id, challenge_id=challenge_id)
            agent_ctx = AgentContext(**context) if isinstance(context, dict) else context
            req = PaymentRequest(
                resource=res_ctx,
                idempotency_key="dry_run_eval",
                context=agent_ctx,
                amount=amount,
                asset=asset,
            )
        elif isinstance(request, dict):
            req = PaymentRequest(**request)
        else:
            req = request

        response = await self.post(
            "/api/v1/integrations/policies/evaluate",
            json=req.model_dump(exclude_none=True),
            timeout=timeout,
        )

        if response.is_success:
            return PolicyDecision(**response.json())

        data: dict[str, Any] = {}
        try:
            data = response.json()
        except Exception:
            pass
        err = data.get("error", {})
        raise map_integration_error(
            status_code=response.status_code,
            code=err.get("code", "POLICY_ERROR"),
            message=err.get("message", response.text),
            next_action=err.get("next_action", "STOP"),
            details=err,
        )

    async def get_me(self, *, timeout: float = 10.0) -> dict[str, Any]:
        """Asynchronously query authenticated agent identity from /api/v1/integrations/agents/me."""
        response = await self.get("/api/v1/integrations/agents/me", timeout=timeout)
        if response.is_success:
            return response.json()
        data: dict[str, Any] = {}
        try:
            data = response.json()
        except Exception:
            pass
        err = data.get("error", {})
        raise map_integration_error(
            status_code=response.status_code,
            code=err.get("code", "UNAUTHENTICATED"),
            message=err.get("message", response.text),
            next_action=err.get("next_action", "PROVIDE_API_KEY"),
            details=err,
        )


# Backward-compatible aliases
AgentCoreClient = AgentPayClient
AsyncAgentCoreClient = AsyncAgentPayClient
