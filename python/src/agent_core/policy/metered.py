"""
Optional policy-engine extension for credential-mode (non-402) calls.

Some gateways accept a pre-issued credential (e.g. ``X-Agent-Key``) and answer
200 directly, so the HTTP 402 flow never starts and ``reserve()`` is never
reached.  Engines that implement this protocol can still meter those calls:

    reserve_metered()  -> reserve an *estimated* amount BEFORE the request is sent
    settle_metered()   -> record the real cost (or keep the estimate) afterwards

Release / failure bookkeeping reuses ``IPolicyEngine.release`` and
``record_failure``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from agent_core.policy.models import PolicyDecision


@runtime_checkable
class IMeteredPolicyEngine(Protocol):
    def reserve_metered(
        self,
        intent_id: str,
        estimated_amount: int,
        domain: str | None,
        ttl_seconds: int = 60,
    ) -> PolicyDecision: ...

    def settle_metered(self, intent_id: str, actual_amount: int | None = None) -> None: ...
