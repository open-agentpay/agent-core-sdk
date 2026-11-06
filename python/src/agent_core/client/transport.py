"""
httpx transparent 402 interceptor transports for AgentCore.

Implements the autonomous financial lifecycle:
  Intercept 402 -> Policy Evaluate & Reserve -> Sign or authorize -> Replay with PAYMENT-SIGNATURE -> Commit or Hold

Adheres strictly to CLAUDE.md safety rules:
  - Fail-closed evaluation
  - Pre-evaluation signing lock
  - No automatic release once signature is transmitted on the wire

Credential-mode requests (agentpay-metering-patch)
--------------------------------------------------
A request that carries a pre-issued gateway credential (``X-Agent-Key`` ...) may be
answered 200 without any 402-round trip, which would bypass the local firewall.
``unmetered_credential_policy`` controls what happens to such requests:

  "block" (default) refuse BEFORE sending -> PolicyViolationError
  "meter" reserve an estimated cost first, settle with the real cost after
                      (needs ``estimate_cost`` and a policy implementing IMeteredPolicyEngine)
  "allow" legacy behaviour, firewall is bypassed (explicit opt-in only)

A single request can opt out with ``extensions={"agentpay_allow_unmetered": True}``.

For AgentCore Gateway virtual wallets, ``wallet_challenge_mode=True`` bypasses the
pre-request credential meter so the gateway can return a price challenge first;
the challenge is then evaluated locally before the authorized retry is sent.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import time
import uuid
from collections.abc import Callable
from typing import Any, Literal

import httpx

from agent_core.client.interfaces import ISigner
from agent_core.core.codecs import (
    encode_wallet_authorization,
    extract_challenge_from_headers,
    inject_authorization_to_headers,
)
from agent_core.core.models import PaymentAuthorization, WalletAuthorization
from agent_core.policy.errors import PolicyErrorCode, PolicyViolationError
from agent_core.policy.interfaces import IPolicyEngine
from agent_core.policy.metered import IMeteredPolicyEngine

logger = logging.getLogger(__name__)

ALLOW_UNMETERED_EXTENSION = "agentpay_allow_unmetered"
DEFAULT_CREDENTIAL_HEADERS: tuple[str, ...] = ("x-agent-key",)
DEFAULT_CREDENTIAL_VALUE_PREFIXES: tuple[str, ...] = ("apk_",)

CredentialMode = Literal["block", "meter", "allow"]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _clone_request_with_authorization(request: httpx.Request, authorization: PaymentAuthorization) -> httpx.Request:
    """Clone an httpx request and inject the PAYMENT-SIGNATURE header."""
    # httpx.Headers keeps repeated headers (e.g. multiple Cookie lines); dict() would fold them.
    headers = httpx.Headers(request.headers)
    inject_authorization_to_headers(headers, authorization)
    content = request.read()
    return httpx.Request(
        method=request.method,
        url=request.url,
        headers=headers,
        content=content,
        extensions=dict(request.extensions),
    )


def _rejection_code(decision: Any) -> PolicyErrorCode:
    """A rejection without a code is a system error: fail closed, never approve."""
    return decision.error_code or PolicyErrorCode.POLICY_SYSTEM_ERROR


def _resolve_clock(clock: Callable[[], int] | None, policy: Any) -> Callable[[], int]:
    if clock is not None:
        return clock
    policy_clock = getattr(policy, "_clock", None)
    if callable(policy_clock):
        return policy_clock
    return lambda: int(time.time())


def _safe_record_failure(policy: Any, reason: str) -> None:
    """Feed the consecutive-failure breaker without masking the caller's own error."""
    record = getattr(policy, "record_failure", None)
    if record is None:
        return
    try:
        record(reason)
    except Exception:  # noqa: BLE001
        logger.exception("policy.record_failure failed (%s)", reason)


# ---------------------------------------------------------------------------
# shared (I/O free) logic
# ---------------------------------------------------------------------------


class _AgentCoreCore:
    def __init__(
        self,
        signer: ISigner,
        policy: IPolicyEngine,
        *,
        auto_retry_on_402: bool,
        raise_on_policy_rejection: bool,
        clock: Callable[[], int] | None,
        unmetered_credential_policy: CredentialMode,
        credential_headers: tuple[str, ...],
        credential_value_prefixes: tuple[str, ...],
        estimate_cost: Callable[[httpx.Request], int] | None,
        actual_cost: Callable[[httpx.Response], int | None] | None,
        credential_ttl_seconds: int,
        wallet_challenge_mode: bool,
    ) -> None:
        if unmetered_credential_policy not in ("block", "meter", "allow"):
            raise ValueError(
                f"unmetered_credential_policy must be block/meter/allow, got {unmetered_credential_policy!r}"
            )
        if unmetered_credential_policy == "meter" and (
            estimate_cost is None or not isinstance(policy, IMeteredPolicyEngine)
        ):
            raise ValueError("meter mode requires estimate_cost and a policy implementing IMeteredPolicyEngine")

        self._signer = signer
        self._policy = policy
        self._auto_retry = auto_retry_on_402
        self._raise_on_rejection = raise_on_policy_rejection
        self._clock = _resolve_clock(clock, policy)
        self._cred_mode: CredentialMode = unmetered_credential_policy
        self._credential_headers = tuple(h.lower() for h in credential_headers)
        self._credential_prefixes = tuple(credential_value_prefixes)
        self._estimate_cost = estimate_cost
        self._actual_cost = actual_cost
        self._cred_ttl = credential_ttl_seconds
        self._wallet_challenge_mode = wallet_challenge_mode

    # -- credential-mode ---------------------------------------------------

    def _has_credential(self, request: httpx.Request) -> bool:
        headers = request.headers  # case-insensitive
        if any(name in headers for name in self._credential_headers):
            return True
        auth = headers.get("authorization")
        if auth and self._credential_prefixes:
            token = auth.strip()
            if token.lower().startswith("bearer "):
                token = token[7:].strip()
            return token.startswith(self._credential_prefixes)
        return False

    def _meter_begin(self, request: httpx.Request) -> str | None:
        """Runs BEFORE the request is sent. Returns an intent id if a metered reservation was taken."""
        # This opt-in is only for AgentCore Gateway wallet routes: the first call must reach
        # the gateway to obtain its price challenge, which is then policy-checked below.
        if self._wallet_challenge_mode and self._has_credential(request):
            return None
        if request.extensions.get(ALLOW_UNMETERED_EXTENSION) or not self._has_credential(request):
            return None
        if self._cred_mode == "allow":
            return None
        if self._cred_mode == "block":
            raise PolicyViolationError(
                PolicyErrorCode.UNMETERED_CREDENTIAL,
                "Request carries a gateway credential that can bypass the HTTP 402 flow; the local "
                "budget/RPM firewall cannot meter it. Blocked (fail-closed).",
            )

        assert self._estimate_cost is not None  # guaranteed by __init__
        try:
            estimate = self._estimate_cost(request)
        except Exception as exc:  # noqa: BLE001
            raise PolicyViolationError(PolicyErrorCode.INVALID_AMOUNT_FORMAT, "estimate_cost callback failed") from exc

        intent_id = f"cred_{uuid.uuid4().hex}"
        decision = self._policy.reserve_metered(  # type: ignore[attr-defined]
            intent_id, estimate, request.url.host, self._cred_ttl
        )
        if not decision.approved:
            code = _rejection_code(decision)
            raise PolicyViolationError(code, f"credential call rejected by policy: {code.value}")
        return intent_id

    def _meter_end(self, intent_id: str, response: httpx.Response) -> None:
        """Settle a metered credential call once a response exists."""
        code = response.status_code
        if 200 <= code < 300:
            actual: int | None = None
            if self._actual_cost is not None:
                try:
                    actual = self._actual_cost(response)  # must read headers only
                except Exception:  # noqa: BLE001
                    logger.exception("actual_cost callback failed; keeping the estimate")
            self._policy.settle_metered(intent_id, actual)  # type: ignore[attr-defined]
        elif code >= 500:
            # Upstream state unknown: HOLD the reservation until TTL and feed the breaker.
            _safe_record_failure(self._policy, f"upstream {code} on credential call")
        else:
            # 1xx/3xx/4xx (including 402): gateway did not serve/charge -> give the quota back.
            try:
                self._policy.release(intent_id)
            except Exception:  # noqa: BLE001
                logger.exception("release of credential reservation %s failed; held until TTL", intent_id)

    # -- x402 --------------------------------------------------------------

    def _prepare_payment(self, request: httpx.Request, response: httpx.Response) -> tuple[Any, Any] | None:
        challenge = extract_challenge_from_headers(response.headers)
        if challenge is None:
            return None  # not a compliant x402 challenge
        if challenge.is_expired(self._clock()):
            return None
        if challenge.scheme not in ("EIP-3009", "agentpay-wallet"):
            raise PolicyViolationError(
                PolicyErrorCode.POLICY_SYSTEM_ERROR, f"unsupported payment scheme: {challenge.scheme}"
            )
        if challenge.scheme == "agentpay-wallet":
            expected_binding = self._request_binding(request)
            if (challenge.extensions or {}).get("requestBinding") != expected_binding:
                raise PolicyViolationError(
                    PolicyErrorCode.POLICY_SYSTEM_ERROR, "wallet challenge requestBinding mismatch"
                )
            if not (challenge.extensions or {}).get("routeId"):
                raise PolicyViolationError(PolicyErrorCode.POLICY_SYSTEM_ERROR, "wallet challenge missing routeId")
            raw_path, _, _ = request.url.raw_path.partition(b"?")
            if challenge.resource_uri != (raw_path.decode("ascii") or "/"):
                raise PolicyViolationError(PolicyErrorCode.POLICY_SYSTEM_ERROR, "wallet challenge resourceUri mismatch")

        payment_request = challenge.to_payment_request(domain=request.url.host)
        # SECURITY-REVIEW: reserve the exact seller challenge amount before generating wallet authorization.
        decision = self._policy.reserve(
            intent_id=payment_request.intent_id,
            amount=payment_request.amount,
            payee=payment_request.payee,
            asset=payment_request.asset,
            network=payment_request.network,
            domain=payment_request.domain,
            ttl_seconds=payment_request.ttl_seconds,
        )
        if not decision.approved:
            if self._raise_on_rejection:
                code = _rejection_code(decision)
                raise PolicyViolationError(code, f"Payment policy rejected 402 challenge: {code.value}")
            return None
        if decision.reservation is None:  # explicit check: survives `python -O`
            raise PolicyViolationError(PolicyErrorCode.POLICY_SYSTEM_ERROR, "approved decision without reservation")
        return challenge, decision.reservation

    @staticmethod
    def _request_binding(request: httpx.Request) -> str:
        """Match the Go Gateway's method/path/query/body SHA-256 canonicalization."""
        raw_path, marker, raw_query = request.url.raw_path.partition(b"?")
        path = raw_path.decode("ascii") or "/"
        query = raw_query.decode("ascii") if marker else ""
        body_digest = hashlib.sha256(request.read()).hexdigest()
        canonical = f"{request.method.upper()}\n{path}\n{query}\n{body_digest}".encode("utf-8")
        return "sha256:" + hashlib.sha256(canonical).hexdigest()

    def _sign_and_clone(self, request: httpx.Request, challenge: Any, reservation: Any) -> httpx.Request:
        # Everything here happens BEFORE transmission, so releasing on failure is safe.
        try:
            if challenge.scheme == "agentpay-wallet":
                # SECURITY-REVIEW: the challenge-bound reservation is the buyer-side approval gate.
                if reservation.intent_id != challenge.challenge_id or reservation.amount != challenge.amount_base_units:
                    raise PolicyViolationError(
                        PolicyErrorCode.POLICY_SYSTEM_ERROR, "wallet reservation does not match challenge"
                    )
                if reservation.expires_at < challenge.valid_before:
                    raise PolicyViolationError(
                        PolicyErrorCode.POLICY_SYSTEM_ERROR, "wallet reservation expires before challenge"
                    )
                request_binding = (challenge.extensions or {}).get("requestBinding")
                if not request_binding:
                    raise PolicyViolationError(
                        PolicyErrorCode.POLICY_SYSTEM_ERROR, "wallet challenge missing requestBinding"
                    )
                wallet_auth = WalletAuthorization(
                    challengeId=challenge.challenge_id,
                    nonce="0x" + secrets.token_bytes(32).hex(),
                    validAfter=challenge.valid_after,
                    validBefore=challenge.valid_before,
                    amount=challenge.amount,
                    resourceUri=challenge.resource_uri,
                    requestBinding=request_binding,
                )
                headers = httpx.Headers(request.headers)
                headers["PAYMENT-SIGNATURE"] = encode_wallet_authorization(wallet_auth)
                content = request.read()
                return httpx.Request(
                    method=request.method,
                    url=request.url,
                    headers=headers,
                    content=content,
                    extensions=dict(request.extensions),
                )
            authorization = self._signer.sign_payment_authorization(challenge, reservation)
            return _clone_request_with_authorization(request, authorization)
        except Exception:
            self._policy.release(reservation.intent_id)
            raise

    def _settle_x402(self, intent_id: str, retry_response: httpx.Response, scheme: str) -> None:
        code = retry_response.status_code
        # SECURITY-REVIEW: only a definitive wallet 4xx releases; ambiguous and 5xx outcomes stay reserved.
        if 200 <= code < 300:
            self._policy.commit(intent_id)
        elif scheme == "agentpay-wallet" and 400 <= code < 500:
            # Wallet authorization has no chain signature; a definitive gateway rejection means no hold was dispatched.
            self._policy.release(intent_id)
        elif code >= 500:
            # Signature is on the wire: keep RESERVED (no auto release) and feed the breaker.
            _safe_record_failure(self._policy, f"upstream {code} after payment")


# ---------------------------------------------------------------------------
# transports
# ---------------------------------------------------------------------------


class AgentCoreTransport(_AgentCoreCore, httpx.BaseTransport):
    """
    Synchronous httpx transport interceptor for AgentCore.

    Transparently catches HTTP 402 Payment Required responses, evaluates the
    challenge against the local policy firewall, then either signs EIP-3009 or
    creates an AgentCore wallet authorization before replaying the request.
    """

    def __init__(
        self,
        inner_transport: httpx.BaseTransport,
        signer: ISigner,
        policy: IPolicyEngine,
        *,
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
    ) -> None:
        httpx.BaseTransport.__init__(self)
        _AgentCoreCore.__init__(
            self,
            signer,
            policy,
            auto_retry_on_402=auto_retry_on_402,
            raise_on_policy_rejection=raise_on_policy_rejection,
            clock=clock,
            unmetered_credential_policy=unmetered_credential_policy,
            credential_headers=credential_headers,
            credential_value_prefixes=credential_value_prefixes,
            estimate_cost=estimate_cost,
            actual_cost=actual_cost,
            credential_ttl_seconds=credential_ttl_seconds,
            wallet_challenge_mode=wallet_challenge_mode,
        )
        self._inner_transport = inner_transport

    def close(self) -> None:
        self._inner_transport.close()

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        meter_id = self._meter_begin(request)  # may raise BEFORE anything is sent
        try:
            response = self._inner_transport.handle_request(request)
        except Exception:
            if meter_id is not None:
                # Request may have reached the gateway: keep the reservation until TTL.
                _safe_record_failure(self._policy, "transport error on credential call")
            raise
        if meter_id is not None:
            self._meter_end(meter_id, response)

        if self._wallet_challenge_mode and self._has_credential(request) and 200 <= response.status_code < 300:
            response.close()
            raise PolicyViolationError(
                PolicyErrorCode.UNMETERED_CREDENTIAL,
                "Wallet challenge mode expected a 402 price challenge; the gateway served the credential request directly.",
            )

        if response.status_code != 402 or not self._auto_retry:
            return response

        prepared = self._prepare_payment(request, response)
        if prepared is None:
            return response
        challenge, reservation = prepared

        retry_request = self._sign_and_clone(request, challenge, reservation)
        response.close()  # free the 402 connection before replaying

        # Transmission safety boundary: once sent, never auto-release on failure.
        try:
            retry_response = self._inner_transport.handle_request(retry_request)
        except Exception:
            _safe_record_failure(self._policy, "transport error after payment signature sent")
            raise

        self._settle_x402(reservation.intent_id, retry_response, challenge.scheme)
        return retry_response


class AsyncAgentCoreTransport(_AgentCoreCore, httpx.AsyncBaseTransport):
    """
    Asynchronous httpx transport interceptor for AgentCore.

    Async equivalent of AgentCoreTransport for AsyncClient and ASGI applications.
    NOTE: policy calls are synchronous (SQLite). They are short, but they do block the event loop.
    """

    def __init__(
        self,
        inner_transport: httpx.AsyncBaseTransport,
        signer: ISigner,
        policy: IPolicyEngine,
        *,
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
    ) -> None:
        httpx.AsyncBaseTransport.__init__(self)
        _AgentCoreCore.__init__(
            self,
            signer,
            policy,
            auto_retry_on_402=auto_retry_on_402,
            raise_on_policy_rejection=raise_on_policy_rejection,
            clock=clock,
            unmetered_credential_policy=unmetered_credential_policy,
            credential_headers=credential_headers,
            credential_value_prefixes=credential_value_prefixes,
            estimate_cost=estimate_cost,
            actual_cost=actual_cost,
            credential_ttl_seconds=credential_ttl_seconds,
            wallet_challenge_mode=wallet_challenge_mode,
        )
        self._inner_transport = inner_transport

    async def aclose(self) -> None:
        await self._inner_transport.aclose()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        meter_id = self._meter_begin(request)
        try:
            response = await self._inner_transport.handle_async_request(request)
        except Exception:
            if meter_id is not None:
                _safe_record_failure(self._policy, "transport error on credential call")
            raise
        if meter_id is not None:
            self._meter_end(meter_id, response)

        if self._wallet_challenge_mode and self._has_credential(request) and 200 <= response.status_code < 300:
            await response.aclose()
            raise PolicyViolationError(
                PolicyErrorCode.UNMETERED_CREDENTIAL,
                "Wallet challenge mode expected a 402 price challenge; the gateway served the credential request directly.",
            )

        if response.status_code != 402 or not self._auto_retry:
            return response

        prepared = self._prepare_payment(request, response)
        if prepared is None:
            return response
        challenge, reservation = prepared

        retry_request = self._sign_and_clone(request, challenge, reservation)
        await response.aclose()

        try:
            retry_response = await self._inner_transport.handle_async_request(retry_request)
        except Exception:
            _safe_record_failure(self._policy, "transport error after payment signature sent")
            raise

        self._settle_x402(reservation.intent_id, retry_response, challenge.scheme)
        return retry_response
