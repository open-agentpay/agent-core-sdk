"""
Mock Seller Service implementation for AgentCore E2E testing.

Provides reference in-memory implementation of a protected seller / merchant API:
  - Generates x402 V2 challenges on initial unauthenticated GET requests (HTTP 402)
  - Inspects PAYMENT-SIGNATURE on retried requests
  - Verifies cryptographic signatures and nonces via Facilitator
  - Settles valid authorizations via Facilitator
  - Delivers protected resource payloads upon verified settlement (HTTP 200 OK)
  - Supports configurable fault injections (upstream crash, facilitator rejection, replay)
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from typing import Any

import httpx
from agentpay_gateway.facilitator.errors import (
    ChallengeExpiredError,
    InvalidSignatureError,
    NonceAlreadyUsedError,
)
from agentpay_gateway.facilitator.models import SettleRequest, VerifyRequest
from agentpay_gateway.facilitator.service import MockFacilitatorService

from agent_core.core.codecs import (
    HEADER_PAYMENT_REQUIRED,
    encode_challenge,
    extract_authorization_from_headers,
)
from agent_core.core.models import PaymentChallenge


class MockSellerService:
    """
    Reference in-memory Seller service for x402 V2 payment negotiation.

    Simulates an upstream API provider protecting paid routes with the x402 protocol.
    """

    def __init__(
        self,
        payee_address: str,
        facilitator: MockFacilitatorService,
        *,
        network: str = "agentpay:internal-ledger",
        asset: str = "CNY",
        asset_symbol: str = "CNY",
        decimals: int = 6,
        clock: Callable[[], int] | None = None,
        challenge_ttl_seconds: int = 300,
    ) -> None:
        self.payee_address = payee_address.lower()
        self.facilitator = facilitator
        self.network = network
        self.asset = asset.lower()
        self.asset_symbol = asset_symbol
        self.decimals = decimals
        self._clock = clock or (lambda: int(time.time()))
        self.challenge_ttl_seconds = challenge_ttl_seconds

        # Routes registry: path -> {"price": int, "handler": Callable | None}
        self._routes: dict[str, dict[str, Any]] = {}
        # Active issued challenges: challenge_id -> PaymentChallenge
        self._active_challenges: dict[str, PaymentChallenge] = {}
        # Settled transactions audit log: list of dicts
        self.settled_transactions: list[dict[str, Any]] = []

        # Fault injection flags
        self.fail_on_upstream: bool = False
        self.fail_verification: bool = False
        self.custom_challenge_override: PaymentChallenge | None = None

    def add_route(
        self,
        path: str,
        price: int,
        *,
        handler: Callable[[httpx.Request], dict[str, Any]] | None = None,
    ) -> None:
        """Register a protected paid route with price in integer base units."""
        self._routes[path] = {
            "price": price,
            "handler": handler,
        }

    def get_time(self) -> int:
        return self._clock()

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        """Process incoming HTTP request according to x402 V2 lifecycle."""
        path = request.url.path

        # 1. Unprotected / public routes
        if path not in self._routes:
            return httpx.Response(
                200,
                json={"status": "ok", "message": "Public unmetered resource"},
                request=request,
            )

        route_info = self._routes[path]
        price = route_info["price"]

        # 2. Check for PAYMENT-SIGNATURE header
        auth = extract_authorization_from_headers(request.headers)
        if auth is None:
            # Emit 402 Payment Required with x402 V2 challenge
            now = self.get_time()
            if self.custom_challenge_override is not None:
                challenge = self.custom_challenge_override
            else:
                challenge_id = f"ch_seller_{uuid.uuid4().hex[:12]}"
                challenge = PaymentChallenge(
                    version="2.0",
                    challengeId=challenge_id,
                    network=self.network,
                    asset=self.asset,
                    assetSymbol=self.asset_symbol,
                    decimals=self.decimals,
                    amount=str(price),
                    payee=self.payee_address,
                    scheme="agentpay-wallet",
                    validAfter=now - 60,
                    validBefore=now + self.challenge_ttl_seconds,
                    facilitatorUrl="https://facilitator.example.com",
                    resourceUri=path,
                )

            self._active_challenges[challenge.challenge_id] = challenge
            encoded_challenge = encode_challenge(challenge)

            headers = {
                HEADER_PAYMENT_REQUIRED: encoded_challenge,
                "Content-Type": "application/json",
            }
            return httpx.Response(
                402,
                headers=headers,
                json={
                    "error": "Payment Required",
                    "challengeId": challenge.challenge_id,
                    "price": price,
                    "asset": self.asset_symbol,
                },
                request=request,
            )

        # 3. Retrieve challenge
        challenge = self._active_challenges.get(auth.challenge_id)
        if challenge is None:
            # Also allow fallback to custom override if set
            challenge = self.custom_challenge_override

        if challenge is None:
            return httpx.Response(
                400,
                json={"error": f"Unknown or expired challengeId: {auth.challenge_id}"},
                request=request,
            )

        # 4. Verify with Facilitator
        if self.fail_verification:
            return httpx.Response(
                401,
                json={"error": "Simulated seller verification failure"},
                request=request,
            )

        try:
            verify_req = VerifyRequest(challenge=challenge, authorization=auth)
            verify_res = self.facilitator.verify(verify_req)
        except InvalidSignatureError as exc:
            return httpx.Response(
                401,
                json={"error": "Invalid signature", "detail": str(exc)},
                request=request,
            )
        except NonceAlreadyUsedError as exc:
            return httpx.Response(
                409,
                json={"error": "Nonce already used", "detail": str(exc)},
                request=request,
            )
        except ChallengeExpiredError as exc:
            return httpx.Response(
                410,
                json={"error": "Challenge expired", "detail": str(exc)},
                request=request,
            )
        except Exception as exc:  # noqa: BLE001
            return httpx.Response(
                502,
                json={"error": "Facilitator verification error", "detail": str(exc)},
                request=request,
            )

        if not verify_res.valid:
            return httpx.Response(
                401,
                json={
                    "error": "Facilitator rejected signature",
                    "reason": verify_res.reason,
                },
                request=request,
            )

        # 5. Settle with Facilitator
        try:
            settle_req = SettleRequest(
                verification_token=verify_res.verification_token,
                authorization=auth,
                idempotency_key=f"idemp_{auth.nonce}",
            )
            settle_res = self.facilitator.settle(settle_req)
        except Exception as exc:  # noqa: BLE001
            return httpx.Response(
                502,
                json={"error": "Facilitator settlement failed", "detail": str(exc)},
                request=request,
            )

        # 6. Fault injection: upstream service crash
        if self.fail_on_upstream:
            return httpx.Response(
                500,
                json={"error": "Internal upstream service error after payment"},
                request=request,
            )

        # 7. Deliver protected resource (200 OK)
        handler = route_info.get("handler")
        if callable(handler):
            data = handler(request)
        else:
            data = {
                "message": f"Resource delivered for {path}",
                "pricePaid": price,
            }

        self.settled_transactions.append(
            {
                "challenge_id": challenge.challenge_id,
                "payer": auth.payer,
                "amount": price,
                "settlement_id": settle_res.settlement_id,
                "path": path,
            }
        )

        return httpx.Response(
            200,
            json={
                "data": data,
                "receipt": {
                    "settlementId": settle_res.settlement_id,
                    "status": settle_res.status.value,
                    "payer": auth.payer,
                    "amount": price,
                },
            },
            request=request,
        )

    def as_transport(self) -> httpx.BaseTransport:
        """Create a synchronous httpx transport directly connected to this seller."""
        return MockSellerTransport(self)

    def as_async_transport(self) -> httpx.AsyncBaseTransport:
        """Create an asynchronous httpx transport directly connected to this seller."""
        return AsyncMockSellerTransport(self)


class MockSellerTransport(httpx.BaseTransport):
    """Synchronous transport routing requests directly to MockSellerService."""

    def __init__(self, service: MockSellerService) -> None:
        super().__init__()
        self.service = service

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        return self.service.handle_request(request)


class AsyncMockSellerTransport(httpx.AsyncBaseTransport):
    """Asynchronous transport routing requests directly to MockSellerService."""

    def __init__(self, service: MockSellerService) -> None:
        super().__init__()
        self.service = service

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return self.service.handle_request(request)
