"""
AgentPay Standard Integration Error Contracts and Exceptions.
"""

from __future__ import annotations

from typing import Any


class AgentPayIntegrationError(Exception):
    """Base exception for all AgentPay harness and integration failures."""

    def __init__(
        self,
        code: str,
        message: str,
        status_code: int = 400,
        next_action: str = "STOP",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message
        self.status_code = status_code
        self.next_action = next_action
        self.details = details or {}


class AgentPayAuthenticationError(AgentPayIntegrationError):
    """Raised when API Key or identity credentials are missing or invalid."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            code="UNAUTHENTICATED",
            message=message,
            status_code=401,
            next_action="PROVIDE_API_KEY",
            details=details,
        )


class AgentPayPolicyDeniedError(AgentPayIntegrationError):
    """Raised when the AgentPay policy engine explicitly rejects execution."""

    def __init__(self, message: str, code: str = "POLICY_DENIED", details: dict[str, Any] | None = None) -> None:
        super().__init__(
            code=code,
            message=message,
            status_code=403,
            next_action="STOP",
            details=details,
        )


class AgentPayBudgetExceededError(AgentPayPolicyDeniedError):
    """Raised when single transaction cap or rolling budget limit is exceeded."""

    def __init__(self, message: str, next_action: str = "INCREASE_BUDGET", details: dict[str, Any] | None = None) -> None:
        super().__init__(
            code="BUDGET_EXCEEDED",
            message=message,
            details=details,
        )
        self.next_action = next_action or "INCREASE_BUDGET"


class AgentPayMerchantNotAllowedError(AgentPayPolicyDeniedError):
    """Raised when merchant or route is not active, unregistered, or disallowed."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            code="MERCHANT_NOT_ALLOWED",
            message=message,
            details=details,
        )


class AgentPayIdempotencyConflictError(AgentPayIntegrationError):
    """Raised when duplicate or conflicting request uses an active idempotency key."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            code="IDEMPOTENCY_CONFLICT",
            message=message,
            status_code=409,
            next_action="POLL_STATUS",
            details=details,
        )


class AgentPayRateLimitedError(AgentPayIntegrationError):
    """Raised when call frequency breaches RPM limits."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            code="RATE_LIMITED",
            message=message,
            status_code=429,
            next_action="BACKOFF",
            details=details,
        )


class AgentPayCircuitOpenError(AgentPayIntegrationError):
    """Raised when loop detection or circuit breaker has tripped."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            code="CIRCUIT_OPEN",
            message=message,
            status_code=503,
            next_action="STOP",
            details=details,
        )


def map_integration_error(
    status_code: int,
    code: str,
    message: str,
    next_action: str = "",
    details: dict[str, Any] | None = None,
) -> AgentPayIntegrationError:
    """Maps HTTP and gateway error payloads to structured Python exception classes."""
    normalized_code = (code or "").upper()

    if status_code == 401 or normalized_code == "UNAUTHENTICATED":
        return AgentPayAuthenticationError(message, details=details)
    if normalized_code == "BUDGET_EXCEEDED":
        return AgentPayBudgetExceededError(message, next_action=next_action or "INCREASE_BUDGET", details=details)
    if normalized_code == "MERCHANT_NOT_ALLOWED":
        return AgentPayMerchantNotAllowedError(message, details=details)
    if status_code == 409 or normalized_code == "IDEMPOTENCY_CONFLICT":
        return AgentPayIdempotencyConflictError(message, details=details)
    if status_code == 429 or normalized_code == "RATE_LIMITED":
        return AgentPayRateLimitedError(message, details=details)
    if normalized_code == "CIRCUIT_OPEN":
        return AgentPayCircuitOpenError(message, details=details)
    if status_code == 403 or "POLICY" in normalized_code:
        return AgentPayPolicyDeniedError(message, code=code, details=details)

    return AgentPayIntegrationError(
        code=code or "UNKNOWN_ERROR",
        message=message,
        status_code=status_code,
        next_action=next_action or "STOP",
        details=details,
    )
