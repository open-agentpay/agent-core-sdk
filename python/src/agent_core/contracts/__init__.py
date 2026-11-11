"""
AgentPay Contracts Package: Framework-agnostic data models, state machines, and error specifications.
"""

from agent_core.contracts.context import AgentContext
from agent_core.contracts.decision import DecisionEnum, PolicyDecision
from agent_core.contracts.errors import (
    AgentPayAuthenticationError,
    AgentPayBudgetExceededError,
    AgentPayCircuitOpenError,
    AgentPayIdempotencyConflictError,
    AgentPayIntegrationError,
    AgentPayMerchantNotAllowedError,
    AgentPayPolicyDeniedError,
    AgentPayRateLimitedError,
    map_integration_error,
)
from agent_core.contracts.payment import PaymentRequest, ResourceContext
from agent_core.contracts.result import (
    FulfillmentStatus,
    PaymentIntentStatus,
    PaymentResult,
    SettlementStatus,
)

__all__ = [
    "AgentContext",
    "ResourceContext",
    "PaymentRequest",
    "DecisionEnum",
    "PolicyDecision",
    "PaymentIntentStatus",
    "SettlementStatus",
    "FulfillmentStatus",
    "PaymentResult",
    "AgentPayIntegrationError",
    "AgentPayAuthenticationError",
    "AgentPayPolicyDeniedError",
    "AgentPayBudgetExceededError",
    "AgentPayMerchantNotAllowedError",
    "AgentPayIdempotencyConflictError",
    "AgentPayRateLimitedError",
    "AgentPayCircuitOpenError",
    "map_integration_error",
]
