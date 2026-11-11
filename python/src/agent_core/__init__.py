"""
agent-core-sdk / agentpay-core-sdk: Universal AI Agent Gateway & FinOps Client SDK.
"""

from __future__ import annotations

from agent_core.client.client import (
    AgentCoreClient,
    AgentPayClient,
    AsyncAgentCoreClient,
    AsyncAgentPayClient,
)
from agent_core.contracts import (
    AgentContext,
    AgentPayAuthenticationError,
    AgentPayBudgetExceededError,
    AgentPayCircuitOpenError,
    AgentPayIdempotencyConflictError,
    AgentPayIntegrationError,
    AgentPayMerchantNotAllowedError,
    AgentPayPolicyDeniedError,
    AgentPayRateLimitedError,
    DecisionEnum,
    FulfillmentStatus,
    PaymentIntentStatus,
    PaymentRequest,
    PaymentResult,
    PolicyDecision,
    ResourceContext,
    SettlementStatus,
    map_integration_error,
)
from agent_core.policy.models import PolicyConfig
from agent_core.policy.sqlite_engine import SQLitePolicyEngine

__version__ = "0.4.0"

__all__ = [
    "AgentCoreClient",
    "AgentPayClient",
    "AsyncAgentCoreClient",
    "AsyncAgentPayClient",
    "PolicyConfig",
    "SQLitePolicyEngine",
    "AgentContext",
    "ResourceContext",
    "PaymentRequest",
    "PolicyDecision",
    "DecisionEnum",
    "PaymentResult",
    "PaymentIntentStatus",
    "SettlementStatus",
    "FulfillmentStatus",
    "AgentPayIntegrationError",
    "AgentPayAuthenticationError",
    "AgentPayPolicyDeniedError",
    "AgentPayBudgetExceededError",
    "AgentPayMerchantNotAllowedError",
    "AgentPayIdempotencyConflictError",
    "AgentPayRateLimitedError",
    "AgentPayCircuitOpenError",
    "map_integration_error",
    "__version__",
]
