"""
AgentPay Policy Decision Contracts.
"""

from __future__ import annotations

import uuid
from enum import Enum
from pydantic import BaseModel, ConfigDict, Field, model_validator


class DecisionEnum(str, Enum):
    """Categorical policy evaluation outcomes."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    REVIEW = "REVIEW"


class PolicyDecision(BaseModel):
    """Result of a policy evaluation against AgentPay financial firewall."""

    model_config = ConfigDict(frozen=True, extra="allow")

    decision: DecisionEnum | str = Field(description="Policy decision (ALLOW, DENY, REQUIRE_APPROVAL, REVIEW).")
    decision_id: str = Field(
        default_factory=lambda: f"dec_{uuid.uuid4().hex}",
        description="Unique policy decision identifier.",
    )
    reason_code: str = Field(
        default="POLICY_PASSED",
        description="Machine-readable rule identifier (e.g. 'POLICY_PASSED', 'ERR_POLICY_MAX_PER_TX').",
    )

    @model_validator(mode="before")
    @classmethod
    def _fill_defaults(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if not data.get("decision_id"):
                data["decision_id"] = f"dec_{uuid.uuid4().hex}"
            if not data.get("reason_code"):
                data["reason_code"] = "POLICY_PASSED"
        return data
    reason: str | None = Field(default=None, description="Human-readable explanation of the decision.")
    payment_intent_id: str | None = Field(default=None, description="Associated payment intent if pre-created.")
    policy_version: str | None = Field(default=None, description="Active policy version identifier.")
    budget_reservation_id: str | None = Field(default=None, description="Pre-reserved hold identifier if applicable.")
    expires_at: str | None = Field(default=None, description="ISO8601 expiration timestamp of this authorization.")

    @property
    def is_allowed(self) -> bool:
        """Returns True if the decision explicitly allows execution."""
        return self.decision == DecisionEnum.ALLOW or self.decision == "ALLOW"

    @property
    def requires_approval(self) -> bool:
        """Returns True if execution requires human-in-the-loop approval."""
        return self.decision == DecisionEnum.REQUIRE_APPROVAL or self.decision == "REQUIRE_APPROVAL"
