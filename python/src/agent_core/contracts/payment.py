"""
AgentPay Payment Request Contracts.
"""

from __future__ import annotations

import uuid
from typing import Any
from pydantic import BaseModel, ConfigDict, Field, model_validator

from agent_core.contracts.context import AgentContext


class ResourceContext(BaseModel):
    """Resource identification for the targeted paid service or challenge."""

    model_config = ConfigDict(frozen=True, extra="allow")

    resource_id: str | None = Field(default=None, description="Registered route or resource identifier.")
    challenge_id: str | None = Field(default=None, description="x402 or wallet challenge identifier if pre-challenged.")


class PaymentRequest(BaseModel):
    """Framework-agnostic payment initiation request contract."""

    model_config = ConfigDict(frozen=True, extra="allow")

    resource: ResourceContext = Field(description="Target resource or challenge.")
    idempotency_key: str = Field(
        default_factory=lambda: f"idem_{uuid.uuid4().hex}",
        description="Unique client-generated idempotency key preventing duplicate charges.",
    )

    @model_validator(mode="before")
    @classmethod
    def _ensure_idempotency_key(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if not data.get("idempotency_key"):
                data["idempotency_key"] = f"idem_{uuid.uuid4().hex}"
        return data
    context: AgentContext | None = Field(default=None, description="Agent and framework provenance metadata.")
    amount: str | None = Field(default=None, description="Precise decimal string amount (e.g. '0.20').")
    asset: str | None = Field(default=None, description="Currency/asset symbol (e.g. 'USDC', 'CNY').")
    network: str | None = Field(default=None, description="Target settlement network (e.g. 'base', 'ethereum').")
    metadata: dict[str, Any] | None = Field(default=None, description="Additional custom metadata tags.")
