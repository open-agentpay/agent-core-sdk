"""
AgentPay Framework-Agnostic Context Contracts.
"""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class AgentContext(BaseModel):
    """Contextual provenance metadata of the executing agent."""

    model_config = ConfigDict(frozen=True, extra="allow")

    tenant_id: str | None = Field(default=None, description="Tenant ID bound by API key credentials.")
    agent_id: str | None = Field(default=None, description="Logical Agent identifier.")
    run_id: str | None = Field(default=None, description="Harness run execution identifier for distributed tracing.")
    framework: str | None = Field(default=None, description="Framework name (e.g. 'langchain', 'openai', 'crewai').")
    framework_version: str | None = Field(default=None, description="Framework version string.")
    environment: str | None = Field(default=None, description="Deployment environment (e.g. 'production', 'staging').")
    tool_name: str | None = Field(default=None, description="Name of the calling tool invoking payment.")
    task_id: str | None = Field(default=None, description="Higher-level workflow task identifier.")
