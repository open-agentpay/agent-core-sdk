"""
Pre-built LangChain PaidHttpTool for AgentCore.

Enables LangChain agents to invoke arbitrary paid HTTP APIs with automatic
402 payment negotiation, payment authorization signing, and financial firewall guardrails.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

try:
    from langchain_core.tools import BaseTool, ToolException
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "The 'langchain-core' package is required to use agentpay.integrations.langchain. "
        "Please install it via: pip install 'agentpay[langchain]' or pip install langchain-core"
    ) from exc

import httpx

from agent_core.client.client import AgentCoreClient, AsyncAgentCoreClient
from agent_core.core.errors import X402Error
from agent_core.policy.errors import PolicyViolationError


class PaidHttpInput(BaseModel):
    """Schema for PaidHttpTool invocation arguments."""

    model_config = ConfigDict(frozen=True)

    url: str = Field(description="The complete URL of the target API endpoint.")
    method: str = Field(
        default="GET",
        description="HTTP method to use (e.g. 'GET', 'POST', 'PUT', 'DELETE'). Defaults to 'GET'.",
    )
    params: dict[str, Any] | None = Field(
        default=None,
        description="Optional query parameters to append to the URL.",
    )
    json_data: dict[str, Any] | None = Field(
        default=None,
        description="Optional JSON body payload for POST/PUT requests.",
    )
    headers: dict[str, str] | None = Field(
        default=None,
        description="Optional additional HTTP request headers.",
    )


class PaidHttpTool(BaseTool):
    """
    Standard LangChain tool for querying paid HTTP endpoints protected by AgentCore/x402.

    Automatically handles HTTP 402 challenge negotiation, offline signing,
    and budget firewall verification.
    """

    name: str = "paid_http_request"
    description: str = (
        "Execute an HTTP request to an API endpoint that may require payment. "
        "Automatically handles x402 payment negotiation, cryptographic authorization, "
        "and checks local budget limits before spending."
    )
    args_schema: type[BaseModel] = PaidHttpInput
    client: AgentCoreClient | None = None
    async_client: AsyncAgentCoreClient | None = None
    handle_policy_violation: bool = True
    handle_tool_error: bool = True

    def _run(
        self,
        url: str,
        method: str = "GET",
        params: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> str:
        """Synchronously execute paid HTTP request."""
        if self.client is None:
            raise ToolException("PaidHttpTool requires an AgentPayClient instance.")

        try:
            response = self.client.request(
                method=method.upper(),
                url=url,
                params=params,
                json=json_data,
                headers=headers,
            )
            response.raise_for_status()

            # Return pretty formatted json if json payload, otherwise text
            try:
                data = response.json()
                return json.dumps(data, ensure_ascii=False)
            except Exception:
                return response.text

        except PolicyViolationError as exc:
            if self.handle_policy_violation:
                raise ToolException(f"AgentPay Firewall Rejected: [{exc.code.value}] {exc.detail or str(exc)}") from exc
            raise
        except X402Error as exc:
            if self.handle_policy_violation:
                raise ToolException(f"AgentCore x402 Protocol Error: {exc}") from exc
            raise
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 402 and self.handle_policy_violation:
                raise ToolException(
                    f"AgentCore Payment Failed: 402 challenge could not be satisfied ({exc.response.text})"
                ) from exc
            raise ToolException(f"HTTP error {exc.response.status_code}: {exc.response.text}") from exc
        except httpx.HTTPError as exc:
            raise ToolException(f"HTTP request failed: {exc}") from exc

    async def _arun(
        self,
        url: str,
        method: str = "GET",
        params: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> str:
        """Asynchronously execute paid HTTP request."""
        client = self.async_client
        if client is None:
            # Fallback to sync client run if async client not provided
            return self._run(
                url=url,
                method=method,
                params=params,
                json_data=json_data,
                headers=headers,
                **kwargs,
            )

        try:
            response = await client.request(
                method=method.upper(),
                url=url,
                params=params,
                json=json_data,
                headers=headers,
            )
            response.raise_for_status()

            try:
                data = response.json()
                return json.dumps(data, ensure_ascii=False)
            except Exception:
                return response.text

        except PolicyViolationError as exc:
            if self.handle_policy_violation:
                raise ToolException(f"AgentCore Firewall Rejected: [{exc.code.value}] {exc.detail or str(exc)}") from exc
            raise
        except X402Error as exc:
            if self.handle_policy_violation:
                raise ToolException(f"AgentCore x402 Protocol Error: {exc}") from exc
            raise
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 402 and self.handle_policy_violation:
                raise ToolException(
                    f"AgentCore Payment Failed: 402 challenge could not be satisfied ({exc.response.text})"
                ) from exc
            raise ToolException(f"HTTP error {exc.response.status_code}: {exc.response.text}") from exc
        except httpx.HTTPError as exc:
            raise ToolException(f"HTTP request failed: {exc}") from exc
