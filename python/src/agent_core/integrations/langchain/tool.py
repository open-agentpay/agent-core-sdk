"""
LangChain PaidTool and @paid_tool decorator for AgentCore.

Wraps LangChain BaseTool and StructuredTool to automatically execute functions
using AgentCoreClient with automatic x402 payment negotiation and financial firewall enforcement.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel

try:
    from langchain_core.tools import StructuredTool, ToolException
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "The 'langchain-core' package is required to use agentpay.integrations.langchain. "
        "Please install it via: pip install 'agentpay[langchain]' or pip install langchain-core"
    ) from exc

from agent_core.client.client import AgentCoreClient, AsyncAgentCoreClient
from agent_core.core.errors import X402Error
from agent_core.policy.errors import PolicyViolationError


class PaidTool(StructuredTool):
    """
    LangChain tool wrapper for paid functions and APIs protected by AgentCore.

    Subclasses StructuredTool to provide full Pydantic v2 schema generation,
    transparent 402 payment negotiation, and financial firewall guardrails.
    """

    client: AgentCoreClient | AsyncAgentCoreClient | None = None
    handle_policy_violation: bool = True

    @classmethod
    def from_function(
        cls,
        func: Callable[..., Any] | None = None,
        coroutine: Callable[..., Any] | None = None,
        name: str | None = None,
        description: str | None = None,
        client: AgentCoreClient | AsyncAgentCoreClient | None = None,
        args_schema: type[BaseModel] | None = None,
        return_direct: bool = False,
        handle_tool_error: bool = True,
        handle_policy_violation: bool = True,
        **kwargs: Any,
    ) -> PaidTool:
        """Create a PaidTool from a sync function or async coroutine."""
        target_fn = func or coroutine
        if target_fn is None:
            raise ValueError("Either 'func' or 'coroutine' must be provided.")

        tool_name = name or target_fn.__name__
        tool_desc = description or target_fn.__doc__ or f"Paid tool {tool_name}"

        # Wrap target functions with AgentCore error handling and parameter injection
        wrapped_sync = None
        wrapped_async = None

        if func is not None:
            wrapped_sync = _wrap_function(
                func,
                bound_client=client,
                handle_policy_violation=handle_policy_violation,
            )

        if coroutine is not None:
            wrapped_async = _wrap_coroutine(
                coroutine,
                bound_client=client,
                handle_policy_violation=handle_policy_violation,
            )

        tool = super().from_function(
            func=wrapped_sync,
            coroutine=wrapped_async,
            name=tool_name,
            description=tool_desc,
            args_schema=args_schema,
            return_direct=return_direct,
            handle_tool_error=handle_tool_error,
            **kwargs,
        )

        tool.client = client
        tool.handle_policy_violation = handle_policy_violation
        return tool  # type: ignore[return-value]


def _wrap_function(
    fn: Callable[..., Any],
    *,
    bound_client: AgentCoreClient | AsyncAgentCoreClient | None,
    handle_policy_violation: bool,
) -> Callable[..., Any]:
    """Wrap a synchronous function to inject client and intercept firewall violations."""
    sig = inspect.signature(fn)
    has_client_param = "client" in sig.parameters

    filtered_params = [p for name, p in sig.parameters.items() if name != "client"] if has_client_param else None

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if has_client_param and "client" not in kwargs and bound_client is not None:
            kwargs["client"] = bound_client

        try:
            return fn(*args, **kwargs)
        except PolicyViolationError as exc:
            if handle_policy_violation:
                raise ToolException(f"AgentCore Firewall Rejected: [{exc.code.value}] {exc.detail or str(exc)}") from exc
            raise
        except X402Error as exc:
            if handle_policy_violation:
                raise ToolException(f"AgentCore x402 Protocol Error: {exc}") from exc
            raise

    if filtered_params is not None:
        wrapper.__signature__ = sig.replace(parameters=filtered_params)  # type: ignore[attr-defined]

    return wrapper


def _wrap_coroutine(
    coro: Callable[..., Any],
    *,
    bound_client: AgentCoreClient | AsyncAgentCoreClient | None,
    handle_policy_violation: bool,
) -> Callable[..., Any]:
    """Wrap an asynchronous coroutine function to inject client and intercept firewall violations."""
    sig = inspect.signature(coro)
    has_client_param = "client" in sig.parameters

    filtered_params = [p for name, p in sig.parameters.items() if name != "client"] if has_client_param else None

    @functools.wraps(coro)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        if has_client_param and "client" not in kwargs and bound_client is not None:
            kwargs["client"] = bound_client

        try:
            return await coro(*args, **kwargs)
        except PolicyViolationError as exc:
            if handle_policy_violation:
                raise ToolException(f"AgentCore Firewall Rejected: [{exc.code.value}] {exc.detail or str(exc)}") from exc
            raise
        except X402Error as exc:
            if handle_policy_violation:
                raise ToolException(f"AgentCore x402 Protocol Error: {exc}") from exc
            raise

    if filtered_params is not None:
        wrapper.__signature__ = sig.replace(parameters=filtered_params)  # type: ignore[attr-defined]

    return wrapper


def paid_tool(
    *args: Any,
    name: str | None = None,
    description: str | None = None,
    client: AgentCoreClient | AsyncAgentCoreClient | None = None,
    return_direct: bool = False,
    args_schema: type[BaseModel] | None = None,
    handle_tool_error: bool = True,
    handle_policy_violation: bool = True,
    **kwargs: Any,
) -> Any:
    """
    Decorator to transform a Python function into an AgentCore-protected LangChain tool.

    Usage:
        @paid_tool(name="stock_quote", description="Get stock price", client=client)
        def get_stock_quote(ticker: str) -> dict:
            return client.get(f"https://api.market.com/v1/quote?ticker={ticker}").json()

        # Or with automatic client injection:
        @paid_tool(client=client)
        def get_weather(city: str, client: AgentCoreClient) -> str:
            return client.get(f"https://api.weather.com/v1?city={city}").text
    """

    def _decorator(target_fn: Callable[..., Any]) -> PaidTool:
        is_async = inspect.iscoroutinefunction(target_fn)

        return PaidTool.from_function(
            func=None if is_async else target_fn,
            coroutine=target_fn if is_async else None,
            name=name,
            description=description,
            client=client,
            args_schema=args_schema,
            return_direct=return_direct,
            handle_tool_error=handle_tool_error,
            handle_policy_violation=handle_policy_violation,
            **kwargs,
        )

    # Support @paid_tool without parentheses
    if len(args) == 1 and callable(args[0]):
        return _decorator(args[0])

    return _decorator
