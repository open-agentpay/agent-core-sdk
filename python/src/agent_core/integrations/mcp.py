"""
Model Context Protocol (MCP) Integration & Pricing Services for AgentPay.

Provides standardized pricing metadata annotations for MCP tools,
quota guard interfaces, and client pre-call interception hooks.
"""

from __future__ import annotations

import functools
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

from agent_core.policy.errors import PolicyErrorCode, PolicyViolationError


@dataclass
class McpPriceMetadata:
    """Standardized MCP Tool pricing metadata."""

    amount_cny: float
    amount_base_units: int = 0
    currency: str = "CNY"
    billing_mode: str = "per_call"
    hitl_required: bool = False
    vendor: Optional[str] = None
    description: Optional[str] = None

    def __post_init__(self) -> None:
        if self.amount_base_units == 0:
            self.amount_base_units = round(self.amount_cny * 1_000_000)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes pricing metadata to MCP schema standard format."""
        d: Dict[str, Any] = {
            "price_cny": round(self.amount_cny, 2),
            "price_base_units": self.amount_base_units,
            "currency": self.currency,
            "billing_mode": self.billing_mode,
            "hitl_required": self.hitl_required,
        }
        if self.vendor:
            d["vendor"] = self.vendor
        if self.description:
            d["description"] = self.description
        return d


@dataclass
class ToolCallContext:
    """Contextual metadata passed during MCP tool invocation."""

    agent_id: str
    tool_name: str
    amount_cny: float
    currency: str = "CNY"
    arguments: Optional[Dict[str, Any]] = None
    call_id: Optional[str] = None


class ToolQuotaGuard(ABC):
    """Abstract interface for Tool budget and quota governance."""

    @abstractmethod
    def evaluate(self, ctx: ToolCallContext) -> bool:
        """Evaluates whether the tool call is permitted under current policy."""
        pass

    @abstractmethod
    def reserve(self, ctx: ToolCallContext) -> str:
        """Reserves/holds quota for the pending call. Returns a unique hold_id."""
        pass

    @abstractmethod
    def commit(self, hold_id: str, actual_cost_cny: float) -> None:
        """Captures and settles the held quota upon successful execution."""
        pass

    @abstractmethod
    def release(self, hold_id: str, reason: str = "") -> None:
        """Releases the held quota without financial loss upon failure."""
        pass


class InMemoryToolQuotaGuard(ToolQuotaGuard):
    """
    Default in-memory quota guard implementation for local development,
    single-node instances, and unit tests.
    """

    def __init__(
        self,
        max_per_call_cny: float = 50.0,
        rolling_budget_cny: float = 500.0,
    ) -> None:
        self.max_per_call_cny = max_per_call_cny
        self.rolling_budget_cny = rolling_budget_cny
        self._total_spent_cny: float = 0.0
        self._active_holds: Dict[str, Dict[str, Any]] = {}

    def evaluate(self, ctx: ToolCallContext) -> bool:
        """Returns True if within single transaction cap and remaining budget."""
        if ctx.amount_cny > self.max_per_call_cny:
            return False
        total_reserved = self.get_total_reserved_cny()
        if (self._total_spent_cny + total_reserved + ctx.amount_cny) > self.rolling_budget_cny:
            return False
        return True

    def reserve(self, ctx: ToolCallContext) -> str:
        """Holds quota; raises PolicyViolationError if limits are breached."""
        if ctx.amount_cny > self.max_per_call_cny:
            raise PolicyViolationError(
                PolicyErrorCode.SINGLE_TX_CAP_EXCEEDED,
                detail=f"SINGLE_TX_CAP_EXCEEDED: Requested ¥{ctx.amount_cny:.2f} exceeds cap ¥{self.max_per_call_cny:.2f}",
            )

        total_reserved = self.get_total_reserved_cny()
        if (self._total_spent_cny + total_reserved + ctx.amount_cny) > self.rolling_budget_cny:
            raise PolicyViolationError(
                PolicyErrorCode.DAILY_BUDGET_EXCEEDED,
                detail=f"BUDGET_CAP_EXCEEDED: Requested ¥{ctx.amount_cny:.2f} exceeds budget limit ¥{self.rolling_budget_cny:.2f}",
            )

        hold_id = f"hold_{uuid.uuid4().hex[:12]}"
        self._active_holds[hold_id] = {
            "ctx": ctx,
            "amount_cny": ctx.amount_cny,
            "timestamp": time.time(),
        }
        return hold_id

    def commit(self, hold_id: str, actual_cost_cny: float) -> None:
        """Settles hold into confirmed spending."""
        if hold_id not in self._active_holds:
            return
        del self._active_holds[hold_id]
        self._total_spent_cny += actual_cost_cny

    def release(self, hold_id: str, reason: str = "") -> None:
        """Cancels hold and restores available budget."""
        if hold_id in self._active_holds:
            del self._active_holds[hold_id]

    def get_active_hold_count(self) -> int:
        return len(self._active_holds)

    def get_total_reserved_cny(self) -> float:
        return sum(item["amount_cny"] for item in self._active_holds.values())

    def get_total_spent_cny(self) -> float:
        return round(self._total_spent_cny, 2)

    def get_remaining_budget_cny(self) -> float:
        remaining = self.rolling_budget_cny - (self._total_spent_cny + self.get_total_reserved_cny())
        return round(max(0.0, remaining), 2)


def mcp_price(
    amount: float,
    currency: str = "CNY",
    billing_mode: str = "per_call",
    hitl_required: bool = False,
    vendor: Optional[str] = None,
    description: Optional[str] = None,
) -> Callable[[Any], Any]:
    """
    Decorator to annotate MCP server tool functions with standardized pricing metadata.
    """

    def decorator(fn: Any) -> Any:
        metadata = McpPriceMetadata(
            amount_cny=amount,
            currency=currency,
            billing_mode=billing_mode,
            hitl_required=hitl_required,
            vendor=vendor,
            description=description,
        )
        setattr(fn, "_agentpay_pricing", metadata)

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return fn(*args, **kwargs)

        setattr(wrapper, "_agentpay_pricing", metadata)
        return wrapper

    return decorator


def get_tool_price_metadata(fn: Any) -> Optional[McpPriceMetadata]:
    """Retrieves pricing metadata from an annotated MCP tool function or object."""
    if hasattr(fn, "_agentpay_pricing"):
        return getattr(fn, "_agentpay_pricing")
    if isinstance(fn, dict) and "_agentpay" in fn:
        raw = fn["_agentpay"]
        return McpPriceMetadata(
            amount_cny=raw.get("price_cny", 0.0),
            amount_base_units=raw.get("price_base_units", 0),
            currency=raw.get("currency", "CNY"),
            billing_mode=raw.get("billing_mode", "per_call"),
            hitl_required=raw.get("hitl_required", False),
            vendor=raw.get("vendor"),
            description=raw.get("description"),
        )
    return None


def inject_tool_schema_pricing(
    schema: Dict[str, Any], pricing: McpPriceMetadata
) -> Dict[str, Any]:
    """
    Enriches an existing MCP Tool Definition JSON schema with `_agentpay` pricing extension.
    """
    enriched = dict(schema)
    enriched["_agentpay"] = pricing.to_dict()
    return enriched


class McpToolInterceptor:
    """
    Client-side interceptor for MCP tool calls.

    Extracts tool pricing metadata before execution, verifies quota against a
    ToolQuotaGuard, blocks excessive spend before invocation, and safely manages
    Hold-and-Capture settlement.
    """

    def __init__(
        self,
        guard: ToolQuotaGuard,
        pricing_registry: Optional[Dict[str, McpPriceMetadata]] = None,
        default_cost_cny: float = 0.0,
        handle_violation: bool = True,
    ) -> None:
        self.guard = guard
        self.pricing_registry = pricing_registry or {}
        self.default_cost_cny = default_cost_cny
        self.handle_violation = handle_violation

    def resolve_pricing(
        self, tool_name: str, execute_fn: Optional[Callable] = None
    ) -> McpPriceMetadata:
        """Resolves tool price from registry, decorated function, or default."""
        if tool_name in self.pricing_registry:
            return self.pricing_registry[tool_name]
        if execute_fn is not None:
            meta = get_tool_price_metadata(execute_fn)
            if meta is not None:
                return meta
        return McpPriceMetadata(amount_cny=self.default_cost_cny)

    def call_tool(
        self,
        tool_name: str,
        arguments: Optional[Dict[str, Any]] = None,
        execute_fn: Optional[Callable] = None,
        agent_id: str = "default_agent",
    ) -> Dict[str, Any]:
        """
        Executes an MCP tool call with pre-call quota evaluation and post-call settlement.
        """
        pricing = self.resolve_pricing(tool_name, execute_fn)
        ctx = ToolCallContext(
            agent_id=agent_id,
            tool_name=tool_name,
            amount_cny=pricing.amount_cny,
            currency=pricing.currency,
            arguments=arguments,
        )

        # 1. Pre-call policy evaluation & reservation
        try:
            hold_id = self.guard.reserve(ctx)
        except PolicyViolationError as err:
            if self.handle_violation:
                return {
                    "isError": True,
                    "content": [
                        {
                            "type": "text",
                            "text": (
                                f"AgentPay Financial Firewall Intercepted: [{err.code.value}] "
                                f"{err.detail}. Upstream tool '{tool_name}' was NOT executed."
                            ),
                        }
                    ],
                    "_agentpay": {
                        "action": "BLOCKED",
                        "reason": err.code.value,
                        "amount_cny": pricing.amount_cny,
                    },
                }
            raise

        # 2. Execution phase with exception safeguard
        try:
            if execute_fn is not None:
                try:
                    raw_res = execute_fn(tool_name, arguments or {})
                except TypeError:
                    raw_res = execute_fn(**(arguments or {}))
            else:
                raw_res = {}

            # 3. Post-call commit (Capture)
            self.guard.commit(hold_id, actual_cost_cny=pricing.amount_cny)

            if isinstance(raw_res, dict) and "content" in raw_res:
                res = dict(raw_res)
            else:
                import json
                text_val = (
                    raw_res
                    if isinstance(raw_res, str)
                    else json.dumps(raw_res, ensure_ascii=False)
                )
                res = {"content": [{"type": "text", "text": text_val}]}

            res["_agentpay"] = {
                "status": "SETTLED",
                "hold_id": hold_id,
                "cost_cny": pricing.amount_cny,
            }
            return res

        except Exception as exc:
            # 4. On execution error: Release hold safely without financial loss
            self.guard.release(hold_id, reason=str(exc))
            raise

