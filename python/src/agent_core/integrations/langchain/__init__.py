"""
AgentCore LangChain Integration.

Provides:
- AgentPayPayTool: Explicit tool for requesting and executing resource payments
- AgentPayGetPaymentTool: Tool for polling three-domain payment lifecycle status
- protect_tool: Declarative guard wrapper providing pre-execution firewall interception
- AgentPayGuardCallbackHandler: CallbackHandler for intercepting protected tools
- @paid_tool: Decorator to convert Python functions into LangChain tools with AgentCore payment negotiation
- PaidTool: LangChain StructuredTool subclass for paid APIs
- PaidHttpTool: Pre-built LangChain tool for executing paid HTTP requests
"""

from __future__ import annotations

from agent_core.integrations.langchain.guard import (
    AgentPayGuardCallbackHandler,
    PaymentDeclaration,
    protect_tool,
)
from agent_core.integrations.langchain.http import PaidHttpInput, PaidHttpTool
from agent_core.integrations.langchain.tool import PaidTool, paid_tool
from agent_core.integrations.langchain.tools import (
    AgentPayGetPaymentInput,
    AgentPayGetPaymentTool,
    AgentPayPayInput,
    AgentPayPayTool,
    get_agentpay_tools,
)

__all__ = [
    "AgentPayPayInput",
    "AgentPayPayTool",
    "AgentPayGetPaymentInput",
    "AgentPayGetPaymentTool",
    "get_agentpay_tools",
    "PaymentDeclaration",
    "protect_tool",
    "AgentPayGuardCallbackHandler",
    "PaidHttpInput",
    "PaidHttpTool",
    "PaidTool",
    "paid_tool",
]
