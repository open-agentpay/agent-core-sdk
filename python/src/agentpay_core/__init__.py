"""
agentpay_core — Official alias and public API for agent_core.
Provides full policy engine, financial firewall, budget controls and gateway interfaces.
"""

from __future__ import annotations

import agent_core
from agent_core import (
    AgentCoreClient,
    AgentPayClient,
    AsyncAgentCoreClient,
    AsyncAgentPayClient,
    PolicyConfig,
    SQLitePolicyEngine,
    __version__,
)
from agent_core import client, core, integrations, policy, protocol, state
import sys

# Register submodules into sys.modules to support `from agentpay_core.client import ...`
for _name in ("client", "policy", "core", "protocol", "state", "integrations"):
    _sub = getattr(agent_core, _name, None)
    if _sub is not None:
        sys.modules[f"agentpay_core.{_name}"] = _sub

__all__ = [
    "AgentCoreClient",
    "AgentPayClient",
    "AsyncAgentCoreClient",
    "AsyncAgentPayClient",
    "PolicyConfig",
    "SQLitePolicyEngine",
    "__version__",
    "client",
    "core",
    "integrations",
    "policy",
    "protocol",
    "state",
]
