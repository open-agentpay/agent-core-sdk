"""
agentpay_core — Official alias for agent_core.
Provides full policy engine, financial firewall, budget controls and gateway interfaces.
"""

from __future__ import annotations

import agent_core
from agent_core import *

__all__ = getattr(agent_core, "__all__", [])
