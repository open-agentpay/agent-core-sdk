# agent-core-sdk ⚡

[![PyPI](https://img.shields.io/pypi/v/agentpay-core-sdk.svg?label=PyPI%20(agentpay-core-sdk))](https://pypi.org/project/agentpay-core-sdk/)
[![npm](https://img.shields.io/npm/v/agentpay-core-sdk.svg?label=npm%20(agentpay-core-sdk))](https://www.npmjs.com/package/agentpay-core-sdk)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0%2B-blue.svg)](https://www.typescriptlang.org)
[![Go Version](https://img.shields.io/badge/Go-1.21%2B-00ADD8.svg)](https://golang.org)

**`agent-core-sdk`** (published on PyPI and npm as **`agentpay-core-sdk`**) is the universal, vendor-neutral financial firewall, runtime policy engine, and high-performance gateway core for autonomous AI agents and enterprise LLM infrastructure.

```bash
# Python
pip install agentpay-core-sdk

# Node.js / TypeScript
npm install agentpay-core-sdk
```

It prevents runaway autonomous agent loops, enforces strict multi-tenant budget ceilings, and enables pluggable micro-metering and settlement across both traditional enterprise quota systems and decentralized settlement rails.

---

## Architecture Overview

```
                                      AI Agent / LLM Application
                                                   │
                      ┌────────────────────────────┴────────────────────────────┐
                      ▼                                                         ▼
        [agent-core (Python SDK)]                               [agent-core-sdk (TypeScript SDK)]
                      │                                                         │
                      │  1. Local Active Guardrail (Policy Pre-Check)           │
                      ▼                                                         ▼
    ┌───────────────────────────────────┐                     ┌───────────────────────────────────┐
    │       SQLite Policy Engine        │                     │       Client Policy Engine        │
    │  - Frozen Status Verification     │                     │  - Single-Request Budget Check    │
    │  - Circuit Breaker (RPM & Failure)│                     │  - Sliding 24h Ceiling            │
    │  - Spending Caps & Quota Reserve  │                     │  - Domain / Payee Whitelist       │
    └───────────────────────────────────┘                     └───────────────────────────────────┘
                      │                                                         │
                      │  2. Forward Authorized Request (HTTP 402 / Quota Token) │
                      ▼                                                         ▼
  ═════════════════════════════════════════════════════════════════════════════════════════════════════════
                                   High-Performance Gateway Core (Go)
  ═════════════════════════════════════════════════════════════════════════════════════════════════════════
                                                   │
                      ┌────────────────────────────┴────────────────────────────┐
                      ▼                                                         ▼
            [RCU Dynamic Router]                                      [Metrics & Audit Log]
                      │                                                         │
                      ▼                                                         ▼
    ┌───────────────────────────────────┐                     ┌───────────────────────────────────┐
    │     Pluggable Settlement Core     │                     │      Upstream Reverse Proxy       │
    │         (SettlementAdapter)       │                     │    - Master API Key Injection     │
    │   ├── QuotaSettlementAdapter      │                     │    - SSRF Protection              │
    │   └── CryptoSettlementAdapter     │                     │    - Idempotent Retry Engine      │
    └───────────────────────────────────┘                     └───────────────────────────────────┘
```

---

## Monorepo Layout

| Directory | Language | Description |
| :--- | :--- | :--- |
| [`python/`](python/) | **Python (>=3.10)** | Core runtime, local SQLite financial firewall, Pydantic data models, LangChain/CrewAI integrations. |
| [`typescript/`](typescript/) | **TypeScript (Node/Web)** | High-speed browser and Node.js client runtime, policy evaluator, and Vercel AI SDK adapters. |
| [`gateway/`](gateway/) | **Go (>=1.21)** | Production-grade edge reverse proxy engine with Read-Copy-Update (RCU) hot route reloading and dual settlement adapters. |

---

## Financial Policy Engine & Defense-in-Depth

The heart of `agent-core-sdk` is its **fail-closed, mathematically deterministic policy engine**. Before any network request or external model invocation is dispatched, the agent evaluates the transaction locally. Zero funds or quotas leave the system if a policy rule is violated.

### Strict Precedence Order

Policy evaluation follows a rigorous 7-stage precedence pipeline:

```
[Incoming Request]
       │
       ▼
 1. Administrative Freeze Check  ────────► [is_frozen = true?] ──────────► REJECT: POLICY_FROZEN
       │
       ▼
 2. Circuit Breaker Evaluation   ────────► [State = OPEN or RPM > Max?] ─► REJECT: CIRCUIT_BREAKER_OPEN
       │
       ▼
 3. Payload & Format Validation  ────────► [Amount <= 0 or Malformed?] ──► REJECT: INVALID_AMOUNT_FORMAT
       │
       ▼
 4. Whitelist Matrix Check       ────────► [Payee/Asset/Network/Domain?] ─► REJECT: NOT_WHITELISTED
       │
       ▼
 5. Single-Transaction Cap Check ────────► [Amount > max_per_tx?] ───────► REJECT: SINGLE_TX_CAP_EXCEEDED
       │
       ▼
 6. Lifetime Budget Limit Check  ────────► [Spent + Amount > Lifetime?] ─► REJECT: LIFETIME_BUDGET_EXCEEDED
       │
       ▼
 7. 24h Rolling Window Budget    ────────► [24h Sum + Amount > Daily?] ──► REJECT: DAILY_BUDGET_EXCEEDED
       │
       ▼
  [APPROVED: Quota Reserved & Transaction Authorized]
```

### 1. Administrative Freeze (`is_frozen`)
An immediate kill-switch that can be triggered by system administrators or automated anomaly detection systems. When frozen, all outgoing calls are rejected in $O(1)$ time with zero DB writes.

### 2. Autonomous Circuit Breaker
Protects enterprise accounts and user balances from hallucinated LLM recursive loops:
- **RPM Threshold (`circuit_max_rpm`)**: Enforces rate limits over a sliding 60-second window.
- **Consecutive Failures (`circuit_consecutive_failures`)**: Trips if upstream endpoints continuously fail or return error status codes.
- **Three-State Machine**:
  - `CLOSED`: Normal operation; all requests pass through policy checks.
  - `OPEN`: Tripped state; all requests fail immediately without touching the network.
  - `HALF_OPEN`: Entered after `circuit_cooldown_seconds` expires; allows a single probe call to test system health.

### 3. Dual-Phase Quota Lifecycle (`reserve` $\to$ `commit` / `release`)
To avoid race conditions and double-spending across parallel agent subtasks, budget changes operate via an atomic two-phase reservation protocol:
1. `reserve(intent_id, amount, ...)`: Evaluates rules under SQLite `BEGIN IMMEDIATE` locks and creates a `RESERVED` ledger hold.
2. `commit(intent_id)`: Transitions state to `COMMITTED` upon successful upstream HTTP 200 delivery.
3. `release(intent_id, reason)`: Releases the hold back to the agent's available pool if the upstream call fails or aborts.

---

## Pluggable Settlement Architecture

The Gateway core exposes an abstract `SettlementAdapter` interface, cleanly decoupling routing from the underlying ledger:

```go
type SettlementAdapter interface {
    VerifyPayment(ctx context.Context, req *PaymentVerificationRequest) (*VerificationResult, error)
    SettlePayment(ctx context.Context, req *PaymentSettlementRequest) (*SettlementResult, error)
    RefundPayment(ctx context.Context, req *PaymentRefundRequest) (*RefundResult, error)
    GetBalance(ctx context.Context, accountID string) (*BalanceResult, error)
}
```

- **`QuotaSettlementAdapter`**: Implements prepaid/postpaid enterprise balance metering, contract quotas, and internal tenant billing (100% cloud & domestic compliant, 0 crypto dependencies).
- **`CryptoSettlementAdapter`**: Implements decentralized verification and settlement via HTTP 402 challenge-response standards (EIP-712 / EIP-3009 offline signing).

---

## Quickstart

### Python Usage

```python
import sqlite3
from agent_core.policy.config import PolicyConfig
from agent_core.policy.db import init_buyer_database
from agent_core.policy.sqlite_engine import SQLitePolicyEngine

# 1. Initialize local SQLite financial firewall
conn = sqlite3.connect(":memory:")
init_buyer_database(conn)

config = PolicyConfig(
    id="policy_agent_production_01",
    wallet_address="tenant_enterprise_01",
    max_per_tx_base_units=1000,          # 10.00 Credits max per transaction
    rolling_budget_24h_base_units=50000, # 500.00 Credits daily limit
    circuit_max_rpm=10,                  # Max 10 requests per minute
    circuit_cooldown_seconds=120,
)
engine = SQLitePolicyEngine(conn, config)

# 2. Atomically reserve quota before executing agent tool
decision = engine.reserve(
    intent_id="intent_call_984712",
    amount=250, # 2.50 Credits
    payee="upstream_ai_provider",
    asset="CREDITS",
    network="internal:quota",
    domain="api.enterprise-gateway.com",
)

if decision.approved:
    try:
        # Execute upstream LLM API call...
        engine.commit("intent_call_984712")
        print("Call completed and quota committed successfully.")
    except Exception:
        engine.release("intent_call_984712", reason="upstream_failed")
else:
    print(f"Call blocked locally by financial firewall: {decision.error_code}")
```

### Embedding the Go Gateway Engine

```go
package main

import (
    "github.com/open-agentpay/agent-core-sdk/gateway/config"
    "github.com/open-agentpay/agent-core-sdk/gateway/metrics"
    "github.com/open-agentpay/agent-core-sdk/gateway/rcu"
    "github.com/open-agentpay/agent-core-sdk/gateway/server"
)

func main() {
    cfg, _ := config.Load("configs/gateway.yaml")
    rcuMgr, _ := rcu.NewManager(initialSnapshot)
    m := metrics.New()

    srv, _ := server.New(cfg, rcuMgr, m)
    srv.Start()
}
```

---

## Conformance & Quality Standards

- **100% Deterministic Verification**: Passes all cross-language test vectors for mathematical budget calculations, sliding time windows, and state transitions.
- **Zero Third-Party Vendor Lock-In**: Pure standard library and protocol primitives; completely independent from specific LLM providers.
- **High Concurrency & Low Latency**: In-memory RCU cache ensures sub-millisecond route resolution under tens of thousands of requests per second.

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
