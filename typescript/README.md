# agent-core-sdk ⚡

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0%2B-blue.svg)](https://www.typescriptlang.org)
[![Go Version](https://img.shields.io/badge/Go-1.21%2B-00ADD8.svg)](https://golang.org)

**`agent-core-sdk`** is the universal, vendor-neutral financial firewall, runtime policy engine, and high-performance gateway core for autonomous AI agents and enterprise LLM infrastructure.

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
- **External Settlement Adapters**: Pluggable adapters can be registered via dependency injection to interface with external payment networks or facilitators.

---

## Quickstart

### Python Usage (SDK 零摩擦调用)

```python
import os
# 从顶层 agentpay_core 直接导入 AgentPayClient
from agentpay_core import AgentPayClient, PolicyConfig, SQLitePolicyEngine

# 1. 策略防火墙：仅配置预算和白名单域名
policy = SQLitePolicyEngine.create_in_memory(
    PolicyConfig(
        id="weather_agent",
        max_per_tx_base_units=250000,  # 0.25 Credits
        rolling_budget_24h_base_units=5000000,  # 5.00 Credits
        whitelist_domains={"gate.aipmedia.cn"},
    )
)

# 2. 客户端直接传入 api_key，自动开启虚拟钱包模式与 402 自动握手
client = AgentPayClient(
    api_key=os.getenv("AGENT_API_KEY", "apk_live_xxx"),
    policy=policy,
)

# 3. 正常发起调用
response = client.get(
    "https://gate.aipmedia.cn/api/v1/simple-weather",
    params={"city": "北京"}
)
print("Response:", response.json())
```

### TypeScript / Node.js Usage (SDK 零摩擦调用)

```typescript
import { AgentPayClient, PolicyConfig, SQLitePolicyEngine } from 'agentpay-core-sdk';

// 1. 策略防火墙配置
const policy = SQLitePolicyEngine.createInMemory(
  new PolicyConfig({
    id: 'weather_agent',
    maxPerTxBaseUnits: 250000n,
    rollingBudget24hBaseUnits: 5000000n,
    whitelistDomains: ['gate.aipmedia.cn'],
  })
);

// 2. 客户端直接传入 apiKey
const client = new AgentPayClient({
  apiKey: process.env.AGENT_API_KEY ?? 'apk_live_xxx',
  policy,
});

// 3. 正常发起调用
const response = await client.get('https://gate.aipmedia.cn/api/v1/simple-weather', {
  params: { timeframe: '24h' },
});
console.log('Response:', await response.json());
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

## 🔌 Model Context Protocol (MCP) Pricing & Guardrails

Use `agentpay-core-sdk/integrations` to monetize MCP tools and safeguard client-side agent calls:

```typescript
import {
  withPrice,
  InMemoryToolQuotaGuard,
  McpToolInterceptor,
  McpPriceMetadata,
} from 'agentpay-core-sdk/integrations';

// 1. Server-side Tool Pricing Annotation
export const marketTool = withPrice({
  name: 'query_market_depth',
  description: 'Query Level 2 quotes',
  execute: async ({ symbol }: { symbol: string }) => ({ symbol, price: 1850.0 }),
}, {
  amount: 0.05,
  currency: 'CNY',
});

// 2. Client-side Pre-Call Financial Guard
const guard = new InMemoryToolQuotaGuard({ maxPerCallCny: 1.00, rollingBudgetCny: 10.00 });
const interceptor = new McpToolInterceptor({
  guard,
  pricingRegistry: {
    query_market_depth: new McpPriceMetadata({ amountCny: 0.05, currency: 'CNY' }),
  },
  handleViolation: true,
});

// 3. Intercepted Tool Calling with Hold/Capture
const result = await interceptor.callTool(
  { toolName: marketTool.name, arguments: { symbol: '600519' } },
  marketTool.execute,
  marketTool
);
console.log(result);
```

👉 **Full Guide**: [MCP Financial Governance & Tool Pricing Guide](../docs/mcp-integration-guide.md)

---

## Conformance & Quality Standards

- **100% Deterministic Verification**: Passes all cross-language test vectors for mathematical budget calculations, sliding time windows, and state transitions.
- **Zero Third-Party Vendor Lock-In**: Pure standard library and protocol primitives; completely independent from specific LLM providers.
- **High Concurrency & Low Latency**: In-memory RCU cache ensures sub-millisecond route resolution under tens of thousands of requests per second.

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
