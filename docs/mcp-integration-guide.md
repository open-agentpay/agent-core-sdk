# Model Context Protocol (MCP) 金融级风控与工具定价集成指南 (MCP Financial Governance Guide)

> **版本**：v0.3.1  
> **适用语言**：Python (>=3.10) & TypeScript / Node.js (>=18)  
> **核心定位**：为 Anthropic MCP（Model Context Protocol）生态注入确定性定价元数据、工具级单笔限额硬顶与客户端 Pre-Call 预算拦截中间件。

---

## 1. 架构定位：为什么 MCP 工具调用需要“资金防火墙”？

在传统的 MCP 架构中，大模型（LLM）通过 JSON-RPC 协议直接调用 MCP Server 暴露的 Tool（如网页爬取、代码分析、高频数据检索）。然而：
1. **失控死循环（Runaway Loops）**：由于 Prompt 缺陷或异常重试，LLM 可能会在数秒内高频调用高价值收费 Tool 上百次；
2. **缺乏成本感知**：LLM 本身不了解不同 Tool 的真实货币成本，可能为了简单任务调用极为昂贵的商业 Tool；
3. **单点无风控**：没有本地预算拦截机制，一旦请求发出，计费即刻发生，产生无法挽回的财务透支。

**`agent-core-sdk` 为 MCP 提供了全生命周期的双端防护架构**：

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        上层应用场景 (LLM Agent 编队 / MCP Client)                       │
│      Claude Desktop / Cursor / LangChain / AutoGen / Dify / 自研智能体编队              │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │ MCP JSON-RPC (tools/list & tools/call)
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                   agent-core-sdk: MCP 核心金融风控层 (Python & TypeScript)              │
│                                                                                        │
│   ┌──────────────────────────────────┐      ┌──────────────────────────────────────┐   │
│   │ Server 端：标价元数据注入        │      │ Client 端：Pre-Call 本地预算拦截器   │   │
│   │ • Python: @mcp_price 装饰器      │      │ • tools/call 拦截与 Tool 标价自适应  │   │
│   │ • TS: withPrice() 工具包装器     │      │ • 超额阻断 (SINGLE_TX_CAP_EXCEEDED)  │   │
│   │ • tools/list 协议元数据自动注入  │      │ • 预算耗尽阻断 (BUDGET_CAP_EXCEEDED) │   │
│   │ • 统一保留 2 位小数 (精确到分)   │      │ • 上游异常零损释放 (Hold Release)    │   │
│   └──────────────────────────────────┘      └──────────────────┬───────────────────┘   │
│                                                                │ 依赖抽象接口           │
│                                                                ▼                       │
│                                              ┌─────────────────────────────────────┐   │
│                                              │ <<Interface>> ToolQuotaGuard        │   │
│                                              │ + evaluate(ctx): bool               │   │
│                                              │ + reserve(ctx): hold_id             │   │
│                                              │ + commit(hold_id, cost): void       │   │
│                                              │ + release(hold_id, reason): void    │   │
│                                              └──────────────────┬──────────────────┘   │
└─────────────────────────────────────────────────────────────────┼──────────────────────┘
                                                                  │ 接口下层实现
                    ┌─────────────────────────────────────────────┴─────────────────────────────────────────────┐
                    ▼                                                                                           ▼
┌───────────────────────────────────────┐                                   ┌───────────────────────────────────────────────────────────┐
│ 标准轻量实现 (agent-core-sdk 自带)     │                                   │ 企业级实现 (AgentFinOps 注入)                              │
│ • InMemoryToolQuotaGuard (本地开箱即用)│                                   │ • EnterpriseFinOpsGuard (树状部门级联配额校验)             │
│ • 适合独立开发者与单机 Agent 应用     │                                   │ • 人在回路 (HITL) 触发 HTTP 402 挂起与飞书/企微卡片推送    │
└───────────────────────────────────────┘                                   └───────────────────────────────────────────────────────────┘
```

---

## 2. MCP 定价协议扩展规范 (`_agentpay`)

在标准的 MCP `tools/list` 响应中，`agent-core-sdk` 自动在 Tool Definition 中注入 `_agentpay` 扩展字段，国内版本金额严格保留两位小数（分）：

```json
{
  "name": "fetch_stock_level2_quote",
  "description": "获取 A 股高频 Level-2 逐笔深度委托行情",
  "inputSchema": {
    "type": "object",
    "properties": {
      "symbol": { "type": "string", "description": "股票代码，例如 600519" }
    },
    "required": ["symbol"]
  },
  "_agentpay": {
    "price_cny": 0.05,
    "price_base_units": 50000,
    "currency": "CNY",
    "billing_mode": "per_call",
    "hitl_required": false,
    "vendor": "open-agentpay"
  }
}
```

---

## 3. Python SDK 实操指引

### 3.1 安装依赖
```bash
pip install agentpay-core-sdk
```

### 3.2 Server 端：为 MCP Tool 声明标价元数据
```python
from agent_core.integrations.mcp import mcp_price, inject_tool_schema_pricing

# 1. 使用 @mcp_price 装饰器标价（单次 0.05 元人民币）
@mcp_price(amount=0.05, currency="CNY", hitl_required=False, vendor="fin-data-lab")
def fetch_stock_level2_quote(symbol: str) -> dict:
    """获取 A 股高频 Level-2 逐笔深度行情"""
    return {"symbol": symbol, "last_price": 1850.00, "depth": 10}

# 2. 在暴露 MCP tools/list 协议时注入定价元数据
raw_schema = {
    "name": "fetch_stock_level2_quote",
    "description": "获取 A 股高频 Level-2 逐笔深度行情",
    "inputSchema": {"type": "object", "properties": {"symbol": {"type": "string"}}}
}
enriched_tool_definition = inject_tool_schema_pricing(
    raw_schema,
    fetch_stock_level2_quote._agentpay_pricing
)
```

### 3.3 Client 端：Pre-Call 本地预算拦截中间件
```python
from agent_core.integrations.mcp import (
    InMemoryToolQuotaGuard,
    McpToolInterceptor,
    McpPriceMetadata
)

# 1. 初始化额度守卫（单笔硬顶上限 1.00 元，24小时滚动预算 10.00 元）
guard = InMemoryToolQuotaGuard(
    max_per_call_cny=1.00,
    rolling_budget_cny=10.00
)

# 2. 初始化拦截器
interceptor = McpToolInterceptor(
    guard=guard,
    pricing_registry={
        "fetch_stock_level2_quote": McpPriceMetadata(amount_cny=0.05, currency="CNY"),
        "heavy_ml_inference": McpPriceMetadata(amount_cny=5.00, currency="CNY")
    },
    handle_violation=True # 拦截后向 LLM 返回语义化错误，避免 LLM 进程崩溃
)

# 3. 执行正常调用 -> 扣款平账 (Capture 0.05 元)
res = interceptor.call_tool(
    tool_name="fetch_stock_level2_quote",
    arguments={"symbol": "600519"},
    execute_fn=fetch_stock_level2_quote,
    agent_id="trading_agent_alpha"
)
print(res)
# {"content": [{"type": "text", "text": "..."}], "_agentpay": {"status": "SETTLED", "cost_cny": 0.05}}

# 4. 执行超出单笔限额的高危调用 (5.00 元 > 1.00 元硬顶) -> 毫秒级阻断！
blocked_res = interceptor.call_tool(
    tool_name="heavy_ml_inference",
    arguments={"model": "deep-reasoner"},
    execute_fn=lambda t, a: print("执行高昂调用..."), # 永远不会被触发！
    agent_id="trading_agent_alpha"
)
print(blocked_res)
# {
#   "isError": True,
#   "content": [{
#     "type": "text",
#     "text": "AgentPay Financial Firewall Intercepted: [SINGLE_TX_CAP_EXCEEDED] Requested ¥5.00 exceeds cap ¥1.00. Upstream tool 'heavy_ml_inference' was NOT executed."
#   }],
#   "_agentpay": {"action": "BLOCKED", "reason": "SINGLE_TX_CAP_EXCEEDED", "amount_cny": 5.00}
# }
```

---

## 4. TypeScript / Node.js SDK 实操指引

### 4.1 安装依赖
```bash
npm install agentpay-core-sdk
```

### 4.2 Server 端：使用 `withPrice` 包装工具
```typescript
import { withPrice, injectToolSchemaPricing } from 'agentpay-core-sdk/integrations';

// 1. 包装工具对象，注入单次 0.05 元定价
export const stockQuoteTool = withPrice({
  name: 'fetch_stock_level2_quote',
  description: '获取 A 股高频 Level-2 逐笔深度行情',
  execute: async ({ symbol }: { symbol: string }) => {
    return { symbol, last_price: 1850.00 };
  }
}, {
  amount: 0.05,
  currency: 'CNY',
  hitlRequired: false
});

// 2. 导出 tools/list schema 时注入
const mcpSchema = injectToolSchemaPricing({
  name: stockQuoteTool.name,
  description: stockQuoteTool.description,
  inputSchema: { type: 'object', properties: { symbol: { type: 'string' } } }
}, stockQuoteTool._agentpay);
```

### 4.3 Client 端：使用 `McpToolInterceptor` 拦截治理
```typescript
import {
  InMemoryToolQuotaGuard,
  McpToolInterceptor,
  McpPriceMetadata
} from 'agentpay-core-sdk/integrations';

// 1. 初始化守卫规则
const guard = new InMemoryToolQuotaGuard({
  maxPerCallCny: 1.00,
  rollingBudgetCny: 10.00
});

// 2. 初始化拦截器
const interceptor = new McpToolInterceptor({
  guard,
  pricingRegistry: {
    fetch_stock_level2_quote: new McpPriceMetadata({ amountCny: 0.05, currency: 'CNY' })
  },
  handleViolation: true
});

// 3. 执行工具调用拦截
const result = await interceptor.callTool(
  {
    toolName: 'fetch_stock_level2_quote',
    arguments: { symbol: '600519' },
    agentId: 'node_analyst_01'
  },
  stockQuoteTool.execute,
  stockQuoteTool
);

console.log(result);
// { content: [...], _agentpay: { status: 'SETTLED', cost_cny: 0.05 } }
```

---

## 5. 核心接口规范 (`ToolQuotaGuard`)

无论是单机轻量应用还是跨部门分布式企业系统，均遵循统一的生命周期接口：

### 5.1 接口契约
```text
                  ┌───────────────────────────────┐
                  │ 1. evaluate(ctx): 策略预检     │
                  └──────────────┬────────────────┘
                                 │
                                 ▼
                  ┌───────────────────────────────┐
                  │ 2. reserve(ctx): 额度冻结     │ ──► 返回 hold_id
                  └──────────────┬────────────────┘
                                 │
                   ┌─────────────┴─────────────┐
                   │ 调用真实 MCP Tool 上游     │
                   └─────────────┬─────────────┘
                                 │
                  ┌──────────────┴──────────────┐
                  ▼                             ▼
        【执行成功 200 OK】             【网络超时 / 业务报错】
┌───────────────────────────────┐ ┌───────────────────────────────┐
│ 3. commit(hold_id, cost)      │ │ 4. release(hold_id, reason)   │
│   原子平账核销 (Capture)       │ │   零损解冻额度 (Release)      │
└───────────────────────────────┘ └───────────────────────────────┘
```

### 5.2 自定义企业级实现示例（扩展接入 AgentFinOps）
若需要接入企业树状部门配额中心或人在回路（HITL）审批，只需实现该接口：

```python
from agent_core.integrations.mcp import ToolQuotaGuard, ToolCallContext

class EnterpriseFinOpsGuard(ToolQuotaGuard):
    def __init__(self, tenant_id: str, finops_gateway_url: str):
        self.tenant_id = tenant_id
        self.gateway_url = finops_gateway_url

    def evaluate(self, ctx: ToolCallContext) -> bool:
        # 查询 AgentFinOps 企业部门级联预算中心
        return check_department_quota(self.tenant_id, ctx.agent_id, ctx.amount_cny)

    def reserve(self, ctx: ToolCallContext) -> str:
        # 冻结配额；若超出风控阈值，生成 approval_id 并推送飞书/企微卡片
        return hold_enterprise_ledger(self.tenant_id, ctx.amount_cny)

    def commit(self, hold_id: str, actual_cost_cny: float) -> None:
        # 记入 PostgreSQL 企业双层对账流水
        settle_enterprise_ledger(hold_id, actual_cost_cny)

    def release(self, hold_id: str, reason: str = "") -> None:
        # 异常零损回滚
        release_enterprise_ledger(hold_id, reason)
```

---

## 6. 常见问答 (FAQ)

### Q1: 为什么拦截后返回 `isError: true` 而不是直接 crash 抛出异常？
**答**：在自主智能体（如 ReAct / LangGraph / AutoGen）中，若 Python/Node 进程直接崩溃，Agent 任务会瞬间中断退出。而 MCP 协议规范定义了当 Tool 执行失败时，返回 `{ isError: true, content: [{ text: "..." }] }`，LLM 接收到结构化错误信息后，能够理解“该工具因单笔超出企业预算被资金防火墙阻断”，并自主选择向用户汇报或调用更低廉的备选工具，**既保护了钱包，又保证了 Agent 任务链路的健壮性**。

### Q2: 上游 MCP Server 网络超时报错，额度会被扣除吗？
**答**：**绝不会**。`McpToolInterceptor` 采用标准的 Hold-and-Capture（预留-核销）两阶段平账模型。只有当 `execute_fn` 正常返回无异常时才会触发 `commit`；一旦捕获到任何 `Exception`（如超时、网络断开），拦截器将在 `finally` 阶段自动触发 `guard.release(hold_id)`，预扣配额即刻原路返还，资金零损失。

### Q3: 如何与 Claude Desktop 现有的 MCP 配置兼容？
**答**：对于以 Stdio 运行的 MCP Server，直接在导出 tool definition 时调用 `inject_tool_schema_pricing`，Claude Desktop 会正常展示 tools，同时标价数据保留在元数据中；对于使用 SDK 的客户端 Agent，使用 `McpToolInterceptor` 包裹 tool call 即可完成本地拦截。
