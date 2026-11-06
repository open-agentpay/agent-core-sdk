# agent-core-sdk ⚡

[![PyPI](https://img.shields.io/pypi/v/agent-core-sdk.svg)](https://pypi.org/project/agent-core-sdk/)
[![npm](https://img.shields.io/npm/v/agent-core-sdk.svg)](https://www.npmjs.com/package/agent-core-sdk)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Universal, vendor-neutral Client SDK for AI Agent Gateways & FinOps Token Metering.  
企业级 AI Agent 统一网关与大模型算力成本治理（FinOps）多语言客户端 SDK。

---

## 📦 支持语言 (Supported Runtimes)

| 语言 | 安装命令 | 适用框架 |
| :--- | :--- | :--- |
| **Python** | `pip install agent-core-sdk` | LangChain, CrewAI, AutoGen, LlamaIndex |
| **TypeScript / JS** | `npm install agent-core-sdk` | Vercel AI SDK, Next.js, LangChain.js, MCP |

---

## 🛡️ 核心能力

- 📊 **Token 毫秒级计量与预算控制**：请求前自动拦截评估额度，流式响应结束实时对账；
- 🛑 **死循环与失控熔断 (Circuit Breaker)**：防止 Agent 无限递归调用耗尽企业预算；
- 🔌 **通用结算适配器 (SettlementAdapter)**：无缝适配内部 Quota 额度与外部计费网关；
- 🤝 **零链上依赖，100% 纯净合规**：纯算法与 HTTP 协议层实现，合规安全。
