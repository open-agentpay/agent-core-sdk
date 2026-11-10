package i18n

// MessagesZH contains all Chinese messages for protocol errors, firewall events, and MCP tool executions.
var MessagesZH = map[string]string{
	// Canonical Protocol & Financial Errors
	"ERR_PAYMENT_REQUIRED":            "资源需要 x402 支付授权后方可访问。",
	"ERR_WALLET_INSUFFICIENT_BALANCE": "钱包可用余额不足以支付本次请求，请前往控制台充值。",
	"ERR_WALLET_FROZEN":               "钱包账户已被冻结或处于欠费状态，请结清欠款或联系管理员。",
	"ERR_PAYMENT_METHOD_NOT_ALLOWED":  "请求的支付方式不被当前路由策略允许。",
	"ERR_POLICY_BUDGET_EXCEEDED":       "已超出组织或项目的 24 小时或总预算限额。",
	"ERR_POLICY_MAX_PER_TX":           "单次交易金额超过了策略规定的单笔交易上限。",
	"ERR_POLICY_CIRCUIT_BROKEN":        "请求过于频繁或触发了熔断保护机制，请稍后重试。",
	"ERR_API_KEY_INVALID":              "提供的 API Key 无效、已撤销或已过期。",
	"ERR_API_KEY_SCOPE_DENIED":          "API Key 缺少执行此操作所需的权限范围 (Scope)。",
	"ERR_TENANT_SUSPENDED":            "企业租户组织已被暂停服务，请联系平台管理员。",
	"ERR_SIGNATURE_INVALID":           "链上支付签名验证失败或数据被篡改。",
	"ERR_WALLET_AUTH_INVALID":         "AgentPay 钱包授权无效、已过期或已被使用。",
	"ERR_WALLET_AUTH_REQUIRED":         "该接口需要提供有效的 AgentPay 虚拟钱包 API Key。",
	"ERR_SIGNATURE_EXPIRED":           "支付授权已超出有效时间窗口。",
	"ERR_NONCE_REPLAY":                "防重放随机数 (Nonce) 已被消费，请使用新的 Nonce。",
	"ERR_IDEMPOTENCY_CONFLICT":        "幂等凭据冲突：请求参数哈希不匹配或同一幂等请求正在并发处理中。",
	"ERR_HOLD_EXPIRED":                "内部资金预扣锁定已超时过期，请重新发起请求。",
	"ERR_UPSTREAM_TIMEOUT":            "网关等待上游服务执行超时，请使用相同 Idempotency-Key 重试（免二次扣费）。",
	"ERR_UPSTREAM_FAILED":             "上游服务发生异常或返回 5xx 错误，请稍后重试。",
	"ERR_CONFIG_VERSION_EXPIRED":       "路由配置版本已更新或回滚，请刷新配置快照后重试。",
	"ERR_ROUTE_NOT_FOUND":              "请求的端点未找到或未发布对应路由。",
	"ERR_AGENT_SUSPENDED":             "该 Agent 实体已被管理员熔断停用。",
	"ERR_AGENT_REVOKED":               "该 Agent 实体已被永久作废。",
	"ERR_ROUTE_NOT_ALLOWED":            "该 Agent 策略不允许调用目标路由。",
	"ERR_RATE_LIMIT_EXCEEDED":          "请求速率已超出限频上限 (RPM)，请降频重试。",

	// Trial Key Safeguard Errors
	"ERR_TRIAL_SINGLE_TX_CAP_EXCEEDED": "该接口单次调用费用超出免密试用 Key 单笔上限 (¥0.50)，请访问控制台获取正式企业 Key 并充值体验。",
	"ERR_TRIAL_NOT_ALLOWED":            "该接口已关闭免密试用体验，请登录控制台获取正式企业 Key。",
	"TRIAL_RATE_LIMIT_EXCEEDED":        "当前 IP 试用申领过于频繁，请直接登录控制台获取长期免费 API Key。",

	// MCP Tool & Firewall Interception Messages
	"MCP_ERR_POLICY_BLOCKED":    "【AgentFinOps 财务防火墙拦截】工具 [%s] 预估费用 ¥%s 超出组织预算或单笔限额: %s (%s)。请联系管理员提升预算或切换低成本方案。",
	"MCP_ERR_TRIAL_NOT_ALLOWED": "【AgentFinOps 试用限制】工具 [%s] 已关闭免密试用体验，请访问 https://console.aipmedia.cn 获取正式企业 Key。",
	"MCP_ERR_TRIAL_CAP_EXCEEDED": "【AgentFinOps 体验限制】工具 [%s] 属于高价值商业接口 (¥%s/次)。免注册试用 Key 单笔最高支持 ¥0.50，请访问 https://console.aipmedia.cn 获取正式企业 Key 并充值体验。",
	"MCP_ERR_ROUTE_NOT_FOUND":   "【AgentFinOps 路由错误】未找到对应工具或路由: %s",
	"MCP_ERR_UPSTREAM_REQUEST":  "创建上游请求失败: %v。已自动释放预扣额度。",
	"MCP_ERR_UPSTREAM_TIMEOUT":  "上游服务调用异常或超时: %v。已自动解冻释放预扣额度 ¥%s，无资金损失。",
	"MCP_ERR_UPSTREAM_STATUS":   "上游服务返回错误状态码 %d: %s。已自动解冻释放预扣额度。",

	// Fallback
	"ERR_INTERNAL": "发生了协议内部错误，请稍后重试。",
}
