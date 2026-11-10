package i18n

// MessagesEN contains English messages for canonical errors and MCP events.
var MessagesEN = map[string]string{
	"ERR_PAYMENT_REQUIRED":            "Resource requires x402 payment authorization.",
	"ERR_WALLET_INSUFFICIENT_BALANCE": "Wallet available balance is insufficient to cover this request.",
	"ERR_WALLET_FROZEN":               "Wallet account is currently frozen or in arrears status.",
	"ERR_PAYMENT_METHOD_NOT_ALLOWED":  "Requested payment method is not permitted by route policy.",
	"ERR_POLICY_BUDGET_EXCEEDED":       "24-hour rolling or lifetime budget ceiling exhausted.",
	"ERR_POLICY_MAX_PER_TX":           "Single transaction amount exceeds maximum per-request policy limit.",
	"ERR_POLICY_CIRCUIT_BROKEN":        "Circuit breaker triggered due to runaway agent loops or high request frequency.",
	"ERR_API_KEY_INVALID":              "Provided API Key is invalid, revoked, or expired.",
	"ERR_API_KEY_SCOPE_DENIED":          "API Key lacks required permission scope for this operation.",
	"ERR_TENANT_SUSPENDED":            "Tenant organization account is suspended.",
	"ERR_SIGNATURE_INVALID":           "Payment signature verification failed or payload tampered.",
	"ERR_WALLET_AUTH_INVALID":         "AgentPay wallet authorization is invalid, expired, mismatched, or already consumed.",
	"ERR_WALLET_AUTH_REQUIRED":         "This route requires an AgentPay virtual-wallet API key.",
	"ERR_SIGNATURE_EXPIRED":           "Payment authorization validity window has expired.",
	"ERR_NONCE_REPLAY":                "Cryptographic nonce has already been consumed or submitted.",
	"ERR_IDEMPOTENCY_CONFLICT":        "Idempotency key collision with mismatched payload hash or in-flight concurrent execution.",
	"ERR_HOLD_EXPIRED":                "Internal wallet hold reservation expired before upstream completion.",
	"ERR_UPSTREAM_TIMEOUT":            "Gateway timed out awaiting upstream API execution.",
	"ERR_UPSTREAM_FAILED":             "Upstream service returned 5xx server error.",
	"ERR_CONFIG_VERSION_EXPIRED":       "Route configuration version has been superseded or rolled back during execution.",
	"ERR_ROUTE_NOT_FOUND":              "Requested endpoint path does not match any configured route.",
	"ERR_AGENT_SUSPENDED":             "Agent is currently suspended by administrator kill-switch.",
	"ERR_AGENT_REVOKED":               "Agent has been permanently revoked and cannot be reactivated.",
	"ERR_ROUTE_NOT_ALLOWED":            "Target route is not in this Agent's authorization allowlist.",
	"ERR_RATE_LIMIT_EXCEEDED":          "Agent request rate limit exceeded.",

	"ERR_TRIAL_SINGLE_TX_CAP_EXCEEDED": "Guest trial API Key single transaction ceiling exceeded (max ¥0.50).",
	"ERR_TRIAL_NOT_ALLOWED":            "This route does not permit anonymous guest trial access.",
	"TRIAL_RATE_LIMIT_EXCEEDED":        "Trial issuance limit exceeded for this IP. Please sign in to console.",

	"MCP_ERR_POLICY_BLOCKED":     "[AgentFinOps Firewall Blocked] Tool [%s] cost ¥%s exceeds policy limits: %s (%s).",
	"MCP_ERR_TRIAL_NOT_ALLOWED":  "[AgentFinOps Trial Limit] Tool [%s] trial access is closed. Please sign in to console.",
	"MCP_ERR_TRIAL_CAP_EXCEEDED": "[AgentFinOps Trial Limit] Tool [%s] is a commercial API (¥%s/call). Trial key supports up to ¥0.50.",
	"MCP_ERR_ROUTE_NOT_FOUND":    "[AgentFinOps Routing Error] Tool [%s] not found.",
	"MCP_ERR_UPSTREAM_REQUEST":   "Failed to create upstream request: %v.",
	"MCP_ERR_UPSTREAM_TIMEOUT":   "Upstream service call failed or timed out: %v.",
	"MCP_ERR_UPSTREAM_STATUS":    "Upstream service returned error status %d: %s.",

	"ERR_INTERNAL": "An internal protocol error occurred.",
}
