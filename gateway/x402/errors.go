package x402

import (
	"encoding/json"
	"net/http"
)

// Canonical Error Code Constants matching specs/conformance/protocol-errors.json (T1.3)
const (
	ErrCodePaymentRequired            = "ERR_PAYMENT_REQUIRED"
	ErrCodeWalletInsufficientBalance  = "ERR_WALLET_INSUFFICIENT_BALANCE"
	ErrCodeWalletFrozen               = "ERR_WALLET_FROZEN"
	ErrCodePaymentMethodNotAllowed    = "ERR_PAYMENT_METHOD_NOT_ALLOWED"
	ErrCodePolicyBudgetExceeded       = "ERR_POLICY_BUDGET_EXCEEDED"
	ErrCodePolicyMaxPerTx             = "ERR_POLICY_MAX_PER_TX"
	ErrCodePolicyCircuitBroken        = "ERR_POLICY_CIRCUIT_BROKEN"
	ErrCodeAPIKeyInvalid              = "ERR_API_KEY_INVALID"
	ErrCodeAPIKeyScopeDenied          = "ERR_API_KEY_SCOPE_DENIED"
	ErrCodeTenantSuspended            = "ERR_TENANT_SUSPENDED"
	ErrCodeSignatureInvalid           = "ERR_SIGNATURE_INVALID"
	ErrCodeWalletAuthorizationInvalid = "ERR_WALLET_AUTH_INVALID"
	ErrCodeWalletAuthRequired         = "ERR_WALLET_AUTH_REQUIRED"
	ErrCodeSignatureExpired           = "ERR_SIGNATURE_EXPIRED"
	ErrCodeNonceReplay                = "ERR_NONCE_REPLAY"
	ErrCodeIdempotencyConflict        = "ERR_IDEMPOTENCY_CONFLICT"
	ErrCodeHoldExpired                = "ERR_HOLD_EXPIRED"
	ErrCodeUpstreamTimeout            = "ERR_UPSTREAM_TIMEOUT"
	ErrCodeUpstreamFailed             = "ERR_UPSTREAM_FAILED"
	ErrCodeConfigVersionExpired       = "ERR_CONFIG_VERSION_EXPIRED"
	ErrCodeRouteNotFound              = "ERR_ROUTE_NOT_FOUND"
	ErrCodeAgentSuspended             = "ERR_AGENT_SUSPENDED"
	ErrCodeAgentRevoked               = "ERR_AGENT_REVOKED"
	ErrCodeRouteNotAllowed            = "ERR_ROUTE_NOT_ALLOWED"
	ErrCodeRateLimitExceeded          = "ERR_RATE_LIMIT_EXCEEDED"

	// Backward compatibility aliases
	ErrCodeNonceAlreadyUsed   = ErrCodeNonceReplay
	ErrCodeUpstreamBadGateway = ErrCodeUpstreamFailed
)

// ErrorDescriptor contains canonical metadata for a protocol error.
type ErrorDescriptor struct {
	Code       string `json:"code"`
	Status     int    `json:"status"`
	Domain     string `json:"domain"`
	Message    string `json:"message"`
	Actionable string `json:"actionable,omitempty"`
}

// CanonicalErrorRegistry maps error codes to canonical taxonomy.
var CanonicalErrorRegistry = map[string]ErrorDescriptor{
	ErrCodePaymentRequired: {
		Code:       ErrCodePaymentRequired,
		Status:     http.StatusPaymentRequired,
		Domain:     "PROTOCOL",
		Message:    "Resource requires x402 payment authorization.",
		Actionable: "Parse PAYMENT-REQUIRED challenge and attach valid PAYMENT-SIGNATURE.",
	},
	ErrCodeWalletInsufficientBalance: {
		Code:       ErrCodeWalletInsufficientBalance,
		Status:     http.StatusPaymentRequired,
		Domain:     "WALLET",
		Message:    "Wallet available balance is insufficient to cover this request.",
		Actionable: "Top up wallet balance via admin grant, onchain transfer, or fiat deposit. Silent downgrade to onchain payment is strictly forbidden.",
	},
	ErrCodeWalletFrozen: {
		Code:       ErrCodeWalletFrozen,
		Status:     http.StatusForbidden,
		Domain:     "WALLET",
		Message:    "Wallet account is currently frozen or in arrears status.",
		Actionable: "Contact administrator or clear arrears balance to restore wallet active status.",
	},
	ErrCodePaymentMethodNotAllowed: {
		Code:       ErrCodePaymentMethodNotAllowed,
		Status:     http.StatusForbidden,
		Domain:     "ROUTING",
		Message:    "Requested payment method is not permitted by route policy.",
		Actionable: "Review route configuration for allowed payment methods ('wallet', 'onchain', or 'both').",
	},
	ErrCodePolicyBudgetExceeded: {
		Code:       ErrCodePolicyBudgetExceeded,
		Status:     http.StatusForbidden,
		Domain:     "POLICY",
		Message:    "24-hour rolling or lifetime budget ceiling exhausted.",
		Actionable: "Increase project/tenant budget cap or await rolling window expiration.",
	},
	ErrCodePolicyMaxPerTx: {
		Code:       ErrCodePolicyMaxPerTx,
		Status:     http.StatusForbidden,
		Domain:     "POLICY",
		Message:    "Single transaction amount exceeds maximum per-request policy limit.",
		Actionable: "Adjust transaction amount or reconfigure policy max_amount_per_request.",
	},
	ErrCodePolicyCircuitBroken: {
		Code:       ErrCodePolicyCircuitBroken,
		Status:     http.StatusTooManyRequests,
		Domain:     "POLICY",
		Message:    "Circuit breaker triggered due to runaway agent loops or high request frequency.",
		Actionable: "Cool down request dispatch loop or wait for automatic probe recovery window.",
	},
	ErrCodeAPIKeyInvalid: {
		Code:       ErrCodeAPIKeyInvalid,
		Status:     http.StatusUnauthorized,
		Domain:     "AUTH",
		Message:    "Provided API Key is invalid, revoked, or expired.",
		Actionable: "Verify Bearer token or obtain a newly generated active API Key from console.",
	},
	ErrCodeAPIKeyScopeDenied: {
		Code:       ErrCodeAPIKeyScopeDenied,
		Status:     http.StatusForbidden,
		Domain:     "AUTH",
		Message:    "API Key lacks required permission scope for this operation.",
		Actionable: "Grant appropriate scope (e.g. 'gateway:call') to the API Key.",
	},
	ErrCodeTenantSuspended: {
		Code:       ErrCodeTenantSuspended,
		Status:     http.StatusForbidden,
		Domain:     "TENANT",
		Message:    "Tenant organization account is suspended.",
		Actionable: "Contact platform super-admin to reinstate tenant account.",
	},
	ErrCodeSignatureInvalid: {
		Code:       ErrCodeSignatureInvalid,
		Status:     http.StatusUnauthorized,
		Domain:     "CRYPTOGRAPHY",
		Message:    "EIP-712 / EIP-3009 payment signature verification failed or payload tampered.",
		Actionable: "Verify private key, CAIP-2 network domain separator, and signer address.",
	},
	ErrCodeWalletAuthorizationInvalid: {
		Code:       ErrCodeWalletAuthorizationInvalid,
		Status:     http.StatusUnauthorized,
		Domain:     "WALLET",
		Message:    "AgentPay wallet authorization is invalid, expired, mismatched, or already consumed.",
		Actionable: "Obtain a fresh PAYMENT-REQUIRED challenge and retry with the matching wallet authorization.",
	},
	ErrCodeWalletAuthRequired: {
		Code:       ErrCodeWalletAuthRequired,
		Status:     http.StatusUnauthorized,
		Domain:     "WALLET",
		Message:    "This route requires an AgentPay virtual-wallet API key.",
		Actionable: "Send an active AgentPay API key to receive the wallet price challenge.",
	},
	ErrCodeSignatureExpired: {
		Code:       ErrCodeSignatureExpired,
		Status:     http.StatusUnauthorized,
		Domain:     "CRYPTOGRAPHY",
		Message:    "Payment authorization validity window has expired.",
		Actionable: "Obtain a fresh challenge and sign within the valid time window.",
	},
	ErrCodeNonceReplay: {
		Code:       ErrCodeNonceReplay,
		Status:     http.StatusConflict,
		Domain:     "SETTLEMENT",
		Message:    "Cryptographic nonce has already been consumed or submitted.",
		Actionable: "Generate a fresh 32-byte cryptographic random nonce.",
	},
	ErrCodeIdempotencyConflict: {
		Code:       ErrCodeIdempotencyConflict,
		Status:     http.StatusConflict,
		Domain:     "IDEMPOTENCY",
		Message:    "Idempotency key collision with mismatched payload hash or in-flight concurrent execution.",
		Actionable: "Use a new unique idempotency key or wait for in-flight request resolution.",
	},
	ErrCodeHoldExpired: {
		Code:       ErrCodeHoldExpired,
		Status:     http.StatusRequestTimeout,
		Domain:     "WALLET",
		Message:    "Internal wallet hold reservation expired before upstream completion.",
		Actionable: "Retry request with fresh hold lease.",
	},
	ErrCodeUpstreamTimeout: {
		Code:       ErrCodeUpstreamTimeout,
		Status:     http.StatusGatewayTimeout,
		Domain:     "GATEWAY",
		Message:    "Gateway timed out awaiting upstream API execution.",
		Actionable: "Retry with exact same Idempotency-Key (free idempotent replay).",
	},
	ErrCodeUpstreamFailed: {
		Code:       ErrCodeUpstreamFailed,
		Status:     http.StatusBadGateway,
		Domain:     "GATEWAY",
		Message:    "Upstream service returned 5xx server error.",
		Actionable: "Investigate upstream service availability; retry with same Idempotency-Key.",
	},
	ErrCodeConfigVersionExpired: {
		Code:       ErrCodeConfigVersionExpired,
		Status:     http.StatusConflict,
		Domain:     "CONFIG",
		Message:    "Route configuration version has been superseded or rolled back during execution.",
		Actionable: "Refresh local gateway route snapshot and retry.",
	},
	ErrCodeRouteNotFound: {
		Code:       ErrCodeRouteNotFound,
		Status:     http.StatusNotFound,
		Domain:     "ROUTING",
		Message:    "Requested endpoint path does not match any configured route.",
		Actionable: "Ensure request URI matches a configured and published route prefix.",
	},
	ErrCodeAgentSuspended: {
		Code:       ErrCodeAgentSuspended,
		Status:     http.StatusForbidden,
		Domain:     "AGENT",
		Message:    "Agent is currently suspended by administrator kill-switch.",
		Actionable: "Contact tenant administrator to unsuspend this agent.",
	},
	ErrCodeAgentRevoked: {
		Code:       ErrCodeAgentRevoked,
		Status:     http.StatusForbidden,
		Domain:     "AGENT",
		Message:    "Agent has been permanently revoked and cannot be reactivated.",
		Actionable: "Create a new agent identity and issue fresh API credentials.",
	},
	ErrCodeRouteNotAllowed: {
		Code:       ErrCodeRouteNotAllowed,
		Status:     http.StatusForbidden,
		Domain:     "POLICY",
		Message:    "Target route is not in this Agent's authorization allowlist.",
		Actionable: "Update agent policy to include target route in route_allowlist.",
	},
	ErrCodeRateLimitExceeded: {
		Code:       ErrCodeRateLimitExceeded,
		Status:     http.StatusTooManyRequests,
		Domain:     "RATE_LIMIT",
		Message:    "Agent request rate limit exceeded.",
		Actionable: "Throttle outbound requests or adjust agent rate_limit_rpm policy.",
	},
}

// ProtocolErrorEnvelope represents the canonical wire format.
type ProtocolErrorEnvelope struct {
	Error ProtocolErrorDetail `json:"error"`
}

// ProtocolErrorDetail matches specs/conformance/protocol-errors.json.
type ProtocolErrorDetail struct {
	Code      string                 `json:"code"`
	Message   string                 `json:"message"`
	Domain    string                 `json:"domain"`
	Status    int                    `json:"status"`
	RequestID string                 `json:"requestId"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// WriteProtocolError writes a schema-compliant error response.
func WriteProtocolError(w http.ResponseWriter, code string, requestID string, details map[string]interface{}) {
	desc, ok := CanonicalErrorRegistry[code]
	if !ok {
		desc = ErrorDescriptor{
			Code:    code,
			Status:  http.StatusInternalServerError,
			Domain:  "INTERNAL",
			Message: "An internal protocol error occurred.",
		}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(desc.Status)

	_ = json.NewEncoder(w).Encode(ProtocolErrorEnvelope{
		Error: ProtocolErrorDetail{
			Code:      desc.Code,
			Message:   desc.Message,
			Domain:    desc.Domain,
			Status:    desc.Status,
			RequestID: requestID,
			Details:   details,
		},
	})
}
