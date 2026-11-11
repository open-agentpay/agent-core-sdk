package integration

import (
	"fmt"
	"strings"

	"github.com/open-agentpay/agent-core-sdk/gateway/payment"
)

// Standard Integration Error Codes (T1.1 & Specification v0.1 §5.5)
const (
	ErrCodeUnauthenticated     = "UNAUTHENTICATED"
	ErrCodeAgentNotFound       = "AGENT_NOT_FOUND"
	ErrCodePolicyDenied        = "POLICY_DENIED"
	ErrCodeBudgetExceeded      = "BUDGET_EXCEEDED"
	ErrCodeMerchantNotAllowed  = "MERCHANT_NOT_ALLOWED"
	ErrCodeChallengeInvalid    = "CHALLENGE_INVALID"
	ErrCodeIdempotencyConflict = "IDEMPOTENCY_CONFLICT"
	ErrCodePaymentPending      = "PAYMENT_PENDING"
	ErrCodeSettlementUnknown   = "SETTLEMENT_UNKNOWN"
	ErrCodeApprovalRequired    = "APPROVAL_REQUIRED"
	ErrCodeRateLimited         = "RATE_LIMITED"
	ErrCodeCircuitOpen         = "CIRCUIT_OPEN"
	ErrCodeInvalidRequest      = "INVALID_REQUEST"
	ErrCodeInternalError       = "INTERNAL_ERROR"
)

// AgentContext captures provenance and telemetry for the executing agent.
type AgentContext struct {
	TenantID         string `json:"tenant_id,omitempty"`
	AgentID          string `json:"agent_id,omitempty"`
	RunID            string `json:"run_id,omitempty"`
	Framework        string `json:"framework,omitempty"`
	FrameworkVersion string `json:"framework_version,omitempty"`
	Environment      string `json:"environment,omitempty"`
	ToolName         string `json:"tool_name,omitempty"`
	TaskID           string `json:"task_id,omitempty"`
}

// ResourceContext specifies the target paid resource or x402 challenge.
type ResourceContext struct {
	ResourceID  string `json:"resource_id,omitempty"`  // Route ID in Gateway
	ChallengeID string `json:"challenge_id,omitempty"` // x402 / Wallet Challenge ID
}

// PaymentRequest is the standard framework-agnostic payload for payment initiation.
type PaymentRequest struct {
	Resource       ResourceContext        `json:"resource"`
	Context        AgentContext           `json:"context,omitempty"`
	IdempotencyKey string                 `json:"idempotency_key"`
	Amount         string                 `json:"amount,omitempty"` // Decimal string (e.g. "0.20")
	Asset          string                 `json:"asset,omitempty"`
	Network        string                 `json:"network,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// PolicyDecisionResponse represents the outcome of a standalone policy evaluation.
type PolicyDecisionResponse struct {
	Decision            string `json:"decision"` // ALLOW, DENY, REQUIRE_APPROVAL, REVIEW
	DecisionID          string `json:"decision_id"`
	PaymentIntentID     string `json:"payment_intent_id,omitempty"`
	ReasonCode          string `json:"reason_code"`
	Reason              string `json:"reason,omitempty"`
	PolicyVersion       string `json:"policy_version,omitempty"`
	BudgetReservationID string `json:"budget_reservation_id,omitempty"`
	ExpiresAt           string `json:"expires_at,omitempty"`
}

// PaymentResultResponse represents the three-domain payment execution status.
type PaymentResultResponse struct {
	PaymentIntentID   string `json:"payment_intent_id"`
	Decision          string `json:"decision"`           // ALLOW, DENY, etc.
	PaymentStatus     string `json:"payment_status"`     // CREATED, AUTHORIZED, COMPLETED, REJECTED, EXPIRED, CANCELLED
	SettlementStatus  string `json:"settlement_status"`  // NOT_STARTED, HELD, SUBMITTED, PENDING, CONFIRMED, FAILED, UNKNOWN
	FulfillmentStatus string `json:"fulfillment_status"` // NOT_STARTED, PROCESSING, DELIVERED, FAILED, RECOVERY_REQUIRED
	Amount            string `json:"amount"`
	Asset             string `json:"asset"`
	Network           string `json:"network,omitempty"`
	TransactionHash   string `json:"transaction_hash,omitempty"`
	IdempotencyKey    string `json:"idempotency_key"`
	NextAction        string `json:"next_action,omitempty"` // NONE, POLL_STATUS, WAIT_APPROVAL
}

// AgentIdentityResponse represents the authenticated caller identity.
type AgentIdentityResponse struct {
	TenantID    string `json:"tenant_id"`
	ProjectID   string `json:"project_id"`
	AgentID     string `json:"agent_id"`
	WalletID    string `json:"wallet_id"`
	Status      string `json:"status"`
	Environment string `json:"environment,omitempty"`
}

// ErrorDetail provides structured, machine-readable error information.
type ErrorDetail struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	NextAction string `json:"next_action,omitempty"`
}

// ErrorResponse wraps ErrorDetail for JSON serialization.
type ErrorResponse struct {
	Error ErrorDetail `json:"error"`
}

// ToExternalPaymentStatus maps internal payment intent statuses to external uppercase enums.
func ToExternalPaymentStatus(internal string) string {
	switch strings.ToLower(internal) {
	case payment.IntentStatusCreated:
		return "CREATED"
	case payment.IntentStatusChallenged:
		return "CHALLENGED"
	case payment.IntentStatusAuthorized:
		return "AUTHORIZED"
	case payment.IntentStatusCompleted:
		return "COMPLETED"
	case payment.IntentStatusRejected:
		return "REJECTED"
	case payment.IntentStatusExpired:
		return "EXPIRED"
	case payment.IntentStatusFailed:
		return "FAILED"
	case payment.IntentStatusNeedsReview:
		return "NEEDS_REVIEW"
	case "cancelled":
		return "CANCELLED"
	case "verified":
		return "VERIFIED"
	default:
		if internal == "" {
			return "UNKNOWN"
		}
		return strings.ToUpper(internal)
	}
}

// ToExternalSettlementStatus maps internal settlement statuses to external uppercase enums.
func ToExternalSettlementStatus(internal string) string {
	switch strings.ToLower(internal) {
	case payment.SettlementStatusNotStarted:
		return "NOT_STARTED"
	case payment.SettlementStatusHeld:
		return "HELD"
	case payment.SettlementStatusSubmitted:
		return "SUBMITTED"
	case payment.SettlementStatusPending:
		return "PENDING"
	case payment.SettlementStatusConfirmed:
		return "CONFIRMED"
	case payment.SettlementStatusReleased:
		return "RELEASED"
	case payment.SettlementStatusFailed:
		return "FAILED"
	case payment.SettlementStatusUnknown:
		return "UNKNOWN"
	case "reorged":
		return "REORGED"
	default:
		if internal == "" {
			return "NOT_STARTED"
		}
		return strings.ToUpper(internal)
	}
}

// ToExternalFulfillmentStatus maps internal fulfillment statuses to external uppercase enums.
func ToExternalFulfillmentStatus(internal string) string {
	switch strings.ToLower(internal) {
	case payment.FulfillmentStatusNotStarted:
		return "NOT_STARTED"
	case payment.FulfillmentStatusInProgress:
		return "PROCESSING"
	case payment.FulfillmentStatusSucceeded:
		return "DELIVERED"
	case payment.FulfillmentStatusFailed:
		return "FAILED"
	case payment.FulfillmentStatusUnknown:
		return "RECOVERY_REQUIRED"
	default:
		if internal == "" {
			return "NOT_STARTED"
		}
		return strings.ToUpper(internal)
	}
}

// FormatBaseUnitsToDecimal converts base units (6 decimals default e.g. USDC) to decimal string.
func FormatBaseUnitsToDecimal(baseUnits int64, decimals int) string {
	if decimals <= 0 {
		decimals = 6
	}
	neg := false
	if baseUnits < 0 {
		neg = true
		baseUnits = -baseUnits
	}
	divisor := int64(1)
	for i := 0; i < decimals; i++ {
		divisor *= 10
	}
	integerPart := baseUnits / divisor
	fractionalPart := baseUnits % divisor

	fracStr := fmt.Sprintf("%0*d", decimals, fractionalPart)
	fracStr = strings.TrimRight(fracStr, "0")
	if fracStr == "" {
		fracStr = "0"
	}
	prefix := ""
	if neg {
		prefix = "-"
	}
	return fmt.Sprintf("%s%d.%s", prefix, integerPart, fracStr)
}
