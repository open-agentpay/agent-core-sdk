// Package payment implements the unified Payment, Settlement, and Fulfillment correlation domain (T5.2).
// It maintains three orthogonal lifecycle state machines per T1.1 Specification v2.1:
// 1. PaymentIntent (High-level business intent)
// 2. SettlementRecord (Financial transfer via wallet hold/capture or onchain broadcast)
// 3. FulfillmentRecord (Upstream API resource delivery)
package payment

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Intent lifecycle statuses (T1.1 §4.1)
const (
	IntentStatusCreated     = "created"
	IntentStatusChallenged  = "challenged"
	IntentStatusAuthorized  = "authorized"
	IntentStatusRejected    = "rejected"
	IntentStatusExpired     = "expired"
	IntentStatusCompleted   = "completed"
	IntentStatusFailed      = "failed"
	IntentStatusNeedsReview = "needs_review"
)

// Settlement lifecycle statuses (T1.1 §4.2)
const (
	SettlementStatusNotStarted = "not_started"
	SettlementStatusHeld       = "held"
	SettlementStatusSubmitted  = "submitted"
	SettlementStatusPending    = "pending"
	SettlementStatusConfirmed  = "confirmed"
	SettlementStatusReleased   = "released"
	SettlementStatusFailed     = "failed"
	SettlementStatusUnknown    = "unknown"
)

// Fulfillment lifecycle statuses (T1.1 §4.3)
const (
	FulfillmentStatusNotStarted = "not_started"
	FulfillmentStatusInProgress = "in_progress"
	FulfillmentStatusSucceeded  = "succeeded"
	FulfillmentStatusFailed     = "failed"
	FulfillmentStatusUnknown    = "unknown"
)

// Canonical composite display statuses (T1.1 §5 & state-machine.json)
const (
	DisplayWalletHoldProcessing             = "WALLET_HOLD_PROCESSING"
	DisplaySettlementInProgress             = "SETTLEMENT_IN_PROGRESS"
	DisplayFulfillmentInProgress            = "FULFILLMENT_IN_PROGRESS"
	DisplayCompleted                        = "COMPLETED"
	DisplaySettledFulfillmentRefundRequired = "SETTLED_FULFILLMENT_FAILED_REFUND_REQUIRED"
	DisplaySettledFulfillmentNeedsReview    = "SETTLED_FULFILLMENT_UNKNOWN_NEEDS_REVIEW"
	DisplayReleasedUnbilled                 = "RELEASED_UNBILLED"
	DisplayPaymentFailed                    = "PAYMENT_FAILED"
	DisplayRecoveryRequired                 = "RECOVERY_REQUIRED"
	DisplayRejected                         = "REJECTED"
	DisplayExpired                          = "EXPIRED"
)

// Standard domain errors
var (
	ErrIntentNotFound         = errors.New("payment intent not found")
	ErrSettlementNotFound     = errors.New("settlement record not found")
	ErrFulfillmentNotFound    = errors.New("fulfillment record not found")
	ErrTenantMismatch         = errors.New("tenant boundary violation: resource belongs to another tenant")
	ErrTerminalState          = errors.New("HARD RULE VIOLATION: cannot mutate a payment entity in terminal state")
	ErrWalletChallengeInvalid = errors.New("wallet challenge is invalid, expired, or already consumed")
	ErrWalletChallengeReplay  = errors.New("wallet challenge nonce was already used")
)

// PaymentIntent tracks the high-level business payment lifecycle (T1.1 §4.1).
type PaymentIntent struct {
	IntentID        string    `json:"intent_id"`
	TenantID        string    `json:"tenant_id"`
	ProjectID       string    `json:"project_id"`
	AgentID         string    `json:"agent_id,omitempty"`
	RouteID         string    `json:"route_id"`
	IdempotencyKey  string    `json:"idempotency_key,omitempty"`
	RequestID       string    `json:"request_id"`
	PaymentMethod   string    `json:"payment_method"` // "wallet" or "onchain"
	AmountBaseUnits int64     `json:"amount_base_units"`
	Asset           string    `json:"asset"`
	Status          string    `json:"status"` // created, challenged, authorized, rejected, expired, completed, failed, needs_review
	ConfigVersionID string    `json:"config_version_id"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// SettlementRecord tracks the financial fund transfer (T1.1 §4.2).
type SettlementRecord struct {
	SettlementID    string    `json:"settlement_id"`
	IntentID        string    `json:"intent_id"`
	PaymentMethod   string    `json:"payment_method"` // "wallet" or "onchain"
	NetworkID       string    `json:"network_id"`
	AssetAddress    string    `json:"asset_address"`
	PayerAddress    string    `json:"payer_address"`
	PayeeAddress    string    `json:"payee_address"`
	AmountBaseUnits int64     `json:"amount_base_units"`
	Nonce           string    `json:"nonce,omitempty"`
	TxHash          string    `json:"tx_hash,omitempty"`
	BlockNumber     *int64    `json:"block_number,omitempty"`
	Status          string    `json:"status"` // not_started, held, submitted, pending, confirmed, released, failed, unknown
	ErrorMessage    string    `json:"error_message,omitempty"`
	// FacilitatorSettlementID is the Facilitator-side settlement identifier returned by
	// POST /v1/settle. It must be persisted so reconciliation survives gateway restarts.
	FacilitatorSettlementID string    `json:"facilitator_settlement_id,omitempty"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
}

// FulfillmentRecord tracks the upstream API delivery status (T1.1 §4.3).
type FulfillmentRecord struct {
	FulfillmentID    string    `json:"fulfillment_id"`
	IntentID         string    `json:"intent_id"`
	UpstreamURL      string    `json:"upstream_url"`
	UpstreamStatus   int       `json:"upstream_status"`
	LatencyMs        int64     `json:"latency_ms"`
	ResponseBodyHash string    `json:"response_body_hash,omitempty"`
	Status           string    `json:"status"` // not_started, in_progress, succeeded, failed, unknown
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// WalletHoldAssociation represents linked virtual wallet hold details.
type WalletHoldAssociation struct {
	HoldID    string    `json:"hold_id"`
	WalletID  string    `json:"wallet_id"`
	Amount    int64     `json:"amount"`
	Status    string    `json:"status"` // held, captured, released, expired
	ExpiresAt time.Time `json:"expires_at"`
}

// WalletChallenge persists an AgentPay wallet quote and its one-time authorization state.
// SECURITY-REVIEW: this record gates money-moving wallet holds and must be consumed atomically.
type WalletChallenge struct {
	ChallengeID    string
	TenantID       string
	WalletID       string
	APIKeyHash     string
	RouteID        string
	IntentID       string
	IdempotencyKey string
	RequestBinding string
	Amount         int64
	Asset          string
	ResourceURI    string
	ValidAfter     time.Time
	ValidBefore    time.Time
	Status         string
	Nonce          string
	HoldID         string
}

// LedgerAssociation represents linked virtual wallet double-entry ledger flow.
type LedgerAssociation struct {
	EntryID   string    `json:"entry_id"`
	WalletID  string    `json:"wallet_id"`
	Type      string    `json:"type"` // capture, hold_release, etc.
	Amount    int64     `json:"amount"`
	CreatedAt time.Time `json:"created_at"`
}

// PaymentAuditRecord is the consolidated composite correlation model (T5.2 Deliverable).
type PaymentAuditRecord struct {
	IntentID        string `json:"intent_id"`
	TenantID        string `json:"tenant_id"`
	ProjectID       string `json:"project_id"`
	AgentID         string `json:"agent_id,omitempty"`
	RouteID         string `json:"route_id"`
	RequestID       string `json:"request_id"`
	IdempotencyKey  string `json:"idempotency_key,omitempty"`
	PaymentMethod   string `json:"payment_method"`
	AmountBaseUnits int64  `json:"amount_base_units"`
	Asset           string `json:"asset"`

	// Composite Status & Human Readable Notes (T1.1 §5)
	DisplayStatus      string `json:"display_status"`
	DisplayNote        string `json:"display_note"`
	IsRecoveryRequired bool   `json:"is_recovery_required"`

	// Three Orthogonal Subsystem States
	IntentStatus      string `json:"intent_status"`
	SettlementStatus  string `json:"settlement_status"`
	FulfillmentStatus string `json:"fulfillment_status"`

	// Linked Entities
	Intent      *PaymentIntent         `json:"intent,omitempty"`
	Settlement  *SettlementRecord      `json:"settlement,omitempty"`
	Fulfillment *FulfillmentRecord     `json:"fulfillment,omitempty"`
	Hold        *WalletHoldAssociation `json:"hold,omitempty"`
	Ledger      *LedgerAssociation     `json:"ledger,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// PaymentAuditFilter provides filtering criteria for composite audit list queries.
type PaymentAuditFilter struct {
	TenantID      string
	ProjectID     string
	AgentID       string
	RouteID       string
	PaymentMethod string
	DisplayStatus string
	IntentStatus  string
	StartTime     *time.Time
	EndTime       *time.Time
	Limit         int
	Offset        int
}

// DeriveCompositeDisplayStatus computes the official composite state per T1.1 §5 and state-machine.json.
func DeriveCompositeDisplayStatus(intentStatus, settlementStatus, fulfillmentStatus string) (displayStatus string, displayNote string, isRecoveryRequired bool) {
	// Intent-level hard terminals / flags
	if intentStatus == IntentStatusNeedsReview {
		return DisplayRecoveryRequired, "系统异常或恢复超期，需人工复核结算与履约状态", true
	}
	if intentStatus == IntentStatusRejected {
		return DisplayRejected, "请求未通过本地策略或权限校验，已被安全拦截", false
	}
	if intentStatus == IntentStatusExpired {
		return DisplayExpired, "支付意图或签名挑战已过期", false
	}

	// 1. Wallet hold acquired, waiting or calling upstream
	if settlementStatus == SettlementStatusHeld && (fulfillmentStatus == FulfillmentStatusNotStarted || fulfillmentStatus == FulfillmentStatusInProgress) {
		return DisplayWalletHoldProcessing, "虚拟钱包额度已成功锁定，正在调用上游服务", false
	}

	// 2. Onchain broadcast in-flight (before, during, or after upstream fulfillment)
	if (settlementStatus == SettlementStatusUnknown || settlementStatus == SettlementStatusPending || settlementStatus == SettlementStatusSubmitted) &&
		fulfillmentStatus == FulfillmentStatusNotStarted {
		return DisplaySettlementInProgress, "链上交易已广播，等待区块确认", false
	}
	if (settlementStatus == SettlementStatusPending || settlementStatus == SettlementStatusSubmitted) &&
		(fulfillmentStatus == FulfillmentStatusInProgress || fulfillmentStatus == FulfillmentStatusSucceeded) {
		return DisplaySettlementInProgress, "上游已履约，链上交易已广播等待区块最终确认", false
	}
	if settlementStatus == SettlementStatusUnknown && fulfillmentStatus != FulfillmentStatusNotStarted {
		return DisplayRecoveryRequired, "链上结算状态未知，正在通过后台对账任务向 Facilitator 查询确认", true
	}

	// 3. Payment confirmed, upstream in-progress
	if settlementStatus == SettlementStatusConfirmed && fulfillmentStatus == FulfillmentStatusInProgress {
		return DisplayFulfillmentInProgress, "资金已扣费确认，上游服务履约交付中", false
	}

	// 4. Completed: both confirmed and succeeded
	if settlementStatus == SettlementStatusConfirmed && fulfillmentStatus == FulfillmentStatusSucceeded {
		return DisplayCompleted, "扣费确权且上游交付成功，交易顺利完成", false
	}

	// 5. Settled but upstream failed (4xx) -> onchain refund required
	if settlementStatus == SettlementStatusConfirmed && fulfillmentStatus == FulfillmentStatusFailed {
		return DisplaySettledFulfillmentRefundRequired, "链上资金已支付但上游履约失败，待系统补偿或退款", true
	}

	// 6. Settled but upstream unknown (5xx/timeout) -> needs review
	if settlementStatus == SettlementStatusConfirmed && fulfillmentStatus == FulfillmentStatusUnknown {
		return DisplaySettledFulfillmentNeedsReview, "资金已扣费确认，但上游返回 5xx/超时，状态未知待核验", true
	}

	// 7. Wallet released on upstream failure (4xx) or expired hold -> unbilled
	if settlementStatus == SettlementStatusReleased && (fulfillmentStatus == FulfillmentStatusFailed || fulfillmentStatus == FulfillmentStatusUnknown || fulfillmentStatus == FulfillmentStatusNotStarted) {
		return DisplayReleasedUnbilled, "上游请求未成功或冻结已到期，钱包冻结已无损全额解冻，买方未产生扣费", false
	}

	// 8. Payment failed before dispatch or alongside upstream failure
	if settlementStatus == SettlementStatusFailed && (fulfillmentStatus == FulfillmentStatusNotStarted || fulfillmentStatus == FulfillmentStatusFailed) {
		return DisplayPaymentFailed, "资金划转失败或余额不足，未产生有效扣费", false
	}
	if settlementStatus == SettlementStatusFailed && (fulfillmentStatus == FulfillmentStatusSucceeded || fulfillmentStatus == FulfillmentStatusInProgress || fulfillmentStatus == FulfillmentStatusUnknown) {
		return DisplayRecoveryRequired, "链上交易回滚失败但上游已触发调用，需人工复核与追偿", true
	}

	// 9. Unknown fulfillment with held wallet (upstream 5xx/timeout)
	if settlementStatus == SettlementStatusHeld && fulfillmentStatus == FulfillmentStatusUnknown {
		return DisplayRecoveryRequired, "上游出现异常或超时，钱包冻结严格锁定中，等待幂等重试或人工对账", true
	}

	// 10. Early stages before settlement dispatch
	if settlementStatus == SettlementStatusNotStarted && fulfillmentStatus == FulfillmentStatusNotStarted {
		switch intentStatus {
		case IntentStatusChallenged:
			return "HTTP_402_CHALLENGED", "已下发 HTTP 402 签名质询，等待买方签名付款", false
		case IntentStatusAuthorized:
			return "PAYMENT_AUTHORIZED", "支付授权与配额已验证通过，待执行资金划转", false
		case IntentStatusCreated:
			return "INTENT_CREATED", "支付意图已创建，正在匹配路由与执行策略拦截", false
		case IntentStatusCompleted:
			return DisplayCompleted, "扣费确权且上游交付成功，交易顺利完成", false
		case IntentStatusFailed:
			return DisplayPaymentFailed, "资金划转失败或余额不足，未发起履约交付", false
		}
	}

	return "UNKNOWN_COMPOSITE", fmt.Sprintf("未定义的复合状态: intent=%s, stl=%s, ful=%s", intentStatus, settlementStatus, fulfillmentStatus), false
}

// GenerateIntentID generates canonical intent ID: pi_<suffix>.
func GenerateIntentID(requestID string) string {
	if requestID != "" {
		return fmt.Sprintf("pi_%s", requestID)
	}
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("pi_%s", hex.EncodeToString(b))
}

// GenerateSettlementID generates canonical settlement ID: stl_<suffix>.
func GenerateSettlementID(suffix string) string {
	if suffix != "" {
		return fmt.Sprintf("stl_%s", suffix)
	}
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("stl_%s", hex.EncodeToString(b))
}

// GenerateFulfillmentID generates canonical fulfillment ID: ful_<suffix>.
func GenerateFulfillmentID(requestID string) string {
	if requestID != "" {
		return fmt.Sprintf("ful_%s", requestID)
	}
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("ful_%s", hex.EncodeToString(b))
}
