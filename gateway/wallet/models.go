package wallet

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
)

// Standard domain errors.
var (
	ErrWalletNotFound      = errors.New("wallet not found")
	ErrWalletFrozen        = errors.New("wallet is frozen or in arrears")
	ErrInsufficientBalance = errors.New("insufficient available balance")
	ErrHoldNotFound        = errors.New("hold not found")
	ErrHoldNotActive       = errors.New("hold is not active")
	ErrHoldExpired         = errors.New("hold has expired")
	ErrAPIKeyInvalid       = errors.New("invalid or revoked API key")
	ErrLedgerConflict      = errors.New("ledger idempotency conflict")
)

// WalletStatus represents the lifecycle state of a virtual wallet.
type WalletStatus string

const (
	StatusActive        WalletStatus = "active"
	StatusFrozen        WalletStatus = "frozen"
	StatusFrozenArrears WalletStatus = "frozen_arrears"
	StatusClosed        WalletStatus = "closed"
)

// HoldStatus represents the state of a temporary balance reservation.
type HoldStatus string

const (
	HoldStatusHeld     HoldStatus = "held"
	HoldStatusCaptured HoldStatus = "captured"
	HoldStatusReleased HoldStatus = "released"
	HoldStatusExpired  HoldStatus = "expired"
)

// LedgerEntryType represents the classification of immutable financial audit rows.
type LedgerEntryType string

const (
	LedgerTypeTopupCredit LedgerEntryType = "topup_credit"
	LedgerTypeCapture     LedgerEntryType = "capture"
	LedgerTypeHoldRelease LedgerEntryType = "hold_release"
	LedgerTypeAdjustment  LedgerEntryType = "adjustment"
	LedgerTypeReversal    LedgerEntryType = "reversal"
)

// TopUpChannel defines the origin of wallet credits.
type TopUpChannel string

const (
	ChannelAdminGrant     TopUpChannel = "admin_grant"
	ChannelOnchainDeposit TopUpChannel = "onchain_deposit"
	ChannelFiat           TopUpChannel = "fiat"
)

// TopUpStatus defines the state of a top-up order.
type TopUpStatus string

const (
	TopUpStatusCreated   TopUpStatus = "created"
	TopUpStatusPending   TopUpStatus = "pending"
	TopUpStatusConfirmed TopUpStatus = "confirmed"
	TopUpStatusFailed    TopUpStatus = "failed"
	TopUpStatusExpired   TopUpStatus = "expired"
	TopUpStatusReversed  TopUpStatus = "reversed"
)

// Wallet represents a tenant-level master virtual wallet container.
type Wallet struct {
	WalletID       string       `json:"wallet_id"`
	TenantID       string       `json:"tenant_id"`
	Asset          string       `json:"asset"`
	Status         WalletStatus `json:"status"`
	Version        int64        `json:"version"`
	AvailableCache int64        `json:"available_cache"`
	HeldCache      int64        `json:"held_cache"`
	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at"`
}

// Hold represents a temporary hold against available funds.
type Hold struct {
	HoldID          string     `json:"hold_id"`
	WalletID        string     `json:"wallet_id"`
	PaymentIntentID string     `json:"payment_intent_id"`
	Amount          int64      `json:"amount"`
	Status          HoldStatus `json:"status"`
	ExpiresAt       time.Time  `json:"expires_at"`
	CreatedAt       time.Time  `json:"created_at"`
}

// LedgerEntry represents an immutable, append-only financial journal entry.
type LedgerEntry struct {
	EntryID        string          `json:"entry_id"`
	WalletID       string          `json:"wallet_id"`
	TenantID       string          `json:"tenant_id"`
	Type           LedgerEntryType `json:"type"`
	Amount         int64           `json:"amount"` // positive for credits, negative for deductions
	IdempotencyKey string          `json:"idempotency_key"`
	RefType        string          `json:"ref_type"`
	RefID          string          `json:"ref_id"`
	OperatorID     string          `json:"operator_id,omitempty"`
	Reason         string          `json:"reason,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
}

// TopUpOrder represents a unified top-up order.
type TopUpOrder struct {
	TopUpID     string       `json:"topup_id"`
	WalletID    string       `json:"wallet_id"`
	TenantID    string       `json:"tenant_id"`
	Channel     TopUpChannel `json:"channel"`
	Amount      int64        `json:"amount"`
	Asset       string       `json:"asset"`
	Status      TopUpStatus  `json:"status"`
	ExternalRef string       `json:"external_ref,omitempty"`
	OperatorID  string       `json:"operator_id,omitempty"`
	Reason      string       `json:"reason,omitempty"`
	CreatedAt   time.Time    `json:"created_at"`
	ConfirmedAt time.Time    `json:"confirmed_at,omitempty"`
}

// APIKeyRecord represents an API key binding to a tenant.
type APIKeyRecord struct {
	KeyID     string    `json:"key_id"`
	TenantID  string    `json:"tenant_id"`
	ProjectID string    `json:"project_id"`
	AgentID   string    `json:"agent_id,omitempty"`
	KeyHash   string    `json:"key_hash"`
	KeyPrefix string    `json:"key_prefix"`
	Status    string    `json:"status"` // active, revoked, expired
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// ReconciliationReport summarizes the balance invariants check.
type ReconciliationReport struct {
	WalletID         string `json:"wallet_id"`
	AvailableCache   int64  `json:"available_cache"`
	HeldCache        int64  `json:"held_cache"`
	TotalInWallet    int64  `json:"total_in_wallet"`
	SumLedgerEntries int64  `json:"sum_ledger_entries"`
	SumActiveHolds   int64  `json:"sum_active_holds"`
	IsBalanced       bool   `json:"is_balanced"`
	Discrepancy      int64  `json:"discrepancy"`
}

// HashAPIKey computes the SHA-256 hex string for an API key token.
func HashAPIKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}
