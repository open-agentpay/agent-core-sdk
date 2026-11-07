package settlement

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrInsufficientQuota is returned when balance/quota is inadequate.
	ErrInsufficientQuota = errors.New("insufficient quota or balance")
	// ErrAdapterNotConfigured is returned when the required settlement adapter is missing.
	ErrAdapterNotConfigured = errors.New("settlement adapter not configured")
	// ErrSettlementFailed is returned when an adapter fails to execute settlement.
	ErrSettlementFailed = errors.New("settlement execution failed")
)

// UnitType represents the neutral currency or accounting unit.
type UnitType string

const (
	UnitQuota   UnitType = "QUOTA"   // Internal compute credit / Token units
	UnitCNY     UnitType = "CNY"     // Chinese Yuan / Fiat units
	UnitUSD     UnitType = "USD"     // US Dollar / Fiat units
)

// AuthorizationRequest encapsulates pre-flight spending authorization.
type AuthorizationRequest struct {
	TenantID        string    `json:"tenant_id"`
	APIKeyID        string    `json:"api_key_id,omitempty"`
	WalletID        string    `json:"wallet_id,omitempty"`
	EstimatedAmount int64     `json:"estimated_amount"`
	Unit            UnitType  `json:"unit"`
	RouteID         string    `json:"route_id,omitempty"`
	ResourceURI     string    `json:"resource_uri,omitempty"`
	Metadata        map[string]any `json:"metadata,omitempty"`
}

// AuthorizationResult represents the outcome of an authorization check.
type AuthorizationResult struct {
	Authorized      bool      `json:"authorized"`
	AuthorizationID string    `json:"authorization_id,omitempty"` // E.g., Hold ID or Auth Token
	RemainingQuota  int64     `json:"remaining_quota,omitempty"`
	ErrorCode       string    `json:"error_code,omitempty"`
	Message         string    `json:"message,omitempty"`
}

// SettlementRequest represents the final settlement instruction after upstream response.
type SettlementRequest struct {
	AuthorizationID string    `json:"authorization_id,omitempty"`
	TenantID        string    `json:"tenant_id"`
	APIKeyID        string    `json:"api_key_id,omitempty"`
	WalletID        string    `json:"wallet_id,omitempty"`
	ActualAmount    int64     `json:"actual_amount"`
	Unit            UnitType  `json:"unit"`
	PromptTokens    int64     `json:"prompt_tokens,omitempty"`
	OutputTokens    int64     `json:"output_tokens,omitempty"`
	Model           string    `json:"model,omitempty"`
	RouteID         string    `json:"route_id,omitempty"`
	IdempotencyKey  string    `json:"idempotency_key,omitempty"`
	Metadata        map[string]any `json:"metadata,omitempty"`
}

// SettlementResult represents the executed settlement receipt.
type SettlementResult struct {
	Success         bool      `json:"success"`
	SettlementID    string    `json:"settlement_id"`
	ExternalTxID    string    `json:"external_tx_id,omitempty"`
	RemainingQuota  int64     `json:"remaining_quota,omitempty"`
	SettledAt       time.Time `json:"settled_at"`
	ErrorCode       string    `json:"error_code,omitempty"`
	Message         string    `json:"message,omitempty"`
}

// SettlementAdapter is the vendor-neutral interface unifying internal and external clearance.
type SettlementAdapter interface {
	// Name returns the unique adapter identifier.
	Name() string

	// Mode returns the operating clearance category (e.g., "internal", "external").
	Mode() string

	// Authorize evaluates pre-execution budget/funds availability.
	Authorize(ctx context.Context, req *AuthorizationRequest) (*AuthorizationResult, error)

	// Settle confirms and records final resource consumption.
	Settle(ctx context.Context, req *SettlementRequest) (*SettlementResult, error)

	// Release releases any pre-authorization holds when upstream requests fail.
	Release(ctx context.Context, authorizationID string) error
}
