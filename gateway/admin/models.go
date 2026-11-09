// Package admin implements the Control Plane domain models, RBAC, management services,
// and REST API endpoints for AgentPay Go Gateway.
package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/open-agentpay/agent-core-sdk/gateway/rcu"
	"github.com/open-agentpay/agent-core-sdk/gateway/upstreamauth"
)

// Standard domain errors.
var (
	ErrTenantNotFound       = errors.New("tenant not found")
	ErrTenantAlreadyExists   = errors.New("tenant already exists")
	ErrTenantSuspended      = errors.New("tenant is suspended")
	ErrTenantTerminated     = errors.New("tenant is terminated")
	ErrProjectNotFound      = errors.New("project not found")
	ErrProjectAlreadyExists  = errors.New("project already exists")
	ErrProjectArchived      = errors.New("project is archived")
	ErrProjectTenantMismatch = errors.New("project does not belong to specified tenant")
	ErrMemberNotFound       = errors.New("member not found")
	ErrMemberAlreadyExists  = errors.New("member already exists in tenant")
	ErrMemberDisabled       = errors.New("member account is disabled")
	ErrPermissionDenied     = errors.New("permission denied")
	ErrCannotRemoveLastOwner = errors.New("cannot remove the last active owner of a tenant")
	ErrCannotDemoteLastOwner = errors.New("cannot demote the last active owner of a tenant")
	ErrAgentNotFound        = errors.New("agent not found")
	ErrAgentAlreadyExists   = errors.New("agent with same name already exists in project")
	ErrAgentSuspended       = errors.New("agent is suspended")
	ErrAgentRevoked         = errors.New("agent is revoked")
	ErrAgentTenantMismatch  = errors.New("agent does not belong to specified tenant")
	ErrInvalidStatusTransition = errors.New("invalid status transition")
	ErrMissingReason        = errors.New("reason is mandatory for this operation")
	ErrAPIKeyNotFound       = errors.New("api key not found")
	ErrAPIKeyRevoked        = errors.New("api key has been revoked")
	ErrRouteNotFound        = errors.New("route not found")
	ErrRouteAlreadyExists   = errors.New("route already exists")
	ErrPolicyNotFound       = errors.New("policy not found")
	ErrWalletNotFound       = errors.New("wallet not found")
	ErrWalletFrozen         = errors.New("wallet is frozen")
	ErrInvalidAmount        = errors.New("amount must be non-zero / positive")
	ErrInvalidCredentials   = errors.New("invalid email or password")
	ErrPasswordTooShort     = errors.New("password must be at least 8 characters long")
	ErrEmailAlreadyRegistered = errors.New("email is already registered")
	ErrConfigValidationFailed = errors.New("cannot publish configuration: static validation matrix failed")
	ErrConfigVersionNotFound  = errors.New("configuration version not found")
	ErrCannotRollbackToActive = errors.New("cannot rollback to currently active version")
	ErrCurrencyLocked         = errors.New("tenant currency is locked after routes or ledger entries exist")
	ErrInvalidCurrency        = errors.New("unsupported currency: must be CNY, USD, or EUR")
	ErrTrialRateLimitExceeded = errors.New("trial rate limit exceeded")
)

const (
	PublicSandboxTenantID  = "ten_public_sandbox"
	PublicSandboxProjectID = "prj_sandbox"
	PublicSandboxAgentID   = "agt_sandbox"
	PublicSandboxWalletID  = "wlt_public_sandbox"
)

// TrialKeyRequest represents the payload for public trial API key generation.
type TrialKeyRequest struct {
	ClientFingerprint string `json:"client_fingerprint,omitempty"`
}

// TrialKeyResponse represents the newly issued trial API key and metadata.
type TrialKeyResponse struct {
	Success          bool   `json:"success"`
	APIKey           string `json:"api_key"`
	BalanceCNY       string `json:"balance_cny"`
	BalanceBaseUnits int64  `json:"balance_base_units"`
	SingleTxCapCNY   string `json:"single_tx_cap_cny"`
	RateLimitRPM     int    `json:"rate_limit_rpm"`
	ExpiresAt        int64  `json:"expires_at"`
	ExpiresInHours   int    `json:"expires_in_hours"`
	ClaimURL         string `json:"claim_url"`
}

// Lifecycle statuses.
type TenantStatus string

const (
	TenantStatusActive     TenantStatus = "active"
	TenantStatusSuspended  TenantStatus = "suspended"
	TenantStatusTerminated TenantStatus = "terminated"
)

type ProjectStatus string

const (
	ProjectStatusActive   ProjectStatus = "active"
	ProjectStatusArchived ProjectStatus = "archived"
)

type MemberRole string

const (
	RoleOwner    MemberRole = "owner"
	RoleAdmin    MemberRole = "admin"
	RoleOperator MemberRole = "operator"
	RoleViewer   MemberRole = "viewer"
)

type MemberStatus string

const (
	MemberStatusActive   MemberStatus = "active"
	MemberStatusDisabled MemberStatus = "disabled"
)

type AgentStatus string

const (
	AgentStatusActive    AgentStatus = "active"
	AgentStatusSuspended AgentStatus = "suspended"
	AgentStatusRevoked   AgentStatus = "revoked"
)

type APIKeyStatus string

const (
	APIKeyStatusActive  APIKeyStatus = "active"
	APIKeyStatusRevoked APIKeyStatus = "revoked"
	APIKeyStatusExpired APIKeyStatus = "expired"
)

type RouteStatus string

const (
	RouteStatusActive   RouteStatus = "active"
	RouteStatusDisabled RouteStatus = "disabled"
)

// Entities.
type Tenant struct {
	TenantID  string       `json:"tenant_id"`
	Name      string       `json:"name"`
	Currency  string       `json:"currency"`
	Status    TenantStatus `json:"status"`
	CreatedAt int64        `json:"created_at"`
	UpdatedAt int64        `json:"updated_at"`
}

// NormalizeCurrency validates and normalizes a tenant currency code.
func NormalizeCurrency(c string) (string, error) {
	if c == "" {
		return "USD", nil
	}
	switch c {
	case "CNY", "USD", "EUR":
		return c, nil
	case "cny":
		return "CNY", nil
	case "usd":
		return "USD", nil
	case "eur":
		return "EUR", nil
	default:
		return "", ErrInvalidCurrency
	}
}

type Project struct {
	ProjectID          string        `json:"project_id"`
	TenantID           string        `json:"tenant_id"`
	DepartmentID       *string       `json:"department_id"`
	Name               string        `json:"name"`
	BudgetCapBaseUnits int64         `json:"budget_cap_base_units"`
	Status             ProjectStatus `json:"status"`
	CreatedAt          int64         `json:"created_at"`
	UpdatedAt          int64         `json:"updated_at"`
}

type Member struct {
	MemberID     string       `json:"member_id"`
	TenantID     string       `json:"tenant_id"`
	Email        string       `json:"email"`
	PasswordHash string       `json:"-"`
	Role         MemberRole   `json:"role"`
	Status       MemberStatus `json:"status"`
	CreatedAt    int64        `json:"created_at"`
	UpdatedAt    int64        `json:"updated_at"`
}

type Agent struct {
	AgentID      string                 `json:"agent_id"`
	TenantID     string                 `json:"tenant_id"`
	ProjectID    string                 `json:"project_id"`
	Name         string                 `json:"name"`
	Status       AgentStatus            `json:"status"`
	PolicyConfig map[string]interface{} `json:"policy_config"`
	CreatedAt    int64                  `json:"created_at"`
	UpdatedAt    int64                  `json:"updated_at"`
}

type APIKey struct {
	KeyID      string       `json:"key_id"`
	TenantID   string       `json:"tenant_id"`
	ProjectID  string       `json:"project_id"`
	AgentID    string       `json:"agent_id"`
	Name       string       `json:"name"`
	KeyHash    string       `json:"key_hash"`
	KeyPrefix  string       `json:"key_prefix"`
	Scopes     []string     `json:"scopes"`
	Status     APIKeyStatus `json:"status"`
	ExpiresAt  *int64       `json:"expires_at,omitempty"`
	LastUsedAt *int64       `json:"last_used_at,omitempty"`
	CreatedAt  int64        `json:"created_at"`
	UpdatedAt  int64        `json:"updated_at"`
}

type CreateAPIKeyResult struct {
	APIKey *APIKey `json:"api_key"`
	RawKey string  `json:"raw_key"`
}

type UpstreamAuthConfig = upstreamauth.UpstreamAuthConfig

// MarketplaceParameter defines a single parameter in the route's API schema.
type MarketplaceParameter struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Required    bool   `json:"required"`
	Description string `json:"description"`
	Example     string `json:"example,omitempty"`
}

type Route struct {
	RouteID               string                 `json:"route_id"`
	TenantID              string                 `json:"tenant_id"`
	ProjectID             string                 `json:"project_id"`
	Slug                  string                 `json:"slug,omitempty"`
	Title                 string                 `json:"title,omitempty"`
	Summary               string                 `json:"summary,omitempty"`
	ProviderName          string                 `json:"provider_name,omitempty"`
	IsPublic              bool                   `json:"is_public"`
	Category              string                 `json:"category,omitempty"`
	Tags                  []string               `json:"tags,omitempty"`
	DescriptionMD         string                 `json:"description_md,omitempty"`
	Network               string                 `json:"network,omitempty"`
	NetworkLabel          string                 `json:"network_label,omitempty"`
	PathPattern           string                 `json:"path_pattern"`
	Methods               []string               `json:"methods,omitempty"`
	UpstreamURL           string                 `json:"upstream_url"`
	PriceBaseUnits        int64                  `json:"price_base_units"`
	Asset                 string                 `json:"asset"`
	OnchainPriceBaseUnits *int64                 `json:"onchain_price_base_units,omitempty"`
	OnchainAsset          string                 `json:"onchain_asset,omitempty"`
	PayeeAddress          string                 `json:"payee_address"`
	AllowedPaymentMethods string                 `json:"allowed_payment_methods"`
	RateLimitRPM          int                    `json:"rate_limit_rpm"`
	TimeoutMs             int                    `json:"timeout_ms"`
	UpstreamAuth          *UpstreamAuthConfig    `json:"upstream_auth,omitempty"`
	Parameters            []MarketplaceParameter `json:"parameters,omitempty"`
	SampleParams          map[string]interface{} `json:"sample_params,omitempty"`
	SampleResponse        map[string]interface{} `json:"sample_response,omitempty"`
	Status                RouteStatus            `json:"status"`
	CreatedAt             int64                  `json:"created_at"`
	UpdatedAt             int64                  `json:"updated_at"`
}

type UpdateRouteInput struct {
	RouteID               string                 `json:"route_id"`
	TenantID              string                 `json:"tenant_id"`
	ProjectID             *string                `json:"project_id,omitempty"`
	Slug                  *string                `json:"slug,omitempty"`
	Title                 *string                `json:"title,omitempty"`
	Summary               *string                `json:"summary,omitempty"`
	ProviderName          *string                `json:"provider_name,omitempty"`
	IsPublic              *bool                  `json:"is_public,omitempty"`
	Category              *string                `json:"category,omitempty"`
	Tags                  []string               `json:"tags,omitempty"`
	DescriptionMD         *string                `json:"description_md,omitempty"`
	Network               *string                `json:"network,omitempty"`
	NetworkLabel          *string                `json:"network_label,omitempty"`
	PathPattern           *string                `json:"path_pattern,omitempty"`
	Methods               []string               `json:"methods,omitempty"`
	UpstreamURL           *string                `json:"upstream_url,omitempty"`
	PriceBaseUnits        *int64                 `json:"price_base_units,omitempty"`
	Asset                 *string                `json:"asset,omitempty"`
	OnchainPriceBaseUnits *int64                 `json:"onchain_price_base_units,omitempty"`
	OnchainAsset          *string                `json:"onchain_asset,omitempty"`
	PayeeAddress          *string                `json:"payee_address,omitempty"`
	AllowedPaymentMethods *string                `json:"allowed_payment_methods,omitempty"`
	RateLimitRPM          *int                   `json:"rate_limit_rpm,omitempty"`
	TimeoutMs             *int                   `json:"timeout_ms,omitempty"`
	UpstreamAuth          *UpstreamAuthConfig    `json:"upstream_auth,omitempty"`
	Parameters            []MarketplaceParameter `json:"parameters,omitempty"`
	SampleParams          map[string]interface{} `json:"sample_params,omitempty"`
	SampleResponse        map[string]interface{} `json:"sample_response,omitempty"`
	Status                *RouteStatus           `json:"status,omitempty"`
}

// MarketplaceSLAMetrics represents real-time gateway telemetry for a public marketplace route.
type MarketplaceSLAMetrics struct {
	SuccessRate24h float64 `json:"success_rate_24h"`
	P95LatencyMs   int64   `json:"p95_latency_ms"`
	PaidCalls24h   int64   `json:"paid_calls_24h"`
	TotalCalls     int64   `json:"total_calls"`
	HealthStatus   string  `json:"health_status"` // "healthy" | "degraded" | "maintenance"
}

// MarketplaceRouteItem represents a public storefront listing enriched with gateway SLA metrics.
type MarketplaceRouteItem struct {
	RouteID               string                 `json:"route_id"`
	TenantID              string                 `json:"tenant_id"`
	ProviderName          string                 `json:"provider_name"`
	Slug                  string                 `json:"slug"`
	Title                 string                 `json:"title"`
	Summary               string                 `json:"summary,omitempty"`
	Category              string                 `json:"category"`
	Tags                  []string               `json:"tags"`
	DescriptionMD         string                 `json:"description_md"`
	Network               string                 `json:"network"`
	NetworkLabel          string                 `json:"network_label,omitempty"`
	PathPattern           string                 `json:"path_pattern"`
	Methods               []string               `json:"methods"`
	PriceBaseUnits        int64                  `json:"price_base_units"`
	Asset                 string                 `json:"asset"`
	OnchainPriceBaseUnits int64                  `json:"onchain_price_base_units"`
	OnchainAsset          string                 `json:"onchain_asset"`
	PayeeAddress          string                 `json:"payee_address"`
	AllowedPaymentMethods string                 `json:"allowed_payment_methods"`
	RateLimitRPM          int                    `json:"rate_limit_rpm"`
	TimeoutMs             int                    `json:"timeout_ms"`
	Status                RouteStatus            `json:"status"`
	SLA                   MarketplaceSLAMetrics  `json:"sla"`
	Parameters            []MarketplaceParameter `json:"parameters,omitempty"`
	SampleParams          map[string]interface{} `json:"sample_params,omitempty"`
	SampleResponse        map[string]interface{} `json:"sample_response,omitempty"`
	CreatedAt             int64                  `json:"created_at"`
	UpdatedAt             int64                  `json:"updated_at"`
}

// MarketplaceFilter defines search and category filtering for public marketplace routes.
type MarketplaceFilter struct {
	Query    string
	Category string
	Network  string
	Tag      string
}

type TestUpstreamInput struct {
	UpstreamURL  string              `json:"upstream_url"`
	Method       string              `json:"method,omitempty"`
	UpstreamAuth *UpstreamAuthConfig `json:"upstream_auth,omitempty"`
}

type TestUpstreamResult struct {
	Success     bool              `json:"success"`
	StatusCode  int               `json:"status_code"`
	StatusText  string            `json:"status_text"`
	LatencyMs   int64             `json:"latency_ms"`
	SentHeaders map[string]string `json:"sent_headers"`
	Error       string            `json:"error,omitempty"`
}

type Policy struct {
	PolicyID               string   `json:"policy_id"`
	TenantID               string   `json:"tenant_id"`
	ProjectID              string   `json:"project_id"`
	AgentID                string   `json:"agent_id,omitempty"`
	RouteID                string   `json:"route_id,omitempty"`
	MaxAmountPerRequest    int64    `json:"max_amount_per_request"`
	Rolling24hBudgetCap    int64    `json:"rolling_24h_budget_cap"`
	CircuitBreakerMaxRPM   int      `json:"circuit_breaker_max_rpm"`
	WhitelistedPayees      []string `json:"whitelisted_payees"`
	WhitelistedNetworks    []string `json:"whitelisted_networks"`
	WhitelistedRoutes      []string `json:"whitelisted_routes"`
	IsActive               bool     `json:"is_active"`
	CreatedAt              int64    `json:"created_at"`
	UpdatedAt              int64    `json:"updated_at"`
}

type ValidationError struct {
	TargetType string `json:"target_type"` // "Route" | "Policy" | "Global"
	TargetID   string `json:"target_id"`
	Field      string `json:"field"`
	Code       string `json:"code"`
	Message    string `json:"message"`
}

type ValidationSummary struct {
	TotalRoutes   int `json:"total_routes"`
	TotalPolicies int `json:"total_policies"`
	ErrorCount    int `json:"error_count"`
	WarningCount  int `json:"warning_count"`
}

type ValidationResult struct {
	Valid       bool              `json:"valid"`
	Errors      []ValidationError `json:"errors"`
	Summary     ValidationSummary `json:"summary"`
	ValidatedAt int64             `json:"validated_at"`
}

type ConfigDraftSummary struct {
	TenantID        string            `json:"tenant_id"`
	PendingChanges  int               `json:"pending_changes"`
	RoutesCount     int               `json:"routes_count"`
	PoliciesCount   int               `json:"policies_count"`
	LastValidatedAt *int64            `json:"last_validated_at,omitempty"`
	IsValidated     bool              `json:"is_validated"`
	LastResult      *ValidationResult `json:"last_result,omitempty"`
}

type RouteDiffItem struct {
	RouteID     string                 `json:"route_id"`
	Action      string                 `json:"action"` // "added" | "modified" | "deleted"
	PathPattern string                 `json:"path_pattern"`
	Before      map[string]interface{} `json:"before,omitempty"`
	After       map[string]interface{} `json:"after,omitempty"`
}

type PolicyDiffItem struct {
	PolicyID string                 `json:"policy_id"`
	Action   string                 `json:"action"` // "added" | "modified" | "deleted"
	Before   map[string]interface{} `json:"before,omitempty"`
	After    map[string]interface{} `json:"after,omitempty"`
}

type ConfigDraftDiff struct {
	TenantID        string           `json:"tenant_id"`
	ActiveVersionID string           `json:"active_version_id,omitempty"`
	HasChanges      bool             `json:"has_changes"`
	RouteDiffs      []RouteDiffItem  `json:"route_diffs"`
	PolicyDiffs     []PolicyDiffItem `json:"policy_diffs"`
}

// ConfigVersion represents an immutable published configuration snapshot (T4.4).
type ConfigVersion struct {
	VersionID      string              `json:"version_id"`
	TenantID       string              `json:"tenant_id"`
	VersionNumber  int64               `json:"version_number"`
	SnapshotJSON   *rcu.ConfigSnapshot `json:"snapshot_json"`
	SnapshotHash   string              `json:"snapshot_hash"`
	PublishedBy    string              `json:"published_by"`
	PublisherEmail string              `json:"publisher_email,omitempty"`
	ChangeSummary  string              `json:"change_summary"`
	IsActive       bool                `json:"is_active"`
	RoutesCount    int                 `json:"routes_count"`
	PoliciesCount  int                 `json:"policies_count"`
	CreatedAt      int64               `json:"created_at"`
}

type PublishConfigRequest struct {
	ChangeSummary string `json:"change_summary"`
}

type RollbackConfigRequest struct {
	TargetVersionID string `json:"target_version_id"`
	Reason          string `json:"reason,omitempty"`
}


type AuditEvent struct {
	AuditID     string                 `json:"audit_id"`
	TenantID    string                 `json:"tenant_id"`
	OperatorID  string                 `json:"operator_id"`
	Action      string                 `json:"action"`
	TargetType  string                 `json:"target_type"`
	TargetID    string                 `json:"target_id"`
	BeforeState map[string]interface{} `json:"before_state,omitempty"`
	AfterState  map[string]interface{} `json:"after_state,omitempty"`
	ClientIP    string                 `json:"client_ip"`
	CreatedAt   int64                  `json:"created_at"`
}

// ID generators.
func generateID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s_%s", prefix, hex.EncodeToString(b))
}

func GenerateTenantID() string  { return generateID("ten") }
func GenerateProjectID() string { return generateID("prj") }
func GenerateMemberID() string  { return generateID("usr") }
func GenerateAgentID() string   { return generateID("agt") }
func GenerateAPIKeyID() string  { return generateID("apk") }
func GenerateRouteID() string   { return generateID("rte") }
func GeneratePolicyID() string  { return generateID("pol") }
func GenerateConfigVersionID() string { return generateID("ver") }
func GenerateAuditID() string   { return generateID("aud") }

func GenerateRawAPIKey() (rawKey string, keyHash string, keyPrefix string) {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	rawKey = "apk_live_" + hex.EncodeToString(b)
	keyPrefix = rawKey[:12]
	hash := hex.EncodeToString(sha256Hash([]byte(rawKey)))
	return rawKey, hash, keyPrefix
}

// GenerateTrialRawAPIKey creates a guest trial API key with apk_live_guest_ prefix.
func GenerateTrialRawAPIKey() (rawKey string, keyHash string, keyPrefix string) {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	rawKey = "apk_live_guest_" + hex.EncodeToString(b)
	keyPrefix = "apk_live_guest_"
	hash := hex.EncodeToString(sha256Hash([]byte(rawKey)))
	return rawKey, hash, keyPrefix
}

func sha256Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
