package usage

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// RequestRecord represents an immutable log of an inbound HTTP request processed by the gateway.
type RequestRecord struct {
	RequestID     string    `json:"request_id"`
	TenantID      string    `json:"tenant_id"`
	ProjectID     string    `json:"project_id"`
	APIKeyID      string    `json:"api_key_id,omitempty"`
	AgentID       string    `json:"agent_id,omitempty"`
	RouteID       string    `json:"route_id,omitempty"`
	ConfigVersion string    `json:"config_version,omitempty"`
	ClientIP      string    `json:"client_ip"`
	HTTPMethod    string    `json:"http_method"`
	RequestPath   string    `json:"request_path"`
	StatusCode    int       `json:"status_code"`
	DurationMs    int64     `json:"duration_ms"`
	ErrorCode     string    `json:"error_code,omitempty"`
	IsReplay      bool      `json:"is_replay"`
	IntentID      string    `json:"intent_id,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// UsageEvent represents an immutable consumption and metering event for billing and analysis.
type UsageEvent struct {
	EventID         string    `json:"event_id"`
	TenantID        string    `json:"tenant_id"`
	ProjectID       string    `json:"project_id"`
	AgentID         string    `json:"agent_id,omitempty"`
	RouteID         string    `json:"route_id"`
	IntentID        string    `json:"intent_id"`
	AmountBaseUnits int64     `json:"amount_base_units"`
	Asset           string    `json:"asset"`
	PaymentMethod   string    `json:"payment_method"` // "wallet", "onchain"
	IsSuccess       bool      `json:"is_success"`
	CreatedAt       time.Time `json:"created_at"`
}

// RequestFilter defines search and pagination criteria for RequestRecords.
type RequestFilter struct {
	TenantID   string
	ProjectID  string
	AgentID    string
	RouteID    string
	StatusCode int
	IsReplay   *bool
	StartTime  *time.Time
	EndTime    *time.Time
	Offset     int
	Limit      int
}

// UsageFilter defines search and pagination criteria for UsageEvents.
type UsageFilter struct {
	TenantID      string
	ProjectID     string
	AgentID       string
	RouteID       string
	IntentID      string
	PaymentMethod string
	IsSuccess     *bool
	StartTime     *time.Time
	EndTime       *time.Time
	Offset        int
	Limit         int
}

// GenerateRequestID generates a canonical req_ ID.
func GenerateRequestID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("req_%s", hex.EncodeToString(b))
}

// GenerateUsageEventID generates a canonical use_ ID.
func GenerateUsageEventID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("use_%s", hex.EncodeToString(b))
}
