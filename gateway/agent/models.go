// Package agent provides Agent-level identity resolution, real-time policy enforcement,
// kill-switch fast-path, and structured behavioral auditing for AgentPay Go Gateway (T2.9 & T1.8).
package agent

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// AgentStatus represents the lifecycle state of an autonomous Agent.
type AgentStatus string

const (
	AgentStatusActive    AgentStatus = "active"
	AgentStatusSuspended AgentStatus = "suspended"
	AgentStatusRevoked   AgentStatus = "revoked"
)

// AgentIdentity represents the verified identity of an Agent resolved from its API Key.
// Security invariant: This is an OBSERVED fact, strictly immune to client spoofing.
type AgentIdentity struct {
	AgentID   string      `json:"agent_id"`
	TenantID  string      `json:"tenant_id"`
	ProjectID string      `json:"project_id"`
	KeyID     string      `json:"key_id"`
	Name      string      `json:"name"`
	Status    AgentStatus `json:"status"`
}

// DeclaredContext represents untrusted context self-reported by the Agent via HTTP headers.
// Security invariant: Stripped of malicious injection chars and strictly limited to 128 chars.
// MUST NOT be used for authorization or financial billing calculations.
type DeclaredContext struct {
	SessionID       string `json:"session_id,omitempty"`
	TaskID          string `json:"task_id,omitempty"`
	ToolName        string `json:"tool_name,omitempty"`
	ParentRequestID string `json:"parent_request_id,omitempty"`
}

// AgentPolicyConfig defines real-time risk controls and budget ceilings for an Agent.
type AgentPolicyConfig struct {
	AgentID             string   `json:"agent_id"`
	MaxAmountPerRequest int64    `json:"max_amount_per_request"`  // 0 = unlimited
	Rolling24hBudgetCap int64    `json:"rolling_24h_budget_cap"`  // 0 = unlimited
	RateLimitRPM        int      `json:"rate_limit_rpm"`          // 0 = unlimited
	RouteAllowlist      []string `json:"route_allowlist"`         // empty = all routes in project allowed
}

// PolicyDecision records the outcome of an in-path synchronous policy evaluation.
type PolicyDecision struct {
	Allowed    bool   `json:"allowed"`
	ReasonCode string `json:"reason_code"` // e.g., ALLOW, ERR_AGENT_SUSPENDED, ERR_POLICY_MAX_PER_TX, etc.
	Reason     string `json:"reason"`
	RuleID     string `json:"rule_id,omitempty"`
}

// CorrelationContext captures distributed tracing identifiers for auditing.
type CorrelationContext struct {
	RequestID      string `json:"request_id"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	IntentID       string `json:"intent_id,omitempty"`
	HoldID         string `json:"hold_id,omitempty"`
	SettlementID   string `json:"settlement_id,omitempty"`
	FulfillmentID  string `json:"fulfillment_id,omitempty"`
}

// ActorContext defines the actor initiating the audited operation.
type ActorContext struct {
	Type      string `json:"type"` // e.g. "agent", "api_key", "admin_user", "system"
	ID        string `json:"id"`
	ClientIP  string `json:"client_ip"`
	UserAgent string `json:"user_agent,omitempty"`
}

// AuditEvent represents a canonical, immutable append-only audit event (T1.5 & T1.8).
type AuditEvent struct {
	EventID     string                 `json:"event_id"`
	EventType   string                 `json:"event_type"` // agent.request, agent.policy_decision, agent.spend, agent.anomaly, agent.control
	Version     string                 `json:"version"`
	Timestamp   string                 `json:"timestamp"`
	TenantID    string                 `json:"tenant_id"`
	ProjectID   string                 `json:"project_id"`
	AgentID     string                 `json:"agent_id"`
	Correlation CorrelationContext     `json:"correlation"`
	Actor       ActorContext           `json:"actor"`
	Declared    *DeclaredContext       `json:"declared,omitempty"`
	Data        map[string]interface{} `json:"data"`
}

// GenerateEventID produces a globally unique canonical event identifier prefixed with evt_.
func GenerateEventID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return fmt.Sprintf("evt_%s", hex.EncodeToString(b))
}

// FormatTimestamp returns an RFC3339 timestamp with microsecond resolution in UTC.
func FormatTimestamp(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000000Z")
}
