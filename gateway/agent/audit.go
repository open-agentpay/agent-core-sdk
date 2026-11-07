package agent

import (
	"sync"
	"time"
)

// Standard Event Types (T1.8 §4.2)
const (
	EventTypeAgentRequest        = "agent.request"
	EventTypeAgentPolicyDecision = "agent.policy_decision"
	EventTypeAgentSpend          = "agent.spend"
	EventTypeAgentAnomaly        = "agent.anomaly"
	EventTypeAgentControl        = "agent.control"
)

// AuditEmitter defines the interface for reliable audit event emission.
type AuditEmitter interface {
	Emit(event *AuditEvent)
}

// MemoryAuditEmitter buffers audit events in-memory for testing, inspection, and verification.
type MemoryAuditEmitter struct {
	mu     sync.RWMutex
	events []*AuditEvent
}

// NewMemoryAuditEmitter creates an in-memory audit emitter.
func NewMemoryAuditEmitter() *MemoryAuditEmitter {
	return &MemoryAuditEmitter{
		events: make([]*AuditEvent, 0),
	}
}

// Emit appends an immutable audit event to the buffer.
func (m *MemoryAuditEmitter) Emit(event *AuditEvent) {
	if event == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	// Ensure essential envelope fields are populated
	if event.EventID == "" {
		event.EventID = GenerateEventID()
	}
	if event.Version == "" {
		event.Version = "1.0"
	}
	if event.Timestamp == "" {
		event.Timestamp = FormatTimestamp(time.Now())
	}

	m.events = append(m.events, event)
}

// Events returns a snapshot of all buffered audit events.
func (m *MemoryAuditEmitter) Events() []*AuditEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*AuditEvent, len(m.events))
	copy(result, m.events)
	return result
}

// EventsByType filters buffered events by canonical event_type.
func (m *MemoryAuditEmitter) EventsByType(eventType string) []*AuditEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*AuditEvent
	for _, e := range m.events {
		if e.EventType == eventType {
			result = append(result, e)
		}
	}
	return result
}

// EventsByAgent filters buffered events by observed Agent ID.
func (m *MemoryAuditEmitter) EventsByAgent(agentID string) []*AuditEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*AuditEvent
	for _, e := range m.events {
		if e.AgentID == agentID {
			result = append(result, e)
		}
	}
	return result
}

// Clear flushes all buffered events.
func (m *MemoryAuditEmitter) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = m.events[:0]
}

// BuildPolicyDecisionEvent constructs a canonical agent.policy_decision event envelope.
func BuildPolicyDecisionEvent(
	agent *AgentIdentity,
	decision PolicyDecision,
	routeID string,
	correlation CorrelationContext,
	clientIP string,
	userAgent string,
	declared *DeclaredContext,
) *AuditEvent {
	action := "allow"
	if !decision.Allowed {
		action = "deny"
	}

	data := map[string]interface{}{
		"action":      action,
		"decision":    action,
		"reason_code": decision.ReasonCode,
		"reason":      decision.Reason,
		"route_id":    routeID,
	}
	if decision.RuleID != "" {
		data["rule_id"] = decision.RuleID
	}

	return &AuditEvent{
		EventID:     GenerateEventID(),
		EventType:   EventTypeAgentPolicyDecision,
		Version:     "1.0",
		Timestamp:   FormatTimestamp(time.Now()),
		TenantID:    agent.TenantID,
		ProjectID:   agent.ProjectID,
		AgentID:     agent.AgentID,
		Correlation: correlation,
		Actor: ActorContext{
			Type:      "agent",
			ID:        agent.AgentID,
			ClientIP:  clientIP,
			UserAgent: userAgent,
		},
		Declared: declared,
		Data:     data,
	}
}

// BuildRequestEvent constructs a canonical agent.request event envelope.
func BuildRequestEvent(
	agent *AgentIdentity,
	correlation CorrelationContext,
	clientIP string,
	userAgent string,
	routeID string,
	httpStatus int,
	durationMs int64,
	requestHash string,
	declared *DeclaredContext,
) *AuditEvent {
	return &AuditEvent{
		EventID:     GenerateEventID(),
		EventType:   EventTypeAgentRequest,
		Version:     "1.0",
		Timestamp:   FormatTimestamp(time.Now()),
		TenantID:    agent.TenantID,
		ProjectID:   agent.ProjectID,
		AgentID:     agent.AgentID,
		Correlation: correlation,
		Actor: ActorContext{
			Type:      "agent",
			ID:        agent.AgentID,
			ClientIP:  clientIP,
			UserAgent: userAgent,
		},
		Declared: declared,
		Data: map[string]interface{}{
			"route_id":     routeID,
			"http_status":  httpStatus,
			"duration_ms":  durationMs,
			"request_hash": requestHash,
		},
	}
}

// BuildSpendEvent constructs a canonical agent.spend event envelope.
func BuildSpendEvent(
	agent *AgentIdentity,
	correlation CorrelationContext,
	clientIP string,
	userAgent string,
	amountBaseUnits int64,
	asset string,
	paymentMethod string,
	action string, // hold, capture, release
	declared *DeclaredContext,
) *AuditEvent {
	return &AuditEvent{
		EventID:     GenerateEventID(),
		EventType:   EventTypeAgentSpend,
		Version:     "1.0",
		Timestamp:   FormatTimestamp(time.Now()),
		TenantID:    agent.TenantID,
		ProjectID:   agent.ProjectID,
		AgentID:     agent.AgentID,
		Correlation: correlation,
		Actor: ActorContext{
			Type:      "agent",
			ID:        agent.AgentID,
			ClientIP:  clientIP,
			UserAgent: userAgent,
		},
		Declared: declared,
		Data: map[string]interface{}{
			"amount_base_units": amountBaseUnits,
			"asset":             asset,
			"payment_method":    paymentMethod,
			"action":            action,
		},
	}
}
