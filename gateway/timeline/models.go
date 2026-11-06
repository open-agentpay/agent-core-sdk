package timeline

import (
	"errors"
	"fmt"
	"time"

	"github.com/open-agentpay/agent-core-sdk/gateway/agent"
)

var (
	ErrTenantMismatch = errors.New("agent does not belong to specified tenant")
	ErrAgentNotFound  = errors.New("agent not found")
)

// ObservedFacts captures verifiable facts observed and verified by the gateway (T1.8 §4.1).
type ObservedFacts struct {
	TenantID        string `json:"tenant_id"`
	ProjectID       string `json:"project_id"`
	AgentID         string `json:"agent_id"`
	RequestID       string `json:"request_id"`
	RouteID         string `json:"route_id,omitempty"`
	ConfigVersion   string `json:"config_version,omitempty"`
	StatusCode      int    `json:"status_code,omitempty"`
	LatencyMs       int64  `json:"latency_ms,omitempty"`
	CostBaseUnits   int64  `json:"cost_base_units,omitempty"`
	PolicyDecision  string `json:"policy_decision,omitempty"` // allow, deny
	RejectCode      string `json:"reject_code,omitempty"`
	PaymentIntentID string `json:"payment_intent_id,omitempty"`
	SettlementID    string `json:"settlement_id,omitempty"`
	HoldID          string `json:"hold_id,omitempty"`
	RequestHash     string `json:"request_hash,omitempty"`
	OperatorID      string `json:"operator_id,omitempty"`
	ControlReason   string `json:"control_reason,omitempty"`
}

// TimelineEvent is the read-model projection of an immutable audit event for visualization.
type TimelineEvent struct {
	EventID    string                 `json:"event_id"`
	EventType  string                 `json:"event_type"` // agent.request, agent.policy_decision, agent.spend, agent.control, agent.anomaly
	OccurredAt string                 `json:"occurred_at"` // RFC3339
	Actor      string                 `json:"actor"`       // agent, admin, system
	Summary    string                 `json:"summary"`
	Observed   ObservedFacts          `json:"observed"`
	Declared   *agent.DeclaredContext `json:"declared,omitempty"`
	Data       map[string]interface{} `json:"data,omitempty"`
}

// TimelineFilter provides query options for retrieving agent timelines.
type TimelineFilter struct {
	TenantID  string
	AgentID   string
	ProjectID string
	SessionID string
	TaskID    string
	EventType string
	StartTime *time.Time
	EndTime   *time.Time
	Limit     int
	Offset    int
}

// TimelineResponse represents the paginated response for the timeline API.
type TimelineResponse struct {
	Items    []*TimelineEvent `json:"items"`
	Total    int64            `json:"total"`
	Count    int              `json:"count"`
	Sessions []string         `json:"sessions"`
}

// GenerateSummary creates a human-readable event summary based on canonical event facts.
func GenerateSummary(event *agent.AuditEvent) string {
	if event == nil {
		return ""
	}

	data := event.Data
	if data == nil {
		data = make(map[string]interface{})
	}

	switch event.EventType {
	case agent.EventTypeAgentRequest:
		routeID, _ := data["route_id"].(string)
		status, _ := data["http_status"].(int)
		if status == 0 {
			if sFloat, ok := data["http_status"].(float64); ok {
				status = int(sFloat)
			}
		}
		durationMs, _ := data["duration_ms"].(int64)
		if durationMs == 0 {
			if dFloat, ok := data["duration_ms"].(float64); ok {
				durationMs = int64(dFloat)
			}
		}
		if status >= 200 && status < 300 {
			return fmt.Sprintf("成功调用路由 %s (HTTP %d, 耗时 %dms)", routeID, status, durationMs)
		}
		return fmt.Sprintf("调用路由 %s 返回异常 (HTTP %d, 耗时 %dms)", routeID, status, durationMs)

	case agent.EventTypeAgentPolicyDecision:
		action, _ := data["action"].(string)
		routeID, _ := data["route_id"].(string)
		reasonCode, _ := data["reason_code"].(string)
		reason, _ := data["reason"].(string)

		if action == "allow" {
			return fmt.Sprintf("策略判定放行: 路由 %s", routeID)
		}
		if reason != "" {
			return fmt.Sprintf("策略拦截: %s [%s]", reason, reasonCode)
		}
		return fmt.Sprintf("策略安全拦截 [%s]", reasonCode)

	case agent.EventTypeAgentSpend:
		action, _ := data["action"].(string)
		amount, _ := data["amount_base_units"].(int64)
		if amount == 0 {
			if aFloat, ok := data["amount_base_units"].(float64); ok {
				amount = int64(aFloat)
			}
		}
		asset, _ := data["asset"].(string)
		method, _ := data["payment_method"].(string)

		actionName := "资金操作"
		switch action {
		case "hold":
			actionName = "冻结锁定"
		case "capture":
			actionName = "扣费确认"
		case "release":
			actionName = "解冻释放"
		}
		return fmt.Sprintf("资金结算 [%s]: %d %s (方式: %s)", actionName, amount, asset, method)

	case agent.EventTypeAgentControl:
		reason, _ := data["control_reason"].(string)
		if reason != "" {
			return fmt.Sprintf("管理控制动作: %s", reason)
		}
		return "管理员执行了 Agent 运行状态控制"

	case agent.EventTypeAgentAnomaly:
		desc, _ := data["description"].(string)
		if desc != "" {
			return fmt.Sprintf("风控异常告警: %s", desc)
		}
		return "风控检测器触发了异常指标告警"

	default:
		return fmt.Sprintf("Agent 行为事件: %s", event.EventType)
	}
}

// FromAuditEvent transforms a low-level AuditEvent into a read-model TimelineEvent.
func FromAuditEvent(event *agent.AuditEvent) *TimelineEvent {
	if event == nil {
		return nil
	}

	actorType := "agent"
	if event.Actor.Type != "" {
		actorType = event.Actor.Type
	}

	observed := ObservedFacts{
		TenantID:        event.TenantID,
		ProjectID:       event.ProjectID,
		AgentID:         event.AgentID,
		RequestID:       event.Correlation.RequestID,
		PaymentIntentID: event.Correlation.IntentID,
		SettlementID:    event.Correlation.SettlementID,
		HoldID:          event.Correlation.HoldID,
		RequestHash:     "",
	}

	if event.Data != nil {
		if rID, ok := event.Data["route_id"].(string); ok {
			observed.RouteID = rID
		}
		if cv, ok := event.Data["config_version"].(string); ok {
			observed.ConfigVersion = cv
		}
		if st, ok := event.Data["http_status"].(int); ok {
			observed.StatusCode = st
		} else if stF, ok := event.Data["http_status"].(float64); ok {
			observed.StatusCode = int(stF)
		}
		if lat, ok := event.Data["duration_ms"].(int64); ok {
			observed.LatencyMs = lat
		} else if latF, ok := event.Data["duration_ms"].(float64); ok {
			observed.LatencyMs = int64(latF)
		}
		if amt, ok := event.Data["amount_base_units"].(int64); ok {
			observed.CostBaseUnits = amt
		} else if amtF, ok := event.Data["amount_base_units"].(float64); ok {
			observed.CostBaseUnits = int64(amtF)
		} else if amt, ok := event.Data["cost_base_units"].(int64); ok {
			observed.CostBaseUnits = amt
		} else if amtF, ok := event.Data["cost_base_units"].(float64); ok {
			observed.CostBaseUnits = int64(amtF)
		}
		if act, ok := event.Data["action"].(string); ok {
			observed.PolicyDecision = act
		}
		if rc, ok := event.Data["reason_code"].(string); ok {
			observed.RejectCode = rc
		}
		if reqHash, ok := event.Data["request_hash"].(string); ok {
			observed.RequestHash = reqHash
		}
		if opID, ok := event.Data["operator_id"].(string); ok {
			observed.OperatorID = opID
		}
		if cr, ok := event.Data["control_reason"].(string); ok {
			observed.ControlReason = cr
		}
	}

	return &TimelineEvent{
		EventID:    event.EventID,
		EventType:  event.EventType,
		OccurredAt: event.Timestamp,
		Actor:      actorType,
		Summary:    GenerateSummary(event),
		Observed:   observed,
		Declared:   event.Declared,
		Data:       event.Data,
	}
}
