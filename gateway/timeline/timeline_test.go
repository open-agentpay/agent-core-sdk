package timeline

import (
	"context"
	"testing"
	"time"

	"github.com/agent-core-sdk/gateway/agent"
)

func TestMemoryTimelineService(t *testing.T) {
	svc := NewMemoryService()
	ctx := context.Background()

	now := time.Now()
	t1 := now.Add(-30 * time.Minute)
	t2 := now.Add(-20 * time.Minute)
	t3 := now.Add(-10 * time.Minute)

	// Event 1: Agent Alpha in Session 1 - Policy Decision (Allow)
	e1 := &agent.AuditEvent{
		EventID:     "evt_001",
		EventType:   agent.EventTypeAgentPolicyDecision,
		Version:     "1.0",
		Timestamp:   t1.UTC().Format(time.RFC3339Nano),
		TenantID:    "ten_alpha",
		ProjectID:   "prj_alpha",
		AgentID:     "agt_alpha",
		Correlation: agent.CorrelationContext{RequestID: "req_001", IntentID: "pi_001"},
		Actor:       agent.ActorContext{Type: "agent", ID: "agt_alpha", ClientIP: "127.0.0.1"},
		Declared: &agent.DeclaredContext{
			SessionID: "sess_alpha_01",
			TaskID:    "task_crawl",
			ToolName:  "fetch_data",
		},
		Data: map[string]interface{}{
			"action":      "allow",
			"route_id":    "route_market_data",
			"reason_code": "POLICY_ALLOW",
		},
	}

	// Event 2: Agent Alpha in Session 1 - Request (200 OK)
	e2 := &agent.AuditEvent{
		EventID:     "evt_002",
		EventType:   agent.EventTypeAgentRequest,
		Version:     "1.0",
		Timestamp:   t2.UTC().Format(time.RFC3339Nano),
		TenantID:    "ten_alpha",
		ProjectID:   "prj_alpha",
		AgentID:     "agt_alpha",
		Correlation: agent.CorrelationContext{RequestID: "req_001", IntentID: "pi_001"},
		Actor:       agent.ActorContext{Type: "agent", ID: "agt_alpha", ClientIP: "127.0.0.1"},
		Declared: &agent.DeclaredContext{
			SessionID: "sess_alpha_01",
			TaskID:    "task_crawl",
			ToolName:  "fetch_data",
		},
		Data: map[string]interface{}{
			"route_id":     "route_market_data",
			"http_status":  200,
			"duration_ms":  int64(450),
			"request_hash": "sha256:abc123",
		},
	}

	// Event 3: Agent Alpha in Session 2 - Policy Decision (Deny)
	e3 := &agent.AuditEvent{
		EventID:     "evt_003",
		EventType:   agent.EventTypeAgentPolicyDecision,
		Version:     "1.0",
		Timestamp:   t3.UTC().Format(time.RFC3339Nano),
		TenantID:    "ten_alpha",
		ProjectID:   "prj_alpha",
		AgentID:     "agt_alpha",
		Correlation: agent.CorrelationContext{RequestID: "req_002", IntentID: "pi_002"},
		Actor:       agent.ActorContext{Type: "agent", ID: "agt_alpha", ClientIP: "127.0.0.1"},
		Declared: &agent.DeclaredContext{
			SessionID: "sess_alpha_02",
			TaskID:    "task_probe",
		},
		Data: map[string]interface{}{
			"action":      "deny",
			"route_id":    "route_secret",
			"reason":      "Exceeded budget cap",
			"reason_code": "ERR_BUDGET_CAP",
		},
	}

	// Event 4: Agent Beta (different tenant ten_beta)
	e4 := &agent.AuditEvent{
		EventID:     "evt_004",
		EventType:   agent.EventTypeAgentRequest,
		Version:     "1.0",
		Timestamp:   now.UTC().Format(time.RFC3339Nano),
		TenantID:    "ten_beta",
		ProjectID:   "prj_beta",
		AgentID:     "agt_beta",
		Correlation: agent.CorrelationContext{RequestID: "req_003"},
		Actor:       agent.ActorContext{Type: "agent", ID: "agt_beta", ClientIP: "127.0.0.1"},
		Declared: &agent.DeclaredContext{
			SessionID: "sess_beta_01",
		},
		Data: map[string]interface{}{
			"route_id":    "route_market_data",
			"http_status": 200,
		},
	}

	_ = svc.RecordEvent(ctx, e1)
	_ = svc.RecordEvent(ctx, e2)
	_ = svc.RecordEvent(ctx, e3)
	_ = svc.RecordEvent(ctx, e4)

	t.Run("Query All for Agent Alpha", func(t *testing.T) {
		items, total, sessions, err := svc.GetTimeline(ctx, "ten_alpha", "agt_alpha", TimelineFilter{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if total != 3 || len(items) != 3 {
			t.Fatalf("expected 3 items, got total=%d, len=%d", total, len(items))
		}
		// Check order (reverse-chronological: e3, e2, e1)
		if items[0].EventID != "evt_003" || items[1].EventID != "evt_002" || items[2].EventID != "evt_001" {
			t.Fatalf("unexpected order: %s, %s, %s", items[0].EventID, items[1].EventID, items[2].EventID)
		}
		// Check sessions
		if len(sessions) != 2 || sessions[0] != "sess_alpha_01" || sessions[1] != "sess_alpha_02" {
			t.Fatalf("unexpected sessions: %v", sessions)
		}
		// Check summary
		if items[0].Summary != "策略拦截: Exceeded budget cap [ERR_BUDGET_CAP]" {
			t.Errorf("unexpected summary for e3: %s", items[0].Summary)
		}
	})

	t.Run("Filter by Session ID", func(t *testing.T) {
		items, total, _, err := svc.GetTimeline(ctx, "ten_alpha", "agt_alpha", TimelineFilter{
			SessionID: "sess_alpha_01",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if total != 2 || len(items) != 2 {
			t.Fatalf("expected 2 items for session 1, got total=%d, len=%d", total, len(items))
		}
		for _, item := range items {
			if item.Declared == nil || item.Declared.SessionID != "sess_alpha_01" {
				t.Fatalf("unexpected item outside session 1: %+v", item)
			}
		}
	})

	t.Run("Filter by Event Type", func(t *testing.T) {
		items, total, _, err := svc.GetTimeline(ctx, "ten_alpha", "agt_alpha", TimelineFilter{
			EventType: agent.EventTypeAgentRequest,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if total != 1 || len(items) != 1 || items[0].EventID != "evt_002" {
			t.Fatalf("expected 1 request event (evt_002), got total=%d", total)
		}
	})

	t.Run("Multi-Tenant Isolation", func(t *testing.T) {
		// ten_alpha tries to query ten_beta's agent
		items, total, _, err := svc.GetTimeline(ctx, "ten_alpha", "agt_beta", TimelineFilter{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if total != 0 || len(items) != 0 {
			t.Fatalf("expected 0 items across tenant boundary, got %d", total)
		}

		// ten_beta querying agt_beta
		itemsBeta, totalBeta, sessionsBeta, err := svc.GetTimeline(ctx, "ten_beta", "agt_beta", TimelineFilter{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if totalBeta != 1 || len(itemsBeta) != 1 || len(sessionsBeta) != 1 {
			t.Fatalf("expected 1 item for ten_beta, got %d", totalBeta)
		}
	})

	t.Run("Pagination", func(t *testing.T) {
		items, total, _, err := svc.GetTimeline(ctx, "ten_alpha", "agt_alpha", TimelineFilter{
			Limit:  1,
			Offset: 1,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if total != 3 || len(items) != 1 || items[0].EventID != "evt_002" {
			t.Fatalf("expected item evt_002 on offset 1, got total=%d, item=%+v", total, items)
		}
	})
}
