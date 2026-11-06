package agent

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/open-agentpay/agent-core-sdk/gateway/rcu"
)


func TestSanitizeDeclaredField(t *testing.T) {
	// Normal string
	if got := SanitizeDeclaredField("sess_12345"); got != "sess_12345" {
		t.Fatalf("expected sess_12345, got %s", got)
	}

	// 128-char limit truncation
	longStr := strings.Repeat("a", 200)
	sanitized := SanitizeDeclaredField(longStr)
	if len(sanitized) != 128 {
		t.Fatalf("expected 128 length, got %d", len(sanitized))
	}

	// Injection characters removal (CRLF, quotes, tags)
	malicious := "task_\r\n<script>alert('xss')</script>_test"
	cleaned := SanitizeDeclaredField(malicious)
	if strings.Contains(cleaned, "\r") || strings.Contains(cleaned, "\n") ||
		strings.Contains(cleaned, "<") || strings.Contains(cleaned, ">") ||
		strings.Contains(cleaned, "'") {
		t.Fatalf("malicious characters were not stripped: %s", cleaned)
	}
}

func TestSanitizeAndStripSpoofedAgentHeaders(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("X-Agent-ID", "spoofed_agt_99999")
	hdr.Set("X-Agent-Tenant-ID", "spoofed_ten_99999")
	hdr.Set("X-Agent-Project-ID", "spoofed_prj_99999")
	hdr.Set("X-Legit-Header", "keep-me")

	SanitizeAndStripSpoofedAgentHeaders(hdr)

	if hdr.Get("X-Agent-ID") != "" {
		t.Fatalf("X-Agent-ID should have been stripped")
	}
	if hdr.Get("X-Agent-Tenant-ID") != "" {
		t.Fatalf("X-Agent-Tenant-ID should have been stripped")
	}
	if hdr.Get("X-Agent-Project-ID") != "" {
		t.Fatalf("X-Agent-Project-ID should have been stripped")
	}
	if hdr.Get("X-Legit-Header") != "keep-me" {
		t.Fatalf("X-Legit-Header should be preserved")
	}
}

func TestKillSwitchInstantEnforcement(t *testing.T) {
	reg := NewRegistry()
	enforcer := NewEnforcer()

	agent := &AgentIdentity{
		AgentID:   "agt_test_01",
		TenantID:  "ten_01",
		ProjectID: "prj_01",
		KeyID:     "apk_01",
		Name:      "TestBot",
		Status:    AgentStatusActive,
	}
	policy := &AgentPolicyConfig{
		AgentID: "agt_test_01",
	}

	reg.RegisterAgent(agent, policy)
	reg.BindAPIKey("apk_live_secret123", agent.AgentID)

	// Step 1: Active agent evaluates to ALLOW
	dec := enforcer.Evaluate(context.Background(), agent, policy, "rou_01", "/api/v1/chat", 100)
	if !dec.Allowed {
		t.Fatalf("expected allowed for active agent, got %v", dec)
	}

	// Step 2: Trigger Kill Switch (instant suspend)
	err := reg.SetAgentStatus("agt_test_01", AgentStatusSuspended)
	if err != nil {
		t.Fatalf("unexpected error setting agent status: %v", err)
	}

	// Refreshed evaluation must be rejected immediately
	updatedAgent, ok := reg.GetAgent("agt_test_01")
	if !ok || updatedAgent.Status != AgentStatusSuspended {
		t.Fatalf("expected suspended status")
	}

	decSuspended := enforcer.Evaluate(context.Background(), updatedAgent, policy, "rou_01", "/api/v1/chat", 100)
	if decSuspended.Allowed || decSuspended.ReasonCode != CodeAgentSuspended {
		t.Fatalf("expected CodeAgentSuspended, got %v", decSuspended)
	}
}

func TestEnforcerPolicyRules(t *testing.T) {
	enforcer := NewEnforcer()

	agent := &AgentIdentity{
		AgentID:   "agt_trader_01",
		TenantID:  "ten_01",
		ProjectID: "prj_01",
		Status:    AgentStatusActive,
	}

	policy := &AgentPolicyConfig{
		AgentID:             "agt_trader_01",
		MaxAmountPerRequest: 500,
		Rolling24hBudgetCap: 1000,
		RateLimitRPM:        2,
		RouteAllowlist:      []string{"rou_allowed", "/api/v1/trade"},
	}

	ctx := context.Background()

	// 1. Route not in allowlist
	decRoute := enforcer.Evaluate(ctx, agent, policy, "rou_forbidden", "/api/v1/secret", 100)
	if decRoute.Allowed || decRoute.ReasonCode != CodeRouteNotAllowed {
		t.Fatalf("expected CodeRouteNotAllowed, got %v", decRoute)
	}

	// 2. Max amount per transaction exceeded
	decMax := enforcer.Evaluate(ctx, agent, policy, "rou_allowed", "/api/v1/trade", 600)
	if decMax.Allowed || decMax.ReasonCode != CodePolicyMaxPerTx {
		t.Fatalf("expected CodePolicyMaxPerTx, got %v", decMax)
	}

	// 3. Normal request within limits
	decOk := enforcer.Evaluate(ctx, agent, policy, "rou_allowed", "/api/v1/trade", 400)
	if !decOk.Allowed {
		t.Fatalf("expected allowed, got %v", decOk)
	}
	enforcer.RecordSpend(agent.AgentID, 400)

	// 4. Second request within rate limit
	decOk2 := enforcer.Evaluate(ctx, agent, policy, "rou_allowed", "/api/v1/trade", 400)
	if !decOk2.Allowed {
		t.Fatalf("expected allowed, got %v", decOk2)
	}
	enforcer.RecordSpend(agent.AgentID, 400)

	// 5. Third request in same minute triggers rate limit (RPM = 2)
	decRate := enforcer.Evaluate(ctx, agent, policy, "rou_allowed", "/api/v1/trade", 100)
	if decRate.Allowed || decRate.ReasonCode != CodeRateLimitExceeded {
		t.Fatalf("expected CodeRateLimitExceeded, got %v", decRate)
	}

	// 6. Test Budget Cap: reset rate window to test budget
	enforcer.mu.Lock()
	delete(enforcer.rateWindows, agent.AgentID)
	enforcer.mu.Unlock()

	// Current spent = 800, requesting 300 (800+300 > 1000)
	decBudget := enforcer.Evaluate(ctx, agent, policy, "rou_allowed", "/api/v1/trade", 300)
	if decBudget.Allowed || decBudget.ReasonCode != CodePolicyBudgetExceeded {
		t.Fatalf("expected CodePolicyBudgetExceeded, got %v", decBudget)
	}
}

func TestAuditEmitterAndBuilders(t *testing.T) {
	emitter := NewMemoryAuditEmitter()

	agent := &AgentIdentity{
		AgentID:   "agt_bot_01",
		TenantID:  "ten_corp",
		ProjectID: "prj_analytics",
		Status:    AgentStatusActive,
	}

	correlation := CorrelationContext{
		RequestID: "req_test_123",
		IntentID:  "pi_test_456",
	}

	declared := &DeclaredContext{
		SessionID: "sess_user_789",
		ToolName:  "calculator",
	}

	// Emit Policy Decision Event
	decEvent := BuildPolicyDecisionEvent(
		agent,
		PolicyDecision{Allowed: true, ReasonCode: CodeAllow, Reason: "ok"},
		"rou_chat",
		correlation,
		"127.0.0.1",
		"TestAgent/1.0",
		declared,
	)
	emitter.Emit(decEvent)

	// Emit Request Event
	reqEvent := BuildRequestEvent(
		agent,
		correlation,
		"127.0.0.1",
		"TestAgent/1.0",
		"rou_chat",
		200,
		45,
		"sha256_dummy_hash",
		declared,
	)
	emitter.Emit(reqEvent)

	// Emit Spend Event
	spendEvent := BuildSpendEvent(
		agent,
		correlation,
		"127.0.0.1",
		"TestAgent/1.0",
		1500,
		"USDC",
		"wallet",
		"capture",
		declared,
	)
	emitter.Emit(spendEvent)

	events := emitter.Events()
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}

	policyEvents := emitter.EventsByType(EventTypeAgentPolicyDecision)
	if len(policyEvents) != 1 {
		t.Fatalf("expected 1 policy event, got %d", len(policyEvents))
	}
	if policyEvents[0].Data["decision"] != "allow" {
		t.Fatalf("expected allow decision in event data")
	}

	agentEvents := emitter.EventsByAgent("agt_bot_01")
	if len(agentEvents) != 3 {
		t.Fatalf("expected 3 events for agent agt_bot_01, got %d", len(agentEvents))
	}
}

// Ensure interface satisfaction
var _ AuditEmitter = (*MemoryAuditEmitter)(nil)
var _ = (*rcu.RouteConfig)(nil)
