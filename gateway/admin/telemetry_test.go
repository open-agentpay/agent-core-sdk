package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/open-agentpay/agent-core-sdk/gateway/usage"
)

func TestGetRouteTelemetryOverview(t *testing.T) {
	ctx := context.Background()
	svc := NewMemoryService(nil, nil)
	usageSvc := usage.NewMemoryService()
	svc.SetUsageService(usageSvc)

	tenantID := "ten_telemetry_test"

	// Register tenant and owner
	_, member, err := svc.CreateTenant(ctx, "Telemetry Test Tenant", tenantID, "owner@test.com")
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}
	actorID := member.MemberID

	// Create test routes
	r1, err := svc.CreateRoute(ctx, &Route{
		RouteID:     "rt_llm_v3",
		TenantID:    tenantID,
		Slug:        "deepseek-v3",
		Title:       "DeepSeek V3 Route",
		RouteType:   "llm",
		ModelName:   "deepseek-v3",
		PathPattern: "/models/deepseek-v3",
		Status:      RouteStatusActive,
		UpstreamURL: "https://api.deepseek.com",
	}, actorID)
	if err != nil {
		t.Fatalf("failed to create route 1: %v", err)
	}

	r2, err := svc.CreateRoute(ctx, &Route{
		RouteID:     "rt_api_weather",
		TenantID:    tenantID,
		Slug:        "weather-api",
		Title:       "Weather API",
		RouteType:   "api",
		PathPattern: "/api/weather",
		Status:      RouteStatusActive,
		UpstreamURL: "https://api.weather.com",
	}, actorID)
	if err != nil {
		t.Fatalf("failed to create route 2: %v", err)
	}

	// Record request records
	// 3 calls to r1 (2 success 100ms & 200ms, 1 fail 500ms)
	_ = usageSvc.RecordRequest(ctx, &usage.RequestRecord{
		RequestID:  "req_1",
		TenantID:   tenantID,
		RouteID:    r1.RouteID,
		StatusCode: 200,
		DurationMs: 100,
		CreatedAt:  time.Now(),
	})
	_ = usageSvc.RecordRequest(ctx, &usage.RequestRecord{
		RequestID:  "req_2",
		TenantID:   tenantID,
		RouteID:    r1.RouteID,
		StatusCode: 200,
		DurationMs: 200,
		CreatedAt:  time.Now(),
	})
	_ = usageSvc.RecordRequest(ctx, &usage.RequestRecord{
		RequestID:  "req_3",
		TenantID:   tenantID,
		RouteID:    r1.RouteID,
		StatusCode: 500,
		DurationMs: 300,
		CreatedAt:  time.Now(),
	})

	// 1 call to r2 (1 success 50ms)
	_ = usageSvc.RecordRequest(ctx, &usage.RequestRecord{
		RequestID:  "req_4",
		TenantID:   tenantID,
		RouteID:    r2.RouteID,
		StatusCode: 200,
		DurationMs: 50,
		CreatedAt:  time.Now(),
	})

	// Record usage events for tokens
	_ = usageSvc.RecordUsage(ctx, &usage.UsageEvent{
		EventID:          "use_1",
		TenantID:         tenantID,
		RouteID:          r1.RouteID,
		PromptTokens:     100,
		CompletionTokens: 250,
		TotalTokens:      350,
		AmountBaseUnits:  700,
		CreatedAt:        time.Now(),
	})
	_ = usageSvc.RecordUsage(ctx, &usage.UsageEvent{
		EventID:          "use_2",
		TenantID:         tenantID,
		RouteID:          r1.RouteID,
		PromptTokens:     50,
		CompletionTokens: 100,
		TotalTokens:      150,
		AmountBaseUnits:  300,
		CreatedAt:        time.Now(),
	})

	// Query telemetry
	resp, err := svc.GetRouteTelemetryOverview(ctx, tenantID, "24h", "", actorID)
	if err != nil {
		t.Fatalf("GetRouteTelemetryOverview failed: %v", err)
	}

	if resp.Summary.TotalCalls != 4 {
		t.Errorf("expected 4 total calls, got %d", resp.Summary.TotalCalls)
	}
	if resp.Summary.FailedCalls != 1 {
		t.Errorf("expected 1 failed call, got %d", resp.Summary.FailedCalls)
	}
	// 3 success out of 4 = 75.0%
	if resp.Summary.SuccessRate != 75.0 {
		t.Errorf("expected 75.0%% success rate, got %v", resp.Summary.SuccessRate)
	}
	// Total tokens: 350 + 150 = 500
	if resp.Summary.TotalTokens != 500 {
		t.Errorf("expected 500 total tokens, got %d", resp.Summary.TotalTokens)
	}
	if resp.Summary.PromptTokens != 150 {
		t.Errorf("expected 150 prompt tokens, got %d", resp.Summary.PromptTokens)
	}
	if resp.Summary.CompletionTokens != 350 {
		t.Errorf("expected 350 completion tokens, got %d", resp.Summary.CompletionTokens)
	}

	// Verify route breakdown
	if len(resp.Routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(resp.Routes))
	}
	// First route should be r1 because it has 3 calls
	if resp.Routes[0].RouteID != r1.RouteID {
		t.Errorf("expected top route to be %s, got %s", r1.RouteID, resp.Routes[0].RouteID)
	}
	if resp.Routes[0].TotalTokens != 500 {
		t.Errorf("expected route 1 total tokens 500, got %d", resp.Routes[0].TotalTokens)
	}
	if resp.Routes[0].Calls != 3 {
		t.Errorf("expected route 1 calls 3, got %d", resp.Routes[0].Calls)
	}
}

func TestRouteAnalyticsHandlerEndpoint(t *testing.T) {
	_, handler, _, tenantID, _, ownerToken, _ := setupRouteTest(t)

	req := httptest.NewRequest("GET", "/api/v1/tenants/"+tenantID+"/analytics/routes-overview?time_range=24h", nil)
	req.Header.Set("Authorization", "Bearer "+ownerToken)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 from analytics endpoint, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp RouteTelemetryOverviewResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode analytics response: %v", err)
	}

	if resp.TenantID != tenantID {
		t.Errorf("expected tenant ID %s, got %s", tenantID, resp.TenantID)
	}
	if resp.TimeRange != "24h" {
		t.Errorf("expected time range 24h, got %s", resp.TimeRange)
	}
}
