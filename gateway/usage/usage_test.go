package usage

import (
	"context"
	"testing"
	"time"
)

func TestMemoryService_RequestAndUsageLifecycle(t *testing.T) {
	svc := NewMemoryService()
	ctx := context.Background()

	now := time.Now()
	rec1 := &RequestRecord{
		RequestID:     "req_01",
		TenantID:      "ten_01",
		ProjectID:     "prj_01",
		AgentID:       "agt_01",
		RouteID:       "rte_01",
		ConfigVersion: "ver_01",
		ClientIP:      "127.0.0.1",
		HTTPMethod:    "GET",
		RequestPath:   "/api/v1/market-data",
		StatusCode:    200,
		DurationMs:    45,
		IsReplay:      false,
		IntentID:      "pi_01",
		CreatedAt:     now.Add(-2 * time.Minute),
	}

	rec2 := &RequestRecord{
		RequestID:     "req_02",
		TenantID:      "ten_01",
		ProjectID:     "prj_01",
		AgentID:       "agt_01",
		RouteID:       "rte_01",
		ConfigVersion: "ver_01",
		ClientIP:      "127.0.0.1",
		HTTPMethod:    "GET",
		RequestPath:   "/api/v1/market-data",
		StatusCode:    200,
		DurationMs:    2,
		IsReplay:      true, // replay hit
		IntentID:      "pi_01",
		CreatedAt:     now.Add(-1 * time.Minute),
	}

	recFail := &RequestRecord{
		RequestID:     "req_03",
		TenantID:      "ten_02", // different tenant
		ProjectID:     "prj_02",
		AgentID:       "agt_02",
		RouteID:       "rte_02",
		ClientIP:      "192.168.1.1",
		HTTPMethod:    "POST",
		RequestPath:   "/api/v1/trade",
		StatusCode:    403,
		DurationMs:    12,
		ErrorCode:     "ERR_AGENT_SUSPENDED",
		IsReplay:      false,
		CreatedAt:     now,
	}

	if err := svc.RecordRequest(ctx, rec1); err != nil {
		t.Fatalf("failed to record req1: %v", err)
	}
	if err := svc.RecordRequest(ctx, rec2); err != nil {
		t.Fatalf("failed to record req2: %v", err)
	}
	if err := svc.RecordRequest(ctx, recFail); err != nil {
		t.Fatalf("failed to record recFail: %v", err)
	}

	// 1. List Request Records for ten_01
	recs, total, err := svc.ListRequestRecords(ctx, RequestFilter{TenantID: "ten_01"})
	if err != nil {
		t.Fatalf("failed to list records: %v", err)
	}
	if total != 2 {
		t.Fatalf("expected 2 records for ten_01, got %d", total)
	}
	if len(recs) != 2 {
		t.Fatalf("expected 2 returned records, got %d", len(recs))
	}
	// Verify descending sort by CreatedAt (rec2 is newer than rec1)
	if recs[0].RequestID != "req_02" || recs[1].RequestID != "req_01" {
		t.Fatalf("expected rec_02 first, then rec_01, got %s, %s", recs[0].RequestID, recs[1].RequestID)
	}

	// 2. Filter by IsReplay
	isReplay := true
	replays, replayTotal, err := svc.ListRequestRecords(ctx, RequestFilter{TenantID: "ten_01", IsReplay: &isReplay})
	if err != nil {
		t.Fatalf("failed to list replays: %v", err)
	}
	if replayTotal != 1 || replays[0].RequestID != "req_02" {
		t.Fatalf("expected 1 replay record 'req_02', got %d", replayTotal)
	}

	// 3. Multi-tenant Boundary Check
	_, err = svc.GetRequestRecord(ctx, "ten_01", "req_03")
	if err != ErrTenantMismatch {
		t.Fatalf("expected ErrTenantMismatch when querying req_03 with ten_01, got %v", err)
	}

	rec3, err := svc.GetRequestRecord(ctx, "ten_02", "req_03")
	if err != nil {
		t.Fatalf("failed to get req_03: %v", err)
	}
	if rec3.ErrorCode != "ERR_AGENT_SUSPENDED" {
		t.Fatalf("expected error code ERR_AGENT_SUSPENDED, got %s", rec3.ErrorCode)
	}

	// 4. Usage Events Recording and Querying
	use1 := &UsageEvent{
		EventID:         "use_01",
		TenantID:        "ten_01",
		ProjectID:       "prj_01",
		AgentID:         "agt_01",
		RouteID:         "rte_01",
		IntentID:        "pi_01",
		AmountBaseUnits: 50000,
		Asset:           "USDC",
		PaymentMethod:   "wallet",
		IsSuccess:       true,
		CreatedAt:       now.Add(-2 * time.Minute),
	}
	if err := svc.RecordUsage(ctx, use1); err != nil {
		t.Fatalf("failed to record usage: %v", err)
	}

	usages, uTotal, err := svc.ListUsageEvents(ctx, UsageFilter{TenantID: "ten_01"})
	if err != nil {
		t.Fatalf("failed to list usages: %v", err)
	}
	if uTotal != 1 || usages[0].EventID != "use_01" {
		t.Fatalf("expected 1 usage event 'use_01', got %d", uTotal)
	}

	// Tenant boundary for usage event
	_, err = svc.GetUsageEvent(ctx, "ten_02", "use_01")
	if err != ErrTenantMismatch {
		t.Fatalf("expected ErrTenantMismatch for usage event, got %v", err)
	}
}
