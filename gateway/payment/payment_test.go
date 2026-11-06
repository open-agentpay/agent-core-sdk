package payment

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCompositeDisplayStatusDerivations(t *testing.T) {
	tests := []struct {
		name              string
		intentStatus      string
		settlementStatus  string
		fulfillmentStatus string
		expectedDisplay   string
		expectedRecovery  bool
	}{
		{
			name:              "Wallet Hold Acquired Calling Upstream",
			intentStatus:      IntentStatusAuthorized,
			settlementStatus:  SettlementStatusHeld,
			fulfillmentStatus: FulfillmentStatusInProgress,
			expectedDisplay:   DisplayWalletHoldProcessing,
			expectedRecovery:  false,
		},
		{
			name:              "Onchain Broadcast In Flight",
			intentStatus:      IntentStatusAuthorized,
			settlementStatus:  SettlementStatusSubmitted,
			fulfillmentStatus: FulfillmentStatusNotStarted,
			expectedDisplay:   DisplaySettlementInProgress,
			expectedRecovery:  false,
		},
		{
			name:              "Payment Confirmed Upstream In Progress",
			intentStatus:      IntentStatusAuthorized,
			settlementStatus:  SettlementStatusConfirmed,
			fulfillmentStatus: FulfillmentStatusInProgress,
			expectedDisplay:   DisplayFulfillmentInProgress,
			expectedRecovery:  false,
		},
		{
			name:              "Completed Happy Path",
			intentStatus:      IntentStatusCompleted,
			settlementStatus:  SettlementStatusConfirmed,
			fulfillmentStatus: FulfillmentStatusSucceeded,
			expectedDisplay:   DisplayCompleted,
			expectedRecovery:  false,
		},
		{
			name:              "Onchain Confirmed But Upstream 4xx",
			intentStatus:      IntentStatusFailed,
			settlementStatus:  SettlementStatusConfirmed,
			fulfillmentStatus: FulfillmentStatusFailed,
			expectedDisplay:   DisplaySettledFulfillmentRefundRequired,
			expectedRecovery:  true,
		},
		{
			name:              "Onchain Confirmed But Upstream 5xx/Timeout",
			intentStatus:      IntentStatusNeedsReview,
			settlementStatus:  SettlementStatusConfirmed,
			fulfillmentStatus: FulfillmentStatusUnknown,
			expectedDisplay:   DisplayRecoveryRequired,
			expectedRecovery:  true,
		},
		{
			name:              "Wallet Released Unbilled on 4xx",
			intentStatus:      IntentStatusFailed,
			settlementStatus:  SettlementStatusReleased,
			fulfillmentStatus: FulfillmentStatusFailed,
			expectedDisplay:   DisplayReleasedUnbilled,
			expectedRecovery:  false,
		},
		{
			name:              "Payment Failed Before Dispatch",
			intentStatus:      IntentStatusFailed,
			settlementStatus:  SettlementStatusFailed,
			fulfillmentStatus: FulfillmentStatusNotStarted,
			expectedDisplay:   DisplayPaymentFailed,
			expectedRecovery:  false,
		},
		{
			name:              "Wallet Held But Upstream 5xx Unknown",
			intentStatus:      IntentStatusAuthorized,
			settlementStatus:  SettlementStatusHeld,
			fulfillmentStatus: FulfillmentStatusUnknown,
			expectedDisplay:   DisplayRecoveryRequired,
			expectedRecovery:  true,
		},
		{
			name:              "Policy Rejected",
			intentStatus:      IntentStatusRejected,
			settlementStatus:  SettlementStatusNotStarted,
			fulfillmentStatus: FulfillmentStatusNotStarted,
			expectedDisplay:   DisplayRejected,
			expectedRecovery:  false,
		},
		{
			name:              "Challenge Expired",
			intentStatus:      IntentStatusExpired,
			settlementStatus:  SettlementStatusNotStarted,
			fulfillmentStatus: FulfillmentStatusNotStarted,
			expectedDisplay:   DisplayExpired,
			expectedRecovery:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			display, _, isRecovery := DeriveCompositeDisplayStatus(tt.intentStatus, tt.settlementStatus, tt.fulfillmentStatus)
			if display != tt.expectedDisplay {
				t.Fatalf("expected display %s, got %s", tt.expectedDisplay, display)
			}
			if isRecovery != tt.expectedRecovery {
				t.Fatalf("expected isRecovery=%v, got %v", tt.expectedRecovery, isRecovery)
			}
		})
	}
}

func TestMemoryServiceCRUDAndCorrelation(t *testing.T) {
	ctx := context.Background()
	svc := NewMemoryService()

	intent := &PaymentIntent{
		IntentID:        "pi_req_test_001",
		TenantID:        "ten_alpha",
		ProjectID:       "prj_alpha",
		AgentID:         "agt_007",
		RouteID:         "rte_weather",
		RequestID:       "req_test_001",
		IdempotencyKey:  "idem_001",
		PaymentMethod:   "wallet",
		AmountBaseUnits: 50000,
		Asset:           "USDC",
		Status:          IntentStatusAuthorized,
		ConfigVersionID: "ver_001",
	}

	if err := svc.CreateIntent(ctx, intent); err != nil {
		t.Fatalf("failed to create intent: %v", err)
	}

	settlement := &SettlementRecord{
		SettlementID:    "stl_hld_001",
		IntentID:        "pi_req_test_001",
		PaymentMethod:   "wallet",
		AmountBaseUnits: 50000,
		Status:          SettlementStatusHeld,
	}
	if err := svc.RecordSettlement(ctx, settlement); err != nil {
		t.Fatalf("failed to record settlement: %v", err)
	}

	fulfillment := &FulfillmentRecord{
		FulfillmentID:  "ful_req_test_001",
		IntentID:       "pi_req_test_001",
		UpstreamURL:    "http://upstream/weather",
		UpstreamStatus: 0,
		Status:         FulfillmentStatusInProgress,
	}
	if err := svc.RecordFulfillment(ctx, fulfillment); err != nil {
		t.Fatalf("failed to record fulfillment: %v", err)
	}

	hold := &WalletHoldAssociation{
		HoldID:    "hld_001",
		WalletID:  "wal_alpha",
		Amount:    50000,
		Status:    "held",
		ExpiresAt: time.Now().Add(120 * time.Second),
	}
	if err := svc.LinkWalletAssociation(ctx, "pi_req_test_001", hold, nil); err != nil {
		t.Fatalf("failed to link hold: %v", err)
	}

	// 1. Initial State Check: WALLET_HOLD_PROCESSING
	audit1, err := svc.GetPaymentAudit(ctx, "ten_alpha", "pi_req_test_001")
	if err != nil {
		t.Fatalf("failed to get audit record: %v", err)
	}
	if audit1.DisplayStatus != DisplayWalletHoldProcessing {
		t.Fatalf("expected display status %s, got %s", DisplayWalletHoldProcessing, audit1.DisplayStatus)
	}
	if audit1.Hold == nil || audit1.Hold.HoldID != "hld_001" {
		t.Fatalf("missing or wrong hold association: %+v", audit1.Hold)
	}

	// 2. Lookup by Request ID
	auditByReq, err := svc.GetPaymentAuditByRequestID(ctx, "ten_alpha", "req_test_001")
	if err != nil || auditByReq.IntentID != "pi_req_test_001" {
		t.Fatalf("failed to lookup by requestID: %v, got %+v", err, auditByReq)
	}

	// 3. Complete Upstream & Capture
	if err := svc.UpdateFulfillment(ctx, "ful_req_test_001", FulfillmentStatusSucceeded, 200, 45, "hash123"); err != nil {
		t.Fatalf("failed to update fulfillment: %v", err)
	}
	if err := svc.UpdateSettlementStatus(ctx, "stl_hld_001", SettlementStatusConfirmed, "", nil, ""); err != nil {
		t.Fatalf("failed to update settlement: %v", err)
	}
	if err := svc.UpdateIntentStatus(ctx, "pi_req_test_001", IntentStatusCompleted); err != nil {
		t.Fatalf("failed to update intent: %v", err)
	}

	ledger := &LedgerAssociation{
		EntryID:   "led_001",
		WalletID:  "wal_alpha",
		Type:      "capture",
		Amount:    -50000,
		CreatedAt: time.Now(),
	}
	if err := svc.LinkWalletAssociation(ctx, "pi_req_test_001", nil, ledger); err != nil {
		t.Fatalf("failed to link ledger: %v", err)
	}

	// 4. Completed State Check
	audit2, err := svc.GetPaymentAudit(ctx, "ten_alpha", "pi_req_test_001")
	if err != nil {
		t.Fatalf("failed to get updated audit: %v", err)
	}
	if audit2.DisplayStatus != DisplayCompleted {
		t.Fatalf("expected display status %s, got %s", DisplayCompleted, audit2.DisplayStatus)
	}
	if audit2.Ledger == nil || audit2.Ledger.EntryID != "led_001" {
		t.Fatalf("missing ledger entry: %+v", audit2.Ledger)
	}
	if audit2.Fulfillment.UpstreamStatus != 200 || audit2.Fulfillment.LatencyMs != 45 {
		t.Fatalf("wrong fulfillment details: %+v", audit2.Fulfillment)
	}

	// 5. Tenant Boundary Check
	_, err = svc.GetPaymentAudit(ctx, "ten_beta", "pi_req_test_001")
	if !errors.Is(err, ErrTenantMismatch) {
		t.Fatalf("expected ErrTenantMismatch when querying across tenants, got: %v", err)
	}

	// 6. List and Filtering
	list, total, err := svc.ListPaymentAudits(ctx, PaymentAuditFilter{
		TenantID:      "ten_alpha",
		DisplayStatus: DisplayCompleted,
	})
	if err != nil || total != 1 || len(list) != 1 {
		t.Fatalf("list failed: total=%d, len=%d, err=%v", total, len(list), err)
	}
}
