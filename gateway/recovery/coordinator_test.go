package recovery

import (
	"context"
	"testing"
)

func TestRecoveryCoordinatorLifecycle(t *testing.T) {
	coord := NewRecoveryCoordinator()
	ctx := context.Background()

	settlementID := "stl_test_123"
	rec := &SettlementRecord{
		SettlementID:    settlementID,
		PaymentIntentID: "pi_test_123",
		PaymentMethod:   "onchain",
		Payer:           "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		Amount:          50000,
		Status:          SettlementSubmitted,
	}

	err := coord.RegisterSettlement(rec)
	if err != nil {
		t.Fatalf("failed to register settlement: %v", err)
	}

	// 1. Mark unknown on timeout
	err = coord.MarkUnknown(settlementID, "network timeout during submission query")
	if err != nil {
		t.Fatalf("failed to mark unknown: %v", err)
	}

	// 2. Blind retry must be strictly prohibited!
	err = coord.GuardAgainstBlindRetry(settlementID)
	if err != ErrBlindRetryProhibited {
		t.Fatalf("expected ErrBlindRetryProhibited, got %v", err)
	}

	// 3. Reconcile via verified status query -> Pending -> Confirmed
	updated, err := coord.ReconcileStatus(ctx, settlementID, true, false, false)
	if err != nil || updated.Status != SettlementPending {
		t.Fatalf("expected SettlementPending after seen on-chain, got %v (err: %v)", updated.Status, err)
	}

	confirmedRec, err := coord.ReconcileStatus(ctx, settlementID, true, true, false)
	if err != nil || confirmedRec.Status != SettlementConfirmed {
		t.Fatalf("expected SettlementConfirmed, got %v (err: %v)", confirmedRec.Status, err)
	}

	// 4. Terminal state immutability
	_, err = coord.ReconcileStatus(ctx, settlementID, false, false, true)
	if err != ErrTerminalState {
		t.Fatalf("expected ErrTerminalState when attempting to mutate confirmed state, got %v", err)
	}
}
