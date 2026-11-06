package wallet

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestWalletConcurrencyNonNegativeOverdraft verifies under high concurrency (100 goroutines)
// that available funds are strictly guarded, zero overdraft occurs, and ledger remains consistent.
func TestWalletConcurrencyNonNegativeOverdraft(t *testing.T) {
	ctx := context.Background()
	svc := NewMemoryService()

	walletID := "wlt_concurrent_overdraft_test"
	tenantID := "ten_concurrent_1"

	// Initial balance: 10,000 base units
	// 100 concurrent workers each attempting to hold 500 base units.
	// Exactly 20 workers must succeed; exactly 80 workers must fail with ErrInsufficientBalance.
	totalBalance := int64(10000)
	requestAmount := int64(500)
	concurrency := 100
	expectedSuccess := int64(totalBalance / requestAmount) // 20

	w := &Wallet{
		WalletID:       walletID,
		TenantID:       tenantID,
		Asset:          "USDC",
		Status:         StatusActive,
		Version:        1,
		AvailableCache: 0,
		HeldCache:      0,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
	svc.RegisterWallet(w)

	// Top up initial balance through ledger
	_ = svc.CreditTopUp(ctx, &TopUpOrder{
		TopUpID:  "top_init_concurrent",
		WalletID: walletID,
		TenantID: tenantID,
		Channel:  ChannelAdminGrant,
		Amount:   totalBalance,
		Asset:    "USDC",
	})

	var successCount int64
	var insufficientCount int64
	var errorCount int64

	var wg sync.WaitGroup
	wg.Add(concurrency)

	startBarrier := make(chan struct{})

	for i := 0; i < concurrency; i++ {
		workerID := i
		go func() {
			defer wg.Done()
			<-startBarrier // Synchronize starting instant for maximum contention

			intentID := fmt.Sprintf("pi_worker_%d", workerID)
			holdID, err := svc.HoldFunds(ctx, walletID, requestAmount, intentID)
			if err == nil {
				atomic.AddInt64(&successCount, 1)
				// Simulate immediate capture
				if capErr := svc.CaptureFunds(ctx, holdID); capErr != nil {
					atomic.AddInt64(&errorCount, 1)
				}
			} else if err == ErrInsufficientBalance {
				atomic.AddInt64(&insufficientCount, 1)
			} else {
				atomic.AddInt64(&errorCount, 1)
			}
		}()
	}

	// Release all workers simultaneously
	close(startBarrier)
	wg.Wait()

	if errorCount > 0 {
		t.Fatalf("unexpected unexpected errors during concurrent execution: %d", errorCount)
	}

	if successCount != expectedSuccess {
		t.Fatalf("expected exactly %d successful holds, got: %d", expectedSuccess, successCount)
	}

	if insufficientCount != int64(concurrency)-expectedSuccess {
		t.Fatalf("expected %d insufficient balance rejections, got: %d", int64(concurrency)-expectedSuccess, insufficientCount)
	}

	// Invariant checks on wallet state
	finalWallet, err := svc.GetWallet(ctx, walletID)
	if err != nil {
		t.Fatalf("failed to retrieve wallet: %v", err)
	}

	if finalWallet.AvailableCache < 0 {
		t.Fatalf("CRITICAL SECURITY VIOLATION: AvailableCache overdrafted below zero: %d", finalWallet.AvailableCache)
	}
	if finalWallet.HeldCache != 0 {
		t.Fatalf("expected HeldCache=0 after all captures completed, got: %d", finalWallet.HeldCache)
	}
	if finalWallet.AvailableCache != 0 {
		t.Fatalf("expected AvailableCache=0 after full exhaustion, got: %d", finalWallet.AvailableCache)
	}

	// Double-entry reconciliation check
	report, err := svc.ReconcileBalance(ctx, walletID)
	if err != nil {
		t.Fatalf("ReconcileBalance failed: %v", err)
	}
	if !report.IsBalanced {
		t.Fatalf("reconciliation reported unbalanced state: %+v", report)
	}
	if report.Discrepancy != 0 {
		t.Fatalf("expected discrepancy=0, got: %d", report.Discrepancy)
	}

	// Ledger must contain 1 top-up + 20 captures = 21 entries
	entries, err := svc.GetLedgerEntries(ctx, walletID)
	if err != nil {
		t.Fatalf("failed to get ledger entries: %v", err)
	}
	if len(entries) != int(expectedSuccess)+1 {
		t.Fatalf("expected %d ledger entries, got: %d", int(expectedSuccess)+1, len(entries))
	}
}
