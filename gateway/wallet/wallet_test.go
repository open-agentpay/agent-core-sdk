package wallet

import (
	"context"
	"testing"
	"time"
)

func setupTestMemoryService() (*MemoryService, string, string, string) {
	svc := NewMemoryService()
	walletID := "wlt_test_tenant_1"
	tenantID := "ten_test_1"
	apiKey := "apk_live_secret_key_123"

	w := &Wallet{
		WalletID:       walletID,
		TenantID:       tenantID,
		Asset:          "USDC",
		Status:         StatusActive,
		Version:        1,
		AvailableCache: 1000000, // 1 USDC = 1,000,000 base units
		HeldCache:      0,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
	svc.RegisterWallet(w)
	svc.RegisterAPIKey(apiKey, tenantID, "prj_default")

	return svc, walletID, tenantID, apiKey
}

func TestWalletLifecycle(t *testing.T) {
	ctx := context.Background()
	svc, walletID, _, apiKey := setupTestMemoryService()

	// 1. Resolve wallet by API Key
	acct, err := svc.GetWalletByAPIKey(ctx, apiKey)
	if err != nil {
		t.Fatalf("expected valid API key resolution, got: %v", err)
	}
	if acct.WalletID != walletID || acct.AvailableBalance != 1000000 {
		t.Fatalf("unexpected account details: %+v", acct)
	}

	// 2. Hold 200,000 base units
	holdID, err := svc.HoldFunds(ctx, walletID, 200000, "pi_req_101")
	if err != nil {
		t.Fatalf("HoldFunds failed: %v", err)
	}
	if holdID == "" {
		t.Fatal("expected non-empty holdID")
	}

	w, _ := svc.GetWallet(ctx, walletID)
	if w.AvailableCache != 800000 || w.HeldCache != 200000 {
		t.Fatalf("expected available=800000, held=200000; got available=%d, held=%d", w.AvailableCache, w.HeldCache)
	}

	// 3. Capture 200,000 base units
	if err := svc.CaptureFunds(ctx, holdID); err != nil {
		t.Fatalf("CaptureFunds failed: %v", err)
	}

	w, _ = svc.GetWallet(ctx, walletID)
	if w.AvailableCache != 800000 || w.HeldCache != 0 {
		t.Fatalf("expected available=800000, held=0 after capture; got available=%d, held=%d", w.AvailableCache, w.HeldCache)
	}

	// 4. Verify Immutable Ledger Entry
	entries, err := svc.GetLedgerEntries(ctx, walletID)
	if err != nil {
		t.Fatalf("GetLedgerEntries failed: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 ledger entry, got %d", len(entries))
	}
	if entries[0].Type != LedgerTypeCapture || entries[0].Amount != -200000 {
		t.Fatalf("unexpected ledger entry: %+v", entries[0])
	}

	// 5. Idempotent Capture (double capture should be safe no-op)
	if err := svc.CaptureFunds(ctx, holdID); err != nil {
		t.Fatalf("expected idempotent capture to succeed, got: %v", err)
	}
	entries, _ = svc.GetLedgerEntries(ctx, walletID)
	if len(entries) != 1 {
		t.Fatalf("idempotent capture created duplicate ledger entry: %d", len(entries))
	}

	// 6. Hold 300,000 base units and Release
	holdID2, err := svc.HoldFunds(ctx, walletID, 300000, "pi_req_102")
	if err != nil {
		t.Fatalf("HoldFunds 2 failed: %v", err)
	}
	w, _ = svc.GetWallet(ctx, walletID)
	if w.AvailableCache != 500000 || w.HeldCache != 300000 {
		t.Fatalf("expected available=500000, held=300000; got available=%d, held=%d", w.AvailableCache, w.HeldCache)
	}

	if err := svc.ReleaseFunds(ctx, holdID2); err != nil {
		t.Fatalf("ReleaseFunds failed: %v", err)
	}
	w, _ = svc.GetWallet(ctx, walletID)
	if w.AvailableCache != 800000 || w.HeldCache != 0 {
		t.Fatalf("expected available=800000, held=0 after release; got available=%d, held=%d", w.AvailableCache, w.HeldCache)
	}

	// 7. Idempotent Release
	if err := svc.ReleaseFunds(ctx, holdID2); err != nil {
		t.Fatalf("expected idempotent release to succeed, got: %v", err)
	}
}

func TestWalletSecurityInvariants(t *testing.T) {
	ctx := context.Background()
	svc, walletID, tenantID, _ := setupTestMemoryService()

	// W5: Non-negative Available Invariant (Insufficient Balance)
	_, err := svc.HoldFunds(ctx, walletID, 2000000, "pi_overdraft")
	if err != ErrInsufficientBalance {
		t.Fatalf("expected ErrInsufficientBalance, got: %v", err)
	}
	w, _ := svc.GetWallet(ctx, walletID)
	if w.AvailableCache != 1000000 || w.HeldCache != 0 {
		t.Fatalf("balance corrupted after rejected overdraft: available=%d, held=%d", w.AvailableCache, w.HeldCache)
	}

	// W6: Administrative Frozen Guard
	wFrozen := &Wallet{
		WalletID:       "wlt_frozen_admin",
		TenantID:       "ten_frozen_admin",
		Asset:          "USDC",
		Status:         StatusFrozen,
		Version:        1,
		AvailableCache: 500000,
		HeldCache:      0,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
	svc.RegisterWallet(wFrozen)
	_, err = svc.HoldFunds(ctx, "wlt_frozen_admin", 100, "pi_frozen")
	if err != ErrWalletFrozen {
		t.Fatalf("expected ErrWalletFrozen on frozen wallet, got: %v", err)
	}

	// W6: Arrears Frozen Guard & Top-up Recovery
	wArrears := &Wallet{
		WalletID:       "wlt_arrears",
		TenantID:       "ten_arrears",
		Asset:          "USDC",
		Status:         StatusFrozenArrears,
		Version:        1,
		AvailableCache: -50000,
		HeldCache:      0,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
	svc.RegisterWallet(wArrears)
	_, err = svc.HoldFunds(ctx, "wlt_arrears", 10, "pi_arrears")
	if err != ErrWalletFrozen {
		t.Fatalf("expected ErrWalletFrozen on arrears wallet, got: %v", err)
	}

	// Top up insufficient amount -> still arrears
	orderPartial := &TopUpOrder{
		TopUpID:   "top_1",
		WalletID:  "wlt_arrears",
		TenantID:  "ten_arrears",
		Channel:   ChannelAdminGrant,
		Amount:    20000,
		Asset:     "USDC",
		CreatedAt: time.Now(),
	}
	if err := svc.CreditTopUp(ctx, orderPartial); err != nil {
		t.Fatalf("CreditTopUp failed: %v", err)
	}
	wA, _ := svc.GetWallet(ctx, "wlt_arrears")
	if wA.Status != StatusFrozenArrears || wA.AvailableCache != -30000 {
		t.Fatalf("expected status=frozen_arrears, available=-30000; got status=%s, available=%d", wA.Status, wA.AvailableCache)
	}

	// Top up sufficient amount -> recovers to active
	orderFull := &TopUpOrder{
		TopUpID:   "top_2",
		WalletID:  "wlt_arrears",
		TenantID:  "ten_arrears",
		Channel:   ChannelFiat,
		Amount:    80000,
		Asset:     "USDC",
		CreatedAt: time.Now(),
	}
	if err := svc.CreditTopUp(ctx, orderFull); err != nil {
		t.Fatalf("CreditTopUp failed: %v", err)
	}
	wA, _ = svc.GetWallet(ctx, "wlt_arrears")
	if wA.Status != StatusActive || wA.AvailableCache != 50000 {
		t.Fatalf("expected status=active, available=50000 after clearing arrears; got status=%s, available=%d", wA.Status, wA.AvailableCache)
	}

	// Now holding funds on recovered wallet succeeds
	hld, err := svc.HoldFunds(ctx, "wlt_arrears", 10000, "pi_after_recovery")
	if err != nil || hld == "" {
		t.Fatalf("expected hold to succeed after clearing arrears, got: %v", err)
	}

	// Invalid API Key Guard
	_, err = svc.GetWalletByAPIKey(ctx, "apk_non_existent")
	if err != ErrAPIKeyInvalid {
		t.Fatalf("expected ErrAPIKeyInvalid, got: %v", err)
	}

	_ = tenantID
}

func TestWalletExpiryRecovery(t *testing.T) {
	ctx := context.Background()
	svc, walletID, _, _ := setupTestMemoryService()

	// Set short TTL
	svc.SetDefaultHoldTTL(10 * time.Millisecond)

	holdID, err := svc.HoldFunds(ctx, walletID, 250000, "pi_expired_test")
	if err != nil {
		t.Fatalf("HoldFunds failed: %v", err)
	}

	w, _ := svc.GetWallet(ctx, walletID)
	if w.AvailableCache != 750000 || w.HeldCache != 250000 {
		t.Fatalf("expected available=750000, held=250000; got %d, %d", w.AvailableCache, w.HeldCache)
	}

	// Wait for TTL expiration
	time.Sleep(20 * time.Millisecond)

	// Sweep expired holds
	releasedCount, err := svc.ReleaseExpiredHolds(ctx, time.Now())
	if err != nil {
		t.Fatalf("ReleaseExpiredHolds failed: %v", err)
	}
	if releasedCount != 1 {
		t.Fatalf("expected 1 hold released, got %d", releasedCount)
	}

	// Funds refunded to available balance
	w, _ = svc.GetWallet(ctx, walletID)
	if w.AvailableCache != 1000000 || w.HeldCache != 0 {
		t.Fatalf("expected funds refunded: available=1000000, held=0; got available=%d, held=%d", w.AvailableCache, w.HeldCache)
	}

	// Hold status must be expired
	if err := svc.CaptureFunds(ctx, holdID); err == nil {
		t.Fatal("expected CaptureFunds on expired hold to fail")
	}
}

func TestWalletDoubleEntryReconciliation(t *testing.T) {
	ctx := context.Background()
	svc := NewMemoryService()
	walletID := "wlt_recon_test"
	tenantID := "ten_recon_test"

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

	// 1. Initial TopUp of 1,000,000
	_ = svc.CreditTopUp(ctx, &TopUpOrder{
		TopUpID:  "top_init",
		WalletID: walletID,
		TenantID: tenantID,
		Channel:  ChannelAdminGrant,
		Amount:   1000000,
		Asset:    "USDC",
	})

	// 2. Perform various transactions:
	// - Hold 100,000 and Capture
	h1, _ := svc.HoldFunds(ctx, walletID, 100000, "pi_1")
	_ = svc.CaptureFunds(ctx, h1)

	// - Hold 200,000 and Release
	h2, _ := svc.HoldFunds(ctx, walletID, 200000, "pi_2")
	_ = svc.ReleaseFunds(ctx, h2)

	// - Hold 150,000 and leave in HELD
	_, _ = svc.HoldFunds(ctx, walletID, 150000, "pi_3")

	// 3. Run reconciliation check
	report, err := svc.ReconcileBalance(ctx, walletID)
	if err != nil {
		t.Fatalf("ReconcileBalance failed: %v", err)
	}

	if !report.IsBalanced {
		t.Fatalf("expected balanced ledger report, got: %+v", report)
	}
	if report.Discrepancy != 0 {
		t.Fatalf("expected discrepancy=0, got %d", report.Discrepancy)
	}
	if report.SumActiveHolds != 150000 || report.HeldCache != 150000 {
		t.Fatalf("active holds mismatch: %+v", report)
	}
	if report.TotalInWallet != 900000 { // 1,000,000 - 100,000 captured = 900,000 total in wallet
		t.Fatalf("expected total in wallet 900000, got %d", report.TotalInWallet)
	}
}
