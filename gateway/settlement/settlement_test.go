package settlement

import (
	"context"
	"testing"
	"time"

	"github.com/open-agentpay/agent-core-sdk/gateway/wallet"
)

func TestQuotaSettlementAdapterLifecycle(t *testing.T) {
	ctx := context.Background()
	memWallet := wallet.NewMemoryService()

	walletID := "wlt_test_quota_1"
	tenantID := "tenant_finops_1"
	apiKey := "apk_live_key_999"

	w := &wallet.Wallet{
		WalletID:       walletID,
		TenantID:       tenantID,
		Asset:          "QUOTA",
		Status:         wallet.StatusActive,
		Version:        1,
		AvailableCache: 1000,
		HeldCache:      0,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
	memWallet.RegisterWallet(w)
	memWallet.RegisterAPIKey(apiKey, tenantID, "prj_default")

	adapter := NewQuotaSettlementAdapter(memWallet)
	if adapter.Name() != "quota-finops" || adapter.Mode() != "quota" {
		t.Fatalf("unexpected adapter metadata: %s %s", adapter.Name(), adapter.Mode())
	}

	// 1. Authorize 200 quota via API Key resolution
	authRes, err := adapter.Authorize(ctx, &AuthorizationRequest{
		APIKeyID:        apiKey,
		EstimatedAmount: 200,
		Unit:            UnitQuota,
	})
	if err != nil {
		t.Fatalf("authorize failed: %v", err)
	}
	if !authRes.Authorized || authRes.AuthorizationID == "" {
		t.Fatalf("expected authorized, got: %+v", authRes)
	}

	// 2. Settle 200 quota
	settleRes, err := adapter.Settle(ctx, &SettlementRequest{
		AuthorizationID: authRes.AuthorizationID,
		WalletID:        walletID,
		ActualAmount:    200,
		Unit:            UnitQuota,
	})
	if err != nil {
		t.Fatalf("settle failed: %v", err)
	}
	if !settleRes.Success {
		t.Fatalf("expected settle success, got: %+v", settleRes)
	}

	// 3. Test Release on failure
	authRes2, err := adapter.Authorize(ctx, &AuthorizationRequest{
		WalletID:        walletID,
		EstimatedAmount: 300,
		Unit:            UnitQuota,
	})
	if err != nil || !authRes2.Authorized {
		t.Fatalf("authorize 2 failed: %v", err)
	}

	err = adapter.Release(ctx, authRes2.AuthorizationID)
	if err != nil {
		t.Fatalf("release failed: %v", err)
	}

	// Balance check: started with 1000, settled 200, released 300 -> available should be 800 with 0 held
	updatedWallet, _ := memWallet.GetWallet(ctx, walletID)
	if updatedWallet.AvailableCache != 800 || updatedWallet.HeldCache != 0 {
		t.Errorf("expected 800 available and 0 held, got avail=%d held=%d", updatedWallet.AvailableCache, updatedWallet.HeldCache)
	}
}
