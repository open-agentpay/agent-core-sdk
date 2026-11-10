package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/open-agentpay/agent-core-sdk/gateway/auth"
	"github.com/open-agentpay/agent-core-sdk/gateway/wallet"
)

func TestTopUpOrdersLedgerLifecycle(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := setupTestService()

	tenant, owner, err := svc.CreateTenant(ctx, "Test TopUp Corp", "ten_topup", "owner@topup.com")
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// 1. Create TopUp Order
	order, err := svc.CreateTopUpOrder(ctx, tenant.TenantID, 5000, wallet.ChannelFiat, "pilot topup", owner.MemberID)
	if err != nil {
		t.Fatalf("failed to create topup order: %v", err)
	}
	if order.Amount != 5000 || order.Status != wallet.TopUpStatusPending {
		t.Fatalf("invalid order created: %+v", order)
	}

	// 2. Query Pending Order
	queried, err := svc.GetTopUpOrderByID(ctx, tenant.TenantID, order.TopUpID)
	if err != nil {
		t.Fatalf("failed to get order: %v", err)
	}
	if queried.Status != wallet.TopUpStatusPending {
		t.Errorf("expected pending status, got %s", queried.Status)
	}

	// 3. Confirm Payment
	confirmedOrder, err := svc.ConfirmTopUpPayment(ctx, order.TopUpID, "ext_tx_123", 5000, "Online TopUp Confirmed", time.Now())
	if err != nil {
		t.Fatalf("failed to confirm payment: %v", err)
	}
	if confirmedOrder.Status != wallet.TopUpStatusConfirmed {
		t.Errorf("expected confirmed status, got %s", confirmedOrder.Status)
	}

	// 4. Verify Wallet Available Balance increased by 5000
	wlt, err := svc.GetWallet(ctx, tenant.TenantID)
	if err != nil {
		t.Fatalf("failed to get wallet: %v", err)
	}
	if wlt.AvailableCache != 5000 {
		t.Errorf("expected available balance 5000, got %d", wlt.AvailableCache)
	}

	// 5. Test Idempotency: confirming again returns order and doesn't double-credit
	confirmedAgain, err := svc.ConfirmTopUpPayment(ctx, order.TopUpID, "ext_tx_123", 5000, "Online TopUp Confirmed", time.Now())
	if err != nil {
		t.Fatalf("idempotent confirm should not fail: %v", err)
	}
	if confirmedAgain.Status != wallet.TopUpStatusConfirmed {
		t.Errorf("expected confirmed status on re-confirm, got %s", confirmedAgain.Status)
	}
	wltAfter, _ := svc.GetWallet(ctx, tenant.TenantID)
	if wltAfter.AvailableCache != 5000 {
		t.Errorf("idempotent confirm should not double credit: expected 5000, got %d", wltAfter.AvailableCache)
	}
}

func TestTopUpArrearsAutoRecovery(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := setupTestService()

	tenant, owner, _ := svc.CreateTenant(ctx, "Arrears Tenant", "ten_arrears", "arr@topup.com")

	// Set wallet to frozen_arrears with -2000 cents (-20.00 CNY)
	wlt, _ := svc.GetWallet(ctx, tenant.TenantID)
	_ = svc.walletSvc.AdjustBalance(ctx, wlt.WalletID, -2000, "arrears simulation", "idem_arr_1", "admin")
	_ = svc.walletSvc.SetWalletStatus(ctx, wlt.WalletID, wallet.StatusFrozenArrears)

	wltBefore, _ := svc.GetWallet(ctx, tenant.TenantID)
	if wltBefore.Status != wallet.StatusFrozenArrears {
		t.Fatalf("expected frozen_arrears, got %s", wltBefore.Status)
	}

	// Create topup order for 5000 cents (50.00 CNY) -> after topup balance = +3000 -> should auto-unfreeze!
	order, err := svc.CreateTopUpOrder(ctx, tenant.TenantID, 5000, wallet.ChannelFiat, "repay arrears", owner.MemberID)
	if err != nil {
		t.Fatalf("failed to create order: %v", err)
	}

	// Confirm payment
	_, err = svc.ConfirmTopUpPayment(ctx, order.TopUpID, "ext_tx_arrears", 5000, "Debt Repayment", time.Now())
	if err != nil {
		t.Fatalf("failed to confirm topup: %v", err)
	}

	wltAfter, _ := svc.GetWallet(ctx, tenant.TenantID)
	if wltAfter.AvailableCache != 3000 {
		t.Errorf("expected available balance 3000, got %d", wltAfter.AvailableCache)
	}
	if wltAfter.Status != wallet.StatusActive {
		t.Errorf("expected wallet status to be restored to active, got %s", wltAfter.Status)
	}
}

func TestDisabledEndpoints(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := setupTestService()
	jwtMgr, err := auth.NewJWTManager("test_secret_for_jwt_testing_32bytes!!", 1*time.Hour)
	if err != nil {
		t.Fatalf("failed to create jwt manager: %v", err)
	}
	handler := NewHandlerWithJWT(svc, jwtMgr)

	tenant, owner, err := svc.CreateTenant(ctx, "Disabled Test Corp", "ten_dis", "owner@dis.com")
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}
	wlt, err := svc.GetWallet(ctx, tenant.TenantID)
	if err != nil {
		t.Fatalf("failed to get wallet: %v", err)
	}

	token, err := jwtMgr.GenerateToken(owner.MemberID, owner.Email, tenant.TenantID, string(owner.Role))
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	// 1. Test POST /api/v1/wallets/{wallet_id}/adjust is disabled
	reqAdjust := httptest.NewRequest(http.MethodPost, "/api/v1/wallets/"+wlt.WalletID+"/adjust", strings.NewReader(`{"amount":100,"reason":"test"}`))
	reqAdjust.Header.Set("Authorization", "Bearer "+token)
	recAdjust := httptest.NewRecorder()
	handler.ServeHTTP(recAdjust, reqAdjust)

	if recAdjust.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for disabled adjust endpoint, got %d: %s", recAdjust.Code, recAdjust.Body.String())
	}
	if !strings.Contains(recAdjust.Body.String(), "ERR_ENDPOINT_DISABLED") {
		t.Errorf("expected ERR_ENDPOINT_DISABLED in response, got: %s", recAdjust.Body.String())
	}

	// 2. Test POST /api/v1/tenants/{tenant_id}/wallets/admin-grant is disabled
	reqGrant := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/"+tenant.TenantID+"/wallets/admin-grant", strings.NewReader(`{"amount":100,"reason":"test"}`))
	reqGrant.Header.Set("Authorization", "Bearer "+token)
	recGrant := httptest.NewRecorder()
	handler.ServeHTTP(recGrant, reqGrant)

	if recGrant.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for disabled admin-grant endpoint, got %d: %s", recGrant.Code, recGrant.Body.String())
	}
	if !strings.Contains(recGrant.Body.String(), "ERR_ENDPOINT_DISABLED") {
		t.Errorf("expected ERR_ENDPOINT_DISABLED in response, got: %s", recGrant.Body.String())
	}
}
