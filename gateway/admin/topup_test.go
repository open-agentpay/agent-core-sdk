package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/open-agentpay/agent-core-sdk/gateway/auth"
	"github.com/open-agentpay/agent-core-sdk/gateway/wallet"
)

func TestTopUpOrdersAndMockPayLifecycle(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := setupTestService()
	jwtMgr := auth.MustNewJWTManager("test-admin-secret-key-for-unit-testing-32b!", 24*time.Hour)
	handler := NewHandlerWithJWT(svc, jwtMgr)

	// Create tenant and owner
	tenant, owner, err := svc.CreateTenant(ctx, "Test TopUp Corp", "ten_topup", "owner@topup.com")
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	token, err := jwtMgr.GenerateToken(owner.MemberID, owner.Email, tenant.TenantID, string(owner.Role))
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	// 1. Create TopUp Order
	bodyJSON, _ := json.Marshal(map[string]interface{}{
		"amount_cents": 5000, // 50.00 CNY
		"channel":      "mock",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/ten_topup/topup-orders", bytes.NewReader(bodyJSON))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", w.Code, w.Body.String())
	}

	var createResp struct {
		TopUpOrder *wallet.TopUpOrder `json:"topup_order"`
		CodeURL    string             `json:"code_url"`
		ExpiresAt  int64              `json:"expires_at"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("failed to parse create response: %v", err)
	}
	if createResp.TopUpOrder == nil || createResp.TopUpOrder.Amount != 5000 {
		t.Fatalf("invalid topup order amount: %+v", createResp.TopUpOrder)
	}
	if createResp.TopUpOrder.Status != wallet.TopUpStatusPending {
		t.Errorf("expected pending status, got %s", createResp.TopUpOrder.Status)
	}
	if createResp.CodeURL == "" {
		t.Error("expected non-empty code_url")
	}

	topupID := createResp.TopUpOrder.TopUpID

	// 2. Query Pending Order
	queryReq := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/ten_topup/topup-orders/"+topupID, nil)
	queryReq.Header.Set("Authorization", "Bearer "+token)
	queryW := httptest.NewRecorder()
	handler.ServeHTTP(queryW, queryReq)

	if queryW.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", queryW.Code)
	}
	var queryResp struct {
		TopUpOrder *wallet.TopUpOrder `json:"topup_order"`
	}
	if err := json.Unmarshal(queryW.Body.Bytes(), &queryResp); err != nil {
		t.Fatalf("failed to parse query resp: %v", err)
	}
	if queryResp.TopUpOrder.Status != wallet.TopUpStatusPending {
		t.Errorf("expected pending, got %s", queryResp.TopUpOrder.Status)
	}

	// 3. Confirm Mock Pay
	confirmJSON, _ := json.Marshal(map[string]interface{}{
		"out_trade_no": topupID,
	})
	confirmReq := httptest.NewRequest(http.MethodPost, "/api/v1/public/mock-pay/confirm", bytes.NewReader(confirmJSON))
	confirmReq.Header.Set("Content-Type", "application/json")
	confirmW := httptest.NewRecorder()
	handler.ServeHTTP(confirmW, confirmReq)

	if confirmW.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on mock confirm, got %d: %s", confirmW.Code, confirmW.Body.String())
	}

	// 4. Verify Wallet Available Balance increased by 5000 cents
	wlt, err := svc.GetWallet(ctx, "ten_topup")
	if err != nil {
		t.Fatalf("failed to get wallet: %v", err)
	}
	if wlt.AvailableCache != 5000 {
		t.Errorf("expected available_cache 5000, got %d", wlt.AvailableCache)
	}

	// 5. Query order again: should be confirmed
	queryW2 := httptest.NewRecorder()
	handler.ServeHTTP(queryW2, queryReq)
	var queryResp2 struct {
		TopUpOrder *wallet.TopUpOrder `json:"topup_order"`
	}
	_ = json.Unmarshal(queryW2.Body.Bytes(), &queryResp2)
	if queryResp2.TopUpOrder.Status != wallet.TopUpStatusConfirmed {
		t.Errorf("expected confirmed status, got %s", queryResp2.TopUpOrder.Status)
	}

	// 6. Test Idempotency: re-confirming same order succeeds without double-crediting
	confirmReq2 := httptest.NewRequest(http.MethodPost, "/api/v1/public/mock-pay/confirm", bytes.NewReader(confirmJSON))
	confirmReq2.Header.Set("Content-Type", "application/json")
	confirmW2 := httptest.NewRecorder()
	handler.ServeHTTP(confirmW2, confirmReq2)
	if confirmW2.Code != http.StatusOK {
		t.Fatalf("expected 200 on idempotent confirm, got %d: %s", confirmW2.Code, confirmW2.Body.String())
	}
	wltAfter, _ := svc.GetWallet(ctx, "ten_topup")
	if wltAfter.AvailableCache != 5000 {
		t.Errorf("idempotent confirm should not double credit: expected 5000, got %d", wltAfter.AvailableCache)
	}
}

func TestTopUpArrearsAutoRecovery(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := setupTestService()
	jwtMgr := auth.MustNewJWTManager("test-admin-secret-key-for-unit-testing-32b!", 24*time.Hour)
	handler := NewHandlerWithJWT(svc, jwtMgr)

	tenant, owner, _ := svc.CreateTenant(ctx, "Arrears Tenant", "ten_arrears", "arr@topup.com")
	token, _ := jwtMgr.GenerateToken(owner.MemberID, owner.Email, tenant.TenantID, string(owner.Role))

	// Set wallet to frozen_arrears with -2000 cents (-20.00 CNY)
	wlt, _ := svc.GetWallet(ctx, "ten_arrears")
	_ = svc.walletSvc.AdjustBalance(ctx, wlt.WalletID, -2000, "arrears simulation", "idem_arr_1", "admin")
	_ = svc.walletSvc.SetWalletStatus(ctx, wlt.WalletID, wallet.StatusFrozenArrears)

	wltBefore, _ := svc.GetWallet(ctx, "ten_arrears")
	if wltBefore.Status != wallet.StatusFrozenArrears {
		t.Fatalf("expected frozen_arrears, got %s", wltBefore.Status)
	}

	// Create topup order for 5000 cents (50.00 CNY) -> after topup balance = +3000 -> should auto-unfreeze!
	bodyJSON, _ := json.Marshal(map[string]interface{}{
		"amount_cents": 5000,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/ten_arrears/topup-orders", bytes.NewReader(bodyJSON))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var createResp struct {
		TopUpOrder *wallet.TopUpOrder `json:"topup_order"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &createResp)

	// Confirm payment
	confirmJSON, _ := json.Marshal(map[string]interface{}{
		"out_trade_no": createResp.TopUpOrder.TopUpID,
	})
	confirmReq := httptest.NewRequest(http.MethodPost, "/api/v1/public/mock-pay/confirm", bytes.NewReader(confirmJSON))
	confirmW := httptest.NewRecorder()
	handler.ServeHTTP(confirmW, confirmReq)

	wltAfter, _ := svc.GetWallet(ctx, "ten_arrears")
	if wltAfter.AvailableCache != 3000 {
		t.Errorf("expected available balance 3000, got %d", wltAfter.AvailableCache)
	}
	if wltAfter.Status != wallet.StatusActive {
		t.Errorf("expected wallet status to be restored to active, got %s", wltAfter.Status)
	}
}
