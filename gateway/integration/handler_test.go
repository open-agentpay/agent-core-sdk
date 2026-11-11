package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/open-agentpay/agent-core-sdk/gateway/agent"
	"github.com/open-agentpay/agent-core-sdk/gateway/idempotency"
	"github.com/open-agentpay/agent-core-sdk/gateway/payment"
	"github.com/open-agentpay/agent-core-sdk/gateway/rcu"
	"github.com/open-agentpay/agent-core-sdk/gateway/wallet"
)

type mockSnapshotReader struct {
	snapshot *rcu.ConfigSnapshot
}

func (m *mockSnapshotReader) Current() *rcu.ConfigSnapshot {
	return m.snapshot
}

func setupTestIntegrationHandler(t *testing.T) (*Handler, *wallet.MemoryService, *payment.MemoryService, idempotency.Store) {
	memWallet := wallet.NewMemoryService()
	// Register test wallet and API key
	memWallet.RegisterWallet(&wallet.Wallet{
		WalletID:       "wlt_test_01",
		TenantID:       "ten_test_01",
		Asset:          "USDC",
		Status:         wallet.StatusActive,
		AvailableCache: 10_000_000, // 10 USDC (6 decimals)
		HeldCache:      0,
	})
	memWallet.RegisterAPIKey("apk_valid_key_123", "ten_test_01", "prj_test_01", "agent_research")

	memPayment := payment.NewMemoryService()
	idemStore := idempotency.NewMemoryStore(1 * time.Hour)

	snap := &rcu.ConfigSnapshot{
		Routes: []rcu.RouteConfig{
			{
				RouteID:        "route_weather",
				TenantID:       "ten_test_01",
				ProjectID:      "prj_test_01",
				PathPattern:    "/v1/weather",
				PriceBaseUnits: 200_000, // 0.20 USDC
				Asset:          "USDC",
				Network:        "base",
				Status:         "active",
			},
		},
	}
	reader := &mockSnapshotReader{snapshot: snap}

	handler := NewHandler(
		reader,
		nil,
		nil,
		nil,
		memPayment,
		memWallet,
		idemStore,
		nil,
	)

	return handler, memWallet, memPayment, idemStore
}

func TestIntegration_Unauthenticated(t *testing.T) {
	handler, _, _, _ := setupTestIntegrationHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/integrations/payments", bytes.NewBufferString("{}"))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	var errResp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if errResp.Error.Code != ErrCodeUnauthenticated {
		t.Fatalf("expected error code %s, got %s", ErrCodeUnauthenticated, errResp.Error.Code)
	}
}

func TestIntegration_GetAgentMe(t *testing.T) {
	handler, _, _, _ := setupTestIntegrationHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/integrations/agents/me", nil)
	req.Header.Set("Authorization", "Bearer apk_valid_key_123")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var me AgentIdentityResponse
	if err := json.Unmarshal(w.Body.Bytes(), &me); err != nil {
		t.Fatalf("failed to decode json: %v", err)
	}
	if me.TenantID != "ten_test_01" || me.WalletID != "wlt_test_01" {
		t.Fatalf("unexpected identity response: %+v", me)
	}
}

func TestIntegration_CreatePayment_SuccessAndIdempotency(t *testing.T) {
	handler, memWallet, memPayment, _ := setupTestIntegrationHandler(t)

	payReq := PaymentRequest{
		Resource: ResourceContext{
			ResourceID: "route_weather",
		},
		Context: AgentContext{
			AgentID:   "agent_research",
			Framework: "langchain",
		},
		IdempotencyKey: "idem_key_001",
	}
	bodyBytes, _ := json.Marshal(payReq)

	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/integrations/payments", bytes.NewReader(bodyBytes))
	req1.Header.Set("Authorization", "Bearer apk_valid_key_123")
	w1 := httptest.NewRecorder()

	handler.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w1.Code, w1.Body.String())
	}

	var res1 PaymentResultResponse
	if err := json.Unmarshal(w1.Body.Bytes(), &res1); err != nil {
		t.Fatalf("failed to unmarshal payment result: %v", err)
	}

	if res1.Decision != "ALLOW" || res1.PaymentStatus != "AUTHORIZED" || res1.SettlementStatus != "HELD" || res1.FulfillmentStatus != "NOT_STARTED" {
		t.Fatalf("unexpected statuses in result: %+v", res1)
	}
	if res1.Amount != "0.2" {
		t.Fatalf("expected amount 0.2, got %s", res1.Amount)
	}

	// Verify wallet hold occurred
	acct, _ := memWallet.GetWalletByAPIKey(context.Background(), "apk_valid_key_123")
	if acct.HeldBalance != 200_000 || acct.AvailableBalance != 9_800_000 {
		t.Fatalf("wallet balances unexpected: available=%d held=%d", acct.AvailableBalance, acct.HeldBalance)
	}

	// Verify PaymentIntent recorded
	intent, err := memPayment.GetIntent(context.Background(), res1.PaymentIntentID)
	if err != nil || intent == nil {
		t.Fatalf("expected intent %s in payment service", res1.PaymentIntentID)
	}

	// Test Idempotent Replay with exact same request
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/integrations/payments", bytes.NewReader(bodyBytes))
	req2.Header.Set("Authorization", "Bearer apk_valid_key_123")
	w2 := httptest.NewRecorder()

	handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200 on replay, got %d", w2.Code)
	}

	var res2 PaymentResultResponse
	_ = json.Unmarshal(w2.Body.Bytes(), &res2)
	if res2.PaymentIntentID != res1.PaymentIntentID {
		t.Fatalf("expected replay to return original payment intent %s, got %s", res1.PaymentIntentID, res2.PaymentIntentID)
	}

	// Test Query GetPayment
	reqQuery := httptest.NewRequest(http.MethodGet, "/api/v1/integrations/payments/"+res1.PaymentIntentID, nil)
	reqQuery.Header.Set("Authorization", "Bearer apk_valid_key_123")
	wQuery := httptest.NewRecorder()

	handler.ServeHTTP(wQuery, reqQuery)
	if wQuery.Code != http.StatusOK {
		t.Fatalf("expected 200 for get payment, got %d: %s", wQuery.Code, wQuery.Body.String())
	}

	var queryRes PaymentResultResponse
	_ = json.Unmarshal(wQuery.Body.Bytes(), &queryRes)
	if queryRes.PaymentIntentID != res1.PaymentIntentID || queryRes.SettlementStatus != "HELD" {
		t.Fatalf("unexpected query result: %+v", queryRes)
	}
}

func TestIntegration_InsufficientBalance(t *testing.T) {
	handler, memWallet, _, _ := setupTestIntegrationHandler(t)

	// Set balance to almost zero by registering wallet with small balance
	memWallet.RegisterWallet(&wallet.Wallet{
		WalletID:       "wlt_test_01",
		TenantID:       "ten_test_01",
		Asset:          "USDC",
		Status:         wallet.StatusActive,
		AvailableCache: 100, // 0.0001 USDC
		HeldCache:      0,
	})

	payReq := PaymentRequest{
		Resource: ResourceContext{
			ResourceID: "route_weather",
		},
		IdempotencyKey: "idem_key_poor",
	}
	bodyBytes, _ := json.Marshal(payReq)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/integrations/payments", bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer apk_valid_key_123")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}

	var errResp ErrorResponse
	_ = json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error.Code != ErrCodeBudgetExceeded {
		t.Fatalf("expected %s, got %s", ErrCodeBudgetExceeded, errResp.Error.Code)
	}
}

func TestIntegration_PolicyEvaluation_DryRun(t *testing.T) {
	handler, _, _, _ := setupTestIntegrationHandler(t)

	// Inject custom policy evaluator that allows
	handler.evaluator = agent.EvaluatorFunc(func(ctx context.Context, req *agent.PolicyRequest) agent.PolicyDecision {
		if req.RouteID == "route_weather" {
			return agent.PolicyDecision{Allowed: true, ReasonCode: "ALLOW"}
		}
		return agent.PolicyDecision{Allowed: false, ReasonCode: "ERR_POLICY_ROUTE_BLOCKED", Reason: "route blocked"}
	})

	payReq := PaymentRequest{
		Resource: ResourceContext{
			ResourceID: "route_weather",
		},
		IdempotencyKey: "eval_001",
	}
	bodyBytes, _ := json.Marshal(payReq)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/integrations/policies/evaluate", bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer apk_valid_key_123")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var dec PolicyDecisionResponse
	_ = json.Unmarshal(w.Body.Bytes(), &dec)
	if dec.Decision != "ALLOW" {
		t.Fatalf("expected decision ALLOW, got %s", dec.Decision)
	}
}
