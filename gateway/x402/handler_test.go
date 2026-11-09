package x402

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/open-agentpay/agent-core-sdk/gateway/metrics"
	"github.com/open-agentpay/agent-core-sdk/gateway/payment"
	"github.com/open-agentpay/agent-core-sdk/gateway/proxy"
	"github.com/open-agentpay/agent-core-sdk/gateway/rcu"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func setupTestProcessor(walletSvc WalletService, verifier PaymentVerifier, nonceStore NonceStore) (*PaymentProcessor, *metrics.Metrics) {
	m := metrics.New()
	mockTransport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewBufferString(`{"data":"upstream-response"}`)),
			Request:    r,
		}, nil
	})
	proxyHandler := proxy.NewHandler(m, mockTransport)
	processor := NewPaymentProcessor(verifier, nonceStore, walletSvc, proxyHandler, m)
	return processor, m
}

func TestUnauthenticatedIssues402Challenge(t *testing.T) {
	processor, m := setupTestProcessor(nil, nil, nil)
	route := &rcu.RouteConfig{
		RouteID:               "rou_market",
		PriceBaseUnits:        50000,
		Asset:                 "CNY",
		PayeeAddress:          "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		AllowedPaymentMethods: "both",
	}

	req := httptest.NewRequest("GET", "/v1/market-data", nil)
	w := httptest.NewRecorder()

	processor.HandleRequest(w, req, route, "req_001")

	// 1. Status must be 402 Payment Required
	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("expected status 402, got %d", w.Code)
	}

	// 2. Must contain PAYMENT-REQUIRED challenge header
	chHeader := w.Header().Get(HeaderPaymentRequired)
	if chHeader == "" {
		t.Fatalf("missing %s response header", HeaderPaymentRequired)
	}

	// 3. Challenge must decode cleanly
	ch, err := DecodeChallenge(chHeader)
	if err != nil {
		t.Fatalf("failed to decode challenge: %v", err)
	}
	if ch.Amount != "50000" || ch.AssetSymbol != "CNY" {
		t.Errorf("challenge content mismatch: %+v", ch)
	}

	// 4. Response body must match canonical error schema
	var errEnvelope ProtocolErrorEnvelope
	if err := json.Unmarshal(w.Body.Bytes(), &errEnvelope); err != nil {
		t.Fatalf("failed to parse json error envelope: %v", err)
	}
	if errEnvelope.Error.Code != ErrCodePaymentRequired {
		t.Errorf("expected error code %s, got %s", ErrCodePaymentRequired, errEnvelope.Error.Code)
	}
	if errEnvelope.Error.RequestID != "req_001" {
		t.Errorf("expected requestId req_001, got %s", errEnvelope.Error.RequestID)
	}

	// 5. Metrics updated
	if m.ChallengesIssuedTotal != 1 {
		t.Errorf("expected 1 challenge metric incremented, got %d", m.ChallengesIssuedTotal)
	}
}

func TestWalletPaymentSuccessAndAccounting(t *testing.T) {
	walletSvc := NewMemoryWalletService()
	walletSvc.RegisterWallet("apk_live_valid123", &WalletAccount{
		WalletID:         "wlt_tenant_01",
		TenantID:         "ten_01",
		Status:           "active",
		AvailableBalance: 1000000,
		HeldBalance:      0,
	})

	processor, m := setupTestProcessor(walletSvc, nil, nil)
	route := &rcu.RouteConfig{
		RouteID:               "rou_market",
		UpstreamURL:           "http://upstream.internal:8000",
		PriceBaseUnits:        50000,
		Asset:                 "CNY",
		AllowedPaymentMethods: "both",
	}

	req := httptest.NewRequest("GET", "/v1/market-data", nil)
	req.Header.Set("Authorization", "Bearer apk_live_valid123")
	w := httptest.NewRecorder()

	serveAuthorizedWalletRequest(t, processor, w, req, route, "req_002")

	// Must succeed and proxy through
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d, body: %s", w.Code, w.Body.String())
	}

	// Check wallet accounting: 50,000 deducted from available, held then captured
	wallet, _ := walletSvc.GetWalletByAPIKey(req.Context(), "apk_live_valid123")
	if wallet.AvailableBalance != 950000 {
		t.Errorf("expected available balance 950000, got %d", wallet.AvailableBalance)
	}
	if wallet.HeldBalance != 0 {
		t.Errorf("expected held balance 0 after capture, got %d", wallet.HeldBalance)
	}

	// Verify metrics
	if m.HoldsCreatedTotal != 1 || m.HoldsCapturedTotal != 1 || m.PaymentsVerifiedTotal != 1 {
		t.Errorf("metrics mismatch: holdsCreated=%d, holdsCaptured=%d, paymentsVerified=%d",
			m.HoldsCreatedTotal, m.HoldsCapturedTotal, m.PaymentsVerifiedTotal)
	}
}

func TestWalletInsufficientBalanceStrictNoDowngrade(t *testing.T) {
	walletSvc := NewMemoryWalletService()
	walletSvc.RegisterWallet("apk_live_poor", &WalletAccount{
		WalletID:         "wlt_tenant_02",
		TenantID:         "ten_02",
		Status:           "active",
		AvailableBalance: 20000, // less than route price of 50000
		HeldBalance:      0,
	})

	processor, m := setupTestProcessor(walletSvc, nil, nil)
	route := &rcu.RouteConfig{
		RouteID:               "rou_market",
		PriceBaseUnits:        50000,
		Asset:                 "CNY",
		AllowedPaymentMethods: "both",
	}

	req := httptest.NewRequest("GET", "/v1/market-data", nil)
	req.Header.Set("Authorization", "Bearer apk_live_poor")
	w := httptest.NewRecorder()

	serveAuthorizedWalletRequest(t, processor, w, req, route, "req_003")

	// STRICT W5 RULE: Must return 402 with ERR_WALLET_INSUFFICIENT_BALANCE
	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402, got %d", w.Code)
	}

	var errEnvelope ProtocolErrorEnvelope
	json.Unmarshal(w.Body.Bytes(), &errEnvelope)
	if errEnvelope.Error.Code != ErrCodeWalletInsufficientBalance {
		t.Errorf("expected %s, got %s", ErrCodeWalletInsufficientBalance, errEnvelope.Error.Code)
	}

	// Verify no challenge header is attached to prevent auto-downgrade confusion
	if w.Header().Get(HeaderPaymentRequired) != "" {
		t.Errorf("payment-required header should not be returned on wallet insufficient error")
	}

	if m.PaymentsFailedTotal != 1 {
		t.Errorf("expected payments failed metric to be 1")
	}
}

func TestWalletFrozenArrearsRejectedWith403(t *testing.T) {
	walletSvc := NewMemoryWalletService()
	walletSvc.RegisterWallet("apk_live_frozen", &WalletAccount{
		WalletID:         "wlt_tenant_03",
		TenantID:         "ten_03",
		Status:           "frozen_arrears",
		AvailableBalance: -10000,
		HeldBalance:      0,
	})

	processor, _ := setupTestProcessor(walletSvc, nil, nil)
	route := &rcu.RouteConfig{
		RouteID:               "rou_market",
		PriceBaseUnits:        50000,
		AllowedPaymentMethods: "both",
	}

	req := httptest.NewRequest("GET", "/v1/market-data", nil)
	req.Header.Set("Authorization", "Bearer apk_live_frozen")
	w := httptest.NewRecorder()

	serveAuthorizedWalletRequest(t, processor, w, req, route, "req_004")

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d", w.Code)
	}
	var errEnvelope ProtocolErrorEnvelope
	json.Unmarshal(w.Body.Bytes(), &errEnvelope)
	if errEnvelope.Error.Code != ErrCodeWalletFrozen {
		t.Errorf("expected %s, got %s", ErrCodeWalletFrozen, errEnvelope.Error.Code)
	}
}

func TestPaymentMethodMismatch(t *testing.T) {
	processor, _ := setupTestProcessor(nil, nil, nil)
	// Route allows wallet only
	route := &rcu.RouteConfig{
		RouteID:               "rou_wallet_only",
		PriceBaseUnits:        10000,
		AllowedPaymentMethods: "wallet",
	}

	// Client sends PAYMENT-SIGNATURE
	req := httptest.NewRequest("GET", "/v1/wallet-only", nil)
	req.Header.Set(HeaderPaymentSignature, "eyJ2ZXJzaW9uIjoiMi4wIn0")
	w := httptest.NewRecorder()

	processor.HandleRequest(w, req, route, "req_005")

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d", w.Code)
	}
	var errEnvelope ProtocolErrorEnvelope
	json.Unmarshal(w.Body.Bytes(), &errEnvelope)
	if errEnvelope.Error.Code != ErrCodePaymentMethodNotAllowed {
		t.Errorf("expected %s, got %s", ErrCodePaymentMethodNotAllowed, errEnvelope.Error.Code)
	}
}

func TestOnChainPaymentSignatureAndNonceReplayGuard(t *testing.T) {
	nonceStore := NewMemoryNonceStore()
	verifier := &MockPaymentVerifier{
		ShouldPass: true,
		Payer:      "0x1111111111111111111111111111111111111111",
	}
	processor, m := setupTestProcessor(nil, verifier, nonceStore)

	route := &rcu.RouteConfig{
		RouteID:               "rou_onchain",
		UpstreamURL:           "http://upstream.internal:8000",
		PriceBaseUnits:        50000,
		Asset:                 "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
		PayeeAddress:          "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		AllowedPaymentMethods: "onchain",
	}

	now := time.Now().Unix()
	auth := &PaymentAuthorization{
		Version:     "2.0",
		ChallengeID: "ch_valid_01",
		Payer:       "0x1111111111111111111111111111111111111111",
		Scheme:      "agentpay-wallet",
		Nonce:       "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		ValidAfter:  now - 10,
		ValidBefore: now + 300,
		Signature:   NewSignatureFromString("0xmock_signature"),
	}
	authHeader, _ := EncodeAuthorization(auth, true)

	// 1. First submission succeeds
	req1 := httptest.NewRequest("GET", "/v1/onchain", nil)
	req1.Header.Set(HeaderPaymentSignature, authHeader)
	w1 := httptest.NewRecorder()

	serveAuthorizedWalletRequest(t, processor, w1, req1, route, "req_006")
	if w1.Code != http.StatusOK {
		t.Fatalf("first submission expected 200 OK, got %d, body: %s", w1.Code, w1.Body.String())
	}
	if m.PaymentsVerifiedTotal != 1 {
		t.Errorf("expected 1 verified payment, got %d", m.PaymentsVerifiedTotal)
	}

	// 2. Replayed submission with exact same Nonce fails with 409 ERR_NONCE_ALREADY_USED
	req2 := httptest.NewRequest("GET", "/v1/onchain", nil)
	req2.Header.Set(HeaderPaymentSignature, authHeader)
	w2 := httptest.NewRecorder()

	serveAuthorizedWalletRequest(t, processor, w2, req2, route, "req_007")
	if w2.Code != http.StatusConflict {
		t.Fatalf("replayed nonce expected 409 Conflict, got %d", w2.Code)
	}
	var errEnvelope ProtocolErrorEnvelope
	json.Unmarshal(w2.Body.Bytes(), &errEnvelope)
	if errEnvelope.Error.Code != ErrCodeNonceAlreadyUsed {
		t.Errorf("expected %s, got %s", ErrCodeNonceAlreadyUsed, errEnvelope.Error.Code)
	}
}

func TestFreeRouteBypassesPayment(t *testing.T) {
	processor, m := setupTestProcessor(nil, nil, nil)
	route := &rcu.RouteConfig{
		RouteID:        "rou_free",
		UpstreamURL:    "http://upstream.internal:8000",
		PriceBaseUnits: 0, // Free!
	}

	req := httptest.NewRequest("GET", "/v1/free", nil)
	w := httptest.NewRecorder()

	serveAuthorizedWalletRequest(t, processor, w, req, route, "req_free")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for free route, got %d", w.Code)
	}
	if m.ChallengesIssuedTotal != 0 || m.PaymentsVerifiedTotal != 0 {
		t.Errorf("free route should not trigger payment metrics")
	}
}

func TestOnChainChallengeAndReplayCorrelateSingleIntent(t *testing.T) {
	nonceStore := NewMemoryNonceStore()
	verifier := &MockPaymentVerifier{
		ShouldPass: true,
		Payer:      "0x1111111111111111111111111111111111111111",
	}
	processor, _ := setupTestProcessor(nil, verifier, nonceStore)

	route := &rcu.RouteConfig{
		RouteID:               "rou_onchain_corr",
		TenantID:              "ten_corr",
		UpstreamURL:           "http://upstream.internal:8000",
		PriceBaseUnits:        50000,
		Asset:                 "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
		PayeeAddress:          "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		AllowedPaymentMethods: "onchain",
	}

	// Step 1: Initial unauthenticated request issues 402 challenge
	req1 := httptest.NewRequest("GET", "/v1/onchain-corr", nil)
	req1.Header.Set(HeaderIdempotencyKey, "idem_onchain_corr_1")
	w1 := httptest.NewRecorder()
	processor.HandleRequest(w1, req1, route, "req_challenge_101")
	if w1.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402, got %d", w1.Code)
	}
	ch, err := DecodeChallenge(w1.Header().Get(HeaderPaymentRequired))
	if err != nil {
		t.Fatalf("decode challenge: %v", err)
	}

	// Verify 1 intent exists in HTTP_402_CHALLENGED state with ID pi_<challengeId>
	records1, total1, err := processor.GetPaymentService().ListPaymentAudits(req1.Context(), payment.PaymentAuditFilter{
		TenantID: "ten_corr",
	})
	if err != nil || total1 != 1 || len(records1) != 1 {
		t.Fatalf("expected 1 challenged audit record, got total=%d len=%d err=%v", total1, len(records1), err)
	}
	expectedIntentID := "pi_" + ch.ChallengeID
	if records1[0].IntentID != expectedIntentID || records1[0].DisplayStatus != "HTTP_402_CHALLENGED" {
		t.Fatalf("unexpected initial audit record: %+v", records1[0])
	}

	// Step 2: Signed replay with a different requestID reuses the same intentID
	auth := &PaymentAuthorization{
		Version:     ch.Version,
		ChallengeID: ch.ChallengeID,
		Payer:       "0x1111111111111111111111111111111111111111",
		Scheme:      ch.Scheme,
		Nonce:       "0x1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
		ValidAfter:  ch.ValidAfter,
		ValidBefore: ch.ValidBefore,
		Signature:   NewSignatureFromString("0xmock_signature"),
	}
	authHeader, _ := EncodeAuthorization(auth, true)

	req2 := httptest.NewRequest("GET", "/v1/onchain-corr", nil)
	req2.Header.Set(HeaderPaymentSignature, authHeader)
	req2.Header.Set(HeaderIdempotencyKey, "idem_onchain_corr_1")
	w2 := httptest.NewRecorder()
	processor.HandleRequest(w2, req2, route, "req_replay_102")
	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on replay, got %d: %s", w2.Code, w2.Body.String())
	}

	// Verify there is STILL only 1 intent record, now transitioned to COMPLETED
	records2, total2, err := processor.GetPaymentService().ListPaymentAudits(req2.Context(), payment.PaymentAuditFilter{
		TenantID: "ten_corr",
	})
	if err != nil || total2 != 1 || len(records2) != 1 {
		t.Fatalf("expected 1 correlated audit record after replay, got total=%d len=%d err=%v", total2, len(records2), err)
	}
	if records2[0].IntentID != expectedIntentID {
		t.Errorf("expected intent_id %s, got %s", expectedIntentID, records2[0].IntentID)
	}
	if records2[0].DisplayStatus != payment.DisplayCompleted {
		t.Errorf("expected display_status %s, got %s", payment.DisplayCompleted, records2[0].DisplayStatus)
	}
	if records2[0].RequestID != "req_replay_102" {
		t.Errorf("expected updated request_id req_replay_102, got %s", records2[0].RequestID)
	}
	if records2[0].IdempotencyKey != "idem_onchain_corr_1" {
		t.Errorf("expected idempotency_key idem_onchain_corr_1, got %s", records2[0].IdempotencyKey)
	}
}

type mockAsyncTestVerifier struct {
	settleStatus SettlementStatus
	lookupStatus SettlementStatus
	settleCalls  int
}

func (m *mockAsyncTestVerifier) VerifyPayment(ctx context.Context, ch *PaymentChallenge, auth *PaymentAuthorization) (*VerificationResult, error) {
	return &VerificationResult{Valid: true, Payer: auth.Payer}, nil
}

func (m *mockAsyncTestVerifier) SettlePayment(ctx context.Context, vToken string, auth *PaymentAuthorization, idemKey string) (*SettleResult, error) {
	m.settleCalls++
	return &SettleResult{
		SettlementID: "ext_stl_001",
		Status:       "submitted",
		TxHash:       "0xabc123def456",
	}, nil
}

func (m *mockAsyncTestVerifier) GetSettlementStatus(ctx context.Context, settlementID string) (*SettlementStatus, error) {
	return &m.settleStatus, nil
}

func (m *mockAsyncTestVerifier) GetSettlementStatusByNonce(ctx context.Context, network, asset, payer, nonce string) (*SettlementStatus, error) {
	return &m.lookupStatus, nil
}

func TestP03AsyncSettlementSubmittedStaysSubmittedUntilReconciledAndRevertMarksFailed(t *testing.T) {
	asyncVerifier := &mockAsyncTestVerifier{
		lookupStatus: SettlementStatus{
			SettlementID: "ext_stl_restart",
			Status:       "CONFIRMED",
			TxHash:       "0x99998888",
		},
	}

	nonceStore := NewMemoryNonceStore()
	processor, _ := setupTestProcessor(nil, asyncVerifier, nonceStore)

	route := &rcu.RouteConfig{
		RouteID:               "rou_p03",
		TenantID:              "ten_p03",
		UpstreamURL:           "http://upstream.internal:8000",
		PriceBaseUnits:        50000,
		Asset:                 "CNY",
		PayeeAddress:          "acc_seller_p03",
		AllowedPaymentMethods: "wallet",
	}

	now := time.Now().Unix()
	auth := &PaymentAuthorization{
		Version:     "2.0",
		ChallengeID: "ch_p03_1",
		Payer:       "acc_buyer_p03",
		Scheme:      "agentpay-wallet",
		Nonce:       "nonce_p03_test_12345",
		ValidAfter:  now - 10,
		ValidBefore: now + 300,
		Signature:   NewSignatureFromString("mock_sig"),
	}

	sc := newReqScope(processor, httptest.NewRequest("GET", "/v1/p03", nil), route, "req_p03_1", nil)
	intentID := "pi_ch_p03_1"
	settlementID := "stl_req_p03_1"
	fulfillmentID := "ful_req_p03_1"
	sc.initIntent("ten_p03", defaultProjectID, "", intentID, "idem_p03_1", "wallet", payment.IntentStatusAuthorized)
	sc.initSettlement(settlementID, intentID, "wallet", payment.SettlementStatusSubmitted, auth.Payer, route.PayeeAddress, auth.Nonce, "")
	sc.initFulfillment(fulfillmentID, intentID)
	sc.updateCorrelationOutcomeWithMode(intentID, settlementID, fulfillmentID, http.StatusOK, false)

	processor.executeAsyncSettlement(sc.r.Context(), intentID, settlementID, "vtok_test_001", auth, "idem_p03_1")

	// 1. After submitted, settlement MUST remain submitted (NOT confirmed!)
	stl1, err := processor.GetPaymentService().GetSettlement(sc.r.Context(), settlementID)
	if err != nil {
		t.Fatalf("get settlement: %v", err)
	}
	if stl1.Status != payment.SettlementStatusSubmitted {
		t.Fatalf("expected settlement status 'submitted' after 202 response, got %q", stl1.Status)
	}
	audit1, err := processor.GetPaymentAudit(sc, "ten_p03", intentID)
	if err != nil {
		t.Fatalf("get payment audit: %v", err)
	}
	if audit1.DisplayStatus != payment.DisplaySettlementInProgress {
		t.Fatalf("expected display status %s while settlement is submitted, got %s", payment.DisplaySettlementInProgress, audit1.DisplayStatus)
	}

	// 2. Reconcile when verifier reports CONFIRMED -> transitions to confirmed & completed
	asyncVerifier.settleStatus = SettlementStatus{
		SettlementID:  "ext_stl_001",
		Status:        "CONFIRMED",
		TxHash:        "tx_confirmed_001",
		Confirmations: 1,
	}
	reconciled, err := processor.ReconcileSettlements(sc.r.Context())
	if err != nil || reconciled != 1 {
		t.Fatalf("expected 1 reconciled settlement, got %d (err=%v)", reconciled, err)
	}
	stl2, _ := processor.GetPaymentService().GetSettlement(sc.r.Context(), settlementID)
	if stl2.Status != payment.SettlementStatusConfirmed {
		t.Fatalf("expected settlement status 'confirmed' after reconciliation, got %q", stl2.Status)
	}

	// 3. Test revert (FAILED from verifier) -> transitions to failed & RECOVERY_REQUIRED
	intentRevert := "pi_ch_p03_revert"
	stlRevertID := "stl_req_p03_revert"
	fulRevertID := "ful_req_p03_revert"
	sc.initIntent("ten_p03", defaultProjectID, "", intentRevert, "idem_p03_2", "wallet", payment.IntentStatusAuthorized)
	sc.initSettlement(stlRevertID, intentRevert, "wallet", payment.SettlementStatusUnknown, auth.Payer, route.PayeeAddress, "nonce_rev", "err_tx")
	sc.initFulfillment(fulRevertID, intentRevert)
	sc.updateCorrelationOutcomeWithMode(intentRevert, stlRevertID, fulRevertID, http.StatusOK, false)
	processor.setExternalSettlementID(stlRevertID, "ext_stl_001")

	asyncVerifier.settleStatus = SettlementStatus{
		SettlementID: "ext_stl_001",
		Status:       "FAILED",
		TxHash:       "err_tx",
		ErrorMessage: "execution reverted",
	}
	reconciled2, err := processor.ReconcileSettlements(sc.r.Context())
	if err != nil || reconciled2 != 1 {
		t.Fatalf("expected 1 reconciled reverted settlement, got %d (err=%v)", reconciled2, err)
	}
	stlRevert, _ := processor.GetPaymentService().GetSettlement(sc.r.Context(), stlRevertID)
	if stlRevert.Status != payment.SettlementStatusFailed {
		t.Fatalf("expected reverted settlement status 'failed', got %q", stlRevert.Status)
	}
	auditRevert, _ := processor.GetPaymentService().GetPaymentAudit(sc.r.Context(), "ten_p03", intentRevert)
	if auditRevert.DisplayStatus != payment.DisplayRecoveryRequired || !auditRevert.IsRecoveryRequired {
		t.Fatalf("expected reverted post-fulfillment audit to be RECOVERY_REQUIRED, got %s (recovery=%v)", auditRevert.DisplayStatus, auditRevert.IsRecoveryRequired)
	}
	// Ensure reconciliation never re-called SettlePayment (no blind retry)
	if asyncVerifier.settleCalls != 1 {
		t.Fatalf("expected exactly 1 SettlePayment call (no blind retry), got %d", asyncVerifier.settleCalls)
	}

	// 4. Test Reconcile fallback to nonce lookup after gateway restart (memory map lost)
	nonceRestart := "nonce_restart_999"
	intentRestart := "pi_ch_p03_restart"
	stlRestartID := "stl_req_p03_restart"
	fulRestartID := "ful_req_p03_restart"
	sc.initIntent("ten_p03", defaultProjectID, "", intentRestart, "idem_p03_restart", "wallet", payment.IntentStatusAuthorized)
	sc.initSettlement(stlRestartID, intentRestart, "wallet", payment.SettlementStatusSubmitted, auth.Payer, route.PayeeAddress, nonceRestart, "")
	sc.initFulfillment(fulRestartID, intentRestart)
	sc.updateCorrelationOutcomeWithMode(intentRestart, stlRestartID, fulRestartID, http.StatusOK, false)

	// Ensure no memory map for stlRestartID
	processor.externalStlMu.Lock()
	delete(processor.externalStlIDs, stlRestartID)
	processor.externalStlMu.Unlock()

	// Reconcile should invoke lookup via nonce, retrieve ext_stl_restart, and mark confirmed
	reconciled3, err := processor.ReconcileSettlements(sc.r.Context())
	if err != nil || reconciled3 != 1 {
		t.Fatalf("expected 1 reconciled settlement via nonce fallback, got %d (err=%v)", reconciled3, err)
	}
	stlRestart, _ := processor.GetPaymentService().GetSettlement(sc.r.Context(), stlRestartID)
	if stlRestart.Status != payment.SettlementStatusConfirmed {
		t.Fatalf("expected restarted settlement status 'confirmed' after nonce reconciliation, got %q", stlRestart.Status)
	}
}

func (p *PaymentProcessor) GetPaymentAudit(sc *reqScope, tenantID, intentID string) (*payment.PaymentAuditRecord, error) {
	return p.paymentService.GetPaymentAudit(sc.r.Context(), tenantID, intentID)
}

func TestP03SweepExpiredHoldsAfter5xx(t *testing.T) {
	walletSvc := NewMemoryWalletService()
	walletSvc.RegisterWallet("apk_live_hold_exp", &WalletAccount{
		WalletID:         "wlt_exp_01",
		TenantID:         "ten_exp_01",
		Status:           "active",
		AvailableBalance: 100000,
		HeldBalance:      0,
	})

	m := metrics.New()
	mock502Transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadGateway,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewBufferString(`{"error":"upstream down"}`)),
			Request:    r,
		}, nil
	})
	processor := NewPaymentProcessor(nil, nil, walletSvc, proxy.NewHandler(m, mock502Transport), m)
	route := &rcu.RouteConfig{
		RouteID:               "rou_502",
		TenantID:              "ten_exp_01",
		UpstreamURL:           "http://upstream.internal:8000",
		PriceBaseUnits:        40000,
		Asset:                 "USD",
		AllowedPaymentMethods: "wallet",
	}

	req := httptest.NewRequest("GET", "/v1/502", nil)
	req.Header.Set("Authorization", "Bearer apk_live_hold_exp")
	w := httptest.NewRecorder()
	serveAuthorizedWalletRequest(t, processor, w, req, route, "req_502_hold")

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 from upstream, got %d", w.Code)
	}
	wlt, _ := walletSvc.GetWalletByAPIKey(req.Context(), "apk_live_hold_exp")
	if wlt.AvailableBalance != 60000 || wlt.HeldBalance != 40000 {
		t.Fatalf("expected held=40000 available=60000 immediately after 502, got held=%d available=%d", wlt.HeldBalance, wlt.AvailableBalance)
	}

	// Sweep after TTL (now + 3 minutes) releases the expired hold
	released, err := processor.SweepExpiredHolds(req.Context(), time.Now().Add(3*time.Minute))
	if err != nil || released != 1 {
		t.Fatalf("expected 1 expired hold released, got %d (err=%v)", released, err)
	}
	wltAfter, _ := walletSvc.GetWalletByAPIKey(req.Context(), "apk_live_hold_exp")
	if wltAfter.AvailableBalance != 100000 || wltAfter.HeldBalance != 0 {
		t.Fatalf("expected held=0 available=100000 after sweep, got held=%d available=%d", wltAfter.HeldBalance, wltAfter.AvailableBalance)
	}
}

func TestP04CaseVariantPayerReplayAndRestartPersistence(t *testing.T) {
	tmpFile := t.TempDir() + "/nonces.json"
	nonceStore1, err := NewPersistentFileNonceStore(tmpFile)
	if err != nil {
		t.Fatalf("failed to create persistent nonce store: %v", err)
	}
	verifier := &MockPaymentVerifier{ShouldPass: true}
	processor1, _ := setupTestProcessor(nil, verifier, nonceStore1)

	route := &rcu.RouteConfig{
		RouteID:               "rou_p04",
		UpstreamURL:           "http://upstream.internal:8000",
		PriceBaseUnits:        50000,
		Asset:                 "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
		PayeeAddress:          "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		AllowedPaymentMethods: "onchain",
	}

	now := time.Now().Unix()
	// 1. First request with EIP-55 mixed-case Payer and uppercase hex in Nonce
	authMixed := &PaymentAuthorization{
		Version:     "2.0",
		ChallengeID: "ch_p04_1",
		Payer:       "0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B",
		Scheme:      "agentpay-wallet",
		Nonce:       "0xABCDEF1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		ValidAfter:  now - 10,
		ValidBefore: now + 300,
		Signature:   NewSignatureFromString("0xmock_signature"),
	}
	hdr1, _ := EncodeAuthorization(authMixed, true)
	req1 := httptest.NewRequest("GET", "/v1/p04", nil)
	req1.Header.Set(HeaderPaymentSignature, hdr1)
	w1 := httptest.NewRecorder()
	processor1.HandleRequest(w1, req1, route, "req_p04_1")
	if w1.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on first request, got %d", w1.Code)
	}

	// 2. Replay with all-lowercase Payer and Nonce MUST be rejected with 409 ERR_NONCE_ALREADY_USED
	authLower := &PaymentAuthorization{
		Version:     "2.0",
		ChallengeID: "ch_p04_1",
		Payer:       "0xab5801a7d398351b8be11c439e05c5b3259aec9b",
		Scheme:      "agentpay-wallet",
		Nonce:       "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		ValidAfter:  now - 10,
		ValidBefore: now + 300,
		Signature:   NewSignatureFromString("0xmock_signature"),
	}
	hdr2, _ := EncodeAuthorization(authLower, true)
	req2 := httptest.NewRequest("GET", "/v1/p04", nil)
	req2.Header.Set(HeaderPaymentSignature, hdr2)
	w2 := httptest.NewRecorder()
	processor1.HandleRequest(w2, req2, route, "req_p04_2")
	if w2.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict on case-variant payer replay, got %d", w2.Code)
	}

	// 3. Simulate gateway restart by creating a new store & processor from the same persistent file
	nonceStoreAfterRestart, err := NewPersistentFileNonceStore(tmpFile)
	if err != nil {
		t.Fatalf("failed to reload persistent nonce store: %v", err)
	}
	processor2, _ := setupTestProcessor(nil, verifier, nonceStoreAfterRestart)
	req3 := httptest.NewRequest("GET", "/v1/p04", nil)
	req3.Header.Set(HeaderPaymentSignature, hdr2)
	w3 := httptest.NewRecorder()
	processor2.HandleRequest(w3, req3, route, "req_p04_3")
	if w3.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict on post-restart nonce replay, got %d", w3.Code)
	}
}

func TestGuestTrialKeyInterception(t *testing.T) {
	walletSvc := NewMemoryWalletService()
	walletSvc.RegisterWallet("apk_live_guest_tester99", &WalletAccount{
		WalletID:         "wlt_public_sandbox",
		TenantID:         "ten_public_sandbox",
		Status:           "active",
		AvailableBalance: 1000000000,
		HeldBalance:      0,
	})

	processor, _ := setupTestProcessor(walletSvc, nil, nil)

	// 1. High price route (¥50 = 50,000,000 base units > ¥0.50 cap) must be 403 rejected
	expensiveRoute := &rcu.RouteConfig{
		RouteID:               "rou_expensive",
		UpstreamURL:           "http://upstream.internal:8000",
		PriceBaseUnits:        50000000,
		Asset:                 "CNY",
		AllowedPaymentMethods: "wallet",
	}

	req1 := httptest.NewRequest("GET", "/v1/expensive", nil)
	req1.Header.Set("Authorization", "Bearer apk_live_guest_tester99")
	w1 := httptest.NewRecorder()
	processor.HandleRequest(w1, req1, expensiveRoute, "req_exp_1")

	if w1.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for guest key calling ¥50 route, got %d", w1.Code)
	}
	if !strings.Contains(w1.Body.String(), "ERR_TRIAL_SINGLE_TX_CAP_EXCEEDED") {
		t.Fatalf("expected ERR_TRIAL_SINGLE_TX_CAP_EXCEEDED error code, got %s", w1.Body.String())
	}

	// 2. Trial-disabled route must be 403 rejected
	trialDisabled := false
	disabledRoute := &rcu.RouteConfig{
		RouteID:               "rou_no_trial",
		UpstreamURL:           "http://upstream.internal:8000",
		PriceBaseUnits:        100000, // ¥0.10 <= ¥0.50
		Asset:                 "CNY",
		AllowedPaymentMethods: "wallet",
		IsTrialAllowed:        &trialDisabled,
	}

	req2 := httptest.NewRequest("GET", "/v1/no-trial", nil)
	req2.Header.Set("Authorization", "Bearer apk_live_guest_tester99")
	w2 := httptest.NewRecorder()
	processor.HandleRequest(w2, req2, disabledRoute, "req_notrial_2")

	if w2.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for guest key calling trial-disabled route, got %d", w2.Code)
	}
	if !strings.Contains(w2.Body.String(), "ERR_TRIAL_NOT_ALLOWED") {
		t.Fatalf("expected ERR_TRIAL_NOT_ALLOWED error code, got %s", w2.Body.String())
	}

	// 3. Eligible route (¥0.20 = 200,000 base units <= ¥0.50) must proceed to challenge (402)
	eligibleRoute := &rcu.RouteConfig{
		RouteID:               "rou_eligible",
		UpstreamURL:           "http://upstream.internal:8000",
		PriceBaseUnits:        200000,
		Asset:                 "CNY",
		AllowedPaymentMethods: "wallet",
	}

	req3 := httptest.NewRequest("GET", "/v1/eligible", nil)
	req3.Header.Set("Authorization", "Bearer apk_live_guest_tester99")
	w3 := httptest.NewRecorder()
	processor.HandleRequest(w3, req3, eligibleRoute, "req_ok_3")

	if w3.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402 challenge for eligible route, got %d", w3.Code)
	}
}

