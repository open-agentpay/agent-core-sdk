package x402

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-agentpay/agent-core-sdk/gateway/metrics"
	"github.com/open-agentpay/agent-core-sdk/gateway/proxy"
	"github.com/open-agentpay/agent-core-sdk/gateway/rcu"
)

func TestWalletIdempotencyCacheHit(t *testing.T) {
	var upstreamCalls int32
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		atomic.AddInt32(&upstreamCalls, 1)
		body := `{"id":"chat_123","message":"hello from upstream"}`
		return &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewBufferString(body)),
			Request:    req,
		}, nil
	})

	proxyHandler := proxy.NewHandler(metrics.New(), rt)
	processor := NewPaymentProcessor(nil, nil, nil, proxyHandler, metrics.New())

	walletService := processor.walletService.(*MemoryWalletService)
	walletService.RegisterWallet("apk_live_idem_001", &WalletAccount{
		WalletID:         "wal_idem_001",
		TenantID:         "ten_idem_001",
		Status:           "active",
		AvailableBalance: 100000,
		HeldBalance:      0,
	})

	route := &rcu.RouteConfig{
		RouteID:               "rou_chat",
		PathPattern:           "/v1/chat",
		UpstreamURL:           "http://upstream.mock/v1/chat",
		PriceBaseUnits:        50000,
		Asset:                 "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
		AllowedPaymentMethods: "wallet",
	}

	idemKey := "key_test_idem_success"
	reqPayload := `{"prompt":"tell me a joke"}`

	// Call 1: First request
	req1 := httptest.NewRequest("POST", "/v1/chat", bytes.NewBufferString(reqPayload))
	req1.Header.Set("Authorization", "Bearer apk_live_idem_001")
	req1.Header.Set(HeaderIdempotencyKey, idemKey)
	w1 := httptest.NewRecorder()

	serveAuthorizedWalletRequest(t, processor, w1, req1, route, "req_001")
	resp1 := w1.Result()

	if resp1.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp1.StatusCode)
	}
	if atomic.LoadInt32(&upstreamCalls) != 1 {
		t.Fatalf("expected 1 upstream call, got %d", upstreamCalls)
	}

	// Verify balance after first charge: 100000 - 50000 = 50000
	wAcc, _ := walletService.GetWalletByAPIKey(req1.Context(), "apk_live_idem_001")
	if wAcc.AvailableBalance != 50000 || wAcc.HeldBalance != 0 {
		t.Fatalf("expected 50000 balance, got avl=%d held=%d", wAcc.AvailableBalance, wAcc.HeldBalance)
	}

	// Call 2: Duplicate request with same Idempotency-Key
	req2 := httptest.NewRequest("POST", "/v1/chat", bytes.NewBufferString(reqPayload))
	req2.Header.Set("Authorization", "Bearer apk_live_idem_001")
	req2.Header.Set(HeaderIdempotencyKey, idemKey)
	w2 := httptest.NewRecorder()

	serveAuthorizedWalletRequest(t, processor, w2, req2, route, "req_002")
	resp2 := w2.Result()

	if resp2.StatusCode != 200 {
		t.Fatalf("expected 200 for duplicate request, got %d", resp2.StatusCode)
	}
	if resp2.Header.Get("X-Cache") != "HIT" {
		t.Fatalf("expected X-Cache: HIT header, got %s", resp2.Header.Get("X-Cache"))
	}
	// Upstream MUST NOT be called a second time
	if atomic.LoadInt32(&upstreamCalls) != 1 {
		t.Fatalf("expected upstreamCalls to remain 1, got %d", upstreamCalls)
	}
	// Wallet MUST NOT be charged again (Anti-Double-Charge)
	if wAcc.AvailableBalance != 50000 {
		t.Fatalf("balance corrupted after idempotency hit: %d", wAcc.AvailableBalance)
	}
}

func TestWalletIdempotencyConflictOnPayloadTamper(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewBufferString(`{"ok":true}`)),
			Request:    req,
		}, nil
	})

	proxyHandler := proxy.NewHandler(metrics.New(), rt)
	processor := NewPaymentProcessor(nil, nil, nil, proxyHandler, metrics.New())

	walletService := processor.walletService.(*MemoryWalletService)
	walletService.RegisterWallet("apk_live_tamper", &WalletAccount{
		WalletID:         "wal_tamper",
		TenantID:         "ten_tamper",
		Status:           "active",
		AvailableBalance: 100000,
	})

	route := &rcu.RouteConfig{
		RouteID:               "rou_tamper",
		PathPattern:           "/v1/data",
		UpstreamURL:           "http://upstream.mock/v1/data",
		PriceBaseUnits:        10000,
		Asset:                 "USDC",
		AllowedPaymentMethods: "wallet",
	}

	idemKey := "key_tamper_001"

	// Request 1: Original payload
	req1 := httptest.NewRequest("POST", "/v1/data", bytes.NewBufferString(`{"action":"read"}`))
	req1.Header.Set("Authorization", "Bearer apk_live_tamper")
	req1.Header.Set(HeaderIdempotencyKey, idemKey)
	w1 := httptest.NewRecorder()
	serveAuthorizedWalletRequest(t, processor, w1, req1, route, "req_1")

	if w1.Result().StatusCode != 200 {
		t.Fatalf("expected 200, got %d", w1.Result().StatusCode)
	}

	// Request 2: Same idempotency key, but altered payload -> MUST return 409 ERR_IDEMPOTENCY_CONFLICT
	req2 := httptest.NewRequest("POST", "/v1/data", bytes.NewBufferString(`{"action":"delete"}`))
	req2.Header.Set("Authorization", "Bearer apk_live_tamper")
	req2.Header.Set(HeaderIdempotencyKey, idemKey)
	w2 := httptest.NewRecorder()
	serveAuthorizedWalletRequest(t, processor, w2, req2, route, "req_2")

	resp2 := w2.Result()
	if resp2.StatusCode != 409 {
		t.Fatalf("expected 409 conflict, got %d", resp2.StatusCode)
	}

	var errBody map[string]interface{}
	_ = json.NewDecoder(resp2.Body).Decode(&errBody)
	errObj := errBody["error"].(map[string]interface{})
	if errObj["code"] != ErrCodeIdempotencyConflict {
		t.Fatalf("expected code %s, got %s", ErrCodeIdempotencyConflict, errObj["code"])
	}
}

func TestFaultInjectionUpstream500AndFreeReplayRecovery(t *testing.T) {
	var callCount int32
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		current := atomic.AddInt32(&callCount, 1)
		if current == 1 {
			// Flaky failure on first attempt
			return &http.Response{
				StatusCode: 503,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewBufferString(`{"error":"service temporarily unavailable"}`)),
				Request:    req,
			}, nil
		}
		// Recovery on second attempt
		return &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewBufferString(`{"success":true,"recovered":true}`)),
			Request:    req,
		}, nil
	})

	proxyHandler := proxy.NewHandler(metrics.New(), rt)
	processor := NewPaymentProcessor(nil, nil, nil, proxyHandler, metrics.New())

	walletService := processor.walletService.(*MemoryWalletService)
	walletService.RegisterWallet("apk_live_flaky", &WalletAccount{
		WalletID:         "wal_flaky_001",
		TenantID:         "ten_flaky_001",
		Status:           "active",
		AvailableBalance: 100000,
		HeldBalance:      0,
	})

	route := &rcu.RouteConfig{
		RouteID:               "rou_flaky",
		PathPattern:           "/v1/flaky",
		UpstreamURL:           "http://upstream.mock/v1/flaky",
		PriceBaseUnits:        30000,
		Asset:                 "USDC",
		AllowedPaymentMethods: "wallet",
	}

	idemKey := "key_recovery_fault_injection"
	payload := `{"query":"analyze_financial_records"}`

	// Step 1: Request 1 fails at upstream with 503
	req1 := httptest.NewRequest("POST", "/v1/flaky", bytes.NewBufferString(payload))
	req1.Header.Set("Authorization", "Bearer apk_live_flaky")
	req1.Header.Set(HeaderIdempotencyKey, idemKey)
	w1 := httptest.NewRecorder()

	serveAuthorizedWalletRequest(t, processor, w1, req1, route, "req_fault_1")
	if w1.Result().StatusCode != 503 {
		t.Fatalf("expected 503 from upstream, got %d", w1.Result().StatusCode)
	}

	// CRITICAL VERIFICATION 1: Wallet fund MUST BE HELD, NOT RELEASED AND NOT CAPTURED
	wAcc, _ := walletService.GetWalletByAPIKey(req1.Context(), "apk_live_flaky")
	if wAcc.AvailableBalance != 70000 {
		t.Fatalf("expected 70000 available balance, got %d", wAcc.AvailableBalance)
	}
	if wAcc.HeldBalance != 30000 {
		t.Fatalf("expected 30000 held balance, got %d", wAcc.HeldBalance)
	}

	// Step 2: Client re-submits exact same request with same Idempotency-Key -> Treated as FREE REPLAY!
	req2 := httptest.NewRequest("POST", "/v1/flaky", bytes.NewBufferString(payload))
	req2.Header.Set("Authorization", "Bearer apk_live_flaky")
	req2.Header.Set(HeaderIdempotencyKey, idemKey)
	w2 := httptest.NewRecorder()

	serveAuthorizedWalletRequest(t, processor, w2, req2, route, "req_fault_2")
	resp2 := w2.Result()

	if resp2.StatusCode != 200 {
		t.Fatalf("expected 200 on Free Replay recovery, got %d", resp2.StatusCode)
	}
	if atomic.LoadInt32(&callCount) != 2 {
		t.Fatalf("expected 2 upstream calls, got %d", callCount)
	}

	// CRITICAL VERIFICATION 2: Free Replay must NOT charge the wallet a second time!
	// Balance: 100000 - 30000 = 70000 available, 0 held (Hold captured upon 200 OK)
	if wAcc.AvailableBalance != 70000 {
		t.Fatalf("wallet double-charged! Available balance: %d (expected 70000)", wAcc.AvailableBalance)
	}
	if wAcc.HeldBalance != 0 {
		t.Fatalf("expected 0 held balance after capture, got %d", wAcc.HeldBalance)
	}

	// Step 3: Third call hits cache directly
	req3 := httptest.NewRequest("POST", "/v1/flaky", bytes.NewBufferString(payload))
	req3.Header.Set("Authorization", "Bearer apk_live_flaky")
	req3.Header.Set(HeaderIdempotencyKey, idemKey)
	w3 := httptest.NewRecorder()

	serveAuthorizedWalletRequest(t, processor, w3, req3, route, "req_fault_3")
	if w3.Result().StatusCode != 200 || w3.Result().Header.Get("X-Cache") != "HIT" {
		t.Fatalf("expected 200 cache hit, got %d", w3.Result().StatusCode)
	}
	if atomic.LoadInt32(&callCount) != 2 {
		t.Fatalf("upstream called on third attempt: %d", callCount)
	}
}

func TestFaultInjectionUpstream4xxReleasesHold(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		// Upstream rejects bad client parameter
		return &http.Response{
			StatusCode: 400,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewBufferString(`{"error":"invalid parameter xyz"}`)),
			Request:    req,
		}, nil
	})

	proxyHandler := proxy.NewHandler(metrics.New(), rt)
	processor := NewPaymentProcessor(nil, nil, nil, proxyHandler, metrics.New())

	walletService := processor.walletService.(*MemoryWalletService)
	walletService.RegisterWallet("apk_live_4xx", &WalletAccount{
		WalletID:         "wal_4xx",
		TenantID:         "ten_4xx",
		Status:           "active",
		AvailableBalance: 100000,
		HeldBalance:      0,
	})

	route := &rcu.RouteConfig{
		RouteID:               "rou_4xx",
		PathPattern:           "/v1/api",
		UpstreamURL:           "http://upstream.mock/v1/api",
		PriceBaseUnits:        25000,
		Asset:                 "USDC",
		AllowedPaymentMethods: "wallet",
	}

	req := httptest.NewRequest("POST", "/v1/api", bytes.NewBufferString(`{"bad":"param"}`))
	req.Header.Set("Authorization", "Bearer apk_live_4xx")
	req.Header.Set(HeaderIdempotencyKey, "key_4xx_release")
	w := httptest.NewRecorder()

	serveAuthorizedWalletRequest(t, processor, w, req, route, "req_4xx_1")
	if w.Result().StatusCode != 400 {
		t.Fatalf("expected 400 from upstream, got %d", w.Result().StatusCode)
	}

	// 4xx MUST trigger ReleaseFunds: AvailableBalance restored to 100000, HeldBalance 0
	wAcc, _ := walletService.GetWalletByAPIKey(req.Context(), "apk_live_4xx")
	if wAcc.AvailableBalance != 100000 || wAcc.HeldBalance != 0 {
		t.Fatalf("expected funds to be released upon 4xx, got avl=%d held=%d", wAcc.AvailableBalance, wAcc.HeldBalance)
	}
}

func TestOnChainIdempotencyAndAntiRollback(t *testing.T) {
	var callCount int32
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		current := atomic.AddInt32(&callCount, 1)
		if current == 1 {
			// Upstream timeout on attempt 1
			return &http.Response{
				StatusCode: 504,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewBufferString(`{"error":"gateway timeout"}`)),
				Request:    req,
			}, nil
		}
		return &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewBufferString(`{"delivered":true}`)),
			Request:    req,
		}, nil
	})

	proxyHandler := proxy.NewHandler(metrics.New(), rt)
	processor := NewPaymentProcessor(nil, nil, nil, proxyHandler, metrics.New())

	route := &rcu.RouteConfig{
		RouteID:               "rou_onchain_idem",
		PathPattern:           "/v1/onchain",
		UpstreamURL:           "http://upstream.mock/v1/onchain",
		PriceBaseUnits:        50000,
		Asset:                 "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
		PayeeAddress:          "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		AllowedPaymentMethods: "onchain",
	}

	now := time.Now().Unix()
	auth := &PaymentAuthorization{
		Version:     "2.0",
		ChallengeID: "ch_recovery_001",
		Payer:       "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		Scheme:      "EIP-3009",
		Nonce:       "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		ValidAfter:  now - 60,
		ValidBefore: now + 300,
		Signature:   NewSignatureFromString("0xmock_signature"),
	}
	encodedAuth, _ := EncodeAuthorization(auth, true)
	idemKey := "key_onchain_fault_001"
	bodyPayload := `{"prompt":"onchain test"}`

	// Call 1: Upstream 504 Timeout
	req1 := httptest.NewRequest("POST", "/v1/onchain", bytes.NewBufferString(bodyPayload))
	req1.Header.Set(HeaderPaymentSignature, encodedAuth)
	req1.Header.Set(HeaderIdempotencyKey, idemKey)
	w1 := httptest.NewRecorder()

	processor.HandleRequest(w1, req1, route, "req_onchain_1")
	if w1.Result().StatusCode != 504 {
		t.Fatalf("expected 504, got %d", w1.Result().StatusCode)
	}

	// Anti-Rollback Check: The settlement record is preserved in unknown state
	settlementID := "stl_req_onchain_1"
	settlement, err := processor.recoveryCoord.GetSettlement(settlementID)
	if err != nil {
		t.Fatalf("settlement record disappeared: %v", err)
	}
	if settlement.Status != "unknown" {
		t.Fatalf("expected unknown settlement state after timeout, got %s", settlement.Status)
	}

	// Call 2: Free Replay retry with same key
	req2 := httptest.NewRequest("POST", "/v1/onchain", bytes.NewBufferString(bodyPayload))
	req2.Header.Set(HeaderPaymentSignature, encodedAuth)
	req2.Header.Set(HeaderIdempotencyKey, idemKey)
	w2 := httptest.NewRecorder()

	processor.HandleRequest(w2, req2, route, "req_onchain_2")
	if w2.Result().StatusCode != 200 {
		t.Fatalf("expected 200 on retry, got %d", w2.Result().StatusCode)
	}

	// Call 3: Cache Hit
	req3 := httptest.NewRequest("POST", "/v1/onchain", bytes.NewBufferString(bodyPayload))
	req3.Header.Set(HeaderPaymentSignature, encodedAuth)
	req3.Header.Set(HeaderIdempotencyKey, idemKey)
	w3 := httptest.NewRecorder()

	processor.HandleRequest(w3, req3, route, "req_onchain_3")
	if w3.Result().StatusCode != 200 || w3.Result().Header.Get("X-Cache") != "HIT" {
		t.Fatalf("expected 200 cache hit on attempt 3, got %d", w3.Result().StatusCode)
	}
	if atomic.LoadInt32(&callCount) != 2 {
		t.Fatalf("upstream called more than twice: %d", callCount)
	}
}
