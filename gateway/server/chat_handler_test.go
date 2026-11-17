package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/open-agentpay/agent-core-sdk/gateway/metrics"
	"github.com/open-agentpay/agent-core-sdk/gateway/rcu"
	"github.com/open-agentpay/agent-core-sdk/gateway/settlement"
	"github.com/open-agentpay/agent-core-sdk/gateway/wallet"
)

func TestChatCompletionHandler_ListModels(t *testing.T) {
	snap := &rcu.ConfigSnapshot{
		SchemaVersion: "2.0.0",
		TenantID:      "ten_01",
		VersionID:     "ver_1",
		VersionNumber: 1,
		Routes: []rcu.RouteConfig{
			{
				RouteID:               "rt_deepseek",
				TenantID:              "ten_01",
				RouteType:             "llm",
				ModelName:             "deepseek-v3",
				PathPattern:           "/models/deepseek-v3",
				Status:                "active",
				UpstreamURL:           "https://api.deepseek.com/v1",
				AllowedPaymentMethods: "wallet",
			},
			{
				RouteID:               "rt_qwen",
				TenantID:              "ten_01",
				RouteType:             "llm",
				ModelName:             "qwen-plus",
				PathPattern:           "/models/qwen-plus",
				Status:                "active",
				UpstreamURL:           "https://dashscope.aliyuncs.com/compatible-mode/v1",
				AllowedPaymentMethods: "wallet",
			},
			{
				RouteID:               "rt_standard_api",
				TenantID:              "ten_01",
				RouteType:             "api", // Regular API, should not appear in /v1/models
				PathPattern:           "/v1/weather",
				Status:                "active",
				UpstreamURL:           "https://api.weather.com",
				AllowedPaymentMethods: "wallet",
			},
		},
	}
	rcuMgr, _ := rcu.NewManager(snap)

	handler := NewChatCompletionHandler(ChatHandlerConfig{
		RCUMgr:  rcuMgr,
		Metrics: metrics.New(),
	})

	req := httptest.NewRequest("GET", "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer apk_test_key")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Object string `json:"object"`
		Data   []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse models response: %v", err)
	}

	if resp.Object != "list" {
		t.Fatalf("expected object=list, got %s", resp.Object)
	}
	if len(resp.Data) != 2 {
		t.Fatalf("expected 2 models, got %d", len(resp.Data))
	}
	if resp.Data[0].ID != "deepseek-v3" && resp.Data[1].ID != "deepseek-v3" {
		t.Fatalf("expected deepseek-v3 in models list")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestChatCompletionHandler_StreamingForward(t *testing.T) {
	// 1. Mock upstream LLM handler
	upstreamHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		chunks := []string{
			`data: {"choices":[{"delta":{"content":"Hi"}}]}`,
			`data: {"choices":[{"delta":{"content":" there!"}}]}`,
			`data: {"choices":[{"delta":{}}],"usage":{"prompt_tokens":5,"completion_tokens":10,"total_tokens":15}}`,
			`data: [DONE]`,
		}
		for _, c := range chunks {
			_, _ = w.Write([]byte(c + "\n\n"))
		}
	})

	mockTransport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		upstreamHandler.ServeHTTP(rec, req)
		return rec.Result(), nil
	})

	// 2. Setup RCU route pointing to mock upstream
	snap := &rcu.ConfigSnapshot{
		SchemaVersion: "2.0.0",
		TenantID:      "ten_01",
		VersionID:     "ver_1",
		VersionNumber: 1,
		Routes: []rcu.RouteConfig{
			{
				RouteID:                       "rt_deepseek",
				TenantID:                      "ten_01",
				RouteType:                     "llm",
				ModelName:                     "deepseek-v3",
				PathPattern:                   "/models/deepseek-stream",
				PricingType:                   "per_token",
				PromptTokenPriceBaseUnits:     2000, // 2000 base units per 1k prompt
				CompletionTokenPriceBaseUnits: 8000, // 8000 base units per 1k completion
				Status:                        "active",
				UpstreamURL:                   "https://api.deepseek.com/v1",
				AllowedPaymentMethods:         "wallet",
				IsPublic:                      true,
			},
		},
	}
	rcuMgr, _ := rcu.NewManager(snap)

	var flushedEvents []*settlement.BatchSettlementEvent
	ringBuffer := settlement.NewLedgerRingBuffer(settlement.RingBufferConfig{
		BufferSize: 100,
		FlushHandler: func(ctx context.Context, events []*settlement.BatchSettlementEvent) error {
			flushedEvents = append(flushedEvents, events...)
			return nil
		},
	})
	ringBuffer.Start(context.Background())
	defer ringBuffer.Close()

	handler := NewChatCompletionHandler(ChatHandlerConfig{
		RCUMgr:     rcuMgr,
		Metrics:    metrics.New(),
		RingBuffer: ringBuffer,
		Transport:  mockTransport,
	})

	// 3. Send streaming chat completions request
	reqBody := `{"model": "deepseek-v3", "messages": [{"role": "user", "content": "Hello"}], "stream": true}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d: %s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Hi") || !strings.Contains(body, "[DONE]") {
		t.Fatalf("expected streamed response containing chunks, got: %s", body)
	}

	// 4. Verify ringBuffer received settlement event
	_ = ringBuffer.Close()
	if len(flushedEvents) != 1 {
		t.Fatalf("expected 1 flushed settlement event, got %d", len(flushedEvents))
	}
	evt := flushedEvents[0]
	if evt.ModelName != "deepseek-v3" {
		t.Fatalf("expected model deepseek-v3, got %s", evt.ModelName)
	}
	if evt.CompletionTokens != 10 {
		t.Fatalf("expected 10 completion tokens, got %d", evt.CompletionTokens)
	}
	// Cost: 5 * 2000 / 1000 + 10 * 8000 / 1000 = 10 + 80 = 90
	if evt.ActualAmount != 90 {
		t.Fatalf("expected actual amount 90, got %d", evt.ActualAmount)
	}
}

func TestChatCompletionHandler_NonStreaming(t *testing.T) {
	upstreamHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := `{"id":"chatcmpl-123","object":"chat.completion","created":1677652288,"model":"deepseek-v3","choices":[{"index":0,"message":{"role":"assistant","content":"Hello world"},"finish_reason":"stop"}],"usage":{"prompt_tokens":9,"completion_tokens":12,"total_tokens":21}}`
		_, _ = w.Write([]byte(resp))
	})

	mockTransport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		upstreamHandler.ServeHTTP(rec, req)
		return rec.Result(), nil
	})

	snap := &rcu.ConfigSnapshot{
		SchemaVersion: "2.0.0",
		TenantID:      "ten_01",
		VersionID:     "ver_1",
		VersionNumber: 1,
		Routes: []rcu.RouteConfig{
			{
				RouteID:                       "rt_deepseek",
				TenantID:                      "ten_01",
				RouteType:                     "llm",
				ModelName:                     "deepseek-v3",
				PathPattern:                   "/models/deepseek-sync",
				PricingType:                   "per_token",
				PromptTokenPriceBaseUnits:     1000,
				CompletionTokenPriceBaseUnits: 2000,
				Status:                        "active",
				UpstreamURL:                   "https://api.deepseek.com/v1",
				AllowedPaymentMethods:         "wallet",
				IsPublic:                      true,
			},
		},
	}
	rcuMgr, _ := rcu.NewManager(snap)

	var flushedEvents []*settlement.BatchSettlementEvent
	ringBuffer := settlement.NewLedgerRingBuffer(settlement.RingBufferConfig{
		BufferSize: 100,
		FlushHandler: func(ctx context.Context, events []*settlement.BatchSettlementEvent) error {
			flushedEvents = append(flushedEvents, events...)
			return nil
		},
	})
	ringBuffer.Start(context.Background())
	defer ringBuffer.Close()

	handler := NewChatCompletionHandler(ChatHandlerConfig{
		RCUMgr:     rcuMgr,
		Metrics:    metrics.New(),
		RingBuffer: ringBuffer,
		Transport:  mockTransport,
	})

	reqBody := `{"model": "deepseek-v3", "messages": [{"role": "user", "content": "Hello"}], "stream": false}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d: %s", rec.Code, rec.Body.String())
	}

	_ = ringBuffer.Close()
	if len(flushedEvents) != 1 {
		t.Fatalf("expected 1 event, got %d", len(flushedEvents))
	}
	evt := flushedEvents[0]
	// 9 * 1000 / 1000 + 12 * 2000 / 1000 = 9 + 24 = 33
	if evt.ActualAmount != 33 {
		t.Fatalf("expected actual amount 33, got %d", evt.ActualAmount)
	}
}

func TestChatCompletionHandler_ModelNotFound(t *testing.T) {
	snap := &rcu.ConfigSnapshot{
		SchemaVersion: "2.0.0",
		TenantID:      "ten_01",
		VersionID:     "ver_1",
		VersionNumber: 1,
		Routes:        []rcu.RouteConfig{},
	}
	rcuMgr, _ := rcu.NewManager(snap)

	handler := NewChatCompletionHandler(ChatHandlerConfig{
		RCUMgr:  rcuMgr,
		Metrics: metrics.New(),
	})

	reqBody := `{"model": "non-existent-model", "messages": [{"role": "user", "content": "Hello"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected HTTP 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestChatCompletionHandler_StreamOptionsInjectionAndWalletSettlement(t *testing.T) {
	var upstreamReceivedBody []byte
	mockTransport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(req.Body)
		upstreamReceivedBody = b

		rec := httptest.NewRecorder()
		rec.Header().Set("Content-Type", "text/event-stream")
		rec.WriteHeader(http.StatusOK)
		ssePayload := "data: {\"choices\":[{\"delta\":{\"content\":\"Hello world\"}}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":20,\"total_tokens\":30}}\n\ndata: [DONE]\n\n"
		_, _ = rec.Write([]byte(ssePayload))
		return rec.Result(), nil
	})

	snap := &rcu.ConfigSnapshot{
		SchemaVersion: "2.0.0",
		TenantID:      "ten_01",
		VersionID:     "ver_1",
		VersionNumber: 1,
		Routes: []rcu.RouteConfig{
			{
				RouteID:                       "rt_gpt",
				TenantID:                      "ten_01",
				RouteType:                     "llm",
				ModelName:                     "gpt-4o",
				PathPattern:                   "/models/gpt-4o",
				PricingType:                   "per_token",
				PromptTokenPriceBaseUnits:     1000,
				CompletionTokenPriceBaseUnits: 2000,
				Status:                        "active",
				UpstreamURL:                   "https://api.openai.com/v1",
				AllowedPaymentMethods:         "wallet",
				IsPublic:                      true,
			},
		},
	}
	rcuMgr, _ := rcu.NewManager(snap)

	walletSvc := wallet.NewMemoryService()
	walletID := "wlt_test_llm"
	w := &wallet.Wallet{
		WalletID:       walletID,
		TenantID:       "ten_01",
		Asset:          "CNY",
		Status:         wallet.StatusActive,
		Version:        1,
		AvailableCache: 1000000,
		HeldCache:      0,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
	walletSvc.RegisterWallet(w)
	apiKey := "apk_test_secret"
	walletSvc.RegisterAPIKey(apiKey, "ten_01", "prj_01")

	handler := NewChatCompletionHandler(ChatHandlerConfig{
		RCUMgr:    rcuMgr,
		Metrics:   metrics.New(),
		WalletSvc: walletSvc,
		Transport: mockTransport,
	})

	reqBody := `{"model": "gpt-4o", "messages": [{"role": "user", "content": "Hi"}], "stream": true}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// 1. Verify upstream received stream_options: {"include_usage": true}
	var upstreamJSON map[string]interface{}
	if err := json.Unmarshal(upstreamReceivedBody, &upstreamJSON); err != nil {
		t.Fatalf("failed to parse upstream body: %v", err)
	}
	streamOpts, ok := upstreamJSON["stream_options"].(map[string]interface{})
	if !ok || streamOpts["include_usage"] != true {
		t.Fatalf("expected stream_options.include_usage=true, got: %v", upstreamJSON["stream_options"])
	}

	// 2. Verify wallet balance was atomically settled via CaptureFundsWithAmount (held returned to 0)
	walletAfter, _ := walletSvc.GetWallet(context.Background(), walletID)
	if walletAfter.HeldCache != 0 {
		t.Fatalf("expected held_cache=0, got %d", walletAfter.HeldCache)
	}
	// actualCost: (10 prompt * 1000)/1000 + (20 completion * 2000)/1000 = 10 + 40 = 50
	expectedAvailable := int64(1000000 - 50)
	if walletAfter.AvailableCache != expectedAvailable {
		t.Fatalf("expected available_cache=%d, got %d", expectedAvailable, walletAfter.AvailableCache)
	}
}
