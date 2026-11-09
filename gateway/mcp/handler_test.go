package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/open-agentpay/agent-core-sdk/gateway/agent"
	"github.com/open-agentpay/agent-core-sdk/gateway/rcu"
)

type mockRCUReader struct {
	snapshot *rcu.ConfigSnapshot
}

func (m *mockRCUReader) Current() *rcu.ConfigSnapshot {
	return m.snapshot
}

type mockPolicyEvaluator struct {
	allow      bool
	reasonCode string
	reason     string
}

func (m *mockPolicyEvaluator) EvaluatePolicy(ctx context.Context, req *agent.PolicyRequest) agent.PolicyDecision {
	return agent.PolicyDecision{
		Allowed:    m.allow,
		ReasonCode: m.reasonCode,
		Reason:     m.reason,
	}
}

type mockSpendRecorder struct {
	recorded []*agent.SpendRecord
}

func (m *mockSpendRecorder) RecordSpend(ctx context.Context, record *agent.SpendRecord) error {
	m.recorded = append(m.recorded, record)
	return nil
}

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func setupTestHandler(evaluator agent.PolicyEvaluator, recorder agent.SpendRecorder, transport http.RoundTripper) *Handler {
	snapshot := &rcu.ConfigSnapshot{
		TenantID: "ten_test",
		Routes: []rcu.RouteConfig{
			{
				RouteID:        "rt_stock_quote",
				PathPattern:    "/v1/tools/stock",
				UpstreamURL:    "http://upstream-stock/api",
				PriceBaseUnits: 50000, // ¥0.05
				Asset:          "CNY",
				ProjectID:      "prj_fin",
			},
			{
				RouteID:        "rt_weather",
				PathPattern:    "/v1/tools/weather",
				UpstreamURL:    "http://upstream-weather/api",
				PriceBaseUnits: 10000, // ¥0.01
				Asset:          "CNY",
				ProjectID:      "prj_fin",
			},
		},
	}
	reader := &mockRCUReader{snapshot: snapshot}
	return NewHandler(reader, nil, evaluator, recorder, transport)
}

func TestMCP_SSE_Handshake(t *testing.T) {
	h := setupTestHandler(nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req := httptest.NewRequest(http.MethodGet, "/v1/mcp/sse?route_id=rt_stock_quote", nil).WithContext(ctx)
	req.Header.Set("Accept", "text/event-stream")

	w := httptest.NewRecorder()

	go func() {
		// Wait brief moment and cancel to end stream
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	h.ServeHTTP(w, req)

	resp := w.Result()
	if resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("expected Content-Type text/event-stream, got %s", resp.Header.Get("Content-Type"))
	}

	body := w.Body.String()
	if !strings.Contains(body, "event: endpoint") {
		t.Fatalf("expected endpoint event in body, got: %s", body)
	}
	if !strings.Contains(body, "/v1/mcp/messages?sessionId=") {
		t.Fatalf("expected session endpoint URL in body, got: %s", body)
	}
}

func TestMCP_Initialize(t *testing.T) {
	h := setupTestHandler(nil, nil, nil)

	initReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"clientInfo": map[string]interface{}{
				"name":    "WorkBuddy",
				"version": "1.0.0",
			},
		},
	}
	body, _ := json.Marshal(initReq)

	req := httptest.NewRequest(http.MethodPost, "/v1/mcp/messages", bytes.NewReader(body))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	var resp JSONRPCResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal JSON-RPC response: %v", err)
	}

	resMap, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map result, got %T", resp.Result)
	}
	if resMap["protocolVersion"] != "2024-11-05" {
		t.Errorf("unexpected protocolVersion: %v", resMap["protocolVersion"])
	}
}

func TestMCP_ToolsList_WithPricingMetadata(t *testing.T) {
	h := setupTestHandler(nil, nil, nil)

	listReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
	}
	body, _ := json.Marshal(listReq)

	req := httptest.NewRequest(http.MethodPost, "/v1/mcp/messages", bytes.NewReader(body))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	var resp struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Result  struct {
			Tools []ToolDefinition `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse tools/list response: %v", err)
	}

	if len(resp.Result.Tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(resp.Result.Tools))
	}

	tool := resp.Result.Tools[0]
	if tool.Name != "rt_stock_quote" {
		t.Errorf("expected rt_stock_quote, got %s", tool.Name)
	}
	if tool.AgentPay == nil || tool.AgentPay["price_cny"] != "0.05" {
		t.Errorf("expected price_cny 0.05, got %v", tool.AgentPay)
	}
}

func TestMCP_ToolsCall_SuccessAndSpendCommitted(t *testing.T) {
	mockTransport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		respBody := `{"symbol": "600519", "price": 1688.00}`
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(respBody)),
			Header:     make(http.Header),
		}, nil
	})

	eval := &mockPolicyEvaluator{allow: true, reasonCode: "ALLOW", reason: "Budget sufficient"}
	recorder := &mockSpendRecorder{}
	h := setupTestHandler(eval, recorder, mockTransport)

	callReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "rt_stock_quote",
			"arguments": map[string]interface{}{
				"symbol": "600519",
			},
		},
	}
	body, _ := json.Marshal(callReq)

	req := httptest.NewRequest(http.MethodPost, "/v1/mcp/messages", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer apk_live_test_123")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	var resp struct {
		JSONRPC string         `json:"jsonrpc"`
		ID      int            `json:"id"`
		Result  ToolCallResult `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse tools/call response: %v", err)
	}

	if resp.Result.IsError {
		t.Fatalf("expected isError=false, got true: %v", resp.Result.Content)
	}
	if len(resp.Result.Content) == 0 || !strings.Contains(resp.Result.Content[0].Text, "1688.00") {
		t.Errorf("unexpected content: %v", resp.Result.Content)
	}

	// Verify SpendRecorder committed transaction
	if len(recorder.recorded) != 1 {
		t.Fatalf("expected 1 recorded transaction, got %d", len(recorder.recorded))
	}
	rec := recorder.recorded[0]
	if rec.AmountBase != 50000 || rec.RouteID != "rt_stock_quote" {
		t.Errorf("unexpected record: %+v", rec)
	}
}

func TestMCP_ToolsCall_PolicyDeniedReturnsLLMFriendlyError(t *testing.T) {
	eval := &mockPolicyEvaluator{
		allow:      false,
		reasonCode: "SINGLE_TX_CAP_EXCEEDED",
		reason:     "Single call cost exceeds project hard cap",
	}
	recorder := &mockSpendRecorder{}
	h := setupTestHandler(eval, recorder, nil)

	callReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      4,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "rt_stock_quote",
			"arguments": map[string]interface{}{
				"symbol": "600519",
			},
		},
	}
	body, _ := json.Marshal(callReq)

	req := httptest.NewRequest(http.MethodPost, "/v1/mcp/messages", bytes.NewReader(body))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	var resp struct {
		JSONRPC string         `json:"jsonrpc"`
		ID      int            `json:"id"`
		Result  ToolCallResult `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse tools/call response: %v", err)
	}

	if !resp.Result.IsError {
		t.Fatalf("expected isError=true for policy violation")
	}
	if len(resp.Result.Content) == 0 || !strings.Contains(resp.Result.Content[0].Text, "【AgentFinOps 财务防火墙拦截】") {
		t.Errorf("expected financial firewall denial message, got: %v", resp.Result.Content)
	}

	// No spend committed
	if len(recorder.recorded) != 0 {
		t.Errorf("expected 0 recorded spend on denial, got %d", len(recorder.recorded))
	}
}

func TestMCP_ToolsCall_UpstreamFailureReleasesHold(t *testing.T) {
	mockTransport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("connection refused to upstream host")
	})

	eval := &mockPolicyEvaluator{allow: true, reasonCode: "ALLOW", reason: "OK"}
	recorder := &mockSpendRecorder{}
	h := setupTestHandler(eval, recorder, mockTransport)

	callReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      5,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "rt_stock_quote",
			"arguments": map[string]interface{}{
				"symbol": "600519",
			},
		},
	}
	body, _ := json.Marshal(callReq)

	req := httptest.NewRequest(http.MethodPost, "/v1/mcp/messages", bytes.NewReader(body))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	var resp struct {
		JSONRPC string         `json:"jsonrpc"`
		ID      int            `json:"id"`
		Result  ToolCallResult `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse tools/call response: %v", err)
	}

	if !resp.Result.IsError {
		t.Fatalf("expected isError=true on upstream failure")
	}
	if len(resp.Result.Content) == 0 || !strings.Contains(resp.Result.Content[0].Text, "已自动解冻释放预扣额度") {
		t.Errorf("expected auto release notice in message, got: %v", resp.Result.Content)
	}

	// Zero spend committed
	if len(recorder.recorded) != 0 {
		t.Errorf("expected 0 recorded spend on failure, got %d", len(recorder.recorded))
	}
}
