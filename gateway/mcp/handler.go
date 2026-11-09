// Package mcp implements standard Model Context Protocol (MCP) SSE and JSON-RPC
// transparent proxy routing for AgentPay Go Gateway.
// Enables external Agent Harnesses (e.g., Tencent WorkBuddy, Cursor, Claude Desktop)
// to connect directly to registered routes as MCP Tools with automatic pricing metadata
// and real-time financial firewall interception (Hold & Capture).
package mcp

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/open-agentpay/agent-core-sdk/gateway/agent"
	"github.com/open-agentpay/agent-core-sdk/gateway/metrics"
	"github.com/open-agentpay/agent-core-sdk/gateway/payment"
	"github.com/open-agentpay/agent-core-sdk/gateway/rcu"
	"github.com/open-agentpay/agent-core-sdk/gateway/wallet"
)

// SnapshotReader abstracts retrieval of current configuration snapshot.
type SnapshotReader interface {
	Current() *rcu.ConfigSnapshot
}

// JSONRPCRequest represents an incoming MCP JSON-RPC 2.0 message.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCResponse represents an outgoing MCP JSON-RPC 2.0 response.
type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
}

// JSONRPCError represents a standard JSON-RPC error.
type JSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// ToolDefinition represents an MCP Tool in tools/list response.
type ToolDefinition struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	InputSchema map[string]interface{} `json:"inputSchema"`
	AgentPay    map[string]interface{} `json:"_agentpay,omitempty"`
	FinOps      map[string]interface{} `json:"_finops,omitempty"`
}

// ToolCallParams represents parameters for tools/call.
type ToolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

// ToolCallContentItem represents a single content piece in tools/call result.
type ToolCallContentItem struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// ToolCallResult represents the result payload of tools/call.
type ToolCallResult struct {
	Content []ToolCallContentItem `json:"content"`
	IsError bool                  `json:"isError,omitempty"`
}

// Handler handles MCP SSE connections and JSON-RPC dispatching.
type Handler struct {
	rcuMgr         SnapshotReader
	metrics        *metrics.Metrics
	evaluator      agent.PolicyEvaluator
	recorder       agent.SpendRecorder
	paymentService payment.Service
	walletService  wallet.Service
	transport      http.RoundTripper

	sessionsMu sync.RWMutex
	sessions   map[string]*sessionInfo
}

// SetPaymentService injects optional payment persistence service for audit correlation.
func (h *Handler) SetPaymentService(svc payment.Service) {
	h.paymentService = svc
}

// SetWalletService injects optional wallet resolution service.
func (h *Handler) SetWalletService(svc wallet.Service) {
	h.walletService = svc
}

type sessionInfo struct {
	sessionID string
	routeID   string
	apiKey    string
	createdAt time.Time
}

// NewHandler creates a new MCP transparent proxy handler.
func NewHandler(
	rcuMgr SnapshotReader,
	m *metrics.Metrics,
	evaluator agent.PolicyEvaluator,
	recorder agent.SpendRecorder,
	transport http.RoundTripper,
) *Handler {
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &Handler{
		rcuMgr:    rcuMgr,
		metrics:   m,
		evaluator: evaluator,
		recorder:  recorder,
		transport: transport,
		sessions:  make(map[string]*sessionInfo),
	}
}

// ServeHTTP handles both GET (SSE stream establishment) and POST (JSON-RPC messages).
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// CORS Headers for browser & desktop webview integration
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-AgentPay-Key, X-Agent-ID, X-Department-ID")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	path := r.URL.Path
	if r.Method == http.MethodGet || (r.Method == http.MethodPost && strings.HasSuffix(path, "/sse") && r.Header.Get("Accept") == "text/event-stream") {
		h.handleSSE(w, r)
		return
	}

	if r.Method == http.MethodPost {
		h.handleMessages(w, r)
		return
	}

	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

// handleSSE sets up standard MCP SSE streaming.
func (h *Handler) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	sessionID := generateSessionID()
	routeID := extractRouteIdentifier(r)
	apiKey := extractAPIKey(r)

	h.sessionsMu.Lock()
	h.sessions[sessionID] = &sessionInfo{
		sessionID: sessionID,
		routeID:   routeID,
		apiKey:    apiKey,
		createdAt: time.Now(),
	}
	h.sessionsMu.Unlock()

	defer func() {
		h.sessionsMu.Lock()
		delete(h.sessions, sessionID)
		h.sessionsMu.Unlock()
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	// Send initial endpoint event as required by MCP SSE Transport Spec
	endpointURL := fmt.Sprintf("/v1/mcp/messages?sessionId=%s", sessionID)
	if routeID != "" {
		endpointURL += fmt.Sprintf("&route_id=%s", routeID)
	}

	fmt.Fprintf(w, "event: endpoint\r\ndata: %s\r\n\r\n", endpointURL)
	flusher.Flush()

	// Keep stream alive until client disconnects
	<-r.Context().Done()
}

// handleMessages handles MCP JSON-RPC 2.0 messages.
func (h *Handler) handleMessages(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.writeError(w, nil, -32700, "Parse error reading request body")
		return
	}

	var req JSONRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		h.writeError(w, nil, -32700, "Parse error invalid JSON")
		return
	}

	routeID := extractRouteIdentifier(r)
	sessionID := r.URL.Query().Get("sessionId")
	apiKey := extractAPIKey(r)
	if apiKey == "" && sessionID != "" {
		h.sessionsMu.RLock()
		if sess, exists := h.sessions[sessionID]; exists {
			apiKey = sess.apiKey
			if routeID == "" {
				routeID = sess.routeID
			}
		}
		h.sessionsMu.RUnlock()
	}

	switch req.Method {
	case "initialize":
		h.handleInitialize(w, req)
	case "notifications/initialized":
		w.WriteHeader(http.StatusOK)
	case "tools/list":
		h.handleToolsList(w, req, routeID)
	case "tools/call":
		h.handleToolsCall(w, r, req, routeID, apiKey)
	default:
		h.writeError(w, req.ID, -32601, fmt.Sprintf("Method not found: %s", req.Method))
	}
}

func (h *Handler) handleInitialize(w http.ResponseWriter, req JSONRPCRequest) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]interface{}{
				"tools": map[string]interface{}{},
			},
			"serverInfo": map[string]interface{}{
				"name":    "AgentFinOps Enterprise Gateway",
				"version": "1.0.0",
			},
		},
	}
	h.writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) handleToolsList(w http.ResponseWriter, req JSONRPCRequest, filterRouteID string) {
	snapshot := h.rcuMgr.Current()
	var tools []ToolDefinition

	for _, route := range snapshot.Routes {
		if !matchRoute(&route, filterRouteID) {
			continue
		}
		rID := route.RouteID
		if rID == "" {
			rID = route.RouteIDSnake
		}

		priceUnits := route.PriceBaseUnits
		priceCny := fmt.Sprintf("%.2f", float64(priceUnits)/1000000.0)
		toolName := sanitizeToolName(rID)

		metadata := map[string]interface{}{
			"price_base_units": priceUnits,
			"price_cny":        priceCny,
			"currency":         route.Asset,
			"single_tx_cap":    50000000,
			"hitl_required":    false,
		}

		tools = append(tools, ToolDefinition{
			Name:        toolName,
			Description: fmt.Sprintf("AgentFinOps 纳管工具 [%s] (资费: ¥%s/次, 端点: %s)", toolName, priceCny, route.PathPattern),
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"payload": map[string]interface{}{
						"type":        "object",
						"description": "JSON 参数负载，透传至后端服务",
					},
				},
			},
			AgentPay: metadata,
			FinOps:   metadata,
		})
	}

	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"tools": tools,
		},
	}
	h.writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) handleToolsCall(
	w http.ResponseWriter,
	r *http.Request,
	req JSONRPCRequest,
	defaultRouteID string,
	apiKey string,
) {
	var params ToolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		h.writeError(w, req.ID, -32602, "Invalid params for tools/call")
		return
	}

	snapshot := h.rcuMgr.Current()
	var targetRoute *rcu.RouteConfig

	// 1. Match route by name or fallback default
	for i := range snapshot.Routes {
		rt := &snapshot.Routes[i]
		rID := rt.RouteID
		if rID == "" {
			rID = rt.RouteIDSnake
		}
		if matchRoute(rt, params.Name) || (defaultRouteID != "" && matchRoute(rt, defaultRouteID)) {
			targetRoute = rt
			break
		}
	}

	if targetRoute == nil {
		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: ToolCallResult{
				IsError: true,
				Content: []ToolCallContentItem{
					{
						Type: "text",
						Text: fmt.Sprintf("【AgentFinOps 路由错误】未找到对应工具或路由: %s", params.Name),
					},
				},
			},
		}
		h.writeJSON(w, http.StatusOK, resp)
		return
	}

	// 2. Extract Organization & Agent Context
	agentID := r.Header.Get("X-Agent-ID")
	if agentID == "" {
		agentID = "mcp_client_agent"
	}
	deptID := r.Header.Get("X-Department-ID")
	tenantID := targetRoute.TenantID
	if tenantID == "" {
		tenantID = targetRoute.TenantIDSnake
	}
	if tenantID == "" {
		tenantID = snapshot.TenantID
	}
	projectID := targetRoute.ProjectID
	if projectID == "" {
		projectID = targetRoute.ProjectIDSnake
	}

	isSandboxGuest := strings.HasPrefix(apiKey, "apk_live_guest_")

	if h.walletService != nil && apiKey != "" {
		if wAcc, err := h.walletService.GetWalletByAPIKey(r.Context(), apiKey); err == nil && wAcc != nil {
			tenantID = wAcc.TenantID
			if wAcc.ProjectID != "" {
				projectID = wAcc.ProjectID
			}
			if wAcc.AgentID != "" {
				agentID = wAcc.AgentID
			}
			if wAcc.TenantID != "ten_public_sandbox" && wAcc.TenantID != "" {
				isSandboxGuest = false
			}
		}
	}

	costUnits := targetRoute.PriceBaseUnits
	costCny := fmt.Sprintf("%.2f", float64(costUnits)/1000000.0)

	// 3. Pre-call Financial Firewall Evaluation (Hold)
	if h.evaluator != nil {
		policyReq := &agent.PolicyRequest{
			Agent: &agent.AgentIdentity{
				AgentID:   agentID,
				TenantID:  tenantID,
				ProjectID: projectID,
				Status:    agent.AgentStatusActive,
			},
			RouteID:    targetRoute.RouteID,
			RoutePath:  targetRoute.PathPattern,
			AmountBase: costUnits,
			Currency:   targetRoute.Asset,
			Metadata: map[string]interface{}{
				"tool_name":     params.Name,
				"api_key":       apiKey,
				"department_id": deptID,
				"source_mcp":    true,
			},
		}

		decision := h.evaluator.EvaluatePolicy(r.Context(), policyReq)
		if !decision.Allowed {
			// Return LLM-friendly denial message so autonomous agents don't enter an infinite retry loop
			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: ToolCallResult{
					IsError: true,
					Content: []ToolCallContentItem{
						{
							Type: "text",
							Text: fmt.Sprintf("【AgentFinOps 财务防火墙拦截】工具 [%s] 预估费用 ¥%s 超出组织预算或单笔限额: %s (%s)。请联系管理员提升预算或切换低成本方案。", params.Name, costCny, decision.Reason, decision.ReasonCode),
						},
					},
				},
			}
			h.writeJSON(w, http.StatusOK, resp)
			return
		}
	}

	// 3.1 Trial Key Safeguard: only restrict guest trial keys still in public sandbox
	if isSandboxGuest {
		if !targetRoute.TrialAllowed() {
			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: ToolCallResult{
					IsError: true,
					Content: []ToolCallContentItem{
						{
							Type: "text",
							Text: fmt.Sprintf("【AgentFinOps 试用限制】工具 [%s] 已关闭免密试用体验，请访问 https://console.aipmedia.cn 获取正式企业 Key。", params.Name),
						},
					},
				},
			}
			h.writeJSON(w, http.StatusOK, resp)
			return
		}
		if costUnits > 500000 {
			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: ToolCallResult{
					IsError: true,
					Content: []ToolCallContentItem{
						{
							Type: "text",
							Text: fmt.Sprintf("【AgentFinOps 体验限制】工具 [%s] 属于高价值商业接口 (¥%s/次)。免注册试用 Key 单笔最高支持 ¥0.50，请访问 https://console.aipmedia.cn 获取正式企业 Key 并充值体验。", params.Name, costCny),
						},
					},
				},
			}
			h.writeJSON(w, http.StatusOK, resp)
			return
		}
	}

	// 4. Safe Upstream Execution (Zero financial loss on error)
	holdID := generateHoldID()
	upstreamPayload, _ := json.Marshal(params.Arguments)
	upstreamURL := targetRoute.UpstreamURL
	if upstreamURL == "" {
		upstreamURL = targetRoute.UpstreamURLSnake
	}

	upstreamReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, upstreamURL, bytes.NewReader(upstreamPayload))
	if err != nil {
		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: ToolCallResult{
				IsError: true,
				Content: []ToolCallContentItem{
					{
						Type: "text",
						Text: fmt.Sprintf("创建上游请求失败: %v。已自动释放预扣额度。", err),
					},
				},
			},
		}
		h.writeJSON(w, http.StatusOK, resp)
		return
	}

	upstreamReq.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		upstreamReq.Header.Set("Authorization", "Bearer "+apiKey)
	}

	client := &http.Client{
		Transport: h.transport,
		Timeout:   30 * time.Second,
	}

	upstreamResp, err := client.Do(upstreamReq)
	if err != nil {
		// Network error / timeout -> Release hold, zero financial loss
		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: ToolCallResult{
				IsError: true,
				Content: []ToolCallContentItem{
					{
						Type: "text",
						Text: fmt.Sprintf("上游服务调用异常或超时: %v。已自动解冻释放预扣额度 ¥%s，无资金损失。", err, costCny),
					},
				},
			},
		}
		h.writeJSON(w, http.StatusOK, resp)
		return
	}
	defer upstreamResp.Body.Close()

	respBody, _ := io.ReadAll(upstreamResp.Body)

	if upstreamResp.StatusCode >= 400 {
		// Upstream returned HTTP error -> Release hold
		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: ToolCallResult{
				IsError: true,
				Content: []ToolCallContentItem{
					{
						Type: "text",
						Text: fmt.Sprintf("上游服务返回错误状态码 %d: %s。已自动解冻释放预扣额度。", upstreamResp.StatusCode, string(respBody)),
					},
				},
			},
		}
		h.writeJSON(w, http.StatusOK, resp)
		return
	}

	// 5. Upstream Succeeded -> Commit expenditure (Capture)
	if h.recorder != nil {
		_ = h.recorder.RecordSpend(r.Context(), &agent.SpendRecord{
			TenantID:   tenantID,
			ProjectID:  projectID,
			AgentID:    agentID,
			RouteID:    targetRoute.RouteID,
			AmountBase: costUnits,
			Currency:   targetRoute.Asset,
			HoldID:     holdID,
			CapturedAt: time.Now().Unix(),
			Metadata: map[string]interface{}{
				"tool_name": params.Name,
				"status":    "committed",
			},
		})
	}
	if h.paymentService != nil {
		intentID := "pi_mcp_" + holdID
		reqID := fmt.Sprintf("req_mcp_%d", time.Now().UnixNano())
		asset := targetRoute.Asset
		if asset == "" {
			asset = "CNY"
		}
		verID := snapshot.VersionID
		if verID == "" {
			verID = "ver_1"
		}
		pID := projectID
		if pID == "" {
			pID = "prj_default"
		}
		intent := &payment.PaymentIntent{
			IntentID:        intentID,
			TenantID:        tenantID,
			ProjectID:       pID,
			AgentID:         agentID,
			RouteID:         targetRoute.RouteID,
			RequestID:       reqID,
			PaymentMethod:   "wallet",
			AmountBaseUnits: costUnits,
			Asset:           asset,
			Status:          payment.IntentStatusCompleted,
			ConfigVersionID: verID,
			CreatedAt:       time.Now(),
			UpdatedAt:       time.Now(),
		}
		_ = h.paymentService.CreateIntent(r.Context(), intent)
	}

	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: ToolCallResult{
			IsError: false,
			Content: []ToolCallContentItem{
				{
					Type: "text",
					Text: string(respBody),
				},
			},
		},
	}
	h.writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *Handler) writeError(w http.ResponseWriter, id interface{}, code int, message string) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &JSONRPCError{
			Code:    code,
			Message: message,
		},
	}
	h.writeJSON(w, http.StatusOK, resp)
}

func extractAPIKey(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	if k := r.Header.Get("X-AgentPay-Key"); k != "" {
		return strings.TrimSpace(k)
	}
	if k := r.Header.Get("X-API-Key"); k != "" {
		return strings.TrimSpace(k)
	}
	if k := r.URL.Query().Get("apiKey"); k != "" {
		return strings.TrimSpace(k)
	}
	if k := r.URL.Query().Get("key"); k != "" {
		return strings.TrimSpace(k)
	}
	if k := r.URL.Query().Get("api_key"); k != "" {
		return strings.TrimSpace(k)
	}
	return ""
}

func sanitizeToolName(name string) string {
	replacer := strings.NewReplacer("-", "_", "/", "_", ".", "_")
	cleaned := replacer.Replace(strings.Trim(name, "/"))
	if cleaned == "" {
		return "tool"
	}
	return cleaned
}

func generateSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func generateHoldID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "hld_" + hex.EncodeToString(b)
}

func extractRouteIdentifier(r *http.Request) string {
	if val := r.URL.Query().Get("route_id"); val != "" {
		return strings.TrimSpace(val)
	}
	if val := r.URL.Query().Get("route"); val != "" {
		return strings.TrimSpace(val)
	}
	if val := r.URL.Query().Get("slug"); val != "" {
		return strings.TrimSpace(val)
	}
	return ""
}

func matchRoute(route *rcu.RouteConfig, identifier string) bool {
	if identifier == "" {
		return true
	}
	cleanID := strings.TrimSpace(identifier)
	rID := route.RouteID
	if rID == "" {
		rID = route.RouteIDSnake
	}
	if rID == cleanID || sanitizeToolName(rID) == sanitizeToolName(cleanID) {
		return true
	}
	if route.PathPattern == cleanID || strings.TrimPrefix(route.PathPattern, "/") == strings.TrimPrefix(cleanID, "/") {
		return true
	}
	return false
}
