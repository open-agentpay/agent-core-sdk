package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/open-agentpay/agent-core-sdk/gateway/admin"
	"github.com/open-agentpay/agent-core-sdk/gateway/metrics"
	"github.com/open-agentpay/agent-core-sdk/gateway/proxy"
	"github.com/open-agentpay/agent-core-sdk/gateway/rcu"
	"github.com/open-agentpay/agent-core-sdk/gateway/settlement"
	"github.com/open-agentpay/agent-core-sdk/gateway/upstreamauth"
	"github.com/open-agentpay/agent-core-sdk/gateway/wallet"
)

// ChatHandlerConfig configures the ChatCompletionHandler.
type ChatHandlerConfig struct {
	RCUMgr     *rcu.Manager
	Metrics    *metrics.Metrics
	AdminSvc   admin.Service
	WalletSvc  wallet.Service
	RingBuffer *settlement.LedgerRingBuffer
	Transport  http.RoundTripper
}

// ChatCompletionHandler serves standard OpenAI-compatible /v1/chat/completions and /v1/models endpoints.
type ChatCompletionHandler struct {
	rcuMgr     *rcu.Manager
	metrics    *metrics.Metrics
	adminSvc   admin.Service
	walletSvc  wallet.Service
	ringBuffer *settlement.LedgerRingBuffer
	transport  http.RoundTripper
}

// NewChatCompletionHandler creates a new ChatCompletionHandler.
func NewChatCompletionHandler(cfg ChatHandlerConfig) *ChatCompletionHandler {
	tr := cfg.Transport
	if tr == nil {
		tr = http.DefaultTransport
	}
	return &ChatCompletionHandler{
		rcuMgr:     cfg.RCUMgr,
		metrics:    cfg.Metrics,
		adminSvc:   cfg.AdminSvc,
		walletSvc:  cfg.WalletSvc,
		ringBuffer: cfg.RingBuffer,
		transport:  tr,
	}
}

// ServeHTTP routes requests between /v1/models and /v1/chat/completions.
func (h *ChatCompletionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	switch {
	case path == "/v1/models" || strings.HasPrefix(path, "/v1/models/"):
		if r.Method != http.MethodGet {
			h.writeOpenAIError(w, http.StatusMethodNotAllowed, "Method not allowed", "invalid_request_error", "method_not_allowed")
			return
		}
		h.handleListModels(w, r)

	case path == "/v1/chat/completions":
		if r.Method != http.MethodPost {
			h.writeOpenAIError(w, http.StatusMethodNotAllowed, "Method not allowed", "invalid_request_error", "method_not_allowed")
			return
		}
		h.handleChatCompletions(w, r)

	default:
		h.writeOpenAIError(w, http.StatusNotFound, "Endpoint not found", "invalid_request_error", "not_found")
	}
}

type openAIModelItem struct {
	ID         string        `json:"id"`
	Object     string        `json:"object"`
	Created    int64         `json:"created"`
	OwnedBy    string        `json:"owned_by"`
	Permission []interface{} `json:"permission"`
	Root       string        `json:"root"`
}

type openAIModelListResponse struct {
	Object string            `json:"object"`
	Data   []openAIModelItem `json:"data"`
}

func (h *ChatCompletionHandler) handleListModels(w http.ResponseWriter, r *http.Request) {
	tenantID := h.extractTenantID(r)

	models := h.rcuMgr.ListLLMModelsForTenant(tenantID)
	items := make([]openAIModelItem, 0, len(models))

	for _, m := range models {
		modelName := m.ModelName
		if modelName == "" {
			modelName = m.ModelNameSnake
		}
		if modelName == "" {
			continue
		}
		ownedBy := "system"
		if m.ModelMetadata != nil {
			if p, ok := m.ModelMetadata["provider"].(string); ok && p != "" {
				ownedBy = p
			}
		}

		items = append(items, openAIModelItem{
			ID:         modelName,
			Object:     "model",
			Created:    1700000000,
			OwnedBy:    ownedBy,
			Permission: []interface{}{},
			Root:       modelName,
		})
	}

	writeJSON(w, http.StatusOK, openAIModelListResponse{
		Object: "list",
		Data:   items,
	})
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatCompletionRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Stream      bool          `json:"stream,omitempty"`
	MaxTokens   int64         `json:"max_tokens,omitempty"`
	Temperature *float64      `json:"temperature,omitempty"`
}

func (h *ChatCompletionHandler) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	tenantID := h.extractTenantID(r)

	rawBody, err := io.ReadAll(r.Body)
	if err != nil {
		h.writeOpenAIError(w, http.StatusBadRequest, "Failed to read request body", "invalid_request_error", "bad_request")
		return
	}
	defer r.Body.Close()

	var req chatCompletionRequest
	if err := json.Unmarshal(rawBody, &req); err != nil {
		h.writeOpenAIError(w, http.StatusBadRequest, "Invalid JSON payload in request", "invalid_request_error", "invalid_payload")
		return
	}
	if req.Model == "" {
		h.writeOpenAIError(w, http.StatusBadRequest, "Missing 'model' field in request", "invalid_request_error", "missing_required_field")
		return
	}

	// 1. Match route in RCU
	route, _, _, ok := h.rcuMgr.GetLLMRouteForTenant(tenantID, req.Model)
	if !ok || route == nil {
		h.writeOpenAIError(w, http.StatusNotFound, fmt.Sprintf("Model '%s' does not exist or is not active", req.Model), "invalid_request_error", "model_not_found")
		return
	}

	// 2. Pre-flight Token & Cost Estimation
	var promptChars int
	for _, m := range req.Messages {
		promptChars += len(m.Content)
	}
	estimatedPromptTokens := int64((promptChars + 3) / 4)
	if estimatedPromptTokens < 1 {
		estimatedPromptTokens = 1
	}

	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 1024
	}
	if maxTokens > 4096 {
		maxTokens = 4096
	}

	promptPrice := route.PromptTokenPriceBaseUnits
	if promptPrice == 0 {
		promptPrice = route.PromptTokenPriceSnake
	}
	completionPrice := route.CompletionTokenPriceBaseUnits
	if completionPrice == 0 {
		completionPrice = route.CompletionTokenPriceSnake
	}

	promptCost := (estimatedPromptTokens * promptPrice) / 1000
	completionCost := (maxTokens * completionPrice) / 1000
	estimatedHold := promptCost + completionCost
	if estimatedHold <= 0 {
		estimatedHold = 1000 // 0.001 CNY minimum hold
	}

	// 3. Prepare Upstream Request
	targetURL := route.UpstreamURL
	if !strings.HasSuffix(targetURL, "/chat/completions") {
		if strings.HasSuffix(targetURL, "/") {
			targetURL += "chat/completions"
		} else {
			targetURL += "/chat/completions"
		}
	}

	upstreamReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, targetURL, bytes.NewReader(rawBody))
	if err != nil {
		h.writeOpenAIError(w, http.StatusInternalServerError, "Failed to construct upstream request", "api_error", "internal_error")
		return
	}

	// Copy allowed client headers
	for k, v := range r.Header {
		if !isHopByHopHeader(k) && !strings.EqualFold(k, "Authorization") {
			upstreamReq.Header[k] = v
		}
	}
	upstreamReq.Header.Set("Content-Type", "application/json")

	// Apply Upstream Auth if configured
	authCfg := route.UpstreamAuth
	if authCfg == nil {
		authCfg = route.UpstreamAuthSnake
	}
	if authCfg != nil {
		authenticator, ok := upstreamauth.Get(authCfg.Type)
		if ok {
			_ = authenticator.Apply(r.Context(), upstreamReq, authCfg.Params, route.UpstreamSecrets)
		}
	}

	// 4. Send Upstream Request
	upstreamResp, err := h.transport.RoundTrip(upstreamReq)
	if err != nil {
		h.writeOpenAIError(w, http.StatusBadGateway, fmt.Sprintf("Failed to reach upstream model provider: %v", err), "api_error", "bad_gateway")
		return
	}
	defer upstreamResp.Body.Close()

	if upstreamResp.StatusCode >= 400 {
		// Forward error from upstream directly
		for k, v := range upstreamResp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(upstreamResp.StatusCode)
		_, _ = io.Copy(w, upstreamResp.Body)
		return
	}

	// 5. Handle Streaming vs Non-Streaming
	if req.Stream {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)

		sniffer := proxy.NewStreamSniffer(proxy.SniffOptions{
			PromptPriceBaseUnits:     promptPrice,
			CompletionPriceBaseUnits: completionPrice,
			EstimatedPromptTokens:    estimatedPromptTokens,
			MaxAllowedBudget:         estimatedHold + 5000000, // allow available cushion
		})

		res, _ := sniffer.SniffAndForward(w, upstreamResp.Body)

		// Record settlement event
		if h.ringBuffer != nil && res != nil {
			h.ringBuffer.Enqueue(&settlement.BatchSettlementEvent{
				EventID:          fmt.Sprintf("evt_%d", time.Now().UnixNano()),
				TenantID:         tenantID,
				RouteID:          route.RouteID,
				ModelName:        req.Model,
				PromptTokens:     res.PromptTokens,
				CompletionTokens: res.CompletionTokens,
				TotalTokens:      res.PromptTokens + res.CompletionTokens,
				ActualAmount:     res.TotalCost,
				CreatedAt:        time.Now(),
			})
		}
		return
	}

	// Non-streaming response handling
	respBody, err := io.ReadAll(upstreamResp.Body)
	if err != nil {
		h.writeOpenAIError(w, http.StatusBadGateway, "Failed to read upstream response body", "api_error", "bad_gateway")
		return
	}

	var parsedResp struct {
		Usage struct {
			PromptTokens     int64 `json:"prompt_tokens"`
			CompletionTokens int64 `json:"completion_tokens"`
			TotalTokens      int64 `json:"total_tokens"`
		} `json:"usage"`
	}
	actualCost := estimatedHold
	var pTok, cTok int64
	if json.Unmarshal(respBody, &parsedResp) == nil && parsedResp.Usage.TotalTokens > 0 {
		pTok = parsedResp.Usage.PromptTokens
		cTok = parsedResp.Usage.CompletionTokens
		actualCost = (pTok*promptPrice)/1000 + (cTok*completionPrice)/1000
	}

	if h.ringBuffer != nil {
		h.ringBuffer.Enqueue(&settlement.BatchSettlementEvent{
			EventID:          fmt.Sprintf("evt_%d", time.Now().UnixNano()),
			TenantID:         tenantID,
			RouteID:          route.RouteID,
			ModelName:        req.Model,
			PromptTokens:     pTok,
			CompletionTokens: cTok,
			TotalTokens:      pTok + cTok,
			ActualAmount:     actualCost,
			CreatedAt:        time.Now(),
		})
	}

	for k, v := range upstreamResp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBody)
}

func (h *ChatCompletionHandler) extractTenantID(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if h.walletSvc != nil {
			if w, err := h.walletSvc.GetWalletByAPIKey(r.Context(), token); err == nil && w != nil {
				return w.TenantID
			}
		}
	}
	return ""
}

func (h *ChatCompletionHandler) writeOpenAIError(w http.ResponseWriter, code int, message, errType, errCode string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]interface{}{
			"message": message,
			"type":    errType,
			"code":    errCode,
		},
	})
}

func isHopByHopHeader(h string) bool {
	switch strings.ToLower(h) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}
