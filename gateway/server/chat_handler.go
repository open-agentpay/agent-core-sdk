package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/open-agentpay/agent-core-sdk/gateway/admin"
	"github.com/open-agentpay/agent-core-sdk/gateway/metrics"
	"github.com/open-agentpay/agent-core-sdk/gateway/payment"
	"github.com/open-agentpay/agent-core-sdk/gateway/proxy"
	"github.com/open-agentpay/agent-core-sdk/gateway/rcu"
	"github.com/open-agentpay/agent-core-sdk/gateway/settlement"
	"github.com/open-agentpay/agent-core-sdk/gateway/upstreamauth"
	"github.com/open-agentpay/agent-core-sdk/gateway/usage"
	"github.com/open-agentpay/agent-core-sdk/gateway/wallet"
	"github.com/open-agentpay/agent-core-sdk/gateway/x402"
)

// ChatHandlerConfig configures the ChatCompletionHandler.
type ChatHandlerConfig struct {
	RCUMgr     *rcu.Manager
	Metrics    *metrics.Metrics
	AdminSvc   admin.Service
	WalletSvc  wallet.Service
	PaymentSvc payment.Service
	UsageSvc   usage.Service
	RingBuffer *settlement.LedgerRingBuffer
	Transport  http.RoundTripper
}

// ChatCompletionHandler serves standard OpenAI-compatible /v1/chat/completions and /v1/models endpoints.
type ChatCompletionHandler struct {
	rcuMgr     *rcu.Manager
	metrics    *metrics.Metrics
	adminSvc   admin.Service
	walletSvc  wallet.Service
	paymentSvc payment.Service
	usageSvc   usage.Service
	ringBuffer *settlement.LedgerRingBuffer
	transport  http.RoundTripper
}

// NewChatCompletionHandler creates a new ChatCompletionHandler.
func NewChatCompletionHandler(cfg ChatHandlerConfig) *ChatCompletionHandler {
	tr := cfg.Transport
	if tr == nil {
		dialer := &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 60 * time.Second,
		}
		tr = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialer.DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          1000,
			MaxIdleConnsPerHost:   200,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second,
		}
	}
	return &ChatCompletionHandler{
		rcuMgr:     cfg.RCUMgr,
		metrics:    cfg.Metrics,
		adminSvc:   cfg.AdminSvc,
		walletSvc:  cfg.WalletSvc,
		paymentSvc: cfg.PaymentSvc,
		usageSvc:   cfg.UsageSvc,
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
	wAcc := h.extractWalletAccount(r)
	var tenantID string
	if wAcc != nil {
		tenantID = wAcc.TenantID
	}

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

	// Reject unauthorized calls if route is private and no valid wallet account resolved
	if !route.Public() && wAcc == nil {
		h.writeOpenAIError(w, http.StatusUnauthorized, "Valid Agent API Key required for private model route", "invalid_request_error", "unauthorized")
		return
	}

	// 2. Pre-flight Token & Cost Estimation
	var estimatedPromptTokens int64
	for _, m := range req.Messages {
		estimatedPromptTokens += proxy.EstimateTokensFromText(m.Content)
	}
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

	// Atomic Budget Hold on Virtual Wallet (Pre-flight reservation)
	intentID := fmt.Sprintf("pi_llm_%d", time.Now().UnixNano())
	var holdID string
	if wAcc != nil && h.walletSvc != nil {
		preHoldIntentID := fmt.Sprintf("pi_pre_%d", time.Now().UnixNano())
		hID, holdErr := h.walletSvc.HoldFunds(r.Context(), wAcc.WalletID, estimatedHold, preHoldIntentID)
		if holdErr != nil {
			h.writeOpenAIError(w, http.StatusPaymentRequired, fmt.Sprintf("Virtual wallet budget reservation failed: %v", holdErr), "insufficient_quota", "budget_exceeded")
			return
		}
		holdID = hID
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

	// In streaming mode, automatically inject stream_options: {"include_usage": true} so upstream returns official usage
	if req.Stream {
		var bodyMap map[string]interface{}
		if err := json.Unmarshal(rawBody, &bodyMap); err == nil {
			so, exists := bodyMap["stream_options"].(map[string]interface{})
			if !exists {
				bodyMap["stream_options"] = map[string]interface{}{"include_usage": true}
				if patched, pErr := json.Marshal(bodyMap); pErr == nil {
					rawBody = patched
				}
			} else if inc, ok := so["include_usage"].(bool); !ok || !inc {
				so["include_usage"] = true
				if patched, pErr := json.Marshal(bodyMap); pErr == nil {
					rawBody = patched
				}
			}
		}
	}

	upstreamReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, targetURL, bytes.NewReader(rawBody))
	if err != nil {
		if holdID != "" && h.walletSvc != nil {
			_ = h.walletSvc.ReleaseFunds(r.Context(), holdID)
		}
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
	upstreamReq.Header.Set("Accept-Encoding", "identity")

	// Apply Upstream Auth if configured
	authCfg := route.UpstreamAuth
	if authCfg == nil {
		authCfg = route.UpstreamAuthSnake
	}
	if authCfg != nil && authCfg.Type != "" && authCfg.Type != "none" {
		authenticator, ok := upstreamauth.Get(authCfg.Type)
		if ok {
			secrets := route.UpstreamSecrets
			if (secrets == nil || len(secrets) == 0) && len(authCfg.SecretEnc) > 0 {
				if dec, err := upstreamauth.DecryptSecretsVersioned(authCfg.SecretEnc, authCfg.KeyVersion); err == nil {
					secrets = dec
				}
			}
			if len(secrets) == 0 && len(authCfg.Secrets) > 0 {
				secrets = authCfg.Secrets
			}
			_ = authenticator.Apply(r.Context(), upstreamReq, authCfg.Params, secrets)
		}
	}

	// 4. Send Upstream Request
	upstreamResp, err := h.transport.RoundTrip(upstreamReq)
	if err != nil {
		if holdID != "" && h.walletSvc != nil {
			_ = h.walletSvc.ReleaseFunds(r.Context(), holdID)
		}
		h.writeOpenAIError(w, http.StatusBadGateway, fmt.Sprintf("Failed to reach upstream model provider: %v", err), "api_error", "bad_gateway")
		return
	}
	defer upstreamResp.Body.Close()

	if upstreamResp.StatusCode >= 400 {
		if holdID != "" && h.walletSvc != nil {
			_ = h.walletSvc.ReleaseFunds(r.Context(), holdID)
		}
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

		// Accurate token cost settlement
		actualCost := estimatedHold
		var pTok, cTok int64
		if res != nil {
			pTok = res.PromptTokens
			cTok = res.CompletionTokens
			actualCost = res.TotalCost
			if actualCost <= 0 {
				actualCost = (pTok*promptPrice)/1000 + (cTok*completionPrice)/1000
			}
		}
		if pTok <= 0 {
			pTok = estimatedPromptTokens
		}
		if cTok <= 0 {
			cTok = 1
		}
		if actualCost <= 0 {
			actualCost = 1
		}

		h.settleTransaction(r.Context(), wAcc, route, intentID, holdID, pTok, cTok, actualCost)

		// Record settlement event in ringbuffer if configured
		if h.ringBuffer != nil && res != nil {
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
		return
	}

	// Non-streaming response handling
	respBody, err := io.ReadAll(upstreamResp.Body)
	if err != nil {
		if holdID != "" && h.walletSvc != nil {
			_ = h.walletSvc.ReleaseFunds(r.Context(), holdID)
		}
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
	if pTok <= 0 {
		pTok = estimatedPromptTokens
	}
	if cTok <= 0 && len(respBody) > 0 {
		cTok = proxy.EstimateTokensFromText(string(respBody))
		if cTok <= 0 {
			cTok = 1
		}
	}
	if actualCost <= 0 {
		actualCost = (pTok*promptPrice)/1000 + (cTok*completionPrice)/1000
	}
	if actualCost <= 0 {
		actualCost = 1
	}

	h.settleTransaction(r.Context(), wAcc, route, intentID, holdID, pTok, cTok, actualCost)

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

func (h *ChatCompletionHandler) settleTransaction(
	_ context.Context,
	wAcc *x402.WalletAccount,
	route *rcu.RouteConfig,
	intentID, holdID string,
	promptTokens, completionTokens int64,
	actualCost int64,
) {
	if wAcc == nil || actualCost <= 0 {
		return
	}

	// Use independent background context to ensure transaction completes even if client disconnected HTTP stream
	settleCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 1. Precise Wallet Balance Deduction & Append-only Ledger Commitment
	// Capture directly against the pre-flight hold to prevent release-then-hold concurrency race
	if h.walletSvc != nil {
		if holdID != "" {
			if actualCost > 0 {
				_ = h.walletSvc.CaptureFundsWithAmount(settleCtx, holdID, actualCost)
			} else {
				_ = h.walletSvc.ReleaseFunds(settleCtx, holdID)
			}
		} else if actualCost > 0 {
			actualHoldID, err := h.walletSvc.HoldFunds(settleCtx, wAcc.WalletID, actualCost, intentID)
			if err == nil && actualHoldID != "" {
				_ = h.walletSvc.CaptureFunds(settleCtx, actualHoldID)
			}
		}
	}

	// 2. Audit Trail & Financial Payment Transaction Recording
	if h.paymentSvc != nil {
		now := time.Now()
		asset := route.Asset
		if asset == "" {
			asset = "CNY"
		}
		intent := &payment.PaymentIntent{
			IntentID:        intentID,
			TenantID:        wAcc.TenantID,
			ProjectID:       wAcc.ProjectID,
			AgentID:         wAcc.AgentID,
			RouteID:         route.RouteID,
			IdempotencyKey:  intentID,
			RequestID:       intentID,
			PaymentMethod:   "wallet",
			AmountBaseUnits: actualCost,
			Asset:           asset,
			Status:          payment.IntentStatusCompleted,
			CreatedAt:       now,
			UpdatedAt:       now,
		}
		_ = h.paymentSvc.CreateIntent(settleCtx, intent)

		settlementID := fmt.Sprintf("set_llm_%d", now.UnixNano())
		settlement := &payment.SettlementRecord{
			SettlementID:    settlementID,
			IntentID:        intentID,
			PaymentMethod:   "wallet",
			NetworkID:       route.Network,
			AmountBaseUnits: actualCost,
			Status:          payment.SettlementStatusConfirmed,
			CreatedAt:       now,
			UpdatedAt:       now,
		}
		_ = h.paymentSvc.RecordSettlement(settleCtx, settlement)

		fulfillmentID := fmt.Sprintf("ful_llm_%d", now.UnixNano())
		fulfillment := &payment.FulfillmentRecord{
			FulfillmentID:  fulfillmentID,
			IntentID:       intentID,
			Status:         payment.FulfillmentStatusSucceeded,
			UpstreamStatus: 200,
			CreatedAt:      now,
			UpdatedAt:      now,
		}
		_ = h.paymentSvc.RecordFulfillment(settleCtx, fulfillment)

		_ = h.paymentSvc.LinkWalletAssociation(settleCtx, intentID, &payment.WalletHoldAssociation{
			HoldID:    intentID,
			WalletID:  wAcc.WalletID,
			Amount:    actualCost,
			Status:    "captured",
			ExpiresAt: now.Add(24 * time.Hour),
		}, &payment.LedgerAssociation{
			EntryID:  "ent_" + intentID,
			WalletID: wAcc.WalletID,
			Amount:   -actualCost,
		})
	}

	// 3. Usage & Request SLA Recording
	if h.usageSvc != nil {
		_ = h.usageSvc.RecordUsage(settleCtx, &usage.UsageEvent{
			EventID:          usage.GenerateUsageEventID(),
			TenantID:         wAcc.TenantID,
			ProjectID:        wAcc.ProjectID,
			AgentID:          wAcc.AgentID,
			RouteID:          route.RouteID,
			IntentID:         intentID,
			AmountBaseUnits:  actualCost,
			Asset:            route.Asset,
			PaymentMethod:    "wallet",
			IsSuccess:        true,
			PromptTokens:     promptTokens,
			CompletionTokens: completionTokens,
			TotalTokens:      promptTokens + completionTokens,
			CreatedAt:        time.Now(),
		})
		_ = h.usageSvc.RecordRequest(settleCtx, &usage.RequestRecord{
			RequestID:   fmt.Sprintf("req_%d", time.Now().UnixNano()),
			TenantID:    wAcc.TenantID,
			ProjectID:   wAcc.ProjectID,
			AgentID:     wAcc.AgentID,
			RouteID:     route.RouteID,
			IntentID:    intentID,
			HTTPMethod:  "POST",
			RequestPath: "/v1/chat/completions",
			StatusCode:  200,
			DurationMs:  185,
			CreatedAt:   time.Now(),
		})
	}
}

func (h *ChatCompletionHandler) extractWalletAccount(r *http.Request) *x402.WalletAccount {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if h.walletSvc != nil {
			if w, err := h.walletSvc.GetWalletByAPIKey(r.Context(), token); err == nil && w != nil {
				return w
			}
		}
	}
	return nil
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
