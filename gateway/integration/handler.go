package integration

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/open-agentpay/agent-core-sdk/gateway/admin"
	"github.com/open-agentpay/agent-core-sdk/gateway/agent"
	"github.com/open-agentpay/agent-core-sdk/gateway/idempotency"
	"github.com/open-agentpay/agent-core-sdk/gateway/metrics"
	"github.com/open-agentpay/agent-core-sdk/gateway/payment"
	"github.com/open-agentpay/agent-core-sdk/gateway/rcu"
	"github.com/open-agentpay/agent-core-sdk/gateway/wallet"
	"github.com/open-agentpay/agent-core-sdk/gateway/x402"
)

// SnapshotReader abstracts retrieval of the active configuration snapshot.
type SnapshotReader interface {
	Current() *rcu.ConfigSnapshot
}

// Handler handles framework-agnostic AgentPay REST Integration API requests.
type Handler struct {
	rcuMgr           SnapshotReader
	metrics          *metrics.Metrics
	evaluator        agent.PolicyEvaluator
	recorder         agent.SpendRecorder
	paymentService   payment.Service
	walletService    wallet.Service
	idempotencyStore idempotency.Store
	adminService     admin.Service
	environment      string
}

// NewHandler creates a new Integration API handler.
func NewHandler(
	rcuMgr SnapshotReader,
	m *metrics.Metrics,
	evaluator agent.PolicyEvaluator,
	recorder agent.SpendRecorder,
	paymentSvc payment.Service,
	walletSvc wallet.Service,
	idemStore idempotency.Store,
	adminSvc admin.Service,
) *Handler {
	return &Handler{
		rcuMgr:           rcuMgr,
		metrics:          m,
		evaluator:        evaluator,
		recorder:         recorder,
		paymentService:   paymentSvc,
		walletService:    walletSvc,
		idempotencyStore: idemStore,
		adminService:     adminSvc,
		environment:      "production",
	}
}

// SetEnvironment sets the runtime environment identifier (e.g. "production", "staging").
func (h *Handler) SetEnvironment(env string) {
	if env != "" {
		h.environment = env
	}
}

// ServeHTTP dispatches requests under /api/v1/integrations/.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-AgentPay-Key, X-Agent-Key, X-Idempotency-Key")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	path := r.URL.Path
	// Strip trailing slashes for stable matching
	cleanPath := strings.TrimRight(path, "/")

	switch {
	case cleanPath == "/api/v1/integrations/payments" && r.Method == http.MethodPost:
		h.handleCreatePayment(w, r)
	case strings.HasPrefix(cleanPath, "/api/v1/integrations/payments/") && r.Method == http.MethodGet:
		h.handleGetPayment(w, r, strings.TrimPrefix(cleanPath, "/api/v1/integrations/payments/"))
	case cleanPath == "/api/v1/integrations/policies/evaluate" && r.Method == http.MethodPost:
		h.handleEvaluatePolicy(w, r)
	case cleanPath == "/api/v1/integrations/agents/me" && r.Method == http.MethodGet:
		h.handleGetAgentMe(w, r)
	default:
		h.writeError(w, http.StatusNotFound, ErrCodeInvalidRequest, fmt.Sprintf("no integration route matching %s %s", r.Method, path), "CHECK_URL")
	}
}

// handleCreatePayment executes a payment request with atomic hold and idempotency protection.
func (h *Handler) handleCreatePayment(w http.ResponseWriter, r *http.Request) {
	wAcc, err := h.authenticate(r)
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, ErrCodeUnauthenticated, err.Error(), "PROVIDE_API_KEY")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB limit
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "failed to read request body", "")
		return
	}

	var req PaymentRequest
	if err := json.Unmarshal(body, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid json payload: "+err.Error(), "")
		return
	}

	// Fallback idempotency key from header if omitted in body
	if req.IdempotencyKey == "" {
		req.IdempotencyKey = r.Header.Get("X-Idempotency-Key")
	}
	if req.IdempotencyKey == "" {
		h.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "idempotency_key is required", "")
		return
	}

	// Idempotency lock check
	requestHash := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s", wAcc.TenantID, req.Resource.ResourceID, req.Amount))))
	if h.idempotencyStore != nil {
		rec, checkRes, err := h.idempotencyStore.CheckOrLock(r.Context(), wAcc.TenantID, req.IdempotencyKey, requestHash, "", "wallet")
		if err != nil {
			h.writeError(w, http.StatusInternalServerError, ErrCodeInternalError, "idempotency check error: "+err.Error(), "")
			return
		}
		if checkRes == idempotency.ResultCacheHit && rec != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(rec.ResponseBody)
			return
		}
		if checkRes == idempotency.ResultConflict {
			h.writeError(w, http.StatusConflict, ErrCodeIdempotencyConflict, "concurrent or conflicting request with same idempotency key", "POLL_STATUS")
			return
		}
	}

	// Resolve Resource / Route
	resourceID := req.Resource.ResourceID
	var route *rcu.RouteConfig
	if h.rcuMgr != nil {
		snap := h.rcuMgr.Current()
		if snap != nil && snap.Routes != nil {
			for i := range snap.Routes {
				r := &snap.Routes[i]
				if r.RouteID == resourceID || r.RouteIDSnake == resourceID || r.PathPattern == resourceID {
					route = r
					break
				}
			}
		}
	}

	if route == nil || route.Status != "active" {
		if h.idempotencyStore != nil {
			_ = h.idempotencyStore.ReleaseLock(r.Context(), wAcc.TenantID, req.IdempotencyKey)
		}
		h.writeError(w, http.StatusNotFound, ErrCodeMerchantNotAllowed, fmt.Sprintf("target resource %q not found or inactive", resourceID), "")
		return
	}

	priceBaseUnits := route.PriceBaseUnits
	asset := route.Asset
	if asset == "" {
		asset = "USDC"
	}

	// Policy Evaluation
	if h.evaluator != nil {
		policyReq := &agent.PolicyRequest{
			Agent: &agent.AgentIdentity{
				AgentID:   wAcc.AgentID,
				TenantID:  wAcc.TenantID,
				ProjectID: wAcc.ProjectID,
				KeyID:     wAcc.APIKeyID,
				Status:    agent.AgentStatusActive,
			},
			RouteID:    route.RouteID,
			RoutePath:  route.PathPattern,
			AmountBase: priceBaseUnits,
			Currency:   asset,
		}
		decision := h.evaluator.EvaluatePolicy(r.Context(), policyReq)
		if !decision.Allowed {
			if h.idempotencyStore != nil {
				_ = h.idempotencyStore.ReleaseLock(r.Context(), wAcc.TenantID, req.IdempotencyKey)
			}
			reasonCode := decision.ReasonCode
			if reasonCode == "" {
				reasonCode = ErrCodePolicyDenied
			}
			h.writeError(w, http.StatusForbidden, reasonCode, "policy rejected: "+decision.Reason, "STOP")
			return
		}
	}

	// Generate Intent ID
	intentID := fmt.Sprintf("pi_%s", randomHex(12))

	// Atomic Budget Hold on Virtual Wallet
	if h.walletService == nil {
		if h.idempotencyStore != nil {
			_ = h.idempotencyStore.ReleaseLock(r.Context(), wAcc.TenantID, req.IdempotencyKey)
		}
		h.writeError(w, http.StatusInternalServerError, ErrCodeInternalError, "wallet service not configured", "")
		return
	}

	holdID, err := h.walletService.HoldFunds(r.Context(), wAcc.WalletID, priceBaseUnits, intentID)
	if err != nil {
		if h.idempotencyStore != nil {
			_ = h.idempotencyStore.ReleaseLock(r.Context(), wAcc.TenantID, req.IdempotencyKey)
		}
		h.writeError(w, http.StatusForbidden, ErrCodeBudgetExceeded, "insufficient funds or budget reservation failed: "+err.Error(), "INCREASE_BUDGET")
		return
	}

	// Record in Payment Service
	now := time.Now()
	if h.paymentService != nil {
		agentID := wAcc.AgentID
		if req.Context.AgentID != "" {
			agentID = req.Context.AgentID
		}
		intent := &payment.PaymentIntent{
			IntentID:        intentID,
			TenantID:        wAcc.TenantID,
			ProjectID:       wAcc.ProjectID,
			AgentID:         agentID,
			RouteID:         route.RouteID,
			IdempotencyKey:  req.IdempotencyKey,
			RequestID:       intentID,
			PaymentMethod:   "wallet",
			AmountBaseUnits: priceBaseUnits,
			Asset:           asset,
			Status:          payment.IntentStatusAuthorized,
			CreatedAt:       now,
			UpdatedAt:       now,
		}
		_ = h.paymentService.CreateIntent(r.Context(), intent)

		settlementID := fmt.Sprintf("set_%s", randomHex(12))
		settlement := &payment.SettlementRecord{
			SettlementID:    settlementID,
			IntentID:        intentID,
			PaymentMethod:   "wallet",
			NetworkID:       route.Network,
			AmountBaseUnits: priceBaseUnits,
			Status:          payment.SettlementStatusHeld,
			CreatedAt:       now,
			UpdatedAt:       now,
		}
		_ = h.paymentService.RecordSettlement(r.Context(), settlement)

		_ = h.paymentService.LinkWalletAssociation(r.Context(), intentID, &payment.WalletHoldAssociation{
			HoldID:    holdID,
			WalletID:  wAcc.WalletID,
			Amount:    priceBaseUnits,
			Status:    "held",
			ExpiresAt: now.Add(10 * time.Minute),
		}, nil)
	}

	result := PaymentResultResponse{
		PaymentIntentID:   intentID,
		Decision:          "ALLOW",
		PaymentStatus:     "AUTHORIZED",
		SettlementStatus:  "HELD",
		FulfillmentStatus: "NOT_STARTED",
		Amount:            FormatBaseUnitsToDecimal(priceBaseUnits, 6),
		Asset:             asset,
		Network:           route.Network,
		IdempotencyKey:    req.IdempotencyKey,
		NextAction:        "POLL_STATUS",
	}

	respBody, _ := json.Marshal(result)

	// Attach payment details & mark completed in idempotency store
	if h.idempotencyStore != nil {
		_ = h.idempotencyStore.AttachPaymentDetails(r.Context(), wAcc.TenantID, req.IdempotencyKey, holdID, "")
		_ = h.idempotencyStore.MarkCompleted(r.Context(), wAcc.TenantID, req.IdempotencyKey, http.StatusOK, map[string]string{"Content-Type": "application/json"}, respBody)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBody)
}

// handleGetPayment retrieves the current three-domain lifecycle status for a payment intent.
func (h *Handler) handleGetPayment(w http.ResponseWriter, r *http.Request, intentID string) {
	wAcc, err := h.authenticate(r)
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, ErrCodeUnauthenticated, err.Error(), "PROVIDE_API_KEY")
		return
	}

	if intentID == "" {
		h.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "payment_intent_id is required", "")
		return
	}

	if h.paymentService == nil {
		h.writeError(w, http.StatusInternalServerError, ErrCodeInternalError, "payment service not configured", "")
		return
	}

	intent, err := h.paymentService.GetIntent(r.Context(), intentID)
	if err != nil || intent == nil {
		h.writeError(w, http.StatusNotFound, ErrCodePaymentPending, fmt.Sprintf("payment intent %q not found", intentID), "")
		return
	}

	// Multi-tenant boundary check
	if intent.TenantID != wAcc.TenantID {
		h.writeError(w, http.StatusNotFound, ErrCodePaymentPending, fmt.Sprintf("payment intent %q not found", intentID), "")
		return
	}

	settlement, _ := h.paymentService.GetSettlementByIntent(r.Context(), intentID)
	fulfillment, _ := h.paymentService.GetFulfillmentByIntent(r.Context(), intentID)

	settlementStatus := "NOT_STARTED"
	txHash := ""
	network := ""
	if settlement != nil {
		settlementStatus = ToExternalSettlementStatus(settlement.Status)
		txHash = settlement.TxHash
		network = settlement.NetworkID
	}

	fulfillmentStatus := "NOT_STARTED"
	if fulfillment != nil {
		fulfillmentStatus = ToExternalFulfillmentStatus(fulfillment.Status)
	}

	decision := "ALLOW"
	if intent.Status == payment.IntentStatusRejected {
		decision = "DENY"
	}

	nextAction := "NONE"
	if settlementStatus == "HELD" || settlementStatus == "PENDING" || settlementStatus == "SUBMITTED" || fulfillmentStatus == "PROCESSING" {
		nextAction = "POLL_STATUS"
	}

	result := PaymentResultResponse{
		PaymentIntentID:   intent.IntentID,
		Decision:          decision,
		PaymentStatus:     ToExternalPaymentStatus(intent.Status),
		SettlementStatus:  settlementStatus,
		FulfillmentStatus: fulfillmentStatus,
		Amount:            FormatBaseUnitsToDecimal(intent.AmountBaseUnits, 6),
		Asset:             intent.Asset,
		Network:           network,
		TransactionHash:   txHash,
		IdempotencyKey:    intent.IdempotencyKey,
		NextAction:        nextAction,
	}

	h.writeJSON(w, http.StatusOK, result)
}

// handleEvaluatePolicy performs a dry-run policy evaluation without reserving funds.
func (h *Handler) handleEvaluatePolicy(w http.ResponseWriter, r *http.Request) {
	wAcc, err := h.authenticate(r)
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, ErrCodeUnauthenticated, err.Error(), "PROVIDE_API_KEY")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "failed to read body", "")
		return
	}

	var req PaymentRequest
	if err := json.Unmarshal(body, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid json: "+err.Error(), "")
		return
	}

	resourceID := req.Resource.ResourceID
	var route *rcu.RouteConfig
	if h.rcuMgr != nil {
		snap := h.rcuMgr.Current()
		if snap != nil && snap.Routes != nil {
			for i := range snap.Routes {
				r := &snap.Routes[i]
				if r.RouteID == resourceID || r.RouteIDSnake == resourceID || r.PathPattern == resourceID {
					route = r
					break
				}
			}
		}
	}

	if route == nil || route.Status != "active" {
		h.writeError(w, http.StatusNotFound, ErrCodeMerchantNotAllowed, fmt.Sprintf("target resource %q not found or inactive", resourceID), "")
		return
	}

	priceBaseUnits := route.PriceBaseUnits
	asset := route.Asset
	if asset == "" {
		asset = "USDC"
	}

	decisionResult := "ALLOW"
	reasonCode := "POLICY_PASSED"
	reason := "policy passed"

	if h.evaluator != nil {
		policyReq := &agent.PolicyRequest{
			Agent: &agent.AgentIdentity{
				AgentID:   wAcc.AgentID,
				TenantID:  wAcc.TenantID,
				ProjectID: wAcc.ProjectID,
				KeyID:     wAcc.APIKeyID,
				Status:    agent.AgentStatusActive,
			},
			RouteID:    route.RouteID,
			RoutePath:  route.PathPattern,
			AmountBase: priceBaseUnits,
			Currency:   asset,
		}
		decision := h.evaluator.EvaluatePolicy(r.Context(), policyReq)
		if !decision.Allowed {
			decisionResult = "DENY"
			reasonCode = decision.ReasonCode
			if reasonCode == "" {
				reasonCode = ErrCodePolicyDenied
			}
			reason = decision.Reason
		}
	}

	resp := PolicyDecisionResponse{
		Decision:      decisionResult,
		DecisionID:    fmt.Sprintf("pd_%s", randomHex(12)),
		ReasonCode:    reasonCode,
		Reason:        reason,
		PolicyVersion: "v1",
		ExpiresAt:     time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleGetAgentMe returns authenticated agent metadata and tenant binding.
func (h *Handler) handleGetAgentMe(w http.ResponseWriter, r *http.Request) {
	wAcc, err := h.authenticate(r)
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, ErrCodeUnauthenticated, err.Error(), "PROVIDE_API_KEY")
		return
	}

	resp := AgentIdentityResponse{
		TenantID:    wAcc.TenantID,
		ProjectID:   wAcc.ProjectID,
		AgentID:     wAcc.AgentID,
		WalletID:    wAcc.WalletID,
		Status:      wAcc.Status,
		Environment: h.environment,
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// authenticate extracts and validates the caller's API key.
func (h *Handler) authenticate(r *http.Request) (*x402.WalletAccount, error) {
	apiKey := extractAPIKey(r)
	if apiKey == "" {
		return nil, fmt.Errorf("missing authentication credentials: pass Bearer token or X-AgentPay-Key")
	}

	if h.walletService == nil {
		return nil, fmt.Errorf("wallet service unavailable")
	}

	wAcc, err := h.walletService.GetWalletByAPIKey(r.Context(), apiKey)
	if err != nil || wAcc == nil {
		return nil, fmt.Errorf("invalid or unrecognized API key")
	}

	if wAcc.Status == "frozen" || wAcc.Status == "closed" {
		return nil, fmt.Errorf("agent wallet account is %s", wAcc.Status)
	}

	return wAcc, nil
}

func extractAPIKey(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		return strings.TrimSpace(authHeader[7:])
	}
	if k := r.Header.Get("X-AgentPay-Key"); k != "" {
		return strings.TrimSpace(k)
	}
	if k := r.Header.Get("X-Agent-Key"); k != "" {
		return strings.TrimSpace(k)
	}
	return ""
}

func (h *Handler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *Handler) writeError(w http.ResponseWriter, status int, code, msg, nextAction string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ErrorResponse{
		Error: ErrorDetail{
			Code:       code,
			Message:    msg,
			NextAction: nextAction,
		},
	})
}

func randomHex(bytesLen int) string {
	b := make([]byte, bytesLen)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
