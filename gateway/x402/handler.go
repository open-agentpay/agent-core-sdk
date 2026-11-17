package x402

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/open-agentpay/agent-core-sdk/gateway/agent"
	"github.com/open-agentpay/agent-core-sdk/gateway/idempotency"
	"github.com/open-agentpay/agent-core-sdk/gateway/metrics"
	"github.com/open-agentpay/agent-core-sdk/gateway/payment"
	"github.com/open-agentpay/agent-core-sdk/gateway/proxy"
	"github.com/open-agentpay/agent-core-sdk/gateway/rcu"
	"github.com/open-agentpay/agent-core-sdk/gateway/recovery"
	"github.com/open-agentpay/agent-core-sdk/gateway/usage"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

type WalletAccount struct {
	WalletID         string
	TenantID         string
	APIKeyID         string
	ProjectID        string
	AgentID          string
	Status           string // active, frozen, frozen_arrears, closed
	AvailableBalance int64
	HeldBalance      int64
}

// WalletService coordinates balance checks, holds, and accounting.
type WalletService interface {
	GetWalletByAPIKey(ctx context.Context, apiKey string) (*WalletAccount, error)
	HoldFunds(ctx context.Context, walletID string, amount int64, intentID string) (string, error)
	CaptureFunds(ctx context.Context, holdID string) error
	ReleaseFunds(ctx context.Context, holdID string) error
}

// markWalletFundsRecovery keeps a payment operation recoverable when the ledger
// capture or release fails. The outcome can be ambiguous, so callers must not
// emit a terminal capture/release event or success metric.
type PaymentProcessor struct {
	verifier           PaymentVerifier
	nonceStore         NonceStore
	walletService      WalletService
	idempotencyStore   idempotency.Store
	recoveryCoord      *recovery.RecoveryCoordinator
	proxyHandler       *proxy.Handler
	metrics            *metrics.Metrics
	agentRegistry      *agent.Registry
	agentEnforcer      *agent.Enforcer
	policyEvaluator    agent.PolicyEvaluator
	spendRecorder      agent.SpendRecorder
	auditEmitter       agent.AuditEmitter
	usageService       usage.Service
	paymentService     payment.Service
	settlementDefaults SettlementDefaults
	assetResolver      AssetResolver
	externalStlMu      sync.RWMutex
	externalStlIDs     map[string]string
}

// NewPaymentProcessor creates an initialized PaymentProcessor with full safety defaults.
func NewPaymentProcessor(
	verifier PaymentVerifier,
	nonceStore NonceStore,
	walletService WalletService,
	proxyHandler *proxy.Handler,
	m *metrics.Metrics,
) *PaymentProcessor {
	if m == nil {
		m = metrics.New()
	}
	if nonceStore == nil {
		nonceStore = NewMemoryNonceStore()
	}
	if verifier == nil {
		verifier = &MockPaymentVerifier{ShouldPass: true}
	}
	if walletService == nil {
		walletService = NewMemoryWalletService()
	}
	return &PaymentProcessor{
		verifier:         verifier,
		nonceStore:       nonceStore,
		walletService:    walletService,
		idempotencyStore: idempotency.NewMemoryStore(24 * time.Hour),
		recoveryCoord:    recovery.NewRecoveryCoordinator(),
		proxyHandler:     proxyHandler,
		metrics:          m,
		agentRegistry:    agent.NewRegistry(),
		agentEnforcer:    agent.NewEnforcer(),
		auditEmitter:     agent.NewMemoryAuditEmitter(),
		usageService:     usage.NewMemoryService(),
		paymentService:   payment.NewMemoryService(),
	}
}

func (p *PaymentProcessor) SetPaymentService(svc payment.Service) {
	if svc != nil {
		p.paymentService = svc
	}
}
func (p *PaymentProcessor) GetPaymentService() payment.Service        { return p.paymentService }
func (p *PaymentProcessor) SetVerifier(verifier PaymentVerifier)      { if verifier != nil { p.verifier = verifier } }
func (p *PaymentProcessor) GetVerifier() PaymentVerifier              { return p.verifier }
func (p *PaymentProcessor) SetNonceStore(s NonceStore)                { if s != nil { p.nonceStore = s } }
func (p *PaymentProcessor) GetNonceStore() NonceStore                 { return p.nonceStore }
func (p *PaymentProcessor) SetSettlementDefaults(d SettlementDefaults) { p.settlementDefaults = d }
func (p *PaymentProcessor) GetSettlementDefaults() SettlementDefaults { return p.settlementDefaults }
func (p *PaymentProcessor) SetAssetResolver(r AssetResolver)          { p.assetResolver = r }
func (p *PaymentProcessor) GetAssetResolver() AssetResolver           { return p.assetResolver }
func (p *PaymentProcessor) SetUsageService(svc usage.Service)         { if svc != nil { p.usageService = svc } }
func (p *PaymentProcessor) GetUsageService() usage.Service            { return p.usageService }
func (p *PaymentProcessor) SetAgentRegistry(reg *agent.Registry)      { if reg != nil { p.agentRegistry = reg } }
func (p *PaymentProcessor) GetAgentRegistry() *agent.Registry         { return p.agentRegistry }
func (p *PaymentProcessor) SetAgentEnforcer(enf *agent.Enforcer)      { if enf != nil { p.agentEnforcer = enf } }
func (p *PaymentProcessor) GetAgentEnforcer() *agent.Enforcer         { return p.agentEnforcer }
func (p *PaymentProcessor) SetPolicyEvaluator(e agent.PolicyEvaluator) { p.policyEvaluator = e }
func (p *PaymentProcessor) GetPolicyEvaluator() agent.PolicyEvaluator { return p.policyEvaluator }
func (p *PaymentProcessor) SetSpendRecorder(r agent.SpendRecorder)     { p.spendRecorder = r }
func (p *PaymentProcessor) GetSpendRecorder() agent.SpendRecorder     { return p.spendRecorder }
func (p *PaymentProcessor) SetAuditEmitter(e agent.AuditEmitter)      { p.auditEmitter = e }
func (p *PaymentProcessor) GetAuditEmitter() agent.AuditEmitter       { return p.auditEmitter }
func (p *PaymentProcessor) SetIdempotencyStore(s idempotency.Store)   { if s != nil { p.idempotencyStore = s } }
func (p *PaymentProcessor) IdempotencyStore() idempotency.Store       { return p.idempotencyStore }
func (p *PaymentProcessor) SetRecoveryCoordinator(c *recovery.RecoveryCoordinator) {
	if c != nil {
		p.recoveryCoord = c
	}
}
func (p *PaymentProcessor) RecoveryCoordinator() *recovery.RecoveryCoordinator { return p.recoveryCoord }

func WriteCachedResponse(w http.ResponseWriter, rec *idempotency.Record) {
	for k, v := range rec.Headers {
		w.Header().Set(k, v)
	}
	w.Header().Set("X-Cache", "HIT")
	w.WriteHeader(rec.StatusCode)
	_, _ = w.Write(rec.ResponseBody)
}

// HandleRequest processes an incoming request against route payment requirements without snapshot tracking.
func (p *PaymentProcessor) HandleRequest(w http.ResponseWriter, r *http.Request, route *rcu.RouteConfig, requestID string) {
	p.HandleRequestWithSnapshot(w, r, route, nil, nil, requestID)
}

// HandleRequestWithSnapshot processes an incoming request against route pricing, policy rules, and tracks active config version.
func (p *PaymentProcessor) HandleRequestWithSnapshot(
	w http.ResponseWriter,
	r *http.Request,
	route *rcu.RouteConfig,
	policy *rcu.PolicyConfig,
	snap *rcu.ConfigSnapshot,
	requestID string,
) {
	sc := newReqScope(p, r, route, requestID, snap)
	if snap != nil {
		w.Header().Set("X-Config-Version", sc.configVersion)
	}

	// 1. Enforce route-specific or global Policy checks (T2.5)
	if policy != nil && policy.IsActive && policy.MaxAmountPerRequest > 0 && route.PriceBaseUnits > policy.MaxAmountPerRequest {
		p.metrics.IncPaymentsFailed()
		sc.recordReq(route.TenantID, defaultProjectID, "", "", "", http.StatusForbidden, ErrCodePolicyMaxPerTx, false)
		WriteProtocolError(w, ErrCodePolicyMaxPerTx, requestID, map[string]interface{}{
			"route_id":               route.RouteID,
			"price_base_units":       route.PriceBaseUnits,
			"max_amount_per_request": policy.MaxAmountPerRequest,
			"policy_id":              policy.PolicyID,
		})
		return
	}

	// 2. Free route bypasses payments
	if route.PriceBaseUnits == 0 {
		p.handleFreeRoute(w, r, route, sc)
		return
	}

	// 3. Buffer request body for deterministic hash computation & replay
	bodyBytes, ok := p.readAndRestoreBody(w, r, sc)
	if !ok {
		return
	}
	requestHash := idempotency.ComputeRequestHash(r.Method, r.URL.Path, r.URL.RawQuery, bodyBytes)
	idemKey := r.Header.Get(HeaderIdempotencyKey)
	authHeader := r.Header.Get(HeaderPaymentSignature)
	apiKey := extractClientAPIKey(r)

	switch {
	case apiKey != "":
		// PATH 1: Virtual Wallet Payment (API Key Presented)
		p.handleWalletPayment(w, r, route, sc, apiKey, authHeader, idemKey, requestHash, bodyBytes)
	case authHeader != "":
		// PATH 2: On-Chain x402 Payment (PAYMENT-SIGNATURE Presented)
		p.handleOnChainPayment(w, r, route, sc, authHeader, idemKey, requestHash)
	default:
		// PATH 3: Unauthenticated -> Issue HTTP 402 Payment Required Challenge
		p.issueOnChainChallenge(w, r, route, sc)
	}
}

func extractClientAPIKey(r *http.Request) string {
	if bearer := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(bearer), "bearer ") {
		return strings.TrimSpace(bearer[7:])
	}
	if k := r.Header.Get("X-API-Key"); k != "" {
		return k
	}
	return r.Header.Get("X-Agent-Key")
}

func (p *PaymentProcessor) readAndRestoreBody(w http.ResponseWriter, r *http.Request, sc *reqScope) ([]byte, bool) {
	if r.Body == nil {
		return nil, true
	}
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		slog.Error("failed to read request body", slog.String("request_id", sc.requestID), slog.Any("error", err))
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"code":      "ERR_INVALID_REQUEST_BODY",
				"message":   "Failed to read request body",
				"status":    http.StatusBadRequest,
				"requestId": sc.requestID,
			},
		})
		sc.recordReq("", "", "", "", "", http.StatusBadRequest, "ERR_INVALID_REQUEST_BODY", false)
		return nil, false
	}
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	return bodyBytes, true
}

func (p *PaymentProcessor) handleFreeRoute(w http.ResponseWriter, r *http.Request, route *rcu.RouteConfig, sc *reqScope) {
	pCtx := &proxy.PaymentContext{
		RequestID:     sc.requestID,
		ConfigVersion: sc.configVersion,
		ConfigHash:    sc.configHash,
	}
	resp, err := p.proxyHandler.ForwardWithCapture(w, r, route, pCtx)
	if err != nil {
		slog.Error("forwarding free route request failed",
			slog.String("request_id", sc.requestID),
			slog.String("route_id", route.RouteID),
			slog.Any("error", err),
		)
	}
	statusCode := http.StatusBadGateway
	if resp != nil {
		statusCode = resp.StatusCode
	}
	sc.recordReq(route.TenantID, defaultProjectID, "", "", "", statusCode, "", false)
}

func (p *PaymentProcessor) forwardWithFallback(w http.ResponseWriter, r *http.Request, route *rcu.RouteConfig, pCtx *proxy.PaymentContext, logLabel string) *proxy.ProxyResponse {
	resp, err := p.proxyHandler.ForwardWithCapture(w, r, route, pCtx)
	if err != nil {
		slog.Error(logLabel,
			slog.String("request_id", pCtx.RequestID),
			slog.String("route_id", route.RouteID),
			slog.Any("error", err),
		)
	}
	if resp == nil {
		return &proxy.ProxyResponse{
			StatusCode: http.StatusBadGateway,
			Headers:    make(map[string]string),
		}
	}
	return resp
}

// ----------------------------------------------------------------------------
// PATH 1: Virtual Wallet Payment Flow
// ----------------------------------------------------------------------------

