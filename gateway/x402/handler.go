package x402

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/open-agentpay/agent-core-sdk/gateway/agent"
	"github.com/open-agentpay/agent-core-sdk/gateway/idempotency"
	"github.com/open-agentpay/agent-core-sdk/gateway/metrics"
	"github.com/open-agentpay/agent-core-sdk/gateway/payment"
	"github.com/open-agentpay/agent-core-sdk/gateway/proxy"
	"github.com/open-agentpay/agent-core-sdk/gateway/rcu"
	"github.com/open-agentpay/agent-core-sdk/gateway/recovery"
	"github.com/open-agentpay/agent-core-sdk/gateway/usage"
)

// WalletAccount represents the state of a virtual wallet.
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
func (p *PaymentProcessor) markWalletFundsRecovery(
	ctx context.Context,
	tenantID, idempotencyKey string,
	statusCode int,
	reason string,
) {
	if idempotencyKey == "" {
		return
	}
	if err := p.idempotencyStore.MarkRecoveryRequired(ctx, tenantID, idempotencyKey, statusCode, reason); err != nil {
		slog.Error("failed to mark wallet funds recovery required",
			slog.String("tenant_id", tenantID),
			slog.String("idempotency_key", idempotencyKey),
			slog.Any("error", err),
		)
	}
}

// MemoryWalletService is an in-memory implementation for standalone/testing operation.
type MemoryWalletService struct {
	mu          sync.Mutex
	wallets     map[string]*WalletAccount
	apiKeys     map[string]string    // apiKey -> walletID
	holds       map[string]int64     // holdID -> amount
	holdWIDs    map[string]string    // holdID -> walletID
	holdExpires map[string]time.Time // holdID -> expiresAt
}

// NewMemoryWalletService creates a thread-safe in-memory wallet service.
func NewMemoryWalletService() *MemoryWalletService {
	return &MemoryWalletService{
		wallets:     make(map[string]*WalletAccount),
		apiKeys:     make(map[string]string),
		holds:       make(map[string]int64),
		holdWIDs:    make(map[string]string),
		holdExpires: make(map[string]time.Time),
	}
}

// RegisterWallet registers an account and associates an API Key.
func (m *MemoryWalletService) RegisterWallet(apiKey string, w *WalletAccount) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.wallets[w.WalletID] = w
	m.apiKeys[apiKey] = w.WalletID
}

func (m *MemoryWalletService) GetWalletByAPIKey(ctx context.Context, apiKey string) (*WalletAccount, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	wID, ok := m.apiKeys[apiKey]
	if !ok {
		return nil, fmt.Errorf("invalid API key")
	}
	w, ok := m.wallets[wID]
	if !ok {
		return nil, fmt.Errorf("wallet not found")
	}
	return w, nil
}

func (m *MemoryWalletService) HoldFunds(ctx context.Context, walletID string, amount int64, intentID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w, ok := m.wallets[walletID]
	if !ok {
		return "", fmt.Errorf("wallet not found")
	}
	if w.Status != "active" {
		return "", fmt.Errorf("wallet is %s", w.Status)
	}
	if w.AvailableBalance < amount {
		return "", fmt.Errorf("insufficient available balance")
	}

	w.AvailableBalance -= amount
	w.HeldBalance += amount
	holdID := fmt.Sprintf("hld_%d", time.Now().UnixNano())
	m.holds[holdID] = amount
	m.holdWIDs[holdID] = walletID
	m.holdExpires[holdID] = time.Now().Add(120 * time.Second)
	return holdID, nil
}

func (m *MemoryWalletService) CaptureFunds(ctx context.Context, holdID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	amount, ok := m.holds[holdID]
	if !ok {
		return fmt.Errorf("hold not found")
	}
	wID := m.holdWIDs[holdID]
	w := m.wallets[wID]
	if w != nil {
		w.HeldBalance -= amount
	}
	delete(m.holds, holdID)
	delete(m.holdWIDs, holdID)
	delete(m.holdExpires, holdID)
	return nil
}

func (m *MemoryWalletService) ReleaseFunds(ctx context.Context, holdID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	amount, ok := m.holds[holdID]
	if !ok {
		return fmt.Errorf("hold not found")
	}
	wID := m.holdWIDs[holdID]
	w := m.wallets[wID]
	if w != nil {
		w.HeldBalance -= amount
		w.AvailableBalance += amount
	}
	delete(m.holds, holdID)
	delete(m.holdWIDs, holdID)
	delete(m.holdExpires, holdID)
	return nil
}

// ReleaseExpiredHolds releases all in-memory wallet holds that have expired before the given timestamp (P0-3).
func (m *MemoryWalletService) ReleaseExpiredHolds(ctx context.Context, before time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var released int64
	for holdID, exp := range m.holdExpires {
		if exp.Before(before) {
			amount := m.holds[holdID]
			wID := m.holdWIDs[holdID]
			if w := m.wallets[wID]; w != nil {
				w.HeldBalance -= amount
				w.AvailableBalance += amount
			}
			delete(m.holds, holdID)
			delete(m.holdWIDs, holdID)
			delete(m.holdExpires, holdID)
			released++
		}
	}
	return released, nil
}

// PaymentProcessor orchestrates dual-path routing, challenge generation, payment validation,
// idempotency enforcement, and anti-rollback failure recovery.
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
	auditEmitter       agent.AuditEmitter
	usageService       usage.Service
	paymentService     payment.Service
	settlementDefaults SettlementDefaults
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
func (p *PaymentProcessor) SetUsageService(svc usage.Service)         { if svc != nil { p.usageService = svc } }
func (p *PaymentProcessor) GetUsageService() usage.Service            { return p.usageService }
func (p *PaymentProcessor) SetAgentRegistry(reg *agent.Registry)      { if reg != nil { p.agentRegistry = reg } }
func (p *PaymentProcessor) GetAgentRegistry() *agent.Registry         { return p.agentRegistry }
func (p *PaymentProcessor) SetAgentEnforcer(enf *agent.Enforcer)      { if enf != nil { p.agentEnforcer = enf } }
func (p *PaymentProcessor) GetAgentEnforcer() *agent.Enforcer         { return p.agentEnforcer }
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

func (p *PaymentProcessor) setExternalSettlementID(gatewayStlID, extStlID string) {
	if gatewayStlID == "" || extStlID == "" {
		return
	}
	p.externalStlMu.Lock()
	defer p.externalStlMu.Unlock()
	if p.externalStlIDs == nil {
		p.externalStlIDs = make(map[string]string)
	}
	p.externalStlIDs[gatewayStlID] = extStlID
}

func (p *PaymentProcessor) getExternalSettlementID(gatewayStlID string) string {
	p.externalStlMu.RLock()
	defer p.externalStlMu.RUnlock()
	if p.externalStlIDs != nil {
		if id, ok := p.externalStlIDs[gatewayStlID]; ok && id != "" {
			return id
		}
	}
	return gatewayStlID
}

func (p *PaymentProcessor) resolveAsyncVerifier() AsyncSettlementVerifier {
	if v, ok := p.verifier.(AsyncSettlementVerifier); ok {
		return v
	}
	return nil
}

// executeAsyncSettlement calls async verifier to dispatch settlement and updates the settlement state.
func (p *PaymentProcessor) executeAsyncSettlement(ctx context.Context, intentID, settlementID, vToken string, auth *PaymentAuthorization, idemKey string) {
	if vToken == "" || auth == nil {
		return
	}
	av := p.resolveAsyncVerifier()
	if av == nil {
		return
	}
	res, err := av.SettlePayment(ctx, vToken, auth, idemKey)
	if err != nil {
		slog.Error("async settlement broadcast failed",
			slog.String("settlement_id", settlementID),
			slog.Any("error", err),
		)
		_ = p.recoveryCoord.MarkUnknown(settlementID, err.Error())
		if p.paymentService != nil {
			_ = p.paymentService.UpdateSettlementStatus(context.Background(), settlementID, payment.SettlementStatusUnknown, "", nil, err.Error())
			_ = p.paymentService.UpdateIntentStatus(context.Background(), intentID, payment.IntentStatusNeedsReview)
		}
		return
	}

	p.setExternalSettlementID(settlementID, res.SettlementID)
	statusLower := strings.ToLower(strings.TrimSpace(res.Status))

	switch statusLower {
	case "confirmed":
		_, _ = p.recoveryCoord.ReconcileStatus(context.Background(), settlementID, true, true, false)
		if p.paymentService != nil {
			_ = p.paymentService.UpdateSettlementStatus(context.Background(), settlementID, payment.SettlementStatusConfirmed, res.TxHash, nil, "")
			_ = p.paymentService.UpdateIntentStatus(context.Background(), intentID, payment.IntentStatusCompleted)
		}
	case "failed", "reverted":
		_, _ = p.recoveryCoord.ReconcileStatus(context.Background(), settlementID, true, false, true)
		if p.paymentService != nil {
			_ = p.paymentService.UpdateSettlementStatus(context.Background(), settlementID, payment.SettlementStatusFailed, res.TxHash, nil, "settlement failed")
			_ = p.paymentService.UpdateIntentStatus(context.Background(), intentID, payment.IntentStatusNeedsReview)
		}
	default:
		_, _ = p.recoveryCoord.ReconcileStatus(context.Background(), settlementID, true, false, false)
		if p.paymentService != nil {
			_ = p.paymentService.UpdateSettlementStatus(context.Background(), settlementID, payment.SettlementStatusSubmitted, res.TxHash, nil, "")
		}
	}
}

// dispatchAsyncSettlement dispatches settlement in background to external verifier.
func (p *PaymentProcessor) dispatchAsyncSettlement(intentID, settlementID string, vToken string, auth *PaymentAuthorization, idemKey string) {
	if vToken == "" || auth == nil || p.resolveAsyncVerifier() == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		p.executeAsyncSettlement(ctx, intentID, settlementID, vToken, auth, idemKey)
	}()
}

// ReconcileSettlements queries async verifier for all non-terminal settlements
// (submitted, pending, unknown) and transitions them to confirmed or failed.
func (p *PaymentProcessor) ReconcileSettlements(ctx context.Context) (int, error) {
	av := p.resolveAsyncVerifier()
	if p.paymentService == nil || av == nil {
		return 0, nil
	}
	records, err := p.paymentService.ListNonTerminalSettlements(ctx)
	if err != nil {
		return 0, err
	}
	reconciled := 0
	for _, rec := range records {
		if _, err := p.recoveryCoord.GetSettlement(rec.SettlementID); errors.Is(err, recovery.ErrSettlementNotFound) {
			_ = p.recoveryCoord.RegisterSettlement(&recovery.SettlementRecord{
				SettlementID:    rec.SettlementID,
				PaymentIntentID: rec.IntentID,
				PaymentMethod:   "wallet",
				Payer:           rec.PayerAddress,
				Amount:          rec.AmountBaseUnits,
				Asset:           rec.AssetAddress,
				Network:         rec.NetworkID,
				TxHashOrNonce:   rec.Nonce,
				Status:          recovery.SettlementState(rec.Status),
			})
		}
		queryID := p.getExternalSettlementID(rec.SettlementID)

		var st *SettlementStatus
		var queryErr error
		if queryID != "" && queryID != rec.SettlementID {
			st, queryErr = av.GetSettlementStatus(ctx, queryID)
		}

		if st == nil && rec.Nonce != "" {
			if queryID == "" || queryID == rec.SettlementID || (queryErr != nil && strings.Contains(queryErr.Error(), "404")) {
				stByNonce, nonceErr := av.GetSettlementStatusByNonce(ctx, rec.NetworkID, rec.AssetAddress, rec.PayerAddress, rec.Nonce)
				if nonceErr == nil && stByNonce != nil {
					st = stByNonce
					queryErr = nil
					if stByNonce.SettlementID != "" {
						p.setExternalSettlementID(rec.SettlementID, stByNonce.SettlementID)
					}
				}
			}
		}

		if queryErr != nil || st == nil {
			errMsg := "settlement status query failed"
			if queryErr != nil {
				errMsg = queryErr.Error()
			}
			_ = p.recoveryCoord.MarkUnknown(rec.SettlementID, errMsg)
			_ = p.paymentService.UpdateSettlementStatus(ctx, rec.SettlementID, payment.SettlementStatusUnknown, rec.TxHash, nil, errMsg)
			continue
		}
		switch strings.ToLower(strings.TrimSpace(st.Status)) {
		case "confirmed":
			_, _ = p.recoveryCoord.ReconcileStatus(ctx, rec.SettlementID, true, true, false)
			_ = p.paymentService.UpdateSettlementStatus(ctx, rec.SettlementID, payment.SettlementStatusConfirmed, st.TxHash, nil, "")
			_ = p.paymentService.UpdateIntentStatus(ctx, rec.IntentID, payment.IntentStatusCompleted)
			reconciled++
		case "failed", "reverted":
			_, _ = p.recoveryCoord.ReconcileStatus(ctx, rec.SettlementID, true, false, true)
			errMsg := st.ErrorMessage
			if errMsg == "" {
				errMsg = "on-chain transaction reverted"
			}
			_ = p.paymentService.UpdateSettlementStatus(ctx, rec.SettlementID, payment.SettlementStatusFailed, st.TxHash, nil, errMsg)
			_ = p.paymentService.UpdateIntentStatus(ctx, rec.IntentID, payment.IntentStatusNeedsReview)
			reconciled++
		case "submitted", "pending":
			_, _ = p.recoveryCoord.ReconcileStatus(ctx, rec.SettlementID, true, false, false)
			_ = p.paymentService.UpdateSettlementStatus(ctx, rec.SettlementID, payment.SettlementStatusPending, st.TxHash, nil, "")
		}
	}
	return reconciled, nil
}

// SweepExpiredHolds releases expired wallet holds and transitions stale held settlements to released (P0-3).
func (p *PaymentProcessor) SweepExpiredHolds(ctx context.Context, before time.Time) (int64, error) {
	var total int64
	if releaser, ok := p.walletService.(interface {
		ReleaseExpiredHolds(ctx context.Context, before time.Time) (int64, error)
	}); ok {
		n, err := releaser.ReleaseExpiredHolds(ctx, before)
		if err != nil {
			return total, err
		}
		total += n
	}
	if p.paymentService != nil {
		n, err := p.paymentService.ExpireStaleHolds(ctx, before)
		if err != nil {
			return total, err
		}
		if total == 0 {
			total = n
		}
	}
	return total, nil
}

// WriteCachedResponse streams a previously recorded successful response to the downstream caller.
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

type walletFlowContext struct {
	sc              *reqScope
	wallet          *WalletAccount
	resolvedAgent   *agent.AgentIdentity
	declared        agent.DeclaredContext
	userAgent       string
	intentID        string
	idemKey         string
	requestHash     string
	walletChallenge *payment.WalletChallenge
	correlation     agent.CorrelationContext
}

func (wfc *walletFlowContext) rejectChallenge(ctx context.Context, paymentSvc payment.Service) {
	if wfc.walletChallenge != nil && paymentSvc != nil {
		if err := paymentSvc.RejectWalletChallenge(ctx, wfc.walletChallenge.ChallengeID); err != nil {
			slog.Error("failed to mark wallet challenge rejected",
				slog.String("challenge_id", wfc.walletChallenge.ChallengeID),
				slog.Any("error", err),
			)
		}
	}
}

func (wfc *walletFlowContext) emitRequestAudit(statusCode int, isReplay bool, errCode string) {
	sc := wfc.sc
	durationMs := time.Since(sc.startTime).Milliseconds()
	if sc.p.auditEmitter != nil && wfc.resolvedAgent.AgentID != "" {
		sc.p.auditEmitter.Emit(agent.BuildRequestEvent(
			wfc.resolvedAgent,
			wfc.correlation,
			sc.clientIP,
			wfc.userAgent,
			sc.route.RouteID,
			statusCode,
			durationMs,
			wfc.requestHash,
			&wfc.declared,
		))
	}
	sc.recordReq(wfc.resolvedAgent.TenantID, wfc.resolvedAgent.ProjectID, wfc.wallet.APIKeyID, wfc.resolvedAgent.AgentID, wfc.intentID, statusCode, errCode, isReplay)
	if !isReplay && wfc.correlation.HoldID != "" {
		settlementID := fmt.Sprintf("stl_%s", wfc.correlation.HoldID)
		fulfillmentID := fmt.Sprintf("ful_%s", sc.requestID)
		sc.updateCorrelationOutcome(wfc.intentID, settlementID, fulfillmentID, statusCode)
	}
}

func (wfc *walletFlowContext) emitSpendAudit(holdID, action string) {
	sc := wfc.sc
	route := sc.route
	p := sc.p
	ctx := sc.r.Context()

	wfc.correlation.HoldID = holdID
	if p.auditEmitter != nil && wfc.resolvedAgent.AgentID != "" {
		corr := wfc.correlation
		corr.HoldID = holdID
		p.auditEmitter.Emit(agent.BuildSpendEvent(
			wfc.resolvedAgent,
			corr,
			sc.clientIP,
			wfc.userAgent,
			route.PriceBaseUnits,
			route.Asset,
			"wallet",
			action,
			&wfc.declared,
		))
	}

	settlementID := fmt.Sprintf("stl_%s", holdID)
	switch action {
	case "hold":
		sc.initIntent(wfc.resolvedAgent.TenantID, wfc.resolvedAgent.ProjectID, wfc.resolvedAgent.AgentID, wfc.intentID, wfc.idemKey, "wallet", payment.IntentStatusAuthorized)
		sc.initSettlement(settlementID, wfc.intentID, "wallet", payment.SettlementStatusHeld, wfc.wallet.WalletID, route.PayeeAddress, holdID, holdID)
		sc.initFulfillment(fmt.Sprintf("ful_%s", sc.requestID), wfc.intentID)
		if p.paymentService != nil {
			_ = p.paymentService.LinkWalletAssociation(ctx, wfc.intentID, &payment.WalletHoldAssociation{
				HoldID:    holdID,
				WalletID:  wfc.wallet.WalletID,
				Amount:    route.PriceBaseUnits,
				Status:    "held",
				ExpiresAt: time.Now().Add(120 * time.Second),
			}, nil)
		}
	case "capture":
		sc.recordUsage(wfc.resolvedAgent.TenantID, wfc.resolvedAgent.ProjectID, wfc.resolvedAgent.AgentID, wfc.intentID, "wallet", true)
		if p.paymentService != nil {
			_ = p.paymentService.LinkWalletAssociation(ctx, wfc.intentID, &payment.WalletHoldAssociation{
				HoldID:    holdID,
				WalletID:  wfc.wallet.WalletID,
				Amount:    route.PriceBaseUnits,
				Status:    "captured",
				ExpiresAt: time.Now().Add(120 * time.Second),
			}, &payment.LedgerAssociation{
				EntryID:   "led_" + holdID,
				WalletID:  wfc.wallet.WalletID,
				Type:      "capture",
				Amount:    -route.PriceBaseUnits,
				CreatedAt: time.Now(),
			})
			_ = p.paymentService.UpdateSettlementStatus(ctx, settlementID, payment.SettlementStatusConfirmed, "", nil, "")
		}
	case "release":
		sc.recordUsage(wfc.resolvedAgent.TenantID, wfc.resolvedAgent.ProjectID, wfc.resolvedAgent.AgentID, wfc.intentID, "wallet", false)
		if p.paymentService != nil {
			_ = p.paymentService.LinkWalletAssociation(ctx, wfc.intentID, &payment.WalletHoldAssociation{
				HoldID:    holdID,
				WalletID:  wfc.wallet.WalletID,
				Amount:    route.PriceBaseUnits,
				Status:    "released",
				ExpiresAt: time.Now().Add(120 * time.Second),
			}, &payment.LedgerAssociation{
				EntryID:   "led_" + holdID,
				WalletID:  wfc.wallet.WalletID,
				Type:      "hold_release",
				Amount:    route.PriceBaseUnits,
				CreatedAt: time.Now(),
			})
			_ = p.paymentService.UpdateSettlementStatus(ctx, settlementID, payment.SettlementStatusReleased, "", nil, "")
		}
	}
}

func (wfc *walletFlowContext) buildPaymentContext(holdID string, includeIdemKey bool) *proxy.PaymentContext {
	sc := wfc.sc
	idem := ""
	if includeIdemKey {
		idem = wfc.idemKey
	}
	return &proxy.PaymentContext{
		PayerAddress:        wfc.wallet.WalletID,
		AmountBaseUnits:     sc.route.PriceBaseUnits,
		Asset:               sc.route.Asset,
		Network:             "platform:internal_ledger",
		TxHash:              holdID,
		IdempotencyKey:      idem,
		RequestID:           sc.requestID,
		ConfigVersion:       sc.configVersion,
		ConfigHash:          sc.configHash,
		AgentID:             wfc.resolvedAgent.AgentID,
		TenantID:            wfc.resolvedAgent.TenantID,
		ProjectID:           wfc.resolvedAgent.ProjectID,
		DeclaredSessionID:   wfc.declared.SessionID,
		DeclaredTaskID:      wfc.declared.TaskID,
		DeclaredToolName:    wfc.declared.ToolName,
		DeclaredParentReqID: wfc.declared.ParentRequestID,
	}
}

func (p *PaymentProcessor) issueWalletChallenge(
	w http.ResponseWriter,
	r *http.Request,
	route *rcu.RouteConfig,
	sc *reqScope,
	wallet *WalletAccount,
	apiKey, idemKey string,
	bodyBytes []byte,
) {
	if route.AllowedPaymentMethods == "onchain" {
		WriteProtocolError(w, ErrCodePaymentMethodNotAllowed, sc.requestID, map[string]interface{}{"allowed_payment_methods": route.AllowedPaymentMethods})
		return
	}
	challengeID := generateChallengeID()
	intentID := "pi_" + challengeID
	now := time.Now()
	validBefore := now.Add(DefaultChallengeTTL)
	requestBinding := ComputeRequestBinding(r.Method, r.URL, bodyBytes)
	keyDigest := sha256.Sum256([]byte(apiKey))
	resourceURI := r.URL.EscapedPath()
	if resourceURI == "" {
		resourceURI = "/"
	}
	walletAsset := "USD"
	switch strings.ToUpper(strings.TrimSpace(route.Asset)) {
	case "CNY", "USD", "EUR":
		walletAsset = strings.ToUpper(strings.TrimSpace(route.Asset))
	}
	walletChallenge := &payment.WalletChallenge{
		ChallengeID:    challengeID,
		TenantID:       wallet.TenantID,
		WalletID:       wallet.WalletID,
		APIKeyHash:     hex.EncodeToString(keyDigest[:]),
		RouteID:        route.RouteID,
		IntentID:       intentID,
		IdempotencyKey: idemKey,
		RequestBinding: requestBinding,
		Amount:         route.PriceBaseUnits,
		Asset:          walletAsset,
		ResourceURI:    resourceURI,
		ValidAfter:     now,
		ValidBefore:    validBefore,
		Status:         "issued",
	}
	projectID := wallet.ProjectID
	if projectID == "" {
		projectID = defaultProjectID
	}
	// The retry's Idempotency-Key is separately bound to the durable challenge; keeping
	// it off the provisional intent avoids colliding with an already completed request.
	sc.initIntent(wallet.TenantID, projectID, wallet.AgentID, intentID, "", "wallet", payment.IntentStatusChallenged)
	if err := p.paymentService.CreateWalletChallenge(r.Context(), walletChallenge); err != nil {
		WriteProtocolError(w, ErrCodeUpstreamBadGateway, sc.requestID, map[string]interface{}{"reason": "failed to persist wallet challenge"})
		return
	}
	ch := &PaymentChallenge{
		Version:     DefaultVersion,
		ChallengeID: challengeID,
		Network:     "agentpay:internal-ledger",
		Asset:       walletAsset,
		AssetSymbol: walletAsset,
		Decimals:    6,
		Amount:      fmt.Sprintf("%d", route.PriceBaseUnits),
		Payee:       "agentpay:route:" + route.RouteID,
		Scheme:      WalletScheme,
		ValidAfter:  now.Unix(),
		ValidBefore: validBefore.Unix(),
		ResourceURI: resourceURI,
		Extensions:  map[string]interface{}{"paymentMethod": "wallet", "routeId": route.RouteID, "requestBinding": requestBinding},
	}
	encoded, err := EncodeChallenge(ch, true)
	if err != nil {
		WriteProtocolError(w, ErrCodeUpstreamBadGateway, sc.requestID, nil)
		return
	}
	w.Header().Set(HeaderPaymentRequired, encoded)
	WriteProtocolError(w, ErrCodePaymentRequired, sc.requestID, map[string]interface{}{"challenge": ch})
}

func (p *PaymentProcessor) handleWalletPayment(
	w http.ResponseWriter,
	r *http.Request,
	route *rcu.RouteConfig,
	sc *reqScope,
	apiKey, authHeader, idemKey, requestHash string,
	bodyBytes []byte,
) {
	if route.AllowedPaymentMethods == "onchain" {
		sc.recordReq(route.TenantID, defaultProjectID, "", "", "", http.StatusMethodNotAllowed, ErrCodePaymentMethodNotAllowed, false)
		WriteProtocolError(w, ErrCodePaymentMethodNotAllowed, sc.requestID, map[string]interface{}{
			"route_id":                route.RouteID,
			"allowed_payment_methods": route.AllowedPaymentMethods,
		})
		return
	}

	wallet, err := p.walletService.GetWalletByAPIKey(r.Context(), apiKey)
	if err != nil {
		sc.recordReq(route.TenantID, defaultProjectID, "", "", "", http.StatusUnauthorized, ErrCodeAPIKeyInvalid, false)
		WriteProtocolError(w, ErrCodeAPIKeyInvalid, sc.requestID, nil)
		return
	}

	if wallet.Status == "frozen_arrears" || wallet.Status == "frozen" {
		sc.recordReq(wallet.TenantID, defaultProjectID, wallet.APIKeyID, "", "", http.StatusForbidden, ErrCodeWalletFrozen, false)
		WriteProtocolError(w, ErrCodeWalletFrozen, sc.requestID, map[string]interface{}{
			"wallet_id": wallet.WalletID,
			"status":    wallet.Status,
		})
		return
	}

	// API-key wallet requests first receive a price challenge. Only the SDK's
	// approved wallet authorization may claim it and proceed to a Hold.
	// SECURITY-REVIEW: challenge claim is durable and one-time before any money-moving operation.
	if authHeader == "" {
		p.issueWalletChallenge(w, r, route, sc, wallet, apiKey, idemKey, bodyBytes)
		return
	}

	auth, err := DecodeWalletAuthorization(authHeader)
	if err != nil {
		WriteProtocolError(w, ErrCodeWalletAuthorizationInvalid, sc.requestID, nil)
		return
	}
	keyDigest := sha256.Sum256([]byte(apiKey))
	requestBinding := ComputeRequestBinding(r.Method, r.URL, bodyBytes)
	if auth.Amount != fmt.Sprintf("%d", route.PriceBaseUnits) || auth.ResourceURI != r.URL.EscapedPath() || auth.RequestBinding != requestBinding {
		WriteProtocolError(w, ErrCodeWalletAuthorizationInvalid, sc.requestID, nil)
		return
	}
	walletChallenge, err := p.paymentService.ConsumeWalletChallenge(
		r.Context(), auth.ChallengeID, wallet.TenantID, wallet.WalletID,
		hex.EncodeToString(keyDigest[:]), route.RouteID, requestBinding, auth.Nonce, idemKey, route.PriceBaseUnits, time.Now(),
	)
	if err != nil || walletChallenge == nil || auth.ValidAfter != walletChallenge.ValidAfter.Unix() || auth.ValidBefore != walletChallenge.ValidBefore.Unix() {
		if errors.Is(err, payment.ErrWalletChallengeReplay) {
			WriteProtocolError(w, ErrCodeNonceReplay, sc.requestID, nil)
			return
		}
		WriteProtocolError(w, ErrCodeWalletAuthorizationInvalid, sc.requestID, nil)
		return
	}

	// 1. Agent resolution and context sanitization (T2.9 & T1.8)
	declared := agent.ExtractDeclaredContext(r)
	agent.SanitizeAndStripSpoofedAgentHeaders(r.Header)
	userAgent := r.UserAgent()

	resolvedAgent, agentPolicy, _ := p.agentRegistry.ResolveAPIKey(apiKey)
	if resolvedAgent == nil {
		projectID := wallet.ProjectID
		if projectID == "" {
			projectID = defaultProjectID
		}
		resolvedAgent = &agent.AgentIdentity{
			AgentID:   wallet.AgentID,
			TenantID:  wallet.TenantID,
			ProjectID: projectID,
			Name:      "DefaultAgent",
			Status:    agent.AgentStatusActive,
		}
	}

	intentID := walletChallenge.IntentID
	wfc := &walletFlowContext{
		sc:              sc,
		wallet:          wallet,
		resolvedAgent:   resolvedAgent,
		declared:        declared,
		userAgent:       userAgent,
		intentID:        intentID,
		idemKey:         idemKey,
		requestHash:     requestHash,
		walletChallenge: walletChallenge,
		correlation: agent.CorrelationContext{
			RequestID:      sc.requestID,
			IdempotencyKey: idemKey,
			IntentID:       intentID,
		},
	}

	// 2. Synchronous In-Path Agent Policy Enforcement (T2.9)
	decision := p.agentEnforcer.Evaluate(r.Context(), resolvedAgent, agentPolicy, route.RouteID, r.URL.Path, route.PriceBaseUnits)
	if p.auditEmitter != nil && resolvedAgent.AgentID != "" {
		p.auditEmitter.Emit(agent.BuildPolicyDecisionEvent(
			resolvedAgent,
			decision,
			route.RouteID,
			wfc.correlation,
			sc.clientIP,
			userAgent,
			&declared,
		))
	}
	if !decision.Allowed {
		wfc.rejectChallenge(r.Context(), p.paymentService)
		p.metrics.IncPaymentsFailed()
		sc.initIntent(resolvedAgent.TenantID, resolvedAgent.ProjectID, resolvedAgent.AgentID, intentID, idemKey, "wallet", payment.IntentStatusRejected)
		sc.recordReq(resolvedAgent.TenantID, resolvedAgent.ProjectID, wallet.APIKeyID, resolvedAgent.AgentID, intentID, http.StatusForbidden, decision.ReasonCode, false)
		WriteProtocolError(w, decision.ReasonCode, sc.requestID, map[string]interface{}{
			"agent_id":    resolvedAgent.AgentID,
			"reason":      decision.Reason,
			"reason_code": decision.ReasonCode,
			"rule_id":     decision.RuleID,
		})
		return
	}

	if idemKey != "" {
		p.handleIdempotentWalletPayment(w, r, route, wfc)
		return
	}
	p.handleNonIdempotentWalletPayment(w, r, route, wfc)
}

func (p *PaymentProcessor) acquireWalletHold(
	w http.ResponseWriter,
	r *http.Request,
	route *rcu.RouteConfig,
	wfc *walletFlowContext,
	idemTenantID string,
) (string, bool) {
	sc := wfc.sc
	wallet := wfc.wallet
	releaseIdemLock := func() {
		if idemTenantID != "" && wfc.idemKey != "" {
			_ = p.idempotencyStore.ReleaseLock(r.Context(), idemTenantID, wfc.idemKey)
		}
	}

	if wallet.AvailableBalance < route.PriceBaseUnits {
		wfc.rejectChallenge(r.Context(), p.paymentService)
		releaseIdemLock()
		p.metrics.IncPaymentsFailed()
		sc.initIntent(wfc.resolvedAgent.TenantID, wfc.resolvedAgent.ProjectID, wfc.resolvedAgent.AgentID, wfc.intentID, wfc.idemKey, "wallet", payment.IntentStatusFailed)
		sc.initSettlement(fmt.Sprintf("stl_%s", sc.requestID), wfc.intentID, "wallet", payment.SettlementStatusFailed, wallet.WalletID, route.PayeeAddress, "", "")
		sc.recordReq(wfc.resolvedAgent.TenantID, wfc.resolvedAgent.ProjectID, wallet.APIKeyID, wfc.resolvedAgent.AgentID, wfc.intentID, http.StatusPaymentRequired, ErrCodeWalletInsufficientBalance, false)
		WriteProtocolError(w, ErrCodeWalletInsufficientBalance, sc.requestID, map[string]interface{}{
			"wallet_id":         wallet.WalletID,
			"required_amount":   route.PriceBaseUnits,
			"available_balance": wallet.AvailableBalance,
			"auto_downgrade":    false,
		})
		return "", false
	}

	holdID, err := p.walletService.HoldFunds(r.Context(), wallet.WalletID, route.PriceBaseUnits, wfc.intentID)
	if err != nil {
		wfc.rejectChallenge(r.Context(), p.paymentService)
		releaseIdemLock()
		p.metrics.IncPaymentsFailed()
		sc.initIntent(wfc.resolvedAgent.TenantID, wfc.resolvedAgent.ProjectID, wfc.resolvedAgent.AgentID, wfc.intentID, wfc.idemKey, "wallet", payment.IntentStatusFailed)
		sc.initSettlement(fmt.Sprintf("stl_%s", sc.requestID), wfc.intentID, "wallet", payment.SettlementStatusFailed, wallet.WalletID, route.PayeeAddress, "", "")
		sc.recordReq(wfc.resolvedAgent.TenantID, wfc.resolvedAgent.ProjectID, wallet.APIKeyID, wfc.resolvedAgent.AgentID, wfc.intentID, http.StatusPaymentRequired, ErrCodeWalletInsufficientBalance, false)
		WriteProtocolError(w, ErrCodeWalletInsufficientBalance, sc.requestID, nil)
		return "", false
	}

	// SECURITY-REVIEW: tie the durable one-time authorization to the created hold before upstream dispatch.
	if wfc.walletChallenge != nil {
		if err := p.paymentService.SetWalletChallengeHold(r.Context(), wfc.walletChallenge.ChallengeID, holdID); err != nil {
			_ = p.walletService.ReleaseFunds(r.Context(), holdID)
			wfc.rejectChallenge(r.Context(), p.paymentService)
			WriteProtocolError(w, ErrCodeUpstreamBadGateway, sc.requestID, map[string]interface{}{"reason": "failed to link wallet challenge to hold"})
			return "", false
		}
	}

	p.metrics.IncHoldsCreated()
	wfc.emitSpendAudit(holdID, "hold")
	return holdID, true
}

func (p *PaymentProcessor) settleIdempotentWalletOutcome(
	ctx context.Context,
	route *rcu.RouteConfig,
	wfc *walletFlowContext,
	tenantID, holdID string,
	resp *proxy.ProxyResponse,
) {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// Capture only after a successful upstream response. A capture failure must
		// remain visible to recovery; logging alone does not reconcile this hold.
		if err := p.walletService.CaptureFunds(ctx, holdID); err != nil {
			slog.Error("failed to capture wallet funds", slog.String("hold_id", holdID), slog.Any("error", err))
			// Preserve the existing hold and leave the idempotency record
			// recoverable; do not emit a capture event or success metric.
			p.markWalletFundsRecovery(ctx, tenantID, wfc.idemKey, resp.StatusCode, "wallet capture failed")
			return
		}
		p.agentEnforcer.RecordSpend(wfc.resolvedAgent.AgentID, route.PriceBaseUnits)
		wfc.emitSpendAudit(holdID, "capture")
		p.metrics.IncHoldsCaptured()
		p.metrics.IncPaymentsVerified()
		if err := p.idempotencyStore.MarkCompleted(ctx, tenantID, wfc.idemKey, resp.StatusCode, resp.Headers, resp.Body); err != nil {
			slog.Error("failed to mark idempotency completed", slog.String("tenant_id", tenantID), slog.String("idempotency_key", wfc.idemKey), slog.Any("error", err))
		}
	} else if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		if err := p.walletService.ReleaseFunds(ctx, holdID); err != nil {
			slog.Error("failed to release wallet funds", slog.String("hold_id", holdID), slog.Any("error", err))
			p.markWalletFundsRecovery(ctx, tenantID, wfc.idemKey, resp.StatusCode, "wallet release failed")
			return
		}
		wfc.emitSpendAudit(holdID, "release")
		p.metrics.IncHoldsReleased()
		if err := p.idempotencyStore.MarkCompleted(ctx, tenantID, wfc.idemKey, resp.StatusCode, resp.Headers, resp.Body); err != nil {
			slog.Error("failed to mark idempotency completed", slog.String("tenant_id", tenantID), slog.String("idempotency_key", wfc.idemKey), slog.Any("error", err))
		}
	} else {
		// 5xx or Timeout: KEEP HELD, Mark Recovery Required (strictly no auto-release or double capture)
		if err := p.idempotencyStore.MarkRecoveryRequired(ctx, tenantID, wfc.idemKey, resp.StatusCode, "upstream failure"); err != nil {
			slog.Error("failed to mark recovery required", slog.String("tenant_id", tenantID), slog.String("idempotency_key", wfc.idemKey), slog.Any("error", err))
		}
	}
}

func (p *PaymentProcessor) handleIdempotentWalletPayment(
	w http.ResponseWriter,
	r *http.Request,
	route *rcu.RouteConfig,
	wfc *walletFlowContext,
) {
	sc := wfc.sc
	wallet := wfc.wallet
	tenantID := wallet.TenantID
	if tenantID == "" {
		tenantID = wallet.WalletID
	}

	rec, checkRes, err := p.idempotencyStore.CheckOrLock(r.Context(), tenantID, wfc.idemKey, wfc.requestHash, wfc.intentID, "wallet")
	if err != nil {
		sc.recordReq(wfc.resolvedAgent.TenantID, wfc.resolvedAgent.ProjectID, wallet.APIKeyID, wfc.resolvedAgent.AgentID, wfc.intentID, http.StatusBadGateway, ErrCodeUpstreamBadGateway, false)
		WriteProtocolError(w, ErrCodeUpstreamBadGateway, sc.requestID, map[string]interface{}{"error": err.Error()})
		return
	}

	switch checkRes {
	case idempotency.ResultConflict:
		wfc.rejectChallenge(r.Context(), p.paymentService)
		sc.recordReq(wfc.resolvedAgent.TenantID, wfc.resolvedAgent.ProjectID, wallet.APIKeyID, wfc.resolvedAgent.AgentID, wfc.intentID, http.StatusConflict, ErrCodeIdempotencyConflict, false)
		WriteProtocolError(w, ErrCodeIdempotencyConflict, sc.requestID, map[string]interface{}{
			"idempotency_key": wfc.idemKey,
			"reason":          "Idempotency conflict: request in-progress or payload altered",
		})
		return

	case idempotency.ResultCacheHit:
		wfc.rejectChallenge(r.Context(), p.paymentService)
		WriteCachedResponse(w, rec)
		wfc.emitRequestAudit(rec.StatusCode, true, "")
		return

	case idempotency.ResultFreeReplay:
		wfc.rejectChallenge(r.Context(), p.paymentService)
		// Anti-Double-Charge Invariant: Reuse existing HoldID without creating a second hold
		pCtx := wfc.buildPaymentContext(rec.HoldID, true)
		resp := p.forwardWithFallback(w, r, route, pCtx, "failed to forward request with capture (wallet idempotent free replay)")
		wfc.emitRequestAudit(resp.StatusCode, true, "")
		p.settleIdempotentWalletOutcome(r.Context(), route, wfc, tenantID, rec.HoldID, resp)
		return
	}

	// Case D: ResultNew (First time receiving this idempotent request)
	holdID, ok := p.acquireWalletHold(w, r, route, wfc, tenantID)
	if !ok {
		return
	}
	_ = p.idempotencyStore.AttachPaymentDetails(r.Context(), tenantID, wfc.idemKey, holdID, "")

	pCtx := wfc.buildPaymentContext(holdID, true)
	resp := p.forwardWithFallback(w, r, route, pCtx, "failed to forward request with capture (wallet idempotent fresh)")
	wfc.emitRequestAudit(resp.StatusCode, false, "")
	p.settleIdempotentWalletOutcome(r.Context(), route, wfc, tenantID, holdID, resp)
}

func (p *PaymentProcessor) handleNonIdempotentWalletPayment(
	w http.ResponseWriter,
	r *http.Request,
	route *rcu.RouteConfig,
	wfc *walletFlowContext,
) {
	sc := wfc.sc
	holdID, ok := p.acquireWalletHold(w, r, route, wfc, "")
	if !ok {
		return
	}
	settlementID := fmt.Sprintf("stl_%s", sc.requestID)
	sc.initSettlement(settlementID, wfc.intentID, "wallet", payment.SettlementStatusHeld, wfc.wallet.WalletID, route.PayeeAddress, holdID, holdID)

	pCtx := wfc.buildPaymentContext(holdID, false)
	resp := p.forwardWithFallback(w, r, route, pCtx, "failed to forward request with capture (wallet non-idempotent)")
	wfc.emitRequestAudit(resp.StatusCode, false, "")

	ctx := r.Context()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// This path has no idempotency record to drive automated recovery, so a
		// capture error needs a durable settlement/reconciliation signal.
		if err := p.walletService.CaptureFunds(ctx, holdID); err != nil {
			slog.Error("failed to capture wallet funds", slog.String("hold_id", holdID), slog.Any("error", err))
			if p.paymentService != nil {
				if statusErr := p.paymentService.UpdateSettlementStatus(ctx, settlementID, payment.SettlementStatusUnknown, "", nil, "wallet capture failed"); statusErr != nil {
					slog.Error("failed to mark wallet settlement unknown", slog.String("settlement_id", settlementID), slog.Any("error", statusErr))
				}
			}
			return
		}
		p.agentEnforcer.RecordSpend(wfc.resolvedAgent.AgentID, route.PriceBaseUnits)
		wfc.emitSpendAudit(holdID, "capture")
		p.metrics.IncHoldsCaptured()
		p.metrics.IncPaymentsVerified()
		if p.paymentService != nil {
			if statusErr := p.paymentService.UpdateSettlementStatus(ctx, settlementID, payment.SettlementStatusConfirmed, "", nil, ""); statusErr != nil {
				slog.Error("failed to mark wallet settlement confirmed", slog.String("settlement_id", settlementID), slog.Any("error", statusErr))
			}
		}
	} else if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		if err := p.walletService.ReleaseFunds(ctx, holdID); err != nil {
			slog.Error("failed to release wallet funds", slog.String("hold_id", holdID), slog.Any("error", err))
			if p.paymentService != nil {
				if statusErr := p.paymentService.UpdateSettlementStatus(ctx, settlementID, payment.SettlementStatusUnknown, "", nil, "wallet release failed"); statusErr != nil {
					slog.Error("failed to mark wallet settlement unknown", slog.String("settlement_id", settlementID), slog.Any("error", statusErr))
				}
			}
			return
		}
		wfc.emitSpendAudit(holdID, "release")
		p.metrics.IncHoldsReleased()
		if p.paymentService != nil {
			if statusErr := p.paymentService.UpdateSettlementStatus(ctx, settlementID, payment.SettlementStatusReleased, "", nil, ""); statusErr != nil {
				slog.Error("failed to mark wallet settlement released", slog.String("settlement_id", settlementID), slog.Any("error", statusErr))
			}
		}
	}
	// In non-idempotent 5xx, hold remains preserved for manual reconciliation/review.
}

// ----------------------------------------------------------------------------
// PATH 2 & 3: On-Chain x402 Payment & Challenge Issuance
// ----------------------------------------------------------------------------

func (p *PaymentProcessor) verifyOnChainPaymentAndNonce(
	w http.ResponseWriter,
	r *http.Request,
	route *rcu.RouteConfig,
	sc *reqScope,
	oc onchainParams,
	auth *PaymentAuthorization,
	intentID, settlementID, idemKey, idemTenantID string,
) (*VerificationResult, bool) {
	releaseIdemLock := func() {
		if idemTenantID != "" && idemKey != "" {
			_ = p.idempotencyStore.ReleaseLock(r.Context(), idemTenantID, idemKey)
		}
	}

	validNonce, err := p.nonceStore.CheckAndRecordNonce(oc.Network, oc.Contract, auth.Payer, auth.Nonce)
	if err != nil || !validNonce {
		releaseIdemLock()
		p.metrics.IncPaymentsFailed()
		sc.initIntent(route.TenantID, defaultProjectID, "", intentID, idemKey, "onchain", payment.IntentStatusFailed)
		sc.initSettlement(settlementID, intentID, "onchain", payment.SettlementStatusFailed, auth.Payer, route.PayeeAddress, auth.Nonce, "")
		sc.recordReq(route.TenantID, defaultProjectID, "", "", intentID, http.StatusPaymentRequired, ErrCodeNonceAlreadyUsed, false)
		WriteProtocolError(w, ErrCodeNonceAlreadyUsed, sc.requestID, map[string]interface{}{
			"nonce": auth.Nonce,
			"payer": auth.Payer,
		})
		return nil, false
	}

	ch := oc.verifyChallenge(auth)
	result, err := p.verifier.VerifyPayment(r.Context(), ch, auth)
	if err != nil || result == nil || !result.Valid {
		releaseIdemLock()
		p.metrics.IncPaymentsFailed()
		errCode := ErrCodeSignatureInvalid
		reason := "signature verification failed"
		if err != nil {
			reason = err.Error()
		} else if result != nil {
			if result.ErrorCode != "" {
				errCode = result.ErrorCode
			}
			if result.Message != "" {
				reason = result.Message
			}
		}
		sc.initIntent(route.TenantID, defaultProjectID, "", intentID, idemKey, "onchain", payment.IntentStatusFailed)
		sc.initSettlement(settlementID, intentID, "onchain", payment.SettlementStatusFailed, auth.Payer, route.PayeeAddress, auth.Nonce, "")
		sc.recordReq(route.TenantID, defaultProjectID, "", "", intentID, http.StatusPaymentRequired, errCode, false)
		WriteProtocolError(w, errCode, sc.requestID, map[string]interface{}{
			"reason": reason,
		})
		return nil, false
	}

	sc.initIntent(route.TenantID, defaultProjectID, "", intentID, idemKey, "onchain", payment.IntentStatusAuthorized)
	sc.initSettlement(settlementID, intentID, "onchain", payment.SettlementStatusSubmitted, auth.Payer, route.PayeeAddress, auth.Nonce, "")
	sc.initFulfillment(fmt.Sprintf("ful_%s", sc.requestID), intentID)
	return result, true
}

func (p *PaymentProcessor) handleOnChainPayment(
	w http.ResponseWriter,
	r *http.Request,
	route *rcu.RouteConfig,
	sc *reqScope,
	authHeader, idemKey, requestHash string,
) {
	if route.AllowedPaymentMethods == "wallet" {
		sc.recordReq(route.TenantID, defaultProjectID, "", "", "", http.StatusMethodNotAllowed, ErrCodePaymentMethodNotAllowed, false)
		WriteProtocolError(w, ErrCodePaymentMethodNotAllowed, sc.requestID, map[string]interface{}{
			"route_id":                route.RouteID,
			"allowed_payment_methods": route.AllowedPaymentMethods,
		})
		return
	}

	slog.Info("x402 authorization received", slog.String("request_id", sc.requestID))
	auth, err := DecodeAuthorization(authHeader)
	if err != nil {
		p.metrics.IncPaymentsFailed()
		intentID := fmt.Sprintf("pi_%s", sc.requestID)
		sc.initIntent(route.TenantID, defaultProjectID, "", intentID, idemKey, "onchain", payment.IntentStatusFailed)
		sc.recordReq(route.TenantID, defaultProjectID, "", "", intentID, http.StatusUnauthorized, ErrCodeSignatureInvalid, false)
		WriteProtocolError(w, ErrCodeSignatureInvalid, sc.requestID, map[string]interface{}{
			"reason": err.Error(),
		})
		return
	}

	oc := p.resolveOnchain(route)
	intentID := fmt.Sprintf("pi_%s", sc.requestID)
	if auth.ChallengeID != "" {
		intentID = "pi_" + auth.ChallengeID
	}
	settlementID := fmt.Sprintf("stl_%s", sc.requestID)
	fulfillmentID := fmt.Sprintf("ful_%s", sc.requestID)

	// 2.1 Idempotent On-Chain Request
	if idemKey != "" {
		tenantID := auth.Payer
		rec, checkRes, err := p.idempotencyStore.CheckOrLock(r.Context(), tenantID, idemKey, requestHash, intentID, "onchain")
		if err != nil {
			sc.recordReq(route.TenantID, defaultProjectID, "", "", intentID, http.StatusBadGateway, ErrCodeUpstreamBadGateway, false)
			WriteProtocolError(w, ErrCodeUpstreamBadGateway, sc.requestID, map[string]interface{}{"error": err.Error()})
			return
		}

		switch checkRes {
		case idempotency.ResultConflict:
			sc.recordReq(route.TenantID, defaultProjectID, "", "", intentID, http.StatusConflict, ErrCodeIdempotencyConflict, false)
			WriteProtocolError(w, ErrCodeIdempotencyConflict, sc.requestID, map[string]interface{}{
				"idempotency_key": idemKey,
				"reason":          "Idempotency conflict: request in-progress or payload altered",
			})
			return

		case idempotency.ResultCacheHit:
			sc.recordReq(route.TenantID, defaultProjectID, "", "", intentID, rec.StatusCode, "", true)
			WriteCachedResponse(w, rec)
			return

		case idempotency.ResultFreeReplay:
			// Free Replay: Do not re-verify signature or double-charge
			pCtx := &proxy.PaymentContext{
				PayerAddress:    auth.Payer,
				AmountBaseUnits: route.PriceBaseUnits,
				Asset:           oc.Contract,
				Network:         oc.Network,
				TxHash:          auth.Nonce,
				IdempotencyKey:  idemKey,
				RequestID:       sc.requestID,
				ConfigVersion:   sc.configVersion,
				ConfigHash:      sc.configHash,
			}
			resp := p.forwardWithFallback(w, r, route, pCtx, "failed to forward request with capture (on-chain idempotent retry)")
			sc.recordReq(route.TenantID, defaultProjectID, "", "", intentID, resp.StatusCode, "", true)
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				if err := p.idempotencyStore.MarkCompleted(r.Context(), tenantID, idemKey, resp.StatusCode, resp.Headers, resp.Body); err != nil {
					slog.Error("failed to mark idempotency completed", slog.String("tenant_id", tenantID), slog.String("idempotency_key", idemKey), slog.Any("error", err))
				}
			} else {
				if err := p.idempotencyStore.MarkRecoveryRequired(r.Context(), tenantID, idemKey, resp.StatusCode, "upstream failure"); err != nil {
					slog.Error("failed to mark recovery required", slog.String("tenant_id", tenantID), slog.String("idempotency_key", idemKey), slog.Any("error", err))
				}
			}
			return
		}

		// ResultNew: Validate Nonce & Signature
		result, ok := p.verifyOnChainPaymentAndNonce(w, r, route, sc, oc, auth, intentID, settlementID, idemKey, tenantID)
		if !ok {
			return
		}

		// Register settlement in recovery coordinator
		_ = p.recoveryCoord.RegisterSettlement(&recovery.SettlementRecord{
			SettlementID:    settlementID,
			PaymentIntentID: intentID,
			PaymentMethod:   "onchain",
			Payer:           auth.Payer,
			Amount:          oc.Price,
			Asset:           oc.Asset,
			Network:         oc.Network,
			TxHashOrNonce:   auth.Nonce,
			Status:          recovery.SettlementSubmitted,
		})
		_ = p.idempotencyStore.AttachPaymentDetails(r.Context(), tenantID, idemKey, "", settlementID)
		p.metrics.IncPaymentsVerified()

		asyncSettle := p.resolveAsyncVerifier() != nil && result.VerificationToken != ""
		pCtx := &proxy.PaymentContext{
			PayerAddress:    result.Payer,
			AmountBaseUnits: oc.Price,
			Asset:           oc.Asset,
			Network:         oc.Network,
			TxHash:          auth.Nonce,
			IdempotencyKey:  idemKey,
			RequestID:       sc.requestID,
			ConfigVersion:   sc.configVersion,
			ConfigHash:      sc.configHash,
		}
		resp := p.forwardWithFallback(w, r, route, pCtx, "failed to forward request with capture (on-chain idempotent)")
		sc.updateCorrelationOutcomeWithMode(intentID, settlementID, fulfillmentID, resp.StatusCode, !asyncSettle)
		sc.recordReq(route.TenantID, defaultProjectID, "", "", intentID, resp.StatusCode, "", false)

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if err := p.idempotencyStore.MarkCompleted(r.Context(), tenantID, idemKey, resp.StatusCode, resp.Headers, resp.Body); err != nil {
				slog.Error("failed to mark idempotency completed", slog.String("tenant_id", tenantID), slog.String("idempotency_key", idemKey), slog.Any("error", err))
			}
			sc.recordUsage(route.TenantID, defaultProjectID, "", intentID, "onchain", true)
			if asyncSettle {
				p.dispatchAsyncSettlement(intentID, settlementID, result.VerificationToken, auth, idemKey)
			} else {
				_, _ = p.recoveryCoord.ReconcileStatus(r.Context(), settlementID, true, true, false)
			}
		} else {
			// Anti-Rollback: Record remains SUBMITTED, Mark recovery required
			_ = p.recoveryCoord.MarkUnknown(settlementID, "upstream error")
			if err := p.idempotencyStore.MarkRecoveryRequired(r.Context(), tenantID, idemKey, resp.StatusCode, "upstream failure"); err != nil {
				slog.Error("failed to mark recovery required", slog.String("tenant_id", tenantID), slog.String("idempotency_key", idemKey), slog.Any("error", err))
			}
			sc.recordUsage(route.TenantID, defaultProjectID, "", intentID, "onchain", false)
		}
		return
	}

	// 2.2 Non-Idempotent On-Chain Request
	result, ok := p.verifyOnChainPaymentAndNonce(w, r, route, sc, oc, auth, intentID, settlementID, idemKey, "")
	if !ok {
		return
	}

	_ = p.recoveryCoord.RegisterSettlement(&recovery.SettlementRecord{
		SettlementID:    settlementID,
		PaymentIntentID: intentID,
		PaymentMethod:   "onchain",
		Payer:           auth.Payer,
		Amount:          oc.Price,
		Asset:           oc.Asset,
		Network:         oc.Network,
		TxHashOrNonce:   auth.Nonce,
		Status:          recovery.SettlementSubmitted,
	})
	asyncSettle := p.resolveAsyncVerifier() != nil && result.VerificationToken != ""
	p.metrics.IncPaymentsVerified()
	pCtx := &proxy.PaymentContext{
		PayerAddress:    result.Payer,
		AmountBaseUnits: oc.Price,
		Asset:           oc.Asset,
		Network:         oc.Network,
		TxHash:          auth.Nonce,
		RequestID:       sc.requestID,
		ConfigVersion:   sc.configVersion,
		ConfigHash:      sc.configHash,
	}
	resp := p.forwardWithFallback(w, r, route, pCtx, "failed to forward request with capture (on-chain non-idempotent)")
	sc.updateCorrelationOutcomeWithMode(intentID, settlementID, fulfillmentID, resp.StatusCode, !asyncSettle)
	sc.recordReq(route.TenantID, defaultProjectID, "", "", intentID, resp.StatusCode, "", false)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		sc.recordUsage(route.TenantID, defaultProjectID, "", intentID, "onchain", true)
		if asyncSettle {
			p.dispatchAsyncSettlement(intentID, settlementID, result.VerificationToken, auth, idemKey)
		} else {
			_, _ = p.recoveryCoord.ReconcileStatus(r.Context(), settlementID, true, true, false)
		}
	} else {
		_ = p.recoveryCoord.MarkUnknown(settlementID, "upstream error")
		sc.recordUsage(route.TenantID, defaultProjectID, "", intentID, "onchain", false)
	}
}

func (p *PaymentProcessor) issueOnChainChallenge(
	w http.ResponseWriter,
	r *http.Request,
	route *rcu.RouteConfig,
	sc *reqScope,
) {
	if route.AllowedPaymentMethods == "wallet" {
		WriteProtocolError(w, ErrCodeWalletAuthRequired, sc.requestID, nil)
		return
	}
	oc := p.resolveOnchain(route)
	ch := oc.newChallenge(r.URL.Path, 300*time.Second)
	intentID := "pi_" + ch.ChallengeID
	// Keep Idempotency-Key off the provisional challenged intent so the retry can bind it cleanly.
	sc.initIntent(route.TenantID, defaultProjectID, "", intentID, "", "onchain", payment.IntentStatusChallenged)
	sc.recordReq(route.TenantID, defaultProjectID, "", "", intentID, http.StatusPaymentRequired, ErrCodePaymentRequired, false)
	p.metrics.IncChallenges()
	encodedChallenge, err := EncodeChallenge(ch, true)
	if err != nil {
		WriteProtocolError(w, ErrCodeUpstreamBadGateway, sc.requestID, nil)
		return
	}

	w.Header().Set(HeaderPaymentRequired, encodedChallenge)
	WriteProtocolError(w, ErrCodePaymentRequired, sc.requestID, map[string]interface{}{
		"challenge": ch,
	})
}
