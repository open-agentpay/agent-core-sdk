package x402

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/open-agentpay/agent-core-sdk/gateway/agent"
	"github.com/open-agentpay/agent-core-sdk/gateway/idempotency"
	"github.com/open-agentpay/agent-core-sdk/gateway/payment"
	"github.com/open-agentpay/agent-core-sdk/gateway/proxy"
	"github.com/open-agentpay/agent-core-sdk/gateway/rcu"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

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

func (wfc *walletFlowContext) emitSpendAudit(holdID, action string, resp ...*proxy.ProxyResponse) {
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
		var pTok, cTok, tTok int64
		if len(resp) > 0 && resp[0] != nil {
			pTok, cTok, tTok = extractTokensFromResponse(resp[0].Body)
		}
		sc.recordUsageWithTokens(wfc.resolvedAgent.TenantID, wfc.resolvedAgent.ProjectID, wfc.resolvedAgent.AgentID, wfc.intentID, "wallet", true, pTok, cTok, tTok)
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

	// Trial Key Safeguards: only restrict guest trial key (apk_live_guest_) if still in public sandbox tenant
	if strings.HasPrefix(apiKey, "apk_live_guest_") && (wallet.TenantID == "ten_public_sandbox" || wallet.TenantID == "") {
		if !route.TrialAllowed() {
			sc.recordReq(wallet.TenantID, defaultProjectID, wallet.APIKeyID, "", "", http.StatusForbidden, "ERR_TRIAL_NOT_ALLOWED", false)
			WriteProtocolError(w, ErrCodeTrialNotAllowed, sc.requestID, map[string]interface{}{
				"route_id": route.RouteID,
			})
			return
		}
		if route.PriceBaseUnits > 500000 {
			costCny := fmt.Sprintf("%.2f", float64(route.PriceBaseUnits)/1000000.0)
			sc.recordReq(wallet.TenantID, defaultProjectID, wallet.APIKeyID, "", "", http.StatusForbidden, "ERR_TRIAL_SINGLE_TX_CAP_EXCEEDED", false)
			WriteProtocolError(w, ErrCodeTrialSingleTxCapExceeded, sc.requestID, map[string]interface{}{
				"route_id":                route.RouteID,
				"price_base_units":        route.PriceBaseUnits,
				"price_cny":               costCny,
				"max_single_tx_base_unit": 500000,
				"max_single_tx_cny":       "0.50",
			})
			return
		}
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

	// 2. Synchronous In-Path Agent Policy Enforcement
	var decision agent.PolicyDecision
	if p.policyEvaluator != nil {
		decision = p.policyEvaluator.EvaluatePolicy(r.Context(), &agent.PolicyRequest{
			Agent:      resolvedAgent,
			Policy:     agentPolicy,
			RouteID:    route.RouteID,
			RoutePath:  r.URL.Path,
			AmountBase: route.PriceBaseUnits,
			Currency:   route.Asset,
			Declared:   &declared,
		})
	} else if p.agentEnforcer != nil {
		decision = p.agentEnforcer.Evaluate(r.Context(), resolvedAgent, agentPolicy, route.RouteID, r.URL.Path, route.PriceBaseUnits)
	} else {
		decision = agent.PolicyDecision{Allowed: true, ReasonCode: agent.CodeAllow}
	}
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
		respData := map[string]interface{}{
			"agent_id":    resolvedAgent.AgentID,
			"reason":      decision.Reason,
			"reason_code": decision.ReasonCode,
			"rule_id":     decision.RuleID,
		}
		for k, v := range decision.Extra {
			respData[k] = v
		}
		WriteProtocolError(w, decision.ReasonCode, sc.requestID, respData)
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
		if p.agentEnforcer != nil {
			p.agentEnforcer.RecordSpend(wfc.resolvedAgent.AgentID, route.PriceBaseUnits)
		}
		if p.spendRecorder != nil {
			_ = p.spendRecorder.RecordSpend(ctx, &agent.SpendRecord{
				TenantID:   wfc.wallet.TenantID,
				ProjectID:  wfc.resolvedAgent.ProjectID,
				AgentID:    wfc.resolvedAgent.AgentID,
				RouteID:    route.RouteID,
				AmountBase: route.PriceBaseUnits,
				Currency:   route.Asset,
				HoldID:     holdID,
				CapturedAt: time.Now().Unix(),
			})
		}
		wfc.emitSpendAudit(holdID, "capture", resp)
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
		if p.agentEnforcer != nil {
			p.agentEnforcer.RecordSpend(wfc.resolvedAgent.AgentID, route.PriceBaseUnits)
		}
		if p.spendRecorder != nil {
			_ = p.spendRecorder.RecordSpend(ctx, &agent.SpendRecord{
				TenantID:   wfc.wallet.TenantID,
				ProjectID:  wfc.resolvedAgent.ProjectID,
				AgentID:    wfc.resolvedAgent.AgentID,
				RouteID:    route.RouteID,
				AmountBase: route.PriceBaseUnits,
				Currency:   route.Asset,
				HoldID:     holdID,
				CapturedAt: time.Now().Unix(),
			})
		}
		wfc.emitSpendAudit(holdID, "capture", resp)
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

