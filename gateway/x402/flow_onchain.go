package x402

import (
	"fmt"
	"github.com/open-agentpay/agent-core-sdk/gateway/idempotency"
	"github.com/open-agentpay/agent-core-sdk/gateway/payment"
	"github.com/open-agentpay/agent-core-sdk/gateway/proxy"
	"github.com/open-agentpay/agent-core-sdk/gateway/rcu"
	"github.com/open-agentpay/agent-core-sdk/gateway/recovery"
	"log/slog"
	"net/http"
	"strconv"
	"time"
)

func (p *PaymentProcessor) verifyOnChainPaymentAndNonce(
	w http.ResponseWriter,
	r *http.Request,
	route *rcu.RouteConfig,
	sc *reqScope,
	oc onchainParams,
	auth *PaymentAuthorization,
	intentID, settlementID, idemKey, idemTenantID string,
) (*VerificationResult, int64, bool) {
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
		return nil, 0, false
	}

	var ch *PaymentChallenge
	if auth.ChallengeID != "" {
		ch = p.getIssuedChallenge(auth.ChallengeID)
	}
	if ch == nil {
		ch = oc.verifyChallenge(auth)
	}
	effectivePrice := oc.Price
	if ch != nil {
		if cp, err := strconv.ParseInt(ch.Amount, 10, 64); err == nil && cp > 0 {
			effectivePrice = cp
		}
	}

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
		return nil, 0, false
	}

	sc.initIntent(route.TenantID, defaultProjectID, "", intentID, idemKey, "onchain", payment.IntentStatusAuthorized)
	sc.initSettlement(settlementID, intentID, "onchain", payment.SettlementStatusSubmitted, auth.Payer, route.PayeeAddress, auth.Nonce, "")
	sc.initFulfillment(fmt.Sprintf("ful_%s", sc.requestID), intentID)
	return result, effectivePrice, true
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
		result, effectivePrice, ok := p.verifyOnChainPaymentAndNonce(w, r, route, sc, oc, auth, intentID, settlementID, idemKey, tenantID)
		if !ok {
			return
		}

		// Register settlement in recovery coordinator
		_ = p.recoveryCoord.RegisterSettlement(&recovery.SettlementRecord{
			SettlementID:    settlementID,
			PaymentIntentID: intentID,
			PaymentMethod:   "onchain",
			Payer:           auth.Payer,
			Amount:          effectivePrice,
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
			AmountBaseUnits: effectivePrice,
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
			var pTok, cTok, tTok int64
			if resp != nil {
				pTok, cTok, tTok = extractTokensFromResponse(resp.Body)
			}
			sc.recordUsageWithTokens(route.TenantID, defaultProjectID, "", intentID, "onchain", true, pTok, cTok, tTok)
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
	result, effectivePrice, ok := p.verifyOnChainPaymentAndNonce(w, r, route, sc, oc, auth, intentID, settlementID, idemKey, "")
	if !ok {
		return
	}

	_ = p.recoveryCoord.RegisterSettlement(&recovery.SettlementRecord{
		SettlementID:    settlementID,
		PaymentIntentID: intentID,
		PaymentMethod:   "onchain",
		Payer:           auth.Payer,
		Amount:          effectivePrice,
		Asset:           oc.Asset,
		Network:         oc.Network,
		TxHashOrNonce:   auth.Nonce,
		Status:          recovery.SettlementSubmitted,
	})
	asyncSettle := p.resolveAsyncVerifier() != nil && result.VerificationToken != ""
	p.metrics.IncPaymentsVerified()
	pCtx := &proxy.PaymentContext{
		PayerAddress:    result.Payer,
		AmountBaseUnits: effectivePrice,
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
		var pTok, cTok, tTok int64
		if resp != nil {
			pTok, cTok, tTok = extractTokensFromResponse(resp.Body)
		}
		sc.recordUsageWithTokens(route.TenantID, defaultProjectID, "", intentID, "onchain", true, pTok, cTok, tTok)
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
	chPrice := oc.Price
	var pricingBreakdown map[string]interface{}
	if p.priceCalculator != nil {
		if calcPrice, breakdown, err := p.priceCalculator.CalculatePrice(r.Context(), oc.Network, oc.Contract, oc.Price); err == nil && calcPrice > 0 {
			chPrice = calcPrice
			pricingBreakdown = breakdown
		}
	}
	ch := oc.newChallengeWithPrice(r.URL.Path, 300*time.Second, chPrice)
	if pricingBreakdown != nil {
		if ch.Extensions == nil {
			ch.Extensions = make(map[string]interface{})
		}
		ch.Extensions["pricing"] = pricingBreakdown
	}
	if route.AllowedPaymentMethods == "both" {
		if ch.Extensions == nil {
			ch.Extensions = make(map[string]interface{})
		}
		ch.Extensions["allowedPaymentMethods"] = "both"
		ch.Extensions["walletSupported"] = true
	}
	p.recordIssuedChallenge(ch)
	intentID := "pi_" + ch.ChallengeID
	// Keep Idempotency-Key off the provisional challenged intent so the retry can bind it cleanly.
	sc.initIntent(route.TenantID, defaultProjectID, "", intentID, "", "onchain", payment.IntentStatusChallenged)
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
