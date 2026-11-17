package x402

import (
	"context"
	"errors"
	"github.com/open-agentpay/agent-core-sdk/gateway/payment"
	"github.com/open-agentpay/agent-core-sdk/gateway/recovery"
	"log/slog"
	"strings"
	"time"
)

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
