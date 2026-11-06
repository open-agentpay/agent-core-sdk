package x402

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/agent-core-sdk/gateway/agent"
	"github.com/agent-core-sdk/gateway/payment"
	"github.com/agent-core-sdk/gateway/rcu"
	"github.com/agent-core-sdk/gateway/usage"
)

const defaultProjectID = "prj_default"

// reqScope holds the immutable per-request context shared by every payment flow.
type reqScope struct {
	p             *PaymentProcessor
	r             *http.Request
	route         *rcu.RouteConfig
	requestID     string
	startTime     time.Time
	clientIP      string
	configVersion string
	configHash    string
}

func newReqScope(
	p *PaymentProcessor, r *http.Request, route *rcu.RouteConfig,
	requestID string, snap *rcu.ConfigSnapshot,
) *reqScope {
	sc := &reqScope{
		p:         p,
		r:         r,
		route:     route,
		requestID: requestID,
		startTime: time.Now(),
		clientIP:  agent.ExtractClientIP(r),
	}
	if snap != nil {
		sc.configVersion = snap.VersionID
		sc.configHash = snap.SnapshotHash
	}
	return sc
}

// scopeIDs normalizes tenant/project IDs. Single source for the "prj_default" fallback.
func (s *reqScope) scopeIDs(tenantID, projectID string) (string, string) {
	if tenantID == "" {
		tenantID = s.route.TenantID
	}
	if (projectID == "" || projectID == defaultProjectID) && s.route.ProjectID != "" {
		projectID = s.route.ProjectID
	}
	if projectID == "" {
		projectID = defaultProjectID
	}
	return tenantID, projectID
}

func (s *reqScope) recordReq(
	tenantID, projectID, apiKeyID, agentID, intentID string,
	statusCode int, errorCode string, isReplay bool,
) {
	if s.p.usageService == nil {
		return
	}
	tID, pID := s.scopeIDs(tenantID, projectID)
	err := s.p.usageService.RecordRequest(s.r.Context(), &usage.RequestRecord{
		RequestID:     s.requestID,
		TenantID:      tID,
		ProjectID:     pID,
		APIKeyID:      apiKeyID,
		AgentID:       agentID,
		RouteID:       s.route.RouteID,
		ConfigVersion: s.configVersion,
		ClientIP:      s.clientIP,
		HTTPMethod:    s.r.Method,
		RequestPath:   s.r.URL.Path,
		StatusCode:    statusCode,
		DurationMs:    time.Since(s.startTime).Milliseconds(),
		ErrorCode:     errorCode,
		IsReplay:      isReplay,
		IntentID:      intentID,
		CreatedAt:     time.Now(),
	})
	if err != nil {
		slog.Error("failed to record request audit record",
			slog.String("request_id", s.requestID), slog.Any("error", err))
	}
}

func (s *reqScope) recordUsage(tenantID, projectID, agentID, intentID, paymentMethod string, isSuccess bool) {
	if s.p.usageService == nil {
		return
	}
	tID, pID := s.scopeIDs(tenantID, projectID)
	err := s.p.usageService.RecordUsage(s.r.Context(), &usage.UsageEvent{
		EventID:         usage.GenerateUsageEventID(),
		TenantID:        tID,
		ProjectID:       pID,
		AgentID:         agentID,
		RouteID:         s.route.RouteID,
		IntentID:        intentID,
		AmountBaseUnits: s.route.PriceBaseUnits,
		Asset:           s.route.Asset,
		PaymentMethod:   paymentMethod,
		IsSuccess:       isSuccess,
		CreatedAt:       time.Now(),
	})
	if err != nil {
		slog.Error("failed to record usage event",
			slog.String("request_id", s.requestID),
			slog.String("intent_id", intentID), slog.Any("error", err))
	}
}

func (s *reqScope) initIntent(tenantID, projectID, agentID, intentID, idemKey, paymentMethod, status string) {
	if s.p.paymentService == nil {
		return
	}
	tID, pID := s.scopeIDs(tenantID, projectID)
	err := s.p.paymentService.CreateIntent(s.r.Context(), &payment.PaymentIntent{
		IntentID:        intentID,
		TenantID:        tID,
		ProjectID:       pID,
		AgentID:         agentID,
		RouteID:         s.route.RouteID,
		IdempotencyKey:  idemKey,
		RequestID:       s.requestID,
		PaymentMethod:   paymentMethod,
		AmountBaseUnits: s.route.PriceBaseUnits,
		Asset:           s.route.Asset,
		Status:          status,
		ConfigVersionID: s.configVersion,
		CreatedAt:       s.startTime,
	})
	if err != nil {
		slog.Error("failed to create payment intent record",
			slog.String("request_id", s.requestID),
			slog.String("intent_id", intentID), slog.Any("error", err))
	}
}

func (s *reqScope) initSettlement(settlementID, intentID, paymentMethod, status, payer, payee, nonce, txHash string) {
	if s.p.paymentService == nil {
		return
	}
	err := s.p.paymentService.RecordSettlement(s.r.Context(), &payment.SettlementRecord{
		SettlementID:    settlementID,
		IntentID:        intentID,
		PaymentMethod:   paymentMethod,
		NetworkID:       s.route.Network,
		AssetAddress:    s.route.Asset,
		PayerAddress:    payer,
		PayeeAddress:    payee,
		AmountBaseUnits: s.route.PriceBaseUnits,
		Nonce:           nonce,
		TxHash:          txHash,
		Status:          status,
		CreatedAt:       s.startTime,
	})
	if err != nil {
		slog.Error("failed to record settlement record",
			slog.String("request_id", s.requestID),
			slog.String("settlement_id", settlementID), slog.Any("error", err))
	}
}

func (s *reqScope) initFulfillment(fulfillmentID, intentID string) {
	if s.p.paymentService == nil {
		return
	}
	err := s.p.paymentService.RecordFulfillment(s.r.Context(), &payment.FulfillmentRecord{
		FulfillmentID: fulfillmentID,
		IntentID:      intentID,
		UpstreamURL:   s.route.UpstreamURL,
		Status:        payment.FulfillmentStatusInProgress,
		CreatedAt:     s.startTime,
	})
	if err != nil {
		slog.Error("failed to record fulfillment record",
			slog.String("request_id", s.requestID),
			slog.String("fulfillment_id", fulfillmentID), slog.Any("error", err))
	}
}

// logIfErr keeps updateCorrelationOutcome flat.
func logIfErr(msg, key, id string, err error) {
	if err != nil {
		slog.Error(msg, slog.String(key, id), slog.Any("error", err))
	}
}

func (s *reqScope) updateCorrelationOutcome(intentID, settlementID, fulfillmentID string, statusCode int) {
	s.updateCorrelationOutcomeWithMode(intentID, settlementID, fulfillmentID, statusCode, true)
}

func (s *reqScope) updateCorrelationOutcomeWithMode(intentID, settlementID, fulfillmentID string, statusCode int, confirmSettlement bool) {
	ps := s.p.paymentService
	if ps == nil {
		return
	}
	ctx := s.r.Context()
	durationMs := time.Since(s.startTime).Milliseconds()

	switch {
	case statusCode >= 200 && statusCode < 300:
		logIfErr("failed to update fulfillment succeeded", "fulfillment_id", fulfillmentID,
			ps.UpdateFulfillment(ctx, fulfillmentID, payment.FulfillmentStatusSucceeded, statusCode, durationMs, ""))
		if confirmSettlement {
			logIfErr("failed to update settlement status confirmed", "settlement_id", settlementID,
				ps.UpdateSettlementStatus(ctx, settlementID, payment.SettlementStatusConfirmed, "", nil, ""))
			logIfErr("failed to update intent completed", "intent_id", intentID,
				ps.UpdateIntentStatus(ctx, intentID, payment.IntentStatusCompleted))
		}
	case statusCode >= 400 && statusCode < 500:
		logIfErr("failed to update fulfillment failed", "fulfillment_id", fulfillmentID,
			ps.UpdateFulfillment(ctx, fulfillmentID, payment.FulfillmentStatusFailed, statusCode, durationMs, ""))
		logIfErr("failed to update intent failed", "intent_id", intentID,
			ps.UpdateIntentStatus(ctx, intentID, payment.IntentStatusFailed))
	default:
		logIfErr("failed to update fulfillment unknown", "fulfillment_id", fulfillmentID,
			ps.UpdateFulfillment(ctx, fulfillmentID, payment.FulfillmentStatusUnknown, statusCode, durationMs, ""))
		logIfErr("failed to update intent needs review", "intent_id", intentID,
			ps.UpdateIntentStatus(ctx, intentID, payment.IntentStatusNeedsReview))
	}
}
