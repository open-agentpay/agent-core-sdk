package settlement

import (
	"context"
	"fmt"
	"time"

	"github.com/agent-core-sdk/gateway/wallet"
)

// QuotaSettlementAdapter handles domestic & enterprise FinOps quota management.
// It relies strictly on internal database ledgers without touching crypto rails.
type QuotaSettlementAdapter struct {
	walletService wallet.Service
}

// NewQuotaSettlementAdapter creates an adapter backed by the virtual wallet service.
func NewQuotaSettlementAdapter(walletService wallet.Service) *QuotaSettlementAdapter {
	return &QuotaSettlementAdapter{
		walletService: walletService,
	}
}

func (q *QuotaSettlementAdapter) Name() string {
	return "quota-finops"
}

func (q *QuotaSettlementAdapter) Mode() string {
	return "quota"
}

// Authorize holds requested quota or credits before dispatching upstream LLM requests.
func (q *QuotaSettlementAdapter) Authorize(ctx context.Context, req *AuthorizationRequest) (*AuthorizationResult, error) {
	if q.walletService == nil {
		return nil, ErrAdapterNotConfigured
	}

	walletID := req.WalletID
	if walletID == "" && req.APIKeyID != "" {
		wAcc, err := q.walletService.GetWalletByAPIKey(ctx, req.APIKeyID)
		if err != nil {
			return &AuthorizationResult{
				Authorized: false,
				ErrorCode:  "WALLET_NOT_FOUND",
				Message:    fmt.Sprintf("failed to resolve wallet for api key: %v", err),
			}, nil
		}
		walletID = wAcc.WalletID
	}

	if walletID == "" {
		return &AuthorizationResult{
			Authorized: false,
			ErrorCode:  "MISSING_WALLET_IDENTITY",
			Message:    "wallet ID or valid API key is required for quota authorization",
		}, nil
	}

	holdID, err := q.walletService.HoldFunds(ctx, walletID, req.EstimatedAmount, req.RouteID)
	if err != nil {
		return &AuthorizationResult{
			Authorized: false,
			ErrorCode:  "QUOTA_EXCEEDED",
			Message:    err.Error(),
		}, nil
	}

	w, _ := q.walletService.GetWallet(ctx, walletID)
	var remaining int64
	if w != nil {
		remaining = w.AvailableCache
	}

	return &AuthorizationResult{
		Authorized:      true,
		AuthorizationID: holdID,
		RemainingQuota:  remaining,
	}, nil
}

// Settle captures the hold and confirms consumption.
func (q *QuotaSettlementAdapter) Settle(ctx context.Context, req *SettlementRequest) (*SettlementResult, error) {
	if q.walletService == nil {
		return nil, ErrAdapterNotConfigured
	}

	if req.AuthorizationID == "" {
		return nil, fmt.Errorf("authorization ID (hold ID) required for quota settlement")
	}

	err := q.walletService.CaptureFunds(ctx, req.AuthorizationID)
	if err != nil {
		return &SettlementResult{
			Success:      false,
			SettlementID: req.AuthorizationID,
			ErrorCode:    "CAPTURE_FAILED",
			Message:      err.Error(),
			SettledAt:    time.Now(),
		}, nil
	}

	return &SettlementResult{
		Success:      true,
		SettlementID: req.AuthorizationID,
		SettledAt:    time.Now(),
	}, nil
}

// Release releases pre-allocated quota holds on upstream failures (4xx/5xx).
func (q *QuotaSettlementAdapter) Release(ctx context.Context, authorizationID string) error {
	if q.walletService == nil {
		return ErrAdapterNotConfigured
	}
	if authorizationID == "" {
		return nil
	}
	return q.walletService.ReleaseFunds(ctx, authorizationID)
}
