package settlement

import (
	"context"
	"time"

	"github.com/open-agentpay/agent-core-sdk/gateway/x402"
)

// CryptoSettlementAdapter handles overseas Web3/EVM blockchain settlements via Facilitator.
type CryptoSettlementAdapter struct {
	verifier x402.PaymentVerifier
}

// NewCryptoSettlementAdapter constructs an adapter backed by an x402 PaymentVerifier.
func NewCryptoSettlementAdapter(verifier x402.PaymentVerifier) *CryptoSettlementAdapter {
	return &CryptoSettlementAdapter{
		verifier: verifier,
	}
}

func (c *CryptoSettlementAdapter) Name() string {
	return "crypto-facilitator"
}

func (c *CryptoSettlementAdapter) Mode() string {
	return "crypto"
}

// Authorize delegates cryptographic signature verification to the verifier / Facilitator.
func (c *CryptoSettlementAdapter) Authorize(ctx context.Context, req *AuthorizationRequest) (*AuthorizationResult, error) {
	if c.verifier == nil {
		return nil, ErrAdapterNotConfigured
	}

	authPayload, ok := req.Metadata["payment_authorization"].(*x402.PaymentAuthorization)
	if !ok || authPayload == nil {
		return &AuthorizationResult{
			Authorized: false,
			ErrorCode:  "MISSING_CRYPTO_AUTH",
			Message:    "valid payment authorization payload required for crypto settlement",
		}, nil
	}

	challenge, ok := req.Metadata["payment_challenge"].(*x402.PaymentChallenge)
	if !ok || challenge == nil {
		return &AuthorizationResult{
			Authorized: false,
			ErrorCode:  "MISSING_CHALLENGE",
			Message:    "payment challenge required for crypto verification",
		}, nil
	}

	res, err := c.verifier.VerifyPayment(ctx, challenge, authPayload)
	if err != nil {
		return &AuthorizationResult{
			Authorized: false,
			ErrorCode:  "VERIFICATION_ERROR",
			Message:    err.Error(),
		}, nil
	}

	if !res.Valid {
		return &AuthorizationResult{
			Authorized: false,
			ErrorCode:  res.ErrorCode,
			Message:    res.Message,
		}, nil
	}

	return &AuthorizationResult{
		Authorized:      true,
		AuthorizationID: res.VerificationToken,
	}, nil
}

// Settle records or dispatches the on-chain settlement task.
func (c *CryptoSettlementAdapter) Settle(ctx context.Context, req *SettlementRequest) (*SettlementResult, error) {
	if c.verifier == nil {
		return nil, ErrAdapterNotConfigured
	}

	// In async facilitator settlement, verification token is accepted as cleared settlement record ID
	return &SettlementResult{
		Success:      true,
		SettlementID: req.AuthorizationID,
		SettledAt:    time.Now(),
	}, nil
}

// Release is a no-op for cryptographic signatures if unbroadcasted.
func (c *CryptoSettlementAdapter) Release(ctx context.Context, authorizationID string) error {
	// Signatures not submitted for on-chain mining expire automatically without gas expenditure.
	_ = authorizationID
	return nil
}

// Ensure interface compliance
var (
	_ SettlementAdapter = (*QuotaSettlementAdapter)(nil)
	_ SettlementAdapter = (*CryptoSettlementAdapter)(nil)
)
