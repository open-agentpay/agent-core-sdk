package wallet

import (
	"context"
	"time"

	"github.com/open-agentpay/agent-core-sdk/gateway/x402"
)

// Service defines the virtual wallet and ledger management interface.
// It directly fulfills x402.WalletService required by PaymentProcessor.
type Service interface {
	// API Key & Wallet Resolution
	GetWalletByAPIKey(ctx context.Context, apiKey string) (*x402.WalletAccount, error)
	GetWallet(ctx context.Context, walletID string) (*Wallet, error)
	GetWalletByTenant(ctx context.Context, tenantID string) (*Wallet, error)

	// Payment Lifecycle
	HoldFunds(ctx context.Context, walletID string, amount int64, intentID string) (string, error)
	CaptureFunds(ctx context.Context, holdID string) error
	ReleaseFunds(ctx context.Context, holdID string) error

	// TopUp and Funds Injection
	CreditTopUp(ctx context.Context, order *TopUpOrder) error
	CreatePendingTopUp(ctx context.Context, order *TopUpOrder) error
	ConfirmTopUpPayment(ctx context.Context, topupID, externalRef string, paidAmountCents int64, confirmedAt time.Time) (*TopUpOrder, error)
	GetTopUpOrderByID(ctx context.Context, topupID string) (*TopUpOrder, error)
	AdjustBalance(ctx context.Context, walletID string, amount int64, reason, idempotencyKey, operatorID string) error
	SetWalletStatus(ctx context.Context, walletID string, status WalletStatus) error

	// Reconciliation and Expiry Recovery
	ReleaseExpiredHolds(ctx context.Context, before time.Time) (int64, error)
	GetLedgerEntries(ctx context.Context, walletID string) ([]*LedgerEntry, error)
	GetTopUpOrders(ctx context.Context, walletID string) ([]*TopUpOrder, error)
	ReconcileBalance(ctx context.Context, walletID string) (*ReconciliationReport, error)
}
