package admin

import (
	"context"
	"fmt"
	"strings"
	"time"
	"github.com/open-agentpay/agent-core-sdk/gateway/wallet"
)

func (p *PostgresService) AdminGrantWallet(ctx context.Context, tenantID string, amount int64, reason string, idempotencyKey string, actorMemberID string, clientIP string) error {
	cleanReason := strings.TrimSpace(reason)
	if cleanReason == "" {
		return ErrMissingReason
	}
	if amount <= 0 {
		return ErrInvalidAmount
	}
	if err := p.enforcePermission(ctx, actorMemberID, tenantID, PermissionWalletAdjust); err != nil {
		return err
	}

	w, err := p.walletSvc.GetWalletByTenant(ctx, tenantID)
	if err != nil {
		return ErrWalletNotFound
	}

	now := time.Now()
	order := &wallet.TopUpOrder{
		TopUpID:     fmt.Sprintf("ord_%s_%d", tenantID, now.UnixNano()),
		WalletID:    w.WalletID,
		TenantID:    tenantID,
		Channel:     wallet.ChannelAdminGrant,
		Amount:      amount,
		Asset:       w.Asset,
		ExternalRef: idempotencyKey,
		Reason:      cleanReason,
		Status:      wallet.TopUpStatusConfirmed,
		CreatedAt:   now,
		ConfirmedAt: now,
	}
	if err := p.walletSvc.CreditTopUp(ctx, order); err != nil {
		return err
	}

	p.recordAudit(ctx, tenantID, actorMemberID, "wallet.admin_grant", "Wallet", w.WalletID, nil, map[string]interface{}{"amount": amount, "reason": cleanReason}, clientIP)
	return nil
}

func (p *PostgresService) AdjustWallet(ctx context.Context, walletID string, amount int64, reason string, idempotencyKey string, actorMemberID string, clientIP string) error {
	cleanReason := strings.TrimSpace(reason)
	if cleanReason == "" {
		return ErrMissingReason
	}

	w, err := p.walletSvc.GetWallet(ctx, walletID)
	if err != nil {
		return ErrWalletNotFound
	}
	if err := p.enforcePermission(ctx, actorMemberID, w.TenantID, PermissionWalletAdjust); err != nil {
		return err
	}
	if err := p.walletSvc.AdjustBalance(ctx, walletID, amount, cleanReason, idempotencyKey, actorMemberID); err != nil {
		return err
	}

	p.recordAudit(ctx, w.TenantID, actorMemberID, "wallet.adjust", "Wallet", walletID, nil, map[string]interface{}{"amount": amount, "reason": cleanReason}, clientIP)
	return nil
}

func (p *PostgresService) FreezeWallet(ctx context.Context, walletID string, reason string, actorMemberID string, clientIP string) error {
	cleanReason := strings.TrimSpace(reason)
	if cleanReason == "" {
		return ErrMissingReason
	}

	w, err := p.walletSvc.GetWallet(ctx, walletID)
	if err != nil {
		return ErrWalletNotFound
	}
	if err := p.enforcePermission(ctx, actorMemberID, w.TenantID, PermissionWalletAdjust); err != nil {
		return err
	}
	if err := p.walletSvc.SetWalletStatus(ctx, walletID, wallet.StatusFrozen); err != nil {
		return err
	}

	p.recordAudit(ctx, w.TenantID, actorMemberID, "wallet.frozen", "Wallet", walletID, nil, map[string]interface{}{"reason": cleanReason}, clientIP)
	return nil
}

func (p *PostgresService) UnfreezeWallet(ctx context.Context, walletID string, reason string, actorMemberID string, clientIP string) error {
	cleanReason := strings.TrimSpace(reason)
	if cleanReason == "" {
		return ErrMissingReason
	}

	w, err := p.walletSvc.GetWallet(ctx, walletID)
	if err != nil {
		return ErrWalletNotFound
	}
	if err := p.enforcePermission(ctx, actorMemberID, w.TenantID, PermissionWalletAdjust); err != nil {
		return err
	}
	if w.Status == wallet.StatusFrozenArrears && w.AvailableCache < 0 {
		return fmt.Errorf("cannot unfreeze wallet in arrears")
	}
	if err := p.walletSvc.SetWalletStatus(ctx, walletID, wallet.StatusActive); err != nil {
		return err
	}

	p.recordAudit(ctx, w.TenantID, actorMemberID, "wallet.unfrozen", "Wallet", walletID, nil, map[string]interface{}{"reason": cleanReason}, clientIP)
	return nil
}

func (p *PostgresService) RecalculateWallet(ctx context.Context, walletID string, actorMemberID string) (map[string]interface{}, error) {
	w, err := p.walletSvc.GetWallet(ctx, walletID)
	if err != nil {
		return nil, ErrWalletNotFound
	}
	if err := p.enforcePermission(ctx, actorMemberID, w.TenantID, PermissionWalletRead); err != nil {
		return nil, err
	}
	return recalculateWalletBalanceMap(ctx, p.walletSvc, walletID)
}

func (p *PostgresService) GetWallet(ctx context.Context, tenantID string) (*wallet.Wallet, error) {
	return p.walletSvc.GetWalletByTenant(ctx, tenantID)
}

func (p *PostgresService) GetWalletByID(ctx context.Context, walletID string) (*wallet.Wallet, error) {
	return p.walletSvc.GetWallet(ctx, walletID)
}

func (p *PostgresService) GetLedgerEntries(ctx context.Context, walletID string) ([]*wallet.LedgerEntry, error) {
	return p.walletSvc.GetLedgerEntries(ctx, walletID)
}

func (p *PostgresService) GetTopUpOrders(ctx context.Context, walletID string) ([]*wallet.TopUpOrder, error) {
	return p.walletSvc.GetTopUpOrders(ctx, walletID)
}

func (p *PostgresService) GetWalletService() wallet.Service {
	return p.walletSvc
}

func (p *PostgresService) CreateTopUpOrder(ctx context.Context, tenantID string, amountCents int64, channel wallet.TopUpChannel, reason, actorMemberID string) (*wallet.TopUpOrder, error) {
	w, err := p.GetWallet(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	topupID := fmt.Sprintf("top_%s_%d", tenantID, time.Now().UnixNano())
	r := reason
	if r == "" {
		r = "topup_credit"
	}
	order := &wallet.TopUpOrder{
		TopUpID:            topupID,
		WalletID:           w.WalletID,
		TenantID:           tenantID,
		Channel:            channel,
		Amount:             amountCents,
		Asset:              w.Asset,
		PaymentCurrency:    w.Asset,
		PaymentMinorAmount: amountCents,
		Status:             wallet.TopUpStatusPending,
		OperatorID:         actorMemberID,
		Reason:             r,
		CreatedAt:          time.Now(),
	}
	if err := p.walletSvc.CreatePendingTopUp(ctx, order); err != nil {
		return nil, err
	}
	return order, nil
}

func (p *PostgresService) GetTopUpOrderByID(ctx context.Context, tenantID, topupID string) (*wallet.TopUpOrder, error) {
	return p.walletSvc.GetTopUpOrderByID(ctx, topupID)
}

func (p *PostgresService) ConfirmTopUpPayment(ctx context.Context, topupID, externalRef string, paidAmountCents int64, reason string, confirmedAt time.Time) (*wallet.TopUpOrder, error) {
	return p.walletSvc.ConfirmTopUpPayment(ctx, topupID, externalRef, paidAmountCents, reason, confirmedAt)
}

// ----------------------------------------------------------------------------
// Audit Events
// ----------------------------------------------------------------------------

