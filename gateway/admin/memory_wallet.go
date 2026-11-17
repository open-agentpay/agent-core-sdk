package admin

import (
	"context"
	"fmt"
	"github.com/open-agentpay/agent-core-sdk/gateway/wallet"
	"strings"
	"time"
)

func (s *MemoryService) AdminGrantWallet(ctx context.Context, tenantID string, amount int64, reason string, idempotencyKey string, actorMemberID string, clientIP string) error {
	cleanReason := strings.TrimSpace(reason)
	if cleanReason == "" {
		return ErrMissingReason
	}
	if amount <= 0 {
		return ErrInvalidAmount
	}
	if err := s.checkPermissionRLock(tenantID, actorMemberID, PermissionWalletAdjust); err != nil {
		return err
	}

	w, err := s.walletSvc.GetWalletByTenant(ctx, tenantID)
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
	if err := s.walletSvc.CreditTopUp(ctx, order); err != nil {
		return err
	}

	s.recordAudit(tenantID, actorMemberID, "wallet.admin_grant", "Wallet", w.WalletID, nil, map[string]interface{}{"amount": amount, "reason": cleanReason}, clientIP)
	return nil
}

func (s *MemoryService) AdjustWallet(ctx context.Context, walletID string, amount int64, reason string, idempotencyKey string, actorMemberID string, clientIP string) error {
	cleanReason := strings.TrimSpace(reason)
	if cleanReason == "" {
		return ErrMissingReason
	}

	w, err := s.walletSvc.GetWallet(ctx, walletID)
	if err != nil {
		return ErrWalletNotFound
	}
	if err := s.checkPermissionRLock(w.TenantID, actorMemberID, PermissionWalletAdjust); err != nil {
		return err
	}
	if err := s.walletSvc.AdjustBalance(ctx, walletID, amount, cleanReason, idempotencyKey, actorMemberID); err != nil {
		return err
	}

	s.recordAudit(w.TenantID, actorMemberID, "wallet.adjust", "Wallet", walletID, nil, map[string]interface{}{"amount": amount, "reason": cleanReason}, clientIP)
	return nil
}

func (s *MemoryService) FreezeWallet(ctx context.Context, walletID string, reason string, actorMemberID string, clientIP string) error {
	cleanReason := strings.TrimSpace(reason)
	if cleanReason == "" {
		return ErrMissingReason
	}

	w, err := s.walletSvc.GetWallet(ctx, walletID)
	if err != nil {
		return ErrWalletNotFound
	}
	if err := s.checkPermissionRLock(w.TenantID, actorMemberID, PermissionWalletAdjust); err != nil {
		return err
	}
	if err := s.walletSvc.SetWalletStatus(ctx, walletID, wallet.StatusFrozen); err != nil {
		return err
	}

	s.recordAudit(w.TenantID, actorMemberID, "wallet.frozen", "Wallet", walletID, nil, map[string]interface{}{"reason": cleanReason}, clientIP)
	return nil
}

func (s *MemoryService) UnfreezeWallet(ctx context.Context, walletID string, reason string, actorMemberID string, clientIP string) error {
	cleanReason := strings.TrimSpace(reason)
	if cleanReason == "" {
		return ErrMissingReason
	}

	w, err := s.walletSvc.GetWallet(ctx, walletID)
	if err != nil {
		return ErrWalletNotFound
	}
	if err := s.checkPermissionRLock(w.TenantID, actorMemberID, PermissionWalletAdjust); err != nil {
		return err
	}
	if w.Status == wallet.StatusFrozenArrears && w.AvailableCache < 0 {
		return fmt.Errorf("cannot unfreeze wallet in arrears")
	}
	if err := s.walletSvc.SetWalletStatus(ctx, walletID, wallet.StatusActive); err != nil {
		return err
	}

	s.recordAudit(w.TenantID, actorMemberID, "wallet.unfrozen", "Wallet", walletID, nil, map[string]interface{}{"reason": cleanReason}, clientIP)
	return nil
}

func (s *MemoryService) RecalculateWallet(ctx context.Context, walletID string, actorMemberID string) (map[string]interface{}, error) {
	w, err := s.walletSvc.GetWallet(ctx, walletID)
	if err != nil {
		return nil, ErrWalletNotFound
	}
	if err := s.checkPermissionRLock(w.TenantID, actorMemberID, PermissionWalletRead); err != nil {
		return nil, err
	}
	return recalculateWalletBalanceMap(ctx, s.walletSvc, walletID)
}

func (s *MemoryService) GetWallet(ctx context.Context, tenantID string) (*wallet.Wallet, error) {
	return s.walletSvc.GetWalletByTenant(ctx, tenantID)
}

func (s *MemoryService) GetWalletByID(ctx context.Context, walletID string) (*wallet.Wallet, error) {
	return s.walletSvc.GetWallet(ctx, walletID)
}

func (s *MemoryService) GetLedgerEntries(ctx context.Context, walletID string) ([]*wallet.LedgerEntry, error) {
	return s.walletSvc.GetLedgerEntries(ctx, walletID)
}

func (s *MemoryService) GetTopUpOrders(ctx context.Context, walletID string) ([]*wallet.TopUpOrder, error) {
	return s.walletSvc.GetTopUpOrders(ctx, walletID)
}

func (s *MemoryService) CreateTopUpOrder(ctx context.Context, tenantID string, amountCents int64, channel wallet.TopUpChannel, reason, actorMemberID string) (*wallet.TopUpOrder, error) {
	w, err := s.GetWallet(ctx, tenantID)
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
	if err := s.walletSvc.CreatePendingTopUp(ctx, order); err != nil {
		return nil, err
	}
	return order, nil
}

func (s *MemoryService) GetTopUpOrderByID(ctx context.Context, tenantID, topupID string) (*wallet.TopUpOrder, error) {
	return s.walletSvc.GetTopUpOrderByID(ctx, topupID)
}

func (s *MemoryService) ConfirmTopUpPayment(ctx context.Context, topupID, externalRef string, paidAmountCents int64, reason string, confirmedAt time.Time) (*wallet.TopUpOrder, error) {
	return s.walletSvc.ConfirmTopUpPayment(ctx, topupID, externalRef, paidAmountCents, reason, confirmedAt)
}

// ----------------------------------------------------------------------------
// Audit Events
// ----------------------------------------------------------------------------

