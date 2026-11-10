package wallet

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/open-agentpay/agent-core-sdk/gateway/x402"
)

// MemoryService provides an in-memory, thread-safe implementation of Service.
type MemoryService struct {
	mu                 sync.RWMutex
	wallets            map[string]*Wallet
	tenantWallets      map[string]string // tenantID -> walletID
	apiKeys            map[string]*APIKeyRecord
	holds              map[string]*Hold
	ledgerEntries      map[string][]*LedgerEntry
	ledgerIdempotency  map[string]bool // walletID:idempotencyKey -> bool
	topups             map[string]*TopUpOrder
	defaultHoldTTL     time.Duration
}

// NewMemoryService creates an initialized MemoryService.
func NewMemoryService() *MemoryService {
	return &MemoryService{
		wallets:           make(map[string]*Wallet),
		tenantWallets:     make(map[string]string),
		apiKeys:           make(map[string]*APIKeyRecord),
		holds:             make(map[string]*Hold),
		ledgerEntries:     make(map[string][]*LedgerEntry),
		ledgerIdempotency: make(map[string]bool),
		topups:            make(map[string]*TopUpOrder),
		defaultHoldTTL:    120 * time.Second,
	}
}

// SetDefaultHoldTTL overrides default hold reservation time-to-live.
func (m *MemoryService) SetDefaultHoldTTL(ttl time.Duration) {
	if ttl > 0 {
		m.defaultHoldTTL = ttl
	}
}

// RegisterWallet registers or updates a wallet record in memory.
func (m *MemoryService) RegisterWallet(w *Wallet) {
	m.mu.Lock()
	defer m.mu.Unlock()

	copied := *w
	m.wallets[w.WalletID] = &copied
	m.tenantWallets[w.TenantID] = w.WalletID
}

// RegisterAPIKey binds an API key token to a tenant.
func (m *MemoryService) RegisterAPIKey(apiKey, tenantID, projectID string, agentID ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var aID string
	if len(agentID) > 0 {
		aID = agentID[0]
	}

	rec := &APIKeyRecord{
		KeyID:     apiKey,
		TenantID:  tenantID,
		ProjectID: projectID,
		AgentID:   aID,
		KeyHash:   HashAPIKey(apiKey),
		KeyPrefix: apiKey[:min(len(apiKey), 8)],
		Status:    "active",
	}
	m.apiKeys[apiKey] = rec
	m.apiKeys[rec.KeyHash] = rec
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GetWalletByAPIKey resolves an API key token to the tenant's primary wallet account.
func (m *MemoryService) GetWalletByAPIKey(ctx context.Context, apiKey string) (*x402.WalletAccount, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rec, ok := m.apiKeys[apiKey]
	if !ok {
		rec, ok = m.apiKeys[HashAPIKey(apiKey)]
	}
	if !ok || rec.Status != "active" {
		return nil, ErrAPIKeyInvalid
	}

	wID, ok := m.tenantWallets[rec.TenantID]
	if !ok {
		return nil, ErrWalletNotFound
	}

	w, ok := m.wallets[wID]
	if !ok {
		return nil, ErrWalletNotFound
	}

	return &x402.WalletAccount{
		WalletID:         w.WalletID,
		TenantID:         w.TenantID,
		APIKeyID:         rec.KeyID,
		ProjectID:        rec.ProjectID,
		AgentID:          rec.AgentID,
		Status:           string(w.Status),
		AvailableBalance: w.AvailableCache,
		HeldBalance:      w.HeldCache,
	}, nil
}

// GetWallet retrieves wallet details by walletID.
func (m *MemoryService) GetWallet(ctx context.Context, walletID string) (*Wallet, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	w, ok := m.wallets[walletID]
	if !ok {
		return nil, ErrWalletNotFound
	}
	copied := *w
	return &copied, nil
}

// GetWalletByTenant retrieves wallet details by tenantID.
func (m *MemoryService) GetWalletByTenant(ctx context.Context, tenantID string) (*Wallet, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	wID, ok := m.tenantWallets[tenantID]
	if !ok {
		return nil, ErrWalletNotFound
	}
	w, ok := m.wallets[wID]
	if !ok {
		return nil, ErrWalletNotFound
	}
	copied := *w
	return &copied, nil
}

// SetWalletStatus updates the status of a wallet.
func (m *MemoryService) SetWalletStatus(ctx context.Context, walletID string, status WalletStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	w, ok := m.wallets[walletID]
	if !ok {
		return ErrWalletNotFound
	}
	w.Status = status
	w.UpdatedAt = time.Now()
	return nil
}

// HoldFunds reserves funds atomically from available cache.
func (m *MemoryService) HoldFunds(ctx context.Context, walletID string, amount int64, intentID string) (string, error) {
	if amount <= 0 {
		return "", fmt.Errorf("hold amount must be positive, got %d", amount)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	w, ok := m.wallets[walletID]
	if !ok {
		return "", ErrWalletNotFound
	}

	if w.Status == StatusFrozen || w.Status == StatusFrozenArrears || w.Status == StatusClosed {
		return "", ErrWalletFrozen
	}

	if w.AvailableCache < amount {
		return "", ErrInsufficientBalance
	}

	w.AvailableCache -= amount
	w.HeldCache += amount
	w.Version++
	w.UpdatedAt = time.Now()

	holdID := fmt.Sprintf("hld_%s_%d", intentID, time.Now().UnixNano())
	now := time.Now()
	hold := &Hold{
		HoldID:          holdID,
		WalletID:        walletID,
		PaymentIntentID: intentID,
		Amount:          amount,
		Status:          HoldStatusHeld,
		ExpiresAt:       now.Add(m.defaultHoldTTL),
		CreatedAt:       now,
	}
	m.holds[holdID] = hold

	return holdID, nil
}

// CaptureFunds confirms deduction of held funds and commits to append-only ledger.
func (m *MemoryService) CaptureFunds(ctx context.Context, holdID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	hold, ok := m.holds[holdID]
	if !ok {
		return ErrHoldNotFound
	}

	// Idempotent completion check
	if hold.Status == HoldStatusCaptured {
		return nil
	}

	if hold.Status != HoldStatusHeld {
		return fmt.Errorf("cannot capture hold in state: %s", hold.Status)
	}

	w, ok := m.wallets[hold.WalletID]
	if !ok {
		return ErrWalletNotFound
	}

	// Update wallet caches
	w.HeldCache -= hold.Amount
	w.Version++
	w.UpdatedAt = time.Now()

	hold.Status = HoldStatusCaptured

	// Append immutable ledger entry
	now := time.Now()
	idemKey := "cap_" + hold.HoldID
	entry := &LedgerEntry{
		EntryID:        fmt.Sprintf("ent_%d", now.UnixNano()),
		WalletID:       w.WalletID,
		TenantID:       w.TenantID,
		Type:           LedgerTypeCapture,
		Amount:         -hold.Amount,
		IdempotencyKey: idemKey,
		RefType:        "Hold",
		RefID:          hold.HoldID,
		CreatedAt:      now,
	}

	compKey := w.WalletID + ":" + idemKey
	if !m.ledgerIdempotency[compKey] {
		m.ledgerEntries[w.WalletID] = append(m.ledgerEntries[w.WalletID], entry)
		m.ledgerIdempotency[compKey] = true
	}

	return nil
}

// ReleaseFunds cancels the hold and refunds amounts back to available cache.
func (m *MemoryService) ReleaseFunds(ctx context.Context, holdID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	hold, ok := m.holds[holdID]
	if !ok {
		return ErrHoldNotFound
	}

	// Idempotent release check
	if hold.Status == HoldStatusReleased {
		return nil
	}

	if hold.Status != HoldStatusHeld {
		return fmt.Errorf("cannot release hold in state: %s", hold.Status)
	}

	w, ok := m.wallets[hold.WalletID]
	if !ok {
		return ErrWalletNotFound
	}

	w.HeldCache -= hold.Amount
	w.AvailableCache += hold.Amount
	w.Version++
	w.UpdatedAt = time.Now()

	hold.Status = HoldStatusReleased
	return nil
}

// CreditTopUp increases available funds and registers ledger credit.
func (m *MemoryService) CreditTopUp(ctx context.Context, order *TopUpOrder) error {
	if order.Amount <= 0 {
		return fmt.Errorf("topup amount must be positive, got %d", order.Amount)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	w, ok := m.wallets[order.WalletID]
	if !ok {
		return ErrWalletNotFound
	}

	now := time.Now()
	order.Status = TopUpStatusConfirmed
	order.ConfirmedAt = now
	m.topups[order.TopUpID] = order

	w.AvailableCache += order.Amount
	w.Version++
	w.UpdatedAt = now

	// Arrears recovery: if balance is restored to non-negative, recover to active (W6)
	if w.Status == StatusFrozenArrears && w.AvailableCache >= 0 {
		w.Status = StatusActive
	}

	// Append immutable ledger entry
	idemKey := "top_" + order.TopUpID
	entry := &LedgerEntry{
		EntryID:        fmt.Sprintf("ent_%d", now.UnixNano()),
		WalletID:       w.WalletID,
		TenantID:       w.TenantID,
		Type:           LedgerTypeTopupCredit,
		Amount:         order.Amount,
		IdempotencyKey: idemKey,
		RefType:        "TopUpOrder",
		RefID:          order.TopUpID,
		OperatorID:     order.OperatorID,
		Reason:         order.Reason,
		CreatedAt:      now,
	}

	compKey := w.WalletID + ":" + idemKey
	if !m.ledgerIdempotency[compKey] {
		m.ledgerEntries[w.WalletID] = append(m.ledgerEntries[w.WalletID], entry)
		m.ledgerIdempotency[compKey] = true
	}

	return nil
}

// CreatePendingTopUp creates a topup order in pending status.
func (m *MemoryService) CreatePendingTopUp(ctx context.Context, order *TopUpOrder) error {
	if order.Amount <= 0 {
		return fmt.Errorf("topup amount must be positive, got %d", order.Amount)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.wallets[order.WalletID]; !ok {
		return ErrWalletNotFound
	}

	order.Status = TopUpStatusPending
	order.CreatedAt = time.Now()
	m.topups[order.TopUpID] = order
	return nil
}

// ConfirmTopUpPayment transitions a pending topup order to confirmed and credits the wallet.
func (m *MemoryService) ConfirmTopUpPayment(ctx context.Context, topupID, externalRef string, paidAmountCents int64, reason string, confirmedAt time.Time) (*TopUpOrder, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	order, ok := m.topups[topupID]
	if !ok {
		// Try search by external_ref or idempotency
		for _, o := range m.topups {
			if o.ExternalRef == externalRef || o.TopUpID == topupID {
				order = o
				break
			}
		}
	}
	if order == nil {
		return nil, fmt.Errorf("topup order %s not found", topupID)
	}

	// Idempotent return if already confirmed
	if order.Status == TopUpStatusConfirmed {
		return order, nil
	}

	if order.Status != TopUpStatusPending && order.Status != TopUpStatusCreated {
		return nil, fmt.Errorf("cannot confirm order in status %s", order.Status)
	}

	if paidAmountCents > 0 && order.Amount != paidAmountCents {
		return nil, fmt.Errorf("payment amount mismatch: expected %d, got %d", order.Amount, paidAmountCents)
	}

	w, ok := m.wallets[order.WalletID]
	if !ok {
		return nil, ErrWalletNotFound
	}

	if confirmedAt.IsZero() {
		confirmedAt = time.Now()
	}
	if reason != "" {
		order.Reason = reason
	}
	if order.Reason == "" {
		order.Reason = "fiat_topup_credit"
	}
	order.Status = TopUpStatusConfirmed
	order.ConfirmedAt = confirmedAt
	order.ExternalRef = externalRef

	w.AvailableCache += order.Amount
	w.Version++
	w.UpdatedAt = confirmedAt

	if w.Status == StatusFrozenArrears && w.AvailableCache >= 0 {
		w.Status = StatusActive
	}

	idemKey := "top_" + order.TopUpID
	entry := &LedgerEntry{
		EntryID:        fmt.Sprintf("ent_%d", confirmedAt.UnixNano()),
		WalletID:       w.WalletID,
		TenantID:       w.TenantID,
		Type:           LedgerTypeTopupCredit,
		Amount:         order.Amount,
		IdempotencyKey: idemKey,
		RefType:        "TopUpOrder",
		RefID:          order.TopUpID,
		OperatorID:     order.OperatorID,
		Reason:         order.Reason,
		CreatedAt:      confirmedAt,
	}

	compKey := w.WalletID + ":" + idemKey
	if !m.ledgerIdempotency[compKey] {
		m.ledgerEntries[w.WalletID] = append(m.ledgerEntries[w.WalletID], entry)
		m.ledgerIdempotency[compKey] = true
	}

	return order, nil
}

// GetTopUpOrderByID retrieves a specific topup order.
func (m *MemoryService) GetTopUpOrderByID(ctx context.Context, topupID string) (*TopUpOrder, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	order, ok := m.topups[topupID]
	if !ok {
		return nil, fmt.Errorf("topup order %s not found", topupID)
	}
	return order, nil
}

// AdjustBalance increases or decreases available funds and registers ledger adjustment.
func (m *MemoryService) AdjustBalance(ctx context.Context, walletID string, amount int64, reason, idempotencyKey, operatorID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	w, ok := m.wallets[walletID]
	if !ok {
		return ErrWalletNotFound
	}

	now := time.Now()
	w.AvailableCache += amount
	w.Version++
	w.UpdatedAt = now

	// Arrears transitions
	if w.Status == StatusFrozenArrears && w.AvailableCache >= 0 {
		w.Status = StatusActive
	} else if w.Status == StatusActive && w.AvailableCache < 0 {
		w.Status = StatusFrozenArrears
	}

	idemKey := idempotencyKey
	if idemKey == "" {
		idemKey = fmt.Sprintf("adj_%d", now.UnixNano())
	}
	entry := &LedgerEntry{
		EntryID:        fmt.Sprintf("ent_%d", now.UnixNano()),
		WalletID:       w.WalletID,
		TenantID:       w.TenantID,
		Type:           LedgerTypeAdjustment,
		Amount:         amount,
		IdempotencyKey: idemKey,
		RefType:        "Adjustment",
		RefID:          idemKey,
		OperatorID:     operatorID,
		Reason:         reason,
		CreatedAt:      now,
	}

	compKey := w.WalletID + ":" + idemKey
	if !m.ledgerIdempotency[compKey] {
		m.ledgerEntries[w.WalletID] = append(m.ledgerEntries[w.WalletID], entry)
		m.ledgerIdempotency[compKey] = true
	}

	return nil
}

// ReleaseExpiredHolds sweeps all holds that timed out and returns amounts to available balance.
func (m *MemoryService) ReleaseExpiredHolds(ctx context.Context, before time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var count int64
	for _, hold := range m.holds {
		if hold.Status == HoldStatusHeld && !hold.ExpiresAt.After(before) {
			w, ok := m.wallets[hold.WalletID]
			if ok {
				w.HeldCache -= hold.Amount
				w.AvailableCache += hold.Amount
				w.Version++
				w.UpdatedAt = time.Now()
			}
			hold.Status = HoldStatusExpired
			count++
		}
	}

	return count, nil
}

// GetLedgerEntries retrieves all immutable financial ledger rows for a wallet.
func (m *MemoryService) GetLedgerEntries(ctx context.Context, walletID string) ([]*LedgerEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entries := m.ledgerEntries[walletID]
	copied := make([]*LedgerEntry, len(entries))
	copy(copied, entries)
	return copied, nil
}

// GetTopUpOrders retrieves all top-up orders for a wallet sorted by creation time descending.
func (m *MemoryService) GetTopUpOrders(ctx context.Context, walletID string) ([]*TopUpOrder, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*TopUpOrder
	for _, ord := range m.topups {
		if ord.WalletID == walletID {
			copied := *ord
			result = append(result, &copied)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})
	return result, nil
}

// ReconcileBalance computes double-entry balance check against immutable ledger and active holds.
func (m *MemoryService) ReconcileBalance(ctx context.Context, walletID string) (*ReconciliationReport, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	w, ok := m.wallets[walletID]
	if !ok {
		return nil, ErrWalletNotFound
	}

	var sumLedger int64
	for _, ent := range m.ledgerEntries[walletID] {
		sumLedger += ent.Amount
	}

	var sumHolds int64
	for _, hld := range m.holds {
		if hld.WalletID == walletID && hld.Status == HoldStatusHeld {
			sumHolds += hld.Amount
		}
	}

	totalInWallet := w.AvailableCache + w.HeldCache
	isBalanced := (sumHolds == w.HeldCache)
	discrepancy := totalInWallet - sumLedger

	return &ReconciliationReport{
		WalletID:         walletID,
		AvailableCache:   w.AvailableCache,
		HeldCache:        w.HeldCache,
		TotalInWallet:    totalInWallet,
		SumLedgerEntries: sumLedger,
		SumActiveHolds:   sumHolds,
		IsBalanced:       isBalanced,
		Discrepancy:      discrepancy,
	}, nil
}
