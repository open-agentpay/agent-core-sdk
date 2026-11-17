package x402

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type MemoryWalletService struct {
	mu          sync.Mutex
	wallets     map[string]*WalletAccount
	apiKeys     map[string]string    // apiKey -> walletID
	holds       map[string]int64     // holdID -> amount
	holdWIDs    map[string]string    // holdID -> walletID
	holdExpires map[string]time.Time // holdID -> expiresAt
}

// NewMemoryWalletService creates a thread-safe in-memory wallet service.
func NewMemoryWalletService() *MemoryWalletService {
	return &MemoryWalletService{
		wallets:     make(map[string]*WalletAccount),
		apiKeys:     make(map[string]string),
		holds:       make(map[string]int64),
		holdWIDs:    make(map[string]string),
		holdExpires: make(map[string]time.Time),
	}
}

// RegisterWallet registers an account and associates an API Key.
func (m *MemoryWalletService) RegisterWallet(apiKey string, w *WalletAccount) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.wallets[w.WalletID] = w
	m.apiKeys[apiKey] = w.WalletID
}

func (m *MemoryWalletService) GetWalletByAPIKey(ctx context.Context, apiKey string) (*WalletAccount, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	wID, ok := m.apiKeys[apiKey]
	if !ok {
		return nil, fmt.Errorf("invalid API key")
	}
	w, ok := m.wallets[wID]
	if !ok {
		return nil, fmt.Errorf("wallet not found")
	}
	return w, nil
}

func (m *MemoryWalletService) HoldFunds(ctx context.Context, walletID string, amount int64, intentID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w, ok := m.wallets[walletID]
	if !ok {
		return "", fmt.Errorf("wallet not found")
	}
	if w.Status != "active" {
		return "", fmt.Errorf("wallet is %s", w.Status)
	}
	if w.AvailableBalance < amount {
		return "", fmt.Errorf("insufficient available balance")
	}

	w.AvailableBalance -= amount
	w.HeldBalance += amount
	holdID := fmt.Sprintf("hld_%d", time.Now().UnixNano())
	m.holds[holdID] = amount
	m.holdWIDs[holdID] = walletID
	m.holdExpires[holdID] = time.Now().Add(120 * time.Second)
	return holdID, nil
}

func (m *MemoryWalletService) CaptureFunds(ctx context.Context, holdID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	amount, ok := m.holds[holdID]
	if !ok {
		return fmt.Errorf("hold not found")
	}
	wID := m.holdWIDs[holdID]
	w := m.wallets[wID]
	if w != nil {
		w.HeldBalance -= amount
	}
	delete(m.holds, holdID)
	delete(m.holdWIDs, holdID)
	delete(m.holdExpires, holdID)
	return nil
}

func (m *MemoryWalletService) ReleaseFunds(ctx context.Context, holdID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	amount, ok := m.holds[holdID]
	if !ok {
		return fmt.Errorf("hold not found")
	}
	wID := m.holdWIDs[holdID]
	w := m.wallets[wID]
	if w != nil {
		w.HeldBalance -= amount
		w.AvailableBalance += amount
	}
	delete(m.holds, holdID)
	delete(m.holdWIDs, holdID)
	delete(m.holdExpires, holdID)
	return nil
}

// ReleaseExpiredHolds releases all in-memory wallet holds that have expired before the given timestamp (P0-3).
func (m *MemoryWalletService) ReleaseExpiredHolds(ctx context.Context, before time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var released int64
	for holdID, exp := range m.holdExpires {
		if exp.Before(before) {
			amount := m.holds[holdID]
			wID := m.holdWIDs[holdID]
			if w := m.wallets[wID]; w != nil {
				w.HeldBalance -= amount
				w.AvailableBalance += amount
			}
			delete(m.holds, holdID)
			delete(m.holdWIDs, holdID)
			delete(m.holdExpires, holdID)
			released++
		}
	}
	return released, nil
}

// PaymentProcessor orchestrates dual-path routing, challenge generation, payment validation,
// idempotency enforcement, and anti-rollback failure recovery.
