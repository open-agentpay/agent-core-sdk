package recovery

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// SettlementState defines canonical settlement lifecycle states per T1.1 Specification.
type SettlementState string

const (
	SettlementNotStarted SettlementState = "not_started"
	SettlementHeld       SettlementState = "held"
	SettlementSubmitted  SettlementState = "submitted"
	SettlementPending    SettlementState = "pending"
	SettlementConfirmed  SettlementState = "confirmed"
	SettlementFailed     SettlementState = "failed"
	SettlementReleased   SettlementState = "released"
	SettlementUnknown    SettlementState = "unknown"
)

// IsTerminal returns true if the settlement has reached an immutable terminal state.
func (s SettlementState) IsTerminal() bool {
	return s == SettlementConfirmed || s == SettlementFailed || s == SettlementReleased
}

// SettlementRecord tracks a financial settlement attempt.
type SettlementRecord struct {
	SettlementID    string
	PaymentIntentID string
	PaymentMethod   string // "wallet" or "onchain"
	Payer           string
	Amount          int64
	Asset           string
	Network         string
	TxHashOrNonce   string
	Status          SettlementState
	Confirmations   int
	FailureReason   string
	UpdatedAt       time.Time
}

var (
	ErrBlindRetryProhibited = errors.New("HARD RULE VIOLATION: blind re-submission prohibited while settlement is unknown")
	ErrTerminalState        = errors.New("HARD RULE VIOLATION: cannot mutate a settlement in terminal state")
	ErrSettlementNotFound   = errors.New("settlement record not found")
)

// RecoveryCoordinator manages state tracking, query-based reconciliation, and anti-rollback guards.
type RecoveryCoordinator struct {
	mu          sync.RWMutex
	settlements map[string]*SettlementRecord
}

// NewRecoveryCoordinator creates an initialized RecoveryCoordinator.
func NewRecoveryCoordinator() *RecoveryCoordinator {
	return &RecoveryCoordinator{
		settlements: make(map[string]*SettlementRecord),
	}
}

// RegisterSettlement registers a new settlement record.
func (c *RecoveryCoordinator) RegisterSettlement(rec *SettlementRecord) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.settlements[rec.SettlementID]; exists {
		return fmt.Errorf("settlement %s already registered", rec.SettlementID)
	}
	rec.UpdatedAt = time.Now()
	c.settlements[rec.SettlementID] = rec
	return nil
}

// GetSettlement retrieves the settlement record.
func (c *RecoveryCoordinator) GetSettlement(settlementID string) (*SettlementRecord, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	rec, ok := c.settlements[settlementID]
	if !ok {
		return nil, ErrSettlementNotFound
	}
	copyRec := *rec
	return &copyRec, nil
}

// MarkUnknown transitions a submitted or pending settlement to unknown (e.g. timeout or transport crash).
func (c *RecoveryCoordinator) MarkUnknown(settlementID string, reason string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	rec, ok := c.settlements[settlementID]
	if !ok {
		return ErrSettlementNotFound
	}
	if rec.Status.IsTerminal() {
		return ErrTerminalState
	}

	rec.Status = SettlementUnknown
	rec.FailureReason = reason
	rec.UpdatedAt = time.Now()
	return nil
}

// GuardAgainstBlindRetry enforces Hard Rule 5: NO re-submitting when status is unknown.
func (c *RecoveryCoordinator) GuardAgainstBlindRetry(settlementID string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	rec, ok := c.settlements[settlementID]
	if !ok {
		return nil // Not found, not a blind retry of an existing unknown
	}
	if rec.Status == SettlementUnknown {
		return ErrBlindRetryProhibited
	}
	return nil
}

// ReconcileStatus inspects the definitive state from a ledger or blockchain query and transitions.
// It strictly forbids re-submitting and only updates via verified on-chain evidence.
func (c *RecoveryCoordinator) ReconcileStatus(ctx context.Context, settlementID string, onchainSeen bool, confirmed bool, reverted bool) (*SettlementRecord, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	rec, ok := c.settlements[settlementID]
	if !ok {
		return nil, ErrSettlementNotFound
	}
	if rec.Status.IsTerminal() {
		return rec, ErrTerminalState
	}

	now := time.Now()
	rec.UpdatedAt = now

	if confirmed {
		rec.Status = SettlementConfirmed
		rec.Confirmations = 1
		rec.FailureReason = ""
		return rec, nil
	}

	if reverted {
		rec.Status = SettlementFailed
		rec.FailureReason = "transaction reverted on-chain"
		return rec, nil
	}

	if onchainSeen {
		rec.Status = SettlementPending
		return rec, nil
	}

	// Still not seen on chain: keep unknown
	rec.Status = SettlementUnknown
	return rec, nil
}
