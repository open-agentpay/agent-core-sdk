package idempotency

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Store defines the storage abstraction for idempotency records.
type Store interface {
	// CheckOrLock evaluates an incoming request against existing idempotency records.
	// If the key is new, it acquires the in-progress lock and creates a record.
	// If the key exists, it evaluates cache hits, free replays, or conflicts.
	CheckOrLock(ctx context.Context, tenantID, key, requestHash, intentID, paymentMethod string) (*Record, CheckResult, error)

	// AttachPaymentDetails updates the record with HoldID or SettlementID once payment is staged.
	AttachPaymentDetails(ctx context.Context, tenantID, key, holdID, settlementID string) error

	// MarkCompleted transitions the record to StateCompleted with cached status, headers, and body.
	MarkCompleted(ctx context.Context, tenantID, key string, statusCode int, headers map[string]string, body []byte) error

	// MarkRecoveryRequired transitions the record to StateRecoveryRequired upon upstream 5xx or timeout.
	MarkRecoveryRequired(ctx context.Context, tenantID, key string, statusCode int, reason string) error

	// ReleaseLock removes or frees an uncommitted lock (e.g. if pre-validation or budget check fails).
	ReleaseLock(ctx context.Context, tenantID, key string) error

	// GetRecord retrieves an existing record by tenant and key.
	GetRecord(ctx context.Context, tenantID, key string) (*Record, error)
}

// MemoryStore is a concurrent in-memory implementation of Store.
type MemoryStore struct {
	mu      sync.RWMutex
	records map[string]*Record // composite key: tenantID + ":" + key
	ttl     time.Duration
}

// NewMemoryStore creates an initialized MemoryStore.
func NewMemoryStore(ttl time.Duration) *MemoryStore {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &MemoryStore{
		records: make(map[string]*Record),
		ttl:     ttl,
	}
}

func (s *MemoryStore) compositeKey(tenantID, key string) string {
	return tenantID + ":" + key
}

// CheckOrLock atomically inspects and transitions the idempotency record.
func (s *MemoryStore) CheckOrLock(ctx context.Context, tenantID, key, requestHash, intentID, paymentMethod string) (*Record, CheckResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ck := s.compositeKey(tenantID, key)
	existing, found := s.records[ck]
	now := time.Now()

	if !found {
		// New request: acquire in-progress lock
		rec := &Record{
			TenantID:        tenantID,
			IdempotencyKey:  key,
			RequestHash:     requestHash,
			PaymentIntentID: intentID,
			PaymentMethod:   paymentMethod,
			State:           StateInProgress,
			AttemptCount:    1,
			CreatedAt:       now,
			UpdatedAt:       now,
		}
		s.records[ck] = rec
		return rec, ResultNew, nil
	}

	// Existing record found: check payload fingerprint consistency
	if existing.RequestHash != requestHash {
		// Conflict: same idempotency key reused for different request payload
		return existing, ResultConflict, nil
	}

	switch existing.State {
	case StateInProgress:
		// Another concurrent request with the exact same key is running
		return existing, ResultConflict, nil

	case StateCompleted:
		// Request previously completed; return cached result
		return existing, ResultCacheHit, nil

	case StateRecoveryRequired:
		// Upstream previously failed with 5xx or timeout; allow Free Replay
		existing.State = StateInProgress
		existing.AttemptCount++
		existing.UpdatedAt = now
		return existing, ResultFreeReplay, nil

	default:
		return existing, ResultConflict, nil
	}
}

// AttachPaymentDetails updates payment references on the existing record.
func (s *MemoryStore) AttachPaymentDetails(ctx context.Context, tenantID, key, holdID, settlementID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ck := s.compositeKey(tenantID, key)
	rec, found := s.records[ck]
	if !found {
		return fmt.Errorf("idempotency record not found for key: %s", key)
	}

	if holdID != "" {
		rec.HoldID = holdID
	}
	if settlementID != "" {
		rec.SettlementID = settlementID
	}
	rec.UpdatedAt = time.Now()
	return nil
}

// MarkCompleted transitions record to completed state and caches response.
func (s *MemoryStore) MarkCompleted(ctx context.Context, tenantID, key string, statusCode int, headers map[string]string, body []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ck := s.compositeKey(tenantID, key)
	rec, found := s.records[ck]
	if !found {
		return fmt.Errorf("idempotency record not found for key: %s", key)
	}

	rec.State = StateCompleted
	rec.StatusCode = statusCode
	rec.Headers = headers
	rec.ResponseBody = body
	rec.FailureReason = ""
	rec.UpdatedAt = time.Now()
	return nil
}

// MarkRecoveryRequired transitions record to recovery required state.
func (s *MemoryStore) MarkRecoveryRequired(ctx context.Context, tenantID, key string, statusCode int, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ck := s.compositeKey(tenantID, key)
	rec, found := s.records[ck]
	if !found {
		return fmt.Errorf("idempotency record not found for key: %s", key)
	}

	rec.State = StateRecoveryRequired
	rec.StatusCode = statusCode
	rec.FailureReason = reason
	rec.UpdatedAt = time.Now()
	return nil
}

// ReleaseLock frees the in-progress lock.
func (s *MemoryStore) ReleaseLock(ctx context.Context, tenantID, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ck := s.compositeKey(tenantID, key)
	rec, found := s.records[ck]
	if !found {
		return nil
	}

	// Only delete if it never finalized into completed or recovery
	if rec.State == StateInProgress {
		delete(s.records, ck)
	}
	return nil
}

// GetRecord retrieves the idempotency record.
func (s *MemoryStore) GetRecord(ctx context.Context, tenantID, key string) (*Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ck := s.compositeKey(tenantID, key)
	rec, found := s.records[ck]
	if !found {
		return nil, fmt.Errorf("record not found")
	}
	// Return a copy to prevent external mutation
	copied := *rec
	return &copied, nil
}
