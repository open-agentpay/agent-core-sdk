package idempotency

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// State represents the lifecycle state of an idempotency record.
type State string

const (
	// StateInProgress indicates the request is currently being dispatched or processed.
	StateInProgress State = "in_progress"
	// StateCompleted indicates the request completed (e.g. 2xx success or 4xx client rejected)
	// and its response is securely cached for subsequent identical requests.
	StateCompleted State = "completed"
	// StateRecoveryRequired indicates the upstream service returned 5xx or timed out.
	// The settlement/hold is maintained, and subsequent identical requests are treated as
	// Free Replays without triggering double-charges.
	StateRecoveryRequired State = "recovery_required"
)

// CheckResult represents the classification outcome of an incoming idempotency check.
type CheckResult int

const (
	// ResultNew indicates no previous request with this key exists; a lock was acquired.
	ResultNew CheckResult = iota
	// ResultCacheHit indicates an identical request previously completed successfully.
	ResultCacheHit
	// ResultFreeReplay indicates a previous attempt encountered upstream failure (5xx/timeout).
	// The client is entitled to replay without paying again.
	ResultFreeReplay
	// ResultConflict indicates a conflict: either an identical key with different payload,
	// or another identical request is currently in flight.
	ResultConflict
)

// Record holds full metadata, state, and cached response for an idempotent operation.
type Record struct {
	TenantID        string
	IdempotencyKey  string
	RequestHash     string
	PaymentIntentID string
	HoldID          string
	SettlementID    string
	PaymentMethod   string // "wallet" or "onchain"
	State           State
	StatusCode      int
	Headers         map[string]string
	ResponseBody    []byte
	FailureReason   string
	AttemptCount    int
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// ComputeRequestHash produces a deterministic SHA-256 fingerprint of the request.
func ComputeRequestHash(method, path, rawQuery string, body []byte) string {
	h := sha256.New()
	h.Write([]byte(method))
	h.Write([]byte{0})
	h.Write([]byte(path))
	h.Write([]byte{0})
	h.Write([]byte(rawQuery))
	h.Write([]byte{0})
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}
