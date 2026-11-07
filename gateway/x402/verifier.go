package x402

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// VerificationResult contains cryptographic verification output.
type VerificationResult struct {
	Valid             bool   `json:"valid"`
	Payer             string `json:"payer,omitempty"`
	VerifiedPayer     string `json:"verifiedPayer,omitempty"`
	VerificationToken string `json:"verificationToken,omitempty"`
	ErrorCode         string `json:"errorCode,omitempty"`
	Message           string `json:"message,omitempty"`
}

// PaymentVerifier verifies payment authorizations.
type PaymentVerifier interface {
	VerifyPayment(ctx context.Context, ch *PaymentChallenge, auth *PaymentAuthorization) (*VerificationResult, error)
}

// SettleResult contains the asynchronous settlement output.
type SettleResult struct {
	SettlementID string `json:"settlementId"`
	Status       string `json:"status"`
	TxHash       string `json:"txHash,omitempty"`
}

// SettlementStatus represents the receipt query output.
type SettlementStatus struct {
	SettlementID  string `json:"settlementId"`
	Status        string `json:"status"`
	TxHash        string `json:"txHash,omitempty"`
	Confirmations int    `json:"confirmations,omitempty"`
	ErrorCode     string `json:"errorCode,omitempty"`
	ErrorMessage  string `json:"errorMessage,omitempty"`
}

// AsyncSettlementVerifier is an optional interface for verifiers that perform asynchronous settlement.
type AsyncSettlementVerifier interface {
	PaymentVerifier
	SettlePayment(ctx context.Context, vToken string, auth *PaymentAuthorization, idemKey string) (*SettleResult, error)
	GetSettlementStatus(ctx context.Context, settlementID string) (*SettlementStatus, error)
	GetSettlementStatusByNonce(ctx context.Context, network, asset, payer, nonce string) (*SettlementStatus, error)
}

// MockPaymentVerifier enables deterministic testing without an external settlement service.
type MockPaymentVerifier struct {
	ShouldPass        bool
	Payer             string
	ErrorCode         string
	VerificationToken string
}

func (m *MockPaymentVerifier) VerifyPayment(ctx context.Context, ch *PaymentChallenge, auth *PaymentAuthorization) (*VerificationResult, error) {
	now := time.Now().Unix()
	if now > auth.ValidBefore {
		return &VerificationResult{
			Valid:     false,
			ErrorCode: ErrCodeSignatureExpired,
			Message:   "authorization has expired",
		}, nil
	}
	if !m.ShouldPass {
		errCode := m.ErrorCode
		if errCode == "" {
			errCode = ErrCodeSignatureInvalid
		}
		return &VerificationResult{
			Valid:     false,
			ErrorCode: errCode,
			Message:   "mock signature verification failed",
		}, nil
	}
	payer := m.Payer
	if payer == "" {
		payer = auth.Payer
	}
	return &VerificationResult{
		Valid:             true,
		Payer:             strings.ToLower(strings.TrimSpace(payer)),
		VerificationToken: m.VerificationToken,
	}, nil
}

// NonceStore tracks spent nonces to prevent replay attacks.
type NonceStore interface {
	CheckAndRecordNonce(network, asset, payer, nonce string) (bool, error)
}

func normalizeNonceTuple(network, asset, payer, nonce string) (string, string, string, string) {
	return strings.ToLower(strings.TrimSpace(network)),
		strings.ToLower(strings.TrimSpace(asset)),
		strings.ToLower(strings.TrimSpace(payer)),
		strings.ToLower(strings.TrimSpace(nonce))
}

// MemoryNonceStore provides thread-safe anti-replay tracking with optional file persistence.
type MemoryNonceStore struct {
	mu       sync.RWMutex
	nonces   map[string]bool
	filePath string
}

// NewMemoryNonceStore creates an in-memory nonce store.
func NewMemoryNonceStore() *MemoryNonceStore {
	return &MemoryNonceStore{
		nonces: make(map[string]bool),
	}
}

// NewPersistentFileNonceStore creates a file-backed nonce store that survives gateway restarts (P0-4).
func NewPersistentFileNonceStore(filePath string) (*MemoryNonceStore, error) {
	store := &MemoryNonceStore{
		nonces:   make(map[string]bool),
		filePath: filePath,
	}
	if filePath != "" {
		if data, err := os.ReadFile(filePath); err == nil && len(data) > 0 {
			var persisted []string
			if err := json.Unmarshal(data, &persisted); err == nil {
				for _, k := range persisted {
					store.nonces[strings.ToLower(strings.TrimSpace(k))] = true
				}
			}
		} else if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
	}
	return store, nil
}

func (s *MemoryNonceStore) CheckAndRecordNonce(network, asset, payer, nonce string) (bool, error) {
	// SECURITY-REVIEW: normalize all tuple components to lowercase so EIP-55 vs lowercase
	// hex addresses or nonces cannot bypass replay detection (P0-4).
	nNet, nAsset, nPayer, nNonce := normalizeNonceTuple(network, asset, payer, nonce)
	key := fmt.Sprintf("%s:%s:%s:%s", nNet, nAsset, nPayer, nNonce)
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.nonces[key] {
		return false, nil // Already used!
	}
	s.nonces[key] = true
	if s.filePath != "" {
		keys := make([]string, 0, len(s.nonces))
		for k := range s.nonces {
			keys = append(keys, k)
		}
		if raw, err := json.Marshal(keys); err == nil {
			_ = os.MkdirAll(filepath.Dir(s.filePath), 0o700)
			_ = os.WriteFile(s.filePath, raw, 0o600)
		}
	}
	return true, nil
}

// PostgresNonceStore provides durable, multi-instance PostgreSQL anti-replay tracking (P0-4).
type PostgresNonceStore struct {
	db *sql.DB
}

// NewPostgresNonceStore initializes the PostgreSQL-backed nonce store and ensures schema readiness.
func NewPostgresNonceStore(db *sql.DB) *PostgresNonceStore {
	if db != nil {
		_, _ = db.Exec(`
			CREATE TABLE IF NOT EXISTS ap_x402_nonce (
				network_id VARCHAR(64) NOT NULL,
				asset_address VARCHAR(128) NOT NULL,
				payer_address VARCHAR(128) NOT NULL,
				nonce VARCHAR(128) NOT NULL,
				created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
				PRIMARY KEY (network_id, asset_address, payer_address, nonce)
			)
		`)
	}
	return &PostgresNonceStore{db: db}
}

func (s *PostgresNonceStore) CheckAndRecordNonce(network, asset, payer, nonce string) (bool, error) {
	if s == nil || s.db == nil {
		return false, fmt.Errorf("postgres nonce store not initialized")
	}
	// SECURITY-REVIEW: atomic ON CONFLICT DO NOTHING guarantees single-use nonces across restarts and replicas (P0-4).
	nNet, nAsset, nPayer, nNonce := normalizeNonceTuple(network, asset, payer, nonce)
	res, err := s.db.Exec(`
		INSERT INTO ap_x402_nonce (network_id, asset_address, payer_address, nonce)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (network_id, asset_address, payer_address, nonce) DO NOTHING
	`, nNet, nAsset, nPayer, nNonce)
	if err != nil {
		return false, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected == 1, nil
}
