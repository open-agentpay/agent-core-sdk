package x402

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
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

// PaymentVerifier verifies EIP-712 / EIP-3009 authorizations.
type PaymentVerifier interface {
	VerifyPayment(ctx context.Context, ch *PaymentChallenge, auth *PaymentAuthorization) (*VerificationResult, error)
}

// FacilitatorVerifier executes verification by delegating to the Facilitator service.
type FacilitatorVerifier struct {
	facilitatorURL string
	apiKey         string
	client         *http.Client
}

// NewFacilitatorVerifier creates a verifier backed by Facilitator /v1/verify.
func NewFacilitatorVerifier(url string, timeout time.Duration) *FacilitatorVerifier {
	return NewFacilitatorVerifierWithAuth(url, "", timeout)
}

// NewFacilitatorVerifierWithAuth creates an authenticated verifier backed by Facilitator.
func NewFacilitatorVerifierWithAuth(url, apiKey string, timeout time.Duration) *FacilitatorVerifier {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if apiKey == "" {
		apiKey = strings.TrimSpace(os.Getenv("AGENTPAY_FACILITATOR_API_KEY"))
	}
	return &FacilitatorVerifier{
		facilitatorURL: strings.TrimRight(url, "/"),
		apiKey:         strings.TrimSpace(apiKey),
		client:         &http.Client{Timeout: timeout},
	}
}

// SetAPIKey configures the API key used to authenticate against Facilitator endpoints.
func (fv *FacilitatorVerifier) SetAPIKey(apiKey string) {
	if fv != nil {
		fv.apiKey = strings.TrimSpace(apiKey)
	}
}

func (fv *FacilitatorVerifier) applyAuthHeaders(req *http.Request) {
	if fv != nil && fv.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+fv.apiKey)
		req.Header.Set("X-Facilitator-Key", fv.apiKey)
	}
}

func (fv *FacilitatorVerifier) VerifyPayment(ctx context.Context, ch *PaymentChallenge, auth *PaymentAuthorization) (*VerificationResult, error) {
	if auth == nil || ch == nil {
		return &VerificationResult{Valid: false, ErrorCode: ErrCodeSignatureInvalid, Message: "nil payload"}, nil
	}

	// 1. Static timestamp bounds check
	now := time.Now().Unix()
	if now < auth.ValidAfter || now > auth.ValidBefore {
		return &VerificationResult{
			Valid:     false,
			ErrorCode: ErrCodeSignatureExpired,
			Message:   fmt.Sprintf("authorization expired or not yet valid (now=%d, validAfter=%d, validBefore=%d)", now, auth.ValidAfter, auth.ValidBefore),
		}, nil
	}

	// 2. Challenge ID correlation check
	if auth.ChallengeID != ch.ChallengeID {
		return &VerificationResult{
			Valid:     false,
			ErrorCode: ErrCodeSignatureInvalid,
			Message:   fmt.Sprintf("challengeId mismatch: auth=%s, challenge=%s", auth.ChallengeID, ch.ChallengeID),
		}, nil
	}

	// 3. Delegate signature verification to Facilitator /v1/verify
	reqBody, _ := json.Marshal(map[string]interface{}{
		"challenge":     ch,
		"authorization": auth,
	})
	slog.Info("send facilitatorURL verify url ", slog.String("facilitatorURL", fv.facilitatorURL))
	req, err := http.NewRequestWithContext(ctx, "POST", fv.facilitatorURL+"/v1/verify", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create facilitator request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	fv.applyAuthHeaders(req)

	resp, err := fv.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("facilitator verify call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errPayload struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errPayload)
		errCode := errPayload.Error.Code
		if errCode == "" {
			errCode = errPayload.Code
		}
		if errCode == "" {
			errCode = ErrCodeSignatureInvalid
		}
		errMsg := errPayload.Error.Message
		if errMsg == "" {
			errMsg = errPayload.Message
		}
		if errMsg == "" {
			errMsg = fmt.Sprintf("facilitator rejected verification with HTTP %d", resp.StatusCode)
		}
		return &VerificationResult{
			Valid:     false,
			ErrorCode: errCode,
			Message:   errMsg,
		}, nil
	}

	var result VerificationResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode facilitator response: %w", err)
	}

	if result.Payer == "" && result.VerifiedPayer != "" {
		result.Payer = result.VerifiedPayer
	}
	result.Payer = strings.ToLower(strings.TrimSpace(result.Payer))

	return &result, nil
}

// SettleResult contains the asynchronous settlement output from Facilitator.
type SettleResult struct {
	SettlementID string `json:"settlementId"`
	Status       string `json:"status"`
	TxHash       string `json:"txHash"`
}

// FacilitatorSettlementStatus represents the receipt query output from Facilitator GET /v1/settle/{id}.
type FacilitatorSettlementStatus struct {
	SettlementID  string `json:"settlementId"`
	Status        string `json:"status"`
	TxHash        string `json:"txHash"`
	Confirmations int    `json:"confirmations"`
	ErrorCode     string `json:"errorCode,omitempty"`
	ErrorMessage  string `json:"errorMessage,omitempty"`
}

// SettlePayment dispatches settlement to Facilitator POST /v1/settle to trigger on-chain transaction broadcast.
func (fv *FacilitatorVerifier) SettlePayment(ctx context.Context, vToken string, auth *PaymentAuthorization, idemKey string) (*SettleResult, error) {
	if fv == nil || fv.facilitatorURL == "" {
		return nil, fmt.Errorf("facilitator url not configured")
	}
	reqBody, err := json.Marshal(map[string]interface{}{
		"verificationToken": vToken,
		"authorization":     auth,
		"idempotencyKey":    idemKey,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal settle request: %w", err)
	}

	slog.Info("dispatching async settlement to facilitator",
		slog.String("facilitator_url", fv.facilitatorURL),
		slog.String("verification_token", vToken),
	)

	req, err := http.NewRequestWithContext(ctx, "POST", fv.facilitatorURL+"/v1/settle", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create facilitator settle request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	fv.applyAuthHeaders(req)

	resp, err := fv.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("facilitator settle call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		bodyBytes, _ := io.ReadAll(resp.Body)
		var errResp struct {
			Error     string `json:"error"`
			ErrorCode string `json:"errorCode"`
			Message   string `json:"message"`
		}
		if err := json.Unmarshal(bodyBytes, &errResp); err == nil && errResp.Message != "" {
			return nil, fmt.Errorf("facilitator settle rejected with HTTP %d [%s]: %s", resp.StatusCode, errResp.ErrorCode, errResp.Message)
		}
		return nil, fmt.Errorf("facilitator settle rejected with HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var res SettleResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("failed to decode facilitator settle response: %w", err)
	}
	return &res, nil
}

// GetSettlementStatus queries Facilitator GET /v1/settle/{id} to reconcile on-chain receipt status.
func (fv *FacilitatorVerifier) GetSettlementStatus(ctx context.Context, settlementID string) (*FacilitatorSettlementStatus, error) {
	if fv == nil || fv.facilitatorURL == "" {
		return nil, fmt.Errorf("facilitator url not configured")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", fv.facilitatorURL+"/v1/settle/"+settlementID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create facilitator status request: %w", err)
	}
	fv.applyAuthHeaders(req)

	resp, err := fv.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("facilitator status query failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("facilitator status returned HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var status FacilitatorSettlementStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to decode facilitator settlement status: %w", err)
	}
	return &status, nil
}

// GetSettlementStatusByNonce queries Facilitator GET /v1/settle/lookup to reconcile status via payment nonce (P0-3).
func (fv *FacilitatorVerifier) GetSettlementStatusByNonce(ctx context.Context, network, asset, payer, nonce string) (*FacilitatorSettlementStatus, error) {
	if fv == nil || fv.facilitatorURL == "" {
		return nil, fmt.Errorf("facilitator url not configured")
	}
	endpoint := fmt.Sprintf("%s/v1/settle/lookup?network=%s&asset=%s&payer=%s&nonce=%s",
		fv.facilitatorURL,
		url.QueryEscape(network),
		url.QueryEscape(asset),
		url.QueryEscape(payer),
		url.QueryEscape(nonce),
	)
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create facilitator status lookup request: %w", err)
	}
	fv.applyAuthHeaders(req)

	resp, err := fv.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("facilitator status lookup query failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("facilitator status lookup returned HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var status FacilitatorSettlementStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to decode facilitator settlement status: %w", err)
	}
	return &status, nil
}

// MockPaymentVerifier enables deterministic testing without a live facilitator.
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
