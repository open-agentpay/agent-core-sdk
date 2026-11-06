package x402

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/open-agentpay/agent-core-sdk/gateway/idempotency"
	"github.com/open-agentpay/agent-core-sdk/gateway/rcu"
)

func getSpecsDir(t *testing.T) string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to resolve current file path")
	}
	return filepath.Join(filepath.Dir(filename), "..", "..", "specs")
}

// TestCanonicalErrorsIntegrityAgainstTaxonomy validates Go CanonicalErrorRegistry against protocol-errors.json.
func TestCanonicalErrorsIntegrityAgainstTaxonomy(t *testing.T) {
	errorsPath := filepath.Join(getSpecsDir(t), "conformance", "protocol-errors.json")
	data, err := os.ReadFile(errorsPath)
	if err != nil {
		t.Fatalf("failed to read protocol-errors.json: %v", err)
	}

	var taxonomy struct {
		Version string `json:"version"`
		Errors  []struct {
			Code       string `json:"code"`
			Status     int    `json:"status"`
			Domain     string `json:"domain"`
			Message    string `json:"message"`
			Actionable string `json:"actionable"`
		} `json:"errors"`
	}

	if err := json.Unmarshal(data, &taxonomy); err != nil {
		t.Fatalf("failed to parse protocol-errors.json: %v", err)
	}

	if taxonomy.Version != "2.0.0" {
		t.Errorf("expected taxonomy version 2.0.0, got %s", taxonomy.Version)
	}

	if len(taxonomy.Errors) < 17 {
		t.Errorf("taxonomy must define at least 17 canonical errors, found %d", len(taxonomy.Errors))
	}

	for _, specErr := range taxonomy.Errors {
		t.Run(specErr.Code, func(t *testing.T) {
			desc, ok := CanonicalErrorRegistry[specErr.Code]
			if !ok {
				t.Fatalf("canonical error code %s missing from Go CanonicalErrorRegistry", specErr.Code)
			}
			if desc.Status != specErr.Status {
				t.Errorf("status mismatch for %s: expected %d, got %d", specErr.Code, specErr.Status, desc.Status)
			}
			if desc.Domain != specErr.Domain {
				t.Errorf("domain mismatch for %s: expected %s, got %s", specErr.Code, specErr.Domain, desc.Domain)
			}
		})
	}

	// Verify WriteProtocolError produces compliant envelope
	t.Run("WireFormatEnvelopeCompliance", func(t *testing.T) {
		rec := httptest.NewRecorder()
		testReqID := "req_test_01j7xyz"
		details := map[string]interface{}{"foo": "bar"}
		WriteProtocolError(rec, ErrCodeWalletInsufficientBalance, testReqID, details)

		if rec.Code != http.StatusPaymentRequired {
			t.Errorf("expected 402 status, got %d", rec.Code)
		}

		var envelope ProtocolErrorEnvelope
		if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
			t.Fatalf("failed to parse error response: %v", err)
		}

		if envelope.Error.Code != ErrCodeWalletInsufficientBalance {
			t.Errorf("expected error code %s, got %s", ErrCodeWalletInsufficientBalance, envelope.Error.Code)
		}
		if envelope.Error.Status != 402 {
			t.Errorf("expected status 402, got %d", envelope.Error.Status)
		}
		if envelope.Error.Domain != "WALLET" {
			t.Errorf("expected domain WALLET, got %s", envelope.Error.Domain)
		}
		if envelope.Error.RequestID != testReqID {
			t.Errorf("expected requestId %s, got %s", testReqID, envelope.Error.RequestID)
		}
		if envelope.Error.Details["foo"] != "bar" {
			t.Errorf("expected details foo=bar, got %v", envelope.Error.Details["foo"])
		}
	})
}

// TestDualPathProtocolTestVectors verifies Go Gateway behavior matches specs/test-vectors/dual-path-protocol.json.
func TestDualPathProtocolTestVectors(t *testing.T) {
	vectorsPath := filepath.Join(getSpecsDir(t), "test-vectors", "dual-path-protocol.json")
	data, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("failed to read dual-path-protocol.json: %v", err)
	}

	var suite struct {
		Version   string `json:"version"`
		TestCases []struct {
			ID          string          `json:"id"`
			Category    string          `json:"category"`
			Description string          `json:"description"`
			Input       json.RawMessage `json:"input"`
			Expected    json.RawMessage `json:"expected"`
		} `json:"testCases"`
	}

	if err := json.Unmarshal(data, &suite); err != nil {
		t.Fatalf("failed to parse dual-path-protocol.json: %v", err)
	}

	for _, tc := range suite.TestCases {
		t.Run(tc.ID, func(t *testing.T) {
			switch tc.ID {
			case "TC_PROTO_01_ONCHAIN_CHALLENGE_FORMAT":
				var input struct {
					RouteID string `json:"route_id"`
					Asset   string `json:"asset"`
					Network string `json:"network"`
					Amount  string `json:"amount"`
					Payee   string `json:"payee"`
				}
				_ = json.Unmarshal(tc.Input, &input)

				route := &rcu.RouteConfig{
					RouteID:               input.RouteID,
					Network:               input.Network,
					Asset:                 input.Asset,
					PriceBaseUnits:        50000,
					PayeeAddress:          input.Payee,
					AllowedPaymentMethods: "onchain",
				}

				processor, _ := setupTestProcessor(nil, nil, nil)
				req := httptest.NewRequest("GET", "/v1/llm/chat", nil)
				rec := httptest.NewRecorder()

				processor.HandleRequest(rec, req, route, "req_proto_01")

				if rec.Code != http.StatusPaymentRequired {
					t.Errorf("expected 402, got %d", rec.Code)
				}
				challengeRaw := rec.Header().Get(HeaderPaymentRequired)
				if challengeRaw == "" {
					t.Fatalf("missing PAYMENT-REQUIRED header")
				}
				challenge, err := DecodeChallenge(challengeRaw)
				if err != nil {
					t.Fatalf("failed to decode challenge: %v", err)
				}
				if challenge.Version != "2.0" {
					t.Errorf("expected version 2.0, got %s", challenge.Version)
				}
				if challenge.Network != input.Network {
					t.Errorf("expected network %s, got %s", input.Network, challenge.Network)
				}
				if challenge.Asset != input.Asset {
					t.Errorf("expected asset %s, got %s", input.Asset, challenge.Asset)
				}
				if challenge.Scheme != "EIP-3009" {
					t.Errorf("expected scheme EIP-3009, got %s", challenge.Scheme)
				}

			case "TC_PROTO_02_WALLET_APIKEY_SELECTION":
				var input struct {
					Headers map[string]string `json:"headers"`
					Route   struct {
						RouteID               string `json:"route_id"`
						AllowedPaymentMethods string `json:"allowed_payment_methods"`
						PriceBaseUnits        int64  `json:"price_base_units"`
					} `json:"route"`
					WalletBalance struct {
						Available int64  `json:"available"`
						Held      int64  `json:"held"`
						Status    string `json:"status"`
					} `json:"wallet_balance"`
				}
				_ = json.Unmarshal(tc.Input, &input)

				route := &rcu.RouteConfig{
					RouteID:               input.Route.RouteID,
					AllowedPaymentMethods: input.Route.AllowedPaymentMethods,
					PriceBaseUnits:        input.Route.PriceBaseUnits,
					UpstreamURL:           "http://upstream.internal:8000",
				}
				walletSvc := NewMemoryWalletService()
				walletSvc.RegisterWallet("apk_live_01j7xyz890abcdef12345678", &WalletAccount{
					WalletID:         "wlt_01",
					TenantID:         "ten_01",
					Status:           input.WalletBalance.Status,
					AvailableBalance: input.WalletBalance.Available,
					HeldBalance:      input.WalletBalance.Held,
				})

				processor, m := setupTestProcessor(walletSvc, nil, nil)
				req := httptest.NewRequest("POST", "/v1/llm/chat", bytes.NewBufferString(`{"prompt":"hello"}`))
				for k, v := range input.Headers {
					req.Header.Set(k, v)
				}
				rec := httptest.NewRecorder()

				serveAuthorizedWalletRequest(t, processor, rec, req, route, "req_proto_02")

				if rec.Code != http.StatusOK {
					t.Fatalf("expected 200 OK, got %d, body: %s", rec.Code, rec.Body.String())
				}
				if m.HoldsCreatedTotal != 1 || m.HoldsCapturedTotal != 1 {
					t.Errorf("expected hold created and captured, holdsCreated=%d, holdsCaptured=%d", m.HoldsCreatedTotal, m.HoldsCapturedTotal)
				}
				wallet, _ := walletSvc.GetWalletByAPIKey(req.Context(), "apk_live_01j7xyz890abcdef12345678")
				if wallet.AvailableBalance != input.WalletBalance.Available-input.Route.PriceBaseUnits {
					t.Errorf("expected available balance %d, got %d", input.WalletBalance.Available-input.Route.PriceBaseUnits, wallet.AvailableBalance)
				}

			case "TC_PROTO_03_WALLET_INSUFFICIENT_NO_DOWNGRADE":
				var input struct {
					Headers map[string]string `json:"headers"`
					Route   struct {
						PriceBaseUnits        int64  `json:"price_base_units"`
						AllowedPaymentMethods string `json:"allowed_payment_methods"`
					} `json:"route"`
					WalletBalance struct {
						Available int64  `json:"available"`
						Held      int64  `json:"held"`
						Status    string `json:"status"`
					} `json:"wallet_balance"`
				}
				_ = json.Unmarshal(tc.Input, &input)

				route := &rcu.RouteConfig{
					RouteID:               "rou_llm",
					AllowedPaymentMethods: input.Route.AllowedPaymentMethods,
					PriceBaseUnits:        input.Route.PriceBaseUnits,
				}
				walletSvc := NewMemoryWalletService()
				walletSvc.RegisterWallet("apk_live_01j7xyz890abcdef12345678", &WalletAccount{
					WalletID:         "wlt_01",
					TenantID:         "ten_01",
					Status:           input.WalletBalance.Status,
					AvailableBalance: input.WalletBalance.Available,
					HeldBalance:      input.WalletBalance.Held,
				})

				processor, _ := setupTestProcessor(walletSvc, nil, nil)
				req := httptest.NewRequest("POST", "/v1/llm/chat", bytes.NewBufferString(`{"prompt":"hello"}`))
				for k, v := range input.Headers {
					req.Header.Set(k, v)
				}
				rec := httptest.NewRecorder()

				serveAuthorizedWalletRequest(t, processor, rec, req, route, "req_proto_03")

				if rec.Code != http.StatusPaymentRequired {
					t.Errorf("expected 402 on insufficient balance, got %d", rec.Code)
				}

				// STRICT INVARIANT: NO AUTO-DOWNGRADE. PAYMENT-REQUIRED header must NOT be present!
				if rec.Header().Get(HeaderPaymentRequired) != "" {
					t.Fatalf("INV_VIOLATION: PAYMENT-REQUIRED header was issued after wallet balance insufficiency!")
				}

				var envelope ProtocolErrorEnvelope
				_ = json.Unmarshal(rec.Body.Bytes(), &envelope)
				if envelope.Error.Code != ErrCodeWalletInsufficientBalance {
					t.Errorf("expected error code %s, got %s", ErrCodeWalletInsufficientBalance, envelope.Error.Code)
				}

			case "TC_PROTO_04_WALLET_FROZEN_ARREARS":
				var input struct {
					Headers       map[string]string `json:"headers"`
					WalletBalance struct {
						Available int64  `json:"available"`
						Held      int64  `json:"held"`
						Status    string `json:"status"`
					} `json:"wallet_balance"`
				}
				_ = json.Unmarshal(tc.Input, &input)

				route := &rcu.RouteConfig{
					RouteID:               "rou_frozen",
					AllowedPaymentMethods: "wallet",
					PriceBaseUnits:        1000,
				}
				walletSvc := NewMemoryWalletService()
				walletSvc.RegisterWallet("apk_live_01j7xyz890abcdef12345678", &WalletAccount{
					WalletID:         "wlt_frozen",
					TenantID:         "ten_01",
					Status:           input.WalletBalance.Status,
					AvailableBalance: input.WalletBalance.Available,
					HeldBalance:      input.WalletBalance.Held,
				})

				processor, _ := setupTestProcessor(walletSvc, nil, nil)
				req := httptest.NewRequest("POST", "/v1/llm/chat", bytes.NewBufferString(`{}`))
				for k, v := range input.Headers {
					req.Header.Set(k, v)
				}
				rec := httptest.NewRecorder()

				processor.HandleRequest(rec, req, route, "req_proto_04")

				if rec.Code != http.StatusForbidden {
					t.Errorf("expected 403 Forbidden, got %d", rec.Code)
				}
				var envelope ProtocolErrorEnvelope
				_ = json.Unmarshal(rec.Body.Bytes(), &envelope)
				if envelope.Error.Code != ErrCodeWalletFrozen {
					t.Errorf("expected %s, got %s", ErrCodeWalletFrozen, envelope.Error.Code)
				}

			case "TC_PROTO_05_PAYMENT_METHOD_MISMATCH":
				var input struct {
					Headers map[string]string `json:"headers"`
					Route   struct {
						RouteID               string `json:"route_id"`
						AllowedPaymentMethods string `json:"allowed_payment_methods"`
					} `json:"route"`
				}
				_ = json.Unmarshal(tc.Input, &input)

				route := &rcu.RouteConfig{
					RouteID:               input.Route.RouteID,
					AllowedPaymentMethods: input.Route.AllowedPaymentMethods,
					PriceBaseUnits:        1000,
				}
				processor, _ := setupTestProcessor(nil, nil, nil)
				req := httptest.NewRequest("POST", "/v1/llm/chat", bytes.NewBufferString(`{}`))
				for k, v := range input.Headers {
					req.Header.Set(k, v)
				}
				rec := httptest.NewRecorder()

				processor.HandleRequest(rec, req, route, "req_proto_05")

				if rec.Code != http.StatusForbidden {
					t.Errorf("expected 403 Forbidden, got %d", rec.Code)
				}
				var envelope ProtocolErrorEnvelope
				_ = json.Unmarshal(rec.Body.Bytes(), &envelope)
				if envelope.Error.Code != ErrCodePaymentMethodNotAllowed {
					t.Errorf("expected %s, got %s", ErrCodePaymentMethodNotAllowed, envelope.Error.Code)
				}

			case "TC_PROTO_06_IDEMPOTENCY_CONFLICT":
				var input struct {
					TenantID            string `json:"tenant_id"`
					IdempotencyKey      string `json:"idempotency_key"`
					OriginalPayloadHash string `json:"original_payload_hash"`
					IncomingPayloadHash string `json:"incoming_payload_hash"`
				}
				_ = json.Unmarshal(tc.Input, &input)

				store := idempotency.NewMemoryStore(time.Hour)
				ctx := context.Background()

				// Register original key with original hash
				rec1, res1, err1 := store.CheckOrLock(ctx, input.TenantID, input.IdempotencyKey, input.OriginalPayloadHash, "pi_01", "wallet")
				if err1 != nil {
					t.Fatalf("failed to acquire initial lock: %v", err1)
				}
				if res1 != idempotency.ResultNew || rec1 == nil {
					t.Fatalf("expected ResultNew for first request, got %v", res1)
				}

				// Mark completed or keep in-progress, then attempt to check with conflicting incoming payload hash
				_, res2, err2 := store.CheckOrLock(ctx, input.TenantID, input.IdempotencyKey, input.IncomingPayloadHash, "pi_02", "wallet")
				if err2 != nil {
					t.Fatalf("unexpected error on conflict check: %v", err2)
				}
				if res2 != idempotency.ResultConflict {
					t.Errorf("expected ResultConflict for altered payload hash, got %v", res2)
				}
			}
		})
	}
}
