package x402

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/agent-core-sdk/gateway/rcu"
)

func TestResolveOnchainAsset(t *testing.T) {
	tests := []struct {
		name            string
		network         string
		assetInput      string
		expectedAddress string
		expectedSymbol  string
	}{
		{
			name:            "Base Sepolia with symbol USDC",
			network:         "eip155:84532",
			assetInput:      "USDC",
			expectedAddress: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
			expectedSymbol:  "USDC",
		},
		{
			name:            "Base Sepolia with symbol USD",
			network:         "eip155:84532",
			assetInput:      "USD",
			expectedAddress: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
			expectedSymbol:  "USDC",
		},
		{
			name:            "Arbitrum Sepolia with symbol USDC",
			network:         "eip155:421614",
			assetInput:      "USDC",
			expectedAddress: "0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d",
			expectedSymbol:  "USDC",
		},
		{
			name:            "Base Mainnet with symbol USDC",
			network:         "eip155:8453",
			assetInput:      "USDC",
			expectedAddress: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
			expectedSymbol:  "USDC",
		},
		{
			name:            "Preserves explicit EVM 0x address",
			network:         "eip155:84532",
			assetInput:      "0x1234567890123456789012345678901234567890",
			expectedAddress: "0x1234567890123456789012345678901234567890",
			expectedSymbol:  "USDC",
		},
		{
			name:            "Empty network defaults to Base Sepolia USDC",
			network:         "",
			assetInput:      "USDC",
			expectedAddress: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
			expectedSymbol:  "USDC",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr, sym := ResolveOnchainAsset(tc.network, tc.assetInput)
			if addr != tc.expectedAddress {
				t.Errorf("expected address %s, got %s", tc.expectedAddress, addr)
			}
			if sym != tc.expectedSymbol {
				t.Errorf("expected symbol %s, got %s", tc.expectedSymbol, sym)
			}
		})
	}
}

func TestIssue402ChallengeResolvesAssetContractAddress(t *testing.T) {
	processor, _ := setupTestProcessor(nil, nil, nil)

	// Simulates route configured with symbol "USDC" under Base Sepolia
	route := &rcu.RouteConfig{
		RouteID:               "rou_weather",
		PathPattern:           "/api/v1/simple-weather",
		Network:               "eip155:84532",
		PriceBaseUnits:        50000,
		Asset:                 "USDC",
		OnchainAsset:          "USDC",
		PayeeAddress:          "0xa0b4af0a1fa90708a33eb127b6963a902020d2ed",
		AllowedPaymentMethods: "onchain",
	}

	req := httptest.NewRequest("GET", "/api/v1/simple-weather", nil)
	w := httptest.NewRecorder()

	processor.HandleRequest(w, req, route, "req_weather_001")

	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402, got %d", w.Code)
	}

	chHeader := w.Header().Get(HeaderPaymentRequired)
	if chHeader == "" {
		t.Fatalf("missing PAYMENT-REQUIRED header")
	}

	ch, err := DecodeChallenge(chHeader)
	if err != nil {
		t.Fatalf("failed to decode challenge: %v", err)
	}

	// Verify asset is the EVM 0x contract address, NOT "USDC"
	expectedAsset := "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
	if ch.Asset != expectedAsset {
		t.Errorf("expected challenge asset to be %s, got %s", expectedAsset, ch.Asset)
	}

	if ch.AssetSymbol != "USDC" {
		t.Errorf("expected challenge assetSymbol to be 'USDC', got %s", ch.AssetSymbol)
	}

	if ch.Network != "eip155:84532" {
		t.Errorf("expected challenge network to be 'eip155:84532', got %s", ch.Network)
	}

	// Verify response body JSON contains challenge with resolved asset
	var env ProtocolErrorEnvelope
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("failed to parse response body: %v", err)
	}
	if env.Error.Details == nil {
		t.Fatalf("expected details in error envelope")
	}
	chRaw, ok := env.Error.Details["challenge"]
	if !ok || chRaw == nil {
		t.Fatalf("expected challenge in extensions")
	}
	chBytes, _ := json.Marshal(chRaw)
	var bodyChallenge PaymentChallenge
	if err := json.Unmarshal(chBytes, &bodyChallenge); err != nil {
		t.Fatalf("failed to unmarshal challenge from body: %v", err)
	}
	if bodyChallenge.Asset != expectedAsset {
		t.Errorf("expected body challenge asset %s, got %s", expectedAsset, bodyChallenge.Asset)
	}
	if bodyChallenge.AssetSymbol != "USDC" {
		t.Errorf("expected body challenge assetSymbol 'USDC', got %s", bodyChallenge.AssetSymbol)
	}

	// Verify configured facilitator URL takes effect
	processor.SetFacilitatorURL("http://127.0.0.1:8001")
	wFac := httptest.NewRecorder()
	processor.HandleRequest(wFac, req, route, "req_weather_fac")
	chFac, err := DecodeChallenge(wFac.Header().Get(HeaderPaymentRequired))
	if err != nil {
		t.Fatalf("failed to decode challenge: %v", err)
	}
	if chFac.FacilitatorURL != "http://127.0.0.1:8001" {
		t.Errorf("expected facilitatorUrl 'http://127.0.0.1:8001', got %s", chFac.FacilitatorURL)
	}
}

func TestSettlementDefaultsTakeEffectOnChallenge(t *testing.T) {
	processor, _ := setupTestProcessor(nil, nil, nil)

	// Configure settlement defaults matching Arbitrum Sepolia
	processor.SetSettlementDefaults(SettlementDefaults{
		DefaultNetwork:       "eip155:421614",
		DefaultAsset:         "0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d",
		DefaultAssetSymbol:   "USDC",
		DefaultAssetDecimals: 6,
		DefaultPayTo:         "0x1111222233334444555566667777888899990000",
	})

	// Route with empty Network and empty PayeeAddress (simulating dynamic route from console/config)
	route := &rcu.RouteConfig{
		RouteID:               "rou_weather_arbitrum",
		PathPattern:           "/api/v1/simple-weather1",
		Network:               "", // Empty, should fall back to settlement.default_network
		PriceBaseUnits:        10000,
		Asset:                 "", // Empty, should fall back to settlement default asset
		PayeeAddress:          "", // Empty, should fall back to settlement.default_pay_to
		AllowedPaymentMethods: "onchain",
	}

	req := httptest.NewRequest("GET", "/api/v1/simple-weather1", nil)
	w := httptest.NewRecorder()

	processor.HandleRequest(w, req, route, "req_arbitrum_001")

	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402, got %d", w.Code)
	}

	chHeader := w.Header().Get(HeaderPaymentRequired)
	if chHeader == "" {
		t.Fatalf("missing PAYMENT-REQUIRED header")
	}

	ch, err := DecodeChallenge(chHeader)
	if err != nil {
		t.Fatalf("failed to decode challenge: %v", err)
	}

	if ch.Network != "eip155:421614" {
		t.Errorf("expected challenge network 'eip155:421614', got %s", ch.Network)
	}
	if ch.Asset != "0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d" {
		t.Errorf("expected challenge asset '0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d', got %s", ch.Asset)
	}
	if ch.AssetSymbol != "USDC" {
		t.Errorf("expected challenge assetSymbol 'USDC', got %s", ch.AssetSymbol)
	}
	if ch.Payee != "0x1111222233334444555566667777888899990000" {
		t.Errorf("expected challenge payee '0x1111222233334444555566667777888899990000', got %s", ch.Payee)
	}
	if ch.Decimals != 6 {
		t.Errorf("expected challenge decimals 6, got %d", ch.Decimals)
	}
}
