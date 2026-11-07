package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/open-agentpay/agent-core-sdk/gateway/admin"
	"github.com/open-agentpay/agent-core-sdk/gateway/auth"
	"github.com/open-agentpay/agent-core-sdk/gateway/config"
	"github.com/open-agentpay/agent-core-sdk/gateway/metrics"
	"github.com/open-agentpay/agent-core-sdk/gateway/rcu"
	"github.com/open-agentpay/agent-core-sdk/gateway/x402"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestServerHealthReadyAndVersionEndpoints(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Auth.JWTSecret = "test-jwt-secret-key-32-bytes-long!!"
	cfg.Auth.UpstreamMasterKey = "0123456789abcdef0123456789abcdef"
	snap := &rcu.ConfigSnapshot{
		SchemaVersion: "2.0.0",
		TenantID:      "ten_default",
		VersionID:     "ver_init",
		Routes: []rcu.RouteConfig{
			{
				RouteID:        "rou_1",
				PathPattern:    "/v1/api",
				UpstreamURL:    "https://api.upstream.com",
				PriceBaseUnits: 1000,
				Status:         "active",
			},
		},
	}
	rcuMgr, err := rcu.NewManager(snap)
	if err != nil {
		t.Fatalf("failed to init rcu: %v", err)
	}

	m := metrics.New()
	mockTransport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewBufferString(`{"forwarded":true}`)),
			Request:    r,
		}, nil
	})
	srv, err := NewWithTransport(&cfg, rcuMgr, m, mockTransport)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	handler := srv.Handler()

	// 1. Test /healthz
	reqHealth := httptest.NewRequest("GET", "/healthz", nil)
	wHealth := httptest.NewRecorder()
	handler.ServeHTTP(wHealth, reqHealth)

	if wHealth.Code != http.StatusOK {
		t.Errorf("healthz expected 200, got %d", wHealth.Code)
	}
	var healthResp HealthResponse
	if err := json.Unmarshal(wHealth.Body.Bytes(), &healthResp); err != nil {
		t.Fatalf("failed to decode health response: %v", err)
	}
	if healthResp.Status != "ok" {
		t.Errorf("expected health status 'ok', got %s", healthResp.Status)
	}

	// 2. Test /readyz
	reqReady := httptest.NewRequest("GET", "/readyz", nil)
	wReady := httptest.NewRecorder()
	handler.ServeHTTP(wReady, reqReady)

	if wReady.Code != http.StatusOK {
		t.Errorf("readyz expected 200, got %d", wReady.Code)
	}
	var readyResp ReadyResponse
	if err := json.Unmarshal(wReady.Body.Bytes(), &readyResp); err != nil {
		t.Fatalf("failed to decode ready response: %v", err)
	}
	if readyResp.RoutesLoaded != 1 || readyResp.ConfigVersion != "ver_init" {
		t.Errorf("readyz expected 1 route loaded, ver_init; got %+v", readyResp)
	}

	// 3. Test /version
	reqVer := httptest.NewRequest("GET", "/version", nil)
	wVer := httptest.NewRecorder()
	handler.ServeHTTP(wVer, reqVer)

	if wVer.Code != http.StatusOK {
		t.Errorf("version expected 200, got %d", wVer.Code)
	}
	var verResp VersionResponse
	if err := json.Unmarshal(wVer.Body.Bytes(), &verResp); err != nil {
		t.Fatalf("failed to decode version response: %v", err)
	}
	if verResp.Service != "agentpay-gateway" {
		t.Errorf("expected service agentpay-gateway, got %s", verResp.Service)
	}

	// 4. Test matched paid route without auth -> issues 402 challenge
	reqRoute := httptest.NewRequest("GET", "/v1/api", nil)
	wRoute := httptest.NewRecorder()
	handler.ServeHTTP(wRoute, reqRoute)

	if wRoute.Code != http.StatusPaymentRequired {
		t.Errorf("expected 402 Payment Required for paid route, got %d", wRoute.Code)
	}
	if wRoute.Header().Get("PAYMENT-REQUIRED") == "" {
		t.Errorf("expected PAYMENT-REQUIRED header in 402 response")
	}

	// 5. Test 404 for unknown route
	req404 := httptest.NewRequest("GET", "/unregistered/path", nil)
	w404 := httptest.NewRecorder()
	handler.ServeHTTP(w404, req404)

	if w404.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unregistered path, got %d", w404.Code)
	}

	// 6. Test Control Plane Admin REST API requires JWT (P0-1)
	reqAdmin := httptest.NewRequest("GET", "/api/v1/tenants", nil)
	wAdmin := httptest.NewRecorder()
	handler.ServeHTTP(wAdmin, reqAdmin)

	if wAdmin.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for unauthenticated /api/v1/tenants, got %d", wAdmin.Code)
	}

	// 7. Test proxy route under /api/v1/... (e.g. /api/v1/simple-weather) with upstream auth
	adminSvc := srv.AdminService()
	tenant, owner, err := adminSvc.Register(reqAdmin.Context(), "AI漫剧租户", "user@aimanju.com", "Password123!")
	if err != nil {
		t.Fatalf("failed to register tenant: %v", err)
	}

	// Verify authenticated GET /api/v1/tenants succeeds for the authenticated tenant
	jwtMgr, _ := auth.NewJWTManager(cfg.Auth.JWTSecret, 24*time.Hour)
	token, _ := jwtMgr.GenerateToken(owner.MemberID, owner.Email, tenant.TenantID, string(owner.Role))
	reqAdminAuth := httptest.NewRequest("GET", "/api/v1/tenants", nil)
	reqAdminAuth.Header.Set("Authorization", "Bearer "+token)
	wAdminAuth := httptest.NewRecorder()
	handler.ServeHTTP(wAdminAuth, reqAdminAuth)
	if wAdminAuth.Code != http.StatusOK {
		t.Errorf("expected 200 for authenticated /api/v1/tenants, got %d", wAdminAuth.Code)
	}

	proj, err := adminSvc.CreateProject(reqAdmin.Context(), tenant.TenantID, "AI漫剧项目", 10000000, "", owner.MemberID)
	if err != nil {
		t.Fatalf("failed to create project: %v", err)
	}

	createdRoute, err := adminSvc.CreateRoute(reqAdmin.Context(), &admin.Route{
		TenantID:              tenant.TenantID,
		ProjectID:             proj.ProjectID,
		PathPattern:           "/api/v1/simple-weather",
		UpstreamURL:           "https://apis.juhe.cn/simpleWeather/query",
		PriceBaseUnits:        50000, // $0.0500
		Asset:                 "USD",
		AllowedPaymentMethods: "wallet",
		Status:                admin.RouteStatusActive,
		UpstreamAuth: &admin.UpstreamAuthConfig{
			Type: "api_key",
			Params: map[string]interface{}{
				"in":   "query",
				"name": "key",
			},
			Secrets: map[string]string{
				"value": "juhe_secret_weather_key",
			},
		},
	}, owner.MemberID)
	if err != nil {
		t.Fatalf("failed to create route: %v", err)
	}

	// Check upstream auth was persisted and write-only secrets not leaked
	if createdRoute.UpstreamAuth == nil || createdRoute.UpstreamAuth.Type != "api_key" {
		t.Fatalf("expected route upstream_auth to be api_key, got %+v", createdRoute.UpstreamAuth)
	}
	if !createdRoute.UpstreamAuth.HasSecret {
		t.Errorf("expected HasSecret to be true")
	}
	if len(createdRoute.UpstreamAuth.Secrets) != 0 {
		t.Errorf("expected Secrets to be empty (write-only), got %v", createdRoute.UpstreamAuth.Secrets)
	}

	// Test 7a: Calling /api/v1/simple-weather directly without credentials returns 401 wallet auth required, NOT 404!
	reqWeatherUnauth := httptest.NewRequest("GET", "/api/v1/simple-weather", nil)
	wWeatherUnauth := httptest.NewRecorder()
	handler.ServeHTTP(wWeatherUnauth, reqWeatherUnauth)

	if wWeatherUnauth.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for /api/v1/simple-weather without wallet API key, got %d (body: %s)", wWeatherUnauth.Code, wWeatherUnauth.Body.String())
	}
	if wWeatherUnauth.Header().Get("PAYMENT-REQUIRED") != "" {
		t.Errorf("did not expect PAYMENT-REQUIRED header without wallet API key")
	}

	// Test 7b: Calling with Virtual Wallet API key succeeds and proxies
	reqWeatherAuth := httptest.NewRequest("GET", "/api/v1/simple-weather?city=Shanghai", nil)
	reqWeatherAuth.Header.Set("Authorization", "Bearer apk_live_valid123")
	wWeatherAuth := httptest.NewRecorder()
	// The wallet API follows the public challenge then PAYMENT-SIGNATURE flow.
	challengeRecorder := httptest.NewRecorder()
	handler.ServeHTTP(challengeRecorder, reqWeatherAuth)
	if challengeRecorder.Code == http.StatusPaymentRequired {
		var challengeResponse struct {
			Error struct {
				Details struct {
					Challenge struct {
						ChallengeID string                 `json:"challengeId"`
						Version     string                 `json:"version"`
						Scheme      string                 `json:"scheme"`
						Amount      string                 `json:"amount"`
						ValidAfter  int64                  `json:"validAfter"`
						ValidBefore int64                  `json:"validBefore"`
						ResourceURI string                 `json:"resourceUri"`
						Extensions  map[string]interface{} `json:"extensions"`
					} `json:"challenge"`
				} `json:"details"`
			} `json:"error"`
		}
		if err := json.Unmarshal(challengeRecorder.Body.Bytes(), &challengeResponse); err != nil {
			t.Fatalf("failed to decode wallet challenge: %v", err)
		}
		challenge := challengeResponse.Error.Details.Challenge
		reqWeatherAuth = httptest.NewRequest("GET", "/api/v1/simple-weather?city=Shanghai", nil)
		reqWeatherAuth.Header.Set("Authorization", "Bearer apk_live_valid123")
		reqWeatherAuth.Header.Set("PAYMENT-SIGNATURE", fmt.Sprintf(`{"version":%q,"challengeId":%q,"scheme":%q,"nonce":"0x%064x","validAfter":%d,"validBefore":%d,"amount":%q,"resourceUri":%q,"requestBinding":%q}`,
			challenge.Version, challenge.ChallengeID, challenge.Scheme, 1, challenge.ValidAfter, challenge.ValidBefore, challenge.Amount, challenge.ResourceURI, challenge.Extensions["requestBinding"]))
		handler.ServeHTTP(wWeatherAuth, reqWeatherAuth)
	} else {
		*wWeatherAuth = *challengeRecorder
	}

	if wWeatherAuth.Code != http.StatusOK {
		t.Errorf("expected 200 for paid /api/v1/simple-weather with wallet, got %d (body: %s)", wWeatherAuth.Code, wWeatherAuth.Body.String())
	}
}

func TestServerRejectsEmptyJWTSecret(t *testing.T) {
	t.Setenv("AGENTPAY_JWT_SECRET", "")
	cfg := config.DefaultConfig()
	cfg.Auth.JWTSecret = ""
	cfg.Auth.UpstreamMasterKey = "0123456789abcdef0123456789abcdef"
	snap := &rcu.ConfigSnapshot{
		SchemaVersion: "2.0.0",
		TenantID:      "ten_default",
		VersionID:     "ver_init",
		Routes:        []rcu.RouteConfig{},
	}
	rcuMgr, err := rcu.NewManager(snap)
	if err != nil {
		t.Fatalf("failed to init rcu: %v", err)
	}
	m := metrics.New()

	_, err = New(&cfg, rcuMgr, m)
	if err == nil {
		t.Fatalf("expected server.New to fail when JWT secret is empty, got nil")
	}
}

func TestServerRejectsEmptyUpstreamMasterKey(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Auth.JWTSecret = "test-secret-at-least-32-characters-long"
	cfg.Auth.UpstreamMasterKey = ""
	t.Setenv("AGENTPAY_UPSTREAM_MASTER_KEY", "")
	snap := &rcu.ConfigSnapshot{
		SchemaVersion: "2.0.0",
		TenantID:      "ten_default",
		VersionID:     "ver_init",
		Routes:        []rcu.RouteConfig{},
	}
	rcuMgr, err := rcu.NewManager(snap)
	if err != nil {
		t.Fatalf("failed to init rcu: %v", err)
	}

	_, err = New(&cfg, rcuMgr, metrics.New())
	if err == nil {
		t.Fatalf("expected server.New to fail when UpstreamMasterKey is empty, got nil")
	}
}

type mockTestCustomVerifier struct{}

func (m *mockTestCustomVerifier) VerifyPayment(ctx context.Context, ch *x402.PaymentChallenge, auth *x402.PaymentAuthorization) (*x402.VerificationResult, error) {
	return nil, nil
}

func (m *mockTestCustomVerifier) SettlePayment(ctx context.Context, vToken string, auth *x402.PaymentAuthorization, idemKey string) (*x402.SettleResult, error) {
	return nil, nil
}

func TestServerNewWiresInjectedVerifier(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Auth.JWTSecret = "test-secret-at-least-32-characters-long"
	cfg.Auth.UpstreamMasterKey = "0123456789abcdef0123456789abcdef"

	snap := &rcu.ConfigSnapshot{
		SchemaVersion: "2.0.0",
		TenantID:      "ten_default",
		VersionID:     "ver_init",
		Routes:        []rcu.RouteConfig{},
	}
	rcuMgr, err := rcu.NewManager(snap)
	if err != nil {
		t.Fatalf("failed to init rcu: %v", err)
	}

	customVerifier := &mockTestCustomVerifier{}
	srv, err := New(&cfg, rcuMgr, metrics.New(), WithPaymentVerifier(customVerifier))
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	verifier := srv.processor.GetVerifier()
	if verifier != x402.PaymentVerifier(customVerifier) {
		t.Errorf("expected processor verifier to be injected verifier, got %v", verifier)
	}
}
