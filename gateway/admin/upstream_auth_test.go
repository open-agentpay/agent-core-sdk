package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/open-agentpay/agent-core-sdk/gateway/auth"
	"github.com/open-agentpay/agent-core-sdk/gateway/upstreamauth"
)

func TestUpstreamAuthEndpointsAndLifecycle(t *testing.T) {
	if err := upstreamauth.ConfigureKeyRing(1, "0123456789abcdef0123456789abcdef", nil); err != nil {
		t.Fatalf("failed to configure keyring: %v", err)
	}

	svc := NewMemoryService(nil, nil)
	jwtMgr := auth.MustNewJWTManager("test-admin-secret-key-for-unit-testing-32b!", 24*time.Hour)
	handler := NewHandlerWithJWT(svc, jwtMgr)

	tenant, owner, err := svc.CreateTenant(context.Background(), "Upstream Auth Org", "ten_upstream_001", "admin@upstream.io")
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}
	ownerToken, _ := jwtMgr.GenerateToken(owner.MemberID, owner.Email, tenant.TenantID, string(owner.Role))

	// 1. Test GET /api/v1/auth-types
	reqTypes := httptest.NewRequest(http.MethodGet, "/api/v1/auth-types", nil)
	recTypes := httptest.NewRecorder()
	handler.ServeHTTP(recTypes, reqTypes)

	if recTypes.Code != http.StatusOK {
		t.Fatalf("expected 200 from /auth-types, got %d: %s", recTypes.Code, recTypes.Body.String())
	}
	var typesResp struct {
		Types []upstreamauth.AuthTypeSchema `json:"types"`
	}
	if err := json.Unmarshal(recTypes.Body.Bytes(), &typesResp); err != nil {
		t.Fatalf("failed to decode auth-types: %v", err)
	}
	if len(typesResp.Types) < 7 {
		t.Errorf("expected at least 7 auth schemas, got %d", len(typesResp.Types))
	}

	// 2. Test POST /api/v1/tenants/:id/routes with UpstreamAuth
	routePayload := map[string]any{
		"path_pattern":            "/v1/models/deepseek",
		"upstream_url":            "https://api.deepseek.com/v1/chat/completions",
		"price_base_units":        20000,
		"allowed_payment_methods": "wallet",
		"upstream_auth": map[string]any{
			"type": "api_key",
			"params": map[string]any{
				"in":     "header",
				"name":   "Authorization",
				"prefix": "Bearer ",
			},
			"secrets": map[string]string{
				"value": "sk-live-deepseek-123456",
			},
		},
	}
	bodyBytes, _ := json.Marshal(routePayload)
	reqCreate := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/"+tenant.TenantID+"/routes", bytes.NewReader(bodyBytes))
	reqCreate.Header.Set("Content-Type", "application/json")
	reqCreate.Header.Set("Authorization", "Bearer "+ownerToken)
	recCreate := httptest.NewRecorder()
	handler.ServeHTTP(recCreate, reqCreate)

	if recCreate.Code != http.StatusCreated {
		t.Fatalf("expected 201 created route, got %d: %s", recCreate.Code, recCreate.Body.String())
	}

	var createResp struct {
		Route *Route `json:"route"`
	}
	if err := json.Unmarshal(recCreate.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("failed to decode created route: %v", err)
	}
	createdRoute := createResp.Route
	if createdRoute.UpstreamAuth == nil {
		t.Fatal("expected UpstreamAuth to be populated")
	}
	if createdRoute.UpstreamAuth.Type != "api_key" {
		t.Errorf("expected type api_key, got %s", createdRoute.UpstreamAuth.Type)
	}
	if !createdRoute.UpstreamAuth.HasSecret {
		t.Error("expected HasSecret to be true")
	}
	// Secrets must NEVER be echoed back in plain text!
	if len(createdRoute.UpstreamAuth.Secrets) != 0 {
		t.Errorf("expected Secrets to be empty (write-only), got %v", createdRoute.UpstreamAuth.Secrets)
	}

	// 3. Test PATCH without updating secrets preserves existing encrypted secret
	updatePayload := map[string]any{
		"price_base_units": 25000,
		"upstream_auth": map[string]any{
			"type": "api_key",
			"params": map[string]any{
				"in":     "header",
				"name":   "Authorization",
				"prefix": "Bearer ",
			},
			// no secrets provided
		},
	}
	updateBytes, _ := json.Marshal(updatePayload)
	reqUpdate := httptest.NewRequest(http.MethodPatch, "/api/v1/tenants/"+tenant.TenantID+"/routes/"+createdRoute.RouteID, bytes.NewReader(updateBytes))
	reqUpdate.Header.Set("Content-Type", "application/json")
	reqUpdate.Header.Set("Authorization", "Bearer "+ownerToken)
	recUpdate := httptest.NewRecorder()
	handler.ServeHTTP(recUpdate, reqUpdate)

	if recUpdate.Code != http.StatusOK {
		t.Fatalf("expected 200 updated route, got %d: %s", recUpdate.Code, recUpdate.Body.String())
	}
	var updateResp struct {
		Route *Route `json:"route"`
	}
	_ = json.Unmarshal(recUpdate.Body.Bytes(), &updateResp)
	if !updateResp.Route.UpstreamAuth.HasSecret {
		t.Error("expected HasSecret to remain true after partial update")
	}

	// 4. Test POST /api/v1/tenants/:id/routes/test-upstream
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"authenticated": true})
	}))
	defer mockUpstream.Close()

	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("http_proxy", "")
	t.Setenv("https_proxy", "")
	t.Setenv("AGENTPAY_ALLOW_PRIVATE_UPSTREAM", "true")

	testPayload := map[string]any{
		"upstream_url": mockUpstream.URL + "/get",
		"method":       "GET",
		"upstream_auth": map[string]any{
			"type": "bearer",
			"secrets": map[string]string{
				"token": "test-token-xyz-12345678",
			},
		},
	}
	testBytes, _ := json.Marshal(testPayload)
	reqTest := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/"+tenant.TenantID+"/routes/test-upstream", bytes.NewReader(testBytes))
	reqTest.Header.Set("Content-Type", "application/json")
	reqTest.Header.Set("Authorization", "Bearer "+ownerToken)
	recTest := httptest.NewRecorder()
	handler.ServeHTTP(recTest, reqTest)

	if recTest.Code != http.StatusOK {
		t.Fatalf("expected 200 from test-upstream, got %d: %s", recTest.Code, recTest.Body.String())
	}

	var testResp struct {
		Result *TestUpstreamResult `json:"result"`
	}
	if err := json.Unmarshal(recTest.Body.Bytes(), &testResp); err != nil {
		t.Fatalf("failed to decode test result: %v", err)
	}

	res := testResp.Result
	if res == nil {
		t.Fatal("expected test result to be non-nil")
	}
	// Verify sentHeaders is present and masked
	authHeader, hasAuth := res.SentHeaders["Authorization"]
	if !hasAuth {
		t.Error("expected Authorization in sentHeaders")
	}
	if authHeader != "" && !bytes.Contains([]byte(authHeader), []byte("●●●●●●")) {
		t.Errorf("expected masked Authorization header, got: %s", authHeader)
	}

	// 5. Test SSRF rejection on test-upstream (e.g. cloud metadata 169.254.169.254 & loopback 127.0.0.1)
	t.Setenv("AGENTPAY_ALLOW_PRIVATE_UPSTREAM", "false")
	for _, ssrfURL := range []string{"http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:8080/internal"} {
		ssrfPayload, _ := json.Marshal(map[string]any{
			"upstream_url": ssrfURL,
			"method":       "GET",
		})
		reqSSRF := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/"+tenant.TenantID+"/routes/test-upstream", bytes.NewReader(ssrfPayload))
		reqSSRF.Header.Set("Content-Type", "application/json")
		reqSSRF.Header.Set("Authorization", "Bearer "+ownerToken)
		recSSRF := httptest.NewRecorder()
		handler.ServeHTTP(recSSRF, reqSSRF)

		if recSSRF.Code != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden for SSRF test-upstream %s, got %d: %s", ssrfURL, recSSRF.Code, recSSRF.Body.String())
		}
	}
}
