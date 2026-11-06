package upstreamauth

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegistrationAndSchemas(t *testing.T) {
	schemas := ListSchemas()
	if len(schemas) < 7 {
		t.Fatalf("expected at least 7 auth schemas, got %d", len(schemas))
	}

	expectedTypes := []string{
		"none", "api_key", "bearer", "basic",
		"oauth2_client_credentials", "hmac_sign", "custom_template",
	}

	schemaMap := make(map[string]AuthTypeSchema)
	for _, s := range schemas {
		schemaMap[s.Type] = s
	}

	for _, exp := range expectedTypes {
		if _, ok := schemaMap[exp]; !ok {
			t.Errorf("missing expected schema type: %s", exp)
		}
	}
}

func TestAESGCMSecretEncryptionAndKeyRotation(t *testing.T) {
	ResetKeyRing()
	t.Setenv("AGENTPAY_UPSTREAM_MASTER_KEY", "")

	secrets := map[string]string{
		"api_key":       "sk-live-9876543210abcdef",
		"client_secret": "cs_top_secret_xyz",
	}

	// 1. Fail-closed when master key is not configured
	if _, err := EncryptSecrets(secrets, nil); !errors.Is(err, ErrMasterKeyNotConfigured) {
		t.Fatalf("expected ErrMasterKeyNotConfigured when key not configured, got: %v", err)
	}

	// 2. Configure v1 key and encrypt
	keyV1 := "0123456789abcdef0123456789abcdef"
	if err := ConfigureKeyRing(1, keyV1, nil); err != nil {
		t.Fatalf("ConfigureKeyRing v1 failed: %v", err)
	}
	t.Cleanup(func() {
		_ = ConfigureKeyRing(1, keyV1, nil)
	})

	encV1, ver1, err := EncryptSecretsVersioned(secrets)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}
	if ver1 != 1 || len(encV1) == 0 {
		t.Fatalf("expected version 1 and non-empty ciphertext, got ver=%d len=%d", ver1, len(encV1))
	}

	dec, err := DecryptSecrets(encV1, nil)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}
	if dec["api_key"] != secrets["api_key"] || dec["client_secret"] != secrets["client_secret"] {
		t.Errorf("decrypted secrets mismatch: %+v", dec)
	}

	// 3. Rotate to v2 key while retaining v1 in keyring
	keyV2 := "fedcba9876543210fedcba9876543210"
	if err := ConfigureKeyRing(2, keyV2, map[int]string{1: keyV1}); err != nil {
		t.Fatalf("ConfigureKeyRing v2 failed: %v", err)
	}

	// Old v1 ciphertext must still be readable
	decFromV1, err := DecryptSecretsVersioned(encV1, 1)
	if err != nil {
		t.Fatalf("expected v1 ciphertext to be decryptable after rotation to v2: %v", err)
	}
	if decFromV1["api_key"] != secrets["api_key"] {
		t.Errorf("expected %s, got %s", secrets["api_key"], decFromV1["api_key"])
	}

	// Re-encrypting upgrades ciphertext to v2
	encV2, ver2, err := ReencryptSecrets(encV1, 1)
	if err != nil {
		t.Fatalf("ReencryptSecrets failed: %v", err)
	}
	if ver2 != 2 {
		t.Fatalf("expected re-encrypted version 2, got %d", ver2)
	}

	// Verify v2 ciphertext cannot be decrypted with v1 key alone
	if _, err := DecryptSecrets(encV2, []byte(keyV1)); err == nil {
		t.Fatal("expected v2 ciphertext decryption with v1 key to fail")
	}

	// 4. Tampered ciphertext check
	encV2[len(encV2)-1] ^= 0xFF
	if _, err := DecryptSecrets(encV2, nil); err == nil {
		t.Fatal("expected decryption error on tampered ciphertext, got nil")
	}
}

func TestSSRFValidationBlocksInternalAndMetadataTargets(t *testing.T) {
	t.Setenv("AGENTPAY_ALLOW_PRIVATE_UPSTREAM", "false")

	blockedURLs := []string{
		"http://127.0.0.1:8080/admin",
		"http://localhost:8000/api",
		"http://169.254.169.254/latest/meta-data/",
		"http://10.0.0.1/internal",
		"http://172.16.5.4/secret",
		"http://192.168.1.1/router",
		"http://[::1]:8080/loopback",
		"http://0.0.0.0:8000/",
		"http://metadata.google.internal/computeMetadata/v1/",
	}

	for _, u := range blockedURLs {
		if err := ValidateUpstreamURL(u); !errors.Is(err, ErrSSRFBlocked) {
			t.Errorf("expected ErrSSRFBlocked for %s, got: %v", u, err)
		}
	}

	// Public HTTPS URL should pass static validation
	if err := ValidateUpstreamURL("https://api.openai.com/v1/chat/completions"); err != nil {
		t.Errorf("expected public URL to pass ValidateUpstreamURL, got: %v", err)
	}
	if !IsBlockedIP(net.ParseIP("100.64.0.1")) {
		t.Errorf("expected CGNAT IP 100.64.0.1 to be blocked")
	}
}

func TestAPIKeyAuthenticator(t *testing.T) {
	auth, ok := Get("api_key")
	if !ok {
		t.Fatal("api_key authenticator not found")
	}

	// 1. In Header
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/v1/data", nil)
	params := map[string]any{
		"in":     "header",
		"name":   "X-API-Key",
		"prefix": "Token ",
	}
	secrets := map[string]string{"value": "my-secret-key-123"}

	if err := auth.Apply(context.Background(), req, params, secrets); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if req.Header.Get("X-API-Key") != "Token my-secret-key-123" {
		t.Errorf("unexpected header: %s", req.Header.Get("X-API-Key"))
	}

	// 2. In Query
	req2, _ := http.NewRequest(http.MethodGet, "https://api.example.com/v1/data?foo=bar", nil)
	params["in"] = "query"
	params["prefix"] = ""
	if err := auth.Apply(context.Background(), req2, params, secrets); err != nil {
		t.Fatalf("apply query failed: %v", err)
	}
	if req2.URL.Query().Get("X-API-Key") != "my-secret-key-123" {
		t.Errorf("unexpected query: %s", req2.URL.RawQuery)
	}

	// 3. In Cookie
	req3, _ := http.NewRequest(http.MethodGet, "https://api.example.com/v1/data", nil)
	params["in"] = "cookie"
	if err := auth.Apply(context.Background(), req3, params, secrets); err != nil {
		t.Fatalf("apply cookie failed: %v", err)
	}
	c, err := req3.Cookie("X-API-Key")
	if err != nil || c.Value != "my-secret-key-123" {
		t.Errorf("unexpected cookie: %v", c)
	}
}

func TestBearerAuthenticator(t *testing.T) {
	auth, ok := Get("bearer")
	if !ok {
		t.Fatal("bearer authenticator not found")
	}

	req, _ := http.NewRequest(http.MethodPost, "https://api.example.com/v1/chat", nil)
	secrets := map[string]string{"token": "jwt-token-xyz-123"}
	if err := auth.Apply(context.Background(), req, nil, secrets); err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	if req.Header.Get("Authorization") != "Bearer jwt-token-xyz-123" {
		t.Errorf("unexpected Authorization header: %s", req.Header.Get("Authorization"))
	}
}

func TestBasicAuthenticator(t *testing.T) {
	auth, ok := Get("basic")
	if !ok {
		t.Fatal("basic authenticator not found")
	}

	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/v1/info", nil)
	secrets := map[string]string{"username": "admin", "password": "password123"}
	if err := auth.Apply(context.Background(), req, nil, secrets); err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:password123"))
	if req.Header.Get("Authorization") != expected {
		t.Errorf("expected basic auth %s, got %s", expected, req.Header.Get("Authorization"))
	}
}

type roundTripFunc func(req *http.Request) *http.Response

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

func TestOAuth2Authenticator(t *testing.T) {
	rawAuth, ok := Get("oauth2_client_credentials")
	if !ok {
		t.Fatal("oauth2 authenticator not found")
	}
	oauthAuth := rawAuth.(*OAuth2Authenticator)

	callCount := 0
	oauthAuth.SetTransport(roundTripFunc(func(r *http.Request) *http.Response {
		callCount++
		respBody := `{"access_token":"mock-oauth2-access-token-999","expires_in":3600}`
		rec := httptest.NewRecorder()
		rec.Header().Set("Content-Type", "application/json")
		rec.WriteHeader(http.StatusOK)
		_, _ = rec.WriteString(respBody)
		return rec.Result()
	}))

	params := map[string]any{
		"token_url":  "https://auth.example.com/oauth/token",
		"scope":      "read write",
		"auth_style": "header",
	}
	secrets := map[string]string{
		"client_id":     "client_007",
		"client_secret": "secret_xyz",
	}

	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/data", nil)
	if err := oauthAuth.Apply(context.Background(), req, params, secrets); err != nil {
		t.Fatalf("first apply failed: %v", err)
	}
	if req.Header.Get("Authorization") != "Bearer mock-oauth2-access-token-999" {
		t.Errorf("unexpected token: %s", req.Header.Get("Authorization"))
	}
	if callCount != 1 {
		t.Fatalf("expected 1 call to token server, got %d", callCount)
	}

	// Second call should reuse cached token
	req2, _ := http.NewRequest(http.MethodGet, "https://api.example.com/data", nil)
	if err := oauthAuth.Apply(context.Background(), req2, params, secrets); err != nil {
		t.Fatalf("second apply failed: %v", err)
	}
	if callCount != 1 {
		t.Errorf("expected token cache hit (callCount=1), got %d", callCount)
	}
}

func TestHMACAuthenticator(t *testing.T) {
	auth, ok := Get("hmac_sign")
	if !ok {
		t.Fatal("hmac_sign authenticator not found")
	}

	req, _ := http.NewRequest(http.MethodPost, "https://api.example.com/v1/orders", nil)
	params := map[string]any{
		"algorithm":        "hmac_sha256",
		"sign_header":      "X-Agent-Sign",
		"timestamp_header": "X-Agent-Time",
		"app_key_header":   "X-Agent-AppKey",
		"app_key":          "app_test_123",
	}
	secrets := map[string]string{
		"secret": "top-secret-signing-key",
	}

	if err := auth.Apply(context.Background(), req, params, secrets); err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	if req.Header.Get("X-Agent-AppKey") != "app_test_123" {
		t.Errorf("missing or invalid appkey header: %s", req.Header.Get("X-Agent-AppKey"))
	}
	if req.Header.Get("X-Agent-Time") == "" {
		t.Error("missing timestamp header")
	}
	if req.Header.Get("X-Agent-Sign") == "" {
		t.Error("missing signature header")
	}
}

func TestCustomTemplateAuthenticator(t *testing.T) {
	auth, ok := Get("custom_template")
	if !ok {
		t.Fatal("custom_template authenticator not found")
	}

	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/v1/market", nil)
	params := map[string]any{
		"headers_template": "{\n\"Authorization\": \"CustomKey {{secret.my_api_key}}\",\n\"X-Req-Method\": \"{{method}}\"\n}",
	}
	secrets := map[string]string{
		"my_api_key": "live-custom-key-777",
	}

	if err := auth.Apply(context.Background(), req, params, secrets); err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	if req.Header.Get("Authorization") != "CustomKey live-custom-key-777" {
		t.Errorf("unexpected Authorization header: %s", req.Header.Get("Authorization"))
	}
	if req.Header.Get("X-Req-Method") != "GET" {
		t.Errorf("unexpected X-Req-Method header: %s", req.Header.Get("X-Req-Method"))
	}
}

func TestMaskHeader(t *testing.T) {
	masked := MaskHeader("Authorization", "Bearer sk-1234567890abcdef")
	if !strings.Contains(masked, "●●●●●●") {
		t.Errorf("expected masked header, got: %s", masked)
	}
	if strings.Contains(masked, "1234567890") {
		t.Errorf("sensitive value leaked in masked header: %s", masked)
	}
}
