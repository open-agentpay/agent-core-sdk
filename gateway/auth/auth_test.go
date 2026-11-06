package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPasswordHashingAndVerification(t *testing.T) {
	password := "SecretP@ssw0rd2026"

	// 1. Minimum length rejection
	_, err := HashPassword("short")
	if err != ErrPasswordTooShort {
		t.Fatalf("expected ErrPasswordTooShort for short password, got: %v", err)
	}

	// 2. Successful hash
	encodedHash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	if len(encodedHash) == 0 {
		t.Fatalf("hash output should not be empty")
	}

	// 3. Positive verification
	if !VerifyPassword(password, encodedHash) {
		t.Fatalf("expected password verification to succeed")
	}

	// 4. Negative verification (wrong password)
	if VerifyPassword("WrongPassword123", encodedHash) {
		t.Fatalf("expected password verification to fail for wrong password")
	}

	// 5. Tampered hash string
	if VerifyPassword(password, "$invalid$hash$format") {
		t.Fatalf("expected verification to fail for invalid hash format")
	}
}

func TestJWTManagerRejectsEmptySecret(t *testing.T) {
	_, err := NewJWTManager("", 24*time.Hour)
	if err == nil {
		t.Fatalf("expected error when secret key is empty, got nil")
	}

	_, err = NewJWTManager("   ", 24*time.Hour)
	if err == nil {
		t.Fatalf("expected error when secret key is whitespace, got nil")
	}
}

func TestJWTGenerationAndValidation(t *testing.T) {
	jwtMgr, err := NewJWTManager("super-secret-key-for-testing", 2*time.Second)
	if err != nil {
		t.Fatalf("unexpected error creating jwt manager: %v", err)
	}

	memberID := "usr_test123"
	email := "alice@agentpay.io"
	tenantID := "ten_test456"
	role := "owner"

	// 1. Generate token
	tokenStr, err := jwtMgr.GenerateToken(memberID, email, tenantID, role)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	// 2. Validate token
	claims, err := jwtMgr.ValidateToken(tokenStr)
	if err != nil {
		t.Fatalf("failed to validate token: %v", err)
	}

	if claims.Subject != memberID {
		t.Errorf("expected subject %s, got %s", memberID, claims.Subject)
	}
	if claims.Email != email {
		t.Errorf("expected email %s, got %s", email, claims.Email)
	}
	if claims.TenantID != tenantID {
		t.Errorf("expected tenantID %s, got %s", tenantID, claims.TenantID)
	}
	if claims.Role != role {
		t.Errorf("expected role %s, got %s", role, claims.Role)
	}

	// 3. Tampered signature
	tamperedToken := tokenStr + "tampered"
	_, err = jwtMgr.ValidateToken(tamperedToken)
	if err != ErrTokenInvalid {
		t.Errorf("expected ErrTokenInvalid for tampered token, got: %v", err)
	}

	// 4. Token expiration
	expiredMgr := MustNewJWTManager("secret", -1*time.Second)
	expiredToken, err := expiredMgr.GenerateToken(memberID, email, tenantID, role)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	_, err = expiredMgr.ValidateToken(expiredToken)
	if err != ErrTokenExpired {
		t.Errorf("expected ErrTokenExpired, got: %v", err)
	}
}

func TestAuthMiddleware(t *testing.T) {
	jwtMgr := MustNewJWTManager("secret", 1*time.Hour)
	middleware := Middleware(jwtMgr)

	handlerExecuted := false
	var capturedMemberID, capturedTenantID string

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerExecuted = true
		capturedMemberID = GetMemberID(r.Context())
		capturedTenantID = GetTenantID(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	wrapped := middleware(nextHandler)

	// Case 1: Valid Bearer token overwrites any spoofed client headers
	token, _ := jwtMgr.GenerateToken("usr_bob", "bob@agentpay.io", "ten_corp", "admin")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Actor-Member-Id", "spoofed_member")
	req.Header.Set("X-Tenant-Id", "spoofed_tenant")
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got: %d", rec.Code)
	}
	if !handlerExecuted {
		t.Fatalf("expected nextHandler to be called")
	}
	if capturedMemberID != "usr_bob" {
		t.Errorf("expected capturedMemberID usr_bob, got: %s", capturedMemberID)
	}
	if capturedTenantID != "ten_corp" {
		t.Errorf("expected capturedTenantID ten_corp, got: %s", capturedTenantID)
	}
	if req.Header.Get("X-Actor-Member-Id") != "usr_bob" {
		t.Errorf("expected X-Actor-Member-Id header to be usr_bob, got: %s", req.Header.Get("X-Actor-Member-Id"))
	}
	if req.Header.Get("X-Tenant-Id") != "ten_corp" {
		t.Errorf("expected X-Tenant-Id header to be ten_corp, got: %s", req.Header.Get("X-Tenant-Id"))
	}

	// Case 2: Invalid Bearer token
	reqInvalid := httptest.NewRequest(http.MethodGet, "/api/v1/protected", nil)
	reqInvalid.Header.Set("Authorization", "Bearer bad.token.value")
	recInvalid := httptest.NewRecorder()

	wrapped.ServeHTTP(recInvalid, reqInvalid)

	if recInvalid.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got: %d", recInvalid.Code)
	}

	// Case 3: No Authorization header strips spoofed X-Actor-Member-Id / X-Tenant-Id headers
	handlerExecuted = false
	reqNoAuth := httptest.NewRequest(http.MethodGet, "/api/v1/public", nil)
	reqNoAuth.Header.Set("X-Actor-Member-Id", "evil_actor")
	reqNoAuth.Header.Set("X-Tenant-Id", "evil_tenant")
	recNoAuth := httptest.NewRecorder()

	wrapped.ServeHTTP(recNoAuth, reqNoAuth)

	if recNoAuth.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for passthrough, got: %d", recNoAuth.Code)
	}
	if !handlerExecuted {
		t.Fatalf("expected nextHandler to be called for passthrough")
	}
	if reqNoAuth.Header.Get("X-Actor-Member-Id") != "" {
		t.Errorf("expected spoofed X-Actor-Member-Id to be stripped, got: %s", reqNoAuth.Header.Get("X-Actor-Member-Id"))
	}
	if reqNoAuth.Header.Get("X-Tenant-Id") != "" {
		t.Errorf("expected spoofed X-Tenant-Id to be stripped, got: %s", reqNoAuth.Header.Get("X-Tenant-Id"))
	}
}
