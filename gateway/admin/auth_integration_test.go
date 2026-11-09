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
)

func TestAuthRegistrationAndLogin(t *testing.T) {
	svc, _, _ := setupTestService()
	jwtMgr := auth.MustNewJWTManager("test-jwt-secret-key-32-bytes!!", 1*time.Hour)
	handler := auth.Middleware(jwtMgr)(NewHandlerWithJWT(svc, jwtMgr))

	// 1. Password too short validation
	badRegPayload := map[string]string{
		"tenant_name": "Acme Short",
		"email":       "short@acme.com",
		"password":    "12345",
	}
	bodyBytes, _ := json.Marshal(badRegPayload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(bodyBytes))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for short password, got: %d", rec.Code)
	}

	// 2. Successful Registration
	regPayload := map[string]string{
		"tenant_name": "Autonomous Dynamics Corp",
		"email":       "alice@autodyn.io",
		"password":    "SecureP@ssw0rd2026",
	}
	bodyBytes, _ = json.Marshal(regPayload)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(bodyBytes))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for registration, got: %d, body: %s", rec.Code, rec.Body.String())
	}

	var regResp struct {
		Token  string  `json:"token"`
		User   *Member `json:"user"`
		Tenant *Tenant `json:"tenant"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &regResp); err != nil {
		t.Fatalf("failed to decode register response: %v", err)
	}

	if regResp.Token == "" {
		t.Fatalf("expected non-empty JWT token")
	}
	if regResp.User.Email != "alice@autodyn.io" || regResp.User.Role != RoleOwner {
		t.Fatalf("expected owner member, got: %+v", regResp.User)
	}
	if regResp.Tenant.Name != "Autonomous Dynamics Corp" {
		t.Fatalf("expected tenant name Autonomous Dynamics Corp, got: %s", regResp.Tenant.Name)
	}

	// 3. Duplicate email rejection
	reqDup := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(bodyBytes))
	recDup := httptest.NewRecorder()
	handler.ServeHTTP(recDup, reqDup)
	if recDup.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict for duplicate registration, got: %d", recDup.Code)
	}

	// 4. Login with valid credentials
	loginPayload := map[string]string{
		"email":    "alice@autodyn.io",
		"password": "SecureP@ssw0rd2026",
	}
	bodyBytes, _ = json.Marshal(loginPayload)
	reqLogin := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(bodyBytes))
	recLogin := httptest.NewRecorder()
	handler.ServeHTTP(recLogin, reqLogin)

	if recLogin.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for valid login, got: %d, body: %s", recLogin.Code, recLogin.Body.String())
	}

	var loginResp struct {
		Token  string  `json:"token"`
		User   *Member `json:"user"`
		Tenant *Tenant `json:"tenant"`
	}
	if err := json.Unmarshal(recLogin.Body.Bytes(), &loginResp); err != nil {
		t.Fatalf("failed to decode login response: %v", err)
	}
	if loginResp.Token == "" {
		t.Fatalf("expected JWT token from login")
	}

	// 5. Login with invalid password
	badLoginPayload := map[string]string{
		"email":    "alice@autodyn.io",
		"password": "WrongPassword!",
	}
	bodyBytes, _ = json.Marshal(badLoginPayload)
	reqBadLogin := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(bodyBytes))
	recBadLogin := httptest.NewRecorder()
	handler.ServeHTTP(recBadLogin, reqBadLogin)

	if recBadLogin.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for bad password, got: %d", recBadLogin.Code)
	}
}

func TestAuthMeProfileAndPermissions(t *testing.T) {
	svc, _, _ := setupTestService()
	jwtMgr := auth.MustNewJWTManager("test-jwt-secret-key-32-bytes!!", 1*time.Hour)
	handler := auth.Middleware(jwtMgr)(NewHandlerWithJWT(svc, jwtMgr))

	// Register owner
	regPayload := map[string]string{
		"tenant_name": "TestCorp",
		"email":       "owner@testcorp.io",
		"password":    "Password123!",
	}
	bodyBytes, _ := json.Marshal(regPayload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(bodyBytes))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var regResp struct {
		Token  string  `json:"token"`
		User   *Member `json:"user"`
		Tenant *Tenant `json:"tenant"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &regResp)

	// Call /auth/me without token -> 401
	reqNoAuth := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	recNoAuth := httptest.NewRecorder()
	handler.ServeHTTP(recNoAuth, reqNoAuth)
	if recNoAuth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for /auth/me without token, got: %d", recNoAuth.Code)
	}

	// Call /auth/me with valid Bearer token -> 200 OK
	reqMe := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	reqMe.Header.Set("Authorization", "Bearer "+regResp.Token)
	recMe := httptest.NewRecorder()
	handler.ServeHTTP(recMe, reqMe)

	if recMe.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /auth/me, got: %d, body: %s", recMe.Code, recMe.Body.String())
	}

	var meResp struct {
		User        *Member  `json:"user"`
		Tenant      *Tenant  `json:"tenant"`
		Permissions []string `json:"permissions"`
	}
	if err := json.Unmarshal(recMe.Body.Bytes(), &meResp); err != nil {
		t.Fatalf("failed to decode /auth/me response: %v", err)
	}

	if meResp.User.Email != "owner@testcorp.io" {
		t.Errorf("expected email owner@testcorp.io, got: %s", meResp.User.Email)
	}
	if len(meResp.Permissions) == 0 {
		t.Errorf("expected non-empty permissions list for owner")
	}
}

func TestJWTSecuredAdminOperation(t *testing.T) {
	svc, _, _ := setupTestService()
	jwtMgr := auth.MustNewJWTManager("test-jwt-secret-key-32-bytes!!", 1*time.Hour)
	handler := auth.Middleware(jwtMgr)(NewHandlerWithJWT(svc, jwtMgr))

	// 1. Register owner
	regPayload := map[string]string{
		"tenant_name": "API Corp",
		"email":       "admin@apicorp.io",
		"password":    "Password123!",
	}
	bodyBytes, _ := json.Marshal(regPayload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(bodyBytes))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var regResp struct {
		Token  string  `json:"token"`
		User   *Member `json:"user"`
		Tenant *Tenant `json:"tenant"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &regResp)

	// 2. Call POST /api/v1/tenants/{tenant_id}/projects relying ONLY on Authorization: Bearer <token>
	projPayload := map[string]interface{}{
		"name":                  "AI Search Swarm",
		"budget_cap_base_units": 100000000,
	}
	bodyBytes, _ = json.Marshal(projPayload)
	reqProj := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/"+regResp.Tenant.TenantID+"/projects", bytes.NewReader(bodyBytes))
	reqProj.Header.Set("Authorization", "Bearer "+regResp.Token)
	// Notice: NO X-Actor-Member-Id header provided! Authenticated by Bearer token.
	recProj := httptest.NewRecorder()
	handler.ServeHTTP(recProj, reqProj)

	if recProj.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created using Bearer token, got: %d, body: %s", recProj.Code, recProj.Body.String())
	}

	var projResp struct {
		Project *Project `json:"project"`
	}
	if err := json.Unmarshal(recProj.Body.Bytes(), &projResp); err != nil {
		t.Fatalf("failed to decode project response: %v", err)
	}
	if projResp.Project.Name != "AI Search Swarm" {
		t.Errorf("expected project name AI Search Swarm, got: %s", projResp.Project.Name)
	}
	if projResp.Project.TenantID != regResp.Tenant.TenantID {
		t.Errorf("expected project tenant %s, got: %s", regResp.Tenant.TenantID, projResp.Project.TenantID)
	}
}

func TestAddMemberWithPasswordAndSelfPasswordChange(t *testing.T) {
	svc, _, _ := setupTestService()
	jwtMgr := auth.MustNewJWTManager("test-jwt-secret-key-32-bytes!!", 1*time.Hour)
	handler := auth.Middleware(jwtMgr)(NewHandlerWithJWT(svc, jwtMgr))

	// 1. Register owner
	regPayload := map[string]string{
		"tenant_name": "DevOps Hub",
		"email":       "owner@devops.hub",
		"password":    "OwnerSecret123!",
	}
	bodyBytes, _ := json.Marshal(regPayload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(bodyBytes))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var regResp struct {
		Token  string  `json:"token"`
		Tenant *Tenant `json:"tenant"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &regResp)

	// 2. Owner adds an operator member with initial password
	addMemberPayload := map[string]string{
		"email":    "operator@devops.hub",
		"role":     "operator",
		"password": "InitPassword123!",
	}
	bodyBytes, _ = json.Marshal(addMemberPayload)
	reqAdd := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/"+regResp.Tenant.TenantID+"/members", bytes.NewReader(bodyBytes))
	reqAdd.Header.Set("Authorization", "Bearer "+regResp.Token)
	recAdd := httptest.NewRecorder()
	handler.ServeHTTP(recAdd, reqAdd)

	if recAdd.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for AddMember, got: %d, body: %s", recAdd.Code, recAdd.Body.String())
	}

	// 3. New operator logs in with initial password
	loginPayload := map[string]string{
		"email":    "operator@devops.hub",
		"password": "InitPassword123!",
	}
	bodyBytes, _ = json.Marshal(loginPayload)
	reqLogin := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(bodyBytes))
	recLogin := httptest.NewRecorder()
	handler.ServeHTTP(recLogin, reqLogin)

	if recLogin.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for operator login, got: %d", recLogin.Code)
	}

	var opLoginResp struct {
		Token string  `json:"token"`
		User  *Member `json:"user"`
	}
	_ = json.Unmarshal(recLogin.Body.Bytes(), &opLoginResp)

	// 4. Operator changes their own password via /api/v1/auth/password
	pwChangePayload := map[string]string{
		"old_password": "InitPassword123!",
		"new_password": "NewOperatorPass456!",
	}
	bodyBytes, _ = json.Marshal(pwChangePayload)
	reqPw := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password", bytes.NewReader(bodyBytes))
	reqPw.Header.Set("Authorization", "Bearer "+opLoginResp.Token)
	recPw := httptest.NewRecorder()
	handler.ServeHTTP(recPw, reqPw)

	if recPw.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for password change, got: %d, body: %s", recPw.Code, recPw.Body.String())
	}

	// 5. Old password no longer works
	reqOldLogin := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(bodyBytes))
	recOldLogin := httptest.NewRecorder()
	handler.ServeHTTP(recOldLogin, reqOldLogin)
	if recOldLogin.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for old password, got: %d", recOldLogin.Code)
	}

	// 6. New password works
	newLoginPayload := map[string]string{
		"email":    "operator@devops.hub",
		"password": "NewOperatorPass456!",
	}
	bodyBytes, _ = json.Marshal(newLoginPayload)
	reqNewLogin := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(bodyBytes))
	recNewLogin := httptest.NewRecorder()
	handler.ServeHTTP(recNewLogin, reqNewLogin)
	if recNewLogin.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for new password, got: %d", recNewLogin.Code)
	}
}

func TestP01UnauthenticatedSpoofedAndCrossTenantIsolation(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := setupTestService()
	jwtMgr := auth.MustNewJWTManager("test-jwt-secret-key-32-bytes!!", 1*time.Hour)
	handler := auth.Middleware(jwtMgr)(NewHandlerWithJWT(svc, jwtMgr))

	// Setup Tenant A and Tenant B
	tenA, ownerA, _ := svc.CreateTenant(ctx, "Tenant Alpha", "ten_alpha", "owner@alpha.io")
	prjA, _ := svc.CreateProject(ctx, tenA.TenantID, "Alpha Project", nil, 1000000, "prj_alpha", ownerA.MemberID)
	agA, _ := svc.CreateAgent(ctx, tenA.TenantID, prjA.ProjectID, "AlphaBot", nil, ownerA.MemberID)
	wltA, _ := svc.GetWallet(ctx, tenA.TenantID)
	viewerA, _ := svc.AddMember(ctx, tenA.TenantID, "viewer@alpha.io", RoleViewer, ownerA.MemberID)

	tenB, ownerB, _ := svc.CreateTenant(ctx, "Tenant Beta", "ten_beta", "owner@beta.io")
	prjB, _ := svc.CreateProject(ctx, tenB.TenantID, "Beta Project", nil, 1000000, "prj_beta", ownerB.MemberID)
	agB, _ := svc.CreateAgent(ctx, tenB.TenantID, prjB.ProjectID, "BetaBot", nil, ownerB.MemberID)
	wltB, _ := svc.GetWallet(ctx, tenB.TenantID)

	tokenOwnerA, _ := jwtMgr.GenerateToken(ownerA.MemberID, ownerA.Email, tenA.TenantID, string(ownerA.Role))
	tokenViewerA, _ := jwtMgr.GenerateToken(viewerA.MemberID, viewerA.Email, tenA.TenantID, string(viewerA.Role))
	_ = prjB

	// 1. Unauthenticated access (even with spoofed X-Tenant-Id / X-Actor-Member-Id) MUST return 401
	unauthCases := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/api/v1/tenants", ""},
		{http.MethodGet, "/api/v1/tenants/" + tenA.TenantID, ""},
		{http.MethodGet, "/api/v1/tenants/" + tenA.TenantID + "/members", ""},
		{http.MethodPost, "/api/v1/tenants/" + tenA.TenantID + "/projects", `{"name":"HackProj"}`},
		{http.MethodGet, "/api/v1/wallets/" + wltA.WalletID, ""},
		{http.MethodPost, "/api/v1/wallets/" + wltA.WalletID + "/adjust", `{"amount":999999999,"reason":"hack"}`},
		{http.MethodGet, "/api/v1/agents/" + agA.AgentID, ""},
		{http.MethodGet, "/api/v1/audit/events?tenant_id=" + tenA.TenantID, ""},
	}

	for _, tc := range unauthCases {
		req := httptest.NewRequest(tc.method, tc.path, bytes.NewBufferString(tc.body))
		req.Header.Set("X-Tenant-Id", tenA.TenantID)
		req.Header.Set("X-Actor-Member-Id", ownerA.MemberID)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized for unauthenticated %s %s, got %d: %s", tc.method, tc.path, rec.Code, rec.Body.String())
		}
	}

	// 2. Viewer token accessing write endpoints MUST return 403
	viewerWriteCases := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodPost, "/api/v1/tenants/" + tenA.TenantID + "/projects", `{"name":"ViewerProj"}`},
		{http.MethodPost, "/api/v1/wallets/" + wltA.WalletID + "/adjust", `{"amount":1000,"reason":"viewer try"}`},
		{http.MethodPost, "/api/v1/agents/" + agA.AgentID + "/kill", `{"reason":"viewer try"}`},
	}

	for _, tc := range viewerWriteCases {
		req := httptest.NewRequest(tc.method, tc.path, bytes.NewBufferString(tc.body))
		req.Header.Set("Authorization", "Bearer "+tokenViewerA)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for viewer %s %s, got %d: %s", tc.method, tc.path, rec.Code, rec.Body.String())
		}
	}

	// 3. Tenant A Owner token accessing Tenant B resources MUST return 403
	crossTenantCases := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/api/v1/tenants/" + tenB.TenantID, ""},
		{http.MethodGet, "/api/v1/tenants/" + tenB.TenantID + "/members", ""},
		{http.MethodPost, "/api/v1/tenants/" + tenB.TenantID + "/projects", `{"name":"CrossTenantProj"}`},
		{http.MethodGet, "/api/v1/wallets/" + wltB.WalletID, ""},
		{http.MethodPost, "/api/v1/wallets/" + wltB.WalletID + "/adjust", `{"amount":999999,"reason":"cross tenant"}`},
		{http.MethodGet, "/api/v1/agents/" + agB.AgentID, ""},
		{http.MethodPost, "/api/v1/agents/" + agB.AgentID + "/kill", `{"reason":"cross tenant kill"}`},
		{http.MethodGet, "/api/v1/audit/events?tenant_id=" + tenB.TenantID, ""},
	}

	for _, tc := range crossTenantCases {
		req := httptest.NewRequest(tc.method, tc.path, bytes.NewBufferString(tc.body))
		req.Header.Set("Authorization", "Bearer "+tokenOwnerA)
		// Even if client tries to spoof X-Tenant-Id for Tenant B
		req.Header.Set("X-Tenant-Id", tenB.TenantID)
		req.Header.Set("X-Actor-Member-Id", ownerB.MemberID)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for cross-tenant %s %s, got %d: %s", tc.method, tc.path, rec.Code, rec.Body.String())
		}
	}
}
