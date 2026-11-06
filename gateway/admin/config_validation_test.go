package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/open-agentpay/agent-core-sdk/gateway/auth"
)

func TestConfigDraftAndValidation(t *testing.T) {
	svc, _, _ := setupTestService()
	jwtMgr := auth.MustNewJWTManager("test-secret-key-32-bytes-long!!", 2*time.Hour)
	handler := auth.Middleware(jwtMgr)(NewHandlerWithJWT(svc, jwtMgr))

	ctx := context.Background()
	tenant, owner, err := svc.CreateTenant(ctx, "Validation Corp", "ten_val", "owner@valcorp.io")
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	ownerToken, _ := jwtMgr.GenerateToken(owner.MemberID, owner.Email, tenant.TenantID, string(owner.Role))

	// 1. Initial draft summary - should show default project
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/"+tenant.TenantID+"/config/draft", nil)
	req.Header.Set("Authorization", "Bearer "+ownerToken)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for draft summary, got %d: %s", w.Code, w.Body.String())
	}

	var draftResp struct {
		Draft *ConfigDraftSummary `json:"draft"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &draftResp)
	if draftResp.Draft == nil {
		t.Fatalf("expected draft summary in response")
	}

	// 2. Validate empty/default config -> should be Valid
	req = httptest.NewRequest(http.MethodPost, "/api/v1/tenants/"+tenant.TenantID+"/config/validate", nil)
	req.Header.Set("Authorization", "Bearer "+ownerToken)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for validate, got %d", w.Code)
	}

	var valResp struct {
		Result *ValidationResult `json:"result"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &valResp)
	if !valResp.Result.Valid {
		t.Fatalf("expected empty draft to be valid, got errors: %+v", valResp.Result.Errors)
	}

	// 3. Inject invalid policy: max_amount (200 USDC) > rolling 24h budget (100 USDC)
	invalidPol := &Policy{
		PolicyID:            "pol_bad_budget",
		TenantID:            tenant.TenantID,
		ProjectID:           "prj_default",
		MaxAmountPerRequest: 200000000, // 200 USDC
		Rolling24hBudgetCap: 100000000, // 100 USDC
		IsActive:            true,
	}
	_, err = svc.CreatePolicy(ctx, invalidPol, owner.MemberID)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	// Also add a route with invalid upstream url
	invalidRoute := &Route{
		RouteID:               "rte_bad_url",
		TenantID:              tenant.TenantID,
		ProjectID:             "prj_default",
		PathPattern:           "/api/v1/broken",
		UpstreamURL:           "ftp://invalid.corp/resource", // Invalid scheme!
		PriceBaseUnits:        50000,
		AllowedPaymentMethods: "wallet",
	}
	svc.routes[invalidRoute.RouteID] = invalidRoute

	// 4. Validate again -> Must be Invalid with exact error codes
	req = httptest.NewRequest(http.MethodPost, "/api/v1/tenants/"+tenant.TenantID+"/config/validate", nil)
	req.Header.Set("Authorization", "Bearer "+ownerToken)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for validate, got %d", w.Code)
	}

	_ = json.Unmarshal(w.Body.Bytes(), &valResp)
	if valResp.Result.Valid {
		t.Fatalf("expected validation to FAIL for broken policy and route")
	}

	foundBudgetErr := false
	foundUpstreamErr := false
	for _, e := range valResp.Result.Errors {
		if e.Code == "MAX_AMOUNT_EXCEEDS_ROLLING_BUDGET" {
			foundBudgetErr = true
		}
		if e.Code == "INVALID_UPSTREAM_URL" {
			foundUpstreamErr = true
		}
	}
	if !foundBudgetErr {
		t.Errorf("expected MAX_AMOUNT_EXCEEDS_ROLLING_BUDGET error, got: %+v", valResp.Result.Errors)
	}
	if !foundUpstreamErr {
		t.Errorf("expected INVALID_UPSTREAM_URL error, got: %+v", valResp.Result.Errors)
	}

	// 5. Check Draft Diff
	req = httptest.NewRequest(http.MethodGet, "/api/v1/tenants/"+tenant.TenantID+"/config/draft/diff", nil)
	req.Header.Set("Authorization", "Bearer "+ownerToken)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for draft diff, got %d", w.Code)
	}

	var diffResp struct {
		Diff *ConfigDraftDiff `json:"diff"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &diffResp)
	if diffResp.Diff == nil || !diffResp.Diff.HasChanges {
		t.Fatalf("expected diff to report pending changes")
	}
	if len(diffResp.Diff.RouteDiffs) != 1 {
		t.Errorf("expected 1 route diff, got %d", len(diffResp.Diff.RouteDiffs))
	}
	if len(diffResp.Diff.PolicyDiffs) != 1 {
		t.Errorf("expected 1 policy diff, got %d", len(diffResp.Diff.PolicyDiffs))
	}
}
