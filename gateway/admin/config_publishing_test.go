package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/open-agentpay/agent-core-sdk/gateway/auth"
	"github.com/open-agentpay/agent-core-sdk/gateway/rcu"
)

func TestConfigPublishingAndRollback(t *testing.T) {
	ctx := context.Background()
	svc := NewMemoryService(nil, nil)

	// Set up RCU Manager
	initialSnap := &rcu.ConfigSnapshot{
		SchemaVersion: "2.0.0",
		TenantID:      "ten_test001",
		VersionID:     "ver_init",
		VersionNumber: 0,
		Routes:        []rcu.RouteConfig{},
		Policies:      []rcu.PolicyConfig{},
	}
	rcuMgr, err := rcu.NewManager(initialSnap)
	if err != nil {
		t.Fatalf("failed to create rcu manager: %v", err)
	}
	svc.SetRCUManager(rcuMgr)

	jwtMgr := auth.MustNewJWTManager("test-admin-secret-key-for-unit-testing-32b!", 24*time.Hour)
	handler := NewHandlerWithJWT(svc, jwtMgr)

	// 1. Create Tenant & Owner Member
	tenant, owner, err := svc.Register(ctx, "AlphaCorp", "owner@alpha.io", "Password123!")
	if err != nil {
		t.Fatalf("failed to register tenant: %v", err)
	}
	tenantID := tenant.TenantID
	ownerID := owner.MemberID
	ownerToken, _ := jwtMgr.GenerateToken(owner.MemberID, owner.Email, tenantID, string(owner.Role))

	// Create a Viewer Member for RBAC checks
	viewer, err := svc.AddMember(ctx, tenantID, "viewer@alpha.io", RoleViewer, ownerID)
	if err != nil {
		t.Fatalf("failed to create viewer member: %v", err)
	}
	viewerToken, _ := jwtMgr.GenerateToken(viewer.MemberID, viewer.Email, tenantID, string(viewer.Role))

	// 2. Create Project and a valid Route & Policy
	proj, err := svc.CreateProject(ctx, tenantID, "AI Engine", 1000000, "", ownerID)
	if err != nil {
		t.Fatalf("failed to create project: %v", err)
	}

	route1, err := svc.CreateRoute(ctx, &Route{
		TenantID:              tenantID,
		ProjectID:             proj.ProjectID,
		PathPattern:           "/v1/chat/completions",
		UpstreamURL:           "https://upstream.llm.provider/v1/chat",
		PriceBaseUnits:        1000,
		Asset:                 "USDC",
		PayeeAddress:          "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		AllowedPaymentMethods: "both",
		TimeoutMs:             15000,
		RateLimitRPM:          300,
		Status:                RouteStatusActive,
	}, ownerID)
	if err != nil {
		t.Fatalf("failed to create route: %v", err)
	}

	_, err = svc.CreatePolicy(ctx, &Policy{
		TenantID:             tenantID,
		ProjectID:            proj.ProjectID,
		RouteID:              route1.RouteID,
		MaxAmountPerRequest:  50000,
		Rolling24hBudgetCap:  500000,
		CircuitBreakerMaxRPM: 60,
		WhitelistedNetworks:  []string{"eip155:42161"},
		IsActive:             true,
	}, ownerID)
	if err != nil {
		t.Fatalf("failed to create policy: %v", err)
	}

	// 3. Test RBAC: Viewer cannot publish configuration
	{
		pubPayload := `{"change_summary": "Initial release"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/"+tenantID+"/config/publish", bytes.NewReader([]byte(pubPayload)))
		req.Header.Set("Authorization", "Bearer "+viewerToken)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden for viewer publish, got %d", w.Code)
		}
	}

	// 4. Test Valid Publish -> Version 1
	var v1ID, v1Hash string
	{
		pubPayload := `{"change_summary": "Release v1: Chat completions route"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/"+tenantID+"/config/publish", bytes.NewReader([]byte(pubPayload)))
		req.Header.Set("Authorization", "Bearer "+ownerToken)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for publish, got %d: %s", w.Code, w.Body.String())
		}

		var resp struct {
			Version ConfigVersion `json:"version"`
		}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("decode publish response: %v", err)
		}

		v := resp.Version
		if v.VersionNumber != 1 {
			t.Errorf("expected version_number 1, got %d", v.VersionNumber)
		}
		if !v.IsActive {
			t.Errorf("expected is_active true for newly published version")
		}
		if !strings.HasPrefix(v.SnapshotHash, "sha256:") {
			t.Errorf("expected snapshot_hash prefix sha256:, got %s", v.SnapshotHash)
		}
		if len(v.SnapshotHash) != 7+64 {
			t.Errorf("expected snapshot_hash length 71, got %d", len(v.SnapshotHash))
		}
		if v.RoutesCount != 1 || v.PoliciesCount != 1 {
			t.Errorf("expected routes_count=1, policies_count=1, got %d / %d", v.RoutesCount, v.PoliciesCount)
		}

		v1ID = v.VersionID
		v1Hash = v.SnapshotHash

		// Verify Gateway RCU instant hot swap
		activeSnap := rcuMgr.Current()
		if activeSnap == nil || activeSnap.VersionID != v1ID {
			t.Errorf("expected gateway RCU to be updated to v1ID %s, got %v", v1ID, activeSnap)
		}
	}

	// 5. Test Static Validation Gate blocks publishing when draft contains invalid configuration
	badRoute, err := svc.CreateRoute(ctx, &Route{
		TenantID:              tenantID,
		ProjectID:             proj.ProjectID,
		PathPattern:           "/v1/embeddings",
		UpstreamURL:           "ftp://bad.scheme.internal", // Invalid URI scheme!
		PriceBaseUnits:        500,
		Asset:                 "USDC",
		AllowedPaymentMethods: "wallet",
		TimeoutMs:             5000,
		RateLimitRPM:          100,
		Status:                RouteStatusActive,
	}, ownerID)
	if err != nil {
		t.Fatalf("failed to create route: %v", err)
	}

	{
		pubPayload := `{"change_summary": "Attempt invalid release"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/"+tenantID+"/config/publish", bytes.NewReader([]byte(pubPayload)))
		req.Header.Set("Authorization", "Bearer "+ownerToken)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusUnprocessableEntity {
			t.Fatalf("expected 422 Unprocessable Entity for invalid publish, got %d: %s", w.Code, w.Body.String())
		}

		// Ensure active version remains v1
		activeSnap := rcuMgr.Current()
		if activeSnap == nil || activeSnap.VersionID != v1ID {
			t.Errorf("expected gateway RCU to remain on v1ID %s after blocked publish", v1ID)
		}
	}

	// 6. Fix the bad route and publish Version 2
	_, err = svc.UpdateRoute(ctx, &UpdateRouteInput{
		TenantID:    tenantID,
		RouteID:     badRoute.RouteID,
		UpstreamURL: func(s string) *string { return &s }("https://valid.llm.provider/v1/embeddings"),
	}, ownerID)
	if err != nil {
		t.Fatalf("failed to update route: %v", err)
	}

	var v2ID, v2Hash string
	{
		pubPayload := `{"change_summary": "Release v2: Add embeddings route"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/"+tenantID+"/config/publish", bytes.NewReader([]byte(pubPayload)))
		req.Header.Set("Authorization", "Bearer "+ownerToken)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for valid publish v2, got %d: %s", w.Code, w.Body.String())
		}

		var resp struct {
			Version ConfigVersion `json:"version"`
		}
		_ = json.NewDecoder(w.Body).Decode(&resp)

		v := resp.Version
		if v.VersionNumber != 2 {
			t.Errorf("expected version_number 2, got %d", v.VersionNumber)
		}
		if !v.IsActive {
			t.Errorf("expected is_active true for v2")
		}
		if v.RoutesCount != 2 {
			t.Errorf("expected routes_count=2, got %d", v.RoutesCount)
		}

		v2ID = v.VersionID
		v2Hash = v.SnapshotHash

		// Check previous v1 is no longer active
		v1Ver, err := svc.GetConfigVersion(ctx, tenantID, v1ID)
		if err != nil || v1Ver.IsActive {
			t.Errorf("expected v1 is_active=false, got err=%v, is_active=%v", err, v1Ver.IsActive)
		}
	}

	// 7. Test List Config Versions (Descending order)
	{
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/"+tenantID+"/config/versions", nil)
		req.Header.Set("Authorization", "Bearer "+ownerToken)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for list versions, got %d: %s", w.Code, w.Body.String())
		}

		var resp struct {
			Versions []*ConfigVersion `json:"versions"`
		}
		_ = json.NewDecoder(w.Body).Decode(&resp)

		if len(resp.Versions) != 2 {
			t.Fatalf("expected 2 versions in list, got %d", len(resp.Versions))
		}
		if resp.Versions[0].VersionID != v2ID || resp.Versions[1].VersionID != v1ID {
			t.Errorf("expected versions sorted [v2, v1], got [%s, %s]", resp.Versions[0].VersionID, resp.Versions[1].VersionID)
		}
	}

	// 8. Test Version Diff between v1 and v2
	{
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/"+tenantID+"/config/versions/diff?base="+v1ID+"&target="+v2ID, nil)
		req.Header.Set("Authorization", "Bearer "+ownerToken)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for version diff, got %d: %s", w.Code, w.Body.String())
		}

		var resp struct {
			Diff ConfigDraftDiff `json:"diff"`
		}
		_ = json.NewDecoder(w.Body).Decode(&resp)

		if !resp.Diff.HasChanges {
			t.Errorf("expected diff between v1 and v2 to have changes")
		}
		if len(resp.Diff.RouteDiffs) == 0 {
			t.Errorf("expected route diffs between v1 and v2")
		}
	}

	// 9. Test Rollback to v1 (TC_CFG_04_ROLLBACK_INTEGRITY)
	// Must produce new version v3 with identical snapshotHash as v1!
	{
		rollbackPayload := `{"target_version_id": "` + v1ID + `", "reason": "Incident mitigation"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/"+tenantID+"/config/rollback", bytes.NewReader([]byte(rollbackPayload)))
		req.Header.Set("Authorization", "Bearer "+ownerToken)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for rollback, got %d: %s", w.Code, w.Body.String())
		}

		var resp struct {
			Version ConfigVersion `json:"version"`
		}
		_ = json.NewDecoder(w.Body).Decode(&resp)

		v3 := resp.Version
		if v3.VersionNumber != 3 {
			t.Errorf("expected version_number 3 after rollback, got %d", v3.VersionNumber)
		}
		if !v3.IsActive {
			t.Errorf("expected v3 is_active=true")
		}
		// Critical Contract: active_hash must equal v1Hash!
		if v3.SnapshotHash != v1Hash {
			t.Errorf("expected rollback snapshotHash %s to match v1Hash %s", v3.SnapshotHash, v1Hash)
		}
		if v3.SnapshotHash == v2Hash {
			t.Errorf("rollback snapshotHash should differ from v2Hash")
		}
		if v3.RoutesCount != 1 {
			t.Errorf("expected 1 route in restored v3, got %d", v3.RoutesCount)
		}

		// Verify Gateway RCU instantly switched to v3
		activeSnap := rcuMgr.Current()
		if activeSnap == nil || activeSnap.VersionID != v3.VersionID {
			t.Errorf("expected gateway RCU to be updated to v3 %s, got %v", v3.VersionID, activeSnap)
		}
	}

	// 10. Cannot rollback to currently active version
	{
		// Try rolling back to the active version (v3)
		activeSnap := rcuMgr.Current()
		rollbackPayload := `{"target_version_id": "` + activeSnap.VersionID + `"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/"+tenantID+"/config/rollback", bytes.NewReader([]byte(rollbackPayload)))
		req.Header.Set("Authorization", "Bearer "+ownerToken)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request when rolling back to active version, got %d", w.Code)
		}
	}
}
