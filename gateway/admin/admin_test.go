package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/open-agentpay/agent-core-sdk/gateway/agent"
	"github.com/open-agentpay/agent-core-sdk/gateway/auth"
	"github.com/open-agentpay/agent-core-sdk/gateway/wallet"
)

func setupTestService() (*MemoryService, *agent.Registry, wallet.Service) {
	reg := agent.NewRegistry()
	wlt := wallet.NewMemoryService()
	svc := NewMemoryService(reg, wlt)
	return svc, reg, wlt
}

func TestTenantAndProjectLifecycle(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := setupTestService()

	// 1. Create Tenant with Owner
	tenant, owner, err := svc.CreateTenant(ctx, "Acme Corp", "ten_acme", "owner@acme.com")
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}
	if tenant.Name != "Acme Corp" || owner.Role != RoleOwner {
		t.Fatalf("unexpected tenant/owner: %+v, %+v", tenant, owner)
	}

	// Duplicate tenant rejected
	_, _, err = svc.CreateTenant(ctx, "Acme Corp", "", "other@acme.com")
	if err != ErrTenantAlreadyExists {
		t.Fatalf("expected ErrTenantAlreadyExists, got %v", err)
	}

	// Empty actorMemberID must be rejected
	_, err = svc.CreateProject(ctx, tenant.TenantID, "Unauthorized Project", nil, 50000000, "prj_unauth", "")
	if err != ErrPermissionDenied {
		t.Fatalf("expected ErrPermissionDenied for empty actorMemberID, got %v", err)
	}

	// 2. Create Project
	proj, err := svc.CreateProject(ctx, tenant.TenantID, "Project X", nil, 50000000, "prj_x", owner.MemberID)
	if err != nil {
		t.Fatalf("failed to create project: %v", err)
	}
	if proj.Name != "Project X" || proj.BudgetCapBaseUnits != 50000000 {
		t.Fatalf("unexpected project: %+v", proj)
	}

	// Duplicate project in same tenant rejected
	_, err = svc.CreateProject(ctx, tenant.TenantID, "Project X", nil, 0, "", owner.MemberID)
	if err != ErrProjectAlreadyExists {
		t.Fatalf("expected ErrProjectAlreadyExists, got %v", err)
	}

	// 3. Update & Delete Project
	newCap := int64(100000000)
	updatedProj, err := svc.UpdateProject(ctx, tenant.TenantID, proj.ProjectID, "Project X Renamed", nil, &newCap, nil, owner.MemberID)
	if err != nil {
		t.Fatalf("failed to update project: %v", err)
	}
	if updatedProj.Name != "Project X Renamed" || updatedProj.BudgetCapBaseUnits != 100000000 {
		t.Fatalf("unexpected updated project: %+v", updatedProj)
	}

	err = svc.DeleteProject(ctx, tenant.TenantID, proj.ProjectID, owner.MemberID)
	if err != nil {
		t.Fatalf("failed to delete project: %v", err)
	}

	_, err = svc.GetProject(ctx, tenant.TenantID, proj.ProjectID)
	if err != ErrProjectNotFound {
		t.Fatalf("expected ErrProjectNotFound, got %v", err)
	}
}

func TestMemberRBACAndLastOwnerProtection(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := setupTestService()

	tenant, owner, _ := svc.CreateTenant(ctx, "Security Org", "ten_sec", "owner@sec.com")

	// Add Admin, Operator, Viewer
	admin, err := svc.AddMember(ctx, tenant.TenantID, "admin@sec.com", RoleAdmin, owner.MemberID)
	if err != nil {
		t.Fatalf("failed to add admin: %v", err)
	}
	viewer, err := svc.AddMember(ctx, tenant.TenantID, "viewer@sec.com", RoleViewer, owner.MemberID)
	if err != nil {
		t.Fatalf("failed to add viewer: %v", err)
	}

	// Viewer cannot add members
	_, err = svc.AddMember(ctx, tenant.TenantID, "hack@sec.com", RoleOperator, viewer.MemberID)
	if err != ErrPermissionDenied {
		t.Fatalf("expected ErrPermissionDenied for viewer, got %v", err)
	}

	// Last active Owner cannot be removed
	err = svc.RemoveMember(ctx, tenant.TenantID, owner.MemberID, admin.MemberID)
	if err != ErrCannotRemoveLastOwner {
		t.Fatalf("expected ErrCannotRemoveLastOwner, got %v", err)
	}

	// Last active Owner cannot be demoted
	demoteRole := RoleAdmin
	_, err = svc.UpdateMember(ctx, tenant.TenantID, owner.MemberID, &demoteRole, nil, admin.MemberID)
	if err != ErrCannotDemoteLastOwner {
		t.Fatalf("expected ErrCannotDemoteLastOwner, got %v", err)
	}
}

func TestAgentLifecycleAndKillSwitchFastPath(t *testing.T) {
	ctx := context.Background()
	svc, reg, _ := setupTestService()

	tenant, owner, _ := svc.CreateTenant(ctx, "Agent Corp", "ten_agent", "owner@agent.com")
	proj, _ := svc.CreateProject(ctx, tenant.TenantID, "Bot Project", nil, 0, "prj_bot", owner.MemberID)

	// 1. Create Agent
	ag, err := svc.CreateAgent(ctx, tenant.TenantID, proj.ProjectID, "TradingBot", map[string]interface{}{
		"budget_limit": 50000000,
	}, owner.MemberID)
	if err != nil {
		t.Fatalf("failed to create agent: %v", err)
	}
	if ag.Status != AgentStatusActive {
		t.Fatalf("expected status active, got %s", ag.Status)
	}

	// Check registry registration in Go data plane
	resIdentity, _, err := reg.ResolveAPIKey("any_key")
	_ = resIdentity // should not resolve yet since no key bound

	// 2. Issue 2 API Keys
	keyRes1, err := svc.CreateAPIKey(ctx, tenant.TenantID, proj.ProjectID, ag.AgentID, "Key 1", nil, nil, owner.MemberID)
	if err != nil {
		t.Fatalf("failed to create api key: %v", err)
	}
	keyRes2, err := svc.CreateAPIKey(ctx, tenant.TenantID, proj.ProjectID, ag.AgentID, "Key 2", nil, nil, owner.MemberID)
	if err != nil {
		t.Fatalf("failed to create api key 2: %v", err)
	}
	_ = keyRes2

	// Verify key resolves to agent in Go registry
	resolvedAg, _, err := reg.ResolveAPIKey(keyRes1.RawKey)
	if err != nil || resolvedAg.AgentID != ag.AgentID {
		t.Fatalf("failed to resolve agent from raw key in registry: %v", err)
	}

	// 3. Kill Switch: Missing reason fails
	_, _, err = svc.KillAgent(ctx, tenant.TenantID, ag.AgentID, "", owner.MemberID, false, "127.0.0.1")
	if err != ErrMissingReason {
		t.Fatalf("expected ErrMissingReason, got %v", err)
	}

	// 4. Execute Kill Switch (Suspend)
	killedAg, revokedKeys, err := svc.KillAgent(ctx, tenant.TenantID, ag.AgentID, "Emergency pause due to volatility", owner.MemberID, false, "10.0.0.1")
	if err != nil {
		t.Fatalf("failed to kill agent: %v", err)
	}
	if killedAg.Status != AgentStatusSuspended {
		t.Fatalf("expected agent status suspended, got %s", killedAg.Status)
	}
	if len(revokedKeys) != 2 {
		t.Fatalf("expected 2 revoked keys, got %d", len(revokedKeys))
	}

	// Verify Go data plane registry is immediately suspended (nanosecond latency)
	resolvedAg, _, _ = reg.ResolveAPIKey(keyRes1.RawKey)
	if resolvedAg.Status != agent.AgentStatusSuspended {
		t.Fatalf("expected registry status suspended, got %s", resolvedAg.Status)
	}

	// Check audit log
	audits, _ := svc.ListAuditEvents(ctx, tenant.TenantID, "Agent", ag.AgentID, 10)
	if len(audits) == 0 || audits[0].Action != "agent.control" {
		t.Fatalf("expected agent.control audit event, got %+v", audits)
	}
	if audits[0].AfterState["reason"] != "Emergency pause due to volatility" {
		t.Fatalf("audit event reason mismatch: %+v", audits[0].AfterState)
	}

	// 5. Permanent Revocation
	revokedAg, _, err := svc.KillAgent(ctx, tenant.TenantID, ag.AgentID, "Decommissioned permanently", owner.MemberID, true, "10.0.0.1")
	if err != nil {
		t.Fatalf("failed to revoke agent: %v", err)
	}
	if revokedAg.Status != AgentStatusRevoked {
		t.Fatalf("expected agent status revoked, got %s", revokedAg.Status)
	}

	// Revoked agent cannot be updated back to active
	_, err = svc.UpdateAgentStatus(ctx, tenant.TenantID, ag.AgentID, AgentStatusActive, owner.MemberID)
	if err != ErrInvalidStatusTransition {
		t.Fatalf("expected ErrInvalidStatusTransition, got %v", err)
	}
}

func TestVirtualWalletAdminAndLedger(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := setupTestService()

	tenant, owner, _ := svc.CreateTenant(ctx, "Finance Org", "ten_fin", "owner@fin.com")

	wlt, err := svc.GetWallet(ctx, tenant.TenantID)
	if err != nil {
		t.Fatalf("failed to get master wallet: %v", err)
	}
	if wlt.AvailableCache != 0 {
		t.Fatalf("expected 0 balance, got %d", wlt.AvailableCache)
	}

	// 0. Unauthorized role (Viewer) or empty actorMemberID rejection
	viewer, err := svc.AddMember(ctx, tenant.TenantID, "viewer@ledger.com", RoleViewer, owner.MemberID)
	if err != nil {
		t.Fatalf("failed to add viewer: %v", err)
	}
	err = svc.AdminGrantWallet(ctx, tenant.TenantID, 1000000, "Unauthorized grant", "bad_01", viewer.MemberID, "127.0.0.1")
	if err != ErrPermissionDenied {
		t.Fatalf("expected ErrPermissionDenied for viewer grant, got %v", err)
	}
	err = svc.AdjustWallet(ctx, wlt.WalletID, 1000000, "Unauthorized adjust", "bad_02", viewer.MemberID, "127.0.0.1")
	if err != ErrPermissionDenied {
		t.Fatalf("expected ErrPermissionDenied for viewer adjust, got %v", err)
	}
	err = svc.AdjustWallet(ctx, wlt.WalletID, 1000000, "Anonymous adjust", "bad_03", "", "127.0.0.1")
	if err != ErrPermissionDenied {
		t.Fatalf("expected ErrPermissionDenied for empty actorMemberID adjust, got %v", err)
	}

	// 1. Admin grant with reason (Owner succeeds)
	err = svc.AdminGrantWallet(ctx, tenant.TenantID, 50000000, "Initial pilot credit", "grant_01", owner.MemberID, "127.0.0.1")
	if err != nil {
		t.Fatalf("failed to admin grant: %v", err)
	}

	wlt, _ = svc.GetWallet(ctx, tenant.TenantID)
	if wlt.AvailableCache != 50000000 {
		t.Fatalf("expected 50_000_000 balance, got %d", wlt.AvailableCache)
	}

	// 2. Adjust wallet
	err = svc.AdjustWallet(ctx, wlt.WalletID, -10000000, "Correction adjustment", "adj_01", owner.MemberID, "127.0.0.1")
	if err != nil {
		t.Fatalf("failed to adjust wallet: %v", err)
	}
	wlt, _ = svc.GetWallet(ctx, tenant.TenantID)
	if wlt.AvailableCache != 40000000 {
		t.Fatalf("expected 40_000_000 balance, got %d", wlt.AvailableCache)
	}

	// 3. Freeze & Unfreeze
	err = svc.FreezeWallet(ctx, wlt.WalletID, "Security audit freeze", owner.MemberID, "127.0.0.1")
	if err != nil {
		t.Fatalf("failed to freeze wallet: %v", err)
	}
	wlt, _ = svc.GetWallet(ctx, tenant.TenantID)
	if wlt.Status != wallet.StatusFrozen {
		t.Fatalf("expected frozen status, got %s", wlt.Status)
	}

	err = svc.UnfreezeWallet(ctx, wlt.WalletID, "Audit cleared", owner.MemberID, "127.0.0.1")
	if err != nil {
		t.Fatalf("failed to unfreeze wallet: %v", err)
	}
	wlt, _ = svc.GetWallet(ctx, tenant.TenantID)
	if wlt.Status != wallet.StatusActive {
		t.Fatalf("expected active status, got %s", wlt.Status)
	}

	// 4. Recalculate & Ledger
	rep, err := svc.RecalculateWallet(ctx, wlt.WalletID, owner.MemberID)
	if err != nil {
		t.Fatalf("failed to recalculate: %v", err)
	}
	if rep["consistent"] != true {
		t.Fatalf("expected consistent ledger reconciliation, got %+v", rep)
	}
}

func TestControlPlaneRESTAPI(t *testing.T) {
	svc, _, _ := setupTestService()
	jwtMgr := auth.MustNewJWTManager("test-admin-secret-key-for-unit-testing-32b!", 24*time.Hour)
	handler := NewHandlerWithJWT(svc, jwtMgr)

	// 1. POST /api/v1/auth/register
	regBody, _ := json.Marshal(map[string]interface{}{
		"tenant_name": "API Org",
		"email":       "api_owner@org.com",
		"password":    "Password123!",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(regBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("failed to register tenant via REST: status %d, body: %s", rec.Code, rec.Body.String())
	}
	var regResp struct {
		Token  string  `json:"token"`
		Tenant *Tenant `json:"tenant"`
		User   *Member `json:"user"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&regResp); err != nil {
		t.Fatalf("failed to decode register response: %v", err)
	}
	if regResp.Tenant == nil || regResp.User == nil || regResp.Token == "" {
		t.Fatalf("nil tenant, user, or token in response: %+v", regResp)
	}
	tID := regResp.Tenant.TenantID
	ownerToken := regResp.Token

	// 2. POST /api/v1/tenants/{tenant_id}/projects
	pBody, _ := json.Marshal(map[string]interface{}{
		"name": "API Project",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/tenants/"+tID+"/projects", bytes.NewReader(pBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+ownerToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("failed to create project via REST: status %d, body: %s", rec.Code, rec.Body.String())
	}
	var pResp struct {
		Project *Project `json:"project"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&pResp)
	pID := pResp.Project.ProjectID

	// 3. POST /api/v1/tenants/{tenant_id}/agents
	agBody, _ := json.Marshal(map[string]interface{}{
		"project_id": pID,
		"name":       "APIAgent",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/tenants/"+tID+"/agents", bytes.NewReader(agBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+ownerToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("failed to create agent via REST: status %d, body: %s", rec.Code, rec.Body.String())
	}
	var agResp struct {
		Agent *Agent `json:"agent"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&agResp)
	agID := agResp.Agent.AgentID

	// 4. POST /api/v1/tenants/{tenant_id}/agents/{agent_id}/kill without reason -> 400
	killBodyNoReason, _ := json.Marshal(map[string]interface{}{
		"reason": "",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/tenants/"+tID+"/agents/"+agID+"/kill", bytes.NewReader(killBodyNoReason))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+ownerToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty reason, got %d", rec.Code)
	}

	// 5. POST /api/v1/agents/{agent_id}/kill (flat route) with reason -> 200
	killBody, _ := json.Marshal(map[string]interface{}{
		"reason": "REST Kill invoked",
		"revoke": false,
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/agents/"+agID+"/kill", bytes.NewReader(killBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+ownerToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for flat kill, got %d, body: %s", rec.Code, rec.Body.String())
	}
	var killResp struct {
		Killed bool        `json:"killed"`
		Status AgentStatus `json:"status"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&killResp)
	if !killResp.Killed || killResp.Status != AgentStatusSuspended {
		t.Fatalf("unexpected kill response: %+v", killResp)
	}

	// 6. GET /api/v1/audit/events
	req = httptest.NewRequest(http.MethodGet, "/api/v1/audit/events?tenant_id="+tID, nil)
	req.Header.Set("Authorization", "Bearer "+ownerToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("failed to get audit events via REST: status %d, body: %s", rec.Code, rec.Body.String())
	}
	var auditResp struct {
		Count int `json:"count"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&auditResp)
	if auditResp.Count < 3 {
		t.Fatalf("expected at least 3 audit events, got %d", auditResp.Count)
	}
}
