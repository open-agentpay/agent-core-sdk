package admin

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/open-agentpay/agent-core-sdk/gateway/auth"
	"github.com/open-agentpay/agent-core-sdk/gateway/payment"
	"github.com/open-agentpay/agent-core-sdk/gateway/timeline"
	"github.com/open-agentpay/agent-core-sdk/gateway/upstreamauth"
	"github.com/open-agentpay/agent-core-sdk/gateway/usage"
	"github.com/open-agentpay/agent-core-sdk/gateway/wallet"
)

// APIHandler dispatches control plane requests.
type APIHandler struct {
	svc                 Service
	jwtMgr              *auth.JWTManager
	subresourceHandlers map[string]http.Handler
}

// RegisterSubresource registers an extension HTTP handler for a tenant subresource (e.g. /api/v1/tenants/{id}/<name>).
func (h *APIHandler) RegisterSubresource(name string, handler http.Handler) {
	if h.subresourceHandlers == nil {
		h.subresourceHandlers = make(map[string]http.Handler)
	}
	h.subresourceHandlers[name] = handler
}

// NewHandler creates a new HTTP handler for control plane REST API with a test JWT manager.
// For production, use NewHandlerWithJWT with an explicitly configured JWT manager.
func NewHandler(svc Service) http.Handler {
	return NewHandlerWithJWT(svc, auth.MustNewJWTManager("test-admin-secret-key-for-unit-testing-32b!", 24*time.Hour))
}

// NewHandlerWithJWT creates a new HTTP handler for control plane REST API with explicit JWT manager.
func NewHandlerWithJWT(svc Service, jwtMgr *auth.JWTManager) http.Handler {
	if jwtMgr == nil {
		panic("admin.NewHandlerWithJWT: jwtMgr cannot be nil")
	}
	return &APIHandler{svc: svc, jwtMgr: jwtMgr}
}

// authenticateRequest extracts and validates JWT claims if not already injected by auth.Middleware.
// Client-supplied X-Actor-Member-Id and X-Tenant-Id headers are NEVER trusted.
// # SECURITY-REVIEW
func (h *APIHandler) authenticateRequest(r *http.Request) (*http.Request, error) {
	if auth.GetClaims(r.Context()) != nil {
		return r, nil
	}
	auth.StripUntrustedIdentityHeaders(r.Header)
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		tokenStr := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		claims, err := h.jwtMgr.ValidateToken(tokenStr)
		if err != nil {
			return r, err
		}
		ctx := auth.WithClaims(r.Context(), claims)
		r = r.WithContext(ctx)
		r.Header.Set("X-Actor-Member-Id", claims.Subject)
		r.Header.Set("X-Tenant-Id", claims.TenantID)
	}
	return r, nil
}

func (h *APIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimRight(r.URL.Path, "/")
	clientIP := r.RemoteAddr
	if hostPort := strings.TrimSpace(r.RemoteAddr); hostPort != "" {
		clientIP = hostPort
	}

	// 1. Public unauthenticated endpoints
	switch {
	case strings.HasPrefix(path, "/api/v1/public/marketplace"):
		NewPublicMarketplaceHandler(h.svc).ServeHTTP(w, r)
		return
	case path == "/api/v1/auth-types" && r.Method == http.MethodGet:
		h.writeJSON(w, http.StatusOK, map[string]interface{}{"types": h.svc.GetAuthTypes()})
		return
	case (path == "/api/v1/auth/register" || path == "/api/v1/auth/login") && r.Method == http.MethodPost:
		h.handleAuth(w, r, path, "", "")
		return
	}

	// 2. All other control-plane routes require a valid JWT token
	r, err := h.authenticateRequest(r)
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "ERR_UNAUTHORIZED", err.Error())
		return
	}

	actorMemberID := auth.GetMemberID(r.Context())
	authTenantID := auth.GetTenantID(r.Context())
	if actorMemberID == "" || authTenantID == "" {
		h.writeError(w, http.StatusUnauthorized, "ERR_UNAUTHORIZED", "authentication required")
		return
	}

	actorMember, err := h.svc.GetMember(r.Context(), authTenantID, actorMemberID)
	if err != nil || actorMember == nil {
		h.writeError(w, http.StatusUnauthorized, "ERR_UNAUTHORIZED", "invalid or unknown authenticated member")
		return
	}
	if actorMember.Status != MemberStatusActive {
		h.writeError(w, http.StatusForbidden, "ERR_PERMISSION_DENIED", ErrMemberDisabled.Error())
		return
	}

	switch {
	case strings.HasPrefix(path, "/api/v1/auth/"):
		h.handleAuth(w, r, path, actorMemberID, authTenantID)
	case path == "/api/v1/audit/events" && r.Method == http.MethodGet:
		h.handleAuditEvents(w, r, actorMember, authTenantID)
	case strings.HasPrefix(path, "/api/v1/agents/"):
		parts := strings.Split(strings.TrimPrefix(path, "/api/v1/agents/"), "/")
		if h.handleAgentSubpath(w, r, authTenantID, actorMemberID, actorMember, clientIP, parts) {
			return
		}
		http.NotFound(w, r)
	case strings.HasPrefix(path, "/api/v1/wallets/"):
		parts := strings.Split(strings.TrimPrefix(path, "/api/v1/wallets/"), "/")
		if h.handleFlatWalletSubpath(w, r, authTenantID, actorMemberID, actorMember, clientIP, parts) {
			return
		}
		http.NotFound(w, r)
	case path == "/api/v1/tenants":
		if h.handleTenantsRoot(w, r, authTenantID, actorMember) {
			return
		}
		http.NotFound(w, r)
	case strings.HasPrefix(path, "/api/v1/tenants/"):
		parts := strings.Split(strings.TrimPrefix(path, "/api/v1/tenants/"), "/")
		if h.handleTenantScoped(w, r, authTenantID, actorMemberID, actorMember, clientIP, parts) {
			return
		}
		http.NotFound(w, r)
	default:
		http.NotFound(w, r)
	}
}

// ----------------------------------------------------------------------------
// 0. Auth & Audit Endpoints
// ----------------------------------------------------------------------------

func (h *APIHandler) handleAuth(w http.ResponseWriter, r *http.Request, path, actorMemberID, authTenantID string) {
	switch {
	case path == "/api/v1/auth/register" && r.Method == http.MethodPost:
		var body struct {
			TenantName string `json:"tenant_name"`
			Email      string `json:"email"`
			Password   string `json:"password"`
			Currency   string `json:"currency"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			h.writeError(w, http.StatusBadRequest, "ERR_INVALID_JSON", "invalid request body")
			return
		}
		tenant, member, err := h.svc.Register(r.Context(), body.TenantName, body.Email, body.Password, body.Currency)
		if err != nil {
			h.handleError(w, err)
			return
		}
		token, err := h.jwtMgr.GenerateToken(member.MemberID, member.Email, tenant.TenantID, string(member.Role))
		if err != nil {
			h.handleError(w, err)
			return
		}
		h.writeJSON(w, http.StatusCreated, map[string]interface{}{
			"token":  token,
			"user":   member,
			"tenant": tenant,
		})

	case path == "/api/v1/auth/login" && r.Method == http.MethodPost:
		var body struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			h.writeError(w, http.StatusBadRequest, "ERR_INVALID_JSON", "invalid request body")
			return
		}
		member, tenant, err := h.svc.Login(r.Context(), body.Email, body.Password)
		if err != nil {
			h.handleError(w, err)
			return
		}
		token, err := h.jwtMgr.GenerateToken(member.MemberID, member.Email, tenant.TenantID, string(member.Role))
		if err != nil {
			h.handleError(w, err)
			return
		}
		h.writeJSON(w, http.StatusOK, map[string]interface{}{
			"token":  token,
			"user":   member,
			"tenant": tenant,
		})

	case path == "/api/v1/auth/me" && r.Method == http.MethodGet:
		if actorMemberID == "" || authTenantID == "" {
			h.writeError(w, http.StatusUnauthorized, "ERR_UNAUTHORIZED", "unauthenticated user")
			return
		}
		member, err := h.svc.GetMember(r.Context(), authTenantID, actorMemberID)
		if err != nil {
			h.handleError(w, err)
			return
		}
		tenant, err := h.svc.GetTenant(r.Context(), member.TenantID)
		if err != nil {
			h.handleError(w, err)
			return
		}
		h.writeJSON(w, http.StatusOK, map[string]interface{}{
			"user":        member,
			"tenant":      tenant,
			"permissions": GetRolePermissions(member.Role),
		})

	case path == "/api/v1/auth/password" && r.Method == http.MethodPost:
		if actorMemberID == "" || authTenantID == "" {
			h.writeError(w, http.StatusUnauthorized, "ERR_UNAUTHORIZED", "unauthenticated user")
			return
		}
		var body struct {
			OldPassword string `json:"old_password"`
			NewPassword string `json:"new_password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			h.writeError(w, http.StatusBadRequest, "ERR_INVALID_JSON", "invalid request body")
			return
		}
		m, err := h.svc.GetMember(r.Context(), authTenantID, actorMemberID)
		if err != nil {
			h.handleError(w, err)
			return
		}
		if m.PasswordHash != "" && body.OldPassword != "" {
			if !auth.VerifyPassword(body.OldPassword, m.PasswordHash) {
				h.writeError(w, http.StatusUnauthorized, "ERR_INVALID_CREDENTIALS", "old password is incorrect")
				return
			}
		}
		if err := h.svc.SetMemberPassword(r.Context(), m.TenantID, m.MemberID, body.NewPassword); err != nil {
			h.handleError(w, err)
			return
		}
		h.writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})

	default:
		http.NotFound(w, r)
	}
}

func (h *APIHandler) handleAuditEvents(w http.ResponseWriter, r *http.Request, actorMember *Member, authTenantID string) {
	if err := EnforcePermission(actorMember, PermissionAuditRead); err != nil {
		h.handleError(w, err)
		return
	}
	q := r.URL.Query()
	tID := q.Get("tenant_id")
	if tID != "" && tID != authTenantID {
		h.handleError(w, ErrPermissionDenied)
		return
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	events, err := h.svc.ListAuditEvents(r.Context(), authTenantID, q.Get("target_type"), q.Get("target_id"), limit)
	if err != nil {
		h.handleError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]interface{}{"count": len(events), "items": events})
}

// ----------------------------------------------------------------------------
// 1. Agents & Flat Wallet Endpoints
// ----------------------------------------------------------------------------

// handleAgentSubpath handles operations under /{agent_id}[/kill|/status|/timeline]
// shared by both `/api/v1/agents/...` and `/api/v1/tenants/{tenant_id}/agents/...`.
func (h *APIHandler) handleAgentSubpath(
	w http.ResponseWriter,
	r *http.Request,
	tenantID, actorMemberID string,
	actorMember *Member,
	clientIP string,
	parts []string,
) bool {
	if len(parts) == 0 || parts[0] == "" {
		return false
	}
	agentID := parts[0]
	method := r.Method

	if len(parts) == 2 {
		switch parts[1] {
		case "kill":
			if method != http.MethodPost {
				return false
			}
			var body struct {
				Reason string `json:"reason"`
				Revoke bool   `json:"revoke"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			ag, keys, err := h.svc.KillAgent(r.Context(), tenantID, agentID, body.Reason, actorMemberID, body.Revoke, clientIP)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{
				"agent":        ag,
				"revoked_keys": keys,
				"killed":       true,
				"status":       ag.Status,
			})
			return true

		case "status":
			if method != http.MethodPost {
				return false
			}
			var body struct {
				Status string `json:"status"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			ag, err := h.svc.UpdateAgentStatus(r.Context(), tenantID, agentID, AgentStatus(body.Status), actorMemberID)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"agent": ag})
			return true

		case "timeline":
			if method != http.MethodGet {
				return false
			}
			h.handleAgentTimeline(w, r, tenantID, agentID, actorMemberID)
			return true
		}
		return false
	}

	if len(parts) == 1 {
		switch method {
		case http.MethodGet:
			if err := EnforcePermission(actorMember, PermissionAgentRead); err != nil {
				h.handleError(w, err)
				return true
			}
			ag, err := h.svc.GetAgent(r.Context(), tenantID, agentID)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"agent": ag})
			return true

		case http.MethodPatch:
			var body struct {
				Name         string                 `json:"name"`
				PolicyConfig map[string]interface{} `json:"policy_config"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			ag, err := h.svc.UpdateAgent(r.Context(), tenantID, agentID, body.Name, body.PolicyConfig, actorMemberID)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"agent": ag})
			return true

		case http.MethodDelete:
			if err := h.svc.DeleteAgent(r.Context(), tenantID, agentID, actorMemberID); err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"deleted": true, "agent_id": agentID})
			return true
		}
	}
	return false
}

func (h *APIHandler) handleFlatWalletSubpath(
	w http.ResponseWriter,
	r *http.Request,
	authTenantID, actorMemberID string,
	actorMember *Member,
	clientIP string,
	parts []string,
) bool {
	if len(parts) == 0 || parts[0] == "" {
		return false
	}
	walletID := parts[0]
	method := r.Method

	wlt, err := h.svc.GetWalletByID(r.Context(), walletID)
	if err != nil {
		h.handleError(w, err)
		return true
	}
	if wlt.TenantID != authTenantID {
		h.handleError(w, ErrPermissionDenied)
		return true
	}

	if len(parts) == 1 && method == http.MethodGet {
		if err := EnforcePermission(actorMember, PermissionWalletRead); err != nil {
			h.handleError(w, err)
			return true
		}
		h.writeJSON(w, http.StatusOK, map[string]interface{}{"wallet": wlt})
		return true
	}

	if len(parts) == 2 {
		switch parts[1] {
		case "adjust":
			if method != http.MethodPost {
				return false
			}
			h.writeError(w, http.StatusForbidden, "ERR_ENDPOINT_DISABLED", "Manual wallet adjustment API has been disabled.")
			return true

		case "freeze", "unfreeze":
			if method != http.MethodPost {
				return false
			}
			var body struct {
				Reason string `json:"reason"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			var err error
			if parts[1] == "freeze" {
				err = h.svc.FreezeWallet(r.Context(), walletID, body.Reason, actorMemberID, clientIP)
			} else {
				err = h.svc.UnfreezeWallet(r.Context(), walletID, body.Reason, actorMemberID, clientIP)
			}
			if err != nil {
				h.handleError(w, err)
				return true
			}
			wlt, _ := h.svc.GetWalletByID(r.Context(), walletID)
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"wallet": wlt})
			return true

		case "recalculate":
			if method != http.MethodPost {
				return false
			}
			report, err := h.svc.RecalculateWallet(r.Context(), walletID, actorMemberID)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"recalculation": report})
			return true

		case "ledger":
			if method != http.MethodGet {
				return false
			}
			if err := EnforcePermission(actorMember, PermissionWalletRead); err != nil {
				h.handleError(w, err)
				return true
			}
			entries, err := h.svc.GetLedgerEntries(r.Context(), walletID)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"count": len(entries), "items": entries})
			return true

		case "topups":
			if method != http.MethodGet {
				return false
			}
			if err := EnforcePermission(actorMember, PermissionWalletRead); err != nil {
				h.handleError(w, err)
				return true
			}
			orders, err := h.svc.GetTopUpOrders(r.Context(), walletID)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"count": len(orders), "items": orders})
			return true
		}
	}
	return false
}

// ----------------------------------------------------------------------------
// 2. Tenants & Scoped Sub-Resources (/api/v1/tenants/...)
// ----------------------------------------------------------------------------

func (h *APIHandler) handleTenantsRoot(w http.ResponseWriter, r *http.Request, authTenantID string, actorMember *Member) bool {
	switch r.Method {
	case http.MethodPost:
		if !auth.IsSystemContext(r.Context()) {
			h.handleError(w, ErrPermissionDenied)
			return true
		}
		var body struct {
			Name       string `json:"name"`
			TenantID   string `json:"tenant_id"`
			OwnerEmail string `json:"owner_email"`
			Currency   string `json:"currency"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			h.writeError(w, http.StatusBadRequest, "ERR_INVALID_PARAM", "malformed JSON body")
			return true
		}
		t, owner, err := h.svc.CreateTenant(r.Context(), body.Name, body.TenantID, body.OwnerEmail, body.Currency)
		if err != nil {
			h.handleError(w, err)
			return true
		}
		resp := map[string]interface{}{"tenant": t}
		if owner != nil {
			resp["owner"] = owner
		}
		h.writeJSON(w, http.StatusCreated, resp)
		return true

	case http.MethodGet:
		if err := EnforcePermission(actorMember, PermissionTenantRead); err != nil {
			h.handleError(w, err)
			return true
		}
		t, err := h.svc.GetTenant(r.Context(), authTenantID)
		if err != nil {
			h.handleError(w, err)
			return true
		}
		h.writeJSON(w, http.StatusOK, map[string]interface{}{"tenants": []*Tenant{t}})
		return true
	}
	return false
}

func (h *APIHandler) handleTenantScoped(
	w http.ResponseWriter,
	r *http.Request,
	authTenantID, actorMemberID string,
	actorMember *Member,
	clientIP string,
	parts []string,
) bool {
	if len(parts) == 0 || parts[0] == "" {
		return false
	}
	tenantID := parts[0]
	if tenantID != authTenantID {
		h.handleError(w, ErrPermissionDenied)
		return true
	}
	method := r.Method

	if len(parts) == 1 {
		switch method {
		case http.MethodGet:
			if err := EnforcePermission(actorMember, PermissionTenantRead); err != nil {
				h.handleError(w, err)
				return true
			}
			t, err := h.svc.GetTenant(r.Context(), tenantID)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"tenant": t})
			return true

		case http.MethodPatch:
			var body struct {
				Name     string `json:"name"`
				Currency string `json:"currency"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			var t *Tenant
			var err error
			if body.Currency != "" {
				t, err = h.svc.UpdateTenantCurrency(r.Context(), tenantID, body.Currency, actorMemberID)
				if err != nil {
					h.handleError(w, err)
					return true
				}
			}
			if body.Name != "" || body.Currency == "" {
				t, err = h.svc.UpdateTenant(r.Context(), tenantID, body.Name, actorMemberID)
				if err != nil {
					h.handleError(w, err)
					return true
				}
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"tenant": t})
			return true
		}
		return false
	}

	sub := parts[1]
	rest := parts[2:]

	if h.subresourceHandlers != nil {
		if subHandler, ok := h.subresourceHandlers[sub]; ok && subHandler != nil {
			subHandler.ServeHTTP(w, r)
			return true
		}
	}

	switch sub {
	case "currency":
		if len(rest) == 0 && (method == http.MethodPatch || method == http.MethodPost) {
			var body struct {
				Currency string `json:"currency"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			t, err := h.svc.UpdateTenantCurrency(r.Context(), tenantID, body.Currency, actorMemberID)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"tenant": t})
			return true
		}
	case "status":
		if len(rest) == 0 && method == http.MethodPost {
			var body struct {
				Status string `json:"status"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			t, err := h.svc.UpdateTenantStatus(r.Context(), tenantID, TenantStatus(body.Status), actorMemberID)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"tenant": t})
			return true
		}
	case "projects":
		return h.handleTenantProjects(w, r, tenantID, actorMemberID, actorMember, rest)
	case "members":
		return h.handleTenantMembers(w, r, tenantID, actorMemberID, actorMember, rest)
	case "agents":
		return h.handleTenantAgents(w, r, tenantID, actorMemberID, actorMember, clientIP, rest)
	case "api-keys":
		return h.handleTenantAPIKeys(w, r, tenantID, actorMemberID, actorMember, rest)
	case "routes":
		return h.handleTenantRoutes(w, r, tenantID, actorMemberID, actorMember, rest)
	case "policies":
		return h.handleTenantPolicies(w, r, tenantID, actorMemberID, actorMember, rest)
	case "config":
		return h.handleTenantConfig(w, r, tenantID, actorMemberID, actorMember, rest)
	case "wallets":
		return h.handleTenantWallets(w, r, tenantID, actorMemberID, actorMember, clientIP, rest)
	case "requests":
		return h.handleTenantRequests(w, r, tenantID, actorMemberID, rest)
	case "usages":
		return h.handleTenantUsages(w, r, tenantID, actorMemberID, rest)
	case "payments":
		return h.handleTenantPayments(w, r, tenantID, actorMemberID, rest)
	case "claim-trial-key":
		if method == http.MethodPost && len(rest) == 0 {
			var body struct {
				APIKey    string `json:"api_key"`
				ProjectID string `json:"project_id"`
				AgentID   string `json:"agent_id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				h.writeError(w, http.StatusBadRequest, "ERR_INVALID_PARAM", "malformed JSON body")
				return true
			}
			key, err := h.svc.ClaimTrialAPIKey(r.Context(), tenantID, body.APIKey, body.ProjectID, body.AgentID, actorMemberID)
			if err != nil {
				h.writeError(w, http.StatusBadRequest, "ERR_CLAIM_FAILED", err.Error())
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{
				"success": true,
				"message": "试用 Key 认领转正成功！已绑定为当前企业长效正式密钥，无需更改 Cursor / WorkBuddy 配置即可直接运行。",
				"api_key": key,
			})
			return true
		}
	}
	return false
}

func (h *APIHandler) handleTenantProjects(w http.ResponseWriter, r *http.Request, tenantID, actorMemberID string, actorMember *Member, rest []string) bool {
	method := r.Method
	if len(rest) == 0 {
		switch method {
		case http.MethodPost:
			var body struct {
				Name               string  `json:"name"`
				DepartmentID       *string `json:"department_id"`
				BudgetCapBaseUnits int64   `json:"budget_cap_base_units"`
				ProjectID          string  `json:"project_id"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			var deptIDToSet *string
			if body.DepartmentID != nil && strings.TrimSpace(*body.DepartmentID) != "" {
				d := strings.TrimSpace(*body.DepartmentID)
				deptIDToSet = &d
			}
			p, err := h.svc.CreateProject(r.Context(), tenantID, body.Name, deptIDToSet, body.BudgetCapBaseUnits, body.ProjectID, actorMemberID)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusCreated, map[string]interface{}{"project": p})
			return true

		case http.MethodGet:
			if err := EnforcePermission(actorMember, PermissionProjectRead); err != nil {
				h.handleError(w, err)
				return true
			}
			projects, err := h.svc.ListProjects(r.Context(), tenantID)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"projects": projects})
			return true
		}
		return false
	}

	if len(rest) == 1 {
		projectID := rest[0]
		switch method {
		case http.MethodGet:
			if err := EnforcePermission(actorMember, PermissionProjectRead); err != nil {
				h.handleError(w, err)
				return true
			}
			p, err := h.svc.GetProject(r.Context(), tenantID, projectID)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"project": p})
			return true

		case http.MethodPatch:
			bodyBytes, _ := io.ReadAll(r.Body)
			var raw map[string]json.RawMessage
			_ = json.Unmarshal(bodyBytes, &raw)

			var body struct {
				Name               string         `json:"name"`
				DepartmentID       *string        `json:"department_id"`
				BudgetCapBaseUnits *int64         `json:"budget_cap_base_units"`
				Status             *ProjectStatus `json:"status"`
			}
			_ = json.Unmarshal(bodyBytes, &body)

			var deptToUpdate *string
			if _, specified := raw["department_id"]; specified {
				if body.DepartmentID == nil || strings.TrimSpace(*body.DepartmentID) == "" {
					empty := ""
					deptToUpdate = &empty
				} else {
					clean := strings.TrimSpace(*body.DepartmentID)
					deptToUpdate = &clean
				}
			}
			p, err := h.svc.UpdateProject(r.Context(), tenantID, projectID, body.Name, deptToUpdate, body.BudgetCapBaseUnits, body.Status, actorMemberID)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"project": p})
			return true

		case http.MethodDelete:
			if err := h.svc.DeleteProject(r.Context(), tenantID, projectID, actorMemberID); err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"deleted": true, "project_id": projectID})
			return true
		}
	}
	return false
}

func (h *APIHandler) handleTenantMembers(w http.ResponseWriter, r *http.Request, tenantID, actorMemberID string, actorMember *Member, rest []string) bool {
	method := r.Method
	if len(rest) == 0 {
		switch method {
		case http.MethodPost:
			var body struct {
				Email    string `json:"email"`
				Role     string `json:"role"`
				Password string `json:"password,omitempty"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			m, err := h.svc.AddMember(r.Context(), tenantID, body.Email, MemberRole(body.Role), actorMemberID)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			if body.Password != "" {
				_ = h.svc.SetMemberPassword(r.Context(), tenantID, m.MemberID, body.Password)
			}
			h.writeJSON(w, http.StatusCreated, map[string]interface{}{"member": m})
			return true

		case http.MethodGet:
			if err := EnforcePermission(actorMember, PermissionMemberRead); err != nil {
				h.handleError(w, err)
				return true
			}
			members, err := h.svc.ListMembers(r.Context(), tenantID)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"members": members})
			return true
		}
		return false
	}

	if len(rest) == 1 {
		memberID := rest[0]
		switch method {
		case http.MethodGet:
			if err := EnforcePermission(actorMember, PermissionMemberRead); err != nil {
				h.handleError(w, err)
				return true
			}
			m, err := h.svc.GetMember(r.Context(), tenantID, memberID)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"member": m})
			return true

		case http.MethodPatch:
			var body struct {
				Role   *MemberRole   `json:"role"`
				Status *MemberStatus `json:"status"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			m, err := h.svc.UpdateMember(r.Context(), tenantID, memberID, body.Role, body.Status, actorMemberID)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"member": m})
			return true

		case http.MethodDelete:
			if err := h.svc.RemoveMember(r.Context(), tenantID, memberID, actorMemberID); err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"deleted": true, "member_id": memberID})
			return true
		}
	}
	return false
}

func (h *APIHandler) handleTenantAgents(w http.ResponseWriter, r *http.Request, tenantID, actorMemberID string, actorMember *Member, clientIP string, rest []string) bool {
	if len(rest) == 0 {
		switch r.Method {
		case http.MethodPost:
			var body struct {
				ProjectID    string                 `json:"project_id"`
				Name         string                 `json:"name"`
				PolicyConfig map[string]interface{} `json:"policy_config"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			ag, err := h.svc.CreateAgent(r.Context(), tenantID, body.ProjectID, body.Name, body.PolicyConfig, actorMemberID)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusCreated, map[string]interface{}{"agent": ag})
			return true

		case http.MethodGet:
			if err := EnforcePermission(actorMember, PermissionAgentRead); err != nil {
				h.handleError(w, err)
				return true
			}
			projectID := r.URL.Query().Get("project_id")
			var statusPtr *AgentStatus
			if s := r.URL.Query().Get("status"); s != "" {
				st := AgentStatus(s)
				statusPtr = &st
			}
			agents, err := h.svc.ListAgents(r.Context(), tenantID, projectID, statusPtr)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"agents": agents})
			return true
		}
		return false
	}
	return h.handleAgentSubpath(w, r, tenantID, actorMemberID, actorMember, clientIP, rest)
}

func (h *APIHandler) handleTenantAPIKeys(w http.ResponseWriter, r *http.Request, tenantID, actorMemberID string, actorMember *Member, rest []string) bool {
	method := r.Method
	if len(rest) == 0 {
		switch method {
		case http.MethodPost:
			var body struct {
				ProjectID string   `json:"project_id"`
				AgentID   string   `json:"agent_id"`
				Name      string   `json:"name"`
				Scopes    []string `json:"scopes"`
				ExpiresAt *int64   `json:"expires_at"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			res, err := h.svc.CreateAPIKey(r.Context(), tenantID, body.ProjectID, body.AgentID, body.Name, body.Scopes, body.ExpiresAt, actorMemberID)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusCreated, map[string]interface{}{
				"api_key": res.APIKey,
				"raw_key": res.RawKey,
			})
			return true

		case http.MethodGet:
			if err := EnforcePermission(actorMember, PermissionAPIKeyRead); err != nil {
				h.handleError(w, err)
				return true
			}
			agentID := r.URL.Query().Get("agent_id")
			keys, err := h.svc.ListAPIKeys(r.Context(), tenantID, agentID)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"api_keys": keys})
			return true
		}
		return false
	}

	if len(rest) == 1 && rest[0] == "claim-trial" && method == http.MethodPost {
		var body struct {
			APIKey    string `json:"api_key"`
			ProjectID string `json:"project_id"`
			AgentID   string `json:"agent_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			h.writeError(w, http.StatusBadRequest, "ERR_INVALID_PARAM", "malformed JSON body")
			return true
		}
		key, err := h.svc.ClaimTrialAPIKey(r.Context(), tenantID, body.APIKey, body.ProjectID, body.AgentID, actorMemberID)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, "ERR_CLAIM_FAILED", err.Error())
			return true
		}
		h.writeJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "试用 Key 认领转正成功！已绑定为当前企业长效正式密钥，无需更改 Cursor / WorkBuddy 配置即可直接运行。",
			"api_key": key,
		})
		return true
	}

	if len(rest) == 2 && method == http.MethodPost {
		keyID, action := rest[0], rest[1]
		switch action {
		case "revoke":
			k, err := h.svc.RevokeAPIKey(r.Context(), tenantID, keyID, actorMemberID)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"api_key": k})
			return true
		case "rotate":
			res, err := h.svc.RotateAPIKey(r.Context(), tenantID, keyID, actorMemberID)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{
				"api_key": res.APIKey,
				"raw_key": res.RawKey,
			})
			return true
		}
	}
	return false
}

func (h *APIHandler) handleTenantRoutes(w http.ResponseWriter, r *http.Request, tenantID, actorMemberID string, actorMember *Member, rest []string) bool {
	method := r.Method
	if len(rest) == 0 {
		switch method {
		case http.MethodPost:
			var rBody Route
			_ = json.NewDecoder(r.Body).Decode(&rBody)
			rBody.TenantID = tenantID
			created, err := h.svc.CreateRoute(r.Context(), &rBody, actorMemberID)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusCreated, map[string]interface{}{"route": created})
			return true

		case http.MethodGet:
			if err := EnforcePermission(actorMember, PermissionRouteRead); err != nil {
				h.handleError(w, err)
				return true
			}
			routes, err := h.svc.ListRoutes(r.Context(), tenantID)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			if projectID := r.URL.Query().Get("project_id"); projectID != "" {
				filtered := make([]*Route, 0)
				for _, rt := range routes {
					if rt.ProjectID == projectID {
						filtered = append(filtered, rt)
					}
				}
				routes = filtered
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"routes": routes})
			return true
		}
		return false
	}

	if len(rest) == 1 {
		if rest[0] == "test-upstream" && method == http.MethodPost {
			var body TestUpstreamInput
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				h.writeError(w, http.StatusBadRequest, "ERR_INVALID_PARAM", "malformed JSON body")
				return true
			}
			res, err := h.svc.TestUpstream(r.Context(), tenantID, &body, actorMemberID)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"result": res})
			return true
		}

		routeID := rest[0]
		switch method {
		case http.MethodGet:
			if err := EnforcePermission(actorMember, PermissionRouteRead); err != nil {
				h.handleError(w, err)
				return true
			}
			route, err := h.svc.GetRoute(r.Context(), tenantID, routeID)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"route": route})
			return true

		case http.MethodPatch:
			var rBody UpdateRouteInput
			_ = json.NewDecoder(r.Body).Decode(&rBody)
			rBody.RouteID = routeID
			rBody.TenantID = tenantID
			updated, err := h.svc.UpdateRoute(r.Context(), &rBody, actorMemberID)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"route": updated})
			return true

		case http.MethodDelete:
			if err := h.svc.DeleteRoute(r.Context(), tenantID, routeID, actorMemberID); err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"deleted": true, "route_id": routeID})
			return true
		}
	}
	return false
}

func (h *APIHandler) handleTenantPolicies(w http.ResponseWriter, r *http.Request, tenantID, actorMemberID string, actorMember *Member, rest []string) bool {
	method := r.Method
	if len(rest) == 0 {
		switch method {
		case http.MethodPost:
			var pBody Policy
			_ = json.NewDecoder(r.Body).Decode(&pBody)
			pBody.TenantID = tenantID
			created, err := h.svc.CreatePolicy(r.Context(), &pBody, actorMemberID)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusCreated, map[string]interface{}{"policy": created})
			return true

		case http.MethodGet:
			if err := EnforcePermission(actorMember, PermissionPolicyRead); err != nil {
				h.handleError(w, err)
				return true
			}
			q := r.URL.Query()
			policies, err := h.svc.ListPolicies(r.Context(), tenantID, q.Get("project_id"), q.Get("agent_id"))
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"policies": policies})
			return true
		}
		return false
	}

	if len(rest) == 1 {
		policyID := rest[0]
		switch method {
		case http.MethodGet:
			if err := EnforcePermission(actorMember, PermissionPolicyRead); err != nil {
				h.handleError(w, err)
				return true
			}
			pol, err := h.svc.GetPolicy(r.Context(), tenantID, policyID)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"policy": pol})
			return true

		case http.MethodPatch:
			var pBody Policy
			_ = json.NewDecoder(r.Body).Decode(&pBody)
			pBody.PolicyID = policyID
			pBody.TenantID = tenantID
			updated, err := h.svc.UpdatePolicy(r.Context(), &pBody, actorMemberID)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"policy": updated})
			return true

		case http.MethodDelete:
			if err := h.svc.DeletePolicy(r.Context(), tenantID, policyID, actorMemberID); err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"deleted": true, "policy_id": policyID})
			return true
		}
	}
	return false
}

func (h *APIHandler) handleTenantConfig(w http.ResponseWriter, r *http.Request, tenantID, actorMemberID string, actorMember *Member, rest []string) bool {
	if len(rest) == 0 {
		return false
	}
	method := r.Method

	switch rest[0] {
	case "validate":
		if method != http.MethodPost {
			return false
		}
		res, err := h.svc.ValidateConfig(r.Context(), tenantID, actorMemberID)
		if err != nil {
			h.handleError(w, err)
			return true
		}
		h.writeJSON(w, http.StatusOK, map[string]interface{}{"result": res})
		return true

	case "publish":
		if method != http.MethodPost {
			return false
		}
		var body struct {
			ChangeSummary string `json:"change_summary"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		ver, err := h.svc.PublishConfig(r.Context(), tenantID, body.ChangeSummary, actorMemberID)
		if err != nil {
			h.handleError(w, err)
			return true
		}
		h.writeJSON(w, http.StatusOK, map[string]interface{}{"version": ver})
		return true

	case "rollback":
		if method != http.MethodPost {
			return false
		}
		var body struct {
			TargetVersionID string `json:"target_version_id"`
			Reason          string `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			h.writeError(w, http.StatusBadRequest, "ERR_INVALID_JSON", "invalid request body")
			return true
		}
		ver, err := h.svc.RollbackConfig(r.Context(), tenantID, body.TargetVersionID, body.Reason, actorMemberID)
		if err != nil {
			h.handleError(w, err)
			return true
		}
		h.writeJSON(w, http.StatusOK, map[string]interface{}{"version": ver})
		return true

	case "versions":
		if method != http.MethodGet {
			return false
		}
		if err := EnforcePermission(actorMember, PermissionRouteRead); err != nil {
			h.handleError(w, err)
			return true
		}
		if len(rest) == 2 && rest[1] == "diff" {
			q := r.URL.Query()
			baseVer := q.Get("base")
			if baseVer == "" {
				baseVer = q.Get("from")
			}
			targetVer := q.Get("target")
			if targetVer == "" {
				targetVer = q.Get("to")
			}
			diff, err := h.svc.GetConfigVersionDiff(r.Context(), tenantID, baseVer, targetVer)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"diff": diff})
			return true
		}
		if len(rest) == 1 {
			list, err := h.svc.ListConfigVersions(r.Context(), tenantID)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"versions": list})
			return true
		}
		if len(rest) == 2 {
			ver, err := h.svc.GetConfigVersion(r.Context(), tenantID, rest[1])
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"version": ver})
			return true
		}

	case "draft":
		if method != http.MethodGet {
			return false
		}
		if err := EnforcePermission(actorMember, PermissionRouteRead); err != nil {
			h.handleError(w, err)
			return true
		}
		if len(rest) == 2 && rest[1] == "diff" {
			diff, err := h.svc.GetDraftDiff(r.Context(), tenantID)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"diff": diff})
			return true
		}
		if len(rest) == 1 {
			summary, err := h.svc.GetDraftSummary(r.Context(), tenantID)
			if err != nil {
				h.handleError(w, err)
				return true
			}
			h.writeJSON(w, http.StatusOK, map[string]interface{}{"draft": summary})
			return true
		}
	}
	return false
}

func (h *APIHandler) handleTenantWallets(w http.ResponseWriter, r *http.Request, tenantID, actorMemberID string, actorMember *Member, clientIP string, rest []string) bool {
	if len(rest) == 0 && r.Method == http.MethodGet {
		if err := EnforcePermission(actorMember, PermissionWalletRead); err != nil {
			h.handleError(w, err)
			return true
		}
		wlt, err := h.svc.GetWallet(r.Context(), tenantID)
		if err != nil {
			h.handleError(w, err)
			return true
		}
		h.writeJSON(w, http.StatusOK, map[string]interface{}{"wallet": wlt})
		return true
	}
	if len(rest) == 1 && rest[0] == "admin-grant" && r.Method == http.MethodPost {
		h.writeError(w, http.StatusForbidden, "ERR_ENDPOINT_DISABLED", "Admin wallet grant API has been disabled.")
		return true
	}
	return false
}

func (h *APIHandler) handleTenantRequests(w http.ResponseWriter, r *http.Request, tenantID, actorMemberID string, rest []string) bool {
	if r.Method != http.MethodGet {
		return false
	}
	if len(rest) == 0 {
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		offset, _ := strconv.Atoi(q.Get("offset"))
		statusCode, _ := strconv.Atoi(q.Get("status_code"))

		var isReplay *bool
		if rStr := q.Get("is_replay"); rStr != "" {
			b := rStr == "true" || rStr == "1"
			isReplay = &b
		}

		filter := usage.RequestFilter{
			ProjectID:  q.Get("project_id"),
			AgentID:    q.Get("agent_id"),
			RouteID:    q.Get("route_id"),
			StatusCode: statusCode,
			IsReplay:   isReplay,
			Limit:      limit,
			Offset:     offset,
		}

		list, total, err := h.svc.ListRequestRecords(r.Context(), tenantID, filter, actorMemberID)
		if err != nil {
			h.handleError(w, err)
			return true
		}
		h.writeJSON(w, http.StatusOK, map[string]interface{}{
			"requests": list,
			"total":    total,
			"limit":    limit,
			"offset":   offset,
		})
		return true
	}
	if len(rest) == 1 {
		rec, err := h.svc.GetRequestRecord(r.Context(), tenantID, rest[0], actorMemberID)
		if err != nil {
			h.handleError(w, err)
			return true
		}
		h.writeJSON(w, http.StatusOK, map[string]interface{}{"request": rec})
		return true
	}
	return false
}

func (h *APIHandler) handleTenantUsages(w http.ResponseWriter, r *http.Request, tenantID, actorMemberID string, rest []string) bool {
	if r.Method != http.MethodGet {
		return false
	}
	if len(rest) == 0 {
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		offset, _ := strconv.Atoi(q.Get("offset"))

		var isSuccess *bool
		if sStr := q.Get("is_success"); sStr != "" {
			b := sStr == "true" || sStr == "1"
			isSuccess = &b
		}

		filter := usage.UsageFilter{
			ProjectID:     q.Get("project_id"),
			AgentID:       q.Get("agent_id"),
			RouteID:       q.Get("route_id"),
			IntentID:      q.Get("intent_id"),
			PaymentMethod: q.Get("payment_method"),
			IsSuccess:     isSuccess,
			Limit:         limit,
			Offset:        offset,
		}

		list, total, err := h.svc.ListUsageEvents(r.Context(), tenantID, filter, actorMemberID)
		if err != nil {
			h.handleError(w, err)
			return true
		}
		h.writeJSON(w, http.StatusOK, map[string]interface{}{
			"usages": list,
			"total":  total,
			"limit":  limit,
			"offset": offset,
		})
		return true
	}
	if len(rest) == 1 {
		evt, err := h.svc.GetUsageEvent(r.Context(), tenantID, rest[0], actorMemberID)
		if err != nil {
			h.handleError(w, err)
			return true
		}
		h.writeJSON(w, http.StatusOK, map[string]interface{}{"usage": evt})
		return true
	}
	return false
}

func (h *APIHandler) handleTenantPayments(w http.ResponseWriter, r *http.Request, tenantID, actorMemberID string, rest []string) bool {
	if r.Method != http.MethodGet {
		return false
	}
	if len(rest) == 0 {
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		offset, _ := strconv.Atoi(q.Get("offset"))

		filter := payment.PaymentAuditFilter{
			ProjectID:     q.Get("project_id"),
			AgentID:       q.Get("agent_id"),
			RouteID:       q.Get("route_id"),
			PaymentMethod: q.Get("payment_method"),
			DisplayStatus: q.Get("display_status"),
			IntentStatus:  q.Get("intent_status"),
			Limit:         limit,
			Offset:        offset,
		}
		if st := q.Get("start_time"); st != "" {
			if t, err := time.Parse(time.RFC3339, st); err == nil {
				filter.StartTime = &t
			}
		}
		if et := q.Get("end_time"); et != "" {
			if t, err := time.Parse(time.RFC3339, et); err == nil {
				filter.EndTime = &t
			}
		}

		list, total, err := h.svc.ListPaymentAudits(r.Context(), tenantID, filter, actorMemberID)
		if err != nil {
			h.handleError(w, err)
			return true
		}
		h.writeJSON(w, http.StatusOK, map[string]interface{}{
			"payments": list,
			"total":    total,
			"limit":    limit,
			"offset":   offset,
		})
		return true
	}
	if len(rest) == 1 {
		rec, err := h.svc.GetPaymentAudit(r.Context(), tenantID, rest[0], actorMemberID)
		if err != nil {
			h.handleError(w, err)
			return true
		}
		h.writeJSON(w, http.StatusOK, map[string]interface{}{"payment": rec})
		return true
	}
	if len(rest) == 2 && rest[0] == "by-request" {
		rec, err := h.svc.GetPaymentAuditByRequestID(r.Context(), tenantID, rest[1], actorMemberID)
		if err != nil {
			h.handleError(w, err)
			return true
		}
		h.writeJSON(w, http.StatusOK, map[string]interface{}{"payment": rec})
		return true
	}
	return false
}

// ----------------------------------------------------------------------------
// 3. Error Mapping, JSON Response & Agent Timeline Helpers
// ----------------------------------------------------------------------------

func (h *APIHandler) handleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrTenantNotFound),
		errors.Is(err, ErrProjectNotFound),
		errors.Is(err, ErrMemberNotFound),
		errors.Is(err, ErrAgentNotFound),
		errors.Is(err, ErrAPIKeyNotFound),
		errors.Is(err, ErrRouteNotFound),
		errors.Is(err, ErrPolicyNotFound),
		errors.Is(err, ErrWalletNotFound),
		errors.Is(err, usage.ErrRequestRecordNotFound),
		errors.Is(err, usage.ErrUsageEventNotFound),
		errors.Is(err, payment.ErrIntentNotFound),
		errors.Is(err, payment.ErrSettlementNotFound),
		errors.Is(err, payment.ErrFulfillmentNotFound):
		h.writeError(w, http.StatusNotFound, "ERR_NOT_FOUND", err.Error())
	case errors.Is(err, ErrPermissionDenied),
		errors.Is(err, ErrMemberDisabled),
		errors.Is(err, ErrTenantSuspended),
		errors.Is(err, ErrTenantTerminated),
		errors.Is(err, ErrProjectArchived),
		errors.Is(err, ErrProjectTenantMismatch),
		errors.Is(err, ErrAgentTenantMismatch),
		errors.Is(err, ErrAgentSuspended),
		errors.Is(err, ErrAgentRevoked),
		errors.Is(err, usage.ErrTenantMismatch),
		errors.Is(err, payment.ErrTenantMismatch):
		h.writeError(w, http.StatusForbidden, "ERR_PERMISSION_DENIED", err.Error())
	case errors.Is(err, upstreamauth.ErrSSRFBlocked):
		h.writeError(w, http.StatusForbidden, "ERR_SSRF_BLOCKED", err.Error())
	case errors.Is(err, ErrTenantAlreadyExists),
		errors.Is(err, ErrProjectAlreadyExists),
		errors.Is(err, ErrMemberAlreadyExists),
		errors.Is(err, ErrAgentAlreadyExists),
		errors.Is(err, ErrRouteAlreadyExists):
		h.writeError(w, http.StatusConflict, "ERR_ALREADY_EXISTS", err.Error())
	case errors.Is(err, ErrMissingReason):
		h.writeError(w, http.StatusBadRequest, "ERR_MISSING_REASON", err.Error())
	case errors.Is(err, ErrInvalidStatusTransition),
		errors.Is(err, ErrCannotRemoveLastOwner),
		errors.Is(err, ErrCannotDemoteLastOwner),
		errors.Is(err, ErrInvalidAmount):
		h.writeError(w, http.StatusBadRequest, "ERR_INVALID_PARAM", err.Error())
	case errors.Is(err, ErrInvalidCredentials):
		h.writeError(w, http.StatusUnauthorized, "ERR_INVALID_CREDENTIALS", err.Error())
	case errors.Is(err, ErrPasswordTooShort):
		h.writeError(w, http.StatusBadRequest, "ERR_PASSWORD_TOO_SHORT", err.Error())
	case errors.Is(err, ErrEmailAlreadyRegistered):
		h.writeError(w, http.StatusConflict, "ERR_EMAIL_ALREADY_REGISTERED", err.Error())
	case errors.Is(err, ErrConfigValidationFailed):
		h.writeError(w, http.StatusUnprocessableEntity, "ERR_CONFIG_VALIDATION_FAILED", err.Error())
	case errors.Is(err, ErrConfigVersionNotFound):
		h.writeError(w, http.StatusNotFound, "ERR_CONFIG_VERSION_NOT_FOUND", err.Error())
	case errors.Is(err, ErrCannotRollbackToActive):
		h.writeError(w, http.StatusBadRequest, "ERR_CANNOT_ROLLBACK_TO_ACTIVE", err.Error())
	case errors.Is(err, ErrCurrencyLocked):
		h.writeError(w, http.StatusConflict, "ERR_CURRENCY_LOCKED", err.Error())
	case errors.Is(err, ErrInvalidCurrency):
		h.writeError(w, http.StatusBadRequest, "ERR_INVALID_CURRENCY", err.Error())
	case errors.Is(err, wallet.ErrInsufficientBalance):
		h.writeError(w, http.StatusPaymentRequired, "ERR_INSUFFICIENT_FUNDS", err.Error())
	default:
		h.writeError(w, http.StatusBadRequest, "ERR_BAD_REQUEST", err.Error())
	}
}

func (h *APIHandler) writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *APIHandler) writeError(w http.ResponseWriter, statusCode int, code, message string) {
	if statusCode >= 500 {
		slog.Error("admin control-plane request error", slog.Int("status", statusCode), slog.String("code", code), slog.String("message", message))
	} else if statusCode >= 400 {
		slog.Warn("admin control-plane client warning", slog.Int("status", statusCode), slog.String("code", code), slog.String("message", message))
	}
	h.writeJSON(w, statusCode, map[string]interface{}{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}

func parseFlexibleTimestamp(raw string) *time.Time {
	if raw == "" {
		return nil
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return &t
	}
	if sec, err := strconv.ParseInt(raw, 10, 64); err == nil {
		var t time.Time
		if sec > 1e11 {
			t = time.UnixMilli(sec)
		} else {
			t = time.Unix(sec, 0)
		}
		return &t
	}
	return nil
}

func (h *APIHandler) handleAgentTimeline(w http.ResponseWriter, r *http.Request, tenantID, agentID, actorMemberID string) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	if limit <= 0 {
		limit = 50
	} else if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}

	filter := timeline.TimelineFilter{
		SessionID: q.Get("session_id"),
		TaskID:    q.Get("task_id"),
		EventType: q.Get("event_type"),
		StartTime: parseFlexibleTimestamp(q.Get("start_time")),
		EndTime:   parseFlexibleTimestamp(q.Get("end_time")),
		Limit:     limit,
		Offset:    offset,
	}

	events, total, sessions, err := h.svc.GetAgentTimeline(r.Context(), tenantID, agentID, filter, actorMemberID)
	if err != nil {
		h.handleError(w, err)
		return
	}

	if events == nil {
		events = []*timeline.TimelineEvent{}
	}
	if sessions == nil {
		sessions = []string{}
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"items":    events,
		"total":    total,
		"count":    len(events),
		"sessions": sessions,
	})
}
