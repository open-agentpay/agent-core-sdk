package admin

import (
	"encoding/json"
	"github.com/open-agentpay/agent-core-sdk/gateway/auth"
	"io"
	"net/http"
	"strings"
)

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
	case "analytics":
		return h.handleTenantAnalytics(w, r, tenantID, actorMemberID, rest)
	case "payments":
		return h.handleTenantPayments(w, r, tenantID, actorMemberID, rest)
	case "audit-events", "audit":
		if method == http.MethodGet {
			h.handleAuditEvents(w, r, actorMember, tenantID)
			return true
		}
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

