package admin

import (
	"encoding/json"
	"github.com/open-agentpay/agent-core-sdk/gateway/auth"
	"net/http"
)

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

