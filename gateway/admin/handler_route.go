package admin

import (
	"encoding/json"
	"net/http"
)

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

