package admin

import (
	"encoding/json"
	"github.com/open-agentpay/agent-core-sdk/gateway/timeline"
	"net/http"
	"strconv"
)

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
