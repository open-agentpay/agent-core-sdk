package admin

import (
	"encoding/json"
	"github.com/open-agentpay/agent-core-sdk/gateway/payment"
	"github.com/open-agentpay/agent-core-sdk/gateway/usage"
	"net/http"
	"strconv"
	"time"
)

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

func (h *APIHandler) handleTenantAnalytics(w http.ResponseWriter, r *http.Request, tenantID, actorMemberID string, rest []string) bool {
	if r.Method != http.MethodGet {
		return false
	}
	if len(rest) == 1 && rest[0] == "routes-overview" {
		q := r.URL.Query()
		timeRange := q.Get("time_range")
		projectID := q.Get("project_id")

		resp, err := h.svc.GetRouteTelemetryOverview(r.Context(), tenantID, timeRange, projectID, actorMemberID)
		if err != nil {
			h.handleError(w, err)
			return true
		}
		h.writeJSON(w, http.StatusOK, resp)
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

