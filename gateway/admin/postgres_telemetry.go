package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
	"github.com/open-agentpay/agent-core-sdk/gateway/payment"
	"github.com/open-agentpay/agent-core-sdk/gateway/usage"
)

func (p *PostgresService) ListAuditEvents(ctx context.Context, tenantID, targetType, targetID string, limit int) ([]*AuditEvent, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	var sb strings.Builder
	sb.WriteString(`
		SELECT audit_id, tenant_id, operator_id, action, target_type, target_id, before_state, after_state, client_ip,
		       EXTRACT(EPOCH FROM created_at)::bigint
		FROM ap_audit_event
		WHERE 1=1
	`)
	args := make([]interface{}, 0)
	idx := 1

	if tenantID != "" {
		sb.WriteString(fmt.Sprintf(" AND tenant_id = $%d", idx))
		args = append(args, tenantID)
		idx++
	}
	if targetType != "" {
		sb.WriteString(fmt.Sprintf(" AND target_type = $%d", idx))
		args = append(args, targetType)
		idx++
	}
	if targetID != "" {
		sb.WriteString(fmt.Sprintf(" AND target_id = $%d", idx))
		args = append(args, targetID)
		idx++
	}
	sb.WriteString(fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d;", idx))
	args = append(args, limit)

	rows, err := p.db.QueryContext(ctx, sb.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	events := make([]*AuditEvent, 0)
	for rows.Next() {
		var ev AuditEvent
		var beforeBytes, afterBytes []byte
		if err := rows.Scan(&ev.AuditID, &ev.TenantID, &ev.OperatorID, &ev.Action, &ev.TargetType, &ev.TargetID, &beforeBytes, &afterBytes, &ev.ClientIP, &ev.CreatedAt); err != nil {
			return nil, err
		}
		if len(beforeBytes) > 0 {
			_ = json.Unmarshal(beforeBytes, &ev.BeforeState)
		}
		if len(afterBytes) > 0 {
			_ = json.Unmarshal(afterBytes, &ev.AfterState)
		}
		events = append(events, &ev)
	}
	return events, nil
}

// ----------------------------------------------------------------------------
// Upstream Authentication & Connectivity Testing (T4.2 Enhancement)
// ----------------------------------------------------------------------------

func (p *PostgresService) ListRequestRecords(ctx context.Context, tenantID string, filter usage.RequestFilter, actorMemberID string) ([]*usage.RequestRecord, int64, error) {
	if err := p.enforcePermission(ctx, actorMemberID, tenantID, PermissionAuditRead); err != nil {
		return nil, 0, err
	}
	filter.TenantID = tenantID
	return p.GetUsageService().ListRequestRecords(ctx, filter)
}

func (p *PostgresService) GetRequestRecord(ctx context.Context, tenantID, requestID string, actorMemberID string) (*usage.RequestRecord, error) {
	if err := p.enforcePermission(ctx, actorMemberID, tenantID, PermissionAuditRead); err != nil {
		return nil, err
	}
	return p.GetUsageService().GetRequestRecord(ctx, tenantID, requestID)
}

func (p *PostgresService) ListUsageEvents(ctx context.Context, tenantID string, filter usage.UsageFilter, actorMemberID string) ([]*usage.UsageEvent, int64, error) {
	if err := p.enforcePermission(ctx, actorMemberID, tenantID, PermissionAuditRead); err != nil {
		return nil, 0, err
	}
	filter.TenantID = tenantID
	return p.GetUsageService().ListUsageEvents(ctx, filter)
}

func (p *PostgresService) GetUsageEvent(ctx context.Context, tenantID, eventID string, actorMemberID string) (*usage.UsageEvent, error) {
	if err := p.enforcePermission(ctx, actorMemberID, tenantID, PermissionAuditRead); err != nil {
		return nil, err
	}
	return p.GetUsageService().GetUsageEvent(ctx, tenantID, eventID)
}

func (p *PostgresService) GetRouteTelemetryOverview(ctx context.Context, tenantID, timeRange, projectID, actorMemberID string) (*RouteTelemetryOverviewResponse, error) {
	if err := p.enforcePermission(ctx, actorMemberID, tenantID, PermissionAuditRead); err != nil {
		return nil, err
	}

	normRange, dur := ParseTimeRange(timeRange)
	cacheKey := fmt.Sprintf("%s:%s:%s", tenantID, projectID, normRange)

	p.telemetryMu.RLock()
	if entry, ok := p.telemetryCache[cacheKey]; ok && time.Now().Before(entry.expiresAt) {
		p.telemetryMu.RUnlock()
		return entry.data, nil
	}
	p.telemetryMu.RUnlock()

	since := time.Now().Add(-dur)

	// Fetch tenant routes
	routes, err := p.ListRoutes(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	routeItemsMap := make(map[string]*RouteTelemetryItem)
	for _, r := range routes {
		modelName := r.ModelName
		if modelName == "" {
			modelName = r.Slug
		}
		routeItemsMap[r.RouteID] = &RouteTelemetryItem{
			RouteID:     r.RouteID,
			ModelName:   modelName,
			Title:       r.Title,
			RouteType:   r.RouteType,
			Status:      string(r.Status),
			SuccessRate: 100.0,
		}
	}

	// 1. Query request metrics grouped by route_id
	var reqQuery string
	var reqArgs []interface{}
	if projectID != "" {
		reqQuery = `
			SELECT route_id,
			       COUNT(*) as total_calls,
			       COUNT(CASE WHEN status_code >= 200 AND status_code < 400 THEN 1 END) as success_calls,
			       COUNT(CASE WHEN status_code >= 400 AND status_code < 500 THEN 1 END) as blocked_calls,
			       COUNT(CASE WHEN status_code >= 500 THEN 1 END) as upstream_error_calls,
			       COALESCE(AVG(duration_ms)::bigint, 0) as avg_duration,
			       COALESCE(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY duration_ms)::bigint, 0) as p95_duration
			FROM ap_request_record
			WHERE tenant_id = $1 AND project_id = $2 AND created_at >= $3 AND route_id IS NOT NULL AND route_id != ''
			GROUP BY route_id;
		`
		reqArgs = []interface{}{tenantID, projectID, since}
	} else {
		reqQuery = `
			SELECT route_id,
			       COUNT(*) as total_calls,
			       COUNT(CASE WHEN status_code >= 200 AND status_code < 400 THEN 1 END) as success_calls,
			       COUNT(CASE WHEN status_code >= 400 AND status_code < 500 THEN 1 END) as blocked_calls,
			       COUNT(CASE WHEN status_code >= 500 THEN 1 END) as upstream_error_calls,
			       COALESCE(AVG(duration_ms)::bigint, 0) as avg_duration,
			       COALESCE(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY duration_ms)::bigint, 0) as p95_duration
			FROM ap_request_record
			WHERE tenant_id = $1 AND created_at >= $2 AND route_id IS NOT NULL AND route_id != ''
			GROUP BY route_id;
		`
		reqArgs = []interface{}{tenantID, since}
	}

	reqRows, reqErr := p.db.QueryContext(ctx, reqQuery, reqArgs...)
	if reqErr == nil {
		defer reqRows.Close()
		for reqRows.Next() {
			var rID string
			var calls, succ, blocked, upErr, avgD, p95D int64
			if err := reqRows.Scan(&rID, &calls, &succ, &blocked, &upErr, &avgD, &p95D); err == nil {
				item, exists := routeItemsMap[rID]
				if !exists {
					item = &RouteTelemetryItem{
						RouteID:   rID,
						ModelName: rID,
						Title:     rID,
						RouteType: "api",
						Status:    "active",
					}
					routeItemsMap[rID] = item
				}
				item.Calls = calls
				item.SuccessCalls = succ
				item.BlockedCalls = blocked
				item.UpstreamErrorCalls = upErr
				item.AvgDurationMs = avgD
				item.P95DurationMs = p95D
				if calls > 0 {
					item.SuccessRate = float64(int((float64(succ)/float64(calls))*1000)) / 10.0
				}
			}
		}
	}

	// 2. Query usage and token stats grouped by route_id
	var useQuery string
	var useArgs []interface{}
	if projectID != "" {
		useQuery = `
			SELECT route_id,
			       COALESCE(SUM(amount_base_units), 0) as cost_amount,
			       COALESCE(SUM(prompt_tokens), 0) as prompt_tokens,
			       COALESCE(SUM(completion_tokens), 0) as completion_tokens,
			       COALESCE(SUM(total_tokens), 0) as total_tokens
			FROM ap_usage_event
			WHERE tenant_id = $1 AND project_id = $2 AND created_at >= $3
			GROUP BY route_id;
		`
		useArgs = []interface{}{tenantID, projectID, since}
	} else {
		useQuery = `
			SELECT route_id,
			       COALESCE(SUM(amount_base_units), 0) as cost_amount,
			       COALESCE(SUM(prompt_tokens), 0) as prompt_tokens,
			       COALESCE(SUM(completion_tokens), 0) as completion_tokens,
			       COALESCE(SUM(total_tokens), 0) as total_tokens
			FROM ap_usage_event
			WHERE tenant_id = $1 AND created_at >= $2
			GROUP BY route_id;
		`
		useArgs = []interface{}{tenantID, since}
	}

	useRows, useErr := p.db.QueryContext(ctx, useQuery, useArgs...)
	if useErr == nil {
		defer useRows.Close()
		for useRows.Next() {
			var rID string
			var cost, pTok, cTok, tTok int64
			if err := useRows.Scan(&rID, &cost, &pTok, &cTok, &tTok); err == nil {
				if item, exists := routeItemsMap[rID]; exists {
					item.CostAmount = cost
					item.PromptTokens = pTok
					item.CompletionTokens = cTok
					if tTok <= 0 && (pTok > 0 || cTok > 0) {
						tTok = pTok + cTok
					}
					item.TotalTokens = tTok
				}
			}
		}
	} else {
		// Fallback for legacy database before token migration
		var fallbackQuery string
		if projectID != "" {
			fallbackQuery = `
				SELECT route_id, COALESCE(SUM(amount_base_units), 0) as cost_amount
				FROM ap_usage_event
				WHERE tenant_id = $1 AND project_id = $2 AND created_at >= $3
				GROUP BY route_id;
			`
		} else {
			fallbackQuery = `
				SELECT route_id, COALESCE(SUM(amount_base_units), 0) as cost_amount
				FROM ap_usage_event
				WHERE tenant_id = $1 AND created_at >= $2
				GROUP BY route_id;
			`
		}
		if fbRows, fbErr := p.db.QueryContext(ctx, fallbackQuery, useArgs...); fbErr == nil {
			defer fbRows.Close()
			for fbRows.Next() {
				var rID string
				var cost int64
				if err := fbRows.Scan(&rID, &cost); err == nil {
					if item, exists := routeItemsMap[rID]; exists {
						item.CostAmount = cost
					}
				}
			}
		}
	}

	// 4. Assemble Route list and calculate tenant summary
	routeList := make([]*RouteTelemetryItem, 0, len(routeItemsMap))
	var summary RouteTelemetrySummary
	var totalSuccCalls int64
	var totalBlockedCalls int64
	var totalUpstreamErrorCalls int64
	var sumDurationTotal int64

	for _, item := range routeItemsMap {
		routeList = append(routeList, item)

		summary.TotalCalls += item.Calls
		summary.TotalTokens += item.TotalTokens
		summary.PromptTokens += item.PromptTokens
		summary.CompletionTokens += item.CompletionTokens
		sumDurationTotal += (item.AvgDurationMs * item.Calls)

		totalSuccCalls += item.SuccessCalls
		totalBlockedCalls += item.BlockedCalls
		totalUpstreamErrorCalls += item.UpstreamErrorCalls
	}

	sort.Slice(routeList, func(i, j int) bool {
		return routeList[i].Calls > routeList[j].Calls
	})

	if summary.TotalCalls > 0 {
		summary.SuccessRate = float64(int((float64(totalSuccCalls)/float64(summary.TotalCalls))*1000)) / 10.0
		summary.AvgDurationMs = sumDurationTotal / summary.TotalCalls
		summary.SuccessCalls = totalSuccCalls
		summary.BlockedCalls = totalBlockedCalls
		summary.UpstreamErrorCalls = totalUpstreamErrorCalls
		summary.FailedCalls = summary.TotalCalls - totalSuccCalls
		if len(routeList) > 0 {
			summary.P95DurationMs = routeList[0].P95DurationMs
		}
	} else {
		summary.SuccessRate = 100.0
	}

	resp := &RouteTelemetryOverviewResponse{
		TenantID:  tenantID,
		TimeRange: normRange,
		ProjectID: projectID,
		Summary:   summary,
		Routes:    routeList,
		CachedAt:  time.Now().Unix(),
	}

	// Cache result in memory for 15s
	p.telemetryMu.Lock()
	if p.telemetryCache == nil {
		p.telemetryCache = make(map[string]*telemetryCacheEntry)
	}
	p.telemetryCache[cacheKey] = &telemetryCacheEntry{
		data:      resp,
		expiresAt: time.Now().Add(15 * time.Second),
	}
	p.telemetryMu.Unlock()

	return resp, nil
}

func (p *PostgresService) GetPaymentAudit(ctx context.Context, tenantID, intentID string, actorMemberID string) (*payment.PaymentAuditRecord, error) {
	if err := p.enforcePermission(ctx, actorMemberID, tenantID, PermissionAuditRead); err != nil {
		return nil, err
	}
	return p.GetPaymentService().GetPaymentAudit(ctx, tenantID, intentID)
}

func (p *PostgresService) GetPaymentAuditByRequestID(ctx context.Context, tenantID, requestID string, actorMemberID string) (*payment.PaymentAuditRecord, error) {
	if err := p.enforcePermission(ctx, actorMemberID, tenantID, PermissionAuditRead); err != nil {
		return nil, err
	}
	return p.GetPaymentService().GetPaymentAuditByRequestID(ctx, tenantID, requestID)
}

func (p *PostgresService) ListPaymentAudits(ctx context.Context, tenantID string, filter payment.PaymentAuditFilter, actorMemberID string) ([]*payment.PaymentAuditRecord, int64, error) {
	if err := p.enforcePermission(ctx, actorMemberID, tenantID, PermissionAuditRead); err != nil {
		return nil, 0, err
	}
	filter.TenantID = tenantID
	return p.GetPaymentService().ListPaymentAudits(ctx, filter)
}

