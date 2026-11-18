package admin

import (
	"context"
	"github.com/open-agentpay/agent-core-sdk/gateway/auth"
	"github.com/open-agentpay/agent-core-sdk/gateway/payment"
	"github.com/open-agentpay/agent-core-sdk/gateway/usage"
	"sort"
	"time"
)

func (s *MemoryService) ListAuditEvents(ctx context.Context, tenantID, targetType, targetID string, limit int) ([]*AuditEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make([]*AuditEvent, 0)
	for i := len(s.auditEvents) - 1; i >= 0; i-- {
		ev := s.auditEvents[i]
		if tenantID != "" && ev.TenantID != tenantID {
			continue
		}
		if targetType != "" && ev.TargetType != targetType {
			continue
		}
		if targetID != "" && ev.TargetID != targetID {
			continue
		}
		res = append(res, ev)
		if limit > 0 && len(res) >= limit {
			break
		}
	}
	return res, nil
}

// ----------------------------------------------------------------------------
// Config Draft, Validation, Publishing & Rollback (T4.3 & T4.4)
// ----------------------------------------------------------------------------

func (s *MemoryService) enforceAuditRead(ctx context.Context, tenantID, actorMemberID string) error {
	if actorMemberID == "" {
		if auth.IsSystemContext(ctx) {
			return nil
		}
		return ErrPermissionDenied
	}
	member, err := s.GetMember(ctx, tenantID, actorMemberID)
	if err != nil {
		return ErrPermissionDenied
	}
	return EnforcePermission(member, PermissionAuditRead)
}

func (s *MemoryService) ListRequestRecords(ctx context.Context, tenantID string, filter usage.RequestFilter, actorMemberID string) ([]*usage.RequestRecord, int64, error) {
	if err := s.enforceAuditRead(ctx, tenantID, actorMemberID); err != nil {
		return nil, 0, err
	}
	filter.TenantID = tenantID
	return s.GetUsageService().ListRequestRecords(ctx, filter)
}

func (s *MemoryService) GetRequestRecord(ctx context.Context, tenantID, requestID string, actorMemberID string) (*usage.RequestRecord, error) {
	if err := s.enforceAuditRead(ctx, tenantID, actorMemberID); err != nil {
		return nil, err
	}
	return s.GetUsageService().GetRequestRecord(ctx, tenantID, requestID)
}

func (s *MemoryService) ListUsageEvents(ctx context.Context, tenantID string, filter usage.UsageFilter, actorMemberID string) ([]*usage.UsageEvent, int64, error) {
	if err := s.enforceAuditRead(ctx, tenantID, actorMemberID); err != nil {
		return nil, 0, err
	}
	filter.TenantID = tenantID
	return s.GetUsageService().ListUsageEvents(ctx, filter)
}

func (s *MemoryService) GetUsageEvent(ctx context.Context, tenantID, eventID string, actorMemberID string) (*usage.UsageEvent, error) {
	if err := s.enforceAuditRead(ctx, tenantID, actorMemberID); err != nil {
		return nil, err
	}
	return s.GetUsageService().GetUsageEvent(ctx, tenantID, eventID)
}

func (s *MemoryService) GetRouteTelemetryOverview(ctx context.Context, tenantID, timeRange, projectID, actorMemberID string) (*RouteTelemetryOverviewResponse, error) {
	if err := s.enforceAuditRead(ctx, tenantID, actorMemberID); err != nil {
		return nil, err
	}

	normRange, dur := ParseTimeRange(timeRange)
	since := time.Now().Add(-dur)

	routes, err := s.ListRoutes(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	usageSvc := s.GetUsageService()
	if usageSvc == nil {
		return &RouteTelemetryOverviewResponse{
			TenantID:  tenantID,
			TimeRange: normRange,
			ProjectID: projectID,
			Summary:   RouteTelemetrySummary{SuccessRate: 100.0},
			Routes:    []*RouteTelemetryItem{},
			CachedAt:  time.Now().Unix(),
		}, nil
	}

	reqFilter := usage.RequestFilter{
		TenantID:  tenantID,
		ProjectID: projectID,
		StartTime: &since,
		Limit:     10000,
	}
	reqRecords, _, _ := usageSvc.ListRequestRecords(ctx, reqFilter)

	useFilter := usage.UsageFilter{
		TenantID:  tenantID,
		ProjectID: projectID,
		StartTime: &since,
		Limit:     10000,
	}
	useRecords, _, _ := usageSvc.ListUsageEvents(ctx, useFilter)

	routeItemsMap := make(map[string]*RouteTelemetryItem)
	routeLatencies := make(map[string][]int64)

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

	allLatencies := make([]int64, 0, len(reqRecords))
	var totalCalls, totalSuccess, totalBlocked, totalUpErr int64

	for _, req := range reqRecords {
		totalCalls++
		isOk := req.StatusCode >= 200 && req.StatusCode < 400
		isBlocked := req.StatusCode >= 400 && req.StatusCode < 500
		isUpErr := req.StatusCode >= 500

		if isOk {
			totalSuccess++
		}
		if isBlocked {
			totalBlocked++
		}
		if isUpErr {
			totalUpErr++
		}
		allLatencies = append(allLatencies, req.DurationMs)

		item, ok := routeItemsMap[req.RouteID]
		if !ok {
			item = &RouteTelemetryItem{
				RouteID:     req.RouteID,
				ModelName:   req.RouteID,
				Title:       req.RouteID,
				RouteType:   "api",
				Status:      "active",
				SuccessRate: 100.0,
			}
			routeItemsMap[req.RouteID] = item
		}
		item.Calls++
		if isOk {
			item.SuccessCalls++
		}
		if isBlocked {
			item.BlockedCalls++
		}
		if isUpErr {
			item.UpstreamErrorCalls++
		}
		routeLatencies[req.RouteID] = append(routeLatencies[req.RouteID], req.DurationMs)
	}

	var promptTok, compTok, totTok int64
	for _, u := range useRecords {
		promptTok += u.PromptTokens
		compTok += u.CompletionTokens
		totTok += u.TotalTokens

		if item, ok := routeItemsMap[u.RouteID]; ok {
			item.PromptTokens += u.PromptTokens
			item.CompletionTokens += u.CompletionTokens
			item.TotalTokens += u.TotalTokens
			item.CostAmount += u.AmountBaseUnits
		}
	}

	routeList := make([]*RouteTelemetryItem, 0, len(routeItemsMap))
	for _, item := range routeItemsMap {
		lats := routeLatencies[item.RouteID]
		if len(lats) > 0 {
			var okCount int64
			var sumLat int64
			for _, lat := range lats {
				sumLat += lat
			}
			item.AvgDurationMs = sumLat / int64(len(lats))

			sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
			p95Idx := int(float64(len(lats)-1) * 0.95)
			if p95Idx >= 0 && p95Idx < len(lats) {
				item.P95DurationMs = lats[p95Idx]
			}
			for _, req := range reqRecords {
				if req.RouteID == item.RouteID && req.StatusCode >= 200 && req.StatusCode < 400 {
					okCount++
				}
			}
			item.SuccessRate = float64(int((float64(okCount)/float64(len(lats)))*1000)) / 10.0
		}
		routeList = append(routeList, item)
	}

	sort.Slice(routeList, func(i, j int) bool {
		return routeList[i].Calls > routeList[j].Calls
	})

	var overallSuccessRate float64 = 100.0
	if totalCalls > 0 {
		overallSuccessRate = float64(int((float64(totalSuccess)/float64(totalCalls))*1000)) / 10.0
	}
	var avgDuration int64
	var p95Duration int64
	if len(allLatencies) > 0 {
		var sumLat int64
		for _, lat := range allLatencies {
			sumLat += lat
		}
		avgDuration = sumLat / int64(len(allLatencies))

		sort.Slice(allLatencies, func(i, j int) bool { return allLatencies[i] < allLatencies[j] })
		p95Idx := int(float64(len(allLatencies)-1) * 0.95)
		if p95Idx >= 0 && p95Idx < len(allLatencies) {
			p95Duration = allLatencies[p95Idx]
		}
	}

	return &RouteTelemetryOverviewResponse{
		TenantID:  tenantID,
		TimeRange: normRange,
		ProjectID: projectID,
		Summary: RouteTelemetrySummary{
			TotalCalls:         totalCalls,
			SuccessCalls:       totalSuccess,
			BlockedCalls:       totalBlocked,
			UpstreamErrorCalls: totalUpErr,
			SuccessRate:        overallSuccessRate,
			AvgDurationMs:      avgDuration,
			P95DurationMs:      p95Duration,
			TotalTokens:        totTok,
			PromptTokens:       promptTok,
			CompletionTokens:   compTok,
			FailedCalls:        totalCalls - totalSuccess,
		},
		Routes:   routeList,
		CachedAt: time.Now().Unix(),
	}, nil
}

func (s *MemoryService) GetPaymentAudit(ctx context.Context, tenantID, intentID string, actorMemberID string) (*payment.PaymentAuditRecord, error) {
	if err := s.enforceAuditRead(ctx, tenantID, actorMemberID); err != nil {
		return nil, err
	}
	return s.GetPaymentService().GetPaymentAudit(ctx, tenantID, intentID)
}

func (s *MemoryService) GetPaymentAuditByRequestID(ctx context.Context, tenantID, requestID string, actorMemberID string) (*payment.PaymentAuditRecord, error) {
	if err := s.enforceAuditRead(ctx, tenantID, actorMemberID); err != nil {
		return nil, err
	}
	return s.GetPaymentService().GetPaymentAuditByRequestID(ctx, tenantID, requestID)
}

func (s *MemoryService) ListPaymentAudits(ctx context.Context, tenantID string, filter payment.PaymentAuditFilter, actorMemberID string) ([]*payment.PaymentAuditRecord, int64, error) {
	if err := s.enforceAuditRead(ctx, tenantID, actorMemberID); err != nil {
		return nil, 0, err
	}
	filter.TenantID = tenantID
	return s.GetPaymentService().ListPaymentAudits(ctx, filter)
}

