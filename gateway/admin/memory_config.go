package admin

import (
	"context"
	"fmt"
	"github.com/open-agentpay/agent-core-sdk/gateway/rcu"
	"strings"
	"time"
)

func (s *MemoryService) tenantRoutesAndPoliciesLocked(tenantID string) ([]*Route, []*Policy) {
	routes := make([]*Route, 0)
	for _, r := range s.routes {
		if r.TenantID == tenantID {
			routes = append(routes, r)
		}
	}
	policies := make([]*Policy, 0)
	for _, p := range s.policies {
		if p.TenantID == tenantID {
			policies = append(policies, p)
		}
	}
	return routes, policies
}

func (s *MemoryService) ValidateConfig(ctx context.Context, tenantID string, actorMemberID string) (*ValidationResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.tenants[tenantID]; !ok {
		return nil, ErrTenantNotFound
	}
	if err := s.checkPermissionLocked(tenantID, actorMemberID, PermissionRouteRead); err != nil {
		return nil, err
	}

	routes, policies := s.tenantRoutesAndPoliciesLocked(tenantID)
	res := evaluateConfigValidation(routes, policies)

	if s.lastValidation == nil {
		s.lastValidation = make(map[string]*ValidationResult)
	}
	s.lastValidation[tenantID] = res

	s.recordAudit(tenantID, actorMemberID, "config.validated", "Tenant", tenantID, nil, map[string]interface{}{
		"valid":       res.Valid,
		"error_count": len(res.Errors),
	}, "127.0.0.1")

	return res, nil
}

func (s *MemoryService) GetDraftSummary(ctx context.Context, tenantID string) (*ConfigDraftSummary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	routes, policies := s.tenantRoutesAndPoliciesLocked(tenantID)
	var lastRes *ValidationResult
	if s.lastValidation != nil {
		lastRes = s.lastValidation[tenantID]
	}
	return buildDraftSummary(tenantID, len(routes), len(policies), lastRes), nil
}

func (s *MemoryService) GetDraftDiff(ctx context.Context, tenantID string) (*ConfigDraftDiff, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	routes, policies := s.tenantRoutesAndPoliciesLocked(tenantID)
	return buildDraftDiff(tenantID, routes, policies), nil
}

func (s *MemoryService) resolvePublisherEmailLocked(tenantID, actorMemberID string) (string, error) {
	if actorMemberID == "" {
		return "", ErrPermissionDenied
	}
	actor, ok := s.members[actorMemberID]
	if !ok || actor.TenantID != tenantID {
		return "", ErrPermissionDenied
	}
	if err := EnforcePermission(actor, PermissionRouteWrite); err != nil {
		return "", err
	}
	return actor.Email, nil
}

func (s *MemoryService) nextVersionNumberLocked(tenantID string) int64 {
	var maxVerNum int64
	for _, v := range s.configVersionHistory[tenantID] {
		if v.VersionNumber > maxVerNum {
			maxVerNum = v.VersionNumber
		}
	}
	return maxVerNum + 1
}

func (s *MemoryService) PublishConfig(ctx context.Context, tenantID string, changeSummary string, actorMemberID string) (*ConfigVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.tenants[tenantID]; !ok {
		return nil, ErrTenantNotFound
	}
	publisherEmail, err := s.resolvePublisherEmailLocked(tenantID, actorMemberID)
	if err != nil {
		return nil, err
	}

	routes, policies := s.tenantRoutesAndPoliciesLocked(tenantID)
	if valRes := evaluateConfigValidation(routes, policies); !valRes.Valid {
		return nil, ErrConfigValidationFailed
	}

	rcuRoutes, rcuPolicies := buildRCUSnapshotConfigs(routes, policies)
	snapshotHash := rcu.ComputeCanonicalSnapshotHash(rcuRoutes, rcuPolicies)
	newVersionNumber := s.nextVersionNumberLocked(tenantID)
	versionID := GenerateConfigVersionID()
	now := time.Now().Unix()

	summary := strings.TrimSpace(changeSummary)
	if summary == "" {
		summary = fmt.Sprintf("Publish configuration version v%d", newVersionNumber)
	}

	snap := &rcu.ConfigSnapshot{
		SchemaVersion: "2.0.0",
		TenantID:      tenantID,
		VersionID:     versionID,
		VersionNumber: newVersionNumber,
		PublishedAt:   now,
		PublishedBy:   actorMemberID,
		ChangeSummary: summary,
		SnapshotHash:  snapshotHash,
		Routes:        rcuRoutes,
		Policies:      rcuPolicies,
	}

	for _, v := range s.configVersionHistory[tenantID] {
		v.IsActive = false
	}

	newVer := &ConfigVersion{
		VersionID:      versionID,
		TenantID:       tenantID,
		VersionNumber:  newVersionNumber,
		SnapshotJSON:   snap,
		SnapshotHash:   snapshotHash,
		PublishedBy:    actorMemberID,
		PublisherEmail: publisherEmail,
		ChangeSummary:  summary,
		IsActive:       true,
		RoutesCount:    len(rcuRoutes),
		PoliciesCount:  len(rcuPolicies),
		CreatedAt:      now,
	}

	s.configVersions[versionID] = newVer
	s.configVersionHistory[tenantID] = append(s.configVersionHistory[tenantID], newVer)

	if s.rcuMgr != nil {
		_ = s.rcuMgr.Update(snap)
	}

	s.recordAudit(tenantID, actorMemberID, "config.published", "ConfigVersion", versionID, nil, map[string]interface{}{
		"version_number": newVersionNumber,
		"snapshot_hash":  snapshotHash,
		"change_summary": summary,
		"routes_count":   len(rcuRoutes),
		"policies_count": len(rcuPolicies),
	}, "127.0.0.1")

	return newVer, nil
}

func (s *MemoryService) ListConfigVersions(ctx context.Context, tenantID string) ([]*ConfigVersion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	history := s.configVersionHistory[tenantID]
	if len(history) == 0 {
		return []*ConfigVersion{}, nil
	}
	res := make([]*ConfigVersion, len(history))
	for i, v := range history {
		res[len(history)-1-i] = v
	}
	return res, nil
}

func (s *MemoryService) GetConfigVersion(ctx context.Context, tenantID, versionID string) (*ConfigVersion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ver, ok := s.configVersions[versionID]
	if !ok || ver.TenantID != tenantID {
		return nil, ErrConfigVersionNotFound
	}
	return ver, nil
}

func (s *MemoryService) RollbackConfig(ctx context.Context, tenantID, targetVersionID, reason, actorMemberID string) (*ConfigVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.tenants[tenantID]; !ok {
		return nil, ErrTenantNotFound
	}
	publisherEmail, err := s.resolvePublisherEmailLocked(tenantID, actorMemberID)
	if err != nil {
		return nil, err
	}

	targetVer, ok := s.configVersions[targetVersionID]
	if !ok || targetVer.TenantID != tenantID {
		return nil, ErrConfigVersionNotFound
	}
	if targetVer.IsActive {
		return nil, ErrCannotRollbackToActive
	}

	newVersionNumber := s.nextVersionNumberLocked(tenantID)
	versionID := GenerateConfigVersionID()
	now := time.Now().Unix()

	restoredSnap, summary := buildRestoredSnapshot(tenantID, versionID, actorMemberID, reason, newVersionNumber, now, targetVer)

	for _, v := range s.configVersionHistory[tenantID] {
		v.IsActive = false
	}

	newVer := &ConfigVersion{
		VersionID:      versionID,
		TenantID:       tenantID,
		VersionNumber:  newVersionNumber,
		SnapshotJSON:   restoredSnap,
		SnapshotHash:   targetVer.SnapshotHash,
		PublishedBy:    actorMemberID,
		PublisherEmail: publisherEmail,
		ChangeSummary:  summary,
		IsActive:       true,
		RoutesCount:    len(restoredSnap.Routes),
		PoliciesCount:  len(restoredSnap.Policies),
		CreatedAt:      now,
	}

	s.configVersions[versionID] = newVer
	s.configVersionHistory[tenantID] = append(s.configVersionHistory[tenantID], newVer)

	for id, r := range s.routes {
		if r.TenantID == tenantID {
			delete(s.routes, id)
		}
	}
	for _, rr := range restoredSnap.Routes {
		s.routes[rr.RouteID] = &Route{
			RouteID:               rr.RouteID,
			TenantID:              tenantID,
			ProjectID:             rr.ProjectID,
			PathPattern:           rr.PathPattern,
			UpstreamURL:           rr.UpstreamURL,
			PriceBaseUnits:        rr.PriceBaseUnits,
			Asset:                 rr.Asset,
			PayeeAddress:          rr.PayeeAddress,
			AllowedPaymentMethods: rr.AllowedPaymentMethods,
			TimeoutMs:             rr.TimeoutMS,
			RateLimitRPM:          rr.RateLimitRPM,
			Status:                RouteStatus(rr.Status),
			UpstreamAuth:          rr.UpstreamAuth,
			CreatedAt:             now,
			UpdatedAt:             now,
		}
	}

	if s.rcuMgr != nil {
		_ = s.rcuMgr.Update(restoredSnap)
	}

	s.recordAudit(tenantID, actorMemberID, "config.rolled_back", "ConfigVersion", versionID, map[string]interface{}{
		"target_version_id":     targetVer.VersionID,
		"target_version_number": targetVer.VersionNumber,
	}, map[string]interface{}{
		"new_version_id":     versionID,
		"new_version_number": newVersionNumber,
		"active_hash":        targetVer.SnapshotHash,
		"reason":             reason,
	}, "127.0.0.1")

	return newVer, nil
}

func (s *MemoryService) GetConfigVersionDiff(ctx context.Context, tenantID, baseVersionID, targetVersionID string) (*ConfigDraftDiff, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var baseSnap, targetSnap *rcu.ConfigSnapshot
	if baseVersionID != "" {
		v, ok := s.configVersions[baseVersionID]
		if !ok || v.TenantID != tenantID {
			return nil, ErrConfigVersionNotFound
		}
		baseSnap = v.SnapshotJSON
	} else {
		for _, v := range s.configVersionHistory[tenantID] {
			if v.IsActive {
				baseSnap = v.SnapshotJSON
				break
			}
		}
	}

	if targetVersionID != "" {
		v, ok := s.configVersions[targetVersionID]
		if !ok || v.TenantID != tenantID {
			return nil, ErrConfigVersionNotFound
		}
		targetSnap = v.SnapshotJSON
	}

	return computeSnapshotDiff(tenantID, baseSnap, targetSnap), nil
}

// ----------------------------------------------------------------------------
// Upstream Authentication & Connectivity Testing (T4.2 Enhancement)
// ----------------------------------------------------------------------------

