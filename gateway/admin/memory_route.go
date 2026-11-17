package admin

import (
	"context"
	"fmt"
	"strings"
	"time"
)

func (s *MemoryService) CreateRoute(ctx context.Context, r *Route, actorMemberID string) (*Route, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.checkPermissionLocked(r.TenantID, actorMemberID, PermissionRouteWrite); err != nil {
		return nil, err
	}

	if r.ProjectID != "" {
		p, ok := s.projects[r.ProjectID]
		if !ok || p.TenantID != r.TenantID {
			return nil, ErrProjectNotFound
		}
	}

	cleanPath := strings.TrimSpace(r.PathPattern)
	for _, existing := range s.routes {
		if existing.TenantID == r.TenantID && existing.PathPattern == cleanPath {
			return nil, ErrRouteAlreadyExists
		}
	}

	var tenantCurrency string
	if t, ok := s.tenants[r.TenantID]; ok {
		tenantCurrency = t.Currency
	}
	if err := normalizeNewRoute(r, tenantCurrency, time.Now().Unix()); err != nil {
		return nil, err
	}

	s.routes[r.RouteID] = r
	s.recordAudit(r.TenantID, actorMemberID, "route.created", "Route", r.RouteID, nil, map[string]interface{}{
		"path":         r.PathPattern,
		"slug":         r.Slug,
		"is_public":    r.IsPublic,
		"upstream_url": r.UpstreamURL,
		"price":        r.PriceBaseUnits,
		"status":       string(r.Status),
	}, "127.0.0.1")
	_ = s.syncRCULocked()
	return r, nil
}

func (s *MemoryService) GetRoute(ctx context.Context, tenantID, routeID string) (*Route, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	r, ok := s.routes[routeID]
	if !ok || (tenantID != "" && r.TenantID != tenantID) {
		return nil, ErrRouteNotFound
	}
	return r, nil
}

func (s *MemoryService) ListRoutes(ctx context.Context, tenantID string) ([]*Route, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make([]*Route, 0)
	for _, r := range s.routes {
		if tenantID == "" || r.TenantID == tenantID {
			res = append(res, r)
		}
	}
	return res, nil
}

func (s *MemoryService) UpdateRoute(ctx context.Context, input *UpdateRouteInput, actorMemberID string) (*Route, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.routes[input.RouteID]
	if !ok || existing.TenantID != input.TenantID {
		return nil, ErrRouteNotFound
	}
	if err := s.checkPermissionLocked(input.TenantID, actorMemberID, PermissionRouteWrite); err != nil {
		return nil, err
	}

	before := map[string]interface{}{
		"project_id":              existing.ProjectID,
		"slug":                    existing.Slug,
		"is_public":               existing.IsPublic,
		"path_pattern":            existing.PathPattern,
		"upstream_url":            existing.UpstreamURL,
		"price_base_units":        existing.PriceBaseUnits,
		"asset":                   existing.Asset,
		"payee_address":           existing.PayeeAddress,
		"allowed_payment_methods": existing.AllowedPaymentMethods,
		"rate_limit_rpm":          existing.RateLimitRPM,
		"timeout_ms":              existing.TimeoutMs,
		"status":                  string(existing.Status),
	}

	if input.PathPattern != nil {
		cleanPath := strings.TrimSpace(*input.PathPattern)
		if cleanPath == "" {
			return nil, fmt.Errorf("path_pattern cannot be empty")
		}
		if !strings.HasPrefix(cleanPath, "/") {
			return nil, fmt.Errorf("path_pattern must begin with /")
		}
		for _, other := range s.routes {
			if other.RouteID != input.RouteID && other.TenantID == input.TenantID && other.PathPattern == cleanPath {
				return nil, ErrRouteAlreadyExists
			}
		}
		existing.PathPattern = cleanPath
	}

	if input.ProjectID != nil {
		pID := strings.TrimSpace(*input.ProjectID)
		if pID != "" {
			p, ok := s.projects[pID]
			if !ok || p.TenantID != input.TenantID {
				return nil, ErrProjectNotFound
			}
		}
		existing.ProjectID = pID
	}

	if err := applyRouteUpdateFields(existing, input, time.Now().Unix()); err != nil {
		return nil, err
	}

	s.recordAudit(input.TenantID, actorMemberID, "route.updated", "Route", input.RouteID, before, map[string]interface{}{
		"path_pattern":            existing.PathPattern,
		"slug":                    existing.Slug,
		"is_public":               existing.IsPublic,
		"upstream_url":            existing.UpstreamURL,
		"price_base_units":        existing.PriceBaseUnits,
		"payee_address":           existing.PayeeAddress,
		"allowed_payment_methods": existing.AllowedPaymentMethods,
		"timeout_ms":              existing.TimeoutMs,
		"status":                  string(existing.Status),
	}, "127.0.0.1")

	_ = s.syncRCULocked()
	return existing, nil
}

func (s *MemoryService) DeleteRoute(ctx context.Context, tenantID, routeID, actorMemberID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.routes[routeID]
	if !ok || existing.TenantID != tenantID {
		return ErrRouteNotFound
	}
	if err := s.checkPermissionLocked(tenantID, actorMemberID, PermissionRouteWrite); err != nil {
		return err
	}

	delete(s.routes, routeID)
	s.recordAudit(tenantID, actorMemberID, "route.deleted", "Route", routeID, map[string]interface{}{"path": existing.PathPattern}, nil, "127.0.0.1")
	_ = s.syncRCULocked()
	return nil
}

func (s *MemoryService) CreatePolicy(ctx context.Context, pol *Policy, actorMemberID string) (*Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if pol == nil {
		return nil, fmt.Errorf("policy cannot be nil")
	}
	if err := s.checkPermissionLocked(pol.TenantID, actorMemberID, PermissionPolicyWrite); err != nil {
		return nil, err
	}

	if pol.PolicyID == "" {
		pol.PolicyID = GeneratePolicyID()
	}
	now := time.Now().Unix()
	pol.CreatedAt = now
	pol.UpdatedAt = now
	pol.IsActive = true
	s.policies[pol.PolicyID] = pol

	s.recordAudit(pol.TenantID, actorMemberID, "policy.created", "Policy", pol.PolicyID, nil, nil, "127.0.0.1")
	_ = s.syncRCULocked()
	return pol, nil
}

func (s *MemoryService) GetPolicy(ctx context.Context, tenantID, policyID string) (*Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	pol, ok := s.policies[policyID]
	if !ok || (tenantID != "" && pol.TenantID != tenantID) {
		return nil, ErrPolicyNotFound
	}
	return pol, nil
}

func (s *MemoryService) ListPolicies(ctx context.Context, tenantID, projectID, agentID string) ([]*Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make([]*Policy, 0)
	for _, p := range s.policies {
		if tenantID != "" && p.TenantID != tenantID {
			continue
		}
		if projectID != "" && p.ProjectID != projectID {
			continue
		}
		if agentID != "" && p.AgentID != agentID {
			continue
		}
		res = append(res, p)
	}
	return res, nil
}

func (s *MemoryService) UpdatePolicy(ctx context.Context, pol *Policy, actorMemberID string) (*Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if pol == nil {
		return nil, fmt.Errorf("policy cannot be nil")
	}
	if err := s.checkPermissionLocked(pol.TenantID, actorMemberID, PermissionPolicyWrite); err != nil {
		return nil, err
	}

	existing, ok := s.policies[pol.PolicyID]
	if !ok || existing.TenantID != pol.TenantID {
		return nil, ErrPolicyNotFound
	}
	pol.UpdatedAt = time.Now().Unix()
	s.policies[pol.PolicyID] = pol

	s.recordAudit(pol.TenantID, actorMemberID, "policy.updated", "Policy", pol.PolicyID, nil, nil, "127.0.0.1")
	_ = s.syncRCULocked()
	return pol, nil
}

func (s *MemoryService) DeletePolicy(ctx context.Context, tenantID, policyID, actorMemberID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.checkPermissionLocked(tenantID, actorMemberID, PermissionPolicyWrite); err != nil {
		return err
	}
	existing, ok := s.policies[policyID]
	if !ok || existing.TenantID != tenantID {
		return ErrPolicyNotFound
	}
	delete(s.policies, policyID)

	s.recordAudit(tenantID, actorMemberID, "policy.deleted", "Policy", policyID, nil, nil, "127.0.0.1")
	_ = s.syncRCULocked()
	return nil
}

// ----------------------------------------------------------------------------
// RCU Data Plane Synchronization
// ----------------------------------------------------------------------------

