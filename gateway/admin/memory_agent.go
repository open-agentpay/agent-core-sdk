package admin

import (
	"context"
	"fmt"
	"github.com/open-agentpay/agent-core-sdk/gateway/agent"
	"github.com/open-agentpay/agent-core-sdk/gateway/timeline"
	"github.com/open-agentpay/agent-core-sdk/gateway/wallet"
	"strings"
	"time"
)

func (s *MemoryService) CreateAgent(ctx context.Context, tenantID, projectID, name string, policyCfg map[string]interface{}, actorMemberID string) (*Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	proj, ok := s.projects[projectID]
	if !ok || proj.TenantID != tenantID {
		return nil, ErrProjectNotFound
	}
	if proj.Status == ProjectStatusArchived {
		return nil, ErrProjectArchived
	}
	if err := s.checkPermissionLocked(tenantID, actorMemberID, PermissionAgentCreate); err != nil {
		return nil, err
	}

	cleanName := strings.TrimSpace(name)
	if cleanName == "" {
		return nil, fmt.Errorf("agent name cannot be empty")
	}
	for _, a := range s.agents {
		if a.ProjectID == projectID && a.Name == cleanName {
			return nil, ErrAgentAlreadyExists
		}
	}

	now := time.Now().Unix()
	aid := GenerateAgentID()
	if policyCfg == nil {
		policyCfg = make(map[string]interface{})
	}

	ag := &Agent{
		AgentID:             aid,
		TenantID:            tenantID,
		ProjectID:           projectID,
		Name:                cleanName,
		Status:              AgentStatusActive,
		PolicyConfig:        policyCfg,
		CreatedAt:           now,
		UpdatedAt:           now,
		RequestsCount:       0,
		TotalSpendBaseUnits: 0,
		RejectRate:          "0.0%",
	}
	s.agents[aid] = ag

	if s.agentRegistry != nil {
		s.agentRegistry.RegisterAgent(&agent.AgentIdentity{
			AgentID:   aid,
			TenantID:  tenantID,
			ProjectID: projectID,
			Name:      cleanName,
			Status:    agent.AgentStatusActive,
		}, nil)
	}

	s.recordAudit(tenantID, actorMemberID, "agent.created", "Agent", aid, nil, map[string]interface{}{"name": cleanName, "project_id": projectID}, "127.0.0.1")
	return ag, nil
}

func (s *MemoryService) GetAgent(ctx context.Context, tenantID, agentID string) (*Agent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ag, ok := s.agents[agentID]
	if !ok {
		return nil, ErrAgentNotFound
	}
	if tenantID != "" && ag.TenantID != tenantID {
		return nil, ErrAgentTenantMismatch
	}
	return ag, nil
}

func (s *MemoryService) ListAgents(ctx context.Context, tenantID, projectID string, status *AgentStatus) ([]*Agent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make([]*Agent, 0)
	for _, a := range s.agents {
		if tenantID != "" && a.TenantID != tenantID {
			continue
		}
		if projectID != "" && a.ProjectID != projectID {
			continue
		}
		if status != nil && a.Status != *status {
			continue
		}
		res = append(res, a)
	}
	return res, nil
}

func (s *MemoryService) UpdateAgent(ctx context.Context, tenantID, agentID string, name string, policyCfg map[string]interface{}, actorMemberID string) (*Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ag, ok := s.agents[agentID]
	if !ok {
		return nil, ErrAgentNotFound
	}
	if ag.TenantID != tenantID {
		return nil, ErrAgentTenantMismatch
	}
	if ag.Status == AgentStatusRevoked {
		return nil, ErrAgentRevoked
	}
	if err := s.checkPermissionLocked(tenantID, actorMemberID, PermissionAgentUpdate); err != nil {
		return nil, err
	}

	before := map[string]interface{}{"name": ag.Name, "policy_config": ag.PolicyConfig}
	if name != "" {
		cleanName := strings.TrimSpace(name)
		for _, other := range s.agents {
			if other.AgentID != agentID && other.ProjectID == ag.ProjectID && other.Name == cleanName {
				return nil, ErrAgentAlreadyExists
			}
		}
		ag.Name = cleanName
	}
	if policyCfg != nil {
		ag.PolicyConfig = policyCfg
	}
	ag.UpdatedAt = time.Now().Unix()

	s.recordAudit(tenantID, actorMemberID, "agent.updated", "Agent", agentID, before, map[string]interface{}{"name": ag.Name, "policy_config": ag.PolicyConfig}, "127.0.0.1")
	return ag, nil
}

func (s *MemoryService) UpdateAgentStatus(ctx context.Context, tenantID, agentID string, status AgentStatus, actorMemberID string) (*Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ag, ok := s.agents[agentID]
	if !ok {
		return nil, ErrAgentNotFound
	}
	if ag.TenantID != tenantID {
		return nil, ErrAgentTenantMismatch
	}
	if ag.Status == AgentStatusRevoked && status != AgentStatusRevoked {
		return nil, ErrInvalidStatusTransition
	}

	reqPerm := PermissionAgentUpdate
	if status == AgentStatusRevoked || status == AgentStatusSuspended {
		reqPerm = PermissionAgentKill
	}
	if err := s.checkPermissionLocked(tenantID, actorMemberID, reqPerm); err != nil {
		return nil, err
	}

	before := map[string]interface{}{"status": string(ag.Status)}
	ag.Status = status
	ag.UpdatedAt = time.Now().Unix()

	if status == AgentStatusRevoked {
		for _, k := range s.apiKeys {
			if k.AgentID == agentID && k.Status == APIKeyStatusActive {
				k.Status = APIKeyStatusRevoked
				k.UpdatedAt = ag.UpdatedAt
			}
		}
	}
	if s.agentRegistry != nil {
		s.agentRegistry.SetAgentStatus(agentID, agent.AgentStatus(status))
	}

	s.recordAudit(tenantID, actorMemberID, "agent.status.changed", "Agent", agentID, before, map[string]interface{}{"status": string(status)}, "127.0.0.1")
	return ag, nil
}

func (s *MemoryService) KillAgent(ctx context.Context, tenantID, agentID, reason string, actorMemberID string, revoke bool, clientIP string) (*Agent, []string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cleanReason := strings.TrimSpace(reason)
	if cleanReason == "" {
		return nil, nil, ErrMissingReason
	}

	ag, ok := s.agents[agentID]
	if !ok {
		return nil, nil, ErrAgentNotFound
	}
	if ag.TenantID != tenantID {
		return nil, nil, ErrAgentTenantMismatch
	}
	if ag.Status == AgentStatusRevoked {
		return nil, nil, ErrInvalidStatusTransition
	}
	if actorMemberID == "" {
		return nil, nil, ErrPermissionDenied
	}
	if err := s.checkPermissionLocked(tenantID, actorMemberID, PermissionAgentKill); err != nil {
		return nil, nil, err
	}

	targetStatus := AgentStatusSuspended
	if revoke {
		targetStatus = AgentStatusRevoked
	}

	now := time.Now().Unix()
	before := map[string]interface{}{"status": string(ag.Status)}
	ag.Status = targetStatus
	ag.UpdatedAt = now

	revokedKeys := make([]string, 0)
	for _, k := range s.apiKeys {
		if k.AgentID == agentID && k.Status == APIKeyStatusActive {
			k.Status = APIKeyStatusRevoked
			k.UpdatedAt = now
			revokedKeys = append(revokedKeys, k.KeyID)
		}
	}

	if s.agentRegistry != nil {
		s.agentRegistry.SetAgentStatus(agentID, agent.AgentStatus(targetStatus))
	}

	after := map[string]interface{}{
		"status":       string(targetStatus),
		"reason":       cleanReason,
		"revoked_keys": revokedKeys,
		"revoke":       revoke,
	}
	s.recordAudit(tenantID, actorMemberID, "agent.control", "Agent", agentID, before, after, clientIP)
	return ag, revokedKeys, nil
}

func (s *MemoryService) DeleteAgent(ctx context.Context, tenantID, agentID, actorMemberID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ag, ok := s.agents[agentID]
	if !ok {
		return ErrAgentNotFound
	}
	if ag.TenantID != tenantID {
		return ErrAgentTenantMismatch
	}
	if err := s.checkPermissionLocked(tenantID, actorMemberID, PermissionAgentKill); err != nil {
		return err
	}

	for _, k := range s.apiKeys {
		if k.AgentID == agentID {
			k.Status = APIKeyStatusRevoked
		}
	}
	delete(s.agents, agentID)

	s.recordAudit(tenantID, actorMemberID, "agent.deleted", "Agent", agentID, map[string]interface{}{"name": ag.Name}, nil, "127.0.0.1")
	return nil
}

// ----------------------------------------------------------------------------
// API Keys
// ----------------------------------------------------------------------------

func (s *MemoryService) CreateAPIKey(ctx context.Context, tenantID, projectID, agentID, name string, scopes []string, expiresAt *int64, actorMemberID string) (*CreateAPIKeyResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ag, ok := s.agents[agentID]
	if !ok || ag.TenantID != tenantID || ag.ProjectID != projectID {
		return nil, ErrAgentNotFound
	}
	if err := s.checkPermissionLocked(tenantID, actorMemberID, PermissionAPIKeyCreate); err != nil {
		return nil, err
	}

	rawKey, keyHash, keyPrefix := GenerateRawAPIKey()
	now := time.Now().Unix()
	if scopes == nil {
		scopes = []string{"gateway:call"}
	}

	k := &APIKey{
		KeyID:     GenerateAPIKeyID(),
		TenantID:  tenantID,
		ProjectID: projectID,
		AgentID:   agentID,
		Name:      strings.TrimSpace(name),
		KeyHash:   keyHash,
		KeyPrefix: keyPrefix,
		Scopes:    scopes,
		Status:    APIKeyStatusActive,
		ExpiresAt: expiresAt,
		CreatedAt: now,
		UpdatedAt: now,
	}
	s.apiKeys[k.KeyID] = k

	if s.agentRegistry != nil {
		s.agentRegistry.BindAPIKeyHash(keyHash, agentID)
	}
	if s.walletSvc != nil {
		if memWlt, ok := s.walletSvc.(*wallet.MemoryService); ok {
			memWlt.RegisterAPIKey(rawKey, tenantID, projectID, agentID)
		}
	}

	s.recordAudit(tenantID, actorMemberID, "apikey.created", "ApiKey", k.KeyID, nil, map[string]interface{}{"name": k.Name, "agent_id": agentID}, "127.0.0.1")
	return &CreateAPIKeyResult{APIKey: k, RawKey: rawKey}, nil
}

func (s *MemoryService) GetAPIKey(ctx context.Context, tenantID, keyID string) (*APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	k, ok := s.apiKeys[keyID]
	if !ok || (tenantID != "" && k.TenantID != tenantID) {
		return nil, ErrAPIKeyNotFound
	}
	return k, nil
}

func (s *MemoryService) ListAPIKeys(ctx context.Context, tenantID, agentID string) ([]*APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make([]*APIKey, 0)
	for _, k := range s.apiKeys {
		if tenantID != "" && k.TenantID != tenantID {
			continue
		}
		if agentID != "" && k.AgentID != agentID {
			continue
		}
		res = append(res, k)
	}
	return res, nil
}

func (s *MemoryService) RevokeAPIKey(ctx context.Context, tenantID, keyID, actorMemberID string) (*APIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	k, ok := s.apiKeys[keyID]
	if !ok || k.TenantID != tenantID {
		return nil, ErrAPIKeyNotFound
	}
	if err := s.checkPermissionLocked(tenantID, actorMemberID, PermissionAPIKeyRevoke); err != nil {
		return nil, err
	}

	k.Status = APIKeyStatusRevoked
	k.UpdatedAt = time.Now().Unix()

	s.recordAudit(tenantID, actorMemberID, "apikey.revoked", "ApiKey", keyID, nil, map[string]interface{}{"status": "revoked"}, "127.0.0.1")
	return k, nil
}

func (s *MemoryService) RotateAPIKey(ctx context.Context, tenantID, keyID, actorMemberID string) (*CreateAPIKeyResult, error) {
	oldKey, err := s.RevokeAPIKey(ctx, tenantID, keyID, actorMemberID)
	if err != nil {
		return nil, err
	}
	return s.CreateAPIKey(ctx, tenantID, oldKey.ProjectID, oldKey.AgentID, oldKey.Name, oldKey.Scopes, oldKey.ExpiresAt, actorMemberID)
}

// ----------------------------------------------------------------------------
// Routes & Policies
// ----------------------------------------------------------------------------

func (s *MemoryService) GetAgentTimeline(ctx context.Context, tenantID, agentID string, filter timeline.TimelineFilter, actorMemberID string) ([]*timeline.TimelineEvent, int64, []string, error) {
	if err := s.enforceAuditRead(ctx, tenantID, actorMemberID); err != nil {
		return nil, 0, nil, err
	}
	ag, err := s.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		return nil, 0, nil, err
	}
	if ag == nil || ag.TenantID != tenantID {
		return nil, 0, nil, ErrAgentNotFound
	}
	filter.TenantID = tenantID
	filter.AgentID = agentID
	return s.GetTimelineService().GetTimeline(ctx, tenantID, agentID, filter)
}
