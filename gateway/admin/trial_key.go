package admin

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/open-agentpay/agent-core-sdk/gateway/wallet"
)

var (
	trialRateLimiterMu sync.Mutex
	trialIPHistory     = make(map[string][]time.Time)
)

func checkAndRecordTrialIP(clientIP string, limit int, window time.Duration) bool {
	trialRateLimiterMu.Lock()
	defer trialRateLimiterMu.Unlock()

	now := time.Now()
	cutoff := now.Add(-window)

	times := trialIPHistory[clientIP]
	valid := make([]time.Time, 0, len(times))
	for _, t := range times {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= limit {
		trialIPHistory[clientIP] = valid
		return false
	}

	valid = append(valid, now)
	trialIPHistory[clientIP] = valid
	return true
}

func (s *MemoryService) CreateTrialAPIKey(ctx context.Context, clientIP, fingerprint string) (*TrialKeyResponse, error) {
	cleanIP := strings.TrimSpace(clientIP)
	if cleanIP == "" {
		cleanIP = "127.0.0.1"
	}
	if !checkAndRecordTrialIP(cleanIP, 3, 24*time.Hour) {
		return nil, ErrTrialRateLimitExceeded
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().Unix()
	if _, ok := s.tenants[PublicSandboxTenantID]; !ok {
		s.tenants[PublicSandboxTenantID] = &Tenant{
			TenantID:  PublicSandboxTenantID,
			Name:      "OpenAgentPay Public Sandbox",
			Currency:  "CNY",
			Status:    TenantStatusActive,
			CreatedAt: now,
			UpdatedAt: now,
		}
	}
	if _, ok := s.projects[PublicSandboxProjectID]; !ok {
		s.projects[PublicSandboxProjectID] = &Project{
			ProjectID:          PublicSandboxProjectID,
			TenantID:           PublicSandboxTenantID,
			Name:               "Sandbox Trial Project",
			BudgetCapBaseUnits: 1000000000,
			Status:             ProjectStatusActive,
			CreatedAt:          now,
			UpdatedAt:          now,
		}
	}
	if _, ok := s.agents[PublicSandboxAgentID]; !ok {
		s.agents[PublicSandboxAgentID] = &Agent{
			AgentID:      PublicSandboxAgentID,
			TenantID:     PublicSandboxTenantID,
			ProjectID:    PublicSandboxProjectID,
			Name:         "Sandbox Guest Agent",
			Status:       AgentStatusActive,
			PolicyConfig: map[string]interface{}{},
			CreatedAt:    now,
			UpdatedAt:    now,
		}
	}

	rawKey, keyHash, keyPrefix := GenerateTrialRawAPIKey()
	keyID := GenerateAPIKeyID()
	expTime := now + 24*3600

	scopes := []string{"gateway:call", "marketplace:trial"}
	k := &APIKey{
		KeyID:     keyID,
		TenantID:  PublicSandboxTenantID,
		ProjectID: PublicSandboxProjectID,
		AgentID:   PublicSandboxAgentID,
		Name:      "Public Marketplace Trial Key",
		KeyHash:   keyHash,
		KeyPrefix: keyPrefix,
		Scopes:    scopes,
		Status:    APIKeyStatusActive,
		ExpiresAt: &expTime,
		CreatedAt: now,
		UpdatedAt: now,
	}
	s.apiKeys[k.KeyID] = k

	if s.agentRegistry != nil {
		s.agentRegistry.BindAPIKeyHash(keyHash, PublicSandboxAgentID)
	}
	if s.walletSvc != nil {
		if memWlt, ok := s.walletSvc.(*wallet.MemoryService); ok {
			memWlt.RegisterWallet(&wallet.Wallet{
				WalletID:       "wlt_public_sandbox",
				TenantID:       PublicSandboxTenantID,
				Asset:          "CNY",
				AvailableCache: 100000000000,
				Status:         wallet.StatusActive,
			})
			memWlt.RegisterAPIKey(rawKey, PublicSandboxTenantID, PublicSandboxProjectID, PublicSandboxAgentID)
		}
	}

	return &TrialKeyResponse{
		Success:          true,
		APIKey:           rawKey,
		BalanceCNY:       "5.00",
		BalanceBaseUnits: 5000000,
		SingleTxCapCNY:   "0.50",
		RateLimitRPM:     6,
		ExpiresAt:        expTime,
		ExpiresInHours:   24,
		ClaimURL:         "https://console.aipmedia.cn/agents?claim_key=" + rawKey,
	}, nil
}

// ClaimTrialAPIKey upgrades and migrates an anonymous trial key to an enterprise tenant (MemoryService).
func (s *MemoryService) ClaimTrialAPIKey(ctx context.Context, tenantID string, rawAPIKey string, projectID, agentID string, actorMemberID string) (*APIKey, error) {
	cleanKey := strings.TrimSpace(rawAPIKey)
	if !strings.HasPrefix(cleanKey, "apk_live_guest_") {
		return nil, errors.New("仅支持转正以 apk_live_guest_ 开头的试用测试 Key")
	}

	hash := sha256.Sum256([]byte(cleanKey))
	hashHex := hex.EncodeToString(hash[:])

	s.mu.Lock()
	defer s.mu.Unlock()

	var matched *APIKey
	for _, k := range s.apiKeys {
		if k.KeyHash == hashHex {
			matched = k
			break
		}
	}
	if matched == nil {
		return nil, errors.New("未找到该测试 Key 记录，请确认密钥无误或尚未过期")
	}

	if matched.TenantID != PublicSandboxTenantID && matched.TenantID != tenantID {
		return nil, errors.New("该测试 Key 已被其他组织认领转正")
	}

	targetProj := projectID
	if targetProj != "" {
		if p, ok := s.projects[targetProj]; !ok || p.TenantID != tenantID || p.Status != "active" {
			targetProj = ""
		}
	}
	if targetProj == "" {
		for _, p := range s.projects {
			if p.TenantID == tenantID && p.Status == "active" {
				targetProj = p.ProjectID
				break
			}
		}
	}
	if targetProj == "" {
		newPID := GenerateProjectID()
		s.projects[newPID] = &Project{
			ProjectID:          newPID,
			TenantID:           tenantID,
			Name:               "默认业务项目 (Default Project)",
			Status:             "active",
			BudgetCapBaseUnits: 1000000000,
			CreatedAt:          time.Now().Unix(),
			UpdatedAt:          time.Now().Unix(),
		}
		targetProj = newPID
	}

	targetAgent := agentID
	if targetAgent != "" {
		if a, ok := s.agents[targetAgent]; !ok || a.TenantID != tenantID || a.Status != AgentStatusActive {
			targetAgent = ""
		}
	}
	if targetAgent == "" {
		for _, a := range s.agents {
			if a.TenantID == tenantID && a.Status == AgentStatusActive {
				targetAgent = a.AgentID
				break
			}
		}
	}
	if targetAgent == "" {
		newAID := GenerateAgentID()
		s.agents[newAID] = &Agent{
			AgentID:   newAID,
			TenantID:  tenantID,
			ProjectID: targetProj,
			Name:      "默认智能体 (Default Agent)",
			Status:    AgentStatusActive,
			CreatedAt: time.Now().Unix(),
			UpdatedAt: time.Now().Unix(),
		}
		targetAgent = newAID
	}

	matched.TenantID = tenantID
	matched.ProjectID = targetProj
	matched.AgentID = targetAgent
	matched.Name = fmt.Sprintf("认领转正的测试 Key (%s)", matched.KeyPrefix)
	matched.ExpiresAt = nil
	matched.Status = APIKeyStatusActive
	matched.UpdatedAt = time.Now().Unix()

	if s.agentRegistry != nil {
		s.agentRegistry.BindAPIKeyHash(hashHex, targetAgent)
	}
	if s.walletSvc != nil {
		if memWlt, ok := s.walletSvc.(*wallet.MemoryService); ok {
			memWlt.RegisterAPIKey(cleanKey, tenantID, targetProj, targetAgent)
		}
	}

	return matched, nil
}

// CleanExpiredTrialKeys cleans up expired unclaimed guest trial keys in memory.
func (s *MemoryService) CleanExpiredTrialKeys(ctx context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().Unix()
	var count int64
	for id, k := range s.apiKeys {
		if k.TenantID == PublicSandboxTenantID && k.ExpiresAt != nil && *k.ExpiresAt < now-3600 {
			delete(s.apiKeys, id)
			count++
		}
	}
	return count, nil
}

func (p *PostgresService) CreateTrialAPIKey(ctx context.Context, clientIP, fingerprint string) (*TrialKeyResponse, error) {
	cleanIP := strings.TrimSpace(clientIP)
	if cleanIP == "" {
		cleanIP = "127.0.0.1"
	}
	if !checkAndRecordTrialIP(cleanIP, 3, 24*time.Hour) {
		return nil, ErrTrialRateLimitExceeded
	}

	// Idempotently ensure sandbox records exist
	_, _ = p.db.ExecContext(ctx, `
		INSERT INTO ap_tenant (tenant_id, name, currency, status)
		VALUES ('ten_public_sandbox', 'OpenAgentPay Public Sandbox', 'CNY', 'active')
		ON CONFLICT (tenant_id) DO NOTHING;

		INSERT INTO ap_project (project_id, tenant_id, name, budget_cap_base_units, status)
		VALUES ('prj_sandbox', 'ten_public_sandbox', 'Sandbox Trial Project', 1000000000, 'active')
		ON CONFLICT (project_id) DO NOTHING;

		INSERT INTO ap_agent (agent_id, tenant_id, project_id, name, status)
		VALUES ('agt_sandbox', 'ten_public_sandbox', 'prj_sandbox', 'Sandbox Guest Agent', 'active')
		ON CONFLICT (project_id, name) DO NOTHING;

		INSERT INTO ap_wallet (wallet_id, tenant_id, asset, status, available_cache)
		VALUES ('wlt_public_sandbox', 'ten_public_sandbox', 'CNY', 'active', 100000000000)
		ON CONFLICT (tenant_id) DO NOTHING;
	`)

	rawKey, keyHash, keyPrefix := GenerateTrialRawAPIKey()
	keyID := GenerateAPIKeyID()
	now := time.Now()
	expTime := now.Add(24 * time.Hour)
	expUnix := expTime.Unix()

	scopes := []string{"gateway:call", "marketplace:trial"}
	scopesBytes, _ := json.Marshal(scopes)

	if _, err := p.db.ExecContext(ctx, `
		INSERT INTO ap_api_key (key_id, tenant_id, project_id, agent_id, name, key_hash, key_prefix, scopes, status, expires_at, created_at, updated_at)
		VALUES ($1, 'ten_public_sandbox', 'prj_sandbox', 'agt_sandbox', 'Public Marketplace Trial Key', $2, $3, $4, 'active', $5, $6, $6);
	`, keyID, keyHash, keyPrefix, scopesBytes, expTime, now); err != nil {
		return nil, fmt.Errorf("failed to insert trial api key: %w", err)
	}

	if p.agentReg != nil {
		p.agentReg.BindAPIKeyHash(keyHash, PublicSandboxAgentID)
	}

	return &TrialKeyResponse{
		Success:          true,
		APIKey:           rawKey,
		BalanceCNY:       "5.00",
		BalanceBaseUnits: 5000000,
		SingleTxCapCNY:   "0.50",
		RateLimitRPM:     6,
		ExpiresAt:        expUnix,
		ExpiresInHours:   24,
		ClaimURL:         "https://console.aipmedia.cn/agents?claim_key=" + rawKey,
	}, nil
}

// ClaimTrialAPIKey upgrades and migrates an anonymous trial key to an enterprise tenant (PostgresService).
func (p *PostgresService) ClaimTrialAPIKey(ctx context.Context, tenantID string, rawAPIKey string, projectID, agentID string, actorMemberID string) (*APIKey, error) {
	cleanKey := strings.TrimSpace(rawAPIKey)
	if !strings.HasPrefix(cleanKey, "apk_live_guest_") {
		return nil, errors.New("仅支持转正以 apk_live_guest_ 开头的试用测试 Key")
	}

	if err := p.enforcePermission(ctx, actorMemberID, tenantID, PermissionAPIKeyCreate); err != nil {
		return nil, err
	}

	hash := sha256.Sum256([]byte(cleanKey))
	hashHex := hex.EncodeToString(hash[:])

	var keyID, existingTenantID, existingName, existingPrefix, existingStatus string
	var expiresAt sql.NullTime
	err := p.db.QueryRowContext(ctx, `
		SELECT key_id, tenant_id, name, key_prefix, status, expires_at
		FROM ap_api_key
		WHERE key_hash = $1
	`, hashHex).Scan(&keyID, &existingTenantID, &existingName, &existingPrefix, &existingStatus, &expiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("未找到该测试 Key 记录，请确认密钥无误或尚未过期")
		}
		return nil, err
	}

	if existingTenantID != PublicSandboxTenantID && existingTenantID != tenantID {
		return nil, errors.New("该测试 Key 已被其他组织认领转正")
	}

	targetProj := strings.TrimSpace(projectID)
	if targetProj != "" {
		var validProj bool
		_ = p.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM ap_project WHERE project_id = $1 AND tenant_id = $2 AND status = 'active');`, targetProj, tenantID).Scan(&validProj)
		if !validProj {
			targetProj = ""
		}
	}
	if targetProj == "" {
		_ = p.db.QueryRowContext(ctx, `
			SELECT project_id FROM ap_project 
			WHERE tenant_id = $1 AND status = 'active' 
			ORDER BY created_at ASC LIMIT 1
		`, tenantID).Scan(&targetProj)
	}
	if targetProj == "" {
		targetProj = GenerateProjectID()
		_, err = p.db.ExecContext(ctx, `
			INSERT INTO ap_project (project_id, tenant_id, name, budget_cap_base_units, status)
			VALUES ($1, $2, '默认业务项目 (Default Project)', 1000000000, 'active')
			ON CONFLICT (project_id) DO NOTHING;
		`, targetProj, tenantID)
		if err != nil {
			return nil, fmt.Errorf("failed to auto-create default project for new tenant: %w", err)
		}
	}

	targetAgent := strings.TrimSpace(agentID)
	if targetAgent != "" {
		var validAgent bool
		_ = p.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM ap_agent WHERE agent_id = $1 AND tenant_id = $2 AND status = 'active');`, targetAgent, tenantID).Scan(&validAgent)
		if !validAgent {
			targetAgent = ""
		}
	}
	if targetAgent == "" {
		_ = p.db.QueryRowContext(ctx, `
			SELECT agent_id FROM ap_agent 
			WHERE tenant_id = $1 AND status = 'active' 
			ORDER BY created_at ASC LIMIT 1
		`, tenantID).Scan(&targetAgent)
	}
	if targetAgent == "" {
		targetAgent = GenerateAgentID()
		defaultPolicy := map[string]interface{}{
			"rate_limit_rpm": 60,
			"kya": map[string]interface{}{
				"model_provider": "DeepSeek",
				"model_version":  "deepseek-v3",
				"framework":      "LangChain",
				"autonomy_level": "L2_semi_autonomous",
				"status":         "verified",
			},
		}
		policyJSON, _ := json.Marshal(defaultPolicy)
		_, err = p.db.ExecContext(ctx, `
			INSERT INTO ap_agent (agent_id, tenant_id, project_id, name, status, policy_config)
			VALUES ($1, $2, $3, '默认智能体 (Default Agent)', 'active', $4)
			ON CONFLICT (project_id, name) DO NOTHING;
		`, targetAgent, tenantID, targetProj, policyJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to auto-create default agent for new tenant: %w", err)
		}
	}

	newName := fmt.Sprintf("认领转正的测试 Key (%s)", existingPrefix)

	var updated APIKey
	var expNull sql.NullInt64
	var lastUsedNull sql.NullInt64
	var scopesJSON []byte

	err = p.db.QueryRowContext(ctx, `
		UPDATE ap_api_key
		SET tenant_id = $1,
		    project_id = $2,
		    agent_id = $3,
		    name = $4,
		    expires_at = NULL,
		    status = 'active',
		    updated_at = NOW()
		WHERE key_hash = $5
		RETURNING key_id, tenant_id, project_id, agent_id, name, key_prefix, scopes, status,
		          EXTRACT(EPOCH FROM expires_at)::BIGINT,
		          EXTRACT(EPOCH FROM last_used_at)::BIGINT,
		          EXTRACT(EPOCH FROM created_at)::BIGINT,
		          EXTRACT(EPOCH FROM updated_at)::BIGINT
	`, tenantID, targetProj, targetAgent, newName, hashHex).Scan(
		&updated.KeyID, &updated.TenantID, &updated.ProjectID, &updated.AgentID,
		&updated.Name, &updated.KeyPrefix, &scopesJSON, &updated.Status,
		&expNull, &lastUsedNull, &updated.CreatedAt, &updated.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to claim and migrate trial key: %w", err)
	}

	if len(scopesJSON) > 0 {
		_ = json.Unmarshal(scopesJSON, &updated.Scopes)
	}
	if expNull.Valid {
		v := expNull.Int64
		updated.ExpiresAt = &v
	}
	if lastUsedNull.Valid {
		v := lastUsedNull.Int64
		updated.LastUsedAt = &v
	}

	if p.agentReg != nil {
		p.agentReg.BindAPIKeyHash(hashHex, targetAgent)
	}

	// Migrate historical requests, intents, and usage events from sandbox to the enterprise tenant
	_, _ = p.db.ExecContext(ctx, `
		UPDATE ap_request_record
		SET tenant_id = $1, project_id = $2, agent_id = $3
		WHERE api_key_id = $4
	`, tenantID, targetProj, targetAgent, updated.KeyID)

	_, _ = p.db.ExecContext(ctx, `
		UPDATE ap_payment_intent
		SET tenant_id = $1, project_id = $2, agent_id = $3
		WHERE request_id IN (SELECT request_id FROM ap_request_record WHERE api_key_id = $4)
	`, tenantID, targetProj, targetAgent, updated.KeyID)

	_, _ = p.db.ExecContext(ctx, `
		UPDATE ap_usage_event
		SET tenant_id = $1, project_id = $2, agent_id = $3
		WHERE intent_id IN (
			SELECT intent_id FROM ap_request_record 
			WHERE api_key_id = $4 AND intent_id IS NOT NULL
		)
	`, tenantID, targetProj, targetAgent, updated.KeyID)

	p.recordAudit(ctx, tenantID, actorMemberID, "api_key.claimed_trial", "APIKey", updated.KeyID,
		map[string]interface{}{"from_tenant": existingTenantID},
		map[string]interface{}{"to_tenant": tenantID, "project_id": targetProj, "agent_id": targetAgent},
		"127.0.0.1",
	)

	return &updated, nil
}

// CleanExpiredTrialKeys purges unclaimed guest trial keys in Postgres whose expires_at is past 1 hour.
func (p *PostgresService) CleanExpiredTrialKeys(ctx context.Context) (int64, error) {
	res, err := p.db.ExecContext(ctx, `
		DELETE FROM ap_api_key
		WHERE tenant_id = 'ten_public_sandbox'
		  AND expires_at IS NOT NULL
		  AND expires_at < NOW() - INTERVAL '1 hour'
	`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

var slugSanitizeRegex = regexp.MustCompile(`[^a-z0-9\-]+`)

// NormalizeSlug normalizes a route slug or derives one from path_pattern.
