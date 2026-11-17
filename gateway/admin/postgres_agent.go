package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"github.com/open-agentpay/agent-core-sdk/gateway/agent"
	"github.com/open-agentpay/agent-core-sdk/gateway/timeline"
)

func (p *PostgresService) CreateAgent(ctx context.Context, tenantID, projectID, name string, policyCfg map[string]interface{}, actorMemberID string) (*Agent, error) {
	if err := p.enforcePermission(ctx, actorMemberID, tenantID, PermissionAgentCreate); err != nil {
		return nil, err
	}

	cleanName := strings.TrimSpace(name)
	if cleanName == "" {
		return nil, fmt.Errorf("agent name cannot be empty")
	}

	var exists bool
	_ = p.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM ap_agent WHERE project_id = $1 AND name = $2);`, projectID, cleanName).Scan(&exists)
	if exists {
		return nil, ErrAgentAlreadyExists
	}

	agID := GenerateAgentID()
	now := time.Now()
	nowUnix := now.Unix()
	if policyCfg == nil {
		policyCfg = make(map[string]interface{})
	}
	cfgBytes, _ := json.Marshal(policyCfg)

	if _, err := p.db.ExecContext(ctx, `
		INSERT INTO ap_agent (agent_id, tenant_id, project_id, name, status, policy_config, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'active', $5, $6, $6);
	`, agID, tenantID, projectID, cleanName, cfgBytes, now); err != nil {
		return nil, err
	}

	ag := &Agent{
		AgentID:      agID,
		TenantID:     tenantID,
		ProjectID:    projectID,
		Name:         cleanName,
		Status:       AgentStatusActive,
		PolicyConfig: policyCfg,
		CreatedAt:    nowUnix,
		UpdatedAt:    nowUnix,
	}

	if p.agentReg != nil {
		p.agentReg.RegisterAgent(&agent.AgentIdentity{
			AgentID:   agID,
			TenantID:  tenantID,
			ProjectID: projectID,
			Name:      cleanName,
			Status:    agent.AgentStatusActive,
		}, nil)
	}

	p.recordAudit(ctx, tenantID, actorMemberID, "agent.created", "Agent", agID, nil, map[string]interface{}{"name": cleanName}, "127.0.0.1")
	return ag, nil
}

func (p *PostgresService) GetAgent(ctx context.Context, tenantID, agentID string) (*Agent, error) {
	var ag Agent
	var cfgBytes []byte
	var reqCount, totalSpend, rejCount int64
	var lastActive sql.NullInt64

	err := p.db.QueryRowContext(ctx, `
		SELECT a.agent_id, a.tenant_id, a.project_id, a.name, a.status, a.policy_config,
		       EXTRACT(EPOCH FROM a.created_at)::bigint, EXTRACT(EPOCH FROM a.updated_at)::bigint,
		       COALESCE(r.req_count, 0),
		       COALESCE(s.total_spend, 0),
		       COALESCE(r.rej_count, 0),
		       r.last_active
		FROM ap_agent a
		LEFT JOIN (
			SELECT agent_id,
			       COUNT(*) AS req_count,
			       COUNT(CASE WHEN status_code = 403 OR error_code LIKE 'ERR_POLICY%' OR error_code = 'ERR_POLICY_REJECT' THEN 1 END) AS rej_count,
			       MAX(EXTRACT(EPOCH FROM created_at)::bigint) AS last_active
			FROM ap_request_record
			WHERE agent_id = $1
			GROUP BY agent_id
		) r ON a.agent_id = r.agent_id
		LEFT JOIN (
			SELECT agent_id,
			       COALESCE(SUM(amount_base_units), 0) AS total_spend
			FROM ap_usage_event
			WHERE agent_id = $1 AND is_success = TRUE
			GROUP BY agent_id
		) s ON a.agent_id = s.agent_id
		WHERE a.agent_id = $1;
	`, agentID).Scan(
		&ag.AgentID, &ag.TenantID, &ag.ProjectID, &ag.Name, &ag.Status, &cfgBytes,
		&ag.CreatedAt, &ag.UpdatedAt,
		&reqCount, &totalSpend, &rejCount, &lastActive,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAgentNotFound
	}
	if err != nil {
		return nil, err
	}
	if tenantID != "" && ag.TenantID != tenantID {
		return nil, ErrAgentTenantMismatch
	}
	_ = json.Unmarshal(cfgBytes, &ag.PolicyConfig)

	ag.RequestsCount = reqCount
	ag.TotalSpendBaseUnits = totalSpend
	if reqCount > 0 {
		ag.RejectRate = fmt.Sprintf("%.1f%%", float64(rejCount)*100.0/float64(reqCount))
	} else {
		ag.RejectRate = "0.0%"
	}
	if lastActive.Valid {
		v := lastActive.Int64
		ag.LastActiveAt = &v
	}

	return &ag, nil
}

func (p *PostgresService) ListAgents(ctx context.Context, tenantID, projectID string, status *AgentStatus) ([]*Agent, error) {
	args := make([]interface{}, 0)
	idx := 1

	tenantFilter := "WHERE agent_id IS NOT NULL"
	if tenantID != "" {
		tenantFilter = fmt.Sprintf("WHERE agent_id IS NOT NULL AND tenant_id = $%d", idx)
		args = append(args, tenantID)
		idx++
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`
		WITH req_stats AS (
			SELECT agent_id,
			       COUNT(*) AS req_count,
			       COUNT(CASE WHEN status_code = 403 OR error_code LIKE 'ERR_POLICY%%%%' OR error_code = 'ERR_POLICY_REJECT' THEN 1 END) AS rej_count,
			       MAX(EXTRACT(EPOCH FROM created_at)::bigint) AS last_active
			FROM ap_request_record
			%s
			GROUP BY agent_id
		),
		spend_stats AS (
			SELECT agent_id,
			       COALESCE(SUM(amount_base_units), 0) AS total_spend
			FROM ap_usage_event
			%s AND is_success = TRUE
			GROUP BY agent_id
		)
		SELECT a.agent_id, a.tenant_id, a.project_id, a.name, a.status, a.policy_config,
		       EXTRACT(EPOCH FROM a.created_at)::bigint, EXTRACT(EPOCH FROM a.updated_at)::bigint,
		       COALESCE(r.req_count, 0),
		       COALESCE(s.total_spend, 0),
		       COALESCE(r.rej_count, 0),
		       r.last_active
		FROM ap_agent a
		LEFT JOIN req_stats r ON a.agent_id = r.agent_id
		LEFT JOIN spend_stats s ON a.agent_id = s.agent_id
		WHERE 1=1
	`, tenantFilter, tenantFilter))

	if tenantID != "" {
		// Notice: tenantID was already added as arg 1 if not empty
		sb.WriteString(" AND a.tenant_id = $1")
	}
	if projectID != "" {
		sb.WriteString(fmt.Sprintf(" AND a.project_id = $%d", idx))
		args = append(args, projectID)
		idx++
	}
	if status != nil {
		sb.WriteString(fmt.Sprintf(" AND a.status = $%d", idx))
		args = append(args, string(*status))
		idx++
	}
	sb.WriteString(" ORDER BY a.created_at DESC;")

	rows, err := p.db.QueryContext(ctx, sb.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	agentsList := make([]*Agent, 0)
	for rows.Next() {
		var ag Agent
		var cfgBytes []byte
		var reqCount, totalSpend, rejCount int64
		var lastActive sql.NullInt64

		if err := rows.Scan(
			&ag.AgentID, &ag.TenantID, &ag.ProjectID, &ag.Name, &ag.Status, &cfgBytes,
			&ag.CreatedAt, &ag.UpdatedAt,
			&reqCount, &totalSpend, &rejCount, &lastActive,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(cfgBytes, &ag.PolicyConfig)

		ag.RequestsCount = reqCount
		ag.TotalSpendBaseUnits = totalSpend
		if reqCount > 0 {
			ag.RejectRate = fmt.Sprintf("%.1f%%", float64(rejCount)*100.0/float64(reqCount))
		} else {
			ag.RejectRate = "0.0%"
		}
		if lastActive.Valid {
			v := lastActive.Int64
			ag.LastActiveAt = &v
		}

		agentsList = append(agentsList, &ag)
	}
	return agentsList, nil
}

func (p *PostgresService) UpdateAgent(ctx context.Context, tenantID, agentID string, name string, policyCfg map[string]interface{}, actorMemberID string) (*Agent, error) {
	if err := p.enforcePermission(ctx, actorMemberID, tenantID, PermissionAgentUpdate); err != nil {
		return nil, err
	}

	ag, err := p.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		return nil, err
	}
	if ag.Status == AgentStatusRevoked {
		return nil, ErrAgentRevoked
	}

	before := map[string]interface{}{"name": ag.Name, "status": string(ag.Status)}
	if name != "" {
		ag.Name = strings.TrimSpace(name)
	}
	if policyCfg != nil {
		ag.PolicyConfig = policyCfg
	}

	cfgBytes, _ := json.Marshal(ag.PolicyConfig)
	if _, err := p.db.ExecContext(ctx, `
		UPDATE ap_agent SET name = $1, policy_config = $2, updated_at = NOW() WHERE agent_id = $3;
	`, ag.Name, cfgBytes, agentID); err != nil {
		return nil, err
	}

	ag.UpdatedAt = time.Now().Unix()
	if p.agentReg != nil {
		p.agentReg.RegisterAgent(&agent.AgentIdentity{
			AgentID:   ag.AgentID,
			TenantID:  ag.TenantID,
			ProjectID: ag.ProjectID,
			Name:      ag.Name,
			Status:    agent.AgentStatus(ag.Status),
		}, nil)
	}

	p.recordAudit(ctx, tenantID, actorMemberID, "agent.updated", "Agent", agentID, before, map[string]interface{}{"name": ag.Name}, "127.0.0.1")
	return ag, nil
}

func (p *PostgresService) UpdateAgentStatus(ctx context.Context, tenantID, agentID string, status AgentStatus, actorMemberID string) (*Agent, error) {
	if err := p.enforcePermission(ctx, actorMemberID, tenantID, PermissionAgentUpdate); err != nil {
		return nil, err
	}

	ag, err := p.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		return nil, err
	}
	if ag.Status == AgentStatusRevoked {
		return nil, ErrAgentRevoked
	}

	before := map[string]interface{}{"status": string(ag.Status)}
	if _, err := p.db.ExecContext(ctx, `
		UPDATE ap_agent SET status = $1, updated_at = NOW() WHERE agent_id = $2;
	`, string(status), agentID); err != nil {
		return nil, err
	}

	ag.Status = status
	ag.UpdatedAt = time.Now().Unix()
	if p.agentReg != nil {
		p.agentReg.SetAgentStatus(agentID, agent.AgentStatus(status))
	}

	p.recordAudit(ctx, tenantID, actorMemberID, "agent.status_updated", "Agent", agentID, before, map[string]interface{}{"status": string(status)}, "127.0.0.1")
	return ag, nil
}

func (p *PostgresService) KillAgent(ctx context.Context, tenantID, agentID, reason string, actorMemberID string, revoke bool, clientIP string) (*Agent, []string, error) {
	cleanReason := strings.TrimSpace(reason)
	if cleanReason == "" {
		return nil, nil, ErrMissingReason
	}
	if err := p.enforcePermission(ctx, actorMemberID, tenantID, PermissionAgentKill); err != nil {
		return nil, nil, err
	}

	ag, err := p.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		return nil, nil, err
	}

	if p.agentReg != nil {
		p.agentReg.SetAgentStatus(agentID, agent.AgentStatusSuspended)
	}

	if _, err := p.db.ExecContext(ctx, `
		UPDATE ap_agent SET status = 'suspended', updated_at = NOW() WHERE agent_id = $1;
	`, agentID); err != nil {
		return nil, nil, err
	}
	ag.Status = AgentStatusSuspended
	ag.UpdatedAt = time.Now().Unix()

	revokedKeys := make([]string, 0)
	if revoke {
		rows, err := p.db.QueryContext(ctx, `
			SELECT key_id, key_hash FROM ap_api_key WHERE agent_id = $1 AND status = 'active';
		`, agentID)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var kID, kHash string
				if err := rows.Scan(&kID, &kHash); err == nil {
					revokedKeys = append(revokedKeys, kID)
					if p.agentReg != nil {
						p.agentReg.RevokeKey(kHash)
					}
				}
			}
			_, _ = p.db.ExecContext(ctx, `
				UPDATE ap_api_key SET status = 'revoked', updated_at = NOW() WHERE agent_id = $1 AND status = 'active';
			`, agentID)
		}
	}

	p.recordAudit(ctx, ag.TenantID, actorMemberID, "agent.kill", "Agent", agentID, nil, map[string]interface{}{
		"reason":       cleanReason,
		"revoked_keys": revokedKeys,
	}, clientIP)

	return ag, revokedKeys, nil
}

func (p *PostgresService) DeleteAgent(ctx context.Context, tenantID, agentID, actorMemberID string) error {
	if err := p.enforcePermission(ctx, actorMemberID, tenantID, PermissionAgentKill); err != nil {
		return err
	}
	ag, err := p.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		return err
	}
	if p.agentReg != nil {
		p.agentReg.SetAgentStatus(agentID, agent.AgentStatusRevoked)
	}
	if _, err := p.db.ExecContext(ctx, `DELETE FROM ap_agent WHERE agent_id = $1;`, agentID); err != nil {
		return err
	}
	p.recordAudit(ctx, tenantID, actorMemberID, "agent.deleted", "Agent", agentID, map[string]interface{}{"name": ag.Name}, nil, "127.0.0.1")
	return nil
}

// ----------------------------------------------------------------------------
// API Keys
// ----------------------------------------------------------------------------

func (p *PostgresService) CreateAPIKey(ctx context.Context, tenantID, projectID, agentID, name string, scopes []string, expiresAt *int64, actorMemberID string) (*CreateAPIKeyResult, error) {
	if err := p.enforcePermission(ctx, actorMemberID, tenantID, PermissionAPIKeyCreate); err != nil {
		return nil, err
	}

	ag, err := p.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		return nil, err
	}
	if ag.Status == AgentStatusRevoked {
		return nil, ErrAgentRevoked
	}

	cleanName := strings.TrimSpace(name)
	if cleanName == "" {
		return nil, fmt.Errorf("api key name cannot be empty")
	}

	rawKey, keyHash, keyPrefix := GenerateRawAPIKey()
	keyID := GenerateAPIKeyID()
	now := time.Now()
	nowUnix := now.Unix()

	if len(scopes) == 0 {
		scopes = []string{"gateway:call"}
	}
	scopesBytes, _ := json.Marshal(scopes)

	var expTime *time.Time
	if expiresAt != nil {
		t := time.Unix(*expiresAt, 0)
		expTime = &t
	}

	if _, err := p.db.ExecContext(ctx, `
		INSERT INTO ap_api_key (key_id, tenant_id, project_id, agent_id, name, key_hash, key_prefix, scopes, status, expires_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'active', $9, $10, $10);
	`, keyID, tenantID, projectID, agentID, cleanName, keyHash, keyPrefix, scopesBytes, expTime, now); err != nil {
		return nil, err
	}

	if p.agentReg != nil {
		p.agentReg.BindAPIKeyHash(keyHash, agentID)
	}

	apiKey := &APIKey{
		KeyID:     keyID,
		TenantID:  tenantID,
		ProjectID: projectID,
		AgentID:   agentID,
		Name:      cleanName,
		KeyHash:   keyHash,
		KeyPrefix: keyPrefix,
		Scopes:    scopes,
		Status:    APIKeyStatusActive,
		ExpiresAt: expiresAt,
		CreatedAt: nowUnix,
		UpdatedAt: nowUnix,
	}

	p.recordAudit(ctx, tenantID, actorMemberID, "apikey.created", "APIKey", keyID, nil, map[string]interface{}{"agent_id": agentID, "name": cleanName}, "127.0.0.1")
	return &CreateAPIKeyResult{APIKey: apiKey, RawKey: rawKey}, nil
}

func (p *PostgresService) GetAPIKey(ctx context.Context, tenantID, keyID string) (*APIKey, error) {
	var k APIKey
	var scopesBytes []byte
	var exp sql.NullInt64
	err := p.db.QueryRowContext(ctx, `
		SELECT key_id, tenant_id, project_id, agent_id, name, key_hash, key_prefix, scopes, status,
		       EXTRACT(EPOCH FROM expires_at)::bigint, EXTRACT(EPOCH FROM created_at)::bigint, EXTRACT(EPOCH FROM updated_at)::bigint
		FROM ap_api_key
		WHERE key_id = $1;
	`, keyID).Scan(
		&k.KeyID, &k.TenantID, &k.ProjectID, &k.AgentID, &k.Name, &k.KeyHash, &k.KeyPrefix, &scopesBytes, &k.Status,
		&exp, &k.CreatedAt, &k.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAPIKeyNotFound
	}
	if err != nil {
		return nil, err
	}
	if tenantID != "" && k.TenantID != tenantID {
		return nil, ErrAPIKeyNotFound
	}
	if exp.Valid {
		v := exp.Int64
		k.ExpiresAt = &v
	}
	_ = json.Unmarshal(scopesBytes, &k.Scopes)
	return &k, nil
}

func (p *PostgresService) ListAPIKeys(ctx context.Context, tenantID, agentID string) ([]*APIKey, error) {
	var sb strings.Builder
	sb.WriteString(`
		SELECT key_id, tenant_id, project_id, agent_id, name, key_hash, key_prefix, scopes, status,
		       EXTRACT(EPOCH FROM expires_at)::bigint, EXTRACT(EPOCH FROM created_at)::bigint, EXTRACT(EPOCH FROM updated_at)::bigint
		FROM ap_api_key
		WHERE 1=1
	`)
	args := make([]interface{}, 0)
	idx := 1
	if tenantID != "" {
		sb.WriteString(fmt.Sprintf(" AND tenant_id = $%d", idx))
		args = append(args, tenantID)
		idx++
	}
	if agentID != "" {
		sb.WriteString(fmt.Sprintf(" AND agent_id = $%d", idx))
		args = append(args, agentID)
		idx++
	}
	sb.WriteString(" ORDER BY created_at DESC;")

	rows, err := p.db.QueryContext(ctx, sb.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keys := make([]*APIKey, 0)
	for rows.Next() {
		var k APIKey
		var scopesBytes []byte
		var exp sql.NullInt64
		if err := rows.Scan(&k.KeyID, &k.TenantID, &k.ProjectID, &k.AgentID, &k.Name, &k.KeyHash, &k.KeyPrefix, &scopesBytes, &k.Status, &exp, &k.CreatedAt, &k.UpdatedAt); err != nil {
			return nil, err
		}
		if exp.Valid {
			v := exp.Int64
			k.ExpiresAt = &v
		}
		_ = json.Unmarshal(scopesBytes, &k.Scopes)
		keys = append(keys, &k)
	}
	return keys, nil
}

func (p *PostgresService) RevokeAPIKey(ctx context.Context, tenantID, keyID, actorMemberID string) (*APIKey, error) {
	if err := p.enforcePermission(ctx, actorMemberID, tenantID, PermissionAPIKeyRevoke); err != nil {
		return nil, err
	}

	k, err := p.GetAPIKey(ctx, tenantID, keyID)
	if err != nil {
		return nil, err
	}
	if k.Status == APIKeyStatusRevoked {
		return k, nil
	}

	if _, err := p.db.ExecContext(ctx, `
		UPDATE ap_api_key SET status = 'revoked', updated_at = NOW() WHERE key_id = $1;
	`, keyID); err != nil {
		return nil, err
	}

	if p.agentReg != nil {
		p.agentReg.RevokeKey(k.KeyHash)
	}

	k.Status = APIKeyStatusRevoked
	k.UpdatedAt = time.Now().Unix()
	p.recordAudit(ctx, tenantID, actorMemberID, "apikey.revoked", "APIKey", keyID, nil, map[string]interface{}{"status": "revoked"}, "127.0.0.1")
	return k, nil
}

func (p *PostgresService) RotateAPIKey(ctx context.Context, tenantID, keyID, actorMemberID string) (*CreateAPIKeyResult, error) {
	oldKey, err := p.RevokeAPIKey(ctx, tenantID, keyID, actorMemberID)
	if err != nil {
		return nil, err
	}
	return p.CreateAPIKey(ctx, tenantID, oldKey.ProjectID, oldKey.AgentID, oldKey.Name, oldKey.Scopes, oldKey.ExpiresAt, actorMemberID)
}

// ----------------------------------------------------------------------------
// Routes
// ----------------------------------------------------------------------------

func (p *PostgresService) GetAgentTimeline(ctx context.Context, tenantID, agentID string, filter timeline.TimelineFilter, actorMemberID string) ([]*timeline.TimelineEvent, int64, []string, error) {
	if err := p.enforcePermission(ctx, actorMemberID, tenantID, PermissionAuditRead); err != nil {
		return nil, 0, nil, err
	}
	ag, err := p.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		return nil, 0, nil, err
	}
	if ag == nil || ag.TenantID != tenantID {
		return nil, 0, nil, ErrAgentNotFound
	}
	filter.TenantID = tenantID
	filter.AgentID = agentID
	return p.GetTimelineService().GetTimeline(ctx, tenantID, agentID, filter)
}
