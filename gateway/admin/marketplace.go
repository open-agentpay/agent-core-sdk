package admin

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/open-agentpay/agent-core-sdk/gateway/usage"
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
	if targetProj == "" {
		for _, p := range s.projects {
			if p.TenantID == tenantID && p.Status == "active" {
				targetProj = p.ProjectID
				break
			}
		}
	}
	if targetProj == "" {
		targetProj = "prj_default"
	}

	targetAgent := agentID
	if targetAgent == "" {
		for _, a := range s.agents {
			if a.TenantID == tenantID && a.Status == AgentStatusActive {
				targetAgent = a.AgentID
				break
			}
		}
	}
	if targetAgent == "" {
		targetAgent = "agt_default"
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
	if targetProj == "" {
		_ = p.db.QueryRowContext(ctx, `
			SELECT project_id FROM ap_project 
			WHERE tenant_id = $1 AND status = 'active' 
			ORDER BY created_at ASC LIMIT 1
		`, tenantID).Scan(&targetProj)
	}
	if targetProj == "" {
		targetProj = "prj_default"
	}

	targetAgent := strings.TrimSpace(agentID)
	if targetAgent == "" {
		_ = p.db.QueryRowContext(ctx, `
			SELECT agent_id FROM ap_agent 
			WHERE tenant_id = $1 AND status = 'active' 
			ORDER BY created_at ASC LIMIT 1
		`, tenantID).Scan(&targetAgent)
	}
	if targetAgent == "" {
		targetAgent = "agt_default"
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
func NormalizeSlug(slug, pathPattern string) string {
	s := strings.ToLower(strings.TrimSpace(slug))
	if s == "" {
		s = strings.ToLower(strings.Trim(pathPattern, "/"))
		s = strings.TrimPrefix(s, "api/v1/")
		s = strings.TrimPrefix(s, "v1/")
	}
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, "_", "-")
	s = slugSanitizeRegex.ReplaceAllString(s, "-")
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	return strings.Trim(s, "-")
}

// DefaultTitleFromSlug derives a human-readable title if none was explicitly configured.
func DefaultTitleFromSlug(title, slug, pathPattern string) string {
	t := strings.TrimSpace(title)
	if t != "" {
		return t
	}
	base := NormalizeSlug(slug, pathPattern)
	if base == "" {
		return pathPattern
	}
	parts := strings.Split(base, "-")
	for i, p := range parts {
		if len(p) > 0 {
			switch strings.ToLower(p) {
			case "api", "llm", "ai", "x402", "cny", "usd", "sql", "ocr", "pdf", "sec":
				parts[i] = strings.ToUpper(p)
			default:
				parts[i] = strings.ToUpper(p[:1]) + p[1:]
			}
		}
	}
	return strings.Join(parts, " ")
}

// isFirewallOrPreIntercepted determines if a request record was intercepted by the
// financial firewall, protocol challenge, or gateway security policy layer BEFORE
// any actual upstream API call was dispatched. Such intercepted requests should not
// penalize upstream service SLA or count towards actual upstream interface calls.
func isFirewallOrPreIntercepted(rec *usage.RequestRecord) bool {
	if rec == nil {
		return false
	}
	// 402: Payment required challenges or payment/wallet denials intercepted before upstream
	if rec.StatusCode == http.StatusPaymentRequired {
		return true
	}
	// 403: Financial firewall policy denial, agent policy enforcer denial
	if rec.StatusCode == http.StatusForbidden {
		return true
	}
	// 401: Unauthorized authentication failures
	if rec.StatusCode == http.StatusUnauthorized {
		return true
	}
	// 405: Payment method / route method disallowed before upstream
	if rec.StatusCode == http.StatusMethodNotAllowed {
		return true
	}
	// 400: Malformed inbound payload rejected by gateway parser before upstream
	if rec.StatusCode == http.StatusBadRequest && (rec.ErrorCode == "ERR_INVALID_REQUEST_BODY" || strings.HasPrefix(rec.ErrorCode, "ERR_")) {
		return true
	}
	// Explicit policy/firewall error codes
	errCode := strings.ToUpper(rec.ErrorCode)
	if strings.HasPrefix(errCode, "ERR_POLICY_") ||
		strings.HasPrefix(errCode, "ERR_WALLET_") ||
		strings.HasPrefix(errCode, "ERR_PAYMENT_") ||
		strings.HasPrefix(errCode, "ERR_API_KEY_") ||
		strings.HasPrefix(errCode, "ERR_NONCE_") ||
		strings.HasPrefix(errCode, "ERR_SIGNATURE_") ||
		strings.HasPrefix(errCode, "POLICY_") ||
		strings.HasPrefix(errCode, "CIRCUIT_") ||
		strings.HasPrefix(errCode, "BUDGET_") {
		return true
	}
	return false
}

func computeRouteSLA(ctx context.Context, usageSvc usage.Service, route *Route) MarketplaceSLAMetrics {
	sla := MarketplaceSLAMetrics{
		SuccessRate24h: 99.8,
		P95LatencyMs:   185,
		PaidCalls24h:   0,
		TotalCalls:     0,
		HealthStatus:   "healthy",
	}
	if route.Status != RouteStatusActive {
		sla.HealthStatus = "maintenance"
	}

	if usageSvc == nil {
		return sla
	}

	since24h := time.Now().Add(-24 * time.Hour)
	records, _, err := usageSvc.ListRequestRecords(ctx, usage.RequestFilter{
		TenantID:  route.TenantID,
		RouteID:   route.RouteID,
		StartTime: &since24h,
		Limit:     1000,
	})
	if err == nil && len(records) > 0 {
		// Filter out requests that were intercepted by the financial firewall or gateway policy
		// before actually reaching the upstream API.
		validRecords := make([]*usage.RequestRecord, 0, len(records))
		for _, rec := range records {
			if !isFirewallOrPreIntercepted(rec) {
				validRecords = append(validRecords, rec)
			}
		}

		if len(validRecords) > 0 {
			var okCount int64
			latencies := make([]int64, 0, len(validRecords))
			consecutiveFailures := 0
			for i, rec := range validRecords {
				latencies = append(latencies, rec.DurationMs)
				if rec.StatusCode >= 200 && rec.StatusCode < 400 {
					okCount++
				} else if i < 5 && rec.StatusCode >= 500 {
					consecutiveFailures++
				}
			}
			sla.SuccessRate24h = float64(int((float64(okCount)/float64(len(validRecords)))*1000)) / 10.0
			sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
			p95Idx := int(float64(len(latencies)-1) * 0.95)
			if p95Idx >= 0 && p95Idx < len(latencies) {
				sla.P95LatencyMs = latencies[p95Idx]
			}
			sla.TotalCalls = int64(len(validRecords))
			if consecutiveFailures >= 3 && len(validRecords) >= 3 {
				sla.HealthStatus = "maintenance"
			} else if sla.SuccessRate24h < 95.0 {
				sla.HealthStatus = "degraded"
			}
		}
	}

	successOnly := true
	_, paid24h, err := usageSvc.ListUsageEvents(ctx, usage.UsageFilter{
		TenantID:  route.TenantID,
		RouteID:   route.RouteID,
		IsSuccess: &successOnly,
		StartTime: &since24h,
		Limit:     1,
	})
	if err == nil {
		sla.PaidCalls24h = paid24h
		if sla.TotalCalls < paid24h {
			sla.TotalCalls = paid24h
		}
	}

	return sla
}

func buildMarketplaceRouteItem(ctx context.Context, usageSvc usage.Service, r *Route, providerName string) *MarketplaceRouteItem {
	slug := NormalizeSlug(r.Slug, r.PathPattern)
	title := DefaultTitleFromSlug(r.Title, slug, r.PathPattern)
	cat := strings.TrimSpace(r.Category)
	if cat == "" {
		cat = "AI & LLM"
	}
	netID := strings.TrimSpace(r.Network)
	if netID == "" {
		netID = "eip155:421614"
	}
	tags := r.Tags
	if tags == nil {
		tags = []string{}
	}
	onchainPrice := r.PriceBaseUnits
	if r.OnchainPriceBaseUnits != nil && *r.OnchainPriceBaseUnits > 0 {
		onchainPrice = *r.OnchainPriceBaseUnits
	}
	onchainAsset := r.OnchainAsset
	if onchainAsset == "" {
		onchainAsset = r.Asset
	}
	if onchainAsset == "" {
		onchainAsset = "CNY"
	}
	if r.ProviderName != "" {
		providerName = r.ProviderName
	} else if providerName == "" {
		providerName = "OpenAgentPay Verified Provider"
	}

	methods := r.Methods
	if len(methods) == 0 {
		methods = []string{"POST"}
	}

	params := r.Parameters
	if params == nil {
		params = []MarketplaceParameter{}
	}

	return &MarketplaceRouteItem{
		RouteID:               r.RouteID,
		TenantID:              r.TenantID,
		ProviderName:          providerName,
		Slug:                  slug,
		Title:                 title,
		Summary:               r.Summary,
		Category:              cat,
		Tags:                  tags,
		DescriptionMD:         r.DescriptionMD,
		Network:               netID,
		NetworkLabel:          r.NetworkLabel,
		PathPattern:           r.PathPattern,
		Methods:               methods,
		PriceBaseUnits:        r.PriceBaseUnits,
		Asset:                 r.Asset,
		OnchainPriceBaseUnits: onchainPrice,
		OnchainAsset:          onchainAsset,
		PayeeAddress:          r.PayeeAddress,
		AllowedPaymentMethods: r.AllowedPaymentMethods,
		RateLimitRPM:          r.RateLimitRPM,
		TimeoutMs:             r.TimeoutMs,
		Status:                r.Status,
		SLA:                   computeRouteSLA(ctx, usageSvc, r),
		Parameters:            params,
		SampleParams:          r.SampleParams,
		SampleResponse:        r.SampleResponse,
		CreatedAt:             r.CreatedAt,
		UpdatedAt:             r.UpdatedAt,
	}
}

func matchesMarketplaceFilter(item *MarketplaceRouteItem, filter MarketplaceFilter) bool {
	if filter.Category != "" && !strings.EqualFold(filter.Category, "all") && !strings.EqualFold(item.Category, filter.Category) {
		return false
	}
	if filter.Network != "" && !strings.EqualFold(filter.Network, "all") && !strings.EqualFold(item.Network, filter.Network) {
		return false
	}
	if filter.Tag != "" {
		foundTag := false
		for _, t := range item.Tags {
			if strings.EqualFold(t, filter.Tag) {
				foundTag = true
				break
			}
		}
		if !foundTag {
			return false
		}
	}
	if q := strings.ToLower(strings.TrimSpace(filter.Query)); q != "" {
		haystack := strings.ToLower(item.Title + " " + item.Slug + " " + item.PathPattern + " " + item.Category + " " + item.DescriptionMD + " " + strings.Join(item.Tags, " "))
		if !strings.Contains(haystack, q) {
			return false
		}
	}
	return true
}

// ListMarketplaceRoutes returns all public marketplace routes matching the filter (MemoryService).
func (s *MemoryService) ListMarketplaceRoutes(ctx context.Context, filter MarketplaceFilter) ([]*MarketplaceRouteItem, error) {
	s.mu.RLock()
	routes := make([]*Route, 0)
	tenantNames := make(map[string]string)
	for id, t := range s.tenants {
		tenantNames[id] = t.Name
	}
	for _, r := range s.routes {
		if r.IsPublic {
			copied := *r
			routes = append(routes, &copied)
		}
	}
	usageSvc := s.usageSvc
	s.mu.RUnlock()

	items := make([]*MarketplaceRouteItem, 0, len(routes))
	for _, r := range routes {
		item := buildMarketplaceRouteItem(ctx, usageSvc, r, tenantNames[r.TenantID])
		if matchesMarketplaceFilter(item, filter) {
			items = append(items, item)
		}
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].CreatedAt == items[j].CreatedAt {
			return items[i].Slug < items[j].Slug
		}
		return items[i].CreatedAt > items[j].CreatedAt
	})

	return items, nil
}

// GetMarketplaceRouteBySlug returns a single public marketplace route by its semantic slug or route_id (MemoryService).
func (s *MemoryService) GetMarketplaceRouteBySlug(ctx context.Context, slug string) (*MarketplaceRouteItem, error) {
	cleanSlug := strings.ToLower(strings.TrimSpace(slug))
	if cleanSlug == "" {
		return nil, ErrRouteNotFound
	}

	s.mu.RLock()
	var matched *Route
	var providerName string
	for _, r := range s.routes {
		if !r.IsPublic {
			continue
		}
		effectiveSlug := NormalizeSlug(r.Slug, r.PathPattern)
		if strings.EqualFold(effectiveSlug, cleanSlug) || strings.EqualFold(r.RouteID, cleanSlug) {
			copied := *r
			matched = &copied
			if t, ok := s.tenants[r.TenantID]; ok {
				providerName = t.Name
			}
			break
		}
	}
	usageSvc := s.usageSvc
	s.mu.RUnlock()

	if matched == nil {
		return nil, ErrRouteNotFound
	}

	return buildMarketplaceRouteItem(ctx, usageSvc, matched, providerName), nil
}

// ListMarketplaceRoutes returns all public marketplace routes matching the filter (PostgresService).
func (p *PostgresService) ListMarketplaceRoutes(ctx context.Context, filter MarketplaceFilter) ([]*MarketplaceRouteItem, error) {
	query := `
		SELECT r.route_id, r.tenant_id, r.project_id, COALESCE(r.slug, ''), COALESCE(r.title, ''),
		       COALESCE(r.summary, ''), COALESCE(r.provider_name, ''), r.is_public,
		       COALESCE(r.category, 'General'), COALESCE(r.tags, '[]'::jsonb), COALESCE(r.description_md, ''),
		       COALESCE(r.network, 'eip155:421614'), COALESCE(r.network_label, ''),
		       r.path_pattern, COALESCE(r.methods, '["POST"]'::jsonb), r.upstream_url,
		       r.price_base_units, r.asset, r.onchain_price_base_units, r.onchain_asset,
		       r.payee_address, r.allowed_payment_methods, r.timeout_ms, r.rate_limit_rpm,
		       COALESCE(r.parameters, '[]'::jsonb), COALESCE(r.sample_params, '{}'::jsonb), COALESCE(r.sample_response, '{}'::jsonb),
		       r.status,
		       EXTRACT(EPOCH FROM r.created_at)::bigint, EXTRACT(EPOCH FROM r.updated_at)::bigint,
		       COALESCE(t.name, 'OpenAgentPay Verified Provider')
		FROM ap_route r
		LEFT JOIN ap_tenant t ON t.tenant_id = r.tenant_id
		WHERE r.is_public = TRUE
		ORDER BY r.created_at DESC;
	`
	rows, err := p.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	usageSvc := p.GetUsageService()
	items := make([]*MarketplaceRouteItem, 0)
	for rows.Next() {
		var r Route
		var tagsBytes []byte
		var methodsBytes []byte
		var paramsBytes []byte
		var sampleParamsBytes []byte
		var sampleResponseBytes []byte
		var onchainPrice sql.NullInt64
		var onchainAsset sql.NullString
		var tenantName string

		if err := rows.Scan(
			&r.RouteID, &r.TenantID, &r.ProjectID, &r.Slug, &r.Title,
			&r.Summary, &r.ProviderName, &r.IsPublic,
			&r.Category, &tagsBytes, &r.DescriptionMD,
			&r.Network, &r.NetworkLabel,
			&r.PathPattern, &methodsBytes, &r.UpstreamURL,
			&r.PriceBaseUnits, &r.Asset, &onchainPrice, &onchainAsset,
			&r.PayeeAddress, &r.AllowedPaymentMethods, &r.TimeoutMs, &r.RateLimitRPM,
			&paramsBytes, &sampleParamsBytes, &sampleResponseBytes,
			&r.Status,
			&r.CreatedAt, &r.UpdatedAt, &tenantName,
		); err != nil {
			return nil, err
		}
		if len(tagsBytes) > 0 {
			_ = json.Unmarshal(tagsBytes, &r.Tags)
		}
		if len(methodsBytes) > 0 {
			_ = json.Unmarshal(methodsBytes, &r.Methods)
		}
		if len(paramsBytes) > 0 {
			_ = json.Unmarshal(paramsBytes, &r.Parameters)
		}
		if len(sampleParamsBytes) > 0 {
			_ = json.Unmarshal(sampleParamsBytes, &r.SampleParams)
		}
		if len(sampleResponseBytes) > 0 {
			_ = json.Unmarshal(sampleResponseBytes, &r.SampleResponse)
		}
		if onchainPrice.Valid {
			v := onchainPrice.Int64
			r.OnchainPriceBaseUnits = &v
		}
		if onchainAsset.Valid {
			r.OnchainAsset = onchainAsset.String
		}

		provider := r.ProviderName
		if provider == "" {
			provider = tenantName
		}
		item := buildMarketplaceRouteItem(ctx, usageSvc, &r, provider)
		if matchesMarketplaceFilter(item, filter) {
			items = append(items, item)
		}
	}
	return items, nil
}

// GetMarketplaceRouteBySlug returns a single public marketplace route by slug (PostgresService).
func (p *PostgresService) GetMarketplaceRouteBySlug(ctx context.Context, slug string) (*MarketplaceRouteItem, error) {
	cleanSlug := strings.ToLower(strings.TrimSpace(slug))
	if cleanSlug == "" {
		return nil, ErrRouteNotFound
	}

	items, err := p.ListMarketplaceRoutes(ctx, MarketplaceFilter{})
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		if strings.EqualFold(item.Slug, cleanSlug) || strings.EqualFold(item.RouteID, cleanSlug) {
			return item, nil
		}
	}
	return nil, ErrRouteNotFound
}

// NewPublicMarketplaceHandler creates an unauthenticated HTTP handler for /api/v1/public/marketplace/...
func NewPublicMarketplaceHandler(svc Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Enable CORS for public storefront / Next.js / Agent discovery clients
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Accept, X-Forwarded-For")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		path := strings.TrimRight(r.URL.Path, "/")

		// Handle POST /api/v1/public/marketplace/trial-key
		if r.Method == http.MethodPost && path == "/api/v1/public/marketplace/trial-key" {
			var req TrialKeyRequest
			_ = json.NewDecoder(r.Body).Decode(&req)

			// Resolve client IP from X-Forwarded-For or RemoteAddr
			clientIP := r.Header.Get("X-Forwarded-For")
			if clientIP != "" {
				parts := strings.Split(clientIP, ",")
				clientIP = strings.TrimSpace(parts[0])
			}
			if clientIP == "" {
				clientIP = r.RemoteAddr
				if idx := strings.LastIndex(clientIP, ":"); idx != -1 {
					clientIP = clientIP[:idx]
				}
			}

			trialResp, err := svc.CreateTrialAPIKey(r.Context(), clientIP, req.ClientFingerprint)
			if err != nil {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				if errors.Is(err, ErrTrialRateLimitExceeded) {
					w.WriteHeader(http.StatusTooManyRequests)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"error": map[string]string{
							"code":    "TRIAL_RATE_LIMIT_EXCEEDED",
							"message": "当前 IP 试用申领过于频繁，请直接登录控制台获取长期免费 API Key",
						},
					})
					return
				}
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"error": map[string]string{
						"code":    "ERR_INTERNAL",
						"message": err.Error(),
					},
				})
				return
			}

			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(trialResp)
			return
		}

		if r.Method != http.MethodGet {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error": map[string]string{
					"code":    "ERR_METHOD_NOT_ALLOWED",
					"message": "only GET or POST (trial-key) is supported on public marketplace endpoints",
				},
			})
			return
		}

		if path == "/api/v1/public/marketplace/routes" {
			q := r.URL.Query()
			queryStr := q.Get("q")
			if queryStr == "" {
				queryStr = q.Get("search")
			}
			filter := MarketplaceFilter{
				Query:    queryStr,
				Category: q.Get("category"),
				Network:  q.Get("network"),
				Tag:      q.Get("tag"),
			}
			items, err := svc.ListMarketplaceRoutes(r.Context(), filter)
			if err != nil {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"error": map[string]string{
						"code":    "ERR_INTERNAL",
						"message": err.Error(),
					},
				})
				return
			}
			if items == nil {
				items = []*MarketplaceRouteItem{}
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"count":  len(items),
				"routes": items,
			})
			return
		}

		if strings.HasPrefix(path, "/api/v1/public/marketplace/routes/") {
			slug := strings.TrimPrefix(path, "/api/v1/public/marketplace/routes/")
			if slug == "" || strings.Contains(slug, "/") {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"error": map[string]string{
						"code":    "ERR_NOT_FOUND",
						"message": "marketplace route not found",
					},
				})
				return
			}
			item, err := svc.GetMarketplaceRouteBySlug(r.Context(), slug)
			if err != nil {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"error": map[string]string{
						"code":    "ERR_NOT_FOUND",
						"message": err.Error(),
					},
				})
				return
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"route": item,
			})
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]string{
				"code":    "ERR_NOT_FOUND",
				"message": "marketplace endpoint not found",
			},
		})
	})
}
