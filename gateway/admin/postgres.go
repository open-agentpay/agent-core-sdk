package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/open-agentpay/agent-core-sdk/gateway/agent"
	"github.com/open-agentpay/agent-core-sdk/gateway/auth"
	"github.com/open-agentpay/agent-core-sdk/gateway/payment"
	"github.com/open-agentpay/agent-core-sdk/gateway/rcu"
	"github.com/open-agentpay/agent-core-sdk/gateway/timeline"
	"github.com/open-agentpay/agent-core-sdk/gateway/upstreamauth"
	"github.com/open-agentpay/agent-core-sdk/gateway/usage"
	"github.com/open-agentpay/agent-core-sdk/gateway/wallet"
)

// PostgresService implements admin.Service backed by PostgreSQL.
type PostgresService struct {
	db             *sql.DB
	agentReg       *agent.Registry
	walletSvc      wallet.Service
	usageSvc       usage.Service
	paymentSvc     payment.Service
	timelineSvc    timeline.Service
	mu             sync.RWMutex
	lastValidation map[string]*ValidationResult
	rcuMgr         *rcu.Manager
	telemetryCache map[string]*telemetryCacheEntry
	telemetryMu    sync.RWMutex
}

type telemetryCacheEntry struct {
	data      *RouteTelemetryOverviewResponse
	expiresAt time.Time
}

// NewPostgresService initializes a PostgreSQL admin service and synchronizes the active agents/keys into the in-memory registry.
func NewPostgresService(db *sql.DB, agentReg *agent.Registry, walletSvc wallet.Service) (*PostgresService, error) {
	svc := &PostgresService{
		db:             db,
		agentReg:       agentReg,
		walletSvc:      walletSvc,
		lastValidation: make(map[string]*ValidationResult),
		telemetryCache: make(map[string]*telemetryCacheEntry),
	}
	if err := svc.initSync(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to synchronize agent registry from postgres: %w", err)
	}
	return svc, nil
}

// initSync loads active agents and active API keys from PostgreSQL into the fast-path in-memory registry.
func (p *PostgresService) initSync(ctx context.Context) error {
	_, _ = p.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS api_auth_configs (
			id VARCHAR(64) PRIMARY KEY,
			tenant_id VARCHAR(64) NOT NULL REFERENCES ap_tenant(tenant_id) ON DELETE CASCADE,
			api_id VARCHAR(64) NOT NULL UNIQUE REFERENCES ap_route(route_id) ON DELETE CASCADE,
			type VARCHAR(64) NOT NULL,
			params JSONB NOT NULL DEFAULT '{}'::jsonb,
			secret_enc BYTEA NULL,
			key_version INT NOT NULL DEFAULT 1,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_api_auth_configs_tenant ON api_auth_configs(tenant_id);
		CREATE INDEX IF NOT EXISTS idx_api_auth_configs_api ON api_auth_configs(api_id);

		ALTER TABLE ap_route ADD COLUMN IF NOT EXISTS slug VARCHAR(128) NULL;
		ALTER TABLE ap_route ADD COLUMN IF NOT EXISTS title VARCHAR(256) NOT NULL DEFAULT '';
		ALTER TABLE ap_route ADD COLUMN IF NOT EXISTS is_public BOOLEAN NOT NULL DEFAULT FALSE;
		ALTER TABLE ap_route ADD COLUMN IF NOT EXISTS category VARCHAR(64) NOT NULL DEFAULT 'General';
		ALTER TABLE ap_route ADD COLUMN IF NOT EXISTS tags JSONB NOT NULL DEFAULT '[]'::jsonb;
		ALTER TABLE ap_route ADD COLUMN IF NOT EXISTS description_md TEXT NOT NULL DEFAULT '';
		ALTER TABLE ap_route ADD COLUMN IF NOT EXISTS network VARCHAR(64) NOT NULL DEFAULT 'eip155:421614';

		ALTER TABLE ap_usage_event ADD COLUMN IF NOT EXISTS prompt_tokens BIGINT NOT NULL DEFAULT 0;
		ALTER TABLE ap_usage_event ADD COLUMN IF NOT EXISTS completion_tokens BIGINT NOT NULL DEFAULT 0;
		ALTER TABLE ap_usage_event ADD COLUMN IF NOT EXISTS total_tokens BIGINT NOT NULL DEFAULT 0;
	`)

	if p.agentReg == nil {
		return nil
	}

	agentRows, err := p.db.QueryContext(ctx, `
		SELECT agent_id, tenant_id, project_id, name, status, policy_config
		FROM ap_agent
		WHERE status != 'revoked';
	`)
	if err != nil {
		return err
	}
	defer agentRows.Close()

	for agentRows.Next() {
		var agID, tID, pID, name, status string
		var polCfgBytes []byte
		if err := agentRows.Scan(&agID, &tID, &pID, &name, &status, &polCfgBytes); err != nil {
			return err
		}
		var polCfg map[string]interface{}
		_ = json.Unmarshal(polCfgBytes, &polCfg)

		p.agentReg.RegisterAgent(&agent.AgentIdentity{
			AgentID:   agID,
			TenantID:  tID,
			ProjectID: pID,
			Name:      name,
			Status:    agent.AgentStatus(status),
		}, nil)
	}

	keyRows, err := p.db.QueryContext(ctx, `
		SELECT key_hash, agent_id
		FROM ap_api_key
		WHERE status = 'active';
	`)
	if err != nil {
		return err
	}
	defer keyRows.Close()

	for keyRows.Next() {
		var keyHash, agID string
		if err := keyRows.Scan(&keyHash, &agID); err != nil {
			return err
		}
		p.agentReg.BindAPIKeyHash(keyHash, agID)
	}
	return nil
}

func (p *PostgresService) recordAudit(ctx context.Context, tenantID, operatorID, action, targetType, targetID string, before, after map[string]interface{}, clientIP string) {
	if clientIP == "" {
		clientIP = "127.0.0.1"
	}
	auditID := GenerateAuditID()

	var beforeJSON, afterJSON []byte
	if before != nil {
		beforeJSON, _ = json.Marshal(before)
	}
	if after != nil {
		afterJSON, _ = json.Marshal(after)
	}

	_, _ = p.db.ExecContext(ctx, `
		INSERT INTO ap_audit_event (
			audit_id, tenant_id, operator_id, action, target_type, target_id, before_state, after_state, client_ip, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW());
	`, auditID, tenantID, operatorID, action, targetType, targetID, beforeJSON, afterJSON, clientIP)
}

func (p *PostgresService) getMember(ctx context.Context, tenantID, memberID string) (*Member, error) {
	var m Member
	var pwd sql.NullString
	err := p.db.QueryRowContext(ctx, `
		SELECT member_id, tenant_id, email, password_hash, role, status,
		       EXTRACT(EPOCH FROM created_at)::bigint, EXTRACT(EPOCH FROM updated_at)::bigint
		FROM ap_member
		WHERE member_id = $1;
	`, memberID).Scan(
		&m.MemberID, &m.TenantID, &m.Email, &pwd, &m.Role, &m.Status, &m.CreatedAt, &m.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrMemberNotFound
	}
	if err != nil {
		return nil, err
	}
	if tenantID != "" && m.TenantID != tenantID {
		return nil, ErrMemberNotFound
	}
	if pwd.Valid {
		m.PasswordHash = pwd.String
	}
	return &m, nil
}

func (p *PostgresService) enforcePermission(ctx context.Context, actorMemberID, tenantID string, perm Permission) error {
	if actorMemberID == "" {
		if auth.IsSystemContext(ctx) {
			return nil
		}
		return ErrPermissionDenied
	}
	actor, err := p.getMember(ctx, tenantID, actorMemberID)
	if err != nil || actor.TenantID != tenantID {
		return ErrPermissionDenied
	}
	return EnforcePermission(actor, perm)
}

// ----------------------------------------------------------------------------
// Auth
// ----------------------------------------------------------------------------


type routeRowScanner interface {
	Scan(dest ...interface{}) error
}

func (p *PostgresService) GetAuthTypes() []upstreamauth.AuthTypeSchema {
	return upstreamauth.ListSchemas()
}

func (p *PostgresService) TestUpstream(ctx context.Context, tenantID string, input *TestUpstreamInput, actorMemberID string) (*TestUpstreamResult, error) {
	if err := p.enforcePermission(ctx, actorMemberID, tenantID, PermissionRouteRead); err != nil {
		return nil, err
	}
	result, cleanURL, testErr := executeUpstreamTest(ctx, input)
	if testErr != nil {
		return nil, testErr
	}
	if cleanURL != "" && result.StatusCode > 0 || result.Error != "" && strings.HasPrefix(result.Error, "upstream connection error:") {
		p.recordAudit(ctx, tenantID, actorMemberID, "route.tested", "Route", "", nil, map[string]interface{}{
			"url":         cleanURL,
			"auth_type":   "",
			"success":     result.Success,
			"status_code": result.StatusCode,
		}, "127.0.0.1")
	}
	return result, nil
}

// ----------------------------------------------------------------------------
// RCU Data Plane Synchronization
// ----------------------------------------------------------------------------

func (p *PostgresService) SetRCUManager(mgr *rcu.Manager) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rcuMgr = mgr
}

func (p *PostgresService) SyncRCU(ctx context.Context) error {
	p.mu.RLock()
	mgr := p.rcuMgr
	p.mu.RUnlock()
	if mgr == nil {
		return nil
	}

	rows, err := p.db.QueryContext(ctx, `
		SELECT r.route_id, r.tenant_id, r.project_id, r.path_pattern, r.upstream_url,
		       r.price_base_units, r.asset, r.onchain_price_base_units, r.onchain_asset, r.payee_address, r.allowed_payment_methods,
		       r.timeout_ms, r.rate_limit_rpm, r.status,
		       COALESCE(r.is_trial_allowed, TRUE),
		       c.type, c.params, c.secret_enc, c.key_version,
		       COALESCE(r.route_type, 'api'), COALESCE(r.model_name, ''), COALESCE(r.pricing_type, 'fixed'),
		       COALESCE(r.prompt_token_price_base_units, 0), COALESCE(r.completion_token_price_base_units, 0),
		       COALESCE(r.is_public, FALSE)
		FROM ap_route r
		LEFT JOIN api_auth_configs c ON c.api_id = r.route_id
		WHERE r.status = 'active';
	`)
	if err != nil {
		return fmt.Errorf("failed to query active routes: %w", err)
	}
	defer rows.Close()

	var routes []rcu.RouteConfig
	for rows.Next() {
		var r rcu.RouteConfig
		var onchainPrice sql.NullInt64
		var onchainAsset sql.NullString
		var isTrialAllowed sql.NullBool
		var cType sql.NullString
		var cParamsBytes, cSecretEnc []byte
		var cKeyVersion sql.NullInt64
		var routeType, modelName, pricingType sql.NullString
		var promptPrice, completionPrice sql.NullInt64
		var isPublic sql.NullBool

		if err := rows.Scan(
			&r.RouteID, &r.TenantID, &r.ProjectID, &r.PathPattern, &r.UpstreamURL,
			&r.PriceBaseUnits, &r.Asset, &onchainPrice, &onchainAsset, &r.PayeeAddress, &r.AllowedPaymentMethods,
			&r.TimeoutMS, &r.RateLimitRPM, &r.Status,
			&isTrialAllowed,
			&cType, &cParamsBytes, &cSecretEnc, &cKeyVersion,
			&routeType, &modelName, &pricingType, &promptPrice, &completionPrice,
			&isPublic,
		); err != nil {
			return fmt.Errorf("failed to scan active route: %w", err)
		}
		if isPublic.Valid {
			r.IsPublic = isPublic.Bool
			r.IsPublicSnake = isPublic.Bool
		}
		if routeType.Valid && routeType.String != "" {
			r.RouteType = routeType.String
		} else {
			r.RouteType = "api"
		}
		if modelName.Valid {
			r.ModelName = modelName.String
		}
		if pricingType.Valid && pricingType.String != "" {
			r.PricingType = pricingType.String
		} else {
			r.PricingType = "fixed"
		}
		if promptPrice.Valid {
			r.PromptTokenPriceBaseUnits = promptPrice.Int64
		}
		if completionPrice.Valid {
			r.CompletionTokenPriceBaseUnits = completionPrice.Int64
		}
		if isTrialAllowed.Valid {
			b := isTrialAllowed.Bool
			r.IsTrialAllowed = &b
		}
		if onchainPrice.Valid {
			v := onchainPrice.Int64
			r.OnchainPriceBaseUnits = &v
		}
		if onchainAsset.Valid {
			r.OnchainAsset = onchainAsset.String
		}

		if cType.Valid && cType.String != "" {
			var params map[string]interface{}
			if len(cParamsBytes) > 0 {
				_ = json.Unmarshal(cParamsBytes, &params)
			}
			r.UpstreamAuth = &upstreamauth.UpstreamAuthConfig{
				Type:       cType.String,
				Params:     params,
				SecretEnc:  cSecretEnc,
				HasSecret:  len(cSecretEnc) > 0,
				KeyVersion: int(cKeyVersion.Int64),
			}
			if len(cSecretEnc) > 0 {
				if dec, err := upstreamauth.DecryptSecretsVersioned(cSecretEnc, int(cKeyVersion.Int64)); err == nil {
					r.UpstreamSecrets = dec
				}
			}
		}
		routes = append(routes, r)
	}

	polRows, err := p.db.QueryContext(ctx, `
		SELECT policy_id, tenant_id, project_id, agent_id, route_id,
		       max_amount_per_request, rolling_24h_budget_cap, circuit_breaker_max_rpm,
		       whitelisted_payees, whitelisted_networks, whitelisted_routes, is_active
		FROM ap_policy
		WHERE is_active = TRUE;
	`)
	var policies []rcu.PolicyConfig
	if err == nil {
		defer polRows.Close()
		for polRows.Next() {
			var pol rcu.PolicyConfig
			var agID, rteID sql.NullString
			var payeesBytes, networksBytes, routesBytes []byte
			if err := polRows.Scan(
				&pol.PolicyID, &pol.TenantID, &pol.ProjectID, &agID, &rteID,
				&pol.MaxAmountPerRequest, &pol.Rolling24hBudgetCap, &pol.CircuitBreakerMaxRPM,
				&payeesBytes, &networksBytes, &routesBytes, &pol.IsActive,
			); err == nil {
				if agID.Valid {
					pol.AgentID = &agID.String
				}
				if rteID.Valid {
					pol.RouteID = &rteID.String
				}
				_ = json.Unmarshal(networksBytes, &pol.WhitelistedNetworks)
				_ = json.Unmarshal(routesBytes, &pol.WhitelistedRoutes)
				policies = append(policies, pol)
			}
		}
	}

	return mergeAndApplyRCUSnapshot(mgr, routes, policies, "admin_postgres_sync")
}

// ----------------------------------------------------------------------------
// Observability: Usage, Payment Correlation & Timeline (T5.1, T5.2, T5.8)
// ----------------------------------------------------------------------------

func (p *PostgresService) SetUsageService(svc usage.Service) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.usageSvc = svc
}

func (p *PostgresService) GetUsageService() usage.Service {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.usageSvc == nil {
		p.usageSvc = usage.NewPostgresService(p.db)
	}
	return p.usageSvc
}

func (p *PostgresService) SetPaymentService(svc payment.Service) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.paymentSvc = svc
}

func (p *PostgresService) GetPaymentService() payment.Service {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.paymentSvc == nil {
		return payment.NewPostgresService(p.db)
	}
	return p.paymentSvc
}

func (p *PostgresService) SetTimelineService(svc timeline.Service) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.timelineSvc = svc
}

func (p *PostgresService) GetTimelineService() timeline.Service {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.timelineSvc == nil {
		return timeline.NewPostgresService(p.db)
	}
	return p.timelineSvc
}

