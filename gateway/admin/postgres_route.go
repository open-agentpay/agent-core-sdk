package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

func (p *PostgresService) upsertUpstreamAuth(ctx context.Context, tenantID, routeID string, authCfg *UpstreamAuthConfig, now time.Time) error {
	if authCfg == nil {
		return nil
	}
	paramsJSON, _ := json.Marshal(authCfg.Params)
	_, err := p.db.ExecContext(ctx, `
		INSERT INTO api_auth_configs (id, tenant_id, api_id, type, params, secret_enc, key_version, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (api_id) DO UPDATE SET
			type = EXCLUDED.type,
			params = EXCLUDED.params,
			secret_enc = COALESCE(EXCLUDED.secret_enc, api_auth_configs.secret_enc),
			key_version = EXCLUDED.key_version,
			updated_at = EXCLUDED.updated_at;
	`, "auth_"+routeID, tenantID, routeID, authCfg.Type, paramsJSON, authCfg.SecretEnc, authCfg.KeyVersion, now)
	return err
}

func scanRouteRow(scanner routeRowScanner) (*Route, error) {
	var r Route
	var tagsBytes, methodsBytes, paramsBytes, sampleParamsBytes, sampleResponseBytes []byte
	var onchainPrice sql.NullInt64
	var onchainAsset sql.NullString
	var cType sql.NullString
	var cParamsBytes, cSecretEnc []byte
	var cKeyVersion, cUpdatedAt sql.NullInt64
	var routeType, modelName, pricingType sql.NullString
	var promptPrice, completionPrice sql.NullInt64

	if err := scanner.Scan(
		&r.RouteID, &r.TenantID, &r.ProjectID, &r.Slug, &r.Title,
		&r.Summary, &r.ProviderName, &r.IsPublic,
		&r.Category, &tagsBytes, &r.DescriptionMD,
		&r.Network, &r.NetworkLabel,
		&r.PathPattern, &methodsBytes, &r.UpstreamURL, &r.PriceBaseUnits, &r.Asset,
		&onchainPrice, &onchainAsset, &r.PayeeAddress, &r.AllowedPaymentMethods, &r.TimeoutMs, &r.RateLimitRPM,
		&paramsBytes, &sampleParamsBytes, &sampleResponseBytes,
		&r.Status, &r.CreatedAt, &r.UpdatedAt,
		&cType, &cParamsBytes, &cSecretEnc, &cKeyVersion, &cUpdatedAt,
		&routeType, &modelName, &pricingType, &promptPrice, &completionPrice,
	); err != nil {
		return nil, err
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

	if len(tagsBytes) > 0 {
		_ = json.Unmarshal(tagsBytes, &r.Tags)
	}
	if r.Tags == nil {
		r.Tags = []string{}
	}
	if len(methodsBytes) > 0 {
		_ = json.Unmarshal(methodsBytes, &r.Methods)
	}
	if len(r.Methods) == 0 {
		r.Methods = []string{"POST"}
	}
	if len(paramsBytes) > 0 {
		_ = json.Unmarshal(paramsBytes, &r.Parameters)
	}
	if r.Parameters == nil {
		r.Parameters = []MarketplaceParameter{}
	}
	if len(sampleParamsBytes) > 0 {
		_ = json.Unmarshal(sampleParamsBytes, &r.SampleParams)
	}
	if r.SampleParams == nil {
		r.SampleParams = map[string]interface{}{}
	}
	if len(sampleResponseBytes) > 0 {
		_ = json.Unmarshal(sampleResponseBytes, &r.SampleResponse)
	}
	if r.SampleResponse == nil {
		r.SampleResponse = map[string]interface{}{}
	}

	r.Slug = NormalizeSlug(r.Slug, r.PathPattern)
	r.Title = DefaultTitleFromSlug(r.Title, r.Slug, r.PathPattern)
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
		r.UpstreamAuth = &UpstreamAuthConfig{
			Type:       cType.String,
			Params:     params,
			SecretEnc:  cSecretEnc,
			HasSecret:  len(cSecretEnc) > 0,
			KeyVersion: int(cKeyVersion.Int64),
			UpdatedAt:  cUpdatedAt.Int64,
		}
	}
	return &r, nil
}

func (p *PostgresService) CreateRoute(ctx context.Context, route *Route, actorMemberID string) (*Route, error) {
	if route == nil {
		return nil, fmt.Errorf("route cannot be nil")
	}
	if err := p.enforcePermission(ctx, actorMemberID, route.TenantID, PermissionRouteWrite); err != nil {
		return nil, err
	}

	cleanPath := strings.TrimSpace(route.PathPattern)
	if cleanPath == "" || !strings.HasPrefix(cleanPath, "/") {
		return nil, fmt.Errorf("path_pattern must begin with '/'")
	}

	var exists bool
	_ = p.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM ap_route WHERE tenant_id = $1 AND path_pattern = $2);`, route.TenantID, cleanPath).Scan(&exists)
	if exists {
		return nil, ErrRouteAlreadyExists
	}

	var tenantCurrency string
	if t, err := p.GetTenant(ctx, route.TenantID); err == nil {
		tenantCurrency = t.Currency
	}

	now := time.Now()
	if err := normalizeNewRoute(route, tenantCurrency, now.Unix()); err != nil {
		return nil, err
	}

	var onchainPrice interface{}
	if route.OnchainPriceBaseUnits != nil {
		onchainPrice = *route.OnchainPriceBaseUnits
	}
	onchainAsset := route.OnchainAsset
	if onchainAsset == "" {
		onchainAsset = route.Asset
	}
	if onchainAsset == "" {
		onchainAsset = "CNY"
	}

	tagsJSON, _ := json.Marshal(route.Tags)
	methodsJSON, _ := json.Marshal(route.Methods)
	paramsJSON, _ := json.Marshal(route.Parameters)
	sampleParamsJSON, _ := json.Marshal(route.SampleParams)
	sampleResponseJSON, _ := json.Marshal(route.SampleResponse)

	if _, err := p.db.ExecContext(ctx, `
		INSERT INTO ap_route (
			route_id, tenant_id, project_id, slug, title, summary, provider_name, is_public, category, tags, description_md, network, network_label,
			path_pattern, methods, upstream_url, price_base_units, asset, onchain_price_base_units, onchain_asset,
			payee_address, allowed_payment_methods, timeout_ms, rate_limit_rpm, parameters, sample_params, sample_response, status,
			route_type, model_name, pricing_type, prompt_token_price_base_units, completion_token_price_base_units,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $34);
	`, route.RouteID, route.TenantID, route.ProjectID, route.Slug, route.Title, route.Summary, route.ProviderName, route.IsPublic, route.Category, tagsJSON, route.DescriptionMD, route.Network, route.NetworkLabel,
		route.PathPattern, methodsJSON, route.UpstreamURL, route.PriceBaseUnits, route.Asset, onchainPrice, onchainAsset,
		route.PayeeAddress, route.AllowedPaymentMethods, route.TimeoutMs, route.RateLimitRPM, paramsJSON, sampleParamsJSON, sampleResponseJSON, string(route.Status),
		route.RouteType, route.ModelName, route.PricingType, route.PromptTokenPriceBaseUnits, route.CompletionTokenPriceBaseUnits,
		now); err != nil {
		return nil, err
	}

	if err := p.upsertUpstreamAuth(ctx, route.TenantID, route.RouteID, route.UpstreamAuth, now); err != nil {
		return nil, fmt.Errorf("failed to save upstream_auth: %w", err)
	}

	p.recordAudit(ctx, route.TenantID, actorMemberID, "route.created", "Route", route.RouteID, nil, map[string]interface{}{"path": route.PathPattern, "slug": route.Slug, "is_public": route.IsPublic}, "127.0.0.1")
	_ = p.SyncRCU(ctx)
	return route, nil
}

const selectRouteWithAuthCols = `
	SELECT r.route_id, r.tenant_id, r.project_id, COALESCE(r.slug, ''), COALESCE(r.title, ''),
	       COALESCE(r.summary, ''), COALESCE(r.provider_name, ''), r.is_public,
	       COALESCE(r.category, 'General'), COALESCE(r.tags, '[]'::jsonb), COALESCE(r.description_md, ''),
	       COALESCE(r.network, 'eip155:421614'), COALESCE(r.network_label, ''),
	       r.path_pattern, COALESCE(r.methods, '["POST"]'::jsonb), r.upstream_url, r.price_base_units, r.asset,
	       r.onchain_price_base_units, r.onchain_asset, r.payee_address, r.allowed_payment_methods, r.timeout_ms, r.rate_limit_rpm,
	       COALESCE(r.parameters, '[]'::jsonb), COALESCE(r.sample_params, '{}'::jsonb), COALESCE(r.sample_response, '{}'::jsonb),
	       r.status, EXTRACT(EPOCH FROM r.created_at)::bigint, EXTRACT(EPOCH FROM r.updated_at)::bigint,
	       c.type, c.params, c.secret_enc, c.key_version, EXTRACT(EPOCH FROM c.updated_at)::bigint,
	       COALESCE(r.route_type, 'api'), COALESCE(r.model_name, ''), COALESCE(r.pricing_type, 'fixed'),
	       COALESCE(r.prompt_token_price_base_units, 0), COALESCE(r.completion_token_price_base_units, 0)
	FROM ap_route r
	LEFT JOIN api_auth_configs c ON c.api_id = r.route_id
`

func (p *PostgresService) GetRoute(ctx context.Context, tenantID, routeID string) (*Route, error) {
	r, err := scanRouteRow(p.db.QueryRowContext(ctx, selectRouteWithAuthCols+` WHERE r.route_id = $1;`, routeID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrRouteNotFound
	}
	if err != nil {
		return nil, err
	}
	if tenantID != "" && r.TenantID != tenantID {
		return nil, ErrRouteNotFound
	}
	return r, nil
}

func (p *PostgresService) ListRoutes(ctx context.Context, tenantID string) ([]*Route, error) {
	rows, err := p.db.QueryContext(ctx, selectRouteWithAuthCols+` WHERE r.tenant_id = $1 ORDER BY r.created_at DESC;`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	routes := make([]*Route, 0)
	for rows.Next() {
		r, err := scanRouteRow(rows)
		if err != nil {
			return nil, err
		}
		routes = append(routes, r)
	}
	return routes, nil
}

func (p *PostgresService) UpdateRoute(ctx context.Context, input *UpdateRouteInput, actorMemberID string) (*Route, error) {
	if input == nil {
		return nil, fmt.Errorf("update input cannot be nil")
	}
	if err := p.enforcePermission(ctx, actorMemberID, input.TenantID, PermissionRouteWrite); err != nil {
		return nil, err
	}

	r, err := p.GetRoute(ctx, input.TenantID, input.RouteID)
	if err != nil {
		return nil, err
	}

	before := map[string]interface{}{"path": r.PathPattern, "slug": r.Slug, "is_public": r.IsPublic, "upstream": r.UpstreamURL, "price": r.PriceBaseUnits}

	if input.PathPattern != nil {
		clean := strings.TrimSpace(*input.PathPattern)
		var exists bool
		_ = p.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM ap_route WHERE tenant_id = $1 AND path_pattern = $2 AND route_id != $3);`, input.TenantID, clean, input.RouteID).Scan(&exists)
		if exists {
			return nil, ErrRouteAlreadyExists
		}
		r.PathPattern = clean
	}

	now := time.Now()
	if err := applyRouteUpdateFields(r, input, now.Unix()); err != nil {
		return nil, err
	}

	var onchainPrice interface{}
	if r.OnchainPriceBaseUnits != nil {
		onchainPrice = *r.OnchainPriceBaseUnits
	}
	onchainAsset := r.OnchainAsset
	if onchainAsset == "" {
		onchainAsset = r.Asset
	}
	if onchainAsset == "" {
		onchainAsset = "CNY"
	}
	if len(r.Methods) == 0 {
		r.Methods = []string{"POST"}
	}
	if r.Parameters == nil {
		r.Parameters = []MarketplaceParameter{}
	}
	if r.SampleParams == nil {
		r.SampleParams = map[string]interface{}{}
	}
	if r.SampleResponse == nil {
		r.SampleResponse = map[string]interface{}{}
	}

	tagsJSON, _ := json.Marshal(r.Tags)
	methodsJSON, _ := json.Marshal(r.Methods)
	paramsJSON, _ := json.Marshal(r.Parameters)
	sampleParamsJSON, _ := json.Marshal(r.SampleParams)
	sampleResponseJSON, _ := json.Marshal(r.SampleResponse)

	if _, err := p.db.ExecContext(ctx, `
		UPDATE ap_route
		SET path_pattern = $1, upstream_url = $2, price_base_units = $3, asset = $4, onchain_price_base_units = $5, onchain_asset = $6,
		    payee_address = $7, allowed_payment_methods = $8, timeout_ms = $9, rate_limit_rpm = $10, status = $11,
		    slug = $12, title = $13, summary = $14, provider_name = $15, is_public = $16, category = $17, tags = $18, description_md = $19, network = $20, network_label = $21,
		    methods = $22, parameters = $23, sample_params = $24, sample_response = $25,
		    route_type = $26, model_name = $27, pricing_type = $28, prompt_token_price_base_units = $29, completion_token_price_base_units = $30,
		    updated_at = NOW()
		WHERE route_id = $31;
	`, r.PathPattern, r.UpstreamURL, r.PriceBaseUnits, r.Asset, onchainPrice, onchainAsset,
		r.PayeeAddress, r.AllowedPaymentMethods, r.TimeoutMs, r.RateLimitRPM, string(r.Status),
		r.Slug, r.Title, r.Summary, r.ProviderName, r.IsPublic, r.Category, tagsJSON, r.DescriptionMD, r.Network, r.NetworkLabel,
		methodsJSON, paramsJSON, sampleParamsJSON, sampleResponseJSON,
		r.RouteType, r.ModelName, r.PricingType, r.PromptTokenPriceBaseUnits, r.CompletionTokenPriceBaseUnits,
		input.RouteID); err != nil {
		return nil, err
	}

	if input.UpstreamAuth != nil {
		if err := p.upsertUpstreamAuth(ctx, input.TenantID, input.RouteID, r.UpstreamAuth, now); err != nil {
			return nil, fmt.Errorf("failed to update upstream_auth: %w", err)
		}
	}

	p.recordAudit(ctx, input.TenantID, actorMemberID, "route.updated", "Route", input.RouteID, before, map[string]interface{}{"path": r.PathPattern}, "127.0.0.1")
	_ = p.SyncRCU(ctx)
	return r, nil
}

func (p *PostgresService) DeleteRoute(ctx context.Context, tenantID, routeID, actorMemberID string) error {
	if err := p.enforcePermission(ctx, actorMemberID, tenantID, PermissionRouteWrite); err != nil {
		return err
	}
	r, err := p.GetRoute(ctx, tenantID, routeID)
	if err != nil {
		return err
	}
	_, _ = p.db.ExecContext(ctx, `DELETE FROM api_auth_configs WHERE api_id = $1;`, routeID)
	if _, err := p.db.ExecContext(ctx, `DELETE FROM ap_route WHERE route_id = $1;`, routeID); err != nil {
		return err
	}
	p.recordAudit(ctx, tenantID, actorMemberID, "route.deleted", "Route", routeID, map[string]interface{}{"path": r.PathPattern}, nil, "127.0.0.1")
	_ = p.SyncRCU(ctx)
	return nil
}

// ----------------------------------------------------------------------------
// Policies
// ----------------------------------------------------------------------------

func (p *PostgresService) CreatePolicy(ctx context.Context, pol *Policy, actorMemberID string) (*Policy, error) {
	if pol == nil {
		return nil, fmt.Errorf("policy cannot be nil")
	}
	if err := p.enforcePermission(ctx, actorMemberID, pol.TenantID, PermissionPolicyWrite); err != nil {
		return nil, err
	}

	if pol.PolicyID == "" {
		pol.PolicyID = GeneratePolicyID()
	}
	if pol.WhitelistedPayees == nil {
		pol.WhitelistedPayees = []string{}
	}
	if pol.WhitelistedNetworks == nil {
		pol.WhitelistedNetworks = []string{"eip155:42161"}
	}
	if pol.WhitelistedRoutes == nil {
		pol.WhitelistedRoutes = []string{}
	}

	payeesBytes, _ := json.Marshal(pol.WhitelistedPayees)
	networksBytes, _ := json.Marshal(pol.WhitelistedNetworks)
	routesBytes, _ := json.Marshal(pol.WhitelistedRoutes)

	var agID, rteID sql.NullString
	if pol.AgentID != "" {
		agID = sql.NullString{String: pol.AgentID, Valid: true}
	}
	if pol.RouteID != "" {
		rteID = sql.NullString{String: pol.RouteID, Valid: true}
	}

	now := time.Now()
	nowUnix := now.Unix()
	pol.CreatedAt = nowUnix
	pol.UpdatedAt = nowUnix
	pol.IsActive = true

	if _, err := p.db.ExecContext(ctx, `
		INSERT INTO ap_policy (policy_id, tenant_id, project_id, agent_id, route_id, max_amount_per_request, rolling_24h_budget_cap, circuit_breaker_max_rpm, whitelisted_payees, whitelisted_networks, whitelisted_routes, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $13);
	`, pol.PolicyID, pol.TenantID, pol.ProjectID, agID, rteID, pol.MaxAmountPerRequest, pol.Rolling24hBudgetCap, pol.CircuitBreakerMaxRPM, payeesBytes, networksBytes, routesBytes, pol.IsActive, now); err != nil {
		return nil, err
	}

	p.recordAudit(ctx, pol.TenantID, actorMemberID, "policy.created", "Policy", pol.PolicyID, nil, nil, "127.0.0.1")
	_ = p.SyncRCU(ctx)
	return pol, nil
}

func scanPolicyRow(scanner routeRowScanner) (*Policy, error) {
	var pol Policy
	var agID, rteID sql.NullString
	var payeesBytes, networksBytes, routesBytes []byte

	if err := scanner.Scan(
		&pol.PolicyID, &pol.TenantID, &pol.ProjectID, &agID, &rteID,
		&pol.MaxAmountPerRequest, &pol.Rolling24hBudgetCap, &pol.CircuitBreakerMaxRPM,
		&payeesBytes, &networksBytes, &routesBytes, &pol.IsActive, &pol.CreatedAt, &pol.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if agID.Valid {
		pol.AgentID = agID.String
	}
	if rteID.Valid {
		pol.RouteID = rteID.String
	}
	_ = json.Unmarshal(payeesBytes, &pol.WhitelistedPayees)
	_ = json.Unmarshal(networksBytes, &pol.WhitelistedNetworks)
	_ = json.Unmarshal(routesBytes, &pol.WhitelistedRoutes)
	return &pol, nil
}

func (p *PostgresService) GetPolicy(ctx context.Context, tenantID, policyID string) (*Policy, error) {
	pol, err := scanPolicyRow(p.db.QueryRowContext(ctx, `
		SELECT policy_id, tenant_id, project_id, agent_id, route_id, max_amount_per_request, rolling_24h_budget_cap, circuit_breaker_max_rpm, whitelisted_payees, whitelisted_networks, whitelisted_routes, is_active,
		       EXTRACT(EPOCH FROM created_at)::bigint, EXTRACT(EPOCH FROM updated_at)::bigint
		FROM ap_policy
		WHERE policy_id = $1;
	`, policyID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrPolicyNotFound
	}
	if err != nil {
		return nil, err
	}
	if tenantID != "" && pol.TenantID != tenantID {
		return nil, ErrPolicyNotFound
	}
	return pol, nil
}

func (p *PostgresService) ListPolicies(ctx context.Context, tenantID, projectID, agentID string) ([]*Policy, error) {
	var sb strings.Builder
	sb.WriteString(`
		SELECT policy_id, tenant_id, project_id, agent_id, route_id, max_amount_per_request, rolling_24h_budget_cap, circuit_breaker_max_rpm, whitelisted_payees, whitelisted_networks, whitelisted_routes, is_active,
		       EXTRACT(EPOCH FROM created_at)::bigint, EXTRACT(EPOCH FROM updated_at)::bigint
		FROM ap_policy
		WHERE 1=1
	`)
	args := make([]interface{}, 0)
	idx := 1
	if tenantID != "" {
		sb.WriteString(fmt.Sprintf(" AND tenant_id = $%d", idx))
		args = append(args, tenantID)
		idx++
	}
	if projectID != "" {
		sb.WriteString(fmt.Sprintf(" AND project_id = $%d", idx))
		args = append(args, projectID)
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

	policies := make([]*Policy, 0)
	for rows.Next() {
		pol, err := scanPolicyRow(rows)
		if err != nil {
			return nil, err
		}
		policies = append(policies, pol)
	}
	return policies, nil
}

func (p *PostgresService) UpdatePolicy(ctx context.Context, pol *Policy, actorMemberID string) (*Policy, error) {
	if pol == nil {
		return nil, fmt.Errorf("policy cannot be nil")
	}
	if err := p.enforcePermission(ctx, actorMemberID, pol.TenantID, PermissionPolicyWrite); err != nil {
		return nil, err
	}

	existing, err := p.GetPolicy(ctx, pol.TenantID, pol.PolicyID)
	if err != nil {
		return nil, err
	}

	payeesBytes, _ := json.Marshal(pol.WhitelistedPayees)
	networksBytes, _ := json.Marshal(pol.WhitelistedNetworks)
	routesBytes, _ := json.Marshal(pol.WhitelistedRoutes)

	var agID, rteID sql.NullString
	if pol.AgentID != "" {
		agID = sql.NullString{String: pol.AgentID, Valid: true}
	}
	if pol.RouteID != "" {
		rteID = sql.NullString{String: pol.RouteID, Valid: true}
	}

	if _, err := p.db.ExecContext(ctx, `
		UPDATE ap_policy
		SET agent_id = $1, route_id = $2, max_amount_per_request = $3, rolling_24h_budget_cap = $4, circuit_breaker_max_rpm = $5, whitelisted_payees = $6, whitelisted_networks = $7, whitelisted_routes = $8, is_active = $9, updated_at = NOW()
		WHERE policy_id = $10;
	`, agID, rteID, pol.MaxAmountPerRequest, pol.Rolling24hBudgetCap, pol.CircuitBreakerMaxRPM, payeesBytes, networksBytes, routesBytes, pol.IsActive, pol.PolicyID); err != nil {
		return nil, err
	}

	pol.CreatedAt = existing.CreatedAt
	pol.UpdatedAt = time.Now().Unix()
	p.recordAudit(ctx, pol.TenantID, actorMemberID, "policy.updated", "Policy", pol.PolicyID, nil, nil, "127.0.0.1")
	_ = p.SyncRCU(ctx)
	return pol, nil
}

func (p *PostgresService) DeletePolicy(ctx context.Context, tenantID, policyID, actorMemberID string) error {
	if err := p.enforcePermission(ctx, actorMemberID, tenantID, PermissionPolicyWrite); err != nil {
		return err
	}
	if _, err := p.GetPolicy(ctx, tenantID, policyID); err != nil {
		return err
	}
	if _, err := p.db.ExecContext(ctx, `DELETE FROM ap_policy WHERE policy_id = $1;`, policyID); err != nil {
		return err
	}
	p.recordAudit(ctx, tenantID, actorMemberID, "policy.deleted", "Policy", policyID, nil, nil, "127.0.0.1")
	_ = p.SyncRCU(ctx)
	return nil
}

// ----------------------------------------------------------------------------
// Config Draft, Validation, Publishing & Rollback (T4.3 & T4.4)
// ----------------------------------------------------------------------------

