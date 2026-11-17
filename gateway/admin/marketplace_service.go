package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/open-agentpay/agent-core-sdk/gateway/usage"
	"net/http"
	"sort"
	"strings"
	"time"
)

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
		RouteType:                     r.RouteType,
		ModelName:                     r.ModelName,
		PricingType:                   r.PricingType,
		PromptTokenPriceBaseUnits:     r.PromptTokenPriceBaseUnits,
		CompletionTokenPriceBaseUnits: r.CompletionTokenPriceBaseUnits,
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
		       COALESCE(r.route_type, 'standard'), COALESCE(r.model_name, ''), COALESCE(r.pricing_type, 'per_call'),
		       r.prompt_token_price_base_units, r.completion_token_price_base_units,
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
	paidCallsMap := make(map[string]int64)
	totalCallsMap := make(map[string]int64)

	piRows, piErr := p.db.QueryContext(ctx, `
		SELECT route_id, 
		       COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 HOURS') as paid_24h,
		       COUNT(*) as paid_total
		FROM ap_payment_intent
		WHERE status = 'completed'
		GROUP BY route_id;
	`)
	if piErr == nil {
		for piRows.Next() {
			var rID string
			var p24, pTot int64
			if err := piRows.Scan(&rID, &p24, &pTot); err == nil {
				paidCallsMap[rID] = p24
				totalCallsMap[rID] = pTot
			}
		}
		piRows.Close()
	}

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
		var routeType, modelName, pricingType string
		var promptPrice, completionPrice sql.NullInt64

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
			&routeType, &modelName, &pricingType,
			&promptPrice, &completionPrice,
			&r.CreatedAt, &r.UpdatedAt, &tenantName,
		); err != nil {
			return nil, err
		}
		r.RouteType = routeType
		r.ModelName = modelName
		r.PricingType = pricingType
		if promptPrice.Valid {
			r.PromptTokenPriceBaseUnits = promptPrice.Int64
		}
		if completionPrice.Valid {
			r.CompletionTokenPriceBaseUnits = completionPrice.Int64
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
		if piPaid, ok := paidCallsMap[r.RouteID]; ok && piPaid > 0 {
			item.SLA.PaidCalls24h = piPaid
		} else if piTot, ok := totalCallsMap[r.RouteID]; ok && piTot > 0 {
			item.SLA.PaidCalls24h = piTot
		}
		if piTot, ok := totalCallsMap[r.RouteID]; ok && piTot > item.SLA.TotalCalls {
			item.SLA.TotalCalls = piTot
		}
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
