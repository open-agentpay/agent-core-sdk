package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/open-agentpay/agent-core-sdk/gateway/rcu"
	"github.com/open-agentpay/agent-core-sdk/gateway/upstreamauth"
	"github.com/open-agentpay/agent-core-sdk/gateway/wallet"
)

var (
	ethAddressValidationRegex = regexp.MustCompile(`^0x[a-fA-F0-9]{40}$`)
	caip2ValidationRegex      = regexp.MustCompile(`^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$`)
)

// evaluateConfigValidation runs the static validation matrix (T4.3) over a tenant's routes and policies.
func evaluateConfigValidation(routes []*Route, policies []*Policy) *ValidationResult {
	errorsList := make([]ValidationError, 0)
	seenPatterns := make(map[string]string)

	for _, r := range routes {
		if !strings.HasPrefix(r.UpstreamURL, "http://") && !strings.HasPrefix(r.UpstreamURL, "https://") {
			errorsList = append(errorsList, ValidationError{
				TargetType: "Route",
				TargetID:   r.RouteID,
				Field:      "upstream_url",
				Code:       "INVALID_UPSTREAM_URL",
				Message:    fmt.Sprintf("上游地址 '%s' 非法，必须以 http:// 或 https:// 开头", r.UpstreamURL),
			})
		} else if err := upstreamauth.ValidateUpstreamURL(r.UpstreamURL); err != nil {
			errorsList = append(errorsList, ValidationError{
				TargetType: "Route",
				TargetID:   r.RouteID,
				Field:      "upstream_url",
				Code:       "INVALID_UPSTREAM_URL",
				Message:    err.Error(),
			})
		}

		cleanPath := strings.TrimSpace(r.PathPattern)
		if cleanPath == "" || !strings.HasPrefix(cleanPath, "/") {
			errorsList = append(errorsList, ValidationError{
				TargetType: "Route",
				TargetID:   r.RouteID,
				Field:      "path_pattern",
				Code:       "INVALID_PATH_PATTERN",
				Message:    fmt.Sprintf("路由暴露路径 '%s' 非法，必须以 / 开头", r.PathPattern),
			})
		} else {
			if existingID, seen := seenPatterns[cleanPath]; seen {
				errorsList = append(errorsList, ValidationError{
					TargetType: "Route",
					TargetID:   r.RouteID,
					Field:      "path_pattern",
					Code:       "DUPLICATE_PATH_PATTERN",
					Message:    fmt.Sprintf("路由路径 '%s' 与路由 %s 重复冲突", cleanPath, existingID),
				})
			} else {
				seenPatterns[cleanPath] = r.RouteID
			}
		}

		if r.AllowedPaymentMethods != "wallet" {
			if r.PayeeAddress == "" {
				errorsList = append(errorsList, ValidationError{
					TargetType: "Route",
					TargetID:   r.RouteID,
					Field:      "payee_address",
					Code:       "MISSING_PAYEE_ADDRESS",
					Message:    "支持链上结算时必须指定收款地址",
				})
			} else if !ethAddressValidationRegex.MatchString(r.PayeeAddress) {
				errorsList = append(errorsList, ValidationError{
					TargetType: "Route",
					TargetID:   r.RouteID,
					Field:      "payee_address",
					Code:       "INVALID_PAYEE_ADDRESS",
					Message:    fmt.Sprintf("收款地址 '%s' 格式错误，必须为 42 位 0x 开头的有效 EVM 地址", r.PayeeAddress),
				})
			}
		}

		if r.PriceBaseUnits < 0 {
			errorsList = append(errorsList, ValidationError{
				TargetType: "Route",
				TargetID:   r.RouteID,
				Field:      "price_base_units",
				Code:       "NEGATIVE_PRICE_UNITS",
				Message:    "单次调用单价不能为负数",
			})
		}

		if r.AllowedPaymentMethods != "wallet" && r.AllowedPaymentMethods != "onchain" && r.AllowedPaymentMethods != "both" {
			errorsList = append(errorsList, ValidationError{
				TargetType: "Route",
				TargetID:   r.RouteID,
				Field:      "allowed_payment_methods",
				Code:       "INVALID_PAYMENT_METHOD_OPTION",
				Message:    fmt.Sprintf("支付通道选项 '%s' 无效，必须为 wallet、onchain 或 both", r.AllowedPaymentMethods),
			})
		}

		if r.RateLimitRPM < 0 {
			errorsList = append(errorsList, ValidationError{
				TargetType: "Route",
				TargetID:   r.RouteID,
				Field:      "rate_limit_rpm",
				Code:       "INVALID_RATE_LIMIT",
				Message:    "限流阈值 RPM 不能小于 0",
			})
		}
	}

	for _, p := range policies {
		if p.Rolling24hBudgetCap > 0 && p.MaxAmountPerRequest > p.Rolling24hBudgetCap {
			errorsList = append(errorsList, ValidationError{
				TargetType: "Policy",
				TargetID:   p.PolicyID,
				Field:      "max_amount_per_request",
				Code:       "MAX_AMOUNT_EXCEEDS_ROLLING_BUDGET",
				Message:    fmt.Sprintf("单笔限额 (%d) 超出了 24 小时滚动预算上限 (%d)", p.MaxAmountPerRequest, p.Rolling24hBudgetCap),
			})
		}

		if p.CircuitBreakerMaxRPM < 0 {
			errorsList = append(errorsList, ValidationError{
				TargetType: "Policy",
				TargetID:   p.PolicyID,
				Field:      "circuit_breaker_max_rpm",
				Code:       "INVALID_CIRCUIT_BREAKER_RPM",
				Message:    "熔断阈值 RPM 不能小于 0",
			})
		}

		for _, net := range p.WhitelistedNetworks {
			if !caip2ValidationRegex.MatchString(net) {
				errorsList = append(errorsList, ValidationError{
					TargetType: "Policy",
					TargetID:   p.PolicyID,
					Field:      "whitelisted_networks",
					Code:       "INVALID_NETWORK_IDENTIFIER",
					Message:    fmt.Sprintf("网络标识符 '%s' 不符合 CAIP-2 规范 (如 eip155:1 或 eip155:42161)", net),
				})
			}
		}
	}

	return &ValidationResult{
		Valid:  len(errorsList) == 0,
		Errors: errorsList,
		Summary: ValidationSummary{
			TotalRoutes:   len(routes),
			TotalPolicies: len(policies),
			ErrorCount:    len(errorsList),
			WarningCount:  0,
		},
		ValidatedAt: time.Now().Unix(),
	}
}

func buildDraftSummary(tenantID string, routesCount, policiesCount int, lastRes *ValidationResult) *ConfigDraftSummary {
	var lastTime *int64
	isValidated := false
	if lastRes != nil {
		lastTime = &lastRes.ValidatedAt
		isValidated = lastRes.Valid
	}
	return &ConfigDraftSummary{
		TenantID:        tenantID,
		PendingChanges:  routesCount + policiesCount,
		RoutesCount:     routesCount,
		PoliciesCount:   policiesCount,
		LastValidatedAt: lastTime,
		IsValidated:     isValidated,
		LastResult:      lastRes,
	}
}

func buildDraftDiff(tenantID string, routes []*Route, policies []*Policy) *ConfigDraftDiff {
	routeDiffs := make([]RouteDiffItem, 0, len(routes))
	for _, r := range routes {
		routeDiffs = append(routeDiffs, RouteDiffItem{
			RouteID:     r.RouteID,
			Action:      "added",
			PathPattern: r.PathPattern,
			After: map[string]interface{}{
				"path_pattern":            r.PathPattern,
				"upstream_url":            r.UpstreamURL,
				"price_base_units":        r.PriceBaseUnits,
				"allowed_payment_methods": r.AllowedPaymentMethods,
				"status":                  string(r.Status),
			},
		})
	}

	policyDiffs := make([]PolicyDiffItem, 0, len(policies))
	for _, p := range policies {
		policyDiffs = append(policyDiffs, PolicyDiffItem{
			PolicyID: p.PolicyID,
			Action:   "added",
			After: map[string]interface{}{
				"max_amount_per_request": p.MaxAmountPerRequest,
				"rolling_24h_budget_cap": p.Rolling24hBudgetCap,
				"is_active":              p.IsActive,
			},
		})
	}

	return &ConfigDraftDiff{
		TenantID:    tenantID,
		HasChanges:  len(routeDiffs) > 0 || len(policyDiffs) > 0,
		RouteDiffs:  routeDiffs,
		PolicyDiffs: policyDiffs,
	}
}

func buildRCUSnapshotConfigs(routes []*Route, policies []*Policy) ([]rcu.RouteConfig, []rcu.PolicyConfig) {
	rcuRoutes := make([]rcu.RouteConfig, 0, len(routes))
	for _, r := range routes {
		rcuRoutes = append(rcuRoutes, rcu.RouteConfig{
			RouteID:               r.RouteID,
			TenantID:              r.TenantID,
			ProjectID:             r.ProjectID,
			Network:               r.Network,
			PathPattern:           r.PathPattern,
			UpstreamURL:           r.UpstreamURL,
			PriceBaseUnits:        r.PriceBaseUnits,
			Asset:                 r.Asset,
			OnchainPriceBaseUnits: r.OnchainPriceBaseUnits,
			OnchainAsset:          r.OnchainAsset,
			PayeeAddress:          r.PayeeAddress,
			AllowedPaymentMethods: r.AllowedPaymentMethods,
			TimeoutMS:             r.TimeoutMs,
			RateLimitRPM:          r.RateLimitRPM,
			Status:                string(r.Status),
			UpstreamAuth:          r.UpstreamAuth,
		})
	}

	rcuPolicies := make([]rcu.PolicyConfig, 0, len(policies))
	for _, p := range policies {
		routeID := p.RouteID
		rcuPolicies = append(rcuPolicies, rcu.PolicyConfig{
			PolicyID:             p.PolicyID,
			TenantID:             p.TenantID,
			ProjectID:            p.ProjectID,
			RouteID:              &routeID,
			MaxAmountPerRequest:  p.MaxAmountPerRequest,
			Rolling24hBudgetCap:  p.Rolling24hBudgetCap,
			CircuitBreakerMaxRPM: p.CircuitBreakerMaxRPM,
			WhitelistedNetworks:  p.WhitelistedNetworks,
			WhitelistedRoutes:    p.WhitelistedRoutes,
			IsActive:             p.IsActive,
		})
	}
	return rcuRoutes, rcuPolicies
}

func buildRestoredSnapshot(tenantID, versionID, actorMemberID, reason string, newVersionNumber int64, now int64, targetVer *ConfigVersion) (*rcu.ConfigSnapshot, string) {
	summary := fmt.Sprintf("Rollback to version v%d", targetVer.VersionNumber)
	if strings.TrimSpace(reason) != "" {
		summary = fmt.Sprintf("Rollback to version v%d: %s", targetVer.VersionNumber, strings.TrimSpace(reason))
	}

	restoredRoutes := make([]rcu.RouteConfig, len(targetVer.SnapshotJSON.Routes))
	copy(restoredRoutes, targetVer.SnapshotJSON.Routes)
	restoredPolicies := make([]rcu.PolicyConfig, len(targetVer.SnapshotJSON.Policies))
	copy(restoredPolicies, targetVer.SnapshotJSON.Policies)

	snap := &rcu.ConfigSnapshot{
		SchemaVersion: "2.0.0",
		TenantID:      tenantID,
		VersionID:     versionID,
		VersionNumber: newVersionNumber,
		PublishedAt:   now,
		PublishedBy:   actorMemberID,
		ChangeSummary: summary,
		SnapshotHash:  targetVer.SnapshotHash,
		Routes:        restoredRoutes,
		Policies:      restoredPolicies,
	}
	return snap, summary
}

func computeSnapshotDiff(tenantID string, baseSnap, targetSnap *rcu.ConfigSnapshot) *ConfigDraftDiff {
	routeDiffs := make([]RouteDiffItem, 0)
	policyDiffs := make([]PolicyDiffItem, 0)

	baseRouteMap := make(map[string]rcu.RouteConfig)
	if baseSnap != nil {
		for _, r := range baseSnap.Routes {
			baseRouteMap[r.RouteID] = r
		}
	}

	targetRouteMap := make(map[string]rcu.RouteConfig)
	if targetSnap != nil {
		for _, r := range targetSnap.Routes {
			targetRouteMap[r.RouteID] = r
		}
	}

	for id, tr := range targetRouteMap {
		br, exists := baseRouteMap[id]
		if !exists {
			routeDiffs = append(routeDiffs, RouteDiffItem{
				RouteID:     id,
				Action:      "added",
				PathPattern: tr.PathPattern,
				After: map[string]interface{}{
					"upstream_url":     tr.UpstreamURL,
					"price_base_units": tr.PriceBaseUnits,
				},
			})
		} else if br.UpstreamURL != tr.UpstreamURL || br.PriceBaseUnits != tr.PriceBaseUnits || br.PathPattern != tr.PathPattern {
			routeDiffs = append(routeDiffs, RouteDiffItem{
				RouteID:     id,
				Action:      "modified",
				PathPattern: tr.PathPattern,
				Before: map[string]interface{}{
					"upstream_url":     br.UpstreamURL,
					"price_base_units": br.PriceBaseUnits,
				},
				After: map[string]interface{}{
					"upstream_url":     tr.UpstreamURL,
					"price_base_units": tr.PriceBaseUnits,
				},
			})
		}
	}

	for id, br := range baseRouteMap {
		if _, exists := targetRouteMap[id]; !exists {
			routeDiffs = append(routeDiffs, RouteDiffItem{
				RouteID:     id,
				Action:      "deleted",
				PathPattern: br.PathPattern,
				Before: map[string]interface{}{
					"upstream_url":     br.UpstreamURL,
					"price_base_units": br.PriceBaseUnits,
				},
			})
		}
	}

	activeVerID := ""
	if baseSnap != nil {
		activeVerID = baseSnap.VersionID
	}

	return &ConfigDraftDiff{
		TenantID:        tenantID,
		ActiveVersionID: activeVerID,
		HasChanges:      len(routeDiffs) > 0 || len(policyDiffs) > 0,
		RouteDiffs:      routeDiffs,
		PolicyDiffs:     policyDiffs,
	}
}

func mergeAndApplyRCUSnapshot(mgr *rcu.Manager, routes []rcu.RouteConfig, policies []rcu.PolicyConfig, publishedBy string) error {
	if mgr == nil {
		return nil
	}
	curr := mgr.Current()
	if curr != nil {
		if len(routes) == 0 && len(policies) == 0 {
			return nil
		}
		existingRoutes := make(map[string]bool, len(routes))
		for _, r := range routes {
			existingRoutes[r.PathPattern] = true
		}
		for _, br := range curr.Routes {
			if !existingRoutes[br.PathPattern] && br.Status == "active" {
				routes = append(routes, br)
			}
		}

		existingPolicies := make(map[string]bool, len(policies))
		for _, p := range policies {
			existingPolicies[p.PolicyID] = true
		}
		for _, bp := range curr.Policies {
			if !existingPolicies[bp.PolicyID] && bp.IsActive {
				policies = append(policies, bp)
			}
		}
	} else if len(routes) == 0 && len(policies) == 0 {
		return nil
	}

	now := time.Now()
	newSnap := &rcu.ConfigSnapshot{
		SchemaVersion: "2.0.0",
		TenantID:      "global",
		VersionID:     fmt.Sprintf("ver_sync_%d", now.UnixNano()),
		VersionNumber: now.Unix(),
		PublishedAt:   now.Unix(),
		PublishedBy:   publishedBy,
		Routes:        routes,
		Policies:      policies,
	}
	return mgr.Update(newSnap)
}

func executeUpstreamTest(ctx context.Context, input *TestUpstreamInput) (*TestUpstreamResult, string, error) {
	if input == nil || strings.TrimSpace(input.UpstreamURL) == "" {
		return &TestUpstreamResult{
			Success: false,
			Error:   "upstream_url is required",
		}, "", nil
	}

	cleanURL := strings.TrimSpace(input.UpstreamURL)
	targetURL, err := url.Parse(cleanURL)
	if err != nil || targetURL.Scheme == "" || targetURL.Host == "" {
		return &TestUpstreamResult{
			Success: false,
			Error:   "invalid upstream_url: must include scheme (http/https) and host",
		}, cleanURL, nil
	}

	if err := upstreamauth.ValidateUpstreamURL(cleanURL); err != nil {
		return &TestUpstreamResult{
			Success: false,
			Error:   err.Error(),
		}, cleanURL, err
	}

	method := strings.ToUpper(strings.TrimSpace(input.Method))
	if method == "" {
		method = http.MethodGet
	}

	req, err := http.NewRequestWithContext(ctx, method, cleanURL, nil)
	if err != nil {
		return &TestUpstreamResult{
			Success: false,
			Error:   fmt.Sprintf("failed to construct test request: %v", err),
		}, cleanURL, nil
	}

	if input.UpstreamAuth != nil && input.UpstreamAuth.Type != "" && input.UpstreamAuth.Type != "none" {
		if auth, ok := upstreamauth.Get(input.UpstreamAuth.Type); ok {
			secrets := input.UpstreamAuth.Secrets
			if len(secrets) == 0 && len(input.UpstreamAuth.SecretEnc) > 0 {
				dec, err := upstreamauth.DecryptSecretsVersioned(input.UpstreamAuth.SecretEnc, input.UpstreamAuth.KeyVersion)
				if err != nil {
					return &TestUpstreamResult{
						Success: false,
						Error:   fmt.Sprintf("failed to decrypt upstream auth secrets: %v", err),
					}, cleanURL, err
				}
				secrets = dec
			}
			if err := auth.Apply(ctx, req, input.UpstreamAuth.Params, secrets); err != nil {
				return &TestUpstreamResult{
					Success: false,
					Error:   fmt.Sprintf("failed to apply upstream auth: %v", err),
				}, cleanURL, nil
			}
		}
	}

	sentHeaders := make(map[string]string, len(req.Header))
	for k, vv := range req.Header {
		val := strings.Join(vv, ", ")
		sentHeaders[k] = upstreamauth.MaskHeader(k, val)
	}

	if err := upstreamauth.ValidateUpstreamURLWithDNS(ctx, cleanURL); err != nil {
		if errors.Is(err, upstreamauth.ErrSSRFBlocked) {
			return &TestUpstreamResult{
				Success:     false,
				SentHeaders: sentHeaders,
				Error:       err.Error(),
			}, cleanURL, err
		}
	}

	client := upstreamauth.NewSafeHTTPClient(5 * time.Second)

	start := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()

	result := &TestUpstreamResult{
		SentHeaders: sentHeaders,
		LatencyMs:   latency,
	}

	if err != nil {
		if errors.Is(err, upstreamauth.ErrSSRFBlocked) {
			result.Success = false
			result.Error = err.Error()
			return result, cleanURL, err
		}
		result.Success = false
		result.Error = fmt.Sprintf("upstream connection error: %v", err)
	} else {
		defer resp.Body.Close()
		result.StatusCode = resp.StatusCode
		result.StatusText = resp.Status
		result.Success = resp.StatusCode >= 200 && resp.StatusCode < 400
	}
	return result, cleanURL, nil
}

func normalizeNewRoute(r *Route, tenantCurrency string, now int64) error {
	cleanPath := strings.TrimSpace(r.PathPattern)
	if cleanPath == "" {
		return fmt.Errorf("path_pattern cannot be empty")
	}
	if !strings.HasPrefix(cleanPath, "/") {
		return fmt.Errorf("path_pattern must begin with /")
	}
	cleanUpstream := strings.TrimSpace(r.UpstreamURL)
	if cleanUpstream == "" {
		return fmt.Errorf("upstream_url cannot be empty")
	}
	if err := upstreamauth.ValidateUpstreamURL(cleanUpstream); errors.Is(err, upstreamauth.ErrSSRFBlocked) {
		return err
	}

	if r.RouteID == "" {
		r.RouteID = GenerateRouteID()
	}
	r.PathPattern = cleanPath
	r.UpstreamURL = cleanUpstream
	r.Slug = NormalizeSlug(r.Slug, cleanPath)
	r.Title = DefaultTitleFromSlug(r.Title, r.Slug, cleanPath)
	if strings.TrimSpace(r.Category) == "" {
		r.Category = "AI & LLM"
	} else {
		r.Category = strings.TrimSpace(r.Category)
	}
	if strings.TrimSpace(r.Network) == "" {
		r.Network = "eip155:421614"
	} else {
		r.Network = strings.TrimSpace(r.Network)
	}
	if len(r.Methods) == 0 {
		r.Methods = []string{"POST"}
	}
	if r.Tags == nil {
		r.Tags = []string{}
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
	if r.TimeoutMs <= 0 {
		r.TimeoutMs = 30000
	}
	if r.AllowedPaymentMethods == "" {
		r.AllowedPaymentMethods = "both"
	}
	if r.RateLimitRPM <= 0 {
		r.RateLimitRPM = 600
	}
	if r.Asset == "" {
		if r.AllowedPaymentMethods == "onchain" {
			r.Asset = "USDC"
		} else if tenantCurrency != "" && (r.AllowedPaymentMethods == "wallet" || tenantCurrency != "USD") {
			r.Asset = tenantCurrency
		} else {
			r.Asset = "USDC"
		}
	}
	if r.OnchainAsset == "" && r.AllowedPaymentMethods != "wallet" {
		r.OnchainAsset = "USDC"
	}
	if r.Status == "" {
		r.Status = RouteStatusActive
	}
	r.PayeeAddress = strings.ToLower(strings.TrimSpace(r.PayeeAddress))
	r.CreatedAt = now
	r.UpdatedAt = now

	if r.UpstreamAuth != nil {
		if err := validateAndEncryptUpstreamAuth(r.UpstreamAuth, nil, now); err != nil {
			return err
		}
	}
	return nil
}

func validateAndEncryptUpstreamAuth(authCfg, prevAuth *UpstreamAuthConfig, nowUnix int64) error {
	if authCfg.Type == "" {
		authCfg.Type = "none"
	}
	if auth, ok := upstreamauth.Get(authCfg.Type); ok {
		if err := auth.Validate(authCfg.Params, authCfg.Secrets); err != nil {
			return fmt.Errorf("upstream_auth validation error: %w", err)
		}
	}
	if len(authCfg.Secrets) > 0 {
		enc, keyVer, err := upstreamauth.EncryptSecretsVersioned(authCfg.Secrets)
		if err != nil {
			return fmt.Errorf("failed to encrypt upstream secrets: %w", err)
		}
		authCfg.SecretEnc = enc
		authCfg.HasSecret = true
		authCfg.KeyVersion = keyVer
		authCfg.Secrets = nil
	} else if prevAuth != nil && prevAuth.Type == authCfg.Type {
		authCfg.SecretEnc = prevAuth.SecretEnc
		authCfg.HasSecret = prevAuth.HasSecret
		authCfg.KeyVersion = prevAuth.KeyVersion
	}
	authCfg.UpdatedAt = nowUnix
	return nil
}

func applyRouteUpdateFields(r *Route, input *UpdateRouteInput, nowUnix int64) error {
	if input.Slug != nil {
		r.Slug = NormalizeSlug(*input.Slug, r.PathPattern)
	} else if r.Slug == "" {
		r.Slug = NormalizeSlug("", r.PathPattern)
	}
	if input.Title != nil {
		r.Title = DefaultTitleFromSlug(*input.Title, r.Slug, r.PathPattern)
	}
	if input.Summary != nil {
		r.Summary = strings.TrimSpace(*input.Summary)
	}
	if input.ProviderName != nil {
		r.ProviderName = strings.TrimSpace(*input.ProviderName)
	}
	if input.Methods != nil {
		r.Methods = input.Methods
	}
	if input.NetworkLabel != nil {
		r.NetworkLabel = strings.TrimSpace(*input.NetworkLabel)
	}
	if input.Parameters != nil {
		r.Parameters = input.Parameters
	}
	if input.SampleParams != nil {
		r.SampleParams = input.SampleParams
	}
	if input.SampleResponse != nil {
		r.SampleResponse = input.SampleResponse
	}
	if input.IsPublic != nil {
		r.IsPublic = *input.IsPublic
	}
	if input.Category != nil {
		r.Category = strings.TrimSpace(*input.Category)
	}
	if input.Tags != nil {
		r.Tags = input.Tags
	}
	if input.DescriptionMD != nil {
		r.DescriptionMD = *input.DescriptionMD
	}
	if input.Network != nil && strings.TrimSpace(*input.Network) != "" {
		r.Network = strings.TrimSpace(*input.Network)
	}
	if input.UpstreamURL != nil {
		cleanUpstream := strings.TrimSpace(*input.UpstreamURL)
		if cleanUpstream == "" {
			return fmt.Errorf("upstream_url cannot be empty")
		}
		if err := upstreamauth.ValidateUpstreamURL(cleanUpstream); errors.Is(err, upstreamauth.ErrSSRFBlocked) {
			return err
		}
		r.UpstreamURL = cleanUpstream
	}
	if input.PriceBaseUnits != nil {
		if *input.PriceBaseUnits < 0 {
			return fmt.Errorf("price_base_units cannot be negative")
		}
		r.PriceBaseUnits = *input.PriceBaseUnits
	}
	if input.Asset != nil {
		r.Asset = strings.TrimSpace(*input.Asset)
	}
	if input.OnchainPriceBaseUnits != nil {
		if *input.OnchainPriceBaseUnits < 0 {
			return fmt.Errorf("onchain_price_base_units cannot be negative")
		}
		val := *input.OnchainPriceBaseUnits
		r.OnchainPriceBaseUnits = &val
	}
	if input.OnchainAsset != nil {
		r.OnchainAsset = strings.TrimSpace(*input.OnchainAsset)
	}
	if input.PayeeAddress != nil {
		r.PayeeAddress = strings.ToLower(strings.TrimSpace(*input.PayeeAddress))
	}
	if input.AllowedPaymentMethods != nil {
		method := strings.TrimSpace(*input.AllowedPaymentMethods)
		if method == "wallet" || method == "onchain" || method == "both" {
			r.AllowedPaymentMethods = method
		}
	}
	if input.RateLimitRPM != nil && *input.RateLimitRPM > 0 {
		r.RateLimitRPM = *input.RateLimitRPM
	}
	if input.TimeoutMs != nil && *input.TimeoutMs > 0 {
		r.TimeoutMs = *input.TimeoutMs
	}
	if input.Status != nil {
		r.Status = *input.Status
	}
	if input.UpstreamAuth != nil {
		authCfg := input.UpstreamAuth
		if err := validateAndEncryptUpstreamAuth(authCfg, r.UpstreamAuth, nowUnix); err != nil {
			return err
		}
		r.UpstreamAuth = authCfg
	}
	r.UpdatedAt = nowUnix
	return nil
}

func recalculateWalletBalanceMap(ctx context.Context, walletSvc wallet.Service, walletID string) (map[string]interface{}, error) {
	rep, err := walletSvc.ReconcileBalance(ctx, walletID)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"wallet_id":   walletID,
		"cached":      rep.AvailableCache,
		"calculated":  rep.SumLedgerEntries,
		"consistent":  rep.IsBalanced,
		"is_balanced": rep.IsBalanced,
	}, nil
}
