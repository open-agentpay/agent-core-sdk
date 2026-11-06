// Package rcu implements zero-downtime, lock-free Read-Copy-Update (RCU)
// configuration snapshot caching and static validation for AgentPay Go Gateway (T1.4, T2.1 & T2.5).
package rcu

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/agent-core-sdk/gateway/upstreamauth"
)

var (
	ErrNilSnapshot         = errors.New("cannot update with nil snapshot")
	ErrEmptyVersionID      = errors.New("snapshot version_id cannot be empty")
	ErrInvalidSnapshotHash = errors.New("snapshot hash does not match computed content digest")
	ErrValidationFailed    = errors.New("static validation failed for configuration snapshot")
)

var ethAddressRegex = regexp.MustCompile(`^0x[a-fA-F0-9]{40}$`)

// RouteConfig represents an active compiled route in the snapshot.
// Supports both camelCase and snake_case deserialization.
type RouteConfig struct {
	RouteID               string            `json:"routeId"`
	RouteIDSnake          string            `json:"route_id,omitempty"`
	TenantID              string            `json:"tenantId,omitempty"`
	TenantIDSnake         string            `json:"tenant_id,omitempty"`
	ProjectID             string            `json:"projectId"`
	ProjectIDSnake        string            `json:"project_id,omitempty"`
	PathPattern           string            `json:"pathPattern"`
	PathPatternSnake      string            `json:"path_pattern,omitempty"`
	UpstreamURL           string            `json:"upstreamUrl"`
	UpstreamURLSnake      string            `json:"upstream_url,omitempty"`
	PriceBaseUnits        int64             `json:"priceBaseUnits"`
	PriceBaseUnitsSnake   int64             `json:"price_base_units,omitempty"`
	Asset                 string            `json:"asset"`
	OnchainPriceBaseUnits *int64            `json:"onchainPriceBaseUnits,omitempty"`
	OnchainPriceSnake     *int64            `json:"onchain_price_base_units,omitempty"`
	OnchainAsset          string            `json:"onchainAsset,omitempty"`
	OnchainAssetSnake     string            `json:"onchain_asset,omitempty"`
	Network               string            `json:"network,omitempty"`
	PayeeAddress          string            `json:"payeeAddress"`
	PayeeAddressSnake     string            `json:"payee_address,omitempty"`
	AllowedPaymentMethods string            `json:"allowedPaymentMethods"` // wallet, onchain, both
	AllowedPaymentSnake   string            `json:"allowed_payment_methods,omitempty"`
	TimeoutMS             int               `json:"timeoutMs"`
	TimeoutMSSnake        int               `json:"timeout_ms,omitempty"`
	RateLimitRPM          int               `json:"rateLimitRpm"`
	RateLimitRPMSnake     int               `json:"rate_limit_rpm,omitempty"`
	Status                string            `json:"status"` // active, disabled
	Methods               []string          `json:"methods,omitempty"`
	UpstreamHeaders       map[string]string `json:"upstreamHeaders,omitempty"`
	UpstreamHeadersSnake  map[string]string `json:"upstream_headers,omitempty"`
	MaxBodyBytes          int64                            `json:"maxBodyBytes,omitempty"`
	MaxBodyBytesSnake     int64                            `json:"max_body_bytes,omitempty"`
	UpstreamAuth          *upstreamauth.UpstreamAuthConfig `json:"upstreamAuth,omitempty"`
	UpstreamAuthSnake     *upstreamauth.UpstreamAuthConfig `json:"upstream_auth,omitempty"`
	UpstreamSecrets       map[string]string                `json:"-"`
}

// Normalize populates canonical fields from snake_case aliases if provided.
func (r *RouteConfig) Normalize() {
	if r.RouteID == "" && r.RouteIDSnake != "" {
		r.RouteID = r.RouteIDSnake
	}
	if r.TenantID == "" && r.TenantIDSnake != "" {
		r.TenantID = r.TenantIDSnake
	}
	if r.ProjectID == "" && r.ProjectIDSnake != "" {
		r.ProjectID = r.ProjectIDSnake
	}
	if r.PathPattern == "" && r.PathPatternSnake != "" {
		r.PathPattern = r.PathPatternSnake
	}
	if r.UpstreamURL == "" && r.UpstreamURLSnake != "" {
		r.UpstreamURL = r.UpstreamURLSnake
	}
	if r.PriceBaseUnits == 0 && r.PriceBaseUnitsSnake != 0 {
		r.PriceBaseUnits = r.PriceBaseUnitsSnake
	}
	if r.OnchainPriceBaseUnits == nil && r.OnchainPriceSnake != nil {
		r.OnchainPriceBaseUnits = r.OnchainPriceSnake
	}
	if r.OnchainAsset == "" && r.OnchainAssetSnake != "" {
		r.OnchainAsset = r.OnchainAssetSnake
	}
	if r.PayeeAddress == "" && r.PayeeAddressSnake != "" {
		r.PayeeAddress = r.PayeeAddressSnake
	}
	if r.AllowedPaymentMethods == "" && r.AllowedPaymentSnake != "" {
		r.AllowedPaymentMethods = r.AllowedPaymentSnake
	}
	if r.TimeoutMS == 0 && r.TimeoutMSSnake != 0 {
		r.TimeoutMS = r.TimeoutMSSnake
	}
	if r.RateLimitRPM == 0 && r.RateLimitRPMSnake != 0 {
		r.RateLimitRPM = r.RateLimitRPMSnake
	}
	if len(r.UpstreamHeaders) == 0 && len(r.UpstreamHeadersSnake) > 0 {
		r.UpstreamHeaders = r.UpstreamHeadersSnake
	}
	if r.MaxBodyBytes == 0 && r.MaxBodyBytesSnake != 0 {
		r.MaxBodyBytes = r.MaxBodyBytesSnake
	}
	if r.Status == "" {
		r.Status = "active"
	}
	if r.AllowedPaymentMethods == "" {
		r.AllowedPaymentMethods = "both"
	}
	if r.UpstreamAuth == nil && r.UpstreamAuthSnake != nil {
		r.UpstreamAuth = r.UpstreamAuthSnake
	}
}

// PolicyConfig represents a budget, rate limit, or circuit breaker policy rule.
type PolicyConfig struct {
	PolicyID                 string   `json:"policyId"`
	PolicyIDSnake            string   `json:"policy_id,omitempty"`
	TenantID                 string   `json:"tenantId,omitempty"`
	TenantIDSnake            string   `json:"tenant_id,omitempty"`
	ProjectID                string   `json:"projectId"`
	ProjectIDSnake           string   `json:"project_id,omitempty"`
	AgentID                  *string  `json:"agentId,omitempty"`
	AgentIDSnake             *string  `json:"agent_id,omitempty"`
	RouteID                  *string  `json:"routeId,omitempty"`
	RouteIDSnake             *string  `json:"route_id,omitempty"`
	MaxAmountPerRequest      int64    `json:"maxAmountPerRequest"`
	MaxAmountSnake           int64    `json:"max_amount_per_request,omitempty"`
	Rolling24hBudgetCap      int64    `json:"rolling24hBudgetCap"`
	Rolling24hCapSnake       int64    `json:"rolling_24h_budget_cap,omitempty"`
	CircuitBreakerMaxRPM     int      `json:"circuitBreakerMaxRpm"`
	CircuitBreakerRPMSnake   int      `json:"circuit_breaker_max_rpm,omitempty"`
	WhitelistedNetworks      []string `json:"whitelistedNetworks,omitempty"`
	WhitelistedNetworksSnake []string `json:"whitelisted_networks,omitempty"`
	WhitelistedRoutes        []string `json:"whitelistedRoutes,omitempty"`
	WhitelistedRoutesSnake   []string `json:"whitelisted_routes,omitempty"`
	IsActive                 bool     `json:"isActive"`
	IsActiveSnake            *bool    `json:"is_active,omitempty"`
}

// Normalize populates canonical fields from snake_case aliases.
func (p *PolicyConfig) Normalize() {
	if p.PolicyID == "" && p.PolicyIDSnake != "" {
		p.PolicyID = p.PolicyIDSnake
	}
	if p.TenantID == "" && p.TenantIDSnake != "" {
		p.TenantID = p.TenantIDSnake
	}
	if p.ProjectID == "" && p.ProjectIDSnake != "" {
		p.ProjectID = p.ProjectIDSnake
	}
	if p.AgentID == nil && p.AgentIDSnake != nil {
		p.AgentID = p.AgentIDSnake
	}
	if p.RouteID == nil && p.RouteIDSnake != nil {
		p.RouteID = p.RouteIDSnake
	}
	if p.MaxAmountPerRequest == 0 && p.MaxAmountSnake != 0 {
		p.MaxAmountPerRequest = p.MaxAmountSnake
	}
	if p.Rolling24hBudgetCap == 0 && p.Rolling24hCapSnake != 0 {
		p.Rolling24hBudgetCap = p.Rolling24hCapSnake
	}
	if p.CircuitBreakerMaxRPM == 0 && p.CircuitBreakerRPMSnake != 0 {
		p.CircuitBreakerMaxRPM = p.CircuitBreakerRPMSnake
	}
	if len(p.WhitelistedNetworks) == 0 && len(p.WhitelistedNetworksSnake) > 0 {
		p.WhitelistedNetworks = p.WhitelistedNetworksSnake
	}
	if len(p.WhitelistedRoutes) == 0 && len(p.WhitelistedRoutesSnake) > 0 {
		p.WhitelistedRoutes = p.WhitelistedRoutesSnake
	}
	if p.IsActiveSnake != nil {
		p.IsActive = *p.IsActiveSnake
	}
}

// ConfigSnapshot is an immutable, canonical configuration snapshot.
type ConfigSnapshot struct {
	SchemaVersion      string         `json:"schemaVersion"`
	SchemaVersionSnake string         `json:"schema_version,omitempty"`
	TenantID           string         `json:"tenantId"`
	TenantIDSnake      string         `json:"tenant_id,omitempty"`
	VersionID          string         `json:"versionId"`
	VersionIDSnake     string         `json:"version_id,omitempty"`
	VersionNumber      int64          `json:"versionNumber"`
	VersionNumberSnake int64          `json:"version_number,omitempty"`
	PublishedAt        int64          `json:"publishedAt"`
	PublishedAtSnake   int64          `json:"published_at,omitempty"`
	PublishedBy        string         `json:"publishedBy"`
	PublishedBySnake   string         `json:"published_by,omitempty"`
	ChangeSummary      string         `json:"changeSummary,omitempty"`
	ChangeSummarySnake string         `json:"change_summary,omitempty"`
	SnapshotHash       string         `json:"snapshotHash"`
	SnapshotHashSnake  string         `json:"snapshot_hash,omitempty"`
	Routes             []RouteConfig  `json:"routes"`
	Policies           []PolicyConfig `json:"policies"`

	// Fast lookup indexes built during initialization
	routesByPattern map[string]*RouteConfig  `json:"-"`
	policiesByRoute map[string]*PolicyConfig `json:"-"`
	globalPolicy    *PolicyConfig            `json:"-"`
}

// Normalize populates all canonical fields and normalizes nested routes and policies.
func (s *ConfigSnapshot) Normalize() {
	if s.SchemaVersion == "" && s.SchemaVersionSnake != "" {
		s.SchemaVersion = s.SchemaVersionSnake
	}
	if s.TenantID == "" && s.TenantIDSnake != "" {
		s.TenantID = s.TenantIDSnake
	}
	if s.VersionID == "" && s.VersionIDSnake != "" {
		s.VersionID = s.VersionIDSnake
	}
	if s.VersionNumber == 0 && s.VersionNumberSnake != 0 {
		s.VersionNumber = s.VersionNumberSnake
	}
	if s.PublishedAt == 0 && s.PublishedAtSnake != 0 {
		s.PublishedAt = s.PublishedAtSnake
	}
	if s.PublishedBy == "" && s.PublishedBySnake != "" {
		s.PublishedBy = s.PublishedBySnake
	}
	if s.ChangeSummary == "" && s.ChangeSummarySnake != "" {
		s.ChangeSummary = s.ChangeSummarySnake
	}
	if s.SnapshotHash == "" && s.SnapshotHashSnake != "" {
		s.SnapshotHash = s.SnapshotHashSnake
	}

	for i := range s.Routes {
		s.Routes[i].Normalize()
		if s.Routes[i].TenantID == "" && s.TenantID != "" {
			s.Routes[i].TenantID = s.TenantID
		}
	}
	for i := range s.Policies {
		s.Policies[i].Normalize()
		if s.Policies[i].TenantID == "" && s.TenantID != "" {
			s.Policies[i].TenantID = s.TenantID
		}
	}
}

// ValidateStaticRules checks the snapshot against T1.4 static validation matrix.
func ValidateStaticRules(routes []RouteConfig, policies []PolicyConfig) (bool, string) {
	seenPatterns := make(map[string]bool)

	for i := range routes {
		r := &routes[i]
		r.Normalize()

		// 1. URI must start with http:// or https://
		if !strings.HasPrefix(r.UpstreamURL, "http://") && !strings.HasPrefix(r.UpstreamURL, "https://") {
			return false, "INVALID_UPSTREAM_URL"
		}

		// 2. PathPattern uniqueness
		if seenPatterns[r.PathPattern] {
			return false, "DUPLICATE_PATH_PATTERN"
		}
		seenPatterns[r.PathPattern] = true

		// 3. Payee Address format (if specified and route allows onchain payment)
		if r.PayeeAddress != "" && r.AllowedPaymentMethods != "wallet" && !ethAddressRegex.MatchString(r.PayeeAddress) {
			return false, "INVALID_PAYEE_ADDRESS"
		}

		// 4. Price non-negative
		if r.PriceBaseUnits < 0 {
			return false, "NEGATIVE_PRICE_UNITS"
		}

		// 5. Allowed payment methods
		if r.AllowedPaymentMethods != "wallet" && r.AllowedPaymentMethods != "onchain" && r.AllowedPaymentMethods != "both" {
			return false, "INVALID_PAYMENT_METHOD_OPTION"
		}
	}

	for i := range policies {
		p := &policies[i]
		p.Normalize()

		// Policy budget cap check: maxAmountPerRequest <= rolling24hBudgetCap
		if p.Rolling24hBudgetCap > 0 && p.MaxAmountPerRequest > p.Rolling24hBudgetCap {
			return false, "MAX_AMOUNT_EXCEEDS_ROLLING_BUDGET"
		}

		// Circuit breaker sanity check
		if p.CircuitBreakerMaxRPM < 0 {
			return false, "INVALID_CIRCUIT_BREAKER_RPM"
		}
	}

	return true, ""
}

// ComputeCanonicalSnapshotHash produces the deterministic SHA-256 fingerprint
// across canonically sorted routes and policies (aligned with T1.4).
func ComputeCanonicalSnapshotHash(routes []RouteConfig, policies []PolicyConfig) string {
	// 1. Sort routes by route_id ascending
	sortedRoutes := make([]RouteConfig, len(routes))
	copy(sortedRoutes, routes)
	for i := range sortedRoutes {
		sortedRoutes[i].Normalize()
	}
	sort.Slice(sortedRoutes, func(i, j int) bool {
		return sortedRoutes[i].RouteID < sortedRoutes[j].RouteID
	})

	// 2. Sort policies by policy_id ascending
	sortedPolicies := make([]PolicyConfig, len(policies))
	copy(sortedPolicies, policies)
	for i := range sortedPolicies {
		sortedPolicies[i].Normalize()
	}
	sort.Slice(sortedPolicies, func(i, j int) bool {
		return sortedPolicies[i].PolicyID < sortedPolicies[j].PolicyID
	})

	// 3. Serialize canonically
	type canonicalRoute struct {
		AllowedPaymentMethods string `json:"allowed_payment_methods"`
		Asset                 string `json:"asset"`
		PathPattern           string `json:"path_pattern"`
		PayeeAddress          string `json:"payee_address"`
		PriceBaseUnits        int64  `json:"price_base_units"`
		ProjectID             string `json:"project_id"`
		RateLimitRPM          int    `json:"rate_limit_rpm"`
		RouteID               string `json:"route_id"`
		Status                string `json:"status"`
		TimeoutMS             int    `json:"timeout_ms"`
		UpstreamURL           string `json:"upstream_url"`
	}

	type canonicalPolicy struct {
		CircuitBreakerMaxRPM int      `json:"circuit_breaker_max_rpm"`
		IsActive             bool     `json:"is_active"`
		MaxAmountPerRequest  int64    `json:"max_amount_per_request"`
		PolicyID             string   `json:"policy_id"`
		ProjectID            string   `json:"project_id"`
		Rolling24hBudgetCap  int64    `json:"rolling_24h_budget_cap"`
		RouteID              *string  `json:"route_id"`
		WhitelistedNetworks  []string `json:"whitelisted_networks"`
	}

	cRoutes := make([]canonicalRoute, len(sortedRoutes))
	for i, r := range sortedRoutes {
		cRoutes[i] = canonicalRoute{
			AllowedPaymentMethods: r.AllowedPaymentMethods,
			Asset:                 r.Asset,
			PathPattern:           r.PathPattern,
			PayeeAddress:          r.PayeeAddress,
			PriceBaseUnits:        r.PriceBaseUnits,
			ProjectID:             r.ProjectID,
			RateLimitRPM:          r.RateLimitRPM,
			RouteID:               r.RouteID,
			Status:                r.Status,
			TimeoutMS:             r.TimeoutMS,
			UpstreamURL:           r.UpstreamURL,
		}
	}

	cPolicies := make([]canonicalPolicy, len(sortedPolicies))
	for i, p := range sortedPolicies {
		cPolicies[i] = canonicalPolicy{
			CircuitBreakerMaxRPM: p.CircuitBreakerMaxRPM,
			IsActive:             p.IsActive,
			MaxAmountPerRequest:  p.MaxAmountPerRequest,
			PolicyID:             p.PolicyID,
			ProjectID:            p.ProjectID,
			Rolling24hBudgetCap:  p.Rolling24hBudgetCap,
			RouteID:              p.RouteID,
			WhitelistedNetworks:  p.WhitelistedNetworks,
		}
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"policies": cPolicies,
		"routes":   cRoutes,
	})

	return fmt.Sprintf("sha256:%x", sha256.Sum256(payload))
}

// LoadSnapshotFromJSON deserializes and validates a configuration snapshot JSON.
func LoadSnapshotFromJSON(data []byte) (*ConfigSnapshot, error) {
	var snap ConfigSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("malformed configuration snapshot JSON: %w", err)
	}
	snap.Normalize()

	// Validate static rules
	valid, reason := ValidateStaticRules(snap.Routes, snap.Policies)
	if !valid {
		return nil, fmt.Errorf("%w: %s", ErrValidationFailed, reason)
	}

	return &snap, nil
}

// LoadSnapshotFromFile reads and validates a snapshot from disk.
func LoadSnapshotFromFile(path string) (*ConfigSnapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadSnapshotFromJSON(data)
}

// Manager coordinates atomic pointer swaps of ConfigSnapshot.
type Manager struct {
	current atomic.Pointer[ConfigSnapshot]
}

// NewManager creates an RCU Manager initialized with an initial snapshot.
func NewManager(initial *ConfigSnapshot) (*Manager, error) {
	m := &Manager{}
	if initial != nil {
		if err := m.Update(initial); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// Current returns the currently active snapshot pointer with zero locks.
func (m *Manager) Current() *ConfigSnapshot {
	return m.current.Load()
}

// CurrentVersion returns the active version metadata for request tracking.
func (m *Manager) CurrentVersion() (versionID string, versionNum int64, hash string) {
	snap := m.Current()
	if snap == nil {
		return "bootstrap", 0, "sha256:none"
	}
	return snap.VersionID, snap.VersionNumber, snap.SnapshotHash
}

// Update validates and atomically swaps the active snapshot pointer.
func (m *Manager) Update(snapshot *ConfigSnapshot) error {
	if snapshot == nil {
		return ErrNilSnapshot
	}
	snapshot.Normalize()

	if snapshot.VersionID == "" {
		return ErrEmptyVersionID
	}

	// Validate static rules before activating
	valid, reason := ValidateStaticRules(snapshot.Routes, snapshot.Policies)
	if !valid {
		return fmt.Errorf("%w: %s", ErrValidationFailed, reason)
	}

	// Build indexed lookup maps
	routesMap := make(map[string]*RouteConfig, len(snapshot.Routes))
	for i := range snapshot.Routes {
		r := &snapshot.Routes[i]
		routesMap[r.PathPattern] = r
	}
	snapshot.routesByPattern = routesMap

	policiesMap := make(map[string]*PolicyConfig, len(snapshot.Policies))
	for i := range snapshot.Policies {
		p := &snapshot.Policies[i]
		if p.RouteID != nil && *p.RouteID != "" {
			policiesMap[*p.RouteID] = p
		} else if snapshot.globalPolicy == nil {
			snapshot.globalPolicy = p
		}
	}
	snapshot.policiesByRoute = policiesMap

	// Compute snapshot hash if not provided
	if snapshot.SnapshotHash == "" {
		snapshot.SnapshotHash = ComputeCanonicalSnapshotHash(snapshot.Routes, snapshot.Policies)
	}

	// Atomically swap pointer
	m.current.Store(snapshot)
	return nil
}

// HasPathTemplate reports whether a path or URL pattern contains `{param}` placeholders.
func HasPathTemplate(pattern string) bool {
	openIdx := strings.IndexByte(pattern, '{')
	if openIdx < 0 {
		return false
	}
	closeIdx := strings.IndexByte(pattern[openIdx:], '}')
	return closeIdx > 1
}

// ExtractPathParams matches a route pattern containing `{param}` placeholders against an incoming
// request path and returns the extracted parameter map if matched.
func ExtractPathParams(pattern, reqPath string) (map[string]string, bool) {
	if !HasPathTemplate(pattern) {
		return nil, false
	}

	patTrim := strings.Trim(pattern, "/")
	reqTrim := strings.Trim(reqPath, "/")
	if patTrim == "" || reqTrim == "" {
		return nil, false
	}

	patSegs := strings.Split(patTrim, "/")
	reqSegs := strings.Split(reqTrim, "/")
	if len(patSegs) != len(reqSegs) {
		return nil, false
	}

	params := make(map[string]string)
	for i := 0; i < len(patSegs); i++ {
		patSeg := patSegs[i]
		reqSeg := reqSegs[i]
		if reqSeg == "" {
			return nil, false
		}
		if HasPathTemplate(patSeg) {
			if !matchSegmentTemplate(patSeg, reqSeg, params) {
				return nil, false
			}
		} else if patSeg != reqSeg {
			return nil, false
		}
	}

	return params, true
}

// matchSegmentTemplate matches a single path segment that contains one or more `{param}` placeholders
// (e.g., "{coins}" or "v1-{coins}") and populates params. If the incoming segment is literally the
// unreplaced placeholder "{coins}", it matches structurally without recording "{coins}" as the value.
func matchSegmentTemplate(patSeg, reqSeg string, params map[string]string) bool {
	if strings.HasPrefix(patSeg, "{") && strings.HasSuffix(patSeg, "}") && !strings.Contains(patSeg[1:len(patSeg)-1], "{") {
		name := strings.TrimSpace(patSeg[1 : len(patSeg)-1])
		if name == "" || reqSeg == "" {
			return false
		}
		if reqSeg != patSeg {
			params[name] = reqSeg
		}
		return true
	}

	// Support composite segment templates like "token-{coins}" or "{chain}:{token}"
	remPat := patSeg
	remReq := reqSeg
	for {
		openIdx := strings.IndexByte(remPat, '{')
		if openIdx < 0 {
			return remPat == remReq
		}
		closeIdx := strings.IndexByte(remPat[openIdx:], '}')
		if closeIdx <= 1 {
			return false
		}
		closeIdx += openIdx

		staticPrefix := remPat[:openIdx]
		if !strings.HasPrefix(remReq, staticPrefix) {
			return false
		}
		remReq = remReq[len(staticPrefix):]

		paramName := strings.TrimSpace(remPat[openIdx+1 : closeIdx])
		remPat = remPat[closeIdx+1:]

		if remPat == "" {
			if remReq == "" {
				return false
			}
			if remReq != "{"+paramName+"}" {
				params[paramName] = remReq
			}
			return true
		}

		nextOpen := strings.IndexByte(remPat, '{')
		var nextLiteral string
		if nextOpen < 0 {
			nextLiteral = remPat
		} else {
			nextLiteral = remPat[:nextOpen]
		}
		if nextLiteral == "" {
			return false
		}
		litIdx := strings.Index(remReq, nextLiteral)
		if litIdx <= 0 {
			return false
		}
		val := remReq[:litIdx]
		if val != "{"+paramName+"}" {
			params[paramName] = val
		}
		remReq = remReq[litIdx:]
	}
}

// matchesTrailingTemplateBase reports whether pattern ends with a `/{param}` segment and reqPath
// matches the pattern with that trailing segment omitted (e.g., pattern "/v1/prices/current/{coins}"
// and reqPath "/v1/prices/current" when `{coins}` is supplied via query or JSON body).
func matchesTrailingTemplateBase(pattern, reqPath string) bool {
	if !HasPathTemplate(pattern) {
		return false
	}
	patTrim := strings.Trim(pattern, "/")
	reqTrim := strings.Trim(reqPath, "/")
	if patTrim == "" || reqTrim == "" {
		return false
	}
	patSegs := strings.Split(patTrim, "/")
	reqSegs := strings.Split(reqTrim, "/")
	if len(patSegs) < 2 || len(reqSegs) != len(patSegs)-1 {
		return false
	}
	lastSeg := patSegs[len(patSegs)-1]
	if !strings.HasPrefix(lastSeg, "{") || !strings.HasSuffix(lastSeg, "}") {
		return false
	}
	for i := 0; i < len(reqSegs); i++ {
		if patSegs[i] != reqSegs[i] {
			return false
		}
	}
	return true
}

// TemplateStaticPrefix returns the leading static path prefix before the first `{param}` segment.
func TemplateStaticPrefix(pattern string) string {
	patTrim := strings.Trim(pattern, "/")
	if patTrim == "" {
		return "/"
	}
	segs := strings.Split(patTrim, "/")
	staticSegs := make([]string, 0, len(segs))
	for _, s := range segs {
		if HasPathTemplate(s) {
			break
		}
		staticSegs = append(staticSegs, s)
	}
	if len(staticSegs) == 0 {
		return "/"
	}
	return "/" + strings.Join(staticSegs, "/")
}

// MatchRoute matches an incoming request path against the active routes map.
func (m *Manager) MatchRoute(path string) (*RouteConfig, bool) {
	route, _, _, ok := m.MatchRouteWithPolicy(path)
	return route, ok
}

// MatchRouteWithPolicy matches an incoming request path, returning the route, policy, snapshot, and ok.
func (m *Manager) MatchRouteWithPolicy(path string) (*RouteConfig, *PolicyConfig, *ConfigSnapshot, bool) {
	snap := m.Current()
	if snap == nil || snap.routesByPattern == nil {
		return nil, nil, nil, false
	}

	// 1. Exact match
	if route, ok := snap.routesByPattern[path]; ok {
		if route.Status == "active" {
			policy := snap.findPolicyForRoute(route.RouteID)
			return route, policy, snap, true
		}
		return nil, nil, snap, false
	}

	// 2. Path template match (e.g., "/v1/prices/current/{coins}")
	for i := range snap.Routes {
		route := &snap.Routes[i]
		if route.Status != "active" || !HasPathTemplate(route.PathPattern) {
			continue
		}
		if _, ok := ExtractPathParams(route.PathPattern, path); ok {
			policy := snap.findPolicyForRoute(route.RouteID)
			return route, policy, snap, true
		}
	}

	// 3. Trailing template base match (e.g., "/v1/prices/current" when pattern is "/v1/prices/current/{coins}" and param is in query/body)
	for i := range snap.Routes {
		route := &snap.Routes[i]
		if route.Status != "active" || !HasPathTemplate(route.PathPattern) {
			continue
		}
		if matchesTrailingTemplateBase(route.PathPattern, path) {
			policy := snap.findPolicyForRoute(route.RouteID)
			return route, policy, snap, true
		}
	}

	// 4. Prefix / wildcard match fallback (e.g., "/v1/ai/*")
	for i := range snap.Routes {
		route := &snap.Routes[i]
		if route.Status != "active" {
			continue
		}
		pattern := route.PathPattern
		if strings.HasSuffix(pattern, "/*") {
			prefix := strings.TrimSuffix(pattern, "/*")
			if prefix == "" || path == prefix || strings.HasPrefix(path, prefix+"/") {
				policy := snap.findPolicyForRoute(route.RouteID)
				return route, policy, snap, true
			}
		}
	}

	return nil, nil, snap, false
}

// MatchRouteForTenant matches an incoming request path specifically for a given tenant,
// strictly isolating routes between tenants and avoiding cross-tenant route leakage.
func (m *Manager) MatchRouteForTenant(tenantID, path string) (*RouteConfig, *PolicyConfig, *ConfigSnapshot, bool) {
	route, policy, snap, ok := m.MatchRouteWithPolicy(path)
	if !ok || route == nil {
		return nil, nil, snap, false
	}
	if tenantID != "" {
		expected := route.TenantID
		if expected == "" && snap != nil {
			expected = snap.TenantID
		}
		if expected != "" && expected != tenantID {
			return nil, nil, snap, false
		}
	}
	return route, policy, snap, true
}

func (s *ConfigSnapshot) findPolicyForRoute(routeID string) *PolicyConfig {
	if s.policiesByRoute != nil {
		if pol, ok := s.policiesByRoute[routeID]; ok && pol.IsActive {
			return pol
		}
	}
	if s.globalPolicy != nil && s.globalPolicy.IsActive {
		return s.globalPolicy
	}
	return nil
}
