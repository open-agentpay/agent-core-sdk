package admin

import (
	"context"
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

// LargeAdjustmentThreshold defines amount beyond which dual control / audit alert is needed.
const LargeAdjustmentThreshold int64 = 100_000_000 // 100 Units

// Service defines the Control Plane management operations.
type Service interface {
	// Auth
	Register(ctx context.Context, tenantName, email, password string, currency ...string) (*Tenant, *Member, error)
	Login(ctx context.Context, email, password string) (*Member, *Tenant, error)
	GetMemberByEmail(ctx context.Context, email string) (*Member, *Tenant, error)
	SetMemberPassword(ctx context.Context, tenantID, memberID, password string) error

	// Tenant
	CreateTenant(ctx context.Context, name string, tenantID string, ownerEmail string, currency ...string) (*Tenant, *Member, error)
	GetTenant(ctx context.Context, tenantID string) (*Tenant, error)
	ListTenants(ctx context.Context) ([]*Tenant, error)
	UpdateTenant(ctx context.Context, tenantID string, name string, actorMemberID string) (*Tenant, error)
	UpdateTenantCurrency(ctx context.Context, tenantID string, currency string, actorMemberID string) (*Tenant, error)
	UpdateTenantStatus(ctx context.Context, tenantID string, status TenantStatus, actorMemberID string) (*Tenant, error)

	// Project
	CreateProject(ctx context.Context, tenantID, name string, budgetCap int64, projectID string, actorMemberID string) (*Project, error)
	GetProject(ctx context.Context, tenantID, projectID string) (*Project, error)
	ListProjects(ctx context.Context, tenantID string) ([]*Project, error)
	UpdateProject(ctx context.Context, tenantID, projectID string, name string, budgetCap *int64, status *ProjectStatus, actorMemberID string) (*Project, error)
	DeleteProject(ctx context.Context, tenantID, projectID string, actorMemberID string) error

	// Member
	AddMember(ctx context.Context, tenantID, email string, role MemberRole, actorMemberID string) (*Member, error)
	GetMember(ctx context.Context, tenantID, memberID string) (*Member, error)
	ListMembers(ctx context.Context, tenantID string) ([]*Member, error)
	UpdateMember(ctx context.Context, tenantID, memberID string, role *MemberRole, status *MemberStatus, actorMemberID string) (*Member, error)
	RemoveMember(ctx context.Context, tenantID, memberID string, actorMemberID string) error

	// Agent & Kill Switch
	CreateAgent(ctx context.Context, tenantID, projectID, name string, policyCfg map[string]interface{}, actorMemberID string) (*Agent, error)
	GetAgent(ctx context.Context, tenantID, agentID string) (*Agent, error)
	ListAgents(ctx context.Context, tenantID, projectID string, status *AgentStatus) ([]*Agent, error)
	UpdateAgent(ctx context.Context, tenantID, agentID string, name string, policyCfg map[string]interface{}, actorMemberID string) (*Agent, error)
	UpdateAgentStatus(ctx context.Context, tenantID, agentID string, status AgentStatus, actorMemberID string) (*Agent, error)
	KillAgent(ctx context.Context, tenantID, agentID, reason string, actorMemberID string, revoke bool, clientIP string) (*Agent, []string, error)
	DeleteAgent(ctx context.Context, tenantID, agentID, actorMemberID string) error

	// API Keys
	CreateAPIKey(ctx context.Context, tenantID, projectID, agentID, name string, scopes []string, expiresAt *int64, actorMemberID string) (*CreateAPIKeyResult, error)
	GetAPIKey(ctx context.Context, tenantID, keyID string) (*APIKey, error)
	ListAPIKeys(ctx context.Context, tenantID, agentID string) ([]*APIKey, error)
	RevokeAPIKey(ctx context.Context, tenantID, keyID, actorMemberID string) (*APIKey, error)
	RotateAPIKey(ctx context.Context, tenantID, keyID, actorMemberID string) (*CreateAPIKeyResult, error)

	// Routes
	CreateRoute(ctx context.Context, route *Route, actorMemberID string) (*Route, error)
	GetRoute(ctx context.Context, tenantID, routeID string) (*Route, error)
	ListRoutes(ctx context.Context, tenantID string) ([]*Route, error)
	UpdateRoute(ctx context.Context, input *UpdateRouteInput, actorMemberID string) (*Route, error)
	DeleteRoute(ctx context.Context, tenantID, routeID, actorMemberID string) error

	// Public Marketplace (Read-Only Discovery)
	ListMarketplaceRoutes(ctx context.Context, filter MarketplaceFilter) ([]*MarketplaceRouteItem, error)
	GetMarketplaceRouteBySlug(ctx context.Context, slug string) (*MarketplaceRouteItem, error)

	// Policies
	CreatePolicy(ctx context.Context, pol *Policy, actorMemberID string) (*Policy, error)
	GetPolicy(ctx context.Context, tenantID, policyID string) (*Policy, error)
	ListPolicies(ctx context.Context, tenantID, projectID, agentID string) ([]*Policy, error)
	UpdatePolicy(ctx context.Context, pol *Policy, actorMemberID string) (*Policy, error)
	DeletePolicy(ctx context.Context, tenantID, policyID, actorMemberID string) error

	// Config Draft & Validation (T4.3)
	ValidateConfig(ctx context.Context, tenantID string, actorMemberID string) (*ValidationResult, error)
	GetDraftSummary(ctx context.Context, tenantID string) (*ConfigDraftSummary, error)
	GetDraftDiff(ctx context.Context, tenantID string) (*ConfigDraftDiff, error)

	// Config Publishing, Versions & Rollback (T4.4)
	PublishConfig(ctx context.Context, tenantID string, changeSummary string, actorMemberID string) (*ConfigVersion, error)
	ListConfigVersions(ctx context.Context, tenantID string) ([]*ConfigVersion, error)
	GetConfigVersion(ctx context.Context, tenantID, versionID string) (*ConfigVersion, error)
	RollbackConfig(ctx context.Context, tenantID, targetVersionID, reason string, actorMemberID string) (*ConfigVersion, error)
	GetConfigVersionDiff(ctx context.Context, tenantID, baseVersionID, targetVersionID string) (*ConfigDraftDiff, error)

	// Upstream Auth & Connectivity (T4.2 Enhancement)
	GetAuthTypes() []upstreamauth.AuthTypeSchema
	TestUpstream(ctx context.Context, tenantID string, input *TestUpstreamInput, actorMemberID string) (*TestUpstreamResult, error)

	// Wallet Admin
	AdminGrantWallet(ctx context.Context, tenantID string, amount int64, reason string, idempotencyKey string, actorMemberID string, clientIP string) error
	AdjustWallet(ctx context.Context, walletID string, amount int64, reason string, idempotencyKey string, actorMemberID string, clientIP string) error
	FreezeWallet(ctx context.Context, walletID string, reason string, actorMemberID string, clientIP string) error
	UnfreezeWallet(ctx context.Context, walletID string, reason string, actorMemberID string, clientIP string) error
	RecalculateWallet(ctx context.Context, walletID string, actorMemberID string) (map[string]interface{}, error)
	GetWallet(ctx context.Context, tenantID string) (*wallet.Wallet, error)
	GetWalletByID(ctx context.Context, walletID string) (*wallet.Wallet, error)
	GetLedgerEntries(ctx context.Context, walletID string) ([]*wallet.LedgerEntry, error)
	GetTopUpOrders(ctx context.Context, walletID string) ([]*wallet.TopUpOrder, error)

	// Audit
	ListAuditEvents(ctx context.Context, tenantID, targetType, targetID string, limit int) ([]*AuditEvent, error)

	// Usage & Request Tracing (T5.1)
	SetUsageService(svc usage.Service)
	GetUsageService() usage.Service
	ListRequestRecords(ctx context.Context, tenantID string, filter usage.RequestFilter, actorMemberID string) ([]*usage.RequestRecord, int64, error)
	GetRequestRecord(ctx context.Context, tenantID, requestID string, actorMemberID string) (*usage.RequestRecord, error)
	ListUsageEvents(ctx context.Context, tenantID string, filter usage.UsageFilter, actorMemberID string) ([]*usage.UsageEvent, int64, error)
	GetUsageEvent(ctx context.Context, tenantID, eventID string, actorMemberID string) (*usage.UsageEvent, error)

	// Payment, Settlement & Fulfillment Correlation (T5.2)
	SetPaymentService(svc payment.Service)
	GetPaymentService() payment.Service
	GetPaymentAudit(ctx context.Context, tenantID, intentID string, actorMemberID string) (*payment.PaymentAuditRecord, error)
	GetPaymentAuditByRequestID(ctx context.Context, tenantID, requestID string, actorMemberID string) (*payment.PaymentAuditRecord, error)
	ListPaymentAudits(ctx context.Context, tenantID string, filter payment.PaymentAuditFilter, actorMemberID string) ([]*payment.PaymentAuditRecord, int64, error)

	// Agent Behavior Timeline (T5.8)
	SetTimelineService(svc timeline.Service)
	GetTimelineService() timeline.Service
	GetAgentTimeline(ctx context.Context, tenantID, agentID string, filter timeline.TimelineFilter, actorMemberID string) ([]*timeline.TimelineEvent, int64, []string, error)

	// RCU Data Plane Synchronization
	SetRCUManager(mgr *rcu.Manager)
	SyncRCU(ctx context.Context) error
}

// MemoryService provides an in-memory thread-safe implementation of Service.
type MemoryService struct {
	mu                   sync.RWMutex
	tenants              map[string]*Tenant
	projects             map[string]*Project
	members              map[string]*Member
	agents               map[string]*Agent
	apiKeys              map[string]*APIKey
	routes               map[string]*Route
	policies             map[string]*Policy
	auditEvents          []*AuditEvent
	agentRegistry        *agent.Registry
	walletSvc            wallet.Service
	usageSvc             usage.Service
	paymentSvc           payment.Service
	timelineSvc          timeline.Service
	lastValidation       map[string]*ValidationResult
	configVersions       map[string]*ConfigVersion
	configVersionHistory map[string][]*ConfigVersion
	rcuMgr               *rcu.Manager
}

// NewMemoryService constructs an in-memory control plane service.
func NewMemoryService(agentRegistry *agent.Registry, walletSvc wallet.Service) *MemoryService {
	if agentRegistry == nil {
		agentRegistry = agent.NewRegistry()
	}
	if walletSvc == nil {
		walletSvc = wallet.NewMemoryService()
	}
	return &MemoryService{
		tenants:              make(map[string]*Tenant),
		projects:             make(map[string]*Project),
		members:              make(map[string]*Member),
		agents:               make(map[string]*Agent),
		apiKeys:              make(map[string]*APIKey),
		routes:               make(map[string]*Route),
		policies:             make(map[string]*Policy),
		auditEvents:          make([]*AuditEvent, 0),
		agentRegistry:        agentRegistry,
		walletSvc:            walletSvc,
		timelineSvc:          timeline.NewMemoryService(),
		lastValidation:       make(map[string]*ValidationResult),
		configVersions:       make(map[string]*ConfigVersion),
		configVersionHistory: make(map[string][]*ConfigVersion),
	}
}

func (s *MemoryService) recordAudit(tenantID, operatorID, action, targetType, targetID string, before, after map[string]interface{}, clientIP string) {
	if clientIP == "" {
		clientIP = "127.0.0.1"
	}
	ev := &AuditEvent{
		AuditID:     GenerateAuditID(),
		TenantID:    tenantID,
		OperatorID:  operatorID,
		Action:      action,
		TargetType:  targetType,
		TargetID:    targetID,
		BeforeState: before,
		AfterState:  after,
		ClientIP:    clientIP,
		CreatedAt:   time.Now().Unix(),
	}
	s.auditEvents = append(s.auditEvents, ev)
}

func (s *MemoryService) checkPermissionLocked(tenantID, actorMemberID string, perm Permission) error {
	if actorMemberID == "" {
		return ErrPermissionDenied
	}
	actor, ok := s.members[actorMemberID]
	if !ok || actor.TenantID != tenantID {
		return ErrPermissionDenied
	}
	return EnforcePermission(actor, perm)
}

func (s *MemoryService) checkPermissionRLock(tenantID, actorMemberID string, perm Permission) error {
	if actorMemberID == "" {
		return ErrPermissionDenied
	}
	s.mu.RLock()
	actor, ok := s.members[actorMemberID]
	s.mu.RUnlock()
	if !ok || actor.TenantID != tenantID {
		return ErrPermissionDenied
	}
	return EnforcePermission(actor, perm)
}

func (s *MemoryService) initMasterWalletLocked(tid, curr string) {
	if s.walletSvc == nil {
		return
	}
	if memWlt, ok := s.walletSvc.(*wallet.MemoryService); ok {
		memWlt.RegisterWallet(&wallet.Wallet{
			WalletID:       fmt.Sprintf("wlt_%s", tid),
			TenantID:       tid,
			Asset:          curr,
			Status:         wallet.StatusActive,
			Version:        1,
			AvailableCache: 0,
			HeldCache:      0,
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		})
	}
}

// ----------------------------------------------------------------------------
// Auth
// ----------------------------------------------------------------------------

func (s *MemoryService) Register(ctx context.Context, tenantName, email, password string, currency ...string) (*Tenant, *Member, error) {
	cleanName := strings.TrimSpace(tenantName)
	cleanEmail := strings.TrimSpace(email)
	if cleanName == "" {
		return nil, nil, fmt.Errorf("tenant name cannot be empty")
	}
	if cleanEmail == "" {
		return nil, nil, fmt.Errorf("email cannot be empty")
	}
	if len(password) < 8 {
		return nil, nil, ErrPasswordTooShort
	}

	rawCurr := ""
	if len(currency) > 0 {
		rawCurr = strings.TrimSpace(currency[0])
	}
	curr, err := NormalizeCurrency(rawCurr)
	if err != nil {
		return nil, nil, err
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		return nil, nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, t := range s.tenants {
		if t.Name == cleanName {
			return nil, nil, ErrTenantAlreadyExists
		}
	}
	for _, m := range s.members {
		if strings.EqualFold(m.Email, cleanEmail) {
			return nil, nil, ErrEmailAlreadyRegistered
		}
	}

	tid := GenerateTenantID()
	now := time.Now().Unix()
	t := &Tenant{
		TenantID:  tid,
		Name:      cleanName,
		Currency:  curr,
		Status:    TenantStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
	s.tenants[tid] = t

	ownerMember := &Member{
		MemberID:     GenerateMemberID(),
		TenantID:     tid,
		Email:        cleanEmail,
		PasswordHash: hash,
		Role:         RoleOwner,
		Status:       MemberStatusActive,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	s.members[ownerMember.MemberID] = ownerMember
	s.initMasterWalletLocked(tid, curr)

	defaultPrjID := GenerateProjectID()
	s.projects[defaultPrjID] = &Project{
		ProjectID:          defaultPrjID,
		TenantID:           tid,
		Name:               "默认项目 (Default)",
		BudgetCapBaseUnits: 1000000000,
		Status:             ProjectStatusActive,
		CreatedAt:          now,
		UpdatedAt:          now,
	}

	s.recordAudit(tid, ownerMember.MemberID, "auth.register", "Tenant", tid, nil, map[string]interface{}{"email": cleanEmail, "tenant": cleanName, "currency": curr, "project_id": defaultPrjID}, "127.0.0.1")
	return t, ownerMember, nil
}

func (s *MemoryService) Login(ctx context.Context, email, password string) (*Member, *Tenant, error) {
	cleanEmail := strings.TrimSpace(email)
	s.mu.RLock()
	defer s.mu.RUnlock()

	var matchedMember *Member
	for _, m := range s.members {
		if strings.EqualFold(m.Email, cleanEmail) {
			matchedMember = m
			break
		}
	}
	if matchedMember == nil {
		return nil, nil, ErrInvalidCredentials
	}
	if matchedMember.Status != MemberStatusActive {
		return nil, nil, ErrMemberDisabled
	}

	tenant, ok := s.tenants[matchedMember.TenantID]
	if !ok || tenant.Status != TenantStatusActive {
		return nil, nil, ErrTenantSuspended
	}
	if matchedMember.PasswordHash == "" || !auth.VerifyPassword(password, matchedMember.PasswordHash) {
		return nil, nil, ErrInvalidCredentials
	}
	return matchedMember, tenant, nil
}

func (s *MemoryService) GetMemberByEmail(ctx context.Context, email string) (*Member, *Tenant, error) {
	cleanEmail := strings.TrimSpace(email)
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, m := range s.members {
		if strings.EqualFold(m.Email, cleanEmail) {
			return m, s.tenants[m.TenantID], nil
		}
	}
	return nil, nil, ErrMemberNotFound
}

func (s *MemoryService) SetMemberPassword(ctx context.Context, tenantID, memberID, password string) error {
	if len(password) < 8 {
		return ErrPasswordTooShort
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	m, ok := s.members[memberID]
	if !ok || m.TenantID != tenantID {
		return ErrMemberNotFound
	}
	m.PasswordHash = hash
	m.UpdatedAt = time.Now().Unix()
	return nil
}

// ----------------------------------------------------------------------------
// Tenants
// ----------------------------------------------------------------------------

func (s *MemoryService) CreateTenant(ctx context.Context, name string, tenantID string, ownerEmail string, currency ...string) (*Tenant, *Member, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cleanName := strings.TrimSpace(name)
	if cleanName == "" {
		return nil, nil, fmt.Errorf("tenant name cannot be empty")
	}

	rawCurr := ""
	if len(currency) > 0 {
		rawCurr = strings.TrimSpace(currency[0])
	}
	curr, err := NormalizeCurrency(rawCurr)
	if err != nil {
		return nil, nil, err
	}

	for _, t := range s.tenants {
		if t.Name == cleanName {
			return nil, nil, ErrTenantAlreadyExists
		}
	}

	tid := tenantID
	if tid == "" {
		tid = GenerateTenantID()
	}

	now := time.Now().Unix()
	t := &Tenant{
		TenantID:  tid,
		Name:      cleanName,
		Currency:  curr,
		Status:    TenantStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
	s.tenants[tid] = t

	var ownerMember *Member
	if ownerEmail != "" {
		ownerMember = &Member{
			MemberID:  GenerateMemberID(),
			TenantID:  tid,
			Email:     strings.TrimSpace(ownerEmail),
			Role:      RoleOwner,
			Status:    MemberStatusActive,
			CreatedAt: now,
			UpdatedAt: now,
		}
		s.members[ownerMember.MemberID] = ownerMember
	}

	s.initMasterWalletLocked(tid, curr)
	s.recordAudit(tid, "system", "tenant.created", "Tenant", tid, nil, map[string]interface{}{"name": cleanName, "currency": curr}, "127.0.0.1")
	return t, ownerMember, nil
}

func (s *MemoryService) GetTenant(ctx context.Context, tenantID string) (*Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	t, ok := s.tenants[tenantID]
	if !ok {
		return nil, ErrTenantNotFound
	}
	if t.Currency == "" {
		t.Currency = "USD"
	}
	return t, nil
}

func (s *MemoryService) ListTenants(ctx context.Context) ([]*Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make([]*Tenant, 0, len(s.tenants))
	for _, t := range s.tenants {
		if t.Currency == "" {
			t.Currency = "USD"
		}
		res = append(res, t)
	}
	return res, nil
}

func (s *MemoryService) UpdateTenant(ctx context.Context, tenantID string, name string, actorMemberID string) (*Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.tenants[tenantID]
	if !ok {
		return nil, ErrTenantNotFound
	}
	if err := s.checkPermissionLocked(tenantID, actorMemberID, PermissionTenantUpdate); err != nil {
		return nil, err
	}

	cleanName := strings.TrimSpace(name)
	if cleanName == "" {
		return nil, fmt.Errorf("name cannot be empty")
	}

	before := map[string]interface{}{"name": t.Name}
	t.Name = cleanName
	t.UpdatedAt = time.Now().Unix()

	s.recordAudit(tenantID, actorMemberID, "tenant.updated", "Tenant", tenantID, before, map[string]interface{}{"name": cleanName}, "127.0.0.1")
	return t, nil
}

func (s *MemoryService) UpdateTenantCurrency(ctx context.Context, tenantID string, currency string, actorMemberID string) (*Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.tenants[tenantID]
	if !ok {
		return nil, ErrTenantNotFound
	}
	if err := s.checkPermissionLocked(tenantID, actorMemberID, PermissionTenantUpdate); err != nil {
		return nil, err
	}

	curr, err := NormalizeCurrency(strings.TrimSpace(currency))
	if err != nil {
		return nil, err
	}

	for _, r := range s.routes {
		if r.TenantID == tenantID {
			return nil, ErrCurrencyLocked
		}
	}
	if s.walletSvc != nil {
		wlt, err := s.walletSvc.GetWalletByTenant(ctx, tenantID)
		if err == nil && wlt != nil {
			entries, _ := s.walletSvc.GetLedgerEntries(ctx, wlt.WalletID)
			if len(entries) > 0 {
				return nil, ErrCurrencyLocked
			}
		}
	}

	before := map[string]interface{}{"currency": t.Currency}
	t.Currency = curr
	t.UpdatedAt = time.Now().Unix()

	if s.walletSvc != nil {
		if memWlt, ok := s.walletSvc.(*wallet.MemoryService); ok {
			if wlt, err := memWlt.GetWalletByTenant(ctx, tenantID); err == nil && wlt != nil {
				wlt.Asset = curr
				wlt.UpdatedAt = time.Now()
			}
		}
	}

	s.recordAudit(tenantID, actorMemberID, "tenant.currency.updated", "Tenant", tenantID, before, map[string]interface{}{"currency": curr}, "127.0.0.1")
	return t, nil
}

func (s *MemoryService) UpdateTenantStatus(ctx context.Context, tenantID string, status TenantStatus, actorMemberID string) (*Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.tenants[tenantID]
	if !ok {
		return nil, ErrTenantNotFound
	}
	if t.Status == TenantStatusTerminated && status != TenantStatusTerminated {
		return nil, ErrInvalidStatusTransition
	}
	if actorMemberID == "" {
		if !auth.IsSystemContext(ctx) {
			return nil, ErrPermissionDenied
		}
	} else {
		actor, ok := s.members[actorMemberID]
		if !ok || actor.TenantID != tenantID || actor.Role != RoleOwner {
			return nil, ErrPermissionDenied
		}
	}

	before := map[string]interface{}{"status": string(t.Status)}
	t.Status = status
	t.UpdatedAt = time.Now().Unix()

	s.recordAudit(tenantID, actorMemberID, "tenant.status.changed", "Tenant", tenantID, before, map[string]interface{}{"status": string(status)}, "127.0.0.1")
	return t, nil
}

// ----------------------------------------------------------------------------
// Projects
// ----------------------------------------------------------------------------

func (s *MemoryService) CreateProject(ctx context.Context, tenantID, name string, budgetCap int64, projectID string, actorMemberID string) (*Project, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenant, ok := s.tenants[tenantID]
	if !ok {
		return nil, ErrTenantNotFound
	}
	if tenant.Status == TenantStatusSuspended {
		return nil, ErrTenantSuspended
	}
	if tenant.Status == TenantStatusTerminated {
		return nil, ErrTenantTerminated
	}
	if err := s.checkPermissionLocked(tenantID, actorMemberID, PermissionProjectCreate); err != nil {
		return nil, err
	}

	cleanName := strings.TrimSpace(name)
	if cleanName == "" {
		return nil, fmt.Errorf("project name cannot be empty")
	}
	for _, p := range s.projects {
		if p.TenantID == tenantID && p.Name == cleanName {
			return nil, ErrProjectAlreadyExists
		}
	}

	pid := projectID
	if pid == "" {
		pid = GenerateProjectID()
	}

	now := time.Now().Unix()
	p := &Project{
		ProjectID:          pid,
		TenantID:           tenantID,
		Name:               cleanName,
		BudgetCapBaseUnits: budgetCap,
		Status:             ProjectStatusActive,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	s.projects[pid] = p

	s.recordAudit(tenantID, actorMemberID, "project.created", "Project", pid, nil, map[string]interface{}{"name": cleanName}, "127.0.0.1")
	return p, nil
}

func (s *MemoryService) GetProject(ctx context.Context, tenantID, projectID string) (*Project, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	p, ok := s.projects[projectID]
	if !ok {
		return nil, ErrProjectNotFound
	}
	if tenantID != "" && p.TenantID != tenantID {
		return nil, ErrProjectTenantMismatch
	}
	return p, nil
}

func (s *MemoryService) ListProjects(ctx context.Context, tenantID string) ([]*Project, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make([]*Project, 0)
	for _, p := range s.projects {
		if tenantID == "" || p.TenantID == tenantID {
			res = append(res, p)
		}
	}
	return res, nil
}

func (s *MemoryService) UpdateProject(ctx context.Context, tenantID, projectID string, name string, budgetCap *int64, status *ProjectStatus, actorMemberID string) (*Project, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok := s.projects[projectID]
	if !ok {
		return nil, ErrProjectNotFound
	}
	if p.TenantID != tenantID {
		return nil, ErrProjectTenantMismatch
	}
	if err := s.checkPermissionLocked(tenantID, actorMemberID, PermissionProjectUpdate); err != nil {
		return nil, err
	}

	before := map[string]interface{}{"name": p.Name, "budget_cap": p.BudgetCapBaseUnits, "status": string(p.Status)}
	if name != "" {
		cleanName := strings.TrimSpace(name)
		for _, other := range s.projects {
			if other.ProjectID != projectID && other.TenantID == tenantID && other.Name == cleanName {
				return nil, ErrProjectAlreadyExists
			}
		}
		p.Name = cleanName
	}
	if budgetCap != nil {
		p.BudgetCapBaseUnits = *budgetCap
	}
	if status != nil {
		p.Status = *status
	}
	p.UpdatedAt = time.Now().Unix()

	s.recordAudit(tenantID, actorMemberID, "project.updated", "Project", projectID, before, map[string]interface{}{"name": p.Name, "status": string(p.Status)}, "127.0.0.1")
	return p, nil
}

func (s *MemoryService) DeleteProject(ctx context.Context, tenantID, projectID string, actorMemberID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok := s.projects[projectID]
	if !ok {
		return ErrProjectNotFound
	}
	if p.TenantID != tenantID {
		return ErrProjectTenantMismatch
	}
	if err := s.checkPermissionLocked(tenantID, actorMemberID, PermissionProjectDelete); err != nil {
		return err
	}

	delete(s.projects, projectID)
	s.recordAudit(tenantID, actorMemberID, "project.deleted", "Project", projectID, map[string]interface{}{"name": p.Name}, nil, "127.0.0.1")
	return nil
}

// ----------------------------------------------------------------------------
// Members & RBAC
// ----------------------------------------------------------------------------

func (s *MemoryService) AddMember(ctx context.Context, tenantID, email string, role MemberRole, actorMemberID string) (*Member, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cleanEmail := strings.TrimSpace(strings.ToLower(email))
	if cleanEmail == "" {
		return nil, fmt.Errorf("email cannot be empty")
	}
	if err := s.checkPermissionLocked(tenantID, actorMemberID, PermissionMemberCreate); err != nil {
		return nil, err
	}

	for _, m := range s.members {
		if m.TenantID == tenantID && m.Email == cleanEmail {
			return nil, ErrMemberAlreadyExists
		}
	}

	now := time.Now().Unix()
	m := &Member{
		MemberID:  GenerateMemberID(),
		TenantID:  tenantID,
		Email:     cleanEmail,
		Role:      role,
		Status:    MemberStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
	s.members[m.MemberID] = m

	s.recordAudit(tenantID, actorMemberID, "member.created", "Member", m.MemberID, nil, map[string]interface{}{"email": cleanEmail, "role": string(role)}, "127.0.0.1")
	return m, nil
}

func (s *MemoryService) GetMember(ctx context.Context, tenantID, memberID string) (*Member, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	m, ok := s.members[memberID]
	if !ok || m.TenantID != tenantID {
		return nil, ErrMemberNotFound
	}
	return m, nil
}

func (s *MemoryService) ListMembers(ctx context.Context, tenantID string) ([]*Member, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make([]*Member, 0)
	for _, m := range s.members {
		if m.TenantID == tenantID {
			res = append(res, m)
		}
	}
	return res, nil
}

func (s *MemoryService) countActiveOwnersLocked(tenantID string) int {
	activeOwners := 0
	for _, other := range s.members {
		if other.TenantID == tenantID && other.Role == RoleOwner && other.Status == MemberStatusActive {
			activeOwners++
		}
	}
	return activeOwners
}

func (s *MemoryService) UpdateMember(ctx context.Context, tenantID, memberID string, role *MemberRole, status *MemberStatus, actorMemberID string) (*Member, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	m, ok := s.members[memberID]
	if !ok || m.TenantID != tenantID {
		return nil, ErrMemberNotFound
	}
	if err := s.checkPermissionLocked(tenantID, actorMemberID, PermissionMemberUpdate); err != nil {
		return nil, err
	}

	if m.Role == RoleOwner && (role != nil && *role != RoleOwner || status != nil && *status == MemberStatusDisabled) {
		if s.countActiveOwnersLocked(tenantID) <= 1 {
			return nil, ErrCannotDemoteLastOwner
		}
	}

	before := map[string]interface{}{"role": string(m.Role), "status": string(m.Status)}
	if role != nil {
		m.Role = *role
	}
	if status != nil {
		m.Status = *status
	}
	m.UpdatedAt = time.Now().Unix()

	s.recordAudit(tenantID, actorMemberID, "member.updated", "Member", memberID, before, map[string]interface{}{"role": string(m.Role), "status": string(m.Status)}, "127.0.0.1")
	return m, nil
}

func (s *MemoryService) RemoveMember(ctx context.Context, tenantID, memberID string, actorMemberID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	m, ok := s.members[memberID]
	if !ok || m.TenantID != tenantID {
		return ErrMemberNotFound
	}
	if err := s.checkPermissionLocked(tenantID, actorMemberID, PermissionMemberDelete); err != nil {
		return err
	}
	if m.Role == RoleOwner && s.countActiveOwnersLocked(tenantID) <= 1 {
		return ErrCannotRemoveLastOwner
	}

	delete(s.members, memberID)
	s.recordAudit(tenantID, actorMemberID, "member.deleted", "Member", memberID, map[string]interface{}{"email": m.Email}, nil, "127.0.0.1")
	return nil
}

// ----------------------------------------------------------------------------
// Agents & Kill Switch
// ----------------------------------------------------------------------------

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
		AgentID:      aid,
		TenantID:     tenantID,
		ProjectID:    projectID,
		Name:         cleanName,
		Status:       AgentStatusActive,
		PolicyConfig: policyCfg,
		CreatedAt:    now,
		UpdatedAt:    now,
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

func (s *MemoryService) SetRCUManager(mgr *rcu.Manager) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rcuMgr = mgr
}

func (s *MemoryService) SyncRCU(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.syncRCULocked()
}

func (s *MemoryService) syncRCULocked() error {
	if s.rcuMgr == nil {
		return nil
	}

	routes := make([]rcu.RouteConfig, 0, len(s.routes))
	for _, r := range s.routes {
		if r.Status == RouteStatusActive {
			routes = append(routes, rcu.RouteConfig{
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
	}

	policies := make([]rcu.PolicyConfig, 0, len(s.policies))
	for _, p := range s.policies {
		if p.IsActive {
			var agID, rteID *string
			if p.AgentID != "" {
				ag := p.AgentID
				agID = &ag
			}
			if p.RouteID != "" {
				rt := p.RouteID
				rteID = &rt
			}
			policies = append(policies, rcu.PolicyConfig{
				PolicyID:             p.PolicyID,
				TenantID:             p.TenantID,
				ProjectID:            p.ProjectID,
				AgentID:              agID,
				RouteID:              rteID,
				MaxAmountPerRequest:  p.MaxAmountPerRequest,
				Rolling24hBudgetCap:  p.Rolling24hBudgetCap,
				CircuitBreakerMaxRPM: p.CircuitBreakerMaxRPM,
				WhitelistedNetworks:  p.WhitelistedNetworks,
				WhitelistedRoutes:    p.WhitelistedRoutes,
				IsActive:             p.IsActive,
			})
		}
	}

	return mergeAndApplyRCUSnapshot(s.rcuMgr, routes, policies, "admin_memory_sync")
}

// ----------------------------------------------------------------------------
// Wallets
// ----------------------------------------------------------------------------

func (s *MemoryService) AdminGrantWallet(ctx context.Context, tenantID string, amount int64, reason string, idempotencyKey string, actorMemberID string, clientIP string) error {
	cleanReason := strings.TrimSpace(reason)
	if cleanReason == "" {
		return ErrMissingReason
	}
	if amount <= 0 {
		return ErrInvalidAmount
	}
	if err := s.checkPermissionRLock(tenantID, actorMemberID, PermissionWalletAdjust); err != nil {
		return err
	}

	w, err := s.walletSvc.GetWalletByTenant(ctx, tenantID)
	if err != nil {
		return ErrWalletNotFound
	}

	now := time.Now()
	order := &wallet.TopUpOrder{
		TopUpID:     fmt.Sprintf("ord_%s_%d", tenantID, now.UnixNano()),
		WalletID:    w.WalletID,
		TenantID:    tenantID,
		Channel:     wallet.ChannelAdminGrant,
		Amount:      amount,
		Asset:       w.Asset,
		ExternalRef: idempotencyKey,
		Reason:      cleanReason,
		Status:      wallet.TopUpStatusConfirmed,
		CreatedAt:   now,
		ConfirmedAt: now,
	}
	if err := s.walletSvc.CreditTopUp(ctx, order); err != nil {
		return err
	}

	s.recordAudit(tenantID, actorMemberID, "wallet.admin_grant", "Wallet", w.WalletID, nil, map[string]interface{}{"amount": amount, "reason": cleanReason}, clientIP)
	return nil
}

func (s *MemoryService) AdjustWallet(ctx context.Context, walletID string, amount int64, reason string, idempotencyKey string, actorMemberID string, clientIP string) error {
	cleanReason := strings.TrimSpace(reason)
	if cleanReason == "" {
		return ErrMissingReason
	}

	w, err := s.walletSvc.GetWallet(ctx, walletID)
	if err != nil {
		return ErrWalletNotFound
	}
	if err := s.checkPermissionRLock(w.TenantID, actorMemberID, PermissionWalletAdjust); err != nil {
		return err
	}
	if err := s.walletSvc.AdjustBalance(ctx, walletID, amount, cleanReason, idempotencyKey, actorMemberID); err != nil {
		return err
	}

	s.recordAudit(w.TenantID, actorMemberID, "wallet.adjust", "Wallet", walletID, nil, map[string]interface{}{"amount": amount, "reason": cleanReason}, clientIP)
	return nil
}

func (s *MemoryService) FreezeWallet(ctx context.Context, walletID string, reason string, actorMemberID string, clientIP string) error {
	cleanReason := strings.TrimSpace(reason)
	if cleanReason == "" {
		return ErrMissingReason
	}

	w, err := s.walletSvc.GetWallet(ctx, walletID)
	if err != nil {
		return ErrWalletNotFound
	}
	if err := s.checkPermissionRLock(w.TenantID, actorMemberID, PermissionWalletAdjust); err != nil {
		return err
	}
	if err := s.walletSvc.SetWalletStatus(ctx, walletID, wallet.StatusFrozen); err != nil {
		return err
	}

	s.recordAudit(w.TenantID, actorMemberID, "wallet.frozen", "Wallet", walletID, nil, map[string]interface{}{"reason": cleanReason}, clientIP)
	return nil
}

func (s *MemoryService) UnfreezeWallet(ctx context.Context, walletID string, reason string, actorMemberID string, clientIP string) error {
	cleanReason := strings.TrimSpace(reason)
	if cleanReason == "" {
		return ErrMissingReason
	}

	w, err := s.walletSvc.GetWallet(ctx, walletID)
	if err != nil {
		return ErrWalletNotFound
	}
	if err := s.checkPermissionRLock(w.TenantID, actorMemberID, PermissionWalletAdjust); err != nil {
		return err
	}
	if w.Status == wallet.StatusFrozenArrears && w.AvailableCache < 0 {
		return fmt.Errorf("cannot unfreeze wallet in arrears")
	}
	if err := s.walletSvc.SetWalletStatus(ctx, walletID, wallet.StatusActive); err != nil {
		return err
	}

	s.recordAudit(w.TenantID, actorMemberID, "wallet.unfrozen", "Wallet", walletID, nil, map[string]interface{}{"reason": cleanReason}, clientIP)
	return nil
}

func (s *MemoryService) RecalculateWallet(ctx context.Context, walletID string, actorMemberID string) (map[string]interface{}, error) {
	w, err := s.walletSvc.GetWallet(ctx, walletID)
	if err != nil {
		return nil, ErrWalletNotFound
	}
	if err := s.checkPermissionRLock(w.TenantID, actorMemberID, PermissionWalletRead); err != nil {
		return nil, err
	}
	return recalculateWalletBalanceMap(ctx, s.walletSvc, walletID)
}

func (s *MemoryService) GetWallet(ctx context.Context, tenantID string) (*wallet.Wallet, error) {
	return s.walletSvc.GetWalletByTenant(ctx, tenantID)
}

func (s *MemoryService) GetWalletByID(ctx context.Context, walletID string) (*wallet.Wallet, error) {
	return s.walletSvc.GetWallet(ctx, walletID)
}

func (s *MemoryService) GetLedgerEntries(ctx context.Context, walletID string) ([]*wallet.LedgerEntry, error) {
	return s.walletSvc.GetLedgerEntries(ctx, walletID)
}

func (s *MemoryService) GetTopUpOrders(ctx context.Context, walletID string) ([]*wallet.TopUpOrder, error) {
	return s.walletSvc.GetTopUpOrders(ctx, walletID)
}

// ----------------------------------------------------------------------------
// Audit Events
// ----------------------------------------------------------------------------

func (s *MemoryService) ListAuditEvents(ctx context.Context, tenantID, targetType, targetID string, limit int) ([]*AuditEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make([]*AuditEvent, 0)
	for i := len(s.auditEvents) - 1; i >= 0; i-- {
		ev := s.auditEvents[i]
		if tenantID != "" && ev.TenantID != tenantID {
			continue
		}
		if targetType != "" && ev.TargetType != targetType {
			continue
		}
		if targetID != "" && ev.TargetID != targetID {
			continue
		}
		res = append(res, ev)
		if limit > 0 && len(res) >= limit {
			break
		}
	}
	return res, nil
}

// ----------------------------------------------------------------------------
// Config Draft, Validation, Publishing & Rollback (T4.3 & T4.4)
// ----------------------------------------------------------------------------

func (s *MemoryService) tenantRoutesAndPoliciesLocked(tenantID string) ([]*Route, []*Policy) {
	routes := make([]*Route, 0)
	for _, r := range s.routes {
		if r.TenantID == tenantID {
			routes = append(routes, r)
		}
	}
	policies := make([]*Policy, 0)
	for _, p := range s.policies {
		if p.TenantID == tenantID {
			policies = append(policies, p)
		}
	}
	return routes, policies
}

func (s *MemoryService) ValidateConfig(ctx context.Context, tenantID string, actorMemberID string) (*ValidationResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.tenants[tenantID]; !ok {
		return nil, ErrTenantNotFound
	}
	if err := s.checkPermissionLocked(tenantID, actorMemberID, PermissionRouteRead); err != nil {
		return nil, err
	}

	routes, policies := s.tenantRoutesAndPoliciesLocked(tenantID)
	res := evaluateConfigValidation(routes, policies)

	if s.lastValidation == nil {
		s.lastValidation = make(map[string]*ValidationResult)
	}
	s.lastValidation[tenantID] = res

	s.recordAudit(tenantID, actorMemberID, "config.validated", "Tenant", tenantID, nil, map[string]interface{}{
		"valid":       res.Valid,
		"error_count": len(res.Errors),
	}, "127.0.0.1")

	return res, nil
}

func (s *MemoryService) GetDraftSummary(ctx context.Context, tenantID string) (*ConfigDraftSummary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	routes, policies := s.tenantRoutesAndPoliciesLocked(tenantID)
	var lastRes *ValidationResult
	if s.lastValidation != nil {
		lastRes = s.lastValidation[tenantID]
	}
	return buildDraftSummary(tenantID, len(routes), len(policies), lastRes), nil
}

func (s *MemoryService) GetDraftDiff(ctx context.Context, tenantID string) (*ConfigDraftDiff, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	routes, policies := s.tenantRoutesAndPoliciesLocked(tenantID)
	return buildDraftDiff(tenantID, routes, policies), nil
}

func (s *MemoryService) resolvePublisherEmailLocked(tenantID, actorMemberID string) (string, error) {
	if actorMemberID == "" {
		return "", ErrPermissionDenied
	}
	actor, ok := s.members[actorMemberID]
	if !ok || actor.TenantID != tenantID {
		return "", ErrPermissionDenied
	}
	if err := EnforcePermission(actor, PermissionRouteWrite); err != nil {
		return "", err
	}
	return actor.Email, nil
}

func (s *MemoryService) nextVersionNumberLocked(tenantID string) int64 {
	var maxVerNum int64
	for _, v := range s.configVersionHistory[tenantID] {
		if v.VersionNumber > maxVerNum {
			maxVerNum = v.VersionNumber
		}
	}
	return maxVerNum + 1
}

func (s *MemoryService) PublishConfig(ctx context.Context, tenantID string, changeSummary string, actorMemberID string) (*ConfigVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.tenants[tenantID]; !ok {
		return nil, ErrTenantNotFound
	}
	publisherEmail, err := s.resolvePublisherEmailLocked(tenantID, actorMemberID)
	if err != nil {
		return nil, err
	}

	routes, policies := s.tenantRoutesAndPoliciesLocked(tenantID)
	if valRes := evaluateConfigValidation(routes, policies); !valRes.Valid {
		return nil, ErrConfigValidationFailed
	}

	rcuRoutes, rcuPolicies := buildRCUSnapshotConfigs(routes, policies)
	snapshotHash := rcu.ComputeCanonicalSnapshotHash(rcuRoutes, rcuPolicies)
	newVersionNumber := s.nextVersionNumberLocked(tenantID)
	versionID := GenerateConfigVersionID()
	now := time.Now().Unix()

	summary := strings.TrimSpace(changeSummary)
	if summary == "" {
		summary = fmt.Sprintf("Publish configuration version v%d", newVersionNumber)
	}

	snap := &rcu.ConfigSnapshot{
		SchemaVersion: "2.0.0",
		TenantID:      tenantID,
		VersionID:     versionID,
		VersionNumber: newVersionNumber,
		PublishedAt:   now,
		PublishedBy:   actorMemberID,
		ChangeSummary: summary,
		SnapshotHash:  snapshotHash,
		Routes:        rcuRoutes,
		Policies:      rcuPolicies,
	}

	for _, v := range s.configVersionHistory[tenantID] {
		v.IsActive = false
	}

	newVer := &ConfigVersion{
		VersionID:      versionID,
		TenantID:       tenantID,
		VersionNumber:  newVersionNumber,
		SnapshotJSON:   snap,
		SnapshotHash:   snapshotHash,
		PublishedBy:    actorMemberID,
		PublisherEmail: publisherEmail,
		ChangeSummary:  summary,
		IsActive:       true,
		RoutesCount:    len(rcuRoutes),
		PoliciesCount:  len(rcuPolicies),
		CreatedAt:      now,
	}

	s.configVersions[versionID] = newVer
	s.configVersionHistory[tenantID] = append(s.configVersionHistory[tenantID], newVer)

	if s.rcuMgr != nil {
		_ = s.rcuMgr.Update(snap)
	}

	s.recordAudit(tenantID, actorMemberID, "config.published", "ConfigVersion", versionID, nil, map[string]interface{}{
		"version_number": newVersionNumber,
		"snapshot_hash":  snapshotHash,
		"change_summary": summary,
		"routes_count":   len(rcuRoutes),
		"policies_count": len(rcuPolicies),
	}, "127.0.0.1")

	return newVer, nil
}

func (s *MemoryService) ListConfigVersions(ctx context.Context, tenantID string) ([]*ConfigVersion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	history := s.configVersionHistory[tenantID]
	if len(history) == 0 {
		return []*ConfigVersion{}, nil
	}
	res := make([]*ConfigVersion, len(history))
	for i, v := range history {
		res[len(history)-1-i] = v
	}
	return res, nil
}

func (s *MemoryService) GetConfigVersion(ctx context.Context, tenantID, versionID string) (*ConfigVersion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ver, ok := s.configVersions[versionID]
	if !ok || ver.TenantID != tenantID {
		return nil, ErrConfigVersionNotFound
	}
	return ver, nil
}

func (s *MemoryService) RollbackConfig(ctx context.Context, tenantID, targetVersionID, reason, actorMemberID string) (*ConfigVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.tenants[tenantID]; !ok {
		return nil, ErrTenantNotFound
	}
	publisherEmail, err := s.resolvePublisherEmailLocked(tenantID, actorMemberID)
	if err != nil {
		return nil, err
	}

	targetVer, ok := s.configVersions[targetVersionID]
	if !ok || targetVer.TenantID != tenantID {
		return nil, ErrConfigVersionNotFound
	}
	if targetVer.IsActive {
		return nil, ErrCannotRollbackToActive
	}

	newVersionNumber := s.nextVersionNumberLocked(tenantID)
	versionID := GenerateConfigVersionID()
	now := time.Now().Unix()

	restoredSnap, summary := buildRestoredSnapshot(tenantID, versionID, actorMemberID, reason, newVersionNumber, now, targetVer)

	for _, v := range s.configVersionHistory[tenantID] {
		v.IsActive = false
	}

	newVer := &ConfigVersion{
		VersionID:      versionID,
		TenantID:       tenantID,
		VersionNumber:  newVersionNumber,
		SnapshotJSON:   restoredSnap,
		SnapshotHash:   targetVer.SnapshotHash,
		PublishedBy:    actorMemberID,
		PublisherEmail: publisherEmail,
		ChangeSummary:  summary,
		IsActive:       true,
		RoutesCount:    len(restoredSnap.Routes),
		PoliciesCount:  len(restoredSnap.Policies),
		CreatedAt:      now,
	}

	s.configVersions[versionID] = newVer
	s.configVersionHistory[tenantID] = append(s.configVersionHistory[tenantID], newVer)

	for id, r := range s.routes {
		if r.TenantID == tenantID {
			delete(s.routes, id)
		}
	}
	for _, rr := range restoredSnap.Routes {
		s.routes[rr.RouteID] = &Route{
			RouteID:               rr.RouteID,
			TenantID:              tenantID,
			ProjectID:             rr.ProjectID,
			PathPattern:           rr.PathPattern,
			UpstreamURL:           rr.UpstreamURL,
			PriceBaseUnits:        rr.PriceBaseUnits,
			Asset:                 rr.Asset,
			PayeeAddress:          rr.PayeeAddress,
			AllowedPaymentMethods: rr.AllowedPaymentMethods,
			TimeoutMs:             rr.TimeoutMS,
			RateLimitRPM:          rr.RateLimitRPM,
			Status:                RouteStatus(rr.Status),
			UpstreamAuth:          rr.UpstreamAuth,
			CreatedAt:             now,
			UpdatedAt:             now,
		}
	}

	if s.rcuMgr != nil {
		_ = s.rcuMgr.Update(restoredSnap)
	}

	s.recordAudit(tenantID, actorMemberID, "config.rolled_back", "ConfigVersion", versionID, map[string]interface{}{
		"target_version_id":     targetVer.VersionID,
		"target_version_number": targetVer.VersionNumber,
	}, map[string]interface{}{
		"new_version_id":     versionID,
		"new_version_number": newVersionNumber,
		"active_hash":        targetVer.SnapshotHash,
		"reason":             reason,
	}, "127.0.0.1")

	return newVer, nil
}

func (s *MemoryService) GetConfigVersionDiff(ctx context.Context, tenantID, baseVersionID, targetVersionID string) (*ConfigDraftDiff, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var baseSnap, targetSnap *rcu.ConfigSnapshot
	if baseVersionID != "" {
		v, ok := s.configVersions[baseVersionID]
		if !ok || v.TenantID != tenantID {
			return nil, ErrConfigVersionNotFound
		}
		baseSnap = v.SnapshotJSON
	} else {
		for _, v := range s.configVersionHistory[tenantID] {
			if v.IsActive {
				baseSnap = v.SnapshotJSON
				break
			}
		}
	}

	if targetVersionID != "" {
		v, ok := s.configVersions[targetVersionID]
		if !ok || v.TenantID != tenantID {
			return nil, ErrConfigVersionNotFound
		}
		targetSnap = v.SnapshotJSON
	}

	return computeSnapshotDiff(tenantID, baseSnap, targetSnap), nil
}

// ----------------------------------------------------------------------------
// Upstream Authentication & Connectivity Testing (T4.2 Enhancement)
// ----------------------------------------------------------------------------

func (s *MemoryService) GetAuthTypes() []upstreamauth.AuthTypeSchema {
	return upstreamauth.ListSchemas()
}

func (s *MemoryService) TestUpstream(ctx context.Context, tenantID string, input *TestUpstreamInput, actorMemberID string) (*TestUpstreamResult, error) {
	if err := s.checkPermissionRLock(tenantID, actorMemberID, PermissionRouteRead); err != nil {
		return nil, err
	}
	result, cleanURL, testErr := executeUpstreamTest(ctx, input)
	if testErr != nil {
		return nil, testErr
	}
	if cleanURL != "" && result.StatusCode > 0 || result.Error != "" && strings.HasPrefix(result.Error, "upstream connection error:") {
		s.recordAudit(tenantID, actorMemberID, "route.tested", "Route", "", nil, map[string]interface{}{
			"url":         cleanURL,
			"auth_type":   "",
			"success":     result.Success,
			"status_code": result.StatusCode,
		}, "127.0.0.1")
	}
	return result, nil
}

// ----------------------------------------------------------------------------
// Observability: Usage, Payment Correlation & Timeline (T5.1, T5.2, T5.8)
// ----------------------------------------------------------------------------

func (s *MemoryService) enforceAuditRead(ctx context.Context, tenantID, actorMemberID string) error {
	if actorMemberID == "" {
		if auth.IsSystemContext(ctx) {
			return nil
		}
		return ErrPermissionDenied
	}
	member, err := s.GetMember(ctx, tenantID, actorMemberID)
	if err != nil {
		return ErrPermissionDenied
	}
	return EnforcePermission(member, PermissionAuditRead)
}

func (s *MemoryService) SetUsageService(svc usage.Service) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.usageSvc = svc
}

func (s *MemoryService) GetUsageService() usage.Service {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.usageSvc == nil {
		s.usageSvc = usage.NewMemoryService()
	}
	return s.usageSvc
}

func (s *MemoryService) ListRequestRecords(ctx context.Context, tenantID string, filter usage.RequestFilter, actorMemberID string) ([]*usage.RequestRecord, int64, error) {
	if err := s.enforceAuditRead(ctx, tenantID, actorMemberID); err != nil {
		return nil, 0, err
	}
	filter.TenantID = tenantID
	return s.GetUsageService().ListRequestRecords(ctx, filter)
}

func (s *MemoryService) GetRequestRecord(ctx context.Context, tenantID, requestID string, actorMemberID string) (*usage.RequestRecord, error) {
	if err := s.enforceAuditRead(ctx, tenantID, actorMemberID); err != nil {
		return nil, err
	}
	return s.GetUsageService().GetRequestRecord(ctx, tenantID, requestID)
}

func (s *MemoryService) ListUsageEvents(ctx context.Context, tenantID string, filter usage.UsageFilter, actorMemberID string) ([]*usage.UsageEvent, int64, error) {
	if err := s.enforceAuditRead(ctx, tenantID, actorMemberID); err != nil {
		return nil, 0, err
	}
	filter.TenantID = tenantID
	return s.GetUsageService().ListUsageEvents(ctx, filter)
}

func (s *MemoryService) GetUsageEvent(ctx context.Context, tenantID, eventID string, actorMemberID string) (*usage.UsageEvent, error) {
	if err := s.enforceAuditRead(ctx, tenantID, actorMemberID); err != nil {
		return nil, err
	}
	return s.GetUsageService().GetUsageEvent(ctx, tenantID, eventID)
}

func (s *MemoryService) SetPaymentService(svc payment.Service) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.paymentSvc = svc
}

func (s *MemoryService) GetPaymentService() payment.Service {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.paymentSvc == nil {
		return payment.NewMemoryService()
	}
	return s.paymentSvc
}

func (s *MemoryService) GetPaymentAudit(ctx context.Context, tenantID, intentID string, actorMemberID string) (*payment.PaymentAuditRecord, error) {
	if err := s.enforceAuditRead(ctx, tenantID, actorMemberID); err != nil {
		return nil, err
	}
	return s.GetPaymentService().GetPaymentAudit(ctx, tenantID, intentID)
}

func (s *MemoryService) GetPaymentAuditByRequestID(ctx context.Context, tenantID, requestID string, actorMemberID string) (*payment.PaymentAuditRecord, error) {
	if err := s.enforceAuditRead(ctx, tenantID, actorMemberID); err != nil {
		return nil, err
	}
	return s.GetPaymentService().GetPaymentAuditByRequestID(ctx, tenantID, requestID)
}

func (s *MemoryService) ListPaymentAudits(ctx context.Context, tenantID string, filter payment.PaymentAuditFilter, actorMemberID string) ([]*payment.PaymentAuditRecord, int64, error) {
	if err := s.enforceAuditRead(ctx, tenantID, actorMemberID); err != nil {
		return nil, 0, err
	}
	filter.TenantID = tenantID
	return s.GetPaymentService().ListPaymentAudits(ctx, filter)
}

func (s *MemoryService) SetTimelineService(svc timeline.Service) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.timelineSvc = svc
}

func (s *MemoryService) GetTimelineService() timeline.Service {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.timelineSvc == nil {
		return timeline.NewMemoryService()
	}
	return s.timelineSvc
}

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
