package admin

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/open-agentpay/agent-core-sdk/gateway/agent"
	"github.com/open-agentpay/agent-core-sdk/gateway/payment"
	"github.com/open-agentpay/agent-core-sdk/gateway/rcu"
	"github.com/open-agentpay/agent-core-sdk/gateway/timeline"
	"github.com/open-agentpay/agent-core-sdk/gateway/upstreamauth"
	"github.com/open-agentpay/agent-core-sdk/gateway/usage"
	"github.com/open-agentpay/agent-core-sdk/gateway/wallet"
)

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

func (s *MemoryService) GetWalletService() wallet.Service {
	return s.walletSvc
}

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

