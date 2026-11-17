package admin

import (
	"context"
	"time"
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
	CreateProject(ctx context.Context, tenantID, name string, departmentID *string, budgetCap int64, projectID string, actorMemberID string) (*Project, error)
	GetProject(ctx context.Context, tenantID, projectID string) (*Project, error)
	ListProjects(ctx context.Context, tenantID string) ([]*Project, error)
	UpdateProject(ctx context.Context, tenantID, projectID string, name string, departmentID *string, budgetCap *int64, status *ProjectStatus, actorMemberID string) (*Project, error)
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

	// Public Marketplace (Read-Only Discovery & Zero-Friction Trial Key)
	ListMarketplaceRoutes(ctx context.Context, filter MarketplaceFilter) ([]*MarketplaceRouteItem, error)
	GetMarketplaceRouteBySlug(ctx context.Context, slug string) (*MarketplaceRouteItem, error)
	CreateTrialAPIKey(ctx context.Context, clientIP, fingerprint string) (*TrialKeyResponse, error)
	ClaimTrialAPIKey(ctx context.Context, tenantID string, rawAPIKey string, projectID, agentID string, actorMemberID string) (*APIKey, error)
	CleanExpiredTrialKeys(ctx context.Context) (int64, error)

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
	GetWalletService() wallet.Service
	CreateTopUpOrder(ctx context.Context, tenantID string, amountCents int64, channel wallet.TopUpChannel, reason, actorMemberID string) (*wallet.TopUpOrder, error)
	GetTopUpOrderByID(ctx context.Context, tenantID, topupID string) (*wallet.TopUpOrder, error)
	ConfirmTopUpPayment(ctx context.Context, topupID, externalRef string, paidAmountCents int64, reason string, confirmedAt time.Time) (*wallet.TopUpOrder, error)

	// Audit
	ListAuditEvents(ctx context.Context, tenantID, targetType, targetID string, limit int) ([]*AuditEvent, error)

	// Usage & Request Tracing (T5.1)
	SetUsageService(svc usage.Service)
	GetUsageService() usage.Service
	ListRequestRecords(ctx context.Context, tenantID string, filter usage.RequestFilter, actorMemberID string) ([]*usage.RequestRecord, int64, error)
	GetRequestRecord(ctx context.Context, tenantID, requestID string, actorMemberID string) (*usage.RequestRecord, error)
	ListUsageEvents(ctx context.Context, tenantID string, filter usage.UsageFilter, actorMemberID string) ([]*usage.UsageEvent, int64, error)
	GetUsageEvent(ctx context.Context, tenantID, eventID string, actorMemberID string) (*usage.UsageEvent, error)
	GetRouteTelemetryOverview(ctx context.Context, tenantID, timeRange, projectID, actorMemberID string) (*RouteTelemetryOverviewResponse, error)

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
