package server

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
	"github.com/open-agentpay/agent-core-sdk/gateway/admin"
	"github.com/open-agentpay/agent-core-sdk/gateway/agent"
	"github.com/open-agentpay/agent-core-sdk/gateway/auth"
	"github.com/open-agentpay/agent-core-sdk/gateway/config"
	"github.com/open-agentpay/agent-core-sdk/gateway/mcp"
	"github.com/open-agentpay/agent-core-sdk/gateway/metrics"
	"github.com/open-agentpay/agent-core-sdk/gateway/payment"
	"github.com/open-agentpay/agent-core-sdk/gateway/proxy"
	"github.com/open-agentpay/agent-core-sdk/gateway/rcu"
	"github.com/open-agentpay/agent-core-sdk/gateway/settlement"
	"github.com/open-agentpay/agent-core-sdk/gateway/timeline"
	"github.com/open-agentpay/agent-core-sdk/gateway/upstreamauth"
	"github.com/open-agentpay/agent-core-sdk/gateway/usage"
	"github.com/open-agentpay/agent-core-sdk/gateway/wallet"
	"github.com/open-agentpay/agent-core-sdk/gateway/x402"
)

// GatewayServer encapsulates the HTTP listener and runtime dependencies.
type GatewayServer struct {
	cfg               *config.GatewayConfig
	httpServer        *http.Server
	db                *sql.DB
	metrics           *metrics.Metrics
	rcuMgr            *rcu.Manager
	processor         *x402.PaymentProcessor
	verifier          x402.PaymentVerifier
	settlementAdapter settlement.SettlementAdapter
	walletSvc         wallet.Service
	adminSvc          admin.Service
	usageSvc          usage.Service
	paymentSvc        payment.Service
	timelineSvc       timeline.Service
	startTime         time.Time
	stopOnce          sync.Once
	stopCh            chan struct{}
}

// Option configures optional parameters for GatewayServer.
type Option func(*ServerOptions)

// ServerOptions contains optional overrides for GatewayServer components.
type ServerOptions struct {
	Verifier          x402.PaymentVerifier
	SettlementAdapter settlement.SettlementAdapter
	WalletSvc         wallet.Service
	Transport         http.RoundTripper
	AssetResolver     x402.AssetResolver
	PolicyEvaluator    agent.PolicyEvaluator
	SpendRecorder      agent.SpendRecorder
	ExtraRoutes        map[string]http.Handler
	TenantSubresources map[string]http.Handler
}

// WithTenantSubresource registers an extension handler for tenant-scoped subresources at /api/v1/tenants/{tenant_id}/<name>
func WithTenantSubresource(subresource string, h http.Handler) Option {
	return func(o *ServerOptions) {
		if o.TenantSubresources == nil {
			o.TenantSubresources = make(map[string]http.Handler)
		}
		o.TenantSubresources[subresource] = h
	}
}

// WithPolicyEvaluator provides an optional custom PolicyEvaluator implementation.
func WithPolicyEvaluator(e agent.PolicyEvaluator) Option {
	return func(o *ServerOptions) { o.PolicyEvaluator = e }
}

// WithSpendRecorder provides an optional custom SpendRecorder implementation.
func WithSpendRecorder(r agent.SpendRecorder) Option {
	return func(o *ServerOptions) { o.SpendRecorder = r }
}

// WithExtraRoute registers an extra HTTP handler pattern onto the gateway ServeMux.
func WithExtraRoute(pattern string, h http.Handler) Option {
	return func(o *ServerOptions) {
		if o.ExtraRoutes == nil {
			o.ExtraRoutes = make(map[string]http.Handler)
		}
		o.ExtraRoutes[pattern] = h
	}
}

// WithPaymentVerifier provides a custom PaymentVerifier implementation.
func WithPaymentVerifier(v x402.PaymentVerifier) Option {
	return func(o *ServerOptions) { o.Verifier = v }
}

// WithSettlementAdapter provides a custom SettlementAdapter implementation.
func WithSettlementAdapter(a settlement.SettlementAdapter) Option {
	return func(o *ServerOptions) { o.SettlementAdapter = a }
}

// WithAssetResolver provides a custom AssetResolver implementation.
func WithAssetResolver(r x402.AssetResolver) Option {
	return func(o *ServerOptions) { o.AssetResolver = r }
}

// WithWalletService provides an explicit wallet service implementation.
func WithWalletService(w wallet.Service) Option {
	return func(o *ServerOptions) { o.WalletSvc = w }
}

// WithTransport provides a custom HTTP RoundTripper for upstreams and verifiers.
func WithTransport(t http.RoundTripper) Option {
	return func(o *ServerOptions) { o.Transport = t }
}

// New creates an initialized GatewayServer using functional options.
func New(cfg *config.GatewayConfig, rcuMgr *rcu.Manager, m *metrics.Metrics, opts ...Option) (*GatewayServer, error) {
	var options ServerOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}
	return NewWithOptions(cfg, rcuMgr, m, options)
}

// NewWithTransport creates an initialized GatewayServer with custom transport.
func NewWithTransport(cfg *config.GatewayConfig, rcuMgr *rcu.Manager, m *metrics.Metrics, transport http.RoundTripper) (*GatewayServer, error) {
	return New(cfg, rcuMgr, m, WithTransport(transport))
}

// NewWithWalletAndTransport creates an initialized GatewayServer with explicit wallet service and custom transport.
func NewWithWalletAndTransport(
	cfg *config.GatewayConfig,
	rcuMgr *rcu.Manager,
	m *metrics.Metrics,
	walletSvc wallet.Service,
	transport http.RoundTripper,
) (*GatewayServer, error) {
	return New(cfg, rcuMgr, m, WithWalletService(walletSvc), WithTransport(transport))
}

// NewWithOptions creates an initialized GatewayServer with explicit options.
func NewWithOptions(
	cfg *config.GatewayConfig,
	rcuMgr *rcu.Manager,
	m *metrics.Metrics,
	opts ServerOptions,
) (*GatewayServer, error) {
	walletSvc := opts.WalletSvc
	transport := opts.Transport
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	if rcuMgr == nil {
		return nil, fmt.Errorf("rcu manager cannot be nil")
	}
	if m == nil {
		m = metrics.New()
	}

	// SECURITY-REVIEW (P0-2): Require upstream master key at startup (fail-closed, no hardcoded fallback).
	masterKey := strings.TrimSpace(cfg.Auth.UpstreamMasterKey)
	if masterKey == "" {
		masterKey = strings.TrimSpace(os.Getenv("AGENTPAY_UPSTREAM_MASTER_KEY"))
	}
	if masterKey == "" {
		return nil, fmt.Errorf("upstream master key cannot be empty: configure auth.upstream_master_key or AGENTPAY_UPSTREAM_MASTER_KEY (refusing to start with insecure defaults)")
	}
	keyVersion := cfg.Auth.UpstreamMasterKeyVersion
	if keyVersion <= 0 {
		keyVersion = 1
	}
	if err := upstreamauth.ConfigureKeyRing(keyVersion, masterKey, cfg.Auth.UpstreamPreviousMasterKeys); err != nil {
		return nil, fmt.Errorf("failed to configure upstream master key ring: %w", err)
	}

	proxyHandler := proxy.NewHandler(m, transport)

	var dbConn *sql.DB
	if cfg.Database.PostgresURL != "" {
		db, err := sql.Open("postgres", cfg.Database.PostgresURL)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to database: %w", err)
		}
		if cfg.Database.MaxOpenConns > 0 {
			db.SetMaxOpenConns(cfg.Database.MaxOpenConns)
		}
		if cfg.Database.MaxIdleConns > 0 {
			db.SetMaxIdleConns(cfg.Database.MaxIdleConns)
		}
		if cfg.Database.ConnMaxLifetimeSeconds > 0 {
			db.SetConnMaxLifetime(time.Duration(cfg.Database.ConnMaxLifetimeSeconds) * time.Second)
		}
		dbConn = db
	}

	// Verify if PostgreSQL is reachable
	var isPostgresReady bool
	if dbConn != nil {
		pingCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		if err := dbConn.PingContext(pingCtx); err == nil {
			isPostgresReady = true
		}
		cancel()
	}

	if walletSvc == nil {
		if isPostgresReady {
			walletSvc = wallet.NewPostgresService(dbConn, 120*time.Second)
		} else {
			memWallet := wallet.NewMemoryService()
			// Register baseline development & testing accounts
			memWallet.RegisterWallet(&wallet.Wallet{
				WalletID:       "wlt_tenant_01",
				TenantID:       "ten_01",
				Asset:          "CNY",
				Status:         wallet.StatusActive,
				Version:        1,
				AvailableCache: 10000000,
				HeldCache:      0,
			})
			memWallet.RegisterAPIKey("apk_live_valid123", "ten_01", "prj_01")

			memWallet.RegisterWallet(&wallet.Wallet{
				WalletID:       "wlt_tenant_02",
				TenantID:       "ten_02",
				Asset:          "CNY",
				Status:         wallet.StatusActive,
				Version:        1,
				AvailableCache: 100,
				HeldCache:      0,
			})
			memWallet.RegisterAPIKey("apk_live_poor", "ten_02", "prj_02")

			memWallet.RegisterWallet(&wallet.Wallet{
				WalletID:       "wlt_tenant_03",
				TenantID:       "ten_03",
				Asset:          "CNY",
				Status:         wallet.StatusFrozenArrears,
				Version:        1,
				AvailableCache: -50000,
				HeldCache:      0,
			})
			memWallet.RegisterAPIKey("apk_live_frozen", "ten_03", "prj_03")

			walletSvc = memWallet
		}
	}

	var verifier x402.PaymentVerifier
	if opts.Verifier != nil {
		verifier = opts.Verifier
	}

	// SECURITY-REVIEW (P0-4): Use persistent PostgreSQL or file-backed NonceStore when available.
	var nonceStore x402.NonceStore
	if _, isMem := walletSvc.(*wallet.MemoryService); !isMem && isPostgresReady {
		nonceStore = x402.NewPostgresNonceStore(dbConn)
		slog.Info("AgentPay x402 NonceStore operating in PostgreSQL persistence mode")
	} else if nonceFile := strings.TrimSpace(os.Getenv("AGENTPAY_NONCE_STORE_FILE")); nonceFile != "" {
		if fs, err := x402.NewPersistentFileNonceStore(nonceFile); err == nil {
			nonceStore = fs
		}
	}

	processor := x402.NewPaymentProcessor(verifier, nonceStore, walletSvc, proxyHandler, m)
	if opts.AssetResolver != nil {
		processor.SetAssetResolver(opts.AssetResolver)
	}
	if opts.PolicyEvaluator != nil {
		processor.SetPolicyEvaluator(opts.PolicyEvaluator)
	}
	if opts.SpendRecorder != nil {
		processor.SetSpendRecorder(opts.SpendRecorder)
	}
	if cfg != nil {
		processor.SetSettlementDefaults(x402.SettlementDefaults{
			DefaultNetwork:       cfg.Settlement.DefaultNetwork,
			DefaultAsset:         cfg.Settlement.DefaultAsset,
			DefaultAssetSymbol:   cfg.Settlement.DefaultAssetSymbol,
			DefaultAssetDecimals: cfg.Settlement.DefaultAssetDecimals,
			DefaultPayTo:         cfg.Settlement.DefaultPayTo,
		})
	}

	// Control Plane Admin & Tenancy Service
	agentRegistry := agent.NewRegistry()
	var adminSvc admin.Service

	// If explicit in-memory wallet service was passed by caller, keep admin in-memory
	if _, isMem := walletSvc.(*wallet.MemoryService); !isMem && isPostgresReady {
		pgAdmin, err := admin.NewPostgresService(dbConn, agentRegistry, walletSvc)
		if err == nil {
			adminSvc = pgAdmin
			slog.Info("AgentPay Control Plane operating in PostgreSQL persistence mode")
		} else {
			slog.Warn("failed to initialize postgres admin service, falling back to in-memory", slog.Any("error", err))
		}
	}

	if adminSvc == nil {
		adminSvc = admin.NewMemoryService(agentRegistry, walletSvc)
		slog.Info("AgentPay Control Plane operating in in-memory mode")
	}

	// Usage and Request Event Recording Service (T5.1)
	var usageSvc usage.Service
	if _, isMem := walletSvc.(*wallet.MemoryService); !isMem && isPostgresReady {
		usageSvc = usage.NewPostgresService(dbConn)
		slog.Info("AgentPay Usage & Event Recording operating in PostgreSQL persistence mode")
	} else {
		usageSvc = usage.NewMemoryService()
		slog.Info("AgentPay Usage & Event Recording operating in in-memory mode")
	}
	processor.SetUsageService(usageSvc)
	adminSvc.SetUsageService(usageSvc)

	// Payment, Settlement & Fulfillment Correlation Service (T5.2)
	var paymentSvc payment.Service
	if _, isMem := walletSvc.(*wallet.MemoryService); !isMem && isPostgresReady {
		paymentSvc = payment.NewPostgresService(dbConn)
		slog.Info("AgentPay Payment Correlation operating in PostgreSQL persistence mode")
	} else {
		paymentSvc = payment.NewMemoryService()
		slog.Info("AgentPay Payment Correlation operating in in-memory mode")
	}
	processor.SetPaymentService(paymentSvc)
	adminSvc.SetPaymentService(paymentSvc)

	// Agent Behavior Timeline Service (T5.8)
	var timelineSvc timeline.Service
	if _, isMem := walletSvc.(*wallet.MemoryService); !isMem && isPostgresReady {
		timelineSvc = timeline.NewPostgresService(dbConn)
		slog.Info("AgentPay Agent Behavior Timeline operating in PostgreSQL persistence mode")
	} else {
		timelineSvc = timeline.NewMemoryService()
		slog.Info("AgentPay Agent Behavior Timeline operating in in-memory mode")
	}
	adminSvc.SetTimelineService(timelineSvc)
	processor.SetAuditEmitter(timeline.NewTimelineAuditEmitter(timelineSvc, processor.GetAuditEmitter()))
	processor.SetAgentRegistry(agentRegistry)

	// Wire admin service to RCU Manager and run initial synchronization
	if adminSvc != nil && rcuMgr != nil {
		adminSvc.SetRCUManager(rcuMgr)
		if err := adminSvc.SyncRCU(context.Background()); err != nil {
			slog.Warn("initial RCU snapshot synchronization failed", slog.Any("error", err))
		} else {
			snap := rcuMgr.Current()
			routesCount := 0
			if snap != nil {
				routesCount = len(snap.Routes)
			}
			slog.Info("RCU configuration cache synchronized with control plane", slog.Int("routes_loaded", routesCount))
		}
	}

	jwtSecret := cfg.Auth.JWTSecret
	if jwtSecret == "" {
		jwtSecret = os.Getenv("AGENTPAY_JWT_SECRET")
	}
	if strings.TrimSpace(jwtSecret) == "" {
		return nil, fmt.Errorf("jwt secret key cannot be empty: configure auth.jwt_secret or AGENTPAY_JWT_SECRET (refusing to start with insecure defaults)")
	}
	tokenDuration := 24 * time.Hour
	if cfg.Auth.TokenDurationHours > 0 {
		tokenDuration = time.Duration(cfg.Auth.TokenDurationHours) * time.Hour
	}
	jwtMgr, err := auth.NewJWTManager(jwtSecret, tokenDuration)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize JWT manager: %w", err)
	}
	adminHandler := admin.NewHandlerWithJWT(adminSvc, jwtMgr)
	if apiH, ok := adminHandler.(*admin.APIHandler); ok {
		for sub, h := range opts.TenantSubresources {
			if sub != "" && h != nil {
				apiH.RegisterSubresource(sub, h)
			}
		}
	}
	securedAdminHandler := auth.Middleware(jwtMgr)(adminHandler)

	startTime := time.Now()
	mux := http.NewServeMux()

	// Register system & operational endpoints
	mux.HandleFunc(cfg.Metrics.HealthPath, handleHealthz(startTime))
	mux.HandleFunc(cfg.Metrics.ReadyPath, handleReadyz(rcuMgr))
	mux.HandleFunc("/version", handleVersion())

	// Register Public Read-Only Marketplace Discovery & Zero-Friction Trial Key API (Unauthenticated + CORS)
	publicMarketplaceHandler := admin.NewPublicMarketplaceHandler(adminSvc)
	mux.Handle("/api/v1/public/marketplace/routes", publicMarketplaceHandler)
	mux.Handle("/api/v1/public/marketplace/routes/", publicMarketplaceHandler)
	mux.Handle("/api/v1/public/marketplace/trial-key", publicMarketplaceHandler)

	// Register Control Plane Admin REST API
	// Note: Explicitly register admin domain endpoints so that proxy routes under /api/v1/... (e.g. /api/v1/simple-weather)
	// fall through to handleGatewayFallback rather than being shadowed by ServeMux longest-prefix matching.
	mux.Handle("/api/v1/auth/", securedAdminHandler)
	mux.Handle("/api/v1/auth-types", securedAdminHandler)
	mux.Handle("/api/v1/audit/", securedAdminHandler)
	mux.Handle("/api/v1/agents/", securedAdminHandler)
	mux.Handle("/api/v1/tenants", securedAdminHandler)
	mux.Handle("/api/v1/tenants/", securedAdminHandler)
	mux.Handle("/api/v1/wallets", securedAdminHandler)
	mux.Handle("/api/v1/wallets/", securedAdminHandler)

	// Register Host/Enterprise Extra Routes (if injected)
	for pattern, h := range opts.ExtraRoutes {
		if pattern != "" && h != nil {
			mux.Handle(pattern, h)
		}
	}

	if cfg.Metrics.Enabled {
		mux.Handle(cfg.Metrics.Path, m.Handler())
	}

	// Register Standard MCP (Model Context Protocol) Transparent Proxy Endpoints
	mcpHandler := mcp.NewHandler(rcuMgr, m, opts.PolicyEvaluator, opts.SpendRecorder, opts.Transport)
	mux.Handle("/v1/mcp/sse", mcpHandler)
	mux.Handle("/v1/mcp/messages", mcpHandler)
	mux.Handle("/v1/mcp/messages/", mcpHandler)
	mux.Handle("/v1/mcp/", mcpHandler)

	// Gateway traffic handler routes via x402 payment processor
	mux.HandleFunc("/", handleGatewayFallback(rcuMgr, m, processor, adminSvc))

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	httpSrv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  cfg.Server.ReadTimeout(),
		WriteTimeout: cfg.Server.WriteTimeout(),
		IdleTimeout:  cfg.Server.IdleTimeout(),
	}

	srv := &GatewayServer{
		cfg:               cfg,
		httpServer:        httpSrv,
		db:                dbConn,
		metrics:           m,
		rcuMgr:            rcuMgr,
		processor:         processor,
		verifier:          verifier,
		settlementAdapter: opts.SettlementAdapter,
		walletSvc:         walletSvc,
		adminSvc:          adminSvc,
		usageSvc:          usageSvc,
		paymentSvc:        paymentSvc,
		timelineSvc:       timelineSvc,
		startTime:         startTime,
		stopCh:            make(chan struct{}),
	}

	// SECURITY-REVIEW (P0-3): Start background reconciliation and expired hold sweep loop.
	go srv.runBackgroundReconciliation()

	return srv, nil
}

func (s *GatewayServer) runBackgroundReconciliation() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case now := <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			_, _ = s.processor.ReconcileSettlements(ctx)
			_, _ = s.processor.SweepExpiredHolds(ctx, now)
			cancel()
		}
	}
}

// Start listens on the configured network address.
func (s *GatewayServer) Start() error {
	addr := s.httpServer.Addr
	slog.Info("AgentPay Gateway starting HTTP listener",
		slog.String("address", addr),
		slog.String("health_path", s.cfg.Metrics.HealthPath),
		slog.String("metrics_path", s.cfg.Metrics.Path),
	)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to bind listener on %s: %w", addr, err)
	}

	if err := s.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("http server failed: %w", err)
	}

	return nil
}

// Shutdown gracefully stops the server within the specified context.
func (s *GatewayServer) Shutdown(ctx context.Context) error {
	slog.Info("shutting down HTTP server gracefully")
	s.stopOnce.Do(func() {
		close(s.stopCh)
	})
	err := s.httpServer.Shutdown(ctx)
	if s.db != nil {
		_ = s.db.Close()
	}
	return err
}

// Handler returns the underlying http.Handler for testing.
func (s *GatewayServer) Handler() http.Handler {
	return s.httpServer.Handler
}

// WalletService returns the active wallet service.
func (s *GatewayServer) WalletService() wallet.Service {
	return s.walletSvc
}

// Processor returns the payment processor.
func (s *GatewayServer) Processor() *x402.PaymentProcessor {
	return s.processor
}

// AdminService returns the control plane admin service.
func (s *GatewayServer) AdminService() admin.Service {
	return s.adminSvc
}

// UsageService returns the usage and event recording service.
func (s *GatewayServer) UsageService() usage.Service {
	return s.usageSvc
}

// PaymentService returns the payment, settlement & fulfillment correlation service.
func (s *GatewayServer) PaymentService() payment.Service {
	return s.paymentSvc
}

// TimelineService returns the agent behavior timeline service.
func (s *GatewayServer) TimelineService() timeline.Service {
	return s.timelineSvc
}

// Verifier returns the payment verifier.
func (s *GatewayServer) Verifier() x402.PaymentVerifier {
	return s.verifier
}

// SettlementAdapter returns the settlement adapter if configured.
func (s *GatewayServer) SettlementAdapter() settlement.SettlementAdapter {
	return s.settlementAdapter
}
