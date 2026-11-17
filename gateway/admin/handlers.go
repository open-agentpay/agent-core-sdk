package admin

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/open-agentpay/agent-core-sdk/gateway/auth"
	"github.com/open-agentpay/agent-core-sdk/gateway/httputil"
	"github.com/open-agentpay/agent-core-sdk/gateway/payment"
	"github.com/open-agentpay/agent-core-sdk/gateway/upstreamauth"
	"github.com/open-agentpay/agent-core-sdk/gateway/usage"
	"github.com/open-agentpay/agent-core-sdk/gateway/wallet"
)

// APIHandler dispatches control plane requests.
type APIHandler struct {
	svc                 Service
	jwtMgr              *auth.JWTManager
	subresourceHandlers map[string]http.Handler
}

// RegisterSubresource registers an extension HTTP handler for a tenant subresource (e.g. /api/v1/tenants/{id}/<name>).
func (h *APIHandler) RegisterSubresource(name string, handler http.Handler) {
	if h.subresourceHandlers == nil {
		h.subresourceHandlers = make(map[string]http.Handler)
	}
	h.subresourceHandlers[name] = handler
}

// NewHandler creates a new HTTP handler for control plane REST API with a test JWT manager.
// For production, use NewHandlerWithJWT with an explicitly configured JWT manager.
func NewHandler(svc Service) http.Handler {
	return NewHandlerWithJWT(svc, auth.MustNewJWTManager("test-admin-secret-key-for-unit-testing-32b!", 24*time.Hour))
}

// NewHandlerWithJWT creates a new HTTP handler for control plane REST API with explicit JWT manager.
func NewHandlerWithJWT(svc Service, jwtMgr *auth.JWTManager) http.Handler {
	if jwtMgr == nil {
		panic("admin.NewHandlerWithJWT: jwtMgr cannot be nil")
	}
	return &APIHandler{svc: svc, jwtMgr: jwtMgr}
}

// authenticateRequest extracts and validates JWT claims if not already injected by auth.Middleware.
// Client-supplied X-Actor-Member-Id and X-Tenant-Id headers are NEVER trusted.
// # SECURITY-REVIEW
func (h *APIHandler) authenticateRequest(r *http.Request) (*http.Request, error) {
	if auth.GetClaims(r.Context()) != nil {
		return r, nil
	}
	auth.StripUntrustedIdentityHeaders(r.Header)
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		tokenStr := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		claims, err := h.jwtMgr.ValidateToken(tokenStr)
		if err != nil {
			return r, err
		}
		ctx := auth.WithClaims(r.Context(), claims)
		r = r.WithContext(ctx)
		r.Header.Set("X-Actor-Member-Id", claims.Subject)
		r.Header.Set("X-Tenant-Id", claims.TenantID)
	}
	return r, nil
}

func (h *APIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimRight(r.URL.Path, "/")
	clientIP := r.RemoteAddr
	if hostPort := strings.TrimSpace(r.RemoteAddr); hostPort != "" {
		clientIP = hostPort
	}

	// 1. Public unauthenticated endpoints
	switch {
	case strings.HasPrefix(path, "/api/v1/public/marketplace"):
		NewPublicMarketplaceHandler(h.svc).ServeHTTP(w, r)
		return
	case path == "/api/v1/auth-types" && r.Method == http.MethodGet:
		h.writeJSON(w, http.StatusOK, map[string]interface{}{"types": h.svc.GetAuthTypes()})
		return
	case (path == "/api/v1/auth/register" || path == "/api/v1/auth/login") && r.Method == http.MethodPost:
		h.handleAuth(w, r, path, "", "")
		return
	}

	// 2. All other control-plane routes require a valid JWT token
	r, err := h.authenticateRequest(r)
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "ERR_UNAUTHORIZED", err.Error())
		return
	}

	actorMemberID := auth.GetMemberID(r.Context())
	authTenantID := auth.GetTenantID(r.Context())
	if actorMemberID == "" || authTenantID == "" {
		h.writeError(w, http.StatusUnauthorized, "ERR_UNAUTHORIZED", "authentication required")
		return
	}

	actorMember, err := h.svc.GetMember(r.Context(), authTenantID, actorMemberID)
	if err != nil || actorMember == nil {
		h.writeError(w, http.StatusUnauthorized, "ERR_UNAUTHORIZED", "invalid or unknown authenticated member")
		return
	}
	if actorMember.Status != MemberStatusActive {
		h.writeError(w, http.StatusForbidden, "ERR_PERMISSION_DENIED", ErrMemberDisabled.Error())
		return
	}

	switch {
	case strings.HasPrefix(path, "/api/v1/auth/"):
		h.handleAuth(w, r, path, actorMemberID, authTenantID)
	case path == "/api/v1/audit/events" && r.Method == http.MethodGet:
		h.handleAuditEvents(w, r, actorMember, authTenantID)
	case strings.HasPrefix(path, "/api/v1/agents/"):
		parts := strings.Split(strings.TrimPrefix(path, "/api/v1/agents/"), "/")
		if h.handleAgentSubpath(w, r, authTenantID, actorMemberID, actorMember, clientIP, parts) {
			return
		}
		http.NotFound(w, r)
	case strings.HasPrefix(path, "/api/v1/wallets/"):
		parts := strings.Split(strings.TrimPrefix(path, "/api/v1/wallets/"), "/")
		if h.handleFlatWalletSubpath(w, r, authTenantID, actorMemberID, actorMember, clientIP, parts) {
			return
		}
		http.NotFound(w, r)
	case path == "/api/v1/tenants":
		if h.handleTenantsRoot(w, r, authTenantID, actorMember) {
			return
		}
		http.NotFound(w, r)
	case strings.HasPrefix(path, "/api/v1/tenants/"):
		parts := strings.Split(strings.TrimPrefix(path, "/api/v1/tenants/"), "/")
		if h.handleTenantScoped(w, r, authTenantID, actorMemberID, actorMember, clientIP, parts) {
			return
		}
		http.NotFound(w, r)
	default:
		http.NotFound(w, r)
	}
}

// ----------------------------------------------------------------------------
// 0. Auth & Audit Endpoints
// ----------------------------------------------------------------------------

func (h *APIHandler) handleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrTenantNotFound),
		errors.Is(err, ErrProjectNotFound),
		errors.Is(err, ErrMemberNotFound),
		errors.Is(err, ErrAgentNotFound),
		errors.Is(err, ErrAPIKeyNotFound),
		errors.Is(err, ErrRouteNotFound),
		errors.Is(err, ErrPolicyNotFound),
		errors.Is(err, ErrWalletNotFound),
		errors.Is(err, usage.ErrRequestRecordNotFound),
		errors.Is(err, usage.ErrUsageEventNotFound),
		errors.Is(err, payment.ErrIntentNotFound),
		errors.Is(err, payment.ErrSettlementNotFound),
		errors.Is(err, payment.ErrFulfillmentNotFound):
		h.writeError(w, http.StatusNotFound, "ERR_NOT_FOUND", err.Error())
	case errors.Is(err, ErrPermissionDenied),
		errors.Is(err, ErrMemberDisabled),
		errors.Is(err, ErrTenantSuspended),
		errors.Is(err, ErrTenantTerminated),
		errors.Is(err, ErrProjectArchived),
		errors.Is(err, ErrProjectTenantMismatch),
		errors.Is(err, ErrAgentTenantMismatch),
		errors.Is(err, ErrAgentSuspended),
		errors.Is(err, ErrAgentRevoked),
		errors.Is(err, usage.ErrTenantMismatch),
		errors.Is(err, payment.ErrTenantMismatch):
		h.writeError(w, http.StatusForbidden, "ERR_PERMISSION_DENIED", err.Error())
	case errors.Is(err, upstreamauth.ErrSSRFBlocked):
		h.writeError(w, http.StatusForbidden, "ERR_SSRF_BLOCKED", err.Error())
	case errors.Is(err, ErrTenantAlreadyExists),
		errors.Is(err, ErrProjectAlreadyExists),
		errors.Is(err, ErrMemberAlreadyExists),
		errors.Is(err, ErrAgentAlreadyExists),
		errors.Is(err, ErrRouteAlreadyExists):
		h.writeError(w, http.StatusConflict, "ERR_ALREADY_EXISTS", err.Error())
	case errors.Is(err, ErrMissingReason):
		h.writeError(w, http.StatusBadRequest, "ERR_MISSING_REASON", err.Error())
	case errors.Is(err, ErrInvalidStatusTransition),
		errors.Is(err, ErrCannotRemoveLastOwner),
		errors.Is(err, ErrCannotDemoteLastOwner),
		errors.Is(err, ErrInvalidAmount):
		h.writeError(w, http.StatusBadRequest, "ERR_INVALID_PARAM", err.Error())
	case errors.Is(err, ErrInvalidCredentials):
		h.writeError(w, http.StatusUnauthorized, "ERR_INVALID_CREDENTIALS", err.Error())
	case errors.Is(err, ErrPasswordTooShort):
		h.writeError(w, http.StatusBadRequest, "ERR_PASSWORD_TOO_SHORT", err.Error())
	case errors.Is(err, ErrEmailAlreadyRegistered):
		h.writeError(w, http.StatusConflict, "ERR_EMAIL_ALREADY_REGISTERED", err.Error())
	case errors.Is(err, ErrConfigValidationFailed):
		h.writeError(w, http.StatusUnprocessableEntity, "ERR_CONFIG_VALIDATION_FAILED", err.Error())
	case errors.Is(err, ErrConfigVersionNotFound):
		h.writeError(w, http.StatusNotFound, "ERR_CONFIG_VERSION_NOT_FOUND", err.Error())
	case errors.Is(err, ErrCannotRollbackToActive):
		h.writeError(w, http.StatusBadRequest, "ERR_CANNOT_ROLLBACK_TO_ACTIVE", err.Error())
	case errors.Is(err, ErrCurrencyLocked):
		h.writeError(w, http.StatusConflict, "ERR_CURRENCY_LOCKED", err.Error())
	case errors.Is(err, ErrInvalidCurrency):
		h.writeError(w, http.StatusBadRequest, "ERR_INVALID_CURRENCY", err.Error())
	case errors.Is(err, wallet.ErrInsufficientBalance):
		h.writeError(w, http.StatusPaymentRequired, "ERR_INSUFFICIENT_FUNDS", err.Error())
	default:
		h.writeError(w, http.StatusBadRequest, "ERR_BAD_REQUEST", err.Error())
	}
}

func (h *APIHandler) writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	httputil.WriteJSON(w, statusCode, data)
}

func (h *APIHandler) writeError(w http.ResponseWriter, statusCode int, code, message string) {
	if statusCode >= 500 {
		slog.Error("admin control-plane request error", slog.Int("status", statusCode), slog.String("code", code), slog.String("message", message))
	} else if statusCode >= 400 {
		slog.Warn("admin control-plane client warning", slog.Int("status", statusCode), slog.String("code", code), slog.String("message", message))
	}
	httputil.WriteError(w, statusCode, code, message)
}

func parseFlexibleTimestamp(raw string) *time.Time {
	if raw == "" {
		return nil
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return &t
	}
	if sec, err := strconv.ParseInt(raw, 10, 64); err == nil {
		var t time.Time
		if sec > 1e11 {
			t = time.UnixMilli(sec)
		} else {
			t = time.Unix(sec, 0)
		}
		return &t
	}
	return nil
}

