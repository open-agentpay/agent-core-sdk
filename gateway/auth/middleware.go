package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

type contextKey string

const (
	ClaimsContextKey   contextKey = "agentpay.auth.claims"
	MemberIDContextKey contextKey = "agentpay.auth.member_id"
	TenantIDContextKey contextKey = "agentpay.auth.tenant_id"
	RoleContextKey     contextKey = "agentpay.auth.role"
	SystemContextKey   contextKey = "agentpay.auth.system"
)

// StripUntrustedIdentityHeaders removes any client-supplied identity headers
// so external callers cannot spoof member, tenant, or role identity.
// # SECURITY-REVIEW
func StripUntrustedIdentityHeaders(h http.Header) {
	if h == nil {
		return
	}
	for k := range h {
		lower := strings.ToLower(k)
		if lower == "x-actor-member-id" ||
			lower == "x-tenant-id" ||
			lower == "x-role" ||
			strings.HasPrefix(lower, "x-actor-") ||
			strings.HasPrefix(lower, "x-tenant-") ||
			strings.HasPrefix(lower, "x-role-") {
			h.Del(k)
		}
	}
}

// Middleware returns an HTTP middleware that strips untrusted identity headers
// and extracts and validates Bearer JWT tokens.
// # SECURITY-REVIEW
func Middleware(jwtMgr *JWTManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Always strip client-supplied identity headers first.
			StripUntrustedIdentityHeaders(r.Header)

			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				tokenStr := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
				claims, err := jwtMgr.ValidateToken(tokenStr)
				if err != nil {
					w.Header().Set("Content-Type", "application/json; charset=utf-8")
					w.WriteHeader(http.StatusUnauthorized)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"error": map[string]string{
							"code":    "ERR_UNAUTHORIZED",
							"message": err.Error(),
						},
					})
					return
				}

				ctx := WithClaims(r.Context(), claims)
				r = r.WithContext(ctx)

				// Propagate verified claims to headers for downstream compatibility
				r.Header.Set("X-Actor-Member-Id", claims.Subject)
				r.Header.Set("X-Tenant-Id", claims.TenantID)
			}

			next.ServeHTTP(w, r)
		})
	}
}

// WithClaims injects verified JWT claims into context.
func WithClaims(ctx context.Context, claims *Claims) context.Context {
	if claims == nil {
		return ctx
	}
	ctx = context.WithValue(ctx, ClaimsContextKey, claims)
	ctx = context.WithValue(ctx, MemberIDContextKey, claims.Subject)
	ctx = context.WithValue(ctx, TenantIDContextKey, claims.TenantID)
	ctx = context.WithValue(ctx, RoleContextKey, claims.Role)
	return ctx
}

// WithSystemContext marks a context as an explicit internal system operation.
func WithSystemContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, SystemContextKey, true)
}

// IsSystemContext reports whether ctx was explicitly marked as a system operation.
func IsSystemContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v, ok := ctx.Value(SystemContextKey).(bool)
	return ok && v
}

// GetClaims retrieves Claims from request context if present.
func GetClaims(ctx context.Context) *Claims {
	if ctx == nil {
		return nil
	}
	if val, ok := ctx.Value(ClaimsContextKey).(*Claims); ok {
		return val
	}
	return nil
}

// GetMemberID retrieves authenticated member ID from request context.
func GetMemberID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if val, ok := ctx.Value(MemberIDContextKey).(string); ok {
		return val
	}
	return ""
}

// GetTenantID retrieves authenticated tenant ID from request context.
func GetTenantID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if val, ok := ctx.Value(TenantIDContextKey).(string); ok {
		return val
	}
	return ""
}

// GetRole retrieves authenticated role from request context.
func GetRole(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if val, ok := ctx.Value(RoleContextKey).(string); ok {
		return val
	}
	return ""
}
