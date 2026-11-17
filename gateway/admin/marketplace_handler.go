package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

func NewPublicMarketplaceHandler(svc Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Enable CORS for public storefront / Next.js / Agent discovery clients
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Accept, X-Forwarded-For")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		path := strings.TrimRight(r.URL.Path, "/")

		// Handle POST /api/v1/public/marketplace/trial-key
		if r.Method == http.MethodPost && path == "/api/v1/public/marketplace/trial-key" {
			var req TrialKeyRequest
			_ = json.NewDecoder(r.Body).Decode(&req)

			// Resolve client IP from X-Forwarded-For or RemoteAddr
			clientIP := r.Header.Get("X-Forwarded-For")
			if clientIP != "" {
				parts := strings.Split(clientIP, ",")
				clientIP = strings.TrimSpace(parts[0])
			}
			if clientIP == "" {
				clientIP = r.RemoteAddr
				if idx := strings.LastIndex(clientIP, ":"); idx != -1 {
					clientIP = clientIP[:idx]
				}
			}

			trialResp, err := svc.CreateTrialAPIKey(r.Context(), clientIP, req.ClientFingerprint)
			if err != nil {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				if errors.Is(err, ErrTrialRateLimitExceeded) {
					w.WriteHeader(http.StatusTooManyRequests)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"error": map[string]string{
							"code":    "TRIAL_RATE_LIMIT_EXCEEDED",
							"message": "当前 IP 试用申领过于频繁，请直接登录控制台获取长期免费 API Key",
						},
					})
					return
				}
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"error": map[string]string{
						"code":    "ERR_INTERNAL",
						"message": err.Error(),
					},
				})
				return
			}

			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(trialResp)
			return
		}

		if r.Method != http.MethodGet {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error": map[string]string{
					"code":    "ERR_METHOD_NOT_ALLOWED",
					"message": "only GET or POST (trial-key) is supported on public marketplace endpoints",
				},
			})
			return
		}

		if path == "/api/v1/public/marketplace/routes" {
			q := r.URL.Query()
			queryStr := q.Get("q")
			if queryStr == "" {
				queryStr = q.Get("search")
			}
			filter := MarketplaceFilter{
				Query:    queryStr,
				Category: q.Get("category"),
				Network:  q.Get("network"),
				Tag:      q.Get("tag"),
			}
			items, err := svc.ListMarketplaceRoutes(r.Context(), filter)
			if err != nil {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"error": map[string]string{
						"code":    "ERR_INTERNAL",
						"message": err.Error(),
					},
				})
				return
			}
			if items == nil {
				items = []*MarketplaceRouteItem{}
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"count":  len(items),
				"routes": items,
			})
			return
		}

		if strings.HasPrefix(path, "/api/v1/public/marketplace/routes/") {
			slug := strings.TrimPrefix(path, "/api/v1/public/marketplace/routes/")
			if slug == "" || strings.Contains(slug, "/") {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"error": map[string]string{
						"code":    "ERR_NOT_FOUND",
						"message": "marketplace route not found",
					},
				})
				return
			}
			item, err := svc.GetMarketplaceRouteBySlug(r.Context(), slug)
			if err != nil {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"error": map[string]string{
						"code":    "ERR_NOT_FOUND",
						"message": err.Error(),
					},
				})
				return
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"route": item,
			})
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]string{
				"code":    "ERR_NOT_FOUND",
				"message": "marketplace endpoint not found",
			},
		})
	})
}
