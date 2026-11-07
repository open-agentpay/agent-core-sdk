// Package server implements the HTTP Server, multiplexer routing, health probes,
// metrics endpoints, and graceful lifecycle management for AgentPay Go Gateway.
package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/open-agentpay/agent-core-sdk/gateway/admin"
	"github.com/open-agentpay/agent-core-sdk/gateway/metrics"
	"github.com/open-agentpay/agent-core-sdk/gateway/rcu"
	"github.com/open-agentpay/agent-core-sdk/gateway/x402"
)

var (
	// Version is populated at build time via -ldflags
	Version   = "0.3.0"
	GitCommit = "unknown"
	BuildDate = "unknown"
)

// HealthResponse represents standard JSON health payload.
type HealthResponse struct {
	Status        string  `json:"status"`
	Service       string  `json:"service"`
	UptimeSeconds float64 `json:"uptime_seconds"`
	Timestamp     string  `json:"timestamp"`
}

// ReadyResponse represents readiness probe payload.
type ReadyResponse struct {
	Status        string `json:"status"`
	Service       string `json:"service"`
	ConfigVersion string `json:"config_version,omitempty"`
	RoutesLoaded  int    `json:"routes_loaded"`
	Timestamp     string `json:"timestamp"`
}

// VersionResponse represents build and runtime information.
type VersionResponse struct {
	Service   string `json:"service"`
	Version   string `json:"version"`
	GitCommit string `json:"git_commit"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

func handleHealthz(startTime time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := HealthResponse{
			Status:        "ok",
			Service:       "agentpay-gateway",
			UptimeSeconds: time.Since(startTime).Seconds(),
			Timestamp:     time.Now().UTC().Format(time.RFC3339),
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleReadyz(rcuMgr *rcu.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snap := rcuMgr.Current()
		routesCount := 0
		configVer := "bootstrap"
		if snap != nil {
			routesCount = len(snap.Routes)
			configVer = snap.VersionID
		}

		resp := ReadyResponse{
			Status:        "ready",
			Service:       "agentpay-gateway",
			ConfigVersion: configVer,
			RoutesLoaded:  routesCount,
			Timestamp:     time.Now().UTC().Format(time.RFC3339),
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleVersion() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := VersionResponse{
			Service:   "agentpay-gateway",
			Version:   Version,
			GitCommit: GitCommit,
			BuildDate: BuildDate,
			GoVersion: runtime.Version(),
			OS:        runtime.GOOS,
			Arch:      runtime.GOARCH,
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleGatewayFallback(rcuMgr *rcu.Manager, m *metrics.Metrics, processor *x402.PaymentProcessor, adminSvc admin.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m.IncRequests()
		m.IncInFlight()
		defer m.DecInFlight()

		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = fmt.Sprintf("req_%d", time.Now().UnixNano())
		}

		route, policy, snap, matched := rcuMgr.MatchRouteWithPolicy(r.URL.Path)
		if !matched && adminSvc != nil {
			// Fast recovery: trigger an on-demand sync from persistence in case route was added directly
			_ = adminSvc.SyncRCU(r.Context())
			route, policy, snap, matched = rcuMgr.MatchRouteWithPolicy(r.URL.Path)
		}
		if !matched {
			x402.WriteProtocolError(w, x402.ErrCodeRouteNotFound, requestID, map[string]interface{}{
				"path": r.URL.Path,
			})
			return
		}

		// Process payment (wallet or x402 onchain) and proxy to upstream with snapshot tracking
		processor.HandleRequestWithSnapshot(w, r, route, policy, snap, requestID)
	}
}

func writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(data)
}
