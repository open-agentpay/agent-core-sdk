// Package metrics provides zero-external-dependency, lock-free atomic Prometheus metrics
// for AgentPay Go Gateway.
package metrics

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

// Metrics holds atomic counters and latency measurements.
type Metrics struct {
	startTime              time.Time
	RequestsTotal          uint64
	RequestsInFlight       int64
	ChallengesIssuedTotal  uint64
	PaymentsVerifiedTotal  uint64
	PaymentsFailedTotal    uint64
	UpstreamErrorsTotal    uint64
	HoldsCreatedTotal      uint64
	HoldsCapturedTotal     uint64
	HoldsReleasedTotal     uint64
}

// New creates an initialized Metrics registry.
func New() *Metrics {
	return &Metrics{
		startTime: time.Now(),
	}
}

// IncRequests increments total request count.
func (m *Metrics) IncRequests() {
	atomic.AddUint64(&m.RequestsTotal, 1)
}

// IncInFlight increments concurrent in-flight requests.
func (m *Metrics) IncInFlight() {
	atomic.AddInt64(&m.RequestsInFlight, 1)
}

// DecInFlight decrements concurrent in-flight requests.
func (m *Metrics) DecInFlight() {
	atomic.AddInt64(&m.RequestsInFlight, -1)
}

// IncChallenges increments 402 challenges counter.
func (m *Metrics) IncChallenges() {
	atomic.AddUint64(&m.ChallengesIssuedTotal, 1)
}

// IncPaymentsVerified increments verified payments counter.
func (m *Metrics) IncPaymentsVerified() {
	atomic.AddUint64(&m.PaymentsVerifiedTotal, 1)
}

// IncPaymentsFailed increments failed payments counter.
func (m *Metrics) IncPaymentsFailed() {
	atomic.AddUint64(&m.PaymentsFailedTotal, 1)
}

// IncUpstreamErrors increments upstream 5xx/timeout counter.
func (m *Metrics) IncUpstreamErrors() {
	atomic.AddUint64(&m.UpstreamErrorsTotal, 1)
}

// IncHoldsCreated increments wallet hold counter.
func (m *Metrics) IncHoldsCreated() {
	atomic.AddUint64(&m.HoldsCreatedTotal, 1)
}

// IncHoldsCaptured increments wallet capture counter.
func (m *Metrics) IncHoldsCaptured() {
	atomic.AddUint64(&m.HoldsCapturedTotal, 1)
}

// IncHoldsReleased increments wallet release counter.
func (m *Metrics) IncHoldsReleased() {
	atomic.AddUint64(&m.HoldsReleasedTotal, 1)
}

// Handler returns an HTTP handler exporting Prometheus text exposition format.
func (m *Metrics) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uptime := time.Since(m.startTime).Seconds()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)

		fmt.Fprintf(w, "# HELP agentpay_uptime_seconds Process uptime in seconds\n")
		fmt.Fprintf(w, "# TYPE agentpay_uptime_seconds gauge\n")
		fmt.Fprintf(w, "agentpay_uptime_seconds %.2f\n\n", uptime)

		fmt.Fprintf(w, "# HELP agentpay_requests_total Total number of HTTP requests processed\n")
		fmt.Fprintf(w, "# TYPE agentpay_requests_total counter\n")
		fmt.Fprintf(w, "agentpay_requests_total %d\n\n", atomic.LoadUint64(&m.RequestsTotal))

		fmt.Fprintf(w, "# HELP agentpay_requests_in_flight Current in-flight requests\n")
		fmt.Fprintf(w, "# TYPE agentpay_requests_in_flight gauge\n")
		fmt.Fprintf(w, "agentpay_requests_in_flight %d\n\n", atomic.LoadInt64(&m.RequestsInFlight))

		fmt.Fprintf(w, "# HELP agentpay_challenges_issued_total Total 402 Payment Challenges issued\n")
		fmt.Fprintf(w, "# TYPE agentpay_challenges_issued_total counter\n")
		fmt.Fprintf(w, "agentpay_challenges_issued_total %d\n\n", atomic.LoadUint64(&m.ChallengesIssuedTotal))

		fmt.Fprintf(w, "# HELP agentpay_payments_verified_total Total successful payment authorizations verified\n")
		fmt.Fprintf(w, "# TYPE agentpay_payments_verified_total counter\n")
		fmt.Fprintf(w, "agentpay_payments_verified_total %d\n\n", atomic.LoadUint64(&m.PaymentsVerifiedTotal))

		fmt.Fprintf(w, "# HELP agentpay_payments_failed_total Total failed payment verifications\n")
		fmt.Fprintf(w, "# TYPE agentpay_payments_failed_total counter\n")
		fmt.Fprintf(w, "agentpay_payments_failed_total %d\n\n", atomic.LoadUint64(&m.PaymentsFailedTotal))

		fmt.Fprintf(w, "# HELP agentpay_upstream_errors_total Total upstream 5xx and network timeout errors\n")
		fmt.Fprintf(w, "# TYPE agentpay_upstream_errors_total counter\n")
		fmt.Fprintf(w, "agentpay_upstream_errors_total %d\n\n", atomic.LoadUint64(&m.UpstreamErrorsTotal))

		fmt.Fprintf(w, "# HELP agentpay_wallet_holds_created_total Total virtual wallet funds held\n")
		fmt.Fprintf(w, "# TYPE agentpay_wallet_holds_created_total counter\n")
		fmt.Fprintf(w, "agentpay_wallet_holds_created_total %d\n\n", atomic.LoadUint64(&m.HoldsCreatedTotal))

		fmt.Fprintf(w, "# HELP agentpay_wallet_holds_captured_total Total virtual wallet funds captured\n")
		fmt.Fprintf(w, "# TYPE agentpay_wallet_holds_captured_total counter\n")
		fmt.Fprintf(w, "agentpay_wallet_holds_captured_total %d\n\n", atomic.LoadUint64(&m.HoldsCapturedTotal))

		fmt.Fprintf(w, "# HELP agentpay_wallet_holds_released_total Total virtual wallet funds released\n")
		fmt.Fprintf(w, "# TYPE agentpay_wallet_holds_released_total counter\n")
		fmt.Fprintf(w, "agentpay_wallet_holds_released_total %d\n", atomic.LoadUint64(&m.HoldsReleasedTotal))
	})
}
