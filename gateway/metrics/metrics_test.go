package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsCountersAndPrometheusHandler(t *testing.T) {
	m := New()

	m.IncRequests()
	m.IncRequests()
	m.IncInFlight()
	m.IncChallenges()
	m.IncPaymentsVerified()
	m.IncHoldsCreated()
	m.IncHoldsCaptured()

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	m.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "agentpay_requests_total 2") {
		t.Errorf("expected requests_total 2, got output:\n%s", body)
	}
	if !strings.Contains(body, "agentpay_requests_in_flight 1") {
		t.Errorf("expected requests_in_flight 1, got output:\n%s", body)
	}
	if !strings.Contains(body, "agentpay_challenges_issued_total 1") {
		t.Errorf("expected challenges_issued 1, got output:\n%s", body)
	}
	if !strings.Contains(body, "agentpay_wallet_holds_captured_total 1") {
		t.Errorf("expected holds_captured 1, got output:\n%s", body)
	}

	m.DecInFlight()
	w2 := httptest.NewRecorder()
	m.Handler().ServeHTTP(w2, req)
	if !strings.Contains(w2.Body.String(), "agentpay_requests_in_flight 0") {
		t.Errorf("expected in_flight decremented to 0")
	}
}
