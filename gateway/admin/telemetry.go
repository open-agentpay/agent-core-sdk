package admin

import (
	"time"
)

// RouteTelemetrySummary represents tenant-level aggregated SLA and LLM token usage.
type RouteTelemetrySummary struct {
	TotalCalls         int64   `json:"total_calls"`
	SuccessCalls       int64   `json:"success_calls"`
	BlockedCalls       int64   `json:"blocked_calls"`
	UpstreamErrorCalls int64   `json:"upstream_error_calls"`
	SuccessRate        float64 `json:"success_rate"`
	AvgDurationMs      int64   `json:"avg_duration_ms"`
	P95DurationMs      int64   `json:"p95_duration_ms"`
	TotalTokens        int64   `json:"total_tokens"`
	PromptTokens       int64   `json:"prompt_tokens"`
	CompletionTokens   int64   `json:"completion_tokens"`
	FailedCalls        int64   `json:"failed_calls"`
}

// RouteTelemetryItem represents the telemetry metrics for a single route.
type RouteTelemetryItem struct {
	RouteID            string  `json:"route_id"`
	ModelName          string  `json:"model_name"`
	Title              string  `json:"title"`
	RouteType          string  `json:"route_type"`
	Calls              int64   `json:"calls"`
	SuccessCalls       int64   `json:"success_calls"`
	BlockedCalls       int64   `json:"blocked_calls"`
	UpstreamErrorCalls int64   `json:"upstream_error_calls"`
	SuccessRate        float64 `json:"success_rate"`
	AvgDurationMs      int64   `json:"avg_duration_ms"`
	P95DurationMs      int64   `json:"p95_duration_ms"`
	TotalTokens        int64   `json:"total_tokens"`
	PromptTokens       int64   `json:"prompt_tokens"`
	CompletionTokens   int64   `json:"completion_tokens"`
	CostAmount         int64   `json:"cost_amount"`
	Status             string  `json:"status"`
}

// RouteTelemetryOverviewResponse represents the aggregated dashboard telemetry response.
type RouteTelemetryOverviewResponse struct {
	TenantID  string                `json:"tenant_id"`
	TimeRange string                `json:"time_range"`
	ProjectID string                `json:"project_id,omitempty"`
	Summary   RouteTelemetrySummary `json:"summary"`
	Routes    []*RouteTelemetryItem `json:"routes"`
	CachedAt  int64                 `json:"cached_at"`
}

// ParseTimeRange converts time range strings like "1h", "24h", "7d", "30d" into time.Duration.
func ParseTimeRange(tr string) (string, time.Duration) {
	switch tr {
	case "1h":
		return "1h", 1 * time.Hour
	case "7d":
		return "7d", 7 * 24 * time.Hour
	case "30d":
		return "30d", 30 * 24 * time.Hour
	default:
		return "24h", 24 * time.Hour
	}
}
